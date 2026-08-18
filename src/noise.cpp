#include "noise.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <string_view>

#include "wire.h"

namespace vpn::noise {
namespace {

// The protocol's fixed strings. Every byte of these is load-bearing: a typo
// changes the initial chaining key, which changes every derived key, and the
// only symptom is "the two sides disagree" with nothing to point at.
constexpr std::string_view kConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
constexpr std::string_view kIdentifier = "WireGuard v1 zx2c4 Jason@zx2c4.com";
constexpr std::string_view kLabelMac1 = "mac1----";

std::span<const uint8_t> bytes_of(std::string_view text) {
    return {reinterpret_cast<const uint8_t*>(text.data()), text.size()};
}

// The all-zero preshared key. PSK mode is out of scope, but the mixing step is
// part of the construction and removing it would change every derived key.
std::span<const uint8_t> zero_psk() {
    static constexpr std::array<uint8_t, kPresharedKeySize> kZeros{};
    return kZeros;
}

void write_u32_le(std::span<uint8_t, 4> out, uint32_t value) noexcept {
    for (size_t i = 0; i < 4; ++i) {
        out[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xff);
    }
}

void write_prefix(std::span<uint8_t> out, wire::Type type) noexcept {
    out[0] = static_cast<uint8_t>(type);
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
}

// mac1 over everything before the mac1 field; mac2 all zeros, which is what the
// protocol specifies when no cookie has been received. Phase 7 fills mac2 in
// and starts verifying it; the field has to be here and correctly sized from
// now on, or that change would move every byte after it.
void write_macs(std::span<uint8_t> message, crypto::Key mac1_key) {
    const auto input = wire::mac1_input(message);
    const auto mac1 = wire::mac1_field(message);
    const auto mac2 = wire::mac2_field(message);
    if (!input.has_value() || !mac1.has_value() || !mac2.has_value()) {
        return;  // unreachable: the caller just wrote a well-formed message
    }
    crypto::mac(*mac1, mac1_key, *input);
    std::fill(mac2->begin(), mac2->end(), uint8_t{0});
}

// The two pieces of running state the whitepaper carries through the handshake:
// the chaining key C and the transcript hash H. Kept as plain locals inside each
// step so a message that fails halfway leaves the object's own state untouched.
using MixKey = SecureBuf<crypto::kHashSize>;

// C = HASH(CONSTRUCTION); H = HASH(C || IDENTIFIER); H = HASH(H || Sr^pub).
// The static key mixed in is always the *responder's*, whichever side we are.
void begin(MixKey& chaining_key, MixKey& hash, crypto::Key responder_static) {
    crypto::hash(chaining_key.mut(), bytes_of(kConstruction));
    crypto::hash2(hash.mut(), chaining_key.get(), bytes_of(kIdentifier));
    // Aliasing the output with an input is safe: hash2 reads both operands into
    // the hash state before it writes the digest.
    crypto::hash2(hash.mut(), hash.get(), responder_static);
}

void mix_hash(MixKey& hash, std::span<const uint8_t> data) {
    crypto::hash2(hash.mut(), hash.get(), data);
}

[[nodiscard]] bool mix_dh(MixKey& chaining_key, crypto::Key private_key,
                          crypto::Key peer_public) {
    SecureBuf<crypto::kKeySize> shared;
    if (!crypto::dh(shared.mut(), private_key, peer_public)) {
        return false;
    }
    crypto::kdf1(chaining_key.mut(), chaining_key.get(), shared.get());
    return true;
}

[[nodiscard]] bool mix_dh_key(MixKey& chaining_key, crypto::Key private_key,
                              crypto::Key peer_public,
                              std::span<uint8_t, crypto::kKeySize> key_out) {
    SecureBuf<crypto::kKeySize> shared;
    if (!crypto::dh(shared.mut(), private_key, peer_public)) {
        return false;
    }
    crypto::kdf2(chaining_key.mut(), key_out, chaining_key.get(), shared.get());
    return true;
}

void copy_into(MixKey& destination, crypto::Key source) {
    std::copy(source.begin(), source.end(), destination.mut().begin());
}

[[nodiscard]] bool mac1_ok(std::span<const uint8_t> message, crypto::Key mac1_key,
                           std::span<const uint8_t, crypto::kMacSize> claimed) {
    const auto input = wire::mac1_input(message);
    if (!input.has_value()) {
        return false;
    }
    std::array<uint8_t, crypto::kMacSize> expected{};
    crypto::mac(expected, mac1_key, *input);
    return crypto::equal(expected, claimed);
}

}  // namespace

// ------------------------------------------------------------------ Identity

Identity::Identity(crypto::Key private_key, crypto::Key peer_public) {
    std::copy(private_key.begin(), private_key.end(), private_key_.mut().begin());
    std::copy(peer_public.begin(), peer_public.end(), peer_public_.begin());
    crypto::derive_public(public_key_, private_key_.get());

    // Precomputed once: HASH(LABEL_MAC1 || <static public key>).
    crypto::hash2(own_mac1_key_, bytes_of(kLabelMac1), public_key_);
    crypto::hash2(peer_mac1_key_, bytes_of(kLabelMac1), peer_public_);
}

std::unique_ptr<Identity> Identity::from_base64(std::string_view private_key,
                                                std::string_view peer_public) {
    const auto priv = crypto::from_base64(private_key);
    const auto pub = crypto::from_base64(peer_public);
    if (!priv.has_value() || priv->size() != crypto::kKeySize || !pub.has_value() ||
        pub->size() != crypto::kKeySize) {
        return nullptr;
    }
    return std::make_unique<Identity>(crypto::Key(priv->data(), crypto::kKeySize),
                                      crypto::Key(pub->data(), crypto::kKeySize));
}

// ------------------------------------------------------------ TimestampGuard

bool TimestampGuard::accept(std::span<const uint8_t, crypto::kTimestampSize> timestamp) {
    if (seen_ && !crypto::timestamp_after(timestamp, greatest_)) {
        return false;
    }
    std::copy(timestamp.begin(), timestamp.end(), greatest_.begin());
    seen_ = true;
    return true;
}

// ----------------------------------------------------------------- Handshake


std::optional<std::span<uint8_t>> Handshake::write_initiation(std::span<uint8_t> out) {
    if (out.size() < wire::kInitiationSize) {
        return std::nullopt;
    }
    const std::span<uint8_t> message = out.first(wire::kInitiationSize);

    MixKey chaining_key;
    MixKey hash;
    begin(chaining_key, hash, identity_.peer_public());

    const uint32_t index = crypto::random_index();
    write_prefix(message, wire::Type::handshake_initiation);
    write_u32_le(message.subspan<wire::kInitiationSenderOffset, 4>(), index);

    // Ci = KDF1(Ci, Ei^pub); msg.unencrypted_ephemeral = Ei^pub
    SecureBuf<crypto::kKeySize> ephemeral_private;
    std::array<uint8_t, crypto::kKeySize> ephemeral_public{};
    crypto::generate_keypair(ephemeral_private.mut(), ephemeral_public);
    crypto::kdf1(chaining_key.mut(), chaining_key.get(), ephemeral_public);
    std::copy(ephemeral_public.begin(), ephemeral_public.end(),
              message.begin() + wire::kInitiationEphemeralOffset);
    mix_hash(hash, ephemeral_public);

    // (Ci, k) = KDF2(Ci, DH(Ei^priv, Sr^pub))
    // msg.encrypted_static = AEAD(k, 0, Si^pub, Hi)
    {
        SecureBuf<crypto::kKeySize> key;
        if (!mix_dh_key(chaining_key, ephemeral_private.get(), identity_.peer_public(),
                        key.mut())) {
            return std::nullopt;
        }
        const std::span<uint8_t> field =
            message.subspan(wire::kInitiationStaticOffset, wire::kEncryptedStaticSize);
        crypto::seal(field, key.get(), 0, identity_.public_key(), hash.get());
        mix_hash(hash, field);
    }

    // (Ci, k) = KDF2(Ci, DH(Si^priv, Sr^pub))
    // msg.encrypted_timestamp = AEAD(k, 0, TAI64N(), Hi)
    {
        SecureBuf<crypto::kKeySize> key;
        if (!mix_dh_key(chaining_key, identity_.private_key(), identity_.peer_public(),
                        key.mut())) {
            return std::nullopt;
        }
        std::array<uint8_t, crypto::kTimestampSize> now{};
        crypto::timestamp(now);
        const std::span<uint8_t> field =
            message.subspan(wire::kInitiationTimestampOffset, wire::kEncryptedTimestampSize);
        crypto::seal(field, key.get(), 0, now, hash.get());
        mix_hash(hash, field);
    }

    write_macs(message, identity_.sending_mac1_key());

    // Everything succeeded, so keep the state the response will continue from.
    copy_into(chaining_key_, chaining_key.get());
    copy_into(hash_, hash.get());
    std::copy(ephemeral_private.get().begin(), ephemeral_private.get().end(),
              ephemeral_private_.mut().begin());
    ephemeral_public_ = ephemeral_public;
    local_index_ = index;
    return message;
}

bool Handshake::read_initiation(std::span<const uint8_t> message, TimestampGuard& guard) {
    const std::optional<wire::Message> decoded = wire::decode(message);
    if (!decoded.has_value()) {
        return false;
    }
    const auto* const initiation = std::get_if<wire::HandshakeInitiation>(&*decoded);
    if (initiation == nullptr) {
        return false;
    }

    // mac1 first. It is one keyed hash over bytes we already have, it needs no
    // per-initiator state, and it rejects anything not sent by someone who knows
    // our public key — all before we spend a single scalar multiplication.
    if (!mac1_ok(message, identity_.receiving_mac1_key(), initiation->mac1)) {
        return false;
    }

    MixKey chaining_key;
    MixKey hash;
    begin(chaining_key, hash, identity_.public_key());

    // Cr = KDF1(Cr, msg.ephemeral); Hr = HASH(Hr || msg.ephemeral)
    crypto::kdf1(chaining_key.mut(), chaining_key.get(), initiation->ephemeral);
    mix_hash(hash, initiation->ephemeral);

    // (Cr, k) = KDF2(Cr, DH(Sr^priv, Ei^pub)); open msg.encrypted_static
    std::array<uint8_t, crypto::kKeySize> claimed_static{};
    {
        SecureBuf<crypto::kKeySize> key;
        if (!mix_dh_key(chaining_key, identity_.private_key(), initiation->ephemeral, key.mut())) {
            return false;
        }
        if (!crypto::open(claimed_static, key.get(), 0, initiation->encrypted_static, hash.get())) {
            return false;
        }
        mix_hash(hash, initiation->encrypted_static);
    }

    // This is the authentication step: the static key inside the message must be
    // the peer we were configured for. A mismatch fails here, silently — replying
    // at all would tell a scanner that a VPN lives at this address.
    if (!crypto::equal(claimed_static, identity_.peer_public())) {
        return false;
    }

    // (Cr, k) = KDF2(Cr, DH(Sr^priv, Si^pub)); open msg.encrypted_timestamp
    std::array<uint8_t, crypto::kTimestampSize> timestamp{};
    {
        SecureBuf<crypto::kKeySize> key;
        if (!mix_dh_key(chaining_key, identity_.private_key(), claimed_static, key.mut())) {
            return false;
        }
        if (!crypto::open(timestamp, key.get(), 0, initiation->encrypted_timestamp, hash.get())) {
            return false;
        }
        mix_hash(hash, initiation->encrypted_timestamp);
    }

    // Authenticated, so the timestamp can be trusted enough to compare — and it
    // is checked before we do the work of responding, which is the point of it.
    if (!guard.accept(timestamp)) {
        return false;
    }

    copy_into(chaining_key_, chaining_key.get());
    copy_into(hash_, hash.get());
    std::copy(initiation->ephemeral.begin(), initiation->ephemeral.end(), peer_ephemeral_.begin());
    peer_index_ = initiation->sender_index;
    return true;
}

std::optional<std::span<uint8_t>> Handshake::write_response(std::span<uint8_t> out,
                                                            TransportKeys& keys) {
    if (out.size() < wire::kResponseSize) {
        return std::nullopt;
    }
    const std::span<uint8_t> message = out.first(wire::kResponseSize);

    MixKey chaining_key;
    MixKey hash;
    copy_into(chaining_key, chaining_key_.get());
    copy_into(hash, hash_.get());

    const uint32_t index = crypto::random_index();
    write_prefix(message, wire::Type::handshake_response);
    write_u32_le(message.subspan<wire::kResponseSenderOffset, 4>(), index);
    write_u32_le(message.subspan<wire::kResponseReceiverOffset, 4>(), peer_index_);

    // Cr = KDF1(Cr, Er^pub); msg.unencrypted_ephemeral = Er^pub
    SecureBuf<crypto::kKeySize> ephemeral_private;
    std::array<uint8_t, crypto::kKeySize> ephemeral_public{};
    crypto::generate_keypair(ephemeral_private.mut(), ephemeral_public);
    crypto::kdf1(chaining_key.mut(), chaining_key.get(), ephemeral_public);
    std::copy(ephemeral_public.begin(), ephemeral_public.end(),
              message.begin() + wire::kResponseEphemeralOffset);
    mix_hash(hash, ephemeral_public);

    // Cr = KDF1(Cr, DH(Er^priv, Ei^pub)); Cr = KDF1(Cr, DH(Er^priv, Si^pub))
    if (!mix_dh(chaining_key, ephemeral_private.get(), peer_ephemeral_)) {
        return std::nullopt;
    }
    if (!mix_dh(chaining_key, ephemeral_private.get(), identity_.peer_public())) {
        return std::nullopt;
    }

    // (Cr, tau, k) = KDF3(Cr, Q); Hr = HASH(Hr || tau)
    // msg.encrypted_nothing = AEAD(k, 0, empty, Hr)
    {
        SecureBuf<crypto::kHashSize> tau;
        SecureBuf<crypto::kKeySize> key;
        crypto::kdf3(chaining_key.mut(), tau.mut(), key.mut(), chaining_key.get(), zero_psk());
        mix_hash(hash, tau.get());

        const std::span<uint8_t> field =
            message.subspan(wire::kResponseNothingOffset, wire::kEncryptedNothingSize);
        crypto::seal(field, key.get(), 0, {}, hash.get());
        mix_hash(hash, field);
    }

    // The responder's receive key is the initiator's send key, so the two
    // outputs land the opposite way round on each side.
    crypto::kdf2(keys.receive.mut(), keys.send.mut(), chaining_key.get(), {});
    keys.local_index = index;
    keys.peer_index = peer_index_;
    local_index_ = index;

    // Nothing below needs the handshake state, and every byte of it is key
    // material with no further use.
    chaining_key_.wipe();
    hash_.wipe();
    ephemeral_private_.wipe();

    write_macs(message, identity_.sending_mac1_key());
    return message;
}

bool Handshake::read_response(std::span<const uint8_t> message, TransportKeys& keys) {
    const std::optional<wire::Message> decoded = wire::decode(message);
    if (!decoded.has_value()) {
        return false;
    }
    const auto* const response = std::get_if<wire::HandshakeResponse>(&*decoded);
    if (response == nullptr) {
        return false;
    }

    // It must be a reply to the initiation this object sent, not to some other
    // session's.
    if (response->receiver_index != local_index_) {
        return false;
    }
    if (!mac1_ok(message, identity_.receiving_mac1_key(), response->mac1)) {
        return false;
    }

    // From here on, everything runs on copies. A response that fails any check
    // below must leave this handshake exactly as it was, so that a forged packet
    // cannot cancel one that is still in flight.
    MixKey chaining_key;
    MixKey hash;
    copy_into(chaining_key, chaining_key_.get());
    copy_into(hash, hash_.get());

    // Ci = KDF1(Ci, msg.ephemeral); Hi = HASH(Hi || msg.ephemeral)
    crypto::kdf1(chaining_key.mut(), chaining_key.get(), response->ephemeral);
    mix_hash(hash, response->ephemeral);

    // Ci = KDF1(Ci, DH(Ei^priv, Er^pub)); Ci = KDF1(Ci, DH(Si^priv, Er^pub))
    if (!mix_dh(chaining_key, ephemeral_private_.get(), response->ephemeral)) {
        return false;
    }
    if (!mix_dh(chaining_key, identity_.private_key(), response->ephemeral)) {
        return false;
    }

    // (Ci, tau, k) = KDF3(Ci, Q); Hi = HASH(Hi || tau); open msg.encrypted_nothing
    {
        SecureBuf<crypto::kHashSize> tau;
        SecureBuf<crypto::kKeySize> key;
        crypto::kdf3(chaining_key.mut(), tau.mut(), key.mut(), chaining_key.get(), zero_psk());
        mix_hash(hash, tau.get());

        // Zero plaintext, but the tag still authenticates every mixing step that
        // led here. This is what proves the responder holds the static private
        // key we encrypted to.
        if (!crypto::open({}, key.get(), 0, response->encrypted_nothing, hash.get())) {
            return false;
        }
        mix_hash(hash, response->encrypted_nothing);
    }

    crypto::kdf2(keys.send.mut(), keys.receive.mut(), chaining_key.get(), {});
    keys.local_index = local_index_;
    keys.peer_index = response->sender_index;

    std::copy(response->ephemeral.begin(), response->ephemeral.end(), peer_ephemeral_.begin());
    peer_index_ = response->sender_index;

    chaining_key_.wipe();
    hash_.wipe();
    ephemeral_private_.wipe();
    return true;
}

}  // namespace vpn::noise
