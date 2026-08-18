#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "crypto.h"
#include "secure_buf.h"

// Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s, as specified in the WireGuard
// whitepaper §5.4. Every mixing step here is transcribed from that document in
// the order it gives; none of it is a design decision of ours, and none of it
// may be reordered or simplified.
//
// The PSK is the all-zero key. PSK mode is out of scope, but the mixing step
// stays so the construction matches the spec — and so the transport keys come
// out identical to a real WireGuard peer's.

namespace vpn::noise {

// The all-zero preshared key.
inline constexpr size_t kPresharedKeySize = 32;

// What a completed handshake produces. Two keys, never one: the same key in
// both directions would let an attacker replay a packet back at its sender.
struct TransportKeys {
    SecureBuf<crypto::kKeySize> send;
    SecureBuf<crypto::kKeySize> receive;
    // Ours, which the peer echoes in receiver_index so packets find this
    // session without trial decryption. And theirs, for the packets we send.
    uint32_t local_index = 0;
    uint32_t peer_index = 0;
};

// Long-term identity: our static keypair and the one peer we will talk to.
//
// Non-copyable and non-movable, because it owns a LockedKey — the private key
// lives in guarded, mlocked memory for the life of the process. Construct it
// once and pass it by reference.
class Identity {
public:
    Identity(crypto::Key private_key, crypto::Key peer_public);

    // Both keys base64, as `wg` writes them. Nullptr if either fails to decode
    // or is not 32 bytes.
    static std::unique_ptr<Identity> from_base64(std::string_view private_key,
                                                 std::string_view peer_public);

    Identity(const Identity&) = delete;
    Identity& operator=(const Identity&) = delete;

    [[nodiscard]] crypto::Key private_key() const noexcept { return private_key_.get(); }
    [[nodiscard]] crypto::Key public_key() const noexcept { return public_key_; }
    [[nodiscard]] crypto::Key peer_public() const noexcept { return peer_public_; }

    // mac1 is keyed on HASH(LABEL_MAC1 || <recipient's static public key>).
    // So: sending, key on the peer's; receiving, key on our own.
    [[nodiscard]] crypto::Key sending_mac1_key() const noexcept { return peer_mac1_key_; }
    [[nodiscard]] crypto::Key receiving_mac1_key() const noexcept { return own_mac1_key_; }

private:
    LockedKey private_key_;
    std::array<uint8_t, crypto::kKeySize> public_key_{};
    std::array<uint8_t, crypto::kKeySize> peer_public_{};
    std::array<uint8_t, crypto::kKeySize> own_mac1_key_{};
    std::array<uint8_t, crypto::kKeySize> peer_mac1_key_{};
};

// Loads a private key from a file — base64, one line, exactly as `wg` writes
// one — and the peer's public key from a base64 string. Public keys are not
// secret, so passing one on a command line is fine; private keys are, so that
// one comes from a file.
//
// Nullptr on any problem, with the reason on stderr. Warns, but does not
// refuse, if the key file is readable by anyone but its owner.
std::unique_ptr<Identity> load_identity(const std::string& private_key_path,
                                        std::string_view peer_public_base64);

// The handshake replay defence.
//
// Every initiation carries an encrypted TAI64N timestamp. The responder keeps
// the greatest one it has seen from this peer and rejects anything not strictly
// greater. Without it, a recorded initiation can be replayed forever and the
// responder will keep doing expensive DH for it.
class TimestampGuard {
public:
    // Records and accepts only a strictly greater timestamp.
    [[nodiscard]] bool accept(std::span<const uint8_t, crypto::kTimestampSize> timestamp);

private:
    std::array<uint8_t, crypto::kTimestampSize> greatest_{};
    bool seen_ = false;
};

// One handshake attempt. An object is good for exactly one exchange in one
// direction; start a new one to retry.
//
// Failure is always a silent `false` or `nullopt`. A handshake from an unknown
// or wrong peer must produce no packet on the wire at all — anything else is an
// oracle telling a scanner that something is listening here.
class Handshake {
public:
    explicit Handshake(const Identity& identity) : identity_(identity) {}

    Handshake(const Handshake&) = delete;
    Handshake& operator=(const Handshake&) = delete;

    // --- initiator ---------------------------------------------------------

    // Writes a 148-byte handshake initiation. Nullopt only if `out` is too
    // small or a DH fails.
    std::optional<std::span<uint8_t>> write_initiation(std::span<uint8_t> out);

    // Consumes a 92-byte response and fills `keys`. False on anything wrong.
    //
    // A rejected message leaves this object exactly as it was, so a forged
    // response cannot destroy a handshake that is still in flight. Anyone can
    // send us 92 bytes of noise; being able to cancel a pending handshake with
    // them would be a denial of service that costs the attacker nothing.
    [[nodiscard]] bool read_response(std::span<const uint8_t> message, TransportKeys& keys);

    // --- responder ---------------------------------------------------------

    // Consumes a 148-byte initiation, authenticating the peer. False if the
    // message is malformed, mac1 is wrong, the static key inside is not the
    // peer we expect, or the timestamp is a replay.
    [[nodiscard]] bool read_initiation(std::span<const uint8_t> message, TimestampGuard& guard);

    // Writes a 92-byte response and fills `keys`. Only valid after a successful
    // read_initiation.
    std::optional<std::span<uint8_t>> write_response(std::span<uint8_t> out, TransportKeys& keys);

    [[nodiscard]] uint32_t local_index() const noexcept { return local_index_; }
    [[nodiscard]] uint32_t peer_index() const noexcept { return peer_index_; }

private:
    const Identity& identity_;

    SecureBuf<crypto::kHashSize> chaining_key_;
    SecureBuf<crypto::kHashSize> hash_;
    SecureBuf<crypto::kKeySize> ephemeral_private_;
    std::array<uint8_t, crypto::kKeySize> ephemeral_public_{};
    std::array<uint8_t, crypto::kKeySize> peer_ephemeral_{};

    uint32_t local_index_ = 0;
    uint32_t peer_index_ = 0;
};

}  // namespace vpn::noise
