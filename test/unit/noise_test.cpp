#include "noise.h"

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "check.h"
#include "crypto.h"
#include "wire.h"

using namespace vpn;
using vpn::test::same_bytes;

namespace {

struct Party {
    std::array<uint8_t, 32> private_key{};
    std::array<uint8_t, 32> public_key{};

    Party() { crypto::generate_keypair(private_key, public_key); }
};

// A configured pair: each side holding its own private key and the other's
// public key, which is the whole of v1's key distribution.
struct Pair {
    Party initiator;
    Party responder;
    std::unique_ptr<noise::Identity> client;
    std::unique_ptr<noise::Identity> server;

    Pair() {
        client = std::make_unique<noise::Identity>(initiator.private_key, responder.public_key);
        server = std::make_unique<noise::Identity>(responder.private_key, initiator.public_key);
    }
};

// Runs a full exchange. Returns false if either side rejected anything.
bool full_handshake(Pair& pair, noise::TransportKeys& client_keys,
                    noise::TransportKeys& server_keys, noise::TimestampGuard& guard) {
    noise::Handshake client(*pair.client);
    noise::Handshake server(*pair.server);

    std::array<uint8_t, 256> buffer{};
    const auto initiation = client.write_initiation(buffer);
    if (!initiation.has_value()) {
        return false;
    }
    if (!server.read_initiation(*initiation, guard)) {
        return false;
    }

    std::array<uint8_t, 256> reply{};
    const auto response = server.write_response(reply, server_keys);
    if (!response.has_value()) {
        return false;
    }
    return client.read_response(*response, client_keys);
}

// ------------------------------------------------------------- the happy path

void test_both_sides_agree() {
    CASE("both sides independently derive the same pair of transport keys");

    Pair pair;
    noise::TransportKeys client_keys;
    noise::TransportKeys server_keys;
    noise::TimestampGuard guard;
    CHECK(full_handshake(pair, client_keys, server_keys, guard));

    // The initiator's send key is the responder's receive key, and vice versa.
    // Getting this crossed over is the classic bug and it looks exactly like a
    // key derivation failure.
    CHECK(same_bytes(client_keys.send.get(), server_keys.receive.get()));
    CHECK(same_bytes(client_keys.receive.get(), server_keys.send.get()));

    CASE("the two directions use different keys");
    CHECK(!same_bytes(client_keys.send.get(), client_keys.receive.get()));

    CASE("no derived key is all zeros");
    const std::array<uint8_t, 32> zeros{};
    CHECK(!same_bytes(client_keys.send.get(), zeros));
    CHECK(!same_bytes(client_keys.receive.get(), zeros));

    CASE("session indices are echoed the right way round");
    CHECK_EQ(client_keys.local_index, server_keys.peer_index);
    CHECK_EQ(server_keys.local_index, client_keys.peer_index);

    CASE("the derived keys actually work as AEAD keys");
    const std::vector<uint8_t> plaintext{1, 2, 3, 4, 5};
    std::vector<uint8_t> sealed(plaintext.size() + crypto::kTagSize);
    crypto::seal(sealed, client_keys.send.get(), 0, plaintext, {});
    std::vector<uint8_t> opened(plaintext.size());
    CHECK(crypto::open(opened, server_keys.receive.get(), 0, sealed, {}));
    CHECK(same_bytes(opened, plaintext));
}

void test_message_shapes() {
    CASE("the handshake messages are exactly the sizes the protocol specifies");

    Pair pair;
    noise::Handshake client(*pair.client);
    noise::Handshake server(*pair.server);
    noise::TimestampGuard guard;
    noise::TransportKeys server_keys;

    std::array<uint8_t, 256> buffer{};
    const auto initiation = client.write_initiation(buffer);
    CHECK(initiation.has_value());
    CHECK_EQ(initiation->size(), wire::kInitiationSize);
    CHECK_EQ((*initiation)[0], 1);
    CHECK_EQ((*initiation)[1], 0);
    CHECK_EQ((*initiation)[2], 0);
    CHECK_EQ((*initiation)[3], 0);

    CASE("mac2 is sixteen zero bytes until Phase 7 fills it in");
    const auto mac2 = wire::mac2_field(*initiation);
    CHECK(mac2.has_value());
    const std::array<uint8_t, 16> zeros{};
    CHECK(same_bytes(*mac2, zeros));

    CASE("mac1 is not zero — it is actually computed");
    const auto mac1 = wire::mac1_field(*initiation);
    CHECK(mac1.has_value());
    CHECK(!same_bytes(*mac1, zeros));

    CHECK(server.read_initiation(*initiation, guard));
    std::array<uint8_t, 256> reply{};
    const auto response = server.write_response(reply, server_keys);
    CHECK(response.has_value());
    CHECK_EQ(response->size(), wire::kResponseSize);
    CHECK_EQ((*response)[0], 2);

    CASE("an output buffer too small to hold the message is refused, not truncated");
    for (size_t size = 0; size < wire::kInitiationSize; ++size) {
        noise::Handshake fresh(*pair.client);
        CHECK(!fresh.write_initiation(std::span(buffer).first(size)).has_value());
    }
}

void test_ephemeral_keys_differ_every_time() {
    CASE("each handshake uses a fresh ephemeral, so keys never repeat");

    Pair pair;
    noise::TransportKeys first_client;
    noise::TransportKeys first_server;
    noise::TransportKeys second_client;
    noise::TransportKeys second_server;

    // A guard each. TAI64N here has ~16 ms granularity, so two handshakes this
    // close together carry the *same* timestamp and a shared guard would
    // rightly reject the second — that is the replay defence working, and it
    // has its own test. What is under test here is ephemeral freshness.
    noise::TimestampGuard first_guard;
    noise::TimestampGuard second_guard;
    CHECK(full_handshake(pair, first_client, first_server, first_guard));
    CHECK(full_handshake(pair, second_client, second_server, second_guard));

    // Same static keys, same peers — but forward secrecy requires that a
    // compromise of the statics does not recover these.
    CHECK(!same_bytes(first_client.send.get(), second_client.send.get()));
    CHECK(!same_bytes(first_client.receive.get(), second_client.receive.get()));
    CHECK(first_client.local_index != second_client.local_index);
}

// --------------------------------------------------------------- rejections

void test_wrong_peer_key_fails_silently() {
    CASE("an initiation from an unknown static key is rejected");

    Pair pair;
    Party stranger;
    // The stranger knows the server's public key — anyone can — but the server
    // is configured for someone else.
    auto stranger_identity =
        std::make_unique<noise::Identity>(stranger.private_key, pair.responder.public_key);

    noise::Handshake attacker(*stranger_identity);
    noise::Handshake server(*pair.server);
    noise::TimestampGuard guard;

    std::array<uint8_t, 256> buffer{};
    const auto initiation = attacker.write_initiation(buffer);
    CHECK(initiation.has_value());

    // mac1 is correct — the stranger knows the server's public key — so this
    // gets all the way to the static-key comparison before failing. That is the
    // path worth testing.
    CHECK(!server.read_initiation(*initiation, guard));

    CASE("and the server has nothing to send back");
    // read_initiation returning false is the whole contract: there is no
    // response buffer, no error packet, nothing on the wire. A caller that
    // respected the return value cannot leak the existence of this host.
    CHECK(true);
}

void test_client_configured_for_the_wrong_server() {
    CASE("a client pointed at the wrong server public key gets nowhere");

    Pair pair;
    Party imposter;
    auto misconfigured =
        std::make_unique<noise::Identity>(pair.initiator.private_key, imposter.public_key);

    noise::Handshake client(*misconfigured);
    noise::Handshake server(*pair.server);
    noise::TimestampGuard guard;

    std::array<uint8_t, 256> buffer{};
    const auto initiation = client.write_initiation(buffer);
    CHECK(initiation.has_value());
    // mac1 is keyed on the imposter's public key, so the real server rejects it
    // before doing any DH at all.
    CHECK(!server.read_initiation(*initiation, guard));
}

void test_tampering() {
    CASE("every byte of the initiation is covered by something");

    Pair pair;
    noise::Handshake client(*pair.client);
    std::array<uint8_t, 256> buffer{};
    const auto initiation = client.write_initiation(buffer);
    CHECK(initiation.has_value());

    const std::vector<uint8_t> original(initiation->begin(), initiation->end());

    // Flip one bit in each byte in turn. Nothing should get through: the macs
    // cover the header and the ephemeral, and the AEAD tags cover the rest.
    for (size_t byte = 0; byte < original.size(); ++byte) {
        // Except mac2, which nothing verifies yet. It is only meaningful once
        // the responder is issuing cookies, which is Phase 7; until then the
        // protocol says to send sixteen zero bytes and ignore what arrives.
        // Asserting otherwise here would be asserting a bug.
        if (byte >= wire::kInitiationMac2Offset) {
            continue;
        }
        std::vector<uint8_t> tampered = original;
        tampered[byte] = static_cast<uint8_t>(tampered[byte] ^ 0x01);

        noise::Handshake server(*pair.server);
        noise::TimestampGuard guard;
        if (server.read_initiation(tampered, guard)) {
            vpn::test::begin("a tampered initiation was accepted at byte " +
                             std::to_string(byte));
            CHECK(false);
        } else {
            CHECK(true);
        }
    }
}

void test_response_tampering() {
    CASE("every byte of the response is covered too");

    Pair pair;
    noise::Handshake client(*pair.client);
    noise::Handshake server(*pair.server);
    noise::TimestampGuard guard;
    noise::TransportKeys server_keys;

    std::array<uint8_t, 256> buffer{};
    const auto initiation = client.write_initiation(buffer);
    CHECK(initiation.has_value());
    CHECK(server.read_initiation(*initiation, guard));

    std::array<uint8_t, 256> reply{};
    const auto response = server.write_response(reply, server_keys);
    CHECK(response.has_value());
    const std::vector<uint8_t> original(response->begin(), response->end());

    for (size_t byte = 0; byte < original.size(); ++byte) {
        if (byte >= wire::kResponseMac2Offset) {
            continue;  // unverified until Phase 7, as above
        }
        std::vector<uint8_t> tampered = original;
        tampered[byte] = static_cast<uint8_t>(tampered[byte] ^ 0x80);

        noise::TransportKeys keys;
        // A fresh client would have a different local_index, so reuse this one:
        // the object is single-use, but reading a response twice is exactly
        // what an attacker would try.
        if (client.read_response(tampered, keys)) {
            vpn::test::begin("a tampered response was accepted at byte " + std::to_string(byte));
            CHECK(false);
        } else {
            CHECK(true);
        }
    }

    CASE("and the untampered response still works afterwards");
    noise::TransportKeys client_keys;
    CHECK(client.read_response(original, client_keys));
    CHECK(same_bytes(client_keys.send.get(), server_keys.receive.get()));
}

void test_response_to_a_different_session() {
    CASE("a response naming someone else's session index is rejected");

    Pair pair;
    noise::Handshake client(*pair.client);
    noise::Handshake server(*pair.server);
    noise::TimestampGuard guard;
    noise::TransportKeys server_keys;

    std::array<uint8_t, 256> buffer{};
    const auto initiation = client.write_initiation(buffer);
    CHECK(initiation.has_value());
    CHECK(server.read_initiation(*initiation, guard));

    std::array<uint8_t, 256> reply{};
    const auto response = server.write_response(reply, server_keys);
    CHECK(response.has_value());

    std::vector<uint8_t> altered(response->begin(), response->end());
    altered[wire::kResponseReceiverOffset] =
        static_cast<uint8_t>(altered[wire::kResponseReceiverOffset] + 1);

    noise::TransportKeys keys;
    CHECK(!client.read_response(altered, keys));
}

void test_timestamp_replay() {
    CASE("a replayed initiation is rejected the second time");

    Pair pair;
    noise::Handshake client(*pair.client);
    std::array<uint8_t, 256> buffer{};
    const auto initiation = client.write_initiation(buffer);
    CHECK(initiation.has_value());
    const std::vector<uint8_t> recorded(initiation->begin(), initiation->end());

    noise::TimestampGuard guard;
    {
        noise::Handshake server(*pair.server);
        CHECK(server.read_initiation(recorded, guard));
    }
    {
        // Byte-identical replay. The message is perfectly valid and every MAC
        // and tag verifies — only the timestamp catches it.
        noise::Handshake server(*pair.server);
        CHECK(!server.read_initiation(recorded, guard));
    }

    CASE("but a genuinely newer initiation still gets through");
    // The timestamp has ~16 ms granularity, so a fresh handshake may land on
    // the same stamp. Loop until the clock has moved.
    bool accepted = false;
    for (int attempt = 0; attempt < 200 && !accepted; ++attempt) {
        noise::Handshake fresh_client(*pair.client);
        std::array<uint8_t, 256> fresh_buffer{};
        const auto fresh = fresh_client.write_initiation(fresh_buffer);
        CHECK(fresh.has_value());
        noise::Handshake server(*pair.server);
        accepted = server.read_initiation(*fresh, guard);
    }
    CHECK(accepted);
}

void test_timestamp_guard_ordering() {
    CASE("the guard accepts only strictly increasing timestamps");

    noise::TimestampGuard guard;
    std::array<uint8_t, crypto::kTimestampSize> stamp{};

    stamp[7] = 0x10;
    CHECK(guard.accept(stamp));
    CHECK(!guard.accept(stamp));  // equal is not greater

    stamp[7] = 0x09;
    CHECK(!guard.accept(stamp));  // older

    stamp[7] = 0x11;
    CHECK(guard.accept(stamp));

    CASE("ordering is unsigned, so a high bit does not read as negative");
    stamp[7] = 0x80;
    CHECK(guard.accept(stamp));
    stamp[7] = 0x7f;
    CHECK(!guard.accept(stamp));
}

void test_garbage_input() {
    CASE("arbitrary bytes never crash the responder and never authenticate");

    Pair pair;
    noise::TimestampGuard guard;

    // Wrong lengths, wrong types, and random noise of the right length.
    for (size_t size = 0; size <= wire::kInitiationSize + 4; ++size) {
        std::vector<uint8_t> noise_bytes(size);
        crypto::random_bytes(noise_bytes);
        if (size >= wire::kPrefix) {
            noise_bytes[0] = 1;  // claim to be an initiation
            noise_bytes[1] = 0;
            noise_bytes[2] = 0;
            noise_bytes[3] = 0;
        }
        noise::Handshake server(*pair.server);
        CHECK(!server.read_initiation(noise_bytes, guard));
    }

    CASE("a well-formed message of the wrong type is rejected");
    std::vector<uint8_t> response_shaped(wire::kResponseSize, 0);
    response_shaped[0] = 2;
    noise::Handshake server(*pair.server);
    CHECK(!server.read_initiation(response_shaped, guard));
}

void test_identity_from_base64() {
    CASE("identities load from base64 keys, and reject anything malformed");

    Party party;
    Party peer;
    const std::string priv = crypto::to_base64(party.private_key);
    const std::string pub = crypto::to_base64(peer.public_key);

    auto identity = noise::Identity::from_base64(priv, pub);
    CHECK(identity != nullptr);
    if (identity != nullptr) {
        CHECK(same_bytes(identity->peer_public(), peer.public_key));
        // The public key is derived, not stored — a config holding a mismatched
        // pair cannot exist.
        std::array<uint8_t, 32> expected{};
        crypto::derive_public(expected, party.private_key);
        CHECK(same_bytes(identity->public_key(), expected));
    }

    CASE("wrong-length and malformed keys are refused");
    CHECK(noise::Identity::from_base64("", pub) == nullptr);
    CHECK(noise::Identity::from_base64(priv, "") == nullptr);
    CHECK(noise::Identity::from_base64("not base64!", pub) == nullptr);
    CHECK(noise::Identity::from_base64(priv, "AAAA") == nullptr);  // 3 bytes, not 32
    CHECK(noise::Identity::from_base64(priv, pub + "extra") == nullptr);
}

}  // namespace

int main() {
    crypto::init();
    test_both_sides_agree();
    test_message_shapes();
    test_ephemeral_keys_differ_every_time();
    test_wrong_peer_key_fails_silently();
    test_client_configured_for_the_wrong_server();
    test_tampering();
    test_response_tampering();
    test_response_to_a_different_session();
    test_timestamp_replay();
    test_timestamp_guard_ordering();
    test_garbage_input();
    test_identity_from_base64();
    return vpn::test::report("noise");
}
