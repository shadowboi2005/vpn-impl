// libFuzzer harness for the handshake parser.
//
// decode_fuzz covers the framing. This one covers what happens *after* a message
// is well-formed: the responder does four scalar multiplications, two AEAD
// opens, a constant-time key comparison and a timestamp check, all driven by
// bytes an unauthenticated stranger chose. That is the deepest an attacker can
// push us before proving they know anything.
//
// Two properties are asserted, not just "does not crash":
//   1. Random bytes never authenticate. If read_initiation ever returns true
//      for input the fuzzer invented, the peer authentication is broken.
//   2. A rejected message leaves the handshake object untouched, so a forged
//      packet cannot cancel a handshake that is still in flight.
//
// Build:  cmake --preset fuzz && cmake --build build/fuzz
// Run:    build/fuzz/handshake_fuzz -max_total_time=300 test/fuzz/handshake_corpus

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "crypto.h"
#include "noise.h"
#include "wire.h"

namespace {

// Fixed keys, so a crash the fuzzer finds reproduces. Generating fresh ones per
// run would make every finding a one-off.
constexpr std::array<uint8_t, 32> kServerPrivate = {
    0x58, 0x9a, 0x1c, 0x30, 0x2b, 0x71, 0x64, 0x0e, 0x45, 0x3d, 0x77,
    0x11, 0x2c, 0x05, 0x6a, 0x38, 0x49, 0x6f, 0x18, 0x22, 0x7b, 0x54,
    0x0c, 0x63, 0x39, 0x50, 0x1a, 0x2e, 0x74, 0x6d, 0x08, 0x41,
};
constexpr std::array<uint8_t, 32> kClientPrivate = {
    0x30, 0x77, 0x11, 0x4a, 0x1f, 0x62, 0x58, 0x0d, 0x25, 0x36, 0x49,
    0x7c, 0x03, 0x5e, 0x68, 0x14, 0x2a, 0x71, 0x0b, 0x57, 0x33, 0x6c,
    0x19, 0x40, 0x2d, 0x75, 0x06, 0x51, 0x38, 0x1e, 0x64, 0x42,
};

struct Fixture {
    std::unique_ptr<vpn::noise::Identity> server;
    std::unique_ptr<vpn::noise::Identity> client;

    Fixture() {
        vpn::crypto::init();
        std::array<uint8_t, 32> server_public{};
        std::array<uint8_t, 32> client_public{};
        vpn::crypto::derive_public(server_public, kServerPrivate);
        vpn::crypto::derive_public(client_public, kClientPrivate);
        server = std::make_unique<vpn::noise::Identity>(kServerPrivate, client_public);
        client = std::make_unique<vpn::noise::Identity>(kClientPrivate, server_public);
    }
};

Fixture& fixture() {
    static Fixture instance;
    return instance;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Fixture& keys = fixture();
    const std::span<const uint8_t> input(data, size);

    // --- responder side: arbitrary bytes as a handshake initiation -----------
    {
        vpn::noise::Handshake server(*keys.server);
        vpn::noise::TimestampGuard guard;
        if (server.read_initiation(input, guard)) {
            // The fuzzer cannot know the client's static private key, so it
            // cannot produce a message that authenticates. Reaching here means
            // the static-key check or an AEAD tag is not doing its job.
            __builtin_trap();
        }
    }

    // --- initiator side: arbitrary bytes as a response ----------------------
    //
    // A real client with a real initiation in flight. The response is garbage,
    // so it must be rejected, and rejecting it must not disturb the handshake.
    {
        vpn::noise::Handshake client(*keys.client);
        std::array<uint8_t, 256> buffer{};
        const auto initiation = client.write_initiation(buffer);
        if (!initiation.has_value()) {
            __builtin_trap();  // writing our own initiation must never fail
        }

        vpn::noise::TransportKeys keys_out;
        if (client.read_response(input, keys_out)) {
            __builtin_trap();
        }

        // The handshake must have survived. Prove it by completing the exchange
        // with a genuine response: if the forged one had corrupted any state,
        // this would now fail.
        vpn::noise::Handshake server(*keys.server);
        vpn::noise::TimestampGuard guard;
        if (!server.read_initiation(*initiation, guard)) {
            __builtin_trap();
        }
        std::array<uint8_t, 256> reply{};
        vpn::noise::TransportKeys server_keys;
        const auto response = server.write_response(reply, server_keys);
        if (!response.has_value()) {
            __builtin_trap();
        }
        vpn::noise::TransportKeys client_keys;
        if (!client.read_response(*response, client_keys)) {
            __builtin_trap();  // a forged packet cancelled a live handshake
        }
        if (!vpn::crypto::equal(client_keys.send.get(), server_keys.receive.get())) {
            __builtin_trap();  // the two sides disagreed on a key
        }
    }

    return 0;
}
