// libFuzzer harness for the transport receive path.
//
// decode_fuzz covers the framing and handshake_fuzz covers the handshake. This
// one covers what Phase 5 added: a counter chosen by an attacker indexing into
// the replay bitmap, an in-place AEAD open over attacker-supplied bytes, and the
// inner IPv4 length field deciding how much gets written to the TUN device.
//
// Three properties, not just "does not crash":
//   1. Random bytes never authenticate. The key is fixed and secret from the
//      fuzzer, so a tag it produced by chance would mean the AEAD is not doing
//      its job.
//   2. A rejected packet never advances the replay window. If it did, a single
//      forged packet with a high counter would make every genuine packet after
//      it look ancient — a one-datagram denial of service.
//   3. Whatever open() returns is inside the buffer it was given.
//
// Build:  cmake --preset fuzz && cmake --build build/fuzz
// Run:    build/fuzz/session_fuzz -max_total_time=300 test/fuzz/session_corpus

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <variant>
#include <vector>

#include "crypto.h"
#include "session.h"
#include "wire.h"

using namespace vpn;

namespace {

// Fixed, so a crash reproduces. The fuzzer never sees these bytes.
constexpr std::array<uint8_t, 32> kSendKey = {
    0x2f, 0x1a, 0x74, 0x0b, 0x53, 0x6c, 0x18, 0x40, 0x29, 0x7d, 0x05,
    0x61, 0x3e, 0x12, 0x58, 0x6b, 0x37, 0x0e, 0x49, 0x22, 0x70, 0x1d,
    0x64, 0x0a, 0x55, 0x33, 0x7b, 0x16, 0x4e, 0x08, 0x62, 0x2c,
};
constexpr std::array<uint8_t, 32> kReceiveKey = {
    0x63, 0x0c, 0x39, 0x51, 0x1b, 0x76, 0x2a, 0x45, 0x0f, 0x68, 0x30,
    0x57, 0x13, 0x7e, 0x24, 0x4b, 0x06, 0x6d, 0x35, 0x1f, 0x59, 0x42,
    0x78, 0x21, 0x0d, 0x66, 0x3c, 0x50, 0x17, 0x7a, 0x2e, 0x48,
};
constexpr uint32_t kLocalIndex = 0xa5a5a5a5;

struct Fixture {
    Session receiver;
    Session sender;

    Fixture() {
        vpn::crypto::init();
        // The sender's send key is the receiver's receive key, so the genuine
        // packets built below actually open.
        std::copy(kReceiveKey.begin(), kReceiveKey.end(), receiver.keys().receive.mut().begin());
        std::copy(kSendKey.begin(), kSendKey.end(), receiver.keys().send.mut().begin());
        std::copy(kReceiveKey.begin(), kReceiveKey.end(), sender.keys().send.mut().begin());
        std::copy(kSendKey.begin(), kSendKey.end(), sender.keys().receive.mut().begin());
        receiver.keys().local_index = kLocalIndex;
        receiver.keys().peer_index = kLocalIndex;
        sender.keys().local_index = kLocalIndex;
        sender.keys().peer_index = kLocalIndex;
        receiver.activate();
        sender.activate();
    }
};

// A well-formed IPv4 packet, to prove the tunnel still works after each input.
std::vector<uint8_t> genuine_packet(Session& sender) {
    std::vector<uint8_t> buffer(wire::kTransportHeaderSize + wire::padded_length(1420) +
                                wire::kTagSize);
    const size_t length = 40;
    std::span<uint8_t> payload = std::span(buffer).subspan(wire::kTransportHeaderSize, length);
    std::fill(payload.begin(), payload.end(), uint8_t{0x33});
    payload[0] = 0x45;
    payload[2] = 0;
    payload[3] = static_cast<uint8_t>(length);
    const auto datagram = sender.seal(buffer, length);
    if (!datagram.has_value()) {
        __builtin_trap();
    }
    return {datagram->begin(), datagram->end()};
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // A fresh pair per input: the replay window is stateful, and carrying it
    // between inputs would make findings depend on execution order.
    Fixture fixture;

    std::vector<uint8_t> input(data, data + size);
    const auto decoded = wire::decode(input);
    if (decoded.has_value()) {
        if (const auto* const transport = std::get_if<wire::TransportData>(&*decoded)) {
            const std::span<uint8_t> sealed =
                std::span(input).subspan(wire::kTransportHeaderSize);
            const auto plaintext = fixture.receiver.open(transport->counter, sealed);
            if (plaintext.has_value()) {
                // The fuzzer does not have the key, so it cannot have produced a
                // tag that verifies.
                __builtin_trap();
            }
        }
    }

    // Whatever that input was, a genuine packet must still get through. This is
    // what catches a forged counter advancing the replay window.
    const std::vector<uint8_t> real = genuine_packet(fixture.sender);
    std::vector<uint8_t> copy = real;
    const auto decoded_real = wire::decode(copy);
    if (!decoded_real.has_value()) {
        __builtin_trap();
    }
    const auto* const real_transport = std::get_if<wire::TransportData>(&*decoded_real);
    if (real_transport == nullptr) {
        __builtin_trap();
    }
    const std::span<uint8_t> real_sealed = std::span(copy).subspan(wire::kTransportHeaderSize);
    const auto opened = fixture.receiver.open(real_transport->counter, real_sealed);
    if (!opened.has_value()) {
        __builtin_trap();  // a rejected packet poisoned the session
    }
    if (opened->size() > real_sealed.size()) {
        __builtin_trap();  // the returned span escaped its buffer
    }

    return 0;
}
