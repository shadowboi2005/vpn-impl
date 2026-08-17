// libFuzzer harness for the packet decoder.
//
// PLAN.md calls this the single highest-value C++-specific practice in the
// project, and the reason is narrow: decode() is the one function that runs on
// bytes an attacker chose, before anything has authenticated them. Everything
// it does is a bounds check, and a bounds check is exactly the kind of code that
// looks obviously correct while being off by one.
//
// Build:  cmake --preset fuzz && cmake --build build/fuzz
// Run:    build/fuzz/decode_fuzz -max_total_time=300 test/fuzz/corpus

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <variant>
#include <vector>

#include "wire.h"

namespace {

// Touch every field of a decoded message. Reading through each span is what
// turns a bad offset into an ASan report instead of a value nobody looked at.
uint64_t consume(const vpn::wire::Message& message) {
    uint64_t sum = 0;
    const auto add = [&sum](std::span<const uint8_t> bytes) {
        for (const uint8_t byte : bytes) {
            sum += byte;
        }
    };

    std::visit(
        [&](const auto& msg) {
            using T = std::decay_t<decltype(msg)>;
            if constexpr (std::is_same_v<T, vpn::wire::HandshakeInitiation>) {
                sum += msg.sender_index;
                add(msg.ephemeral);
                add(msg.encrypted_static);
                add(msg.encrypted_timestamp);
                add(msg.mac1);
                add(msg.mac2);
            } else if constexpr (std::is_same_v<T, vpn::wire::HandshakeResponse>) {
                sum += msg.sender_index;
                sum += msg.receiver_index;
                add(msg.ephemeral);
                add(msg.encrypted_nothing);
                add(msg.mac1);
                add(msg.mac2);
            } else if constexpr (std::is_same_v<T, vpn::wire::CookieReply>) {
                sum += msg.receiver_index;
                add(msg.nonce);
                add(msg.encrypted_cookie);
            } else {
                sum += msg.receiver_index;
                sum += msg.counter;
                add(msg.sealed);
            }
        },
        message);
    return sum;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::span<const uint8_t> input(data, size);

    if (const auto message = vpn::wire::decode(input)) {
        [[maybe_unused]] volatile uint64_t sink = consume(*message);

        // Re-encoding a message the decoder accepted must produce the same
        // bytes back. A decoder that reads the right field and an encoder that
        // writes the wrong one only disagree here.
        std::vector<uint8_t> round_trip(size);
        const auto written = std::visit(
            [&](const auto& msg) { return vpn::wire::encode(round_trip, msg); }, *message);
        if (written.has_value()) {
            if (written->size() != size ||
                !std::equal(written->begin(), written->end(), input.begin())) {
                __builtin_trap();
            }
        }
    }

    // The other attacker-controlled parser: the inner IPv4 length field, which
    // is what sizes the write to the TUN device.
    if (const auto length = vpn::wire::inner_packet_length(input)) {
        if (*length > size) {
            __builtin_trap();  // would be an out-of-bounds read downstream
        }
        [[maybe_unused]] volatile uint8_t last = input[*length - 1];
    }

    // The MAC accessors run on unvalidated bytes in Phase 4 and Phase 7.
    if (const auto range = vpn::wire::mac1_input(input)) {
        if (range->size() >= size) {
            __builtin_trap();
        }
    }
    if (const auto range = vpn::wire::mac2_input(input)) {
        if (range->size() >= size) {
            __builtin_trap();
        }
    }

    return 0;
}
