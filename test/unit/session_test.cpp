#include "session.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <variant>
#include <vector>

#include "check.h"
#include "crypto.h"
#include "wire.h"

using namespace vpn;
using vpn::test::same_bytes;

namespace {

// A minimal well-formed IPv4 packet of the requested total length.
std::vector<uint8_t> ipv4_packet(size_t total_length, uint8_t marker = 0xaa) {
    std::vector<uint8_t> packet(total_length, marker);
    packet[0] = 0x45;
    packet[2] = static_cast<uint8_t>((total_length >> 8) & 0xff);
    packet[3] = static_cast<uint8_t>(total_length & 0xff);
    return packet;
}

// Two sessions wired to each other: A's send key is B's receive key.
struct Tunnel {
    Session a;
    Session b;

    Tunnel() {
        std::array<uint8_t, 32> one{};
        std::array<uint8_t, 32> two{};
        crypto::random_bytes(one);
        crypto::random_bytes(two);
        std::copy(one.begin(), one.end(), a.keys().send.mut().begin());
        std::copy(two.begin(), two.end(), a.keys().receive.mut().begin());
        std::copy(one.begin(), one.end(), b.keys().receive.mut().begin());
        std::copy(two.begin(), two.end(), b.keys().send.mut().begin());
        a.keys().local_index = 0x11111111;
        a.keys().peer_index = 0x22222222;
        b.keys().local_index = 0x22222222;
        b.keys().peer_index = 0x11111111;
        a.activate();
        b.activate();
    }
};

// Seals `packet` with `from` into a fresh buffer sized for this MTU.
std::vector<uint8_t> send(Session& from, const std::vector<uint8_t>& packet, size_t mtu = 1420) {
    std::vector<uint8_t> buffer(wire::kTransportHeaderSize + wire::padded_length(mtu) +
                                wire::kTagSize);
    std::copy(packet.begin(), packet.end(), buffer.begin() + wire::kTransportHeaderSize);
    const auto datagram = from.seal(buffer, packet.size());
    if (!datagram.has_value()) {
        return {};
    }
    return {datagram->begin(), datagram->end()};
}

// Feeds a datagram to `to`, returning the recovered inner packet.
std::optional<std::vector<uint8_t>> receive(Session& to, std::vector<uint8_t> datagram) {
    const auto decoded = wire::decode(datagram);
    if (!decoded.has_value()) {
        return std::nullopt;
    }
    const auto* const data = std::get_if<wire::TransportData>(&*decoded);
    if (data == nullptr) {
        return std::nullopt;
    }
    const uint64_t counter = data->counter;
    const std::span<uint8_t> sealed =
        std::span(datagram).subspan(wire::kTransportHeaderSize);
    const auto plaintext = to.open(counter, sealed);
    if (!plaintext.has_value()) {
        return std::nullopt;
    }
    return std::vector<uint8_t>(plaintext->begin(), plaintext->end());
}

// -------------------------------------------------------------- replay window

void test_window_basics() {
    CASE("a fresh window accepts anything and remembers it");

    ReplayWindow window;
    CHECK(window.acceptable(0));
    window.accept(0);
    CHECK(!window.acceptable(0));

    CASE("counters advance and duplicates are refused");
    for (uint64_t counter = 1; counter < 100; ++counter) {
        CHECK(window.acceptable(counter));
        window.accept(counter);
        CHECK(!window.acceptable(counter));
    }
    CHECK_EQ(window.highest(), 99u);

    CASE("out-of-order delivery inside the window is accepted");
    ReplayWindow reordered;
    reordered.accept(100);
    for (uint64_t counter : {99u, 50u, 1u, 0u}) {
        CHECK(reordered.acceptable(counter));
        reordered.accept(counter);
        CHECK(!reordered.acceptable(counter));
    }
    CHECK_EQ(reordered.highest(), 100u);
}

void test_window_edges() {
    CASE("the window is exactly kBits wide, and its boundary is not off by one");

    ReplayWindow window;
    const uint64_t base = ReplayWindow::kBits * 4;  // well past the first wrap
    window.accept(base);

    // The oldest counter still inside the window.
    CHECK(window.acceptable(base - (ReplayWindow::kBits - 1)));
    // One older than that has fallen out.
    CHECK(!window.acceptable(base - ReplayWindow::kBits));
    CHECK(!window.acceptable(base - ReplayWindow::kBits - 1));
    CHECK(!window.acceptable(0));

    CASE("a jump of exactly the window width clears everything behind it");
    // This is the gap where a word-at-a-time implementation shifts a uint64_t
    // by 64 or more, which is undefined behaviour that UBSan would catch here.
    for (uint64_t gap : {uint64_t{1}, uint64_t{63}, uint64_t{64}, uint64_t{65},
                         uint64_t{ReplayWindow::kBits - 1}, uint64_t{ReplayWindow::kBits},
                         uint64_t{ReplayWindow::kBits + 1}, uint64_t{100000}}) {
        ReplayWindow fresh;
        const uint64_t start = ReplayWindow::kBits * 8;
        fresh.accept(start);
        const uint64_t next = start + gap;
        CHECK(fresh.acceptable(next));
        fresh.accept(next);
        CHECK_EQ(fresh.highest(), next);
        // The one we jumped from is still remembered if it is still in range.
        if (gap < ReplayWindow::kBits) {
            CHECK(!fresh.acceptable(start));
        }
        // And a counter in the skipped gap is fresh, not a replay.
        if (gap > 1) {
            CHECK(fresh.acceptable(next - 1));
        }
    }
}

void test_window_wraps_around_the_bitmap() {
    CASE("indices wrap modulo kBits without aliasing an old counter");

    ReplayWindow window;
    window.accept(5);
    // Exactly one window later maps to the same bit. It must not read as a
    // replay just because the bitmap slot is shared.
    CHECK(window.acceptable(5 + ReplayWindow::kBits));
    window.accept(5 + ReplayWindow::kBits);
    CHECK(!window.acceptable(5 + ReplayWindow::kBits));
    // And the original is now out of range.
    CHECK(!window.acceptable(5));
}

void test_window_rejects_exhausted_counters() {
    CASE("counters at or past the reject limit are refused");

    ReplayWindow window;
    CHECK(!window.acceptable(kRejectAfterMessages));
    CHECK(!window.acceptable(kRejectAfterMessages + 1));
    CHECK(!window.acceptable(~uint64_t{0}));
    CHECK(window.acceptable(kRejectAfterMessages - 1));

    CASE("and the send side refuses to use one");
    CHECK(Session::counter_usable(0));
    CHECK(Session::counter_usable(kRejectAfterMessages - 1));
    CHECK(!Session::counter_usable(kRejectAfterMessages));
    CHECK(!Session::counter_usable(~uint64_t{0}));

    CASE("the limit is 2^64 - 2^13 - 1, as the whitepaper states");
    CHECK(kRejectAfterMessages == 0xffffffffffffdfffULL);
}

void test_window_never_advances_on_a_rejected_counter() {
    CASE("acceptable() is a pure query and moves nothing");

    ReplayWindow window;
    window.accept(1000);
    for (int i = 0; i < 100; ++i) {
        (void)window.acceptable(9'000'000);
    }
    CHECK_EQ(window.highest(), 1000u);
    // The high counter is still fresh, because asking about it changed nothing.
    CHECK(window.acceptable(9'000'000));
}

// -------------------------------------------------------------------- session

void test_round_trip() {
    CASE("a packet survives seal and open unchanged");

    Tunnel tunnel;
    for (size_t length : {20u, 21u, 32u, 64u, 100u, 1419u, 1420u}) {
        const std::vector<uint8_t> packet = ipv4_packet(length);
        const std::vector<uint8_t> datagram = send(tunnel.a, packet);
        CHECK(!datagram.empty());

        // Padded to a multiple of 16, plus header and tag.
        CHECK_EQ(datagram.size(),
                 wire::kTransportHeaderSize + wire::padded_length(length) + wire::kTagSize);

        const auto received = receive(tunnel.b, datagram);
        CHECK(received.has_value());
        if (received.has_value()) {
            CHECK(same_bytes(*received, packet));
        }
    }
}

void test_plaintext_is_not_on_the_wire() {
    CASE("the sealed datagram does not contain the packet it carries");

    Tunnel tunnel;
    std::vector<uint8_t> packet = ipv4_packet(200);
    // A recognisable run, the way ping's payload is recognisable.
    for (size_t i = 20; i < packet.size(); ++i) {
        packet[i] = static_cast<uint8_t>(i);
    }
    const std::vector<uint8_t> datagram = send(tunnel.a, packet);

    const auto found = std::search(datagram.begin(), datagram.end(),
                                   packet.begin() + 20, packet.end());
    CHECK(found == datagram.end());  // the payload run appears nowhere in the ciphertext
}

void test_replay_is_dropped() {
    CASE("an unmodified captured packet is dropped when replayed");

    Tunnel tunnel;
    const std::vector<uint8_t> packet = ipv4_packet(64);
    const std::vector<uint8_t> datagram = send(tunnel.a, packet);

    CHECK(receive(tunnel.b, datagram).has_value());
    CHECK(!receive(tunnel.b, datagram).has_value());
    CHECK(!receive(tunnel.b, datagram).has_value());

    CASE("and the tunnel still works afterwards");
    const std::vector<uint8_t> next = send(tunnel.a, packet);
    CHECK(receive(tunnel.b, next).has_value());
}

void test_tampering_is_dropped() {
    CASE("every single-bit flip in a sealed datagram is rejected");

    Tunnel tunnel;
    const std::vector<uint8_t> packet = ipv4_packet(64);
    const std::vector<uint8_t> original = send(tunnel.a, packet);

    size_t rejected = 0;
    size_t attempted = 0;
    for (size_t byte = wire::kTransportHeaderSize; byte < original.size(); ++byte) {
        for (int bit = 0; bit < 8; ++bit) {
            std::vector<uint8_t> tampered = original;
            tampered[byte] = static_cast<uint8_t>(tampered[byte] ^ (1 << bit));
            ++attempted;
            // A fresh receiver each time: the point is that the forgery fails,
            // not that it fails only because an earlier one moved the window.
            Tunnel fresh_pair;
            std::copy(tunnel.b.keys().receive.get().begin(),
                      tunnel.b.keys().receive.get().end(),
                      fresh_pair.b.keys().receive.mut().begin());
            fresh_pair.b.activate();
            if (!receive(fresh_pair.b, tampered).has_value()) {
                ++rejected;
            }
        }
    }
    CHECK_EQ(rejected, attempted);

    CASE("a flipped counter is rejected too — the counter is the nonce");
    for (size_t byte = wire::kTransportCounterOffset;
         byte < wire::kTransportCounterOffset + 8; ++byte) {
        std::vector<uint8_t> tampered = original;
        tampered[byte] = static_cast<uint8_t>(tampered[byte] ^ 0x01);
        Tunnel fresh_pair;
        std::copy(tunnel.b.keys().receive.get().begin(), tunnel.b.keys().receive.get().end(),
                  fresh_pair.b.keys().receive.mut().begin());
        fresh_pair.b.activate();
        CHECK(!receive(fresh_pair.b, tampered).has_value());
    }

    CASE("and the genuine packet still opens on an untouched receiver");
    CHECK(receive(tunnel.b, original).has_value());
}

void test_forgery_does_not_advance_the_window() {
    CASE("a rejected packet leaves the window where it was");

    Tunnel tunnel;
    const std::vector<uint8_t> packet = ipv4_packet(64);

    // Send three, deliver only the first.
    const std::vector<uint8_t> first = send(tunnel.a, packet);
    const std::vector<uint8_t> second = send(tunnel.a, packet);
    const std::vector<uint8_t> third = send(tunnel.a, packet);
    CHECK(receive(tunnel.b, first).has_value());

    // Forge something claiming a far-future counter. If the window advanced on
    // it, the real packets that follow would be rejected as ancient.
    std::vector<uint8_t> forged = third;
    forged[wire::kTransportCounterOffset + 2] = 0xff;
    forged[wire::kTransportCounterOffset + 3] = 0xff;
    CHECK(!receive(tunnel.b, forged).has_value());

    CHECK(receive(tunnel.b, second).has_value());
    CHECK(receive(tunnel.b, third).has_value());
}

void test_reordering_survives() {
    CASE("packets delivered out of order all arrive");

    Tunnel tunnel;
    std::vector<std::vector<uint8_t>> datagrams;
    for (size_t i = 0; i < 200; ++i) {
        datagrams.push_back(send(tunnel.a, ipv4_packet(40, static_cast<uint8_t>(i))));
    }

    // Reverse order: the worst case the window has to tolerate.
    size_t delivered = 0;
    for (auto it = datagrams.rbegin(); it != datagrams.rend(); ++it) {
        if (receive(tunnel.b, *it).has_value()) {
            ++delivered;
        }
    }
    CHECK_EQ(delivered, datagrams.size());

    CASE("and every one of them is a replay the second time");
    size_t replayed = 0;
    for (const auto& datagram : datagrams) {
        if (!receive(tunnel.b, datagram).has_value()) {
            ++replayed;
        }
    }
    CHECK_EQ(replayed, datagrams.size());
}

void test_keepalive() {
    CASE("an empty packet seals, opens, and comes back empty");

    Tunnel tunnel;
    const std::vector<uint8_t> datagram = send(tunnel.a, {});
    CHECK_EQ(datagram.size(), wire::kTransportMinSize);

    const auto received = receive(tunnel.b, datagram);
    CHECK(received.has_value());
    if (received.has_value()) {
        CHECK(received->empty());
    }
}

void test_wrong_key() {
    CASE("a session with the wrong key opens nothing");

    Tunnel tunnel;
    Tunnel stranger;
    const std::vector<uint8_t> datagram = send(tunnel.a, ipv4_packet(64));
    CHECK(!receive(stranger.b, datagram).has_value());
}

void test_inactive_session() {
    CASE("an inactive session neither seals nor opens");

    Session idle;
    std::vector<uint8_t> buffer(2048);
    CHECK(!idle.seal(buffer, 64).has_value());
    CHECK(!idle.open(0, std::span(buffer).first(64)).has_value());
}

void test_counters_increment() {
    CASE("the send counter advances by exactly one per packet, from zero");

    Tunnel tunnel;
    CHECK_EQ(tunnel.a.sent(), 0u);
    for (uint64_t i = 0; i < 50; ++i) {
        const std::vector<uint8_t> datagram = send(tunnel.a, ipv4_packet(40));
        const auto decoded = wire::decode(datagram);
        CHECK(decoded.has_value());
        const auto* const data = std::get_if<wire::TransportData>(&*decoded);
        CHECK(data != nullptr);
        if (data != nullptr) {
            CHECK(data->counter == i);
            CHECK_EQ(data->receiver_index, 0x22222222u);
        }
    }
    CHECK_EQ(tunnel.a.sent(), 50u);
}

void test_padding_is_zero_and_hidden() {
    CASE("padding does not leak the previous packet's tail");

    Tunnel tunnel;
    // A long packet first, then a short one through the same buffer.
    std::vector<uint8_t> buffer(wire::kTransportHeaderSize + wire::padded_length(1420) +
                                wire::kTagSize);

    const std::vector<uint8_t> secret = ipv4_packet(400, 0x5a);
    std::copy(secret.begin(), secret.end(), buffer.begin() + wire::kTransportHeaderSize);
    CHECK(tunnel.a.seal(buffer, secret.size()).has_value());

    // Reuse the same buffer for a 21-byte packet, which pads to 32. The 11 pad
    // bytes must be zero, not whatever the 400-byte packet left there.
    const std::vector<uint8_t> small = ipv4_packet(21, 0x11);
    std::copy(small.begin(), small.end(), buffer.begin() + wire::kTransportHeaderSize);
    const auto datagram = tunnel.a.seal(buffer, small.size());
    CHECK(datagram.has_value());

    std::vector<uint8_t> copy(datagram->begin(), datagram->end());
    const auto opened = receive(tunnel.b, copy);
    CHECK(opened.has_value());
    if (opened.has_value()) {
        CHECK(same_bytes(*opened, small));
    }
}

}  // namespace

int main() {
    crypto::init();
    test_window_basics();
    test_window_edges();
    test_window_wraps_around_the_bitmap();
    test_window_rejects_exhausted_counters();
    test_window_never_advances_on_a_rejected_counter();
    test_round_trip();
    test_plaintext_is_not_on_the_wire();
    test_replay_is_dropped();
    test_tampering_is_dropped();
    test_forgery_does_not_advance_the_window();
    test_reordering_survives();
    test_keepalive();
    test_wrong_key();
    test_inactive_session();
    test_counters_increment();
    test_padding_is_zero_and_hidden();
    return vpn::test::report("session");
}
