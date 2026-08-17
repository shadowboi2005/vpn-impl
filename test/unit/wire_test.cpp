#include "wire.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <numeric>
#include <string>
#include <vector>

#include "check.h"

using namespace vpn::wire;
using vpn::test::same_bytes;

namespace {

// Distinguishable filler, so a field written to the wrong offset shows up as a
// value mismatch rather than a run of identical bytes that happens to match.
std::vector<uint8_t> filled(size_t size, uint8_t seed) {
    std::vector<uint8_t> bytes(size);
    for (size_t i = 0; i < size; ++i) {
        bytes[i] = static_cast<uint8_t>(seed + i);
    }
    return bytes;
}

template <size_t N>
std::span<const uint8_t, N> fixed(const std::vector<uint8_t>& bytes) {
    return std::span<const uint8_t>(bytes).first<N>();
}

// ------------------------------------------------------------ round trips ---

void test_initiation_round_trip() {
    CASE("handshake initiation encodes and decodes back to the same fields");

    const std::vector<uint8_t> ephemeral = filled(kPublicKeySize, 0x10);
    const std::vector<uint8_t> encrypted_static = filled(kEncryptedStaticSize, 0x40);
    const std::vector<uint8_t> timestamp = filled(kEncryptedTimestampSize, 0x80);
    const std::vector<uint8_t> mac1 = filled(kMacSize, 0xa0);
    const std::vector<uint8_t> mac2 = filled(kMacSize, 0xc0);

    const HandshakeInitiation original{
        .sender_index = 0xdeadbeef,
        .ephemeral = fixed<kPublicKeySize>(ephemeral),
        .encrypted_static = fixed<kEncryptedStaticSize>(encrypted_static),
        .encrypted_timestamp = fixed<kEncryptedTimestampSize>(timestamp),
        .mac1 = fixed<kMacSize>(mac1),
        .mac2 = fixed<kMacSize>(mac2),
    };

    std::array<uint8_t, kInitiationSize> buffer{};
    const auto written = encode(buffer, original);
    CHECK(written.has_value());
    CHECK_EQ(written->size(), kInitiationSize);

    // The layout itself, not just the round trip: a self-consistent encoder and
    // decoder that agree on the wrong offsets would pass otherwise.
    CHECK_EQ(buffer[0], static_cast<uint8_t>(Type::handshake_initiation));
    CHECK_EQ(buffer[1], 0);
    CHECK_EQ(buffer[2], 0);
    CHECK_EQ(buffer[3], 0);
    CHECK_EQ(buffer[4], 0xef);  // little-endian sender_index
    CHECK_EQ(buffer[7], 0xde);

    const auto decoded = decode(buffer);
    CHECK(decoded.has_value());
    const auto* const got = std::get_if<HandshakeInitiation>(&*decoded);
    CHECK(got != nullptr);
    if (got == nullptr) {
        return;
    }
    CHECK_EQ(got->sender_index, 0xdeadbeefu);
    CHECK(same_bytes(got->ephemeral, ephemeral));
    CHECK(same_bytes(got->encrypted_static, encrypted_static));
    CHECK(same_bytes(got->encrypted_timestamp, timestamp));
    CHECK(same_bytes(got->mac1, mac1));
    CHECK(same_bytes(got->mac2, mac2));
}

void test_response_round_trip() {
    CASE("handshake response encodes and decodes back to the same fields");

    const std::vector<uint8_t> ephemeral = filled(kPublicKeySize, 0x11);
    const std::vector<uint8_t> nothing = filled(kEncryptedNothingSize, 0x50);
    const std::vector<uint8_t> mac1 = filled(kMacSize, 0x90);
    const std::vector<uint8_t> mac2 = filled(kMacSize, 0xb0);

    const HandshakeResponse original{
        .sender_index = 0x01020304,
        .receiver_index = 0x0a0b0c0d,
        .ephemeral = fixed<kPublicKeySize>(ephemeral),
        .encrypted_nothing = fixed<kEncryptedNothingSize>(nothing),
        .mac1 = fixed<kMacSize>(mac1),
        .mac2 = fixed<kMacSize>(mac2),
    };

    std::array<uint8_t, kResponseSize> buffer{};
    const auto written = encode(buffer, original);
    CHECK(written.has_value());
    CHECK_EQ(written->size(), kResponseSize);
    CHECK_EQ(buffer[0], static_cast<uint8_t>(Type::handshake_response));

    const auto decoded = decode(buffer);
    CHECK(decoded.has_value());
    const auto* const got = std::get_if<HandshakeResponse>(&*decoded);
    CHECK(got != nullptr);
    if (got == nullptr) {
        return;
    }
    CHECK_EQ(got->sender_index, 0x01020304u);
    CHECK_EQ(got->receiver_index, 0x0a0b0c0du);
    CHECK(same_bytes(got->ephemeral, ephemeral));
    CHECK(same_bytes(got->encrypted_nothing, nothing));
    CHECK(same_bytes(got->mac1, mac1));
    CHECK(same_bytes(got->mac2, mac2));
}

void test_cookie_round_trip() {
    CASE("cookie reply encodes and decodes back to the same fields");

    const std::vector<uint8_t> nonce = filled(kCookieNonceSize, 0x20);
    const std::vector<uint8_t> cookie = filled(kEncryptedCookieSize, 0x60);

    const CookieReply original{
        .receiver_index = 0xffffffff,
        .nonce = fixed<kCookieNonceSize>(nonce),
        .encrypted_cookie = fixed<kEncryptedCookieSize>(cookie),
    };

    std::array<uint8_t, kCookieReplySize> buffer{};
    const auto written = encode(buffer, original);
    CHECK(written.has_value());
    CHECK_EQ(written->size(), kCookieReplySize);

    const auto decoded = decode(buffer);
    CHECK(decoded.has_value());
    const auto* const got = std::get_if<CookieReply>(&*decoded);
    CHECK(got != nullptr);
    if (got == nullptr) {
        return;
    }
    CHECK_EQ(got->receiver_index, 0xffffffffu);
    CHECK(same_bytes(got->nonce, nonce));
    CHECK(same_bytes(got->encrypted_cookie, cookie));
}

void test_transport_round_trip() {
    CASE("transport data encodes and decodes back to the same fields");

    const std::vector<uint8_t> sealed = filled(64 + kTagSize, 0x30);
    const TransportData original{
        .receiver_index = 0x11223344,
        // Deliberately large: the counter is a uint64_t and a 32-bit truncation
        // in the serializer would survive any small value.
        .counter = 0x0123456789abcdefULL,
        .sealed = sealed,
    };

    std::vector<uint8_t> buffer(kTransportHeaderSize + sealed.size());
    const auto written = encode(buffer, original);
    CHECK(written.has_value());
    CHECK_EQ(written->size(), buffer.size());
    CHECK_EQ(buffer[8], 0xef);   // little-endian counter, low byte first
    CHECK_EQ(buffer[15], 0x01);  // and high byte last

    const auto decoded = decode(buffer);
    CHECK(decoded.has_value());
    const auto* const got = std::get_if<TransportData>(&*decoded);
    CHECK(got != nullptr);
    if (got == nullptr) {
        return;
    }
    CHECK_EQ(got->receiver_index, 0x11223344u);
    CHECK(got->counter == 0x0123456789abcdefULL);
    CHECK(same_bytes(got->sealed, sealed));
}

// ------------------------------------------------------------- rejections ---

// A valid message of each type, to mutate.
std::vector<uint8_t> valid_message(Type type) {
    switch (type) {
        case Type::handshake_initiation: {
            std::vector<uint8_t> m = filled(kInitiationSize, 0x01);
            m[0] = 1;
            m[1] = m[2] = m[3] = 0;
            return m;
        }
        case Type::handshake_response: {
            std::vector<uint8_t> m = filled(kResponseSize, 0x02);
            m[0] = 2;
            m[1] = m[2] = m[3] = 0;
            return m;
        }
        case Type::cookie_reply: {
            std::vector<uint8_t> m = filled(kCookieReplySize, 0x03);
            m[0] = 3;
            m[1] = m[2] = m[3] = 0;
            return m;
        }
        case Type::transport_data: {
            std::vector<uint8_t> m = filled(kTransportMinSize + 16, 0x04);
            m[0] = 4;
            m[1] = m[2] = m[3] = 0;
            return m;
        }
    }
    return {};
}

void test_truncation() {
    CASE("every prefix of a valid message is rejected");

    for (const Type type : {Type::handshake_initiation, Type::handshake_response,
                            Type::cookie_reply, Type::transport_data}) {
        const std::vector<uint8_t> message = valid_message(type);
        CHECK(decode(message).has_value());

        // Every length from zero up to one short of the real thing. This covers
        // each field boundary without having to enumerate them.
        for (size_t length = 0; length < message.size(); ++length) {
            const bool accepted = decode(std::span(message).first(length)).has_value();
            // Transport data is the one variable-length message: any prefix at
            // or above the minimum is legitimately a shorter valid message.
            const bool should_accept =
                type == Type::transport_data && length >= kTransportMinSize;
            if (accepted != should_accept) {
                CHECK_EQ(static_cast<int>(accepted), static_cast<int>(should_accept));
                std::fprintf(stderr, "  type %d truncated to %zu bytes\n",
                             static_cast<int>(type), length);
            } else {
                CHECK(true);
            }
        }
    }
}

void test_oversize() {
    CASE("a fixed-length message with extra bytes appended is rejected");

    for (const Type type :
         {Type::handshake_initiation, Type::handshake_response, Type::cookie_reply}) {
        std::vector<uint8_t> message = valid_message(type);
        message.push_back(0);
        CHECK(!decode(message).has_value());
    }

    // Transport data has no upper bound in the framing itself — the MTU check
    // in the relay is what bounds it.
    std::vector<uint8_t> transport = valid_message(Type::transport_data);
    transport.push_back(0);
    CHECK(decode(transport).has_value());
}

void test_reserved_bytes() {
    CASE("a nonzero reserved byte is rejected, in any of the three positions");

    for (const Type type : {Type::handshake_initiation, Type::handshake_response,
                            Type::cookie_reply, Type::transport_data}) {
        for (size_t position = 1; position <= 3; ++position) {
            std::vector<uint8_t> message = valid_message(type);
            message[position] = 0x01;
            CHECK(!decode(message).has_value());
        }
    }
}

void test_unknown_types() {
    CASE("every type byte outside 1..4 is rejected");

    for (int type = 0; type < 256; ++type) {
        if (type >= 1 && type <= 4) {
            continue;
        }
        // Long enough that no length check can be the reason for the rejection.
        std::vector<uint8_t> message(kInitiationSize, 0);
        message[0] = static_cast<uint8_t>(type);
        CHECK(!decode(message).has_value());
    }
}

void test_minimum_transport() {
    CASE("a 32-byte transport message is a valid empty keepalive");

    std::vector<uint8_t> message(kTransportMinSize, 0);
    message[0] = 4;
    const auto decoded = decode(message);
    CHECK(decoded.has_value());
    const auto* const got = std::get_if<TransportData>(&*decoded);
    CHECK(got != nullptr);
    if (got != nullptr) {
        CHECK_EQ(got->sealed.size(), kTagSize);
        // Nothing but the tag: the plaintext was empty.
        CHECK_EQ(got->sealed.size() - kTagSize, 0u);
    }

    // One byte short is not.
    message.pop_back();
    CHECK(!decode(message).has_value());
}

// ---------------------------------------------------------------- encoding ---

void test_encode_rejects_small_buffers() {
    CASE("encode refuses to write into a buffer that cannot hold the message");

    const std::vector<uint8_t> sealed = filled(kTagSize, 0x70);
    const TransportData transport{.receiver_index = 1, .counter = 1, .sealed = sealed};

    std::vector<uint8_t> exact(kTransportHeaderSize + sealed.size());
    CHECK(encode(exact, transport).has_value());

    for (size_t size = 0; size < exact.size(); ++size) {
        std::vector<uint8_t> small(size);
        CHECK(!encode(small, transport).has_value());
    }
}

void test_encode_rejects_untagged_payload() {
    CASE("transport data with a payload shorter than the tag is not encodable");

    for (size_t size = 0; size < kTagSize; ++size) {
        const std::vector<uint8_t> sealed(size);
        const TransportData transport{.receiver_index = 1, .counter = 1, .sealed = sealed};
        std::vector<uint8_t> buffer(128);
        CHECK(!encode(buffer, transport).has_value());
    }
}

// ------------------------------------------------------------ mac accessors ---

void test_mac_accessors() {
    CASE("mac1 and mac2 cover the right ranges of a handshake message");

    std::vector<uint8_t> initiation = valid_message(Type::handshake_initiation);
    const auto mac1_in = mac1_input(initiation);
    const auto mac2_in = mac2_input(initiation);
    CHECK(mac1_in.has_value());
    CHECK(mac2_in.has_value());
    CHECK_EQ(mac1_in->size(), kInitiationMac1Offset);
    CHECK_EQ(mac2_in->size(), kInitiationMac2Offset);
    // mac2's input includes mac1: that is the point of the construction.
    CHECK_EQ(mac2_in->size() - mac1_in->size(), kMacSize);

    const auto mac1_out = mac1_field(initiation);
    CHECK(mac1_out.has_value());
    CHECK_EQ(mac1_out->size(), kMacSize);
    CHECK(mac1_out->data() == initiation.data() + kInitiationMac1Offset);

    std::vector<uint8_t> response = valid_message(Type::handshake_response);
    CHECK(mac1_input(response).has_value());
    CHECK_EQ(mac1_input(response)->size(), kResponseMac1Offset);
    CHECK_EQ(mac2_input(response)->size(), kResponseMac2Offset);

    // Not a handshake message, so there are no MACs to point at.
    std::vector<uint8_t> transport = valid_message(Type::transport_data);
    CHECK(!mac1_input(transport).has_value());
    CHECK(!mac2_field(transport).has_value());

    // Right type, wrong length.
    std::vector<uint8_t> short_initiation = valid_message(Type::handshake_initiation);
    short_initiation.pop_back();
    CHECK(!mac1_input(short_initiation).has_value());
}

// --------------------------------------------------------- inner IP packet ---

std::vector<uint8_t> ipv4_packet(size_t total_length, size_t buffer_size, uint8_t ihl = 5) {
    std::vector<uint8_t> packet(buffer_size, 0);
    packet[0] = static_cast<uint8_t>(0x40 | ihl);
    packet[2] = static_cast<uint8_t>((total_length >> 8) & 0xff);
    packet[3] = static_cast<uint8_t>(total_length & 0xff);
    return packet;
}

void test_inner_packet_length() {
    CASE("inner_packet_length validates before it trusts the length field");

    // The ordinary case: a 60-byte packet in a 64-byte padded buffer.
    CHECK(inner_packet_length(ipv4_packet(60, 64)) == 60u);
    // Exactly filling the buffer.
    CHECK(inner_packet_length(ipv4_packet(64, 64)) == 64u);
    // A header-only packet.
    CHECK(inner_packet_length(ipv4_packet(20, 32)) == 20u);

    CASE("inner_packet_length rejects a length that runs past the buffer");
    // The whole point of the check: a forged length must not size a read.
    CHECK(!inner_packet_length(ipv4_packet(65, 64)).has_value());
    CHECK(!inner_packet_length(ipv4_packet(65535, 64)).has_value());

    CASE("inner_packet_length rejects a length shorter than its own header");
    CHECK(!inner_packet_length(ipv4_packet(19, 64)).has_value());
    CHECK(!inner_packet_length(ipv4_packet(0, 64)).has_value());
    // IHL 15 means a 60-byte header, so a 40-byte total is a lie.
    CHECK(!inner_packet_length(ipv4_packet(40, 64, 15)).has_value());
    CHECK(inner_packet_length(ipv4_packet(60, 64, 15)) == 60u);

    CASE("inner_packet_length rejects malformed headers");
    // IHL below 5 cannot hold the mandatory fields.
    for (uint8_t ihl = 0; ihl < 5; ++ihl) {
        CHECK(!inner_packet_length(ipv4_packet(64, 64, ihl)).has_value());
    }
    // IHL claiming a header longer than the buffer.
    CHECK(!inner_packet_length(ipv4_packet(24, 24, 15)).has_value());
    // Not IPv4.
    for (uint8_t version = 0; version < 16; ++version) {
        if (version == 4) {
            continue;
        }
        std::vector<uint8_t> packet = ipv4_packet(60, 64);
        packet[0] = static_cast<uint8_t>((version << 4) | 5);
        CHECK(!inner_packet_length(packet).has_value());
    }
    // Too short to hold an IPv4 header at all.
    for (size_t size = 0; size < 20; ++size) {
        CHECK(!inner_packet_length(std::vector<uint8_t>(size, 0x45)).has_value());
    }
}

void test_padding() {
    CASE("padding rounds up to a multiple of 16 and never down");

    for (size_t n = 0; n <= 2048; ++n) {
        const size_t padded = padded_length(n);
        CHECK_EQ(padded % 16, 0u);
        if (padded < n || padded - n >= 16) {
            CHECK_EQ(padded, n);  // reports the offending value
        } else {
            CHECK(true);
        }
    }
}

}  // namespace

int main() {
    test_initiation_round_trip();
    test_response_round_trip();
    test_cookie_round_trip();
    test_transport_round_trip();
    test_truncation();
    test_oversize();
    test_reserved_bytes();
    test_unknown_types();
    test_minimum_transport();
    test_encode_rejects_small_buffers();
    test_encode_rejects_untagged_payload();
    test_mac_accessors();
    test_inner_packet_length();
    test_padding();
    return vpn::test::report("wire");
}
