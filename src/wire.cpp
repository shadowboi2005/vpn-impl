#include "wire.h"

#include <algorithm>

namespace vpn::wire {
namespace {

// Field by field, byte by byte. Never a reinterpret_cast over the buffer: the
// datagram is not aligned for a uint64_t and the struct would carry padding.

uint32_t read_u32_le(std::span<const uint8_t, 4> bytes) noexcept {
    return static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) | (static_cast<uint32_t>(bytes[3]) << 24);
}

uint64_t read_u64_le(std::span<const uint8_t, 8> bytes) noexcept {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(bytes[i]) << (8 * i);
    }
    return value;
}

void write_u32_le(std::span<uint8_t, 4> out, uint32_t value) noexcept {
    for (size_t i = 0; i < 4; ++i) {
        out[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xff);
    }
}

void write_u64_le(std::span<uint8_t, 8> out, uint64_t value) noexcept {
    for (size_t i = 0; i < 8; ++i) {
        out[i] = static_cast<uint8_t>((value >> (8 * i)) & 0xff);
    }
}

void write_prefix(std::span<uint8_t> out, Type type) noexcept {
    out[0] = static_cast<uint8_t>(type);
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
}

// The reserved bytes must be zero. Both reference implementations read the
// first four bytes as one little-endian uint32 and compare against the type
// constant, so a nonzero reserved field makes their comparison fail. Checking
// it explicitly gets the same result in a form a reader can verify.
bool prefix_ok(std::span<const uint8_t> datagram) noexcept {
    return datagram.size() >= kPrefix && datagram[1] == 0 && datagram[2] == 0 && datagram[3] == 0;
}

// Offsets of the two MAC fields, by message type. Nullopt for anything that is
// not a handshake message of exactly the right length.
struct MacOffsets {
    size_t mac1;
    size_t mac2;
};

std::optional<MacOffsets> mac_offsets(std::span<const uint8_t> message) noexcept {
    if (!prefix_ok(message)) {
        return std::nullopt;
    }
    if (message[0] == static_cast<uint8_t>(Type::handshake_initiation) &&
        message.size() == kInitiationSize) {
        return MacOffsets{kInitiationMac1Offset, kInitiationMac2Offset};
    }
    if (message[0] == static_cast<uint8_t>(Type::handshake_response) &&
        message.size() == kResponseSize) {
        return MacOffsets{kResponseMac1Offset, kResponseMac2Offset};
    }
    return std::nullopt;
}

}  // namespace

std::optional<Message> decode(std::span<const uint8_t> datagram) {
    if (!prefix_ok(datagram)) {
        return std::nullopt;
    }

    switch (datagram[0]) {
        case static_cast<uint8_t>(Type::handshake_initiation): {
            if (datagram.size() != kInitiationSize) {
                return std::nullopt;
            }
            return Message{HandshakeInitiation{
                .sender_index = read_u32_le(datagram.subspan<kInitiationSenderOffset, kIndexSize>()),
                .ephemeral = datagram.subspan<kInitiationEphemeralOffset, kPublicKeySize>(),
                .encrypted_static =
                    datagram.subspan<kInitiationStaticOffset, kEncryptedStaticSize>(),
                .encrypted_timestamp =
                    datagram.subspan<kInitiationTimestampOffset, kEncryptedTimestampSize>(),
                .mac1 = datagram.subspan<kInitiationMac1Offset, kMacSize>(),
                .mac2 = datagram.subspan<kInitiationMac2Offset, kMacSize>(),
            }};
        }

        case static_cast<uint8_t>(Type::handshake_response): {
            if (datagram.size() != kResponseSize) {
                return std::nullopt;
            }
            return Message{HandshakeResponse{
                .sender_index = read_u32_le(datagram.subspan<kResponseSenderOffset, kIndexSize>()),
                .receiver_index =
                    read_u32_le(datagram.subspan<kResponseReceiverOffset, kIndexSize>()),
                .ephemeral = datagram.subspan<kResponseEphemeralOffset, kPublicKeySize>(),
                .encrypted_nothing =
                    datagram.subspan<kResponseNothingOffset, kEncryptedNothingSize>(),
                .mac1 = datagram.subspan<kResponseMac1Offset, kMacSize>(),
                .mac2 = datagram.subspan<kResponseMac2Offset, kMacSize>(),
            }};
        }

        case static_cast<uint8_t>(Type::cookie_reply): {
            if (datagram.size() != kCookieReplySize) {
                return std::nullopt;
            }
            return Message{CookieReply{
                .receiver_index = read_u32_le(datagram.subspan<kCookieReceiverOffset, kIndexSize>()),
                .nonce = datagram.subspan<kCookieNonceOffset, kCookieNonceSize>(),
                .encrypted_cookie =
                    datagram.subspan<kCookieEncryptedOffset, kEncryptedCookieSize>(),
            }};
        }

        case static_cast<uint8_t>(Type::transport_data): {
            // The only variable-length message, and so the only one with a
            // minimum rather than an exact size.
            if (datagram.size() < kTransportMinSize) {
                return std::nullopt;
            }
            return Message{TransportData{
                .receiver_index =
                    read_u32_le(datagram.subspan<kTransportReceiverOffset, kIndexSize>()),
                .counter = read_u64_le(datagram.subspan<kTransportCounterOffset, kCounterSize>()),
                .sealed = datagram.subspan(kTransportHeaderSize),
            }};
        }

        default:
            return std::nullopt;
    }
}

std::optional<std::span<uint8_t>> encode(std::span<uint8_t> out, const HandshakeInitiation& msg) {
    if (out.size() < kInitiationSize) {
        return std::nullopt;
    }
    write_prefix(out, Type::handshake_initiation);
    write_u32_le(out.subspan<kInitiationSenderOffset, kIndexSize>(), msg.sender_index);
    std::ranges::copy(msg.ephemeral, out.begin() + kInitiationEphemeralOffset);
    std::ranges::copy(msg.encrypted_static, out.begin() + kInitiationStaticOffset);
    std::ranges::copy(msg.encrypted_timestamp, out.begin() + kInitiationTimestampOffset);
    std::ranges::copy(msg.mac1, out.begin() + kInitiationMac1Offset);
    std::ranges::copy(msg.mac2, out.begin() + kInitiationMac2Offset);
    return out.first(kInitiationSize);
}

std::optional<std::span<uint8_t>> encode(std::span<uint8_t> out, const HandshakeResponse& msg) {
    if (out.size() < kResponseSize) {
        return std::nullopt;
    }
    write_prefix(out, Type::handshake_response);
    write_u32_le(out.subspan<kResponseSenderOffset, kIndexSize>(), msg.sender_index);
    write_u32_le(out.subspan<kResponseReceiverOffset, kIndexSize>(), msg.receiver_index);
    std::ranges::copy(msg.ephemeral, out.begin() + kResponseEphemeralOffset);
    std::ranges::copy(msg.encrypted_nothing, out.begin() + kResponseNothingOffset);
    std::ranges::copy(msg.mac1, out.begin() + kResponseMac1Offset);
    std::ranges::copy(msg.mac2, out.begin() + kResponseMac2Offset);
    return out.first(kResponseSize);
}

std::optional<std::span<uint8_t>> encode(std::span<uint8_t> out, const CookieReply& msg) {
    if (out.size() < kCookieReplySize) {
        return std::nullopt;
    }
    write_prefix(out, Type::cookie_reply);
    write_u32_le(out.subspan<kCookieReceiverOffset, kIndexSize>(), msg.receiver_index);
    std::ranges::copy(msg.nonce, out.begin() + kCookieNonceOffset);
    std::ranges::copy(msg.encrypted_cookie, out.begin() + kCookieEncryptedOffset);
    return out.first(kCookieReplySize);
}

std::optional<std::span<uint8_t>> encode(std::span<uint8_t> out, const TransportData& msg) {
    if (msg.sealed.size() < kTagSize) {
        return std::nullopt;
    }
    const size_t total = kTransportHeaderSize + msg.sealed.size();
    if (out.size() < total) {
        return std::nullopt;
    }
    encode_transport_header(out, msg.receiver_index, msg.counter);
    std::ranges::copy(msg.sealed, out.begin() + kTransportHeaderSize);
    return out.first(total);
}

std::optional<std::span<uint8_t>> encode_transport_header(std::span<uint8_t> out,
                                                          uint32_t receiver_index,
                                                          uint64_t counter) {
    if (out.size() < kTransportHeaderSize) {
        return std::nullopt;
    }
    write_prefix(out, Type::transport_data);
    write_u32_le(out.subspan<kTransportReceiverOffset, kIndexSize>(), receiver_index);
    write_u64_le(out.subspan<kTransportCounterOffset, kCounterSize>(), counter);
    return out.first(kTransportHeaderSize);
}

std::optional<std::span<const uint8_t>> mac1_input(std::span<const uint8_t> message) {
    const std::optional<MacOffsets> offsets = mac_offsets(message);
    if (!offsets.has_value()) {
        return std::nullopt;
    }
    return message.first(offsets->mac1);
}

std::optional<std::span<const uint8_t>> mac2_input(std::span<const uint8_t> message) {
    const std::optional<MacOffsets> offsets = mac_offsets(message);
    if (!offsets.has_value()) {
        return std::nullopt;
    }
    return message.first(offsets->mac2);
}

std::optional<std::span<uint8_t, kMacSize>> mac1_field(std::span<uint8_t> message) {
    const std::optional<MacOffsets> offsets = mac_offsets(message);
    if (!offsets.has_value()) {
        return std::nullopt;
    }
    return message.subspan(offsets->mac1).first<kMacSize>();
}

std::optional<std::span<uint8_t, kMacSize>> mac2_field(std::span<uint8_t> message) {
    const std::optional<MacOffsets> offsets = mac_offsets(message);
    if (!offsets.has_value()) {
        return std::nullopt;
    }
    return message.subspan(offsets->mac2).first<kMacSize>();
}

std::optional<size_t> inner_packet_length(std::span<const uint8_t> plaintext) {
    static constexpr size_t kMinIpv4Header = 20;
    if (plaintext.size() < kMinIpv4Header) {
        return std::nullopt;
    }

    // IPv4 only, by scope. A version-6 packet here is a bug upstream, not
    // something to forward.
    const uint8_t version = plaintext[0] >> 4;
    if (version != 4) {
        return std::nullopt;
    }

    // IHL counts 32-bit words. Below 5 the header cannot hold its own mandatory
    // fields; above what we received it points past the buffer.
    const size_t header_length = static_cast<size_t>(plaintext[0] & 0x0f) * 4;
    if (header_length < kMinIpv4Header || header_length > plaintext.size()) {
        return std::nullopt;
    }

    // total_length is big-endian: this is an IP header, not our own framing.
    const size_t total_length =
        (static_cast<size_t>(plaintext[2]) << 8) | static_cast<size_t>(plaintext[3]);

    // It must cover the header it claims to have, and must not claim more bytes
    // than were actually decrypted — that second check is the one that stops a
    // forged length from reading padding, or worse, past the buffer.
    if (total_length < header_length || total_length > plaintext.size()) {
        return std::nullopt;
    }
    return total_length;
}

}  // namespace vpn::wire
