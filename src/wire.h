#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <variant>

// WireGuard's wire format, per the whitepaper §5.4. This is not a design; it is
// a transcription. Every size and offset here is dictated by what the kernel
// module puts on the wire and will accept back.
//
// Nothing in this header allocates, copies key material, or reads a byte it has
// not first proved is there. The decoded message types are *views* into the
// caller's receive buffer — they are only valid while that buffer is.

namespace vpn::wire {

enum class Type : uint8_t {
    handshake_initiation = 1,
    handshake_response = 2,
    cookie_reply = 3,
    transport_data = 4,
};

// --------------------------------------------------------------- field sizes

inline constexpr size_t kPrefix = 4;        // type byte + 3 reserved
inline constexpr size_t kIndexSize = 4;
inline constexpr size_t kCounterSize = 8;
inline constexpr size_t kPublicKeySize = 32;
inline constexpr size_t kTagSize = 16;      // Poly1305
inline constexpr size_t kMacSize = 16;
inline constexpr size_t kTimestampSize = 12;  // TAI64N
inline constexpr size_t kCookieSize = 16;
inline constexpr size_t kCookieNonceSize = 24;  // XChaCha20, not the IETF variant

inline constexpr size_t kEncryptedStaticSize = kPublicKeySize + kTagSize;      // 48
inline constexpr size_t kEncryptedTimestampSize = kTimestampSize + kTagSize;   // 28
inline constexpr size_t kEncryptedNothingSize = kTagSize;                      // 16
inline constexpr size_t kEncryptedCookieSize = kCookieSize + kTagSize;         // 32

// ------------------------------------------------- type 1: handshake initiation

inline constexpr size_t kInitiationSenderOffset = 4;
inline constexpr size_t kInitiationEphemeralOffset = 8;
inline constexpr size_t kInitiationStaticOffset = 40;
inline constexpr size_t kInitiationTimestampOffset = 88;
inline constexpr size_t kInitiationMac1Offset = 116;
inline constexpr size_t kInitiationMac2Offset = 132;
inline constexpr size_t kInitiationSize = 148;

static_assert(kInitiationEphemeralOffset == kInitiationSenderOffset + kIndexSize);
static_assert(kInitiationStaticOffset == kInitiationEphemeralOffset + kPublicKeySize);
static_assert(kInitiationTimestampOffset == kInitiationStaticOffset + kEncryptedStaticSize);
static_assert(kInitiationMac1Offset == kInitiationTimestampOffset + kEncryptedTimestampSize);
static_assert(kInitiationMac2Offset == kInitiationMac1Offset + kMacSize);
static_assert(kInitiationSize == kInitiationMac2Offset + kMacSize);

// -------------------------------------------------- type 2: handshake response

inline constexpr size_t kResponseSenderOffset = 4;
inline constexpr size_t kResponseReceiverOffset = 8;
inline constexpr size_t kResponseEphemeralOffset = 12;
inline constexpr size_t kResponseNothingOffset = 44;
inline constexpr size_t kResponseMac1Offset = 60;
inline constexpr size_t kResponseMac2Offset = 76;
inline constexpr size_t kResponseSize = 92;

static_assert(kResponseReceiverOffset == kResponseSenderOffset + kIndexSize);
static_assert(kResponseEphemeralOffset == kResponseReceiverOffset + kIndexSize);
static_assert(kResponseNothingOffset == kResponseEphemeralOffset + kPublicKeySize);
static_assert(kResponseMac1Offset == kResponseNothingOffset + kEncryptedNothingSize);
static_assert(kResponseMac2Offset == kResponseMac1Offset + kMacSize);
static_assert(kResponseSize == kResponseMac2Offset + kMacSize);

// ------------------------------------------------------- type 3: cookie reply

inline constexpr size_t kCookieReceiverOffset = 4;
inline constexpr size_t kCookieNonceOffset = 8;
inline constexpr size_t kCookieEncryptedOffset = 32;
inline constexpr size_t kCookieReplySize = 64;

static_assert(kCookieNonceOffset == kCookieReceiverOffset + kIndexSize);
static_assert(kCookieEncryptedOffset == kCookieNonceOffset + kCookieNonceSize);
static_assert(kCookieReplySize == kCookieEncryptedOffset + kEncryptedCookieSize);

// ------------------------------------------------------ type 4: transport data

inline constexpr size_t kTransportReceiverOffset = 4;
inline constexpr size_t kTransportCounterOffset = 8;
inline constexpr size_t kTransportHeaderSize = 16;
// An empty keepalive: no plaintext, but still sealed and still authenticated.
inline constexpr size_t kTransportMinSize = kTransportHeaderSize + kTagSize;  // 32

static_assert(kTransportCounterOffset == kTransportReceiverOffset + kIndexSize);
static_assert(kTransportHeaderSize == kTransportCounterOffset + kCounterSize);

// ------------------------------------------------------------------ MTU maths

// 1500 − 20 (outer IPv4) − 8 (UDP) − 16 (transport header) − 16 (tag) = 1440.
// Real WireGuard ships 1420, leaving room for paths with extra encapsulation,
// and matching it is free.
inline constexpr int kDefaultTunnelMtu = 1420;
inline constexpr size_t kOuterOverhead = 20 + 8;

// Plaintext is zero-padded to a multiple of 16 before sealing.
constexpr size_t padded_length(size_t plaintext) noexcept {
    return (plaintext + 15) & ~size_t{15};
}

// The largest UDP payload a tunnel of this MTU can produce.
constexpr size_t max_datagram(size_t mtu) noexcept {
    return kTransportHeaderSize + padded_length(mtu) + kTagSize;
}

static_assert(padded_length(0) == 0);
static_assert(padded_length(1) == 16);
static_assert(padded_length(16) == 16);
static_assert(padded_length(1420) == 1424);
static_assert(max_datagram(1420) + kOuterOverhead == 1484);

// ------------------------------------------------------------ decoded messages
//
// Fixed-extent spans throughout. A 32-byte key field has type
// std::span<const uint8_t, 32>, so handing it to something expecting a 16-byte
// MAC is a compile error rather than a Phase 4 debugging session.

struct HandshakeInitiation {
    uint32_t sender_index;
    std::span<const uint8_t, kPublicKeySize> ephemeral;
    std::span<const uint8_t, kEncryptedStaticSize> encrypted_static;
    std::span<const uint8_t, kEncryptedTimestampSize> encrypted_timestamp;
    std::span<const uint8_t, kMacSize> mac1;
    std::span<const uint8_t, kMacSize> mac2;
};

struct HandshakeResponse {
    uint32_t sender_index;
    uint32_t receiver_index;
    std::span<const uint8_t, kPublicKeySize> ephemeral;
    std::span<const uint8_t, kEncryptedNothingSize> encrypted_nothing;
    std::span<const uint8_t, kMacSize> mac1;
    std::span<const uint8_t, kMacSize> mac2;
};

struct CookieReply {
    uint32_t receiver_index;
    std::span<const uint8_t, kCookieNonceSize> nonce;
    std::span<const uint8_t, kEncryptedCookieSize> encrypted_cookie;
};

struct TransportData {
    uint32_t receiver_index;
    uint64_t counter;
    // Padded ciphertext followed by the 16-byte tag. At least kTagSize long.
    std::span<const uint8_t> sealed;
};

using Message = std::variant<HandshakeInitiation, HandshakeResponse, CookieReply, TransportData>;

// Nullopt for anything that is not a well-formed message: too short, nonzero
// reserved bytes, unknown type, or a handshake message that is not exactly its
// stated length. Malformed input is expected, not exceptional — this never
// throws.
std::optional<Message> decode(std::span<const uint8_t> datagram);

// ------------------------------------------------------------------- encoding
//
// Each writes one message into `out` and returns a span over exactly the bytes
// written, or nullopt if `out` is too small. Nothing is written on failure.

std::optional<std::span<uint8_t>> encode(std::span<uint8_t> out, const HandshakeInitiation& msg);
std::optional<std::span<uint8_t>> encode(std::span<uint8_t> out, const HandshakeResponse& msg);
std::optional<std::span<uint8_t>> encode(std::span<uint8_t> out, const CookieReply& msg);
std::optional<std::span<uint8_t>> encode(std::span<uint8_t> out, const TransportData& msg);

// Writes just the 16-byte transport header, leaving the caller to fill the
// sealed payload in place. This is the form the packet path wants: encrypt
// directly into the send buffer rather than sealing elsewhere and copying.
std::optional<std::span<uint8_t>> encode_transport_header(std::span<uint8_t> out,
                                                          uint32_t receiver_index,
                                                          uint64_t counter);

// ----------------------------------------------------------------- mac1 / mac2
//
// mac1 covers every byte before the mac1 field; mac2 covers every byte before
// the mac2 field, mac1 included. Phase 4 writes them, Phase 7 verifies mac2.
// Offsets live here so neither phase recomputes them by hand.

std::optional<std::span<const uint8_t>> mac1_input(std::span<const uint8_t> message);
std::optional<std::span<const uint8_t>> mac2_input(std::span<const uint8_t> message);
std::optional<std::span<uint8_t, kMacSize>> mac1_field(std::span<uint8_t> message);
std::optional<std::span<uint8_t, kMacSize>> mac2_field(std::span<uint8_t> message);

// ------------------------------------------------------------- inner IP packet
//
// The padded plaintext length is not on the wire. The receiver finds the real
// packet by reading the inner IPv4 header's total_length — an attacker-supplied
// 16-bit field, so it is validated like any other parsed input before it is
// trusted to size anything.
//
// Returns the real packet length, or nullopt if this is not a well-formed IPv4
// packet that fits within `plaintext`.
std::optional<size_t> inner_packet_length(std::span<const uint8_t> plaintext);

}  // namespace vpn::wire
