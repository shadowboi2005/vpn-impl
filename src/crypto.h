#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// Thin wrappers over libsodium. Nothing here implements a primitive; the point
// is to give every operation a name, a fixed-extent signature, and a return
// value that cannot be ignored.

namespace vpn::crypto {

inline constexpr size_t kKeySize = 32;    // X25519 public, private, and AEAD keys
inline constexpr size_t kTagSize = 16;    // Poly1305
inline constexpr size_t kTimestampSize = 12;  // TAI64N

using Key = std::span<const uint8_t, kKeySize>;
using MutKey = std::span<uint8_t, kKeySize>;

// Must be called once at startup, before anything else here. Throws on failure
// rather than returning a code nobody checks — this one is not recoverable.
void init();

// ------------------------------------------------------------------- X25519

// Fills `out` with a fresh clamped private key and its public key. Clamping
// matches what `wg genkey` writes, so key files are interchangeable.
void generate_keypair(MutKey private_key, MutKey public_key);
void derive_public(MutKey public_key, Key private_key);

// Returns false if the peer's point is low-order, which libsodium detects and
// which must abort the handshake. Ignoring this is the classic X25519 mistake,
// so the result is [[nodiscard]] and `out` is untouched on failure.
[[nodiscard]] bool dh(MutKey out, Key private_key, Key peer_public);

// ------------------------------------------------- ChaCha20-Poly1305 (IETF)

// The nonce is WireGuard's: 4 zero bytes followed by the 64-bit counter,
// little-endian. Building it here rather than at each call site is deliberate —
// it is the detail the plan warns looks like a key derivation bug when wrong.
//
// `out` must be exactly plaintext.size() + kTagSize.
void seal(std::span<uint8_t> out, Key key, uint64_t counter,
          std::span<const uint8_t> plaintext, std::span<const uint8_t> aad);

// `out` must be exactly ciphertext.size() - kTagSize. Returns false if the tag
// does not verify, and writes nothing in that case.
[[nodiscard]] bool open(std::span<uint8_t> out, Key key, uint64_t counter,
                        std::span<const uint8_t> ciphertext, std::span<const uint8_t> aad);

// XChaCha20-Poly1305, used only by the cookie reply, which carries a 24-byte
// nonce. A separate function so the two cannot be confused at a call site.
inline constexpr size_t kCookieNonceSize = 24;
void seal_cookie(std::span<uint8_t> out, Key key, std::span<const uint8_t, kCookieNonceSize> nonce,
                 std::span<const uint8_t> plaintext, std::span<const uint8_t> aad);
[[nodiscard]] bool open_cookie(std::span<uint8_t> out, Key key,
                               std::span<const uint8_t, kCookieNonceSize> nonce,
                               std::span<const uint8_t> ciphertext, std::span<const uint8_t> aad);

// ---------------------------------------------------------------- BLAKE2s
//
// BLAKE2s, not BLAKE2b. libsodium's crypto_generichash is BLAKE2b — a different
// algorithm, not a parameter — so this comes from the BLAKE2 authors' own
// reference implementation in third-party/libb2.

inline constexpr size_t kHashSize = 32;
inline constexpr size_t kMacSize = 16;

void hash(std::span<uint8_t, kHashSize> out, std::span<const uint8_t> input);

// HASH(a || b), without materialising the concatenation. The handshake mixes
// the running hash with a message field at almost every step, and building a
// temporary for each one would put key-adjacent material on the heap.
void hash2(std::span<uint8_t, kHashSize> out, std::span<const uint8_t> a,
           std::span<const uint8_t> b);

// Keyed BLAKE2s with a 16-byte digest: the MAC behind mac1 and mac2.
void mac(std::span<uint8_t, kMacSize> out, Key key, std::span<const uint8_t> input);

// HMAC-BLAKE2s, the standard HMAC construction over BLAKE2s. Not BLAKE2s's own
// keyed mode — the protocol specifies HMAC, and they are not the same function.
void hmac(std::span<uint8_t, kHashSize> out, std::span<const uint8_t> key,
          std::span<const uint8_t> input);

// The whitepaper's KDF_n. Each output is a separate 32-byte value derived from
// the chaining key and the input:
//
//   t0 = HMAC(chaining_key, input)
//   t1 = HMAC(t0, 0x1)
//   t2 = HMAC(t0, t1 || 0x2)
//   t3 = HMAC(t0, t2 || 0x3)
//
// Callers pass the outputs they need; the intermediate t0 is wiped before
// returning.
void kdf1(std::span<uint8_t, kHashSize> out1, Key chaining_key, std::span<const uint8_t> input);
void kdf2(std::span<uint8_t, kHashSize> out1, std::span<uint8_t, kHashSize> out2, Key chaining_key,
          std::span<const uint8_t> input);
void kdf3(std::span<uint8_t, kHashSize> out1, std::span<uint8_t, kHashSize> out2,
          std::span<uint8_t, kHashSize> out3, Key chaining_key, std::span<const uint8_t> input);

// -------------------------------------------------------------------- misc

// Constant time. Never use == or memcmp on a tag, MAC or key: they return early
// on the first differing byte, and that timing is the whole attack.
[[nodiscard]] bool equal(std::span<const uint8_t> a, std::span<const uint8_t> b);

void random_bytes(std::span<uint8_t> out);
uint32_t random_index();

// TAI64N, big-endian, as the handshake initiation carries it.
void timestamp(std::span<uint8_t, kTimestampSize> out);

// Compares two TAI64N stamps as unsigned big-endian byte strings.
[[nodiscard]] bool timestamp_after(std::span<const uint8_t, kTimestampSize> a,
                                   std::span<const uint8_t, kTimestampSize> b);

// Standard base64 with padding, matching the format `wg` reads and writes.
std::string to_base64(std::span<const uint8_t> bytes);
std::optional<std::vector<uint8_t>> from_base64(std::string_view text);

}  // namespace vpn::crypto
