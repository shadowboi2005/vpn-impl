#include "crypto.h"

#include <sodium.h>

#include <algorithm>
#include <ctime>
#include <stdexcept>

#include "secure_buf.h"

extern "C" {
#include <blake2.h>
}

namespace vpn::crypto {
namespace {

// BLAKE2s processes 64-byte blocks; HMAC's ipad/opad are one block wide.
constexpr size_t kBlockSize = 64;
static_assert(BLAKE2S_BLOCKBYTES == kBlockSize);
static_assert(BLAKE2S_OUTBYTES == kHashSize);

// libb2's argument order is (out, in, key, outlen, inlen, keylen) — not the
// (out, outlen, in, inlen, key, keylen) of the BLAKE2 reference repo. Wrapping
// it once here means the order is written down in exactly one place.
void blake2s_call(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen,
                  const uint8_t* key, size_t keylen) {
    if (::blake2s(out, in, key, outlen, inlen, keylen) != 0) {
        throw std::runtime_error("blake2s failed");
    }
}

void update(blake2s_state& state, std::span<const uint8_t> input) {
    // A zero-length update is a no-op upstream, but an empty span's data() may
    // be null and there is no reason to hand a null pointer across the boundary.
    if (!input.empty()) {
        ::blake2s_update(&state, input.data(), input.size());
    }
}

// WireGuard's AEAD nonce: 4 zero bytes, then the counter little-endian.
struct Nonce {
    uint8_t bytes[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]{};

    explicit Nonce(uint64_t counter) noexcept {
        for (size_t i = 0; i < 8; ++i) {
            bytes[4 + i] = static_cast<uint8_t>((counter >> (8 * i)) & 0xff);
        }
    }
};

static_assert(crypto_scalarmult_curve25519_BYTES == kKeySize);
static_assert(crypto_aead_chacha20poly1305_ietf_KEYBYTES == kKeySize);
static_assert(crypto_aead_chacha20poly1305_ietf_ABYTES == kTagSize);
static_assert(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES == kCookieNonceSize);

}  // namespace

void init() {
    // Safe to call more than once; returns 1 if already initialised.
    if (::sodium_init() < 0) {
        throw std::runtime_error("sodium_init failed; the crypto library is unusable");
    }
}

void generate_keypair(MutKey private_key, MutKey public_key) {
    ::randombytes_buf(private_key.data(), private_key.size());
    // Curve25519 clamping. libsodium clamps internally when it multiplies, but
    // `wg` stores keys already clamped, so doing it here keeps key files
    // byte-identical between the two.
    private_key[0] = static_cast<uint8_t>(private_key[0] & 248);
    private_key[31] = static_cast<uint8_t>((private_key[31] & 127) | 64);
    derive_public(public_key, private_key);
}

void derive_public(MutKey public_key, Key private_key) {
    if (::crypto_scalarmult_curve25519_base(public_key.data(), private_key.data()) != 0) {
        throw std::runtime_error("deriving a public key failed");
    }
}

bool dh(MutKey out, Key private_key, Key peer_public) {
    // Returns -1 for a low-order peer point, whose shared secret would be
    // all-zero and would let anyone impersonate the peer.
    return ::crypto_scalarmult_curve25519(out.data(), private_key.data(), peer_public.data()) == 0;
}

void seal(std::span<uint8_t> out, Key key, uint64_t counter, std::span<const uint8_t> plaintext,
          std::span<const uint8_t> aad) {
    if (out.size() != plaintext.size() + kTagSize) {
        throw std::logic_error("seal: output span is the wrong size");
    }
    const Nonce nonce(counter);
    unsigned long long written = 0;
    ::crypto_aead_chacha20poly1305_ietf_encrypt(out.data(), &written, plaintext.data(),
                                                plaintext.size(), aad.data(), aad.size(), nullptr,
                                                nonce.bytes, key.data());
}

bool open(std::span<uint8_t> out, Key key, uint64_t counter, std::span<const uint8_t> ciphertext,
          std::span<const uint8_t> aad) {
    if (ciphertext.size() < kTagSize || out.size() != ciphertext.size() - kTagSize) {
        return false;
    }
    const Nonce nonce(counter);
    unsigned long long written = 0;
    return ::crypto_aead_chacha20poly1305_ietf_decrypt(
               out.data(), &written, nullptr, ciphertext.data(), ciphertext.size(), aad.data(),
               aad.size(), nonce.bytes, key.data()) == 0;
}

void seal_cookie(std::span<uint8_t> out, Key key, std::span<const uint8_t, kCookieNonceSize> nonce,
                 std::span<const uint8_t> plaintext, std::span<const uint8_t> aad) {
    if (out.size() != plaintext.size() + kTagSize) {
        throw std::logic_error("seal_cookie: output span is the wrong size");
    }
    unsigned long long written = 0;
    ::crypto_aead_xchacha20poly1305_ietf_encrypt(out.data(), &written, plaintext.data(),
                                                 plaintext.size(), aad.data(), aad.size(), nullptr,
                                                 nonce.data(), key.data());
}

bool open_cookie(std::span<uint8_t> out, Key key, std::span<const uint8_t, kCookieNonceSize> nonce,
                 std::span<const uint8_t> ciphertext, std::span<const uint8_t> aad) {
    if (ciphertext.size() < kTagSize || out.size() != ciphertext.size() - kTagSize) {
        return false;
    }
    unsigned long long written = 0;
    return ::crypto_aead_xchacha20poly1305_ietf_decrypt(
               out.data(), &written, nullptr, ciphertext.data(), ciphertext.size(), aad.data(),
               aad.size(), nonce.data(), key.data()) == 0;
}

void hash(std::span<uint8_t, kHashSize> out, std::span<const uint8_t> input) {
    blake2s_call(out.data(), out.size(), input.data(), input.size(), nullptr, 0);
}

void hash2(std::span<uint8_t, kHashSize> out, std::span<const uint8_t> a,
           std::span<const uint8_t> b) {
    blake2s_state state{};
    if (::blake2s_init(&state, kHashSize) != 0) {
        throw std::runtime_error("blake2s_init failed");
    }
    update(state, a);
    update(state, b);
    ::blake2s_final(&state, out.data(), out.size());
}

void mac(std::span<uint8_t, kMacSize> out, Key key, std::span<const uint8_t> input) {
    blake2s_call(out.data(), out.size(), input.data(), input.size(), key.data(), key.size());
}

void hmac(std::span<uint8_t, kHashSize> out, std::span<const uint8_t> key,
          std::span<const uint8_t> input) {
    // The standard HMAC construction over BLAKE2s — deliberately *not*
    // BLAKE2s's own keyed mode, which is a different function producing
    // different output. The protocol specifies HMAC.
    SecureBuf<kBlockSize> padded_key;
    if (key.size() > kBlockSize) {
        // Never happens here (every key is 32 bytes) but the construction is
        // only correct if it is handled.
        hash(padded_key.mut().first<kHashSize>(), key);
    } else {
        std::copy(key.begin(), key.end(), padded_key.mut().begin());
    }

    SecureBuf<kBlockSize> pad;
    SecureBuf<kHashSize> inner;

    for (size_t i = 0; i < kBlockSize; ++i) {
        pad.mut()[i] = static_cast<uint8_t>(padded_key.get()[i] ^ 0x36);
    }
    {
        blake2s_state state{};
        ::blake2s_init(&state, kHashSize);
        update(state, pad.get());
        update(state, input);
        ::blake2s_final(&state, inner.mut().data(), kHashSize);
    }

    for (size_t i = 0; i < kBlockSize; ++i) {
        pad.mut()[i] = static_cast<uint8_t>(padded_key.get()[i] ^ 0x5c);
    }
    {
        blake2s_state state{};
        ::blake2s_init(&state, kHashSize);
        update(state, pad.get());
        update(state, inner.get());
        ::blake2s_final(&state, out.data(), kHashSize);
    }
    // padded_key, pad and inner wipe themselves on the way out.
}

namespace {

// Shared by kdf1/2/3. Every output is derived from t0, and t0 dies here.
//
// Note the aliasing this permits: out1 may be the same buffer as chaining_key,
// which is what "C = KDF1(C, x)" in the whitepaper means. That is safe because
// t0 is computed from chaining_key before any output is written.
void kdf(std::span<uint8_t, kHashSize>* out1, std::span<uint8_t, kHashSize>* out2,
         std::span<uint8_t, kHashSize>* out3, Key chaining_key, std::span<const uint8_t> input) {
    SecureBuf<kHashSize> t0;
    hmac(t0.mut(), chaining_key, input);

    // Each round feeds the previous output back in, followed by the round
    // number as a single byte.
    SecureBuf<kHashSize + 1> chained;
    uint8_t counter = 1;

    chained.mut()[0] = counter;
    hmac(*out1, t0.get(), chained.get().first(1));
    if (out2 == nullptr) {
        return;
    }

    std::copy((*out1).begin(), (*out1).end(), chained.mut().begin());
    chained.mut()[kHashSize] = ++counter;
    hmac(*out2, t0.get(), chained.get());
    if (out3 == nullptr) {
        return;
    }

    std::copy((*out2).begin(), (*out2).end(), chained.mut().begin());
    chained.mut()[kHashSize] = ++counter;
    hmac(*out3, t0.get(), chained.get());
}

}  // namespace

void kdf1(std::span<uint8_t, kHashSize> out1, Key chaining_key, std::span<const uint8_t> input) {
    kdf(&out1, nullptr, nullptr, chaining_key, input);
}

void kdf2(std::span<uint8_t, kHashSize> out1, std::span<uint8_t, kHashSize> out2, Key chaining_key,
          std::span<const uint8_t> input) {
    kdf(&out1, &out2, nullptr, chaining_key, input);
}

void kdf3(std::span<uint8_t, kHashSize> out1, std::span<uint8_t, kHashSize> out2,
          std::span<uint8_t, kHashSize> out3, Key chaining_key, std::span<const uint8_t> input) {
    kdf(&out1, &out2, &out3, chaining_key, input);
}

bool equal(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    // A length mismatch is not secret, so short-circuiting on it leaks nothing.
    if (a.size() != b.size()) {
        return false;
    }
    // Two empty spans are equal, and their null data pointers must not reach a
    // function declared nonnull.
    if (a.empty()) {
        return true;
    }
    return ::sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

void random_bytes(std::span<uint8_t> out) {
    // An empty span's data() is null, and randombytes_buf is declared nonnull.
    if (out.empty()) {
        return;
    }
    ::randombytes_buf(out.data(), out.size());
}

uint32_t random_index() {
    uint32_t value = 0;
    ::randombytes_buf(&value, sizeof(value));
    return value;
}

void timestamp(std::span<uint8_t, kTimestampSize> out) {
    timespec now{};
    ::clock_gettime(CLOCK_REALTIME, &now);

    // TAI64 labels seconds from an epoch offset by 2^62, plus ten leap seconds.
    const uint64_t seconds = 0x400000000000000aULL + static_cast<uint64_t>(now.tv_sec);

    // Both reference implementations round the nanoseconds down to a 2^24 ns
    // boundary — about 16 ms. A full-precision clock reading, sent in every
    // handshake, is a fingerprint of the sender's timer; this keeps the
    // timestamp monotonic without publishing that.
    const uint32_t nanoseconds = static_cast<uint32_t>(now.tv_nsec) & ~uint32_t{0x00ffffff};

    for (size_t i = 0; i < 8; ++i) {
        out[i] = static_cast<uint8_t>((seconds >> (56 - 8 * i)) & 0xff);
    }
    for (size_t i = 0; i < 4; ++i) {
        out[8 + i] = static_cast<uint8_t>((nanoseconds >> (24 - 8 * i)) & 0xff);
    }
}

bool timestamp_after(std::span<const uint8_t, kTimestampSize> a,
                     std::span<const uint8_t, kTimestampSize> b) {
    // TAI64N is big-endian throughout, so lexicographic order on the bytes is
    // chronological order. No constant-time requirement: both values are public.
    for (size_t i = 0; i < kTimestampSize; ++i) {
        if (a[i] != b[i]) {
            return a[i] > b[i];
        }
    }
    return false;  // equal is not "after"
}

std::string to_base64(std::span<const uint8_t> bytes) {
    const size_t capacity = sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_ORIGINAL);
    std::string text(capacity, '\0');
    ::sodium_bin2base64(text.data(), text.size(), bytes.data(), bytes.size(),
                        sodium_base64_VARIANT_ORIGINAL);
    // sodium_base64_ENCODED_LEN counts the terminating NUL.
    text.resize(capacity - 1);
    return text;
}

std::optional<std::vector<uint8_t>> from_base64(std::string_view text) {
    // The empty string is valid base64 for zero bytes. Handled here rather than
    // passed on, because an empty vector's data() is null and
    // sodium_base642bin's first argument is declared nonnull. Callers reject it
    // anyway on length.
    if (text.empty()) {
        return std::vector<uint8_t>{};
    }
    std::vector<uint8_t> bytes(text.size());  // decoding never grows
    size_t decoded = 0;
    const char* end = nullptr;
    if (::sodium_base642bin(bytes.data(), bytes.size(), text.data(), text.size(), " \t\r\n",
                            &decoded, &end, sodium_base64_VARIANT_ORIGINAL) != 0) {
        return std::nullopt;
    }
    // Trailing junk after valid base64 is a malformed key, not a valid prefix.
    if (end != text.data() + text.size()) {
        return std::nullopt;
    }
    bytes.resize(decoded);
    return bytes;
}

}  // namespace vpn::crypto
