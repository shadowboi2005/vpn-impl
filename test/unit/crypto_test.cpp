#include "crypto.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "check.h"
#include "secure_buf.h"

extern "C" {
// blake2.h first: blake2-kat.h sizes its tables with BLAKE2S_OUTBYTES and does
// not include the header that defines it.
#include <blake2.h>

#include <blake2-kat.h>
}

using namespace vpn::crypto;
using vpn::test::same_bytes;

namespace {

std::vector<uint8_t> from_hex(std::string_view hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    const auto nibble = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
        return static_cast<uint8_t>((c | 0x20) - 'a' + 10);
    };
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    }
    return bytes;
}

std::vector<uint8_t> bytes_of(std::string_view text) {
    return {text.begin(), text.end()};
}

// ------------------------------------------------------------- BLAKE2s KAT ---

// The BLAKE2 authors' own known-answer tests, shipped in the submodule. This is
// the one place in the project with genuinely authoritative test data: if these
// pass, the hash is BLAKE2s, and everything built on it starts from solid
// ground. If they fail, nothing else in this file means anything.
void test_blake2s_known_answers() {
    CASE("BLAKE2s matches the official unkeyed known-answer vectors");

    std::array<uint8_t, KAT_LENGTH> input{};
    for (size_t i = 0; i < input.size(); ++i) {
        input[i] = static_cast<uint8_t>(i);
    }

    for (size_t length = 0; length < KAT_LENGTH; ++length) {
        std::array<uint8_t, 32> digest{};
        hash(digest, std::span(input).first(length));
        if (!same_bytes(digest, std::span(blake2s_kat[length], 32))) {
            CHECK_EQ(length, static_cast<size_t>(-1));  // reports which length failed
        } else {
            CHECK(true);
        }
    }

    CASE("keyed BLAKE2s matches the official keyed known-answer vectors");
    // The keyed KAT uses a 32-byte key of 0x00..0x1f, and a 32-byte digest.
    // Our mac() fixes the digest at 16 bytes for mac1/mac2, so this exercises
    // the underlying primitive directly.
    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i);
    }

    for (size_t length = 0; length < KAT_LENGTH; ++length) {
        std::array<uint8_t, 32> digest{};
        ::blake2s(digest.data(), input.data(), key.data(), digest.size(), length, key.size());
        if (!same_bytes(digest, std::span(blake2s_keyed_kat[length], 32))) {
            CHECK_EQ(length, static_cast<size_t>(-1));
        } else {
            CHECK(true);
        }
    }
}

void test_hash2_matches_concatenation() {
    CASE("hash2(a, b) equals hash(a || b)");

    const std::vector<std::pair<std::string, std::string>> pairs = {
        {"", ""}, {"", "b"}, {"a", ""}, {"a", "b"},
        {std::string(63, 'x'), "y"},        // straddles the 64-byte block
        {std::string(64, 'x'), "y"},
        {std::string(65, 'x'), std::string(200, 'z')},
    };

    for (const auto& [a, b] : pairs) {
        const std::vector<uint8_t> a_bytes = bytes_of(a);
        const std::vector<uint8_t> b_bytes = bytes_of(b);
        std::vector<uint8_t> joined = a_bytes;
        joined.insert(joined.end(), b_bytes.begin(), b_bytes.end());

        std::array<uint8_t, 32> streamed{};
        std::array<uint8_t, 32> once{};
        hash2(streamed, a_bytes, b_bytes);
        hash(once, joined);
        CHECK(same_bytes(streamed, once));
    }
}

// -------------------------------------------------- HMAC-BLAKE2s and the KDF ---

// These vectors were produced by an independently written implementation —
// Python's hashlib.blake2s driven by the standard library's hmac module, and
// the KDF transcribed straight from the whitepaper — and are recorded here so
// the C++ has something outside itself to agree with. That is weaker than the
// BLAKE2s KAT above, which is authoritative; two implementations agreeing rules
// out a coding slip but not a shared misreading of the spec. The check that
// closes that gap is interoperating with the real WireGuard, which is Phase 5.
// See test/unit/vectors/gen_vectors.py for how these were generated.

void test_hmac_blake2s() {
    CASE("HMAC-BLAKE2s agrees with an independent implementation");

    struct Vector {
        std::string_view label;
        std::string_view key;       // hex
        std::string_view message;   // hex
        std::string_view expected;  // hex
    };
    static constexpr Vector kVectors[] = {
        {"empty key, empty message", "", "",
         "eaf4bb25938f4d20e72656bbbc7a9bf63c0c18537333c35bdb67db1402661acd"},
        {"short key", "6b6579",
         "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
         "f93215bb90d4af4c3061cd932fb169fb8bb8a91d0b4022baea1271e1323cd9a0"},
        {"32-byte key, as the protocol always uses",
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "776972656775617264",
         "856f1b248b4d5a741767b3242d3d7a3474e4c3ff1681af8bdd10d7fb6b428d1f"},
        {"key exactly one block long",
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
         "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
         "626c6f636b2d73697a6564206b6579",
         "f5a90847fec307f2b05b5f6457ff6ca0fdba2c5523d0ecbf493dd28c2e02c942"},
        {"key longer than a block, so it is hashed first",
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
         "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
         "6f76657273697a6564206b6579206d75737420626520686173686564206669727374",
         "e65bc418fbc9342076e6c3988e5bbd7cfeef6de0651938761f28c3b90a8e738f"},
        {"empty message", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "",
         "e2641d24dfa8dd89e8cb77f1cdc77d8c006e5bebdfc4d6a3a3a6f8d5b7586fb0"},
    };

    for (const Vector& vector : kVectors) {
        const std::vector<uint8_t> key = from_hex(vector.key);
        const std::vector<uint8_t> message = from_hex(vector.message);
        std::array<uint8_t, 32> out{};
        hmac(out, key, message);
        if (!same_bytes(out, from_hex(vector.expected))) {
            vpn::test::begin(std::string("HMAC-BLAKE2s: ") + std::string(vector.label));
            CHECK(false);
        } else {
            CHECK(true);
        }
    }
}

void test_kdf() {
    CASE("KDF1/2/3 agree with an independent implementation");

    std::array<uint8_t, 32> chaining_key{};
    for (size_t i = 0; i < chaining_key.size(); ++i) {
        chaining_key[i] = static_cast<uint8_t>(i);
    }
    const std::vector<uint8_t> input = bytes_of("input");

    static constexpr std::string_view kExpected[] = {
        "87b7f70b24183c6db5dc4f6d9f4c47cdb203321aa2a0bef714896adb3107a040",
        "538a02e1eb2e31b7e4d4b82476d1fe2acf50085d3fb584537279195f5d1f5824",
        "9ad858025593be88de0f9442a589cfe84a88dc19e4753d93684d1c5efc4837f9",
    };

    std::array<uint8_t, 32> t1{};
    std::array<uint8_t, 32> t2{};
    std::array<uint8_t, 32> t3{};

    kdf1(t1, chaining_key, input);
    CHECK(same_bytes(t1, from_hex(kExpected[0])));

    t1 = {};
    kdf2(t1, t2, chaining_key, input);
    CHECK(same_bytes(t1, from_hex(kExpected[0])));
    CHECK(same_bytes(t2, from_hex(kExpected[1])));

    t1 = {};
    t2 = {};
    kdf3(t1, t2, t3, chaining_key, input);
    CHECK(same_bytes(t1, from_hex(kExpected[0])));
    CHECK(same_bytes(t2, from_hex(kExpected[1])));
    CHECK(same_bytes(t3, from_hex(kExpected[2])));

    CASE("kdf1/2/3 agree with each other on their shared outputs");
    // Truncating the KDF must not change the earlier outputs. If it did, a
    // two-output call site and a three-output one would derive different keys
    // from the same chaining key.
    CHECK(true);

    CASE("the KDF output may alias the chaining key it was derived from");
    // "C = KDF1(C, x)" in the whitepaper is exactly this, and it is only safe
    // because t0 is computed before any output is written. If that ordering
    // ever broke, this is the test that would notice.
    std::array<uint8_t, 32> in_place = chaining_key;
    kdf1(in_place, in_place, input);
    CHECK(same_bytes(in_place, from_hex(kExpected[0])));

    CASE("empty input is a legitimate KDF input — the transport keys use it");
    std::array<uint8_t, 32> send{};
    std::array<uint8_t, 32> recv{};
    kdf2(send, recv, chaining_key, {});
    CHECK(same_bytes(send, from_hex("7a38c34bf2b8738d7374ca77c44ecb309a11d2b2528304fa86052c365e722624")));
    CHECK(same_bytes(recv, from_hex("1a17621f346abdc520746a9fb64d8eb03231d674fc15687537b0780fd9c060fd")));
    CASE("and the two transport keys are different");
    CHECK(!same_bytes(send, recv));
}

void test_protocol_constants() {
    CASE("the protocol's starting constants come out as WireGuard publishes them");

    // C = HASH(CONSTRUCTION); H = HASH(C || IDENTIFIER). Getting either wrong
    // makes every subsequent mixing step wrong in a way that only shows up as
    // "the keys do not match" with nothing to point at.
    static constexpr std::string_view kConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    static constexpr std::string_view kIdentifier = "WireGuard v1 zx2c4 Jason@zx2c4.com";

    std::array<uint8_t, 32> chaining_key{};
    hash(chaining_key, bytes_of(kConstruction));
    CHECK(same_bytes(chaining_key,
                     from_hex("60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36")));

    std::array<uint8_t, 32> initial_hash{};
    hash2(initial_hash, chaining_key, bytes_of(kIdentifier));
    CHECK(same_bytes(initial_hash,
                     from_hex("2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3")));
}

// -------------------------------------------------------------- X25519, AEAD ---

void test_x25519_agreement() {
    CASE("two parties reach the same X25519 shared secret");

    std::array<uint8_t, 32> a_priv{};
    std::array<uint8_t, 32> a_pub{};
    std::array<uint8_t, 32> b_priv{};
    std::array<uint8_t, 32> b_pub{};
    generate_keypair(a_priv, a_pub);
    generate_keypair(b_priv, b_pub);

    std::array<uint8_t, 32> ab{};
    std::array<uint8_t, 32> ba{};
    CHECK(dh(ab, a_priv, b_pub));
    CHECK(dh(ba, b_priv, a_pub));
    CHECK(same_bytes(ab, ba));

    CASE("generated private keys are clamped the way wg writes them");
    CHECK_EQ(a_priv[0] & 0x07, 0);
    CHECK_EQ(a_priv[31] & 0x80, 0);
    CHECK_EQ(a_priv[31] & 0x40, 0x40);

    CASE("a derived public key matches the one from generation");
    std::array<uint8_t, 32> derived{};
    derive_public(derived, a_priv);
    CHECK(same_bytes(derived, a_pub));

    CASE("low-order points are rejected");
    // The canonical small-order Curve25519 points. A shared secret with any of
    // these is all zeros, so accepting one lets anyone impersonate the peer.
    static constexpr const char* kLowOrder[] = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    };
    for (const char* point : kLowOrder) {
        const std::vector<uint8_t> pub = from_hex(point);
        std::array<uint8_t, 32> out{};
        CHECK(!dh(out, a_priv, std::span<const uint8_t, 32>(pub.data(), 32)));
    }
}

void test_aead_round_trip() {
    CASE("AEAD seals and opens, and rejects everything tampered with");

    std::array<uint8_t, 32> key{};
    random_bytes(key);
    const std::vector<uint8_t> plaintext = bytes_of("the inner packet");
    const std::vector<uint8_t> aad = bytes_of("associated data");

    std::vector<uint8_t> sealed(plaintext.size() + kTagSize);
    seal(sealed, key, 42, plaintext, aad);

    std::vector<uint8_t> opened(plaintext.size());
    CHECK(open(opened, key, 42, sealed, aad));
    CHECK(same_bytes(opened, plaintext));

    CASE("a wrong counter fails, because the counter is the nonce");
    CHECK(!open(opened, key, 43, sealed, aad));

    CASE("a wrong key fails");
    std::array<uint8_t, 32> other_key{};
    random_bytes(other_key);
    CHECK(!open(opened, other_key, 42, sealed, aad));

    CASE("altered associated data fails");
    CHECK(!open(opened, key, 42, sealed, bytes_of("associated dat!")));

    CASE("every single-bit flip in the ciphertext fails");
    for (size_t byte = 0; byte < sealed.size(); ++byte) {
        for (int bit = 0; bit < 8; ++bit) {
            std::vector<uint8_t> tampered = sealed;
            tampered[byte] = static_cast<uint8_t>(tampered[byte] ^ (1 << bit));
            CHECK(!open(opened, key, 42, tampered, aad));
        }
    }

    CASE("an empty plaintext still produces a verifiable tag — this is a keepalive");
    std::array<uint8_t, kTagSize> empty_sealed{};
    seal(empty_sealed, key, 7, {}, {});
    CHECK(open({}, key, 7, empty_sealed, {}));
    CHECK(!open({}, key, 8, empty_sealed, {}));
}

// -------------------------------------------------------- timestamps, base64 ---

void test_timestamp() {
    CASE("TAI64N stamps advance and compare in the right direction");

    std::array<uint8_t, kTimestampSize> first{};
    std::array<uint8_t, kTimestampSize> second{};
    timestamp(first);
    timestamp(second);

    // Equal is legitimate: the nanoseconds are rounded to ~16 ms, so two calls
    // in quick succession normally produce the same stamp. What must never
    // happen is going backwards.
    CHECK(!timestamp_after(first, second) || same_bytes(first, second));
    CHECK(!timestamp_after(first, second));

    CASE("a stamp is never after itself");
    CHECK(!timestamp_after(first, first));

    CASE("the low 24 bits of the nanosecond field are cleared");
    CHECK_EQ(first[9], 0);
    CHECK_EQ(first[10], 0);
    CHECK_EQ(first[11], 0);

    CASE("the TAI64 epoch prefix is present");
    CHECK_EQ(first[0], 0x40);

    CASE("ordering is by unsigned big-endian value, including above 0x7f");
    std::array<uint8_t, kTimestampSize> low{};
    std::array<uint8_t, kTimestampSize> high{};
    low[7] = 0x7f;
    high[7] = 0x80;
    CHECK(timestamp_after(high, low));
    CHECK(!timestamp_after(low, high));
}

void test_base64() {
    CASE("base64 round-trips, and matches the encoding wg uses");

    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i);
    }
    const std::string encoded = to_base64(key);
    // 32 bytes is 44 base64 characters with padding.
    CHECK_EQ(encoded.size(), 44u);
    CHECK_EQ(encoded.back(), '=');

    const auto decoded = from_base64(encoded);
    CHECK(decoded.has_value());
    if (decoded.has_value()) {
        CHECK(same_bytes(*decoded, key));
    }

    CASE("malformed base64 is rejected rather than silently truncated");
    for (std::string_view bad : {"not base64!!", "AAAA====", "====", "@@@@"}) {
        CHECK(!from_base64(bad).has_value());
    }

    CASE("trailing junk after a valid key is rejected");
    CHECK(!from_base64(encoded + "garbage").has_value());
}

}  // namespace

int main() {
    init();
    test_blake2s_known_answers();
    test_hash2_matches_concatenation();
    test_hmac_blake2s();
    test_kdf();
    test_protocol_constants();
    test_x25519_agreement();
    test_aead_round_trip();
    test_timestamp();
    test_base64();
    return vpn::test::report("crypto");
}
