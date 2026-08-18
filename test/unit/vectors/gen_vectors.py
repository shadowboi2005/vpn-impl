#!/usr/bin/env python3
"""Generates the HMAC-BLAKE2s and KDF vectors used by test/unit/crypto_test.cpp.

The C++ implementation must agree with something written independently of it.
Python's hashlib.blake2s and the standard library's hmac module are a separate
codebase; the KDF below is transcribed directly from the WireGuard whitepaper
rather than from our C++.

This is a cross-implementation check, not an authoritative one. Two
implementations agreeing rules out a coding slip, not a shared misreading of the
spec. The authoritative check for the hash itself is blake2-kat.h; the
authoritative check for the protocol is interoperating with real WireGuard.

    python3 test/unit/vectors/gen_vectors.py
"""

import hashlib
import hmac as hmaclib

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"


def H(data):
    return hashlib.blake2s(data).digest()


def MAC(key, data):
    return hashlib.blake2s(data, digest_size=16, key=key).digest()


def HMAC(key, msg):
    return hmaclib.new(key, msg, hashlib.blake2s).digest()


def KDF(chaining_key, data, n):
    t0 = HMAC(chaining_key, data)
    out, prev = [], b""
    for i in range(1, n + 1):
        prev = HMAC(t0, prev + bytes([i]))
        out.append(prev)
    return out


def show(name, value):
    print(f'    {{"{name}", "{value.hex()}"}},')


print("// HMAC-BLAKE2s: {label, key, message, expected}")
cases = [
    ("empty key, empty message", b"", b""),
    ("short key", b"key", b"The quick brown fox jumps over the lazy dog"),
    ("32-byte key", bytes(range(32)), b"wireguard"),
    ("key exactly one block", bytes(range(64)), b"block-sized key"),
    ("key longer than a block", bytes(range(65)), b"oversized key must be hashed first"),
    ("empty message, 32-byte key", bytes(range(32)), b""),
]
for label, key, msg in cases:
    print(f'    {{"{label}", "{key.hex()}", "{msg.hex()}", "{HMAC(key, msg).hex()}"}},')

print()
print("// KDF, chaining key = 32 bytes 0x00..0x1f, input = \"input\"")
ck = bytes(range(32))
data = b"input"
for n in (1, 2, 3):
    outs = KDF(ck, data, n)
    print(f"// KDF{n}: " + ", ".join(o.hex() for o in outs))

print()
print("// KDF with empty input, as the transport keys are derived")
for o in KDF(ck, b"", 2):
    print("//   " + o.hex())

print()
print("// WireGuard's published starting constants")
ick = H(CONSTRUCTION)
ih = H(ick + IDENTIFIER)
print(f"// INITIAL_CHAINING_KEY = {ick.hex()}")
print(f"// INITIAL_HASH         = {ih.hex()}")
