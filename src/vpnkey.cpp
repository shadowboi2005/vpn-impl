// Key generation, deliberately shaped like `wg genkey` / `wg pubkey` so the
// keys are interchangeable with a real WireGuard configuration.
//
//   vpnkey genkey > private.key
//   vpnkey pubkey < private.key
//   vpnkey genkey | tee private.key | vpnkey pubkey > public.key

#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstdint>
#include <exception>
#include <string>
#include <string_view>

#include "crypto.h"
#include "secure_buf.h"

namespace {

void usage(const char* program) {
    std::fprintf(stderr,
                 "usage: %s genkey | pubkey\n"
                 "  genkey    write a new private key, base64, to stdout\n"
                 "  pubkey    read a private key from stdin, write its public key\n",
                 program);
}

// Refuses to write a private key to a terminal. It would end up in scrollback
// and in the shell's history of whatever ran next; `wg` does the same.
bool stdout_is_safe_for_secrets() {
    return ::isatty(STDOUT_FILENO) == 0;
}

int genkey() {
    if (!stdout_is_safe_for_secrets()) {
        std::fprintf(stderr, "refusing to print a private key to a terminal; redirect it:\n"
                             "  vpnkey genkey > private.key\n");
        return 1;
    }

    vpn::SecureBuf<vpn::crypto::kKeySize> private_key;
    std::array<uint8_t, vpn::crypto::kKeySize> public_key{};
    vpn::crypto::generate_keypair(private_key.mut(), public_key);

    std::string encoded = vpn::crypto::to_base64(private_key.get());
    std::printf("%s\n", encoded.c_str());
    // std::string does not promise to wipe itself, and this one held a key.
    ::sodium_memzero(encoded.data(), encoded.size());
    return 0;
}

int pubkey() {
    std::string line;
    int c = 0;
    while ((c = std::getchar()) != EOF && c != '\n') {
        line.push_back(static_cast<char>(c));
    }
    // Tolerate trailing whitespace from a file written by an editor.
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
        line.pop_back();
    }

    const auto decoded = vpn::crypto::from_base64(line);
    ::sodium_memzero(line.data(), line.size());
    if (!decoded.has_value() || decoded->size() != vpn::crypto::kKeySize) {
        std::fprintf(stderr, "stdin is not a base64 32-byte private key\n");
        return 1;
    }

    std::array<uint8_t, vpn::crypto::kKeySize> public_key{};
    vpn::crypto::derive_public(public_key,
                               vpn::crypto::Key(decoded->data(), vpn::crypto::kKeySize));
    std::printf("%s\n", vpn::crypto::to_base64(public_key).c_str());
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        usage(argv[0]);
        return 2;
    }

    try {
        vpn::crypto::init();
        const std::string_view command = argv[1];
        if (command == "genkey") {
            return genkey();
        }
        if (command == "pubkey") {
            return pubkey();
        }
        usage(argv[0]);
        return 2;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "vpnkey: %s\n", error.what());
        return 1;
    }
}
