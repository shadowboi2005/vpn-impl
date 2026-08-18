#include <cstdio>
#include <cstdlib>
#include <exception>
#include <optional>
#include <memory>
#include <string>
#include <string_view>

#include "args.h"
#include "netcfg.h"
#include "relay.h"
#include "tun.h"
#include "crypto.h"
#include "noise.h"
#include "udp.h"
#include "wire.h"

namespace {

void usage(const char* program) {
    std::fprintf(stderr,
                 "usage: %s [options]\n"
                 "  --dev NAME          tun device name (default tun0)\n"
                 "  --tun-addr CIDR     tunnel address (default 10.9.0.1/24)\n"
                 "  --mtu N             tunnel MTU, 576..1500 (default 1420)\n"
                 "  --listen-port N     udp port to bind (default 51820)\n"
                 "  --wan-if NAME       interface to masquerade out of\n"
                 "                      (default: whichever reaches the internet)\n"
                 "  --private-key PATH  our private key, base64 (required)\n"
                 "  --peer-key BASE64   the client's public key (required)\n"
                 "  --no-nat            do not forward or masquerade\n",
                 program);
}

}  // namespace

int main(int argc, char** argv) {
    std::string dev = "tun0";
    std::string tun_addr = "10.9.0.1/24";
    std::string wan_if;
    int mtu = vpn::wire::kDefaultTunnelMtu;
    uint16_t listen_port = 51820;
    bool install_nat = true;
    std::string private_key_path;
    std::string peer_key;

    for (int i = 1; i < argc; ++i) {
        const std::string_view flag = argv[i];

        if (flag == "-h" || flag == "--help") {
            usage(argv[0]);
            return 0;
        }
        if (flag == "--no-nat") {
            install_nat = false;
            continue;
        }
        if (i + 1 >= argc) {
            std::fprintf(stderr, "%s is not a known option, or needs a value\n", argv[i]);
            return 2;
        }
        const std::string_view value = argv[++i];

        if (flag == "--dev") {
            dev = value;
        } else if (flag == "--tun-addr") {
            if (!vpn::netcfg::subnet_of(value).has_value()) {
                std::fprintf(stderr, "bad --tun-addr (want IPv4/PREFIX, e.g. 10.9.0.1/24)\n");
                return 2;
            }
            tun_addr = value;
        } else if (flag == "--wan-if") {
            wan_if = value;
        } else if (flag == "--private-key") {
            private_key_path = value;
        } else if (flag == "--peer-key") {
            peer_key = value;
        } else if (flag == "--mtu") {
            if (const auto parsed = vpn::args::parse_mtu(value)) {
                mtu = *parsed;
            } else {
                std::fprintf(stderr, "bad --mtu (want 576..1500)\n");
                return 2;
            }
        } else if (flag == "--listen-port") {
            if (const auto parsed = vpn::args::parse_port(value)) {
                listen_port = *parsed;
            } else {
                std::fprintf(stderr, "bad --listen-port (want 1..65535)\n");
                return 2;
            }
        } else {
            std::fprintf(stderr, "unknown argument %s\n", argv[i - 1]);
            usage(argv[0]);
            return 2;
        }
    }

    if (private_key_path.empty() || peer_key.empty()) {
        std::fprintf(stderr, "--private-key and --peer-key are both required\n");
        usage(argv[0]);
        return 2;
    }

    try {
        vpn::crypto::init();
        const std::unique_ptr<vpn::noise::Identity> identity =
            vpn::noise::load_identity(private_key_path, peer_key);
        if (identity == nullptr) {
            return 1;
        }

        vpn::TunDevice tun = vpn::TunDevice::open(dev);
        vpn::netcfg::configure_interface(tun.name(), tun_addr, mtu);

        vpn::UdpSocket sock = vpn::UdpSocket::bind_any(listen_port);

        // Outlives the packet loop, destroyed before the TUN device.
        vpn::netcfg::ServerNat nat;
        if (install_nat) {
            if (wan_if.empty()) {
                // Any routable address off our own subnets will do; nothing is
                // sent to it.
                wan_if = vpn::netcfg::route_to("1.1.1.1").dev;
            }
            // subnet_of already succeeded during argument parsing.
            nat = vpn::netcfg::install_server_nat(tun.name(), *vpn::netcfg::subnet_of(tun_addr),
                                                  wan_if);
        }

        std::fprintf(stderr,
                     "vpnd: %s %s mtu %d, listening on udp/%u\n"
                     "vpnd: no peer yet — the client has to send first\n",
                     tun.name().c_str(), tun_addr.c_str(), mtu, sock.local_port());

        const vpn::RelayStats stats = vpn::run_relay(tun, sock,
                                                     vpn::RelayConfig{
                                                         .mtu = mtu,
                                                         .role = vpn::Role::responder,
                                                         .peer = std::nullopt,
                                                         .identity = identity.get(),
                                                     });
        vpn::print_stats(stderr, stats);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "vpnd: %s\n", error.what());
        return 1;
    }

    return 0;
}
