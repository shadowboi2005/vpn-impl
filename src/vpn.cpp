

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <string_view>

#include "args.h"
#include "netcfg.h"
#include "relay.h"
#include "tun.h"
#include "udp.h"

namespace {

void usage(const char* program) {
    std::fprintf(stderr,
                 "usage: %s --server IP:PORT [options]\n"
                 "  --server IP:PORT    vpn server endpoint (required)\n"
                 "  --dev NAME          tun device name (default tun0)\n"
                 "  --tun-addr CIDR     tunnel address (default 10.9.0.2/24)\n"
                 "  --mtu N             tunnel MTU, 576..1500 (default 1380)\n"
                 "  --listen-port N     local udp port (default 0, ephemeral)\n",
                 program);
}

}  // namespace

int main(int argc, char** argv) {
    std::string dev = "tun0";
    std::string tun_addr = "10.9.0.2/24";
    int mtu = 1380;
    uint16_t listen_port = 0;
    std::optional<sockaddr_in> server;

    for (int i = 1; i < argc; ++i) {
        const std::string_view flag = argv[i];

        if (flag == "-h" || flag == "--help") {
            usage(argv[0]);
            return 0;
        }
        if (i + 1 >= argc) {
            std::fprintf(stderr, "%s needs a value\n", argv[i]);
            return 2;
        }
        const std::string_view value = argv[++i];

        if (flag == "--server") {
            server = vpn::parse_endpoint(value);
            if (!server.has_value()) {
                std::fprintf(stderr, "bad --server (want IPv4:PORT, e.g. 10.0.0.1:51820)\n");
                return 2;
            }
        } else if (flag == "--dev") {
            dev = value;
        } else if (flag == "--tun-addr") {
            tun_addr = value;
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

    if (!server.has_value()) {
        std::fprintf(stderr, "--server is required\n");
        usage(argv[0]);
        return 2;
    }

    try {
        vpn::TunDevice tun = vpn::TunDevice::open(dev);
        vpn::netcfg::configure_interface(tun.name(), tun_addr, mtu);

        vpn::UdpSocket sock = vpn::UdpSocket::bind_any(listen_port);

        std::fprintf(stderr, "vpn: %s %s mtu %d, udp/%u -> %s\n", tun.name().c_str(),
                     tun_addr.c_str(), mtu, sock.local_port(),
                     vpn::format_endpoint(*server).c_str());

        const vpn::RelayStats stats = vpn::run_relay(tun, sock, vpn::RelayConfig{
                                                                   .mtu = mtu,
                                                                   .peer = server,
                                                                   .learn_peer = false,
                                                               });
        vpn::print_stats(stderr, stats);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "vpn: %s\n", error.what());
        return 1;
    }

    return 0;
}
