#include <cstdio>
#include <cstdlib>
#include <exception>
#include <optional>
#include <string>
#include <stdexcept>
#include <string_view>

#include "args.h"
#include "netcfg.h"
#include "relay.h"
#include "tun.h"
#include "udp.h"
#include "wire.h"

namespace {

void usage(const char* program) {
    std::fprintf(stderr,
                 "usage: %s --server IP:PORT [options]\n"
                 "  --server IP:PORT    vpn server endpoint (required)\n"
                 "  --dev NAME          tun device name (default tun0)\n"
                 "  --tun-addr CIDR     tunnel address (default 10.9.0.2/24)\n"
                 "  --mtu N             tunnel MTU, 576..1500 (default 1420)\n"
                 "  --listen-port N     local udp port (default 0, ephemeral)\n"
                 "  --no-routes         do not touch the routing table\n"
                 "  --host-ipv6 MODE    what to do if this host has working IPv6:\n"
                 "                      refuse (default) | block | ignore\n",
                 program);
}

}  // namespace

int main(int argc, char** argv) {
    std::string dev = "tun0";
    std::string tun_addr = "10.9.0.2/24";
    int mtu = vpn::wire::kDefaultTunnelMtu;
    uint16_t listen_port = 0;
    bool install_routes = true;
    vpn::netcfg::Ipv6Policy ipv6_policy = vpn::netcfg::Ipv6Policy::refuse;
    std::optional<sockaddr_in> server;

    for (int i = 1; i < argc; ++i) {
        const std::string_view flag = argv[i];

        if (flag == "-h" || flag == "--help") {
            usage(argv[0]);
            return 0;
        }
        if (flag == "--no-routes") {
            install_routes = false;
            continue;
        }
        if (i + 1 >= argc) {
            std::fprintf(stderr, "%s is not a known option, or needs a value\n", argv[i]);
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
            if (!vpn::netcfg::subnet_of(value).has_value()) {
                std::fprintf(stderr, "bad --tun-addr (want IPv4/PREFIX, e.g. 10.9.0.2/24)\n");
                return 2;
            }
            tun_addr = value;
        } else if (flag == "--host-ipv6") {
            if (const auto parsed = vpn::netcfg::parse_ipv6_policy(value)) {
                ipv6_policy = *parsed;
            } else {
                std::fprintf(stderr, "bad --host-ipv6 (want refuse, block or ignore)\n");
                return 2;
            }
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
        // First, before any state exists to unwind. This tunnel is IPv4-only, so
        // a host that can route IPv6 has a complete way around it: every name
        // with a AAAA record is reached outside the tunnel, in the clear, from
        // the real address. Declared before the TUN device so the block, if
        // there is one, is the last thing lifted on the way out.
        vpn::netcfg::ChangeSet ipv6_block;
        if (vpn::netcfg::host_has_ipv6()) {
            switch (ipv6_policy) {
                case vpn::netcfg::Ipv6Policy::refuse:
                    throw std::runtime_error(
                        "this host has a default IPv6 route, and this tunnel carries only IPv4.\n"
                        "       Traffic to any IPv6-capable destination would go around it, in the "
                        "clear.\n"
                        "       Pass --host-ipv6 block to firewall IPv6 off while the tunnel is "
                        "up,\n"
                        "       or --host-ipv6 ignore to accept the leak.");
                case vpn::netcfg::Ipv6Policy::block:
                    ipv6_block = vpn::netcfg::block_host_ipv6();
                    break;
                case vpn::netcfg::Ipv6Policy::ignore:
                    std::fprintf(stderr,
                                 "WARNING: this host routes IPv6 and the tunnel does not carry it. "
                                 "Traffic to IPv6 destinations is leaving in the clear.\n");
                    break;
            }
        }

        vpn::TunDevice tun = vpn::TunDevice::open(dev);
        vpn::netcfg::configure_interface(tun.name(), tun_addr, mtu);

        vpn::UdpSocket sock = vpn::UdpSocket::bind_any(listen_port);

        // Declared here so it outlives the packet loop and is destroyed before
        // the TUN device — routes first, then the interface they point at.
        // Every exit from this scope, normal or by exception, unwinds through it.
        vpn::netcfg::ChangeSet routes;
        if (install_routes) {
            routes = vpn::netcfg::install_client_routes(tun.name(),
                                                        vpn::format_address(*server));
        }

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
