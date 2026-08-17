#pragma once

#include <netinet/in.h>

#include <cstdint>
#include <cstdio>
#include <optional>

#include "tun.h"
#include "udp.h"

namespace vpn {

struct RelayStats {
    uint64_t tun_to_udp_packets = 0;
    uint64_t tun_to_udp_bytes = 0;
    uint64_t udp_to_tun_packets = 0;
    uint64_t udp_to_tun_bytes = 0;
    uint64_t dropped_no_peer = 0;
    uint64_t dropped_send_failed = 0;
    uint64_t dropped_oversize = 0;
    uint64_t dropped_malformed = 0;
    uint64_t keepalives_received = 0;
    uint64_t endpoint_updates = 0;
};

struct RelayConfig {
    int mtu = 1380;
    // Client: the configured server endpoint. Server: empty until it hears
    // from the client.
    std::optional<sockaddr_in> peer{};
    // Server only.
    bool learn_peer = false;
};

// Runs until SIGINT or SIGTERM, then returns so the caller's destructors run.
RelayStats run_relay(TunDevice& tun, UdpSocket& sock, RelayConfig config);

void print_stats(std::FILE* out, const RelayStats& stats);

}  // namespace vpn
