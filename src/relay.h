#pragma once

#include <netinet/in.h>

#include <cstdint>
#include <cstdio>
#include <optional>

#include "noise.h"
#include "tun.h"
#include "udp.h"
#include "wire.h"

namespace vpn {

struct RelayStats {
    uint64_t tun_to_udp_packets = 0;
    uint64_t tun_to_udp_bytes = 0;
    uint64_t udp_to_tun_packets = 0;
    uint64_t udp_to_tun_bytes = 0;
    uint64_t dropped_no_peer = 0;
    uint64_t dropped_no_session = 0;
    uint64_t dropped_send_failed = 0;
    uint64_t dropped_oversize = 0;
    uint64_t dropped_malformed = 0;
    // Split apart deliberately: a forged packet and a replayed one are
    // different events, and only one of them means someone recorded your
    // traffic and played it back.
    uint64_t dropped_replay = 0;
    uint64_t dropped_auth_failed = 0;
    uint64_t dropped_counter_exhausted = 0;
    uint64_t keepalives_received = 0;
    uint64_t endpoint_updates = 0;
    uint64_t handshakes_started = 0;
    uint64_t handshakes_completed = 0;
    uint64_t handshakes_rejected = 0;
};

// Which half of the handshake this process performs. The client initiates; the
// server only ever responds, and never speaks to an address it has not first
// authenticated.
enum class Role { initiator, responder };

struct RelayConfig {
    int mtu = wire::kDefaultTunnelMtu;
    Role role = Role::initiator;
    // Initiator: the configured server endpoint. Responder: empty until it has
    // authenticated a peer, which is the only thing that ever sets it.
    std::optional<sockaddr_in> peer{};
    // Borrowed for the life of the call. Required.
    const noise::Identity* identity = nullptr;
};

// Runs until SIGINT or SIGTERM, then returns so the caller's destructors run.
RelayStats run_relay(TunDevice& tun, UdpSocket& sock, RelayConfig config);

void print_stats(std::FILE* out, const RelayStats& stats);

}  // namespace vpn
