#include "relay.h"

#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <system_error>
#include <vector>

#include "fd.h"

namespace vpn {
namespace {

// Blocks SIGINT/SIGTERM and returns a descriptor that reports them instead.
// Nothing useful is async-signal-safe, so the loop must learn about signals the
// same way it learns about packets: by being told a descriptor is readable.
UniqueFd make_signalfd() {
    sigset_t mask;
    ::sigemptyset(&mask);
    ::sigaddset(&mask, SIGINT);
    ::sigaddset(&mask, SIGTERM);

    // Block first. Otherwise the default disposition still fires and the
    // process dies without unwinding — which from Phase 2 onward means leaving
    // routes and firewall rules behind.
    if (::sigprocmask(SIG_BLOCK, &mask, nullptr) < 0) {
        throw std::system_error(errno, std::generic_category(), "sigprocmask");
    }

    UniqueFd fd(::signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK));
    if (!fd.valid()) {
        throw std::system_error(errno, std::generic_category(), "signalfd");
    }
    return fd;
}

void epoll_add(int epoll_fd, int fd) {
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.fd = fd;
    if (::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        throw std::system_error(errno, std::generic_category(), "epoll_ctl(EPOLL_CTL_ADD)");
    }
}

}  // namespace

RelayStats run_relay(TunDevice& tun, UdpSocket& sock, RelayConfig config) {
    RelayStats stats;

    UniqueFd signal_fd = make_signalfd();
    UniqueFd epoll_fd(::epoll_create1(EPOLL_CLOEXEC));
    if (!epoll_fd.valid()) {
        throw std::system_error(errno, std::generic_category(), "epoll_create1");
    }

    epoll_add(epoll_fd.get(), tun.fd());
    epoll_add(epoll_fd.get(), sock.fd());
    epoll_add(epoll_fd.get(), signal_fd.get());

    // Sized once, here, and reused for every packet for the life of the
    // process. Nothing below this line allocates.
    const size_t capacity = static_cast<size_t>(config.mtu) + 256;
    std::vector<uint8_t> tun_buffer(capacity);
    std::vector<uint8_t> udp_buffer(capacity);

    std::array<epoll_event, 8> events{};
    bool running = true;

    while (running) {
        const int ready = ::epoll_wait(epoll_fd.get(), events.data(),
                                       static_cast<int>(events.size()), -1);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::generic_category(), "epoll_wait");
        }

        for (int i = 0; i < ready; ++i) {
            const int fd = events[i].data.fd;

            if (fd == tun.fd()) {
                // Outbound: plaintext IP packet from the kernel, straight onto
                // the wire. Phase 3 inserts framing here, Phase 5 encryption.
                while (const std::optional<std::span<uint8_t>> packet =
                           tun.read_packet(tun_buffer)) {
                    if (!config.peer.has_value()) {
                        ++stats.dropped_no_peer;
                        continue;
                    }
                    if (sock.send_to(*packet, *config.peer)) {
                        ++stats.tun_to_udp_packets;
                        stats.tun_to_udp_bytes += packet->size();
                    } else {
                        ++stats.dropped_send_failed;
                    }
                }
            } else if (fd == sock.fd()) {
                // Inbound: whatever arrived on the UDP socket goes to the TUN
                // device unexamined. That is exactly what Phase 3 onward stops
                // doing.
                sockaddr_in from{};
                while (const std::optional<std::span<uint8_t>> packet =
                           sock.recv_from(udp_buffer, from)) {
                    if (config.learn_peer &&
                        (!config.peer.has_value() || !same_endpoint(*config.peer, from))) {
                        config.peer = from;
                        ++stats.endpoint_updates;
                        std::fprintf(stderr, "peer endpoint is now %s\n",
                                     format_endpoint(from).c_str());
                    }
                    if (packet->size() > static_cast<size_t>(config.mtu)) {
                        ++stats.dropped_oversize;
                        continue;
                    }
                    if (packet->empty()) {
                        continue;
                    }
                    tun.write_packet(*packet);
                    ++stats.udp_to_tun_packets;
                    stats.udp_to_tun_bytes += packet->size();
                }
            } else if (fd == signal_fd.get()) {
                signalfd_siginfo info{};
                const ssize_t n = ::read(signal_fd.get(), &info, sizeof(info));
                if (n == static_cast<ssize_t>(sizeof(info))) {
                    std::fprintf(stderr, "signal %u received, shutting down\n", info.ssi_signo);
                }
                running = false;
            }
        }
    }

    return stats;
}

void print_stats(std::FILE* out, const RelayStats& stats) {
    std::fprintf(out,
                 "tun->udp %llu packets / %llu bytes\n"
                 "udp->tun %llu packets / %llu bytes\n"
                 "dropped: %llu no-peer, %llu send-failed, %llu oversize\n"
                 "endpoint updates: %llu\n",
                 static_cast<unsigned long long>(stats.tun_to_udp_packets),
                 static_cast<unsigned long long>(stats.tun_to_udp_bytes),
                 static_cast<unsigned long long>(stats.udp_to_tun_packets),
                 static_cast<unsigned long long>(stats.udp_to_tun_bytes),
                 static_cast<unsigned long long>(stats.dropped_no_peer),
                 static_cast<unsigned long long>(stats.dropped_send_failed),
                 static_cast<unsigned long long>(stats.dropped_oversize),
                 static_cast<unsigned long long>(stats.endpoint_updates));
}

}  // namespace vpn
