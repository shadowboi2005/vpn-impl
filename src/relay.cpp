#include "relay.h"

#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <system_error>
#include <variant>
#include <vector>

#include "fd.h"
#include "session.h"
#include "wire.h"

namespace vpn {
namespace {

// How long to wait before re-sending a handshake initiation that got no reply.
//
// Phase 6 replaces this with the whitepaper's schedule: REKEY_TIMEOUT of 5 s
// plus up to 333 ms of jitter, bounded at 18 attempts. One flat interval is
// enough to make the tunnel come up reliably, which is all Phase 5 needs, and
// pretending otherwise would be implementing Phase 6 early.
constexpr uint64_t kHandshakeRetryNs = 1'000'000'000;

uint64_t monotonic_ns() noexcept {
    timespec now{};
    ::clock_gettime(CLOCK_MONOTONIC, &now);
    return static_cast<uint64_t>(now.tv_sec) * 1'000'000'000ULL +
           static_cast<uint64_t>(now.tv_nsec);
}

// Blocks SIGINT/SIGTERM and returns a descriptor that reports them instead.
// Nothing useful is async-signal-safe, so the loop must learn about signals the
// same way it learns about packets: by being told a descriptor is readable.
UniqueFd make_signalfd() {
    sigset_t mask;
    ::sigemptyset(&mask);
    ::sigaddset(&mask, SIGINT);
    ::sigaddset(&mask, SIGTERM);

    // Block first. Otherwise the default disposition still fires and the
    // process dies without unwinding — which means leaving routes and firewall
    // rules behind.
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
    if (config.identity == nullptr) {
        throw std::logic_error("run_relay needs an identity; the tunnel is not optional");
    }

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
    const size_t mtu = static_cast<size_t>(config.mtu);
    const size_t plaintext_capacity = wire::padded_length(mtu);
    std::vector<uint8_t> tun_buffer(wire::kTransportHeaderSize + plaintext_capacity +
                                    wire::kTagSize);
    // One spare byte, so an oversized datagram arrives visibly truncated rather
    // than looking like a legal maximum-sized one.
    std::vector<uint8_t> udp_buffer(wire::max_datagram(mtu) + 1);
    std::vector<uint8_t> handshake_buffer(wire::kInitiationSize);

    // Packets are read straight into the payload slot of the send buffer, so
    // the header goes in front of them and the AEAD seals over them in place —
    // no copy anywhere on the path.
    const std::span<uint8_t> plaintext_slot =
        std::span(tun_buffer).subspan(wire::kTransportHeaderSize, mtu);

    Session session;
    std::optional<noise::Handshake> pending;  // initiator only
    noise::TimestampGuard timestamp_guard;    // responder only
    uint64_t last_initiation_ns = 0;

    // Sends a handshake initiation, at most once per retry interval. Called
    // when there is traffic to carry and no session to carry it — WireGuard
    // initiates on demand rather than on a schedule, and so does this.
    const auto start_handshake = [&]() {
        if (config.role != Role::initiator || !config.peer.has_value()) {
            return;
        }
        const uint64_t now = monotonic_ns();
        if (last_initiation_ns != 0 && now - last_initiation_ns < kHandshakeRetryNs) {
            return;
        }
        last_initiation_ns = now;

        pending.emplace(*config.identity);
        const auto message = pending->write_initiation(handshake_buffer);
        if (!message.has_value()) {
            pending.reset();
            return;
        }
        if (sock.send_to(*message, *config.peer)) {
            ++stats.handshakes_started;
        } else {
            ++stats.dropped_send_failed;
        }
    };

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
                while (const std::optional<std::span<uint8_t>> packet =
                           tun.read_packet(plaintext_slot)) {
                    if (!config.peer.has_value()) {
                        ++stats.dropped_no_peer;
                        continue;
                    }
                    if (!session.active()) {
                        // Dropped, not queued. The application above will
                        // retransmit; holding packets for an unbounded time is
                        // its own kind of bug.
                        ++stats.dropped_no_session;
                        start_handshake();
                        continue;
                    }

                    const auto datagram = session.seal(tun_buffer, packet->size());
                    if (!datagram.has_value()) {
                        // The only way to get here is counter exhaustion, which
                        // is a hard stop: sending anything more under this key
                        // would reuse a nonce.
                        ++stats.dropped_counter_exhausted;
                        continue;
                    }
                    if (sock.send_to(*datagram, *config.peer)) {
                        ++stats.tun_to_udp_packets;
                        stats.tun_to_udp_bytes += datagram->size();
                    } else {
                        ++stats.dropped_send_failed;
                    }
                }
            } else if (fd == sock.fd()) {
                sockaddr_in from{};
                while (const std::optional<std::span<uint8_t>> datagram =
                           sock.recv_from(udp_buffer, from)) {
                    if (datagram->size() > wire::max_datagram(mtu)) {
                        ++stats.dropped_oversize;
                        continue;
                    }

                    const std::optional<wire::Message> message = wire::decode(*datagram);
                    if (!message.has_value()) {
                        ++stats.dropped_malformed;
                        continue;
                    }

                    if (const auto* const initiation =
                            std::get_if<wire::HandshakeInitiation>(&*message)) {
                        (void)initiation;
                        if (config.role != Role::responder) {
                            ++stats.dropped_malformed;
                            continue;
                        }
                        noise::Handshake handshake(*config.identity);
                        if (!handshake.read_initiation(*datagram, timestamp_guard)) {
                            // Silent. No reply, no log line: a response here
                            // would confirm to a scanner that a VPN lives at
                            // this address, and a log line per attempt is a
                            // free way to fill someone's disk.
                            ++stats.handshakes_rejected;
                            continue;
                        }
                        const auto response =
                            handshake.write_response(handshake_buffer, session.keys());
                        if (!response.has_value()) {
                            ++stats.handshakes_rejected;
                            continue;
                        }
                        session.activate();
                        // The endpoint comes from an authenticated message, and
                        // only from one.
                        if (!config.peer.has_value() || !same_endpoint(*config.peer, from)) {
                            config.peer = from;
                            ++stats.endpoint_updates;
                        }
                        if (sock.send_to(*response, from)) {
                            ++stats.handshakes_completed;
                            std::fprintf(stderr, "session established with %s\n",
                                         format_endpoint(from).c_str());
                        } else {
                            ++stats.dropped_send_failed;
                        }
                        continue;
                    }

                    if (const auto* const response =
                            std::get_if<wire::HandshakeResponse>(&*message)) {
                        (void)response;
                        if (config.role != Role::initiator || !pending.has_value()) {
                            ++stats.dropped_malformed;
                            continue;
                        }
                        // A rejected response leaves `pending` untouched, so a
                        // forged one cannot cancel a handshake in flight.
                        if (!pending->read_response(*datagram, session.keys())) {
                            ++stats.handshakes_rejected;
                            continue;
                        }
                        session.activate();
                        pending.reset();
                        ++stats.handshakes_completed;
                        std::fprintf(stderr, "session established with %s\n",
                                     format_endpoint(from).c_str());
                        continue;
                    }

                    if (std::holds_alternative<wire::CookieReply>(*message)) {
                        // Well-formed, and nothing handles it until Phase 7.
                        ++stats.dropped_malformed;
                        continue;
                    }

                    const auto* const data = std::get_if<wire::TransportData>(&*message);
                    if (data == nullptr) {
                        ++stats.dropped_malformed;
                        continue;
                    }
                    if (!session.active()) {
                        ++stats.dropped_no_session;
                        continue;
                    }
                    if (data->receiver_index != session.local_index()) {
                        // For someone else's session, or for one that no longer
                        // exists.
                        ++stats.dropped_malformed;
                        continue;
                    }
                    if (!session.replay_acceptable(data->counter)) {
                        ++stats.dropped_replay;
                        continue;
                    }

                    // Decrypted in place, over the received bytes.
                    const std::span<uint8_t> sealed =
                        datagram->subspan(wire::kTransportHeaderSize);
                    const std::optional<std::span<uint8_t>> plaintext =
                        session.open(data->counter, sealed);
                    if (!plaintext.has_value()) {
                        ++stats.dropped_auth_failed;
                        continue;
                    }

                    // Authenticated, so the source address can be trusted.
                    // Doing this before the tag verified would let anyone
                    // redirect the tunnel by spoofing one packet.
                    if (config.role == Role::responder &&
                        (!config.peer.has_value() || !same_endpoint(*config.peer, from))) {
                        config.peer = from;
                        ++stats.endpoint_updates;
                        std::fprintf(stderr, "peer roamed to %s\n", format_endpoint(from).c_str());
                    }

                    if (plaintext->empty()) {
                        ++stats.keepalives_received;
                        continue;
                    }

                    tun.write_packet(*plaintext);
                    ++stats.udp_to_tun_packets;
                    stats.udp_to_tun_bytes += plaintext->size();
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
                 "handshakes: %llu started, %llu completed, %llu rejected\n"
                 "dropped: %llu no-peer, %llu no-session, %llu send-failed, %llu oversize\n"
                 "dropped: %llu malformed, %llu replayed, %llu failed-auth, %llu counter-exhausted\n"
                 "keepalives received: %llu\n"
                 "endpoint updates: %llu\n",
                 static_cast<unsigned long long>(stats.tun_to_udp_packets),
                 static_cast<unsigned long long>(stats.tun_to_udp_bytes),
                 static_cast<unsigned long long>(stats.udp_to_tun_packets),
                 static_cast<unsigned long long>(stats.udp_to_tun_bytes),
                 static_cast<unsigned long long>(stats.handshakes_started),
                 static_cast<unsigned long long>(stats.handshakes_completed),
                 static_cast<unsigned long long>(stats.handshakes_rejected),
                 static_cast<unsigned long long>(stats.dropped_no_peer),
                 static_cast<unsigned long long>(stats.dropped_no_session),
                 static_cast<unsigned long long>(stats.dropped_send_failed),
                 static_cast<unsigned long long>(stats.dropped_oversize),
                 static_cast<unsigned long long>(stats.dropped_malformed),
                 static_cast<unsigned long long>(stats.dropped_replay),
                 static_cast<unsigned long long>(stats.dropped_auth_failed),
                 static_cast<unsigned long long>(stats.dropped_counter_exhausted),
                 static_cast<unsigned long long>(stats.keepalives_received),
                 static_cast<unsigned long long>(stats.endpoint_updates));
}

}  // namespace vpn
