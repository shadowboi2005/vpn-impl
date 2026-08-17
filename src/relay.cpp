#include "relay.h"

#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
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
#include "wire.h"

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
    //
    // The send buffer has to hold a full framed datagram: 16-byte header,
    // plaintext padded up to a multiple of 16, and the 16-byte tag. The receive
    // buffer gets one spare byte so an oversized datagram arrives visibly
    // truncated rather than looking like a legal maximum-sized one.
    const size_t mtu = static_cast<size_t>(config.mtu);
    const size_t plaintext_capacity = wire::padded_length(mtu);
    std::vector<uint8_t> tun_buffer(wire::kTransportHeaderSize + plaintext_capacity +
                                    wire::kTagSize);
    std::vector<uint8_t> udp_buffer(wire::max_datagram(mtu) + 1);
    // Packets are read straight into the payload slot of the send buffer, so
    // framing is a header write in front of them rather than a copy. Phase 5
    // seals in place over the same bytes.
    const std::span<uint8_t> plaintext_slot =
        std::span(tun_buffer).subspan(wire::kTransportHeaderSize, mtu);

    // Phase 4 replaces both of these with real session state. Until then there
    // is one implicit session, index zero, and the counter is a plain sequence
    // number that nothing yet depends on.
    uint32_t peer_index = 0;
    uint64_t send_counter = 0;

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
                // Outbound: an IP packet from the kernel, framed as a transport
                // data message. Phase 5 replaces the zero placeholder tag with
                // a real one and seals the payload in place.
                while (const std::optional<std::span<uint8_t>> packet =
                           tun.read_packet(plaintext_slot)) {
                    if (!config.peer.has_value()) {
                        ++stats.dropped_no_peer;
                        continue;
                    }

                    const size_t padded = wire::padded_length(packet->size());
                    const auto payload = tun_buffer.begin() +
                                         static_cast<ptrdiff_t>(wire::kTransportHeaderSize);
                    std::fill(payload + static_cast<ptrdiff_t>(packet->size()),
                              payload + static_cast<ptrdiff_t>(padded + wire::kTagSize),
                              uint8_t{0});

                    wire::encode_transport_header(tun_buffer, peer_index, send_counter++);
                    const std::span<const uint8_t> datagram(
                        tun_buffer.data(), wire::kTransportHeaderSize + padded + wire::kTagSize);

                    if (sock.send_to(datagram, *config.peer)) {
                        ++stats.tun_to_udp_packets;
                        stats.tun_to_udp_bytes += datagram.size();
                    } else {
                        ++stats.dropped_send_failed;
                    }
                }
            } else if (fd == sock.fd()) {
                // Inbound: decode before anything else touches the bytes. Every
                // byte here is attacker-controlled.
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
                    // Handshake and cookie messages are well-formed but have
                    // nowhere to go until Phase 4 builds the state machine.
                    const auto* const data = std::get_if<wire::TransportData>(&*message);
                    if (data == nullptr) {
                        ++stats.dropped_malformed;
                        continue;
                    }

                    // Phase 5 opens the AEAD here, and only what follows may
                    // depend on the contents. Phase 6 moves the endpoint update
                    // below that point: updating on an unauthenticated packet
                    // lets anyone redirect the tunnel.
                    const std::span<const uint8_t> plaintext =
                        data->sealed.first(data->sealed.size() - wire::kTagSize);

                    // The sender pads to a multiple of 16 before sealing, so
                    // anything else did not come from a peer following the
                    // protocol.
                    if (plaintext.size() % 16 != 0) {
                        ++stats.dropped_malformed;
                        continue;
                    }

                    if (config.learn_peer &&
                        (!config.peer.has_value() || !same_endpoint(*config.peer, from))) {
                        config.peer = from;
                        ++stats.endpoint_updates;
                        std::fprintf(stderr, "peer endpoint is now %s\n",
                                     format_endpoint(from).c_str());
                    }

                    // An empty plaintext is a keepalive: authenticated, and
                    // deliberately not delivered anywhere.
                    if (plaintext.empty()) {
                        ++stats.keepalives_received;
                        continue;
                    }

                    // The padded length is not on the wire; the inner header's
                    // own length field is what says where the packet ends.
                    const std::optional<size_t> length = wire::inner_packet_length(plaintext);
                    if (!length.has_value()) {
                        ++stats.dropped_malformed;
                        continue;
                    }

                    tun.write_packet(plaintext.first(*length));
                    ++stats.udp_to_tun_packets;
                    stats.udp_to_tun_bytes += *length;
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
                 "dropped: %llu no-peer, %llu send-failed, %llu oversize, %llu malformed\n"
                 "keepalives received: %llu\n"
                 "endpoint updates: %llu\n",
                 static_cast<unsigned long long>(stats.tun_to_udp_packets),
                 static_cast<unsigned long long>(stats.tun_to_udp_bytes),
                 static_cast<unsigned long long>(stats.udp_to_tun_packets),
                 static_cast<unsigned long long>(stats.udp_to_tun_bytes),
                 static_cast<unsigned long long>(stats.dropped_no_peer),
                 static_cast<unsigned long long>(stats.dropped_send_failed),
                 static_cast<unsigned long long>(stats.dropped_oversize),
                 static_cast<unsigned long long>(stats.dropped_malformed),
                 static_cast<unsigned long long>(stats.keepalives_received),
                 static_cast<unsigned long long>(stats.endpoint_updates));
}

}  // namespace vpn
