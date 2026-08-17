#include "udp.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <cerrno>
#include <charconv>
#include <cstring>
#include <system_error>

namespace vpn {

UdpSocket UdpSocket::bind_any(uint16_t port) {
    UniqueFd fd(::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP));
    if (!fd.valid()) {
        throw std::system_error(errno, std::generic_category(), "socket(AF_INET, SOCK_DGRAM)");
    }

    sockaddr_in me{};
    me.sin_family = AF_INET;
    me.sin_addr.s_addr = htonl(INADDR_ANY);
    me.sin_port = htons(port);

    if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&me), sizeof(me)) < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "bind udp port " + std::to_string(port));
    }

    return UdpSocket(std::move(fd));
}

uint16_t UdpSocket::local_port() const {
    sockaddr_in me{};
    socklen_t len = sizeof(me);
    if (::getsockname(fd_.get(), reinterpret_cast<sockaddr*>(&me), &len) < 0) {
        throw std::system_error(errno, std::generic_category(), "getsockname");
    }
    return ntohs(me.sin_port);
}

std::optional<std::span<uint8_t>> UdpSocket::recv_from(std::span<uint8_t> buf, sockaddr_in& from) {
    for (;;) {
        // The socket is AF_INET, so the kernel can only hand back a sockaddr_in.
        socklen_t len = sizeof(from);
        const ssize_t n = ::recvfrom(fd_.get(), buf.data(), buf.size(), 0,
                                     reinterpret_cast<sockaddr*>(&from), &len);
        if (n >= 0) {
            return buf.first(static_cast<size_t>(n));
        }
        switch (errno) {
            case EINTR:
                continue;
            case EAGAIN:  // EWOULDBLOCK is the same value on Linux
                return std::nullopt;
            case ECONNREFUSED:
            case ENETUNREACH:
            case EHOSTUNREACH:
                // A queued ICMP error surfacing on the socket. Stop draining
                // this round; epoll is level-triggered and will tell us again
                // if there is still a datagram waiting.
                return std::nullopt;
            default:
                throw std::system_error(errno, std::generic_category(), "recvfrom");
        }
    }
}

bool UdpSocket::send_to(std::span<const uint8_t> packet, const sockaddr_in& to) {
    for (;;) {
        const ssize_t n = ::sendto(fd_.get(), packet.data(), packet.size(), 0,
                                   reinterpret_cast<const sockaddr*>(&to), sizeof(to));
        if (n >= 0) {
            return static_cast<size_t>(n) == packet.size();
        }
        switch (errno) {
            case EINTR:
                continue;
            case EAGAIN:  // EWOULDBLOCK is the same value on Linux
            case ENOBUFS:
            case EMSGSIZE:
            case ENETUNREACH:
            case EHOSTUNREACH:
            case ECONNREFUSED:
            case EPERM:  // a firewall rule rejected it
                return false;
            default:
                throw std::system_error(errno, std::generic_category(), "sendto");
        }
    }
}

std::optional<sockaddr_in> parse_endpoint(std::string_view text) {
    const size_t colon = text.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 == text.size()) {
        return std::nullopt;
    }

    const std::string host(text.substr(0, colon));
    const std::string_view port_text = text.substr(colon + 1);

    unsigned port = 0;
    const char* const first = port_text.data();
    const char* const last = first + port_text.size();
    const auto [ptr, ec] = std::from_chars(first, last, port);
    if (ec != std::errc{} || ptr != last || port == 0 || port > 65535) {
        return std::nullopt;
    }

    sockaddr_in out{};
    out.sin_family = AF_INET;
    out.sin_port = htons(static_cast<uint16_t>(port));
    if (::inet_pton(AF_INET, host.c_str(), &out.sin_addr) != 1) {
        return std::nullopt;
    }
    return out;
}

std::string format_address(const sockaddr_in& addr) {
    char text[INET_ADDRSTRLEN] = {};
    if (::inet_ntop(AF_INET, &addr.sin_addr, text, sizeof(text)) == nullptr) {
        return "<invalid>";
    }
    return text;
}

std::string format_endpoint(const sockaddr_in& addr) {
    return format_address(addr) + ":" + std::to_string(ntohs(addr.sin_port));
}

bool same_endpoint(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

}  // namespace vpn
