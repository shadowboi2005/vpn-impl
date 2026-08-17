#pragma once

#include <netinet/in.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "fd.h"

namespace vpn {

// A non-blocking IPv4 UDP socket. IPv4 only
class UdpSocket {
public:
    // Binds to 0.0.0.0:port. Port 0 asks the kernel for an ephemeral one.
    static UdpSocket bind_any(uint16_t port);

    [[nodiscard]] int fd() const noexcept { return fd_.get(); }
    [[nodiscard]] uint16_t local_port() const;

    // Returns the datagram as a prefix of `buf` and fills `from`, or nullopt
    // when there is nothing left to read.
    std::optional<std::span<uint8_t>> recv_from(std::span<uint8_t> buf, sockaddr_in& from);

    // Returns false if the datagram was dropped for an expected reason (queue
    // full, unreachable, too large). Unexpected errors throw.
    bool send_to(std::span<const uint8_t> packet, const sockaddr_in& to);

private:
    explicit UdpSocket(UniqueFd fd) : fd_(std::move(fd)) {}

    UniqueFd fd_;
};

// Parses "10.0.0.1:51820". Returns nullopt on anything malformed.
std::optional<sockaddr_in> parse_endpoint(std::string_view text);

std::string format_endpoint(const sockaddr_in& addr);

// Just the dotted quad, without the port — what ip(8) wants in a route.
std::string format_address(const sockaddr_in& addr);

bool same_endpoint(const sockaddr_in& a, const sockaddr_in& b);

}  // namespace vpn
