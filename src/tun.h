#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "fd.h"

namespace vpn {

// A TUN device. Layer 3, no packet-information header
// IP packet and nothing else. The fd is non-blocking, so the read path drains.
class TunDevice {
public:
    // Creates (or attaches to) the named device. Throws std::system_error on failure
    static TunDevice open(const std::string& name);

    [[nodiscard]] int fd() const noexcept { return fd_.get(); }
    [[nodiscard]] const std::string& name() const noexcept { return name_; }

    // Returns the packet as a prefix of `buf`, or nullopt when the device has
    // nothing queued. EINTR is retried internally.
    std::optional<std::span<uint8_t>> read_packet(std::span<uint8_t> buf);

    // Writes one whole packet. A short write is a bug in our length accounting,
    // not something to retry, so it throws.
    void write_packet(std::span<const uint8_t> packet);

private:
    TunDevice(UniqueFd fd, std::string name) : fd_(std::move(fd)), name_(std::move(name)) {}

    UniqueFd fd_;
    std::string name_;
};

}  // namespace vpn
