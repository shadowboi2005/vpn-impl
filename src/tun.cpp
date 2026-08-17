#include "tun.h"

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>

namespace vpn {

TunDevice TunDevice::open(const std::string& name) {
    if (name.empty() || name.size() >= IFNAMSIZ) {
        throw std::invalid_argument("tun device name must be 1.." + std::to_string(IFNAMSIZ - 1) +
                                    " characters: " + name);
    }

    UniqueFd fd(::open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK));
    if (!fd.valid()) {
        throw std::system_error(errno, std::generic_category(), "open /dev/net/tun");
    }

    ifreq ifr{};
    // IFF_NO_PI is not optional. Without it the kernel prepends a 4-byte
    // packet-information header to every packet and every parser downstream is
    // silently off by four bytes.
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    // ifr was value-initialised, so ifr_name is already NUL-terminated and the
    // length was bounds-checked above.
    std::memcpy(ifr.ifr_name, name.data(), name.size());

    if (::ioctl(fd.get(), TUNSETIFF, &ifr) < 0) {
        throw std::system_error(errno, std::generic_category(), "ioctl(TUNSETIFF) on " + name);
    }

    // The kernel writes back the name it actually used.
    return TunDevice(std::move(fd), std::string(ifr.ifr_name, ::strnlen(ifr.ifr_name, IFNAMSIZ)));
}

std::optional<std::span<uint8_t>> TunDevice::read_packet(std::span<uint8_t> buf) {
    for (;;) {
        const ssize_t n = ::read(fd_.get(), buf.data(), buf.size());
        if (n >= 0) {
            return buf.first(static_cast<size_t>(n));
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN) {  // EWOULDBLOCK is the same value on Linux
            return std::nullopt;
        }
        throw std::system_error(errno, std::generic_category(), "read from " + name_);
    }
}

void TunDevice::write_packet(std::span<const uint8_t> packet) {
    for (;;) {
        const ssize_t n = ::write(fd_.get(), packet.data(), packet.size());
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN) {
                // The device queue is full. Dropping is what a real NIC does.
                return;
            }
            throw std::system_error(errno, std::generic_category(), "write to " + name_);
        }
        // A TUN device takes whole packets or nothing. A short write means our
        // length accounting is wrong, so retrying would send a corrupt packet.
        if (static_cast<size_t>(n) != packet.size()) {
            throw std::runtime_error("short write to " + name_ + ": " + std::to_string(n) + " of " +
                                     std::to_string(packet.size()) + " bytes");
        }
        return;
    }
}

}  // namespace vpn
