#pragma once

#include <unistd.h>

#include <utility>

namespace vpn {

// Owns a file descriptor. Every fd in this program is released by a destructor,
// never by a close() call on an error path.
class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}
    ~UniqueFd() { reset(); }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}

    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

    void reset() noexcept {
        if (fd_ >= 0) {
            // Linux releases the descriptor even when close() reports EINTR, so
            // retrying here would risk closing a descriptor someone else now owns.
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_ = -1;
};

}  // namespace vpn
