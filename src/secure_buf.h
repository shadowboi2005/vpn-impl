#pragma once

#include <sodium.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>

// Storage for key material.
//
// The point of these types is that forgetting to wipe a key is not possible
// rather than merely discouraged. A chaining key, an ephemeral private key or a
// derived transport key goes out of scope and is gone; there is no path where
// it is left on the stack because an error return took a different branch.

namespace vpn {

// A fixed-size buffer, zeroed on destruction.
//
// Copy is deleted so key material cannot silently propagate. Move is deleted
// too, which is the stricter choice: a move leaves the source object's bytes
// intact until its destructor runs, and every extra copy of a key is an extra
// place it can be read from. Functions here take an output span instead of
// returning one of these.
template <size_t N>
class SecureBuf {
public:
    static constexpr size_t size = N;

    SecureBuf() = default;
    ~SecureBuf() { ::sodium_memzero(bytes_.data(), bytes_.size()); }

    SecureBuf(const SecureBuf&) = delete;
    SecureBuf& operator=(const SecureBuf&) = delete;
    SecureBuf(SecureBuf&&) = delete;
    SecureBuf& operator=(SecureBuf&&) = delete;

    [[nodiscard]] std::span<uint8_t, N> mut() noexcept { return bytes_; }
    [[nodiscard]] std::span<const uint8_t, N> get() const noexcept { return bytes_; }

    // Wipe now rather than at scope exit, for state that dies before the object
    // holding it does.
    void wipe() noexcept { ::sodium_memzero(bytes_.data(), bytes_.size()); }

private:
    std::array<uint8_t, N> bytes_{};
};

// A long-term private key, in memory libsodium guards.
//
// sodium_malloc places the allocation between inaccessible guard pages, marks
// it no-access when locked, and mlocks it so it is never written to swap. That
// last part is the reason this exists separately from SecureBuf: a static
// private key lives for the whole run, which is long enough for the page
// holding it to be paged out to disk where zeroing it later achieves nothing.
class LockedKey {
public:
    static constexpr size_t size = 32;

    LockedKey() : bytes_(static_cast<uint8_t*>(::sodium_malloc(size))) {
        if (bytes_ == nullptr) {
            throw std::bad_alloc();
        }
        ::sodium_memzero(bytes_, size);
    }

    ~LockedKey() {
        if (bytes_ != nullptr) {
            // sodium_free zeroes before releasing, but being explicit costs
            // nothing and survives someone swapping the allocator later.
            ::sodium_memzero(bytes_, size);
            ::sodium_free(bytes_);
        }
    }

    LockedKey(const LockedKey&) = delete;
    LockedKey& operator=(const LockedKey&) = delete;
    LockedKey(LockedKey&&) = delete;
    LockedKey& operator=(LockedKey&&) = delete;

    [[nodiscard]] std::span<uint8_t, size> mut() noexcept {
        return std::span<uint8_t, size>(bytes_, size);
    }
    [[nodiscard]] std::span<const uint8_t, size> get() const noexcept {
        return std::span<const uint8_t, size>(bytes_, size);
    }

private:
    uint8_t* bytes_ = nullptr;
};

}  // namespace vpn
