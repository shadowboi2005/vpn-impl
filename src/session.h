#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "noise.h"
#include "wire.h"

// Transport state for one established session: the two keys, the send counter,
// and the replay window that decides whether an inbound counter is fresh.

namespace vpn {

// Counter limits, from the whitepaper. Both are unreachable in practice at any
// plausible packet rate; they are checked explicitly anyway, because "cannot
// happen" is not a property the code can rely on and a wrapped counter reuses a
// nonce, which is total failure of the AEAD.
inline constexpr uint64_t kRejectAfterMessages = ~uint64_t{0} - (uint64_t{1} << 13);
inline constexpr uint64_t kRekeyAfterMessages = uint64_t{1} << 60;
static_assert(kRejectAfterMessages == 0xffffffffffffdfffULL);

// Sliding-window replay protection.
//
// A bitmap of the last kBits counters plus a high-water mark. UDP reorders, so
// "reject anything not larger than the last one" would drop legitimate traffic;
// the window is how far back out-of-order delivery is still accepted.
//
// 8192 bits matches the kernel implementation. It is deliberately generous:
// under 10% loss with reordering, a window that is too small looks exactly like
// a mysterious intermittent packet loss.
class ReplayWindow {
public:
    static constexpr size_t kBits = 8192;

    // Pure query — would this counter be accepted? Called *before* the AEAD, to
    // avoid spending a decryption on an obvious replay.
    [[nodiscard]] bool acceptable(uint64_t counter) const noexcept;

    // Commit. This must only ever be called after the tag has verified.
    // Advancing the window on unauthenticated input lets anyone push the
    // high-water mark up and have the real peer's packets rejected as stale.
    void accept(uint64_t counter) noexcept;

    [[nodiscard]] uint64_t highest() const noexcept { return highest_; }

private:
    static constexpr size_t kWords = kBits / 64;

    [[nodiscard]] bool bit(uint64_t counter) const noexcept;
    void set_bit(uint64_t counter) noexcept;
    void clear_bit(uint64_t counter) noexcept;

    std::array<uint64_t, kWords> bitmap_{};
    uint64_t highest_ = 0;
    bool seen_ = false;
};

// One direction-pair of transport keys, plus the counters either side of them.
class Session {
public:
    Session() = default;
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // Filled by the handshake, then activated. Handing out the keys before
    // activation is what lets Handshake write into them without a move, since
    // key material is deliberately not movable.
    [[nodiscard]] noise::TransportKeys& keys() noexcept { return keys_; }
    void activate() noexcept;

    [[nodiscard]] bool active() const noexcept { return active_; }
    [[nodiscard]] uint32_t local_index() const noexcept { return keys_.local_index; }
    [[nodiscard]] uint32_t peer_index() const noexcept { return keys_.peer_index; }
    [[nodiscard]] uint64_t sent() const noexcept { return send_counter_; }

    // A counter may only be used while it is below the reject limit. Exposed
    // so the boundary is testable without sending 2^64 packets to reach it.
    [[nodiscard]] static constexpr bool counter_usable(uint64_t counter) noexcept {
        return counter < kRejectAfterMessages;
    }

    // Seals `plaintext_len` bytes that are already sitting at
    // buffer[kTransportHeaderSize...], in place, and writes the header in front
    // of them. Returns the whole datagram.
    //
    // Nullopt means the send counter is exhausted, which is a hard stop: there
    // is no safe way to send another packet under this key.
    std::optional<std::span<uint8_t>> seal(std::span<uint8_t> buffer, size_t plaintext_len);

    // Opens `sealed` in place. Returns the inner packet with padding trimmed,
    // or nullopt for any failure at all — a bad tag, a replayed counter, a
    // plaintext that is not a well-formed IPv4 packet.
    //
    // Every failure is silent by construction: there is no error to report, only
    // a packet that is not there.
    std::optional<std::span<uint8_t>> open(uint64_t counter, std::span<uint8_t> sealed);

    // Exposed so the relay can tell a replay apart from a forgery in its
    // counters. open() re-checks it regardless — Session stays correct on its
    // own, whatever a caller does or forgets to do.
    [[nodiscard]] bool replay_acceptable(uint64_t counter) const noexcept {
        return window_.acceptable(counter);
    }

    // True once this session has sent enough that Phase 6 should rekey it.
    [[nodiscard]] bool wants_rekey() const noexcept { return send_counter_ >= kRekeyAfterMessages; }

private:
    noise::TransportKeys keys_;
    ReplayWindow window_;
    uint64_t send_counter_ = 0;
    bool active_ = false;
};

}  // namespace vpn
