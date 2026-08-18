#include "session.h"

#include <algorithm>

#include "crypto.h"

namespace vpn {

// ---------------------------------------------------------------- ReplayWindow

bool ReplayWindow::bit(uint64_t counter) const noexcept {
    const size_t index = static_cast<size_t>(counter % kBits);
    return (bitmap_[index / 64] >> (index % 64)) & 1U;
}

void ReplayWindow::set_bit(uint64_t counter) noexcept {
    const size_t index = static_cast<size_t>(counter % kBits);
    bitmap_[index / 64] |= uint64_t{1} << (index % 64);
}

void ReplayWindow::clear_bit(uint64_t counter) noexcept {
    const size_t index = static_cast<size_t>(counter % kBits);
    bitmap_[index / 64] &= ~(uint64_t{1} << (index % 64));
}

bool ReplayWindow::acceptable(uint64_t counter) const noexcept {
    if (counter >= kRejectAfterMessages) {
        return false;
    }
    if (!seen_) {
        return true;
    }
    if (counter > highest_) {
        return true;
    }
    // Older than anything the window still remembers. It may well be a genuine
    // straggler rather than an attack, but there is no way to tell, and
    // accepting it would mean accepting replays.
    if (highest_ - counter >= kBits) {
        return false;
    }
    return !bit(counter);
}

void ReplayWindow::accept(uint64_t counter) noexcept {
    if (!seen_) {
        seen_ = true;
        highest_ = counter;
        bitmap_.fill(0);
        set_bit(counter);
        return;
    }

    if (counter > highest_) {
        const uint64_t advance = counter - highest_;
        if (advance >= kBits) {
            // The window has moved past everything it held.
            bitmap_.fill(0);
        } else {
            // Clear the slots the window is sliding over, one counter at a
            // time. Word-at-a-time would be faster and is where the shift
            // arithmetic goes wrong: shifting a uint64_t by 64 or more is
            // undefined, and the bug only shows up at the exact gap size that
            // triggers it. This loop has no shift wider than 63.
            for (uint64_t c = highest_ + 1; c <= counter; ++c) {
                clear_bit(c);
            }
        }
        highest_ = counter;
    }
    set_bit(counter);
}

// --------------------------------------------------------------------- Session

void Session::activate() noexcept {
    window_ = ReplayWindow{};
    send_counter_ = 0;
    active_ = true;
}

std::optional<std::span<uint8_t>> Session::seal(std::span<uint8_t> buffer, size_t plaintext_len) {
    if (!active_) {
        return std::nullopt;
    }
    // Never wrap, and never reuse a counter with a key. Past this point the only
    // safe move is a new key, which is Phase 6's job; until then it is a stop.
    if (!counter_usable(send_counter_)) {
        return std::nullopt;
    }

    const size_t padded = wire::padded_length(plaintext_len);
    if (buffer.size() < wire::kTransportHeaderSize + padded + wire::kTagSize) {
        return std::nullopt;
    }

    const std::span<uint8_t> payload = buffer.subspan(wire::kTransportHeaderSize);
    // Zero the padding. It is encrypted along with the packet, so its contents
    // never reach the wire in the clear — but leaving it as whatever the last
    // packet put there would leak that packet's tail into this one's ciphertext
    // length-for-length, and there is no reason to.
    std::fill(payload.begin() + static_cast<ptrdiff_t>(plaintext_len),
              payload.begin() + static_cast<ptrdiff_t>(padded), uint8_t{0});

    const uint64_t counter = send_counter_++;

    // In place: libsodium allows the ciphertext to be written over the
    // plaintext. AAD is empty — WireGuard specifies AEAD(key, nonce, P, e), and
    // authenticating the header instead would be a different protocol. The
    // header is not thereby unprotected: receiver_index only selects a session,
    // and a tampered counter produces a different nonce, which fails the tag.
    crypto::seal(payload.first(padded + wire::kTagSize), keys_.send.get(), counter,
                 payload.first(padded), {});

    wire::encode_transport_header(buffer, keys_.peer_index, counter);
    return buffer.first(wire::kTransportHeaderSize + padded + wire::kTagSize);
}

std::optional<std::span<uint8_t>> Session::open(uint64_t counter, std::span<uint8_t> sealed) {
    if (!active_ || sealed.size() < wire::kTagSize) {
        return std::nullopt;
    }

    // Cheap first: an obvious replay costs nothing to reject, and making an
    // attacker's replay flood cost us a ChaCha20 pass each would be a free
    // amplifier for them.
    if (!window_.acceptable(counter)) {
        return std::nullopt;
    }

    const size_t plaintext_len = sealed.size() - wire::kTagSize;
    // The sender pads to a multiple of 16 before sealing, so anything else did
    // not come from a peer following the protocol.
    if (plaintext_len % 16 != 0) {
        return std::nullopt;
    }

    if (!crypto::open(sealed.first(plaintext_len), keys_.receive.get(), counter, sealed, {})) {
        return std::nullopt;
    }

    // Only now. The window moves for packets that proved they came from the
    // peer, and for nothing else.
    window_.accept(counter);

    const std::span<uint8_t> plaintext = sealed.first(plaintext_len);
    if (plaintext.empty()) {
        return plaintext;  // an authenticated keepalive
    }

    // The padded length is not on the wire; the inner header's own length field
    // is what says where the real packet ends.
    const std::optional<size_t> length = wire::inner_packet_length(plaintext);
    if (!length.has_value()) {
        return std::nullopt;
    }
    return plaintext.first(*length);
}

}  // namespace vpn
