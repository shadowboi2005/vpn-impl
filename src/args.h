#pragma once

#include <charconv>
#include <cstdint>
#include <optional>
#include <string_view>

// Argument parsing shared by the two entrypoints. Startup only — nothing here
// is on the packet path.
namespace vpn::args {

template <typename T>
std::optional<T> parse_number(std::string_view text, T low, T high) {
    T value{};
    const char* const first = text.data();
    const char* const last = first + text.size();
    const auto [ptr, ec] = std::from_chars(first, last, value);
    if (ec != std::errc{} || ptr != last || value < low || value > high) {
        return std::nullopt;
    }
    return value;
}

// 576 is the IPv4 minimum every host must handle; above 1500 needs jumbo frames
// we have not asked for.
inline std::optional<int> parse_mtu(std::string_view text) {
    return parse_number<int>(text, 576, 1500);
}

inline std::optional<uint16_t> parse_port(std::string_view text) {
    return parse_number<uint16_t>(text, 1, 65535);
}

}  // namespace vpn::args
