#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace ali {
enum class Format { Idlefish, Taobao };
using Record = std::array<std::uint8_t, 18>;
// This is a shape gate, not a claim that the seven bytes all represent risks.
inline bool matches(const void* source, int length, Format format = Format::Idlefish) {
    if (!source || length != 18) return false;
    auto data = static_cast<const std::uint8_t*>(source);
    const bool taobao = format == Format::Taobao;
    // The Taobao leading state byte varied between 00 and 10 in live samples.
    const bool leading_matches = taobao ? (data[0] == 0 || data[0] == 0x10) : data[0] == 0x11;
    if (!leading_matches || data[8] != 0x22 || data[9] != 0x33) return false;
    for (std::size_t i = 10; i < 18; ++i) {
        const auto expected = (taobao && i == 15) ? 4 : 0;
        if (data[i] != expected) return false;
    }
    return true;
}
inline Record rewrite(const void* source) {
    Record output{};
    std::memcpy(output.data(), source, output.size());
    // Experimental neutralization. Header, marker, length and trailer survive.
    for (std::size_t i = 1; i < 8; ++i) output[i] = 0;
    return output;
}
}
