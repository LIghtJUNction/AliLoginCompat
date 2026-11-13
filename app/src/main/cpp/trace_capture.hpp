#pragma once
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace ali {
// One instance per calling thread. This diagnostic never edits source buffers.
class TraceCapture {
    struct Record { std::int32_t length; std::vector<unsigned char> prefix; };
    bool active_ = false;
    std::size_t calls_ = 0;
    std::vector<Record> records_;
public:
    bool begin() {
        if (active_) return false;
        active_ = true; calls_ = 0; records_.clear();
        return true;
    }
    void append(const void* source, std::int32_t length) {
        if (!active_) return;
        ++calls_;
        if (!source || length <= 0 || records_.size() >= 64) return;
        const auto* bytes = static_cast<const unsigned char*>(source);
        records_.push_back({length, {bytes, bytes + std::min(length, 256)}});
    }
    std::string finish() {
        active_ = false;
        std::string result = "{\"append_calls\":" + std::to_string(calls_) + ",\"records\":[";
        bool first = true;
        constexpr char digits[] = "0123456789abcdef";
        for (const auto& record : records_) {
            if (!first) result += ',';
            first = false;
            result += "{\"source_length\":" + std::to_string(record.length) + ",\"prefix_hex\":\"";
            for (auto byte : record.prefix) { result += digits[byte >> 4]; result += digits[byte & 15]; }
            result += "\"}";
        }
        result += "]}";
        records_.clear(); calls_ = 0;
        return result;
    }
};
}
