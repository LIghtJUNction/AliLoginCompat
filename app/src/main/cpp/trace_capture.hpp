#pragma once
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace ali {
// One instance per calling thread. This diagnostic never edits source buffers.
class TraceCapture {
    struct Record {
        std::size_t sequence;
        std::uintptr_t caller_offset;
        std::int32_t length;
        std::vector<unsigned char> prefix;
    };
    bool active_ = false;
    std::size_t calls_ = 0;
    std::size_t dropped_ = 0;
    std::vector<Record> records_;
public:
    bool begin() {
        if (active_) return false;
        active_ = true; calls_ = 0; dropped_ = 0; records_.clear();
        return true;
    }
    bool active() const { return active_; }
    void append(const void* source, std::int32_t length, std::uintptr_t caller_offset = 0) {
        if (!active_) return;
        ++calls_;
        if (!source || length <= 0) return;
        if (records_.size() >= 512) { ++dropped_; return; }
        const auto* bytes = static_cast<const unsigned char*>(source);
        records_.push_back({calls_, caller_offset, length, {bytes, bytes + std::min(length, 256)}});
    }
    std::string finish() {
        active_ = false;
        std::string result = "{\"append_calls\":" + std::to_string(calls_) +
            ",\"dropped_records\":" + std::to_string(dropped_) + ",\"records\":[";
        bool first = true;
        constexpr char digits[] = "0123456789abcdef";
        for (const auto& record : records_) {
            if (!first) result += ',';
            first = false;
            result += "{\"sequence\":" + std::to_string(record.sequence) +
                ",\"caller_offset\":" + std::to_string(record.caller_offset) +
                ",\"source_length\":" + std::to_string(record.length) + ",\"prefix_hex\":\"";
            for (auto byte : record.prefix) { result += digits[byte >> 4]; result += digits[byte & 15]; }
            result += "\"}";
        }
        result += "]}";
        records_.clear(); calls_ = 0; dropped_ = 0;
        return result;
    }
};
}
