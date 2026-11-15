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
    struct Event {
        std::size_t sequence;
        std::uintptr_t caller_offset;
        std::string kind;
        std::string target;
        long ret;
    };
    bool active_ = false;
    std::size_t calls_ = 0;
    std::size_t dropped_ = 0;
    std::size_t event_calls_ = 0;
    std::size_t dropped_events_ = 0;
    std::vector<Record> records_;
    std::vector<Event> events_;

    static void append_json_escaped(std::string& out, const std::string& s) {
        for (unsigned char c : s) {
            if (c == '"' || c == '\\') { out.push_back('\\'); out.push_back(static_cast<char>(c)); }
            else if (c >= 0x20 && c < 0x7f) out.push_back(static_cast<char>(c));
            else out.push_back('?');
        }
    }
public:
    static constexpr std::size_t kMaxEvents = 4096;
    bool begin() {
        if (active_) return false;
        active_ = true; calls_ = 0; dropped_ = 0; event_calls_ = 0; dropped_events_ = 0;
        records_.clear(); events_.clear();
        return true;
    }
    bool active() const { return active_; }
    std::size_t position() const { return calls_; }
    void append(const void* source, std::int32_t length, std::uintptr_t caller_offset = 0) {
        if (!active_) return;
        ++calls_;
        if (!source || length <= 0) return;
        if (records_.size() >= 512) { ++dropped_; return; }
        const auto* bytes = static_cast<const unsigned char*>(source);
        records_.push_back({calls_, caller_offset, length, {bytes, bytes + std::min(length, 256)}});
    }
    void record_event(const char* kind, std::uintptr_t caller_offset, const char* target, long ret) {
        if (!active_) return;
        ++event_calls_;
        if (events_.size() >= kMaxEvents) { ++dropped_events_; return; }
        events_.push_back({event_calls_, caller_offset, kind ? kind : "", target ? target : "", ret});
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
        result += "]";
        if (!events_.empty() || dropped_events_ > 0) {
            result += ",\"event_calls\":" + std::to_string(event_calls_) +
                ",\"dropped_events\":" + std::to_string(dropped_events_) + ",\"events\":[";
            bool first_ev = true;
            for (const auto& ev : events_) {
                if (!first_ev) result += ',';
                first_ev = false;
                result += "{\"seq\":" + std::to_string(ev.sequence) +
                    ",\"caller_offset\":" + std::to_string(ev.caller_offset) +
                    ",\"kind\":\"";
                append_json_escaped(result, ev.kind);
                result += "\",\"target\":\"";
                append_json_escaped(result, ev.target);
                result += "\",\"ret\":" + std::to_string(ev.ret) + "}";
            }
            result += "]";
        }
        result += "}";
        records_.clear(); events_.clear(); calls_ = 0; dropped_ = 0; event_calls_ = 0; dropped_events_ = 0;
        return result;
    }
};
}
