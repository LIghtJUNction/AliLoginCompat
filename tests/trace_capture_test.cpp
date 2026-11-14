#include "../app/src/main/cpp/trace_capture.hpp"
#include <cassert>
#include <string>
#include <thread>

thread_local ali::TraceCapture capture;
int main() {
    unsigned char sample[300]{};
    sample[0] = 0xab;
    capture.append(sample, 300);
    assert(capture.finish() == "{\"append_calls\":0,\"dropped_records\":0,\"records\":[]}");
    assert(capture.begin());
    assert(!capture.begin()); // Nested observation must not reset the outer call.
    capture.append(sample, 300);
    std::thread child([&] {
        assert(capture.begin());
        sample[1] = 0xcd;
        capture.append(sample, 2);
        auto result = capture.finish();
        assert(result.find("abcd") != std::string::npos);
        assert(result.find("\"append_calls\":1") != std::string::npos);
    });
    child.join();
    auto result = capture.finish();
    assert(result.find("\"source_length\":300") != std::string::npos);
    assert(result.find("abcd") == std::string::npos); // Copied data cannot change later.
    assert(result.size() < 750); // Prefix is capped at 256 bytes.
    assert(capture.begin());
    unsigned char late = 0xef;
    for (int n = 0; n < 700; ++n)
        capture.append(n == 399 ? &late : sample, 1, 0x1234);
    capture.append(nullptr, 4);
    capture.append(sample, -1);
    result = capture.finish();
    assert(result.find("\"append_calls\":702") != std::string::npos);
    assert(result.find("\"dropped_records\":188") != std::string::npos);
    assert(result.find("\"sequence\":400,\"caller_offset\":4660,\"source_length\":1,\"prefix_hex\":\"ef\"") != std::string::npos);
    std::size_t count = 0, pos = 0;
    while ((pos = result.find("source_length", pos)) != std::string::npos) { ++count; ++pos; }
    assert(count == 512);
    assert(sample[0] == 0xab && sample[1] == 0xcd);
}
