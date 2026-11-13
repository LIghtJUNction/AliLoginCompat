#include "../app/src/main/cpp/trace_capture.hpp"
#include <cassert>
#include <string>
#include <thread>

thread_local ali::TraceCapture capture;
int main() {
    unsigned char sample[300]{};
    sample[0] = 0xab;
    capture.append(sample, 300);
    assert(capture.finish() == "{\"append_calls\":0,\"records\":[]}");
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
    assert(result.size() < 650); // Prefix is capped at 256 bytes.
    assert(capture.begin());
    for (int n = 0; n < 100; ++n) capture.append(sample, 1);
    capture.append(nullptr, 4);
    capture.append(sample, -1);
    result = capture.finish();
    assert(result.find("\"append_calls\":102") != std::string::npos);
    std::size_t count = 0, pos = 0;
    while ((pos = result.find("source_length", pos)) != std::string::npos) { ++count; ++pos; }
    assert(count == 64);
    assert(sample[0] == 0xab && sample[1] == 0xcd);
}
