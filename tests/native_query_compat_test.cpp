#include "../app/src/main/cpp/native_query_compat.hpp"

#include <array>
#include <cassert>
#include <cstdio>
#include <string>
#include <unistd.h>

namespace {
struct Property {
    const char* name;
    const char* value;
    int result;
    int error;
};

int read_sample(const prop_info* opaque, char* name, char* value) {
    const auto& sample = *reinterpret_cast<const Property*>(opaque);
    if (name) std::strcpy(name, sample.name);
    if (value) std::strcpy(value, sample.value);
    errno = sample.error;
    return sample.result;
}

void check_property(const Property& property, bool compat, const char* expected_value,
                    int expected_result, bool provide_name = true) {
    char name[64]{};
    char value[64]{};
    int observed = 0;
    const int result = ali::native_query::read_property(
        read_sample, reinterpret_cast<const prop_info*>(&property),
        provide_name ? name : nullptr, value, compat,
        [&](const char* actual_name, const char* actual_value) {
            ++observed;
            assert(std::strcmp(actual_name, property.name) == 0);
            assert(std::strcmp(actual_value, expected_value) == 0);
            // Diagnostic helpers must not change the API's errno contract.
            errno = EIO;
        });
    assert(result == expected_result);
    assert(errno == property.error);
    assert(std::strcmp(value, expected_value) == 0);
    assert(observed == (provide_name && property.result >= 0 ? 1 : 0));
}

void property_contract() {
    check_property({"ro.debuggable", "1", 1, EAGAIN}, false, "1", 1);
    check_property({"ro.debuggable", "enabled", 7, ERANGE}, true, "0", 1);
    check_property({"service.adb.root", "true", 4, EINTR}, true, "0", 1);
    check_property({"ro.secure", "0", 1, EBUSY}, true, "1", 1);
    // Preserve the original integer result instead of recomputing it globally.
    check_property({"unrelated.property", "untouched", 37, EALREADY},
                   true, "untouched", 37);
    check_property({"ro.secure", "stale-value", -1, EACCES},
                   true, "stale-value", -1);
    check_property({"ro.debuggable", "1", 1, ENOTTY}, true, "1", 1, false);

    bool observed = false;
    errno = 0;
    assert(ali::native_query::read_property(
        nullptr, nullptr, nullptr, nullptr, true,
        [&](const char*, const char*) { observed = true; }) == -1);
    assert(errno == ENOSYS);
    assert(!observed);
}

void receive_contract() {
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0);
    const std::string payload = "magicnet0|body";
    assert(send(sockets[0], payload.data(), payload.size(), 0) ==
           static_cast<ssize_t>(payload.size()));

    std::array<char, 12> first;
    std::array<char, 48> second;
    first.fill('a');
    second.fill('b');
    // This occurrence is outside the valid receive length and must stay intact.
    std::memcpy(second.data() + 24, "magicnet0", 9);
    auto expected_first = first;
    auto expected_second = second;
    std::memcpy(expected_first.data(), payload.data(), first.size());
    std::memcpy(expected_second.data(), payload.data() + first.size(),
                payload.size() - first.size());
    struct iovec vectors[] = {{first.data(), first.size()}, {second.data(), second.size()}};
    struct msghdr message{};
    message.msg_iov = vectors;
    message.msg_iovlen = 2;

    assert(ali::native_query::receive_message(
        ::recvmsg, sockets[1], &message, MSG_PEEK) == static_cast<ssize_t>(payload.size()));
    assert(first == expected_first);
    assert(second == expected_second);
    // Flags and the message must reach the real syscall: PEEK did not consume it.
    assert(ali::native_query::receive_message(
        ::recvmsg, sockets[1], &message, 0) == static_cast<ssize_t>(payload.size()));
    assert(first == expected_first);
    assert(second == expected_second);

    errno = 0;
    assert(ali::native_query::receive_message(::recvmsg, -1, &message, 0) == -1);
    assert(errno == EBADF);
    assert(first == expected_first);
    assert(second == expected_second);

    // A truncated datagram can report more bytes than fit in the iovec.
    assert(send(sockets[0], payload.data(), payload.size(), 0) ==
           static_cast<ssize_t>(payload.size()));
    std::array<char, 4> short_buffer{};
    struct iovec short_vector{short_buffer.data(), short_buffer.size()};
    struct msghdr short_message{};
    short_message.msg_iov = &short_vector;
    short_message.msg_iovlen = 1;
    assert(ali::native_query::receive_message(
        ::recvmsg, sockets[1], &short_message, MSG_TRUNC) ==
        static_cast<ssize_t>(payload.size()));
    assert((short_message.msg_flags & MSG_TRUNC) != 0);
    assert(std::memcmp(short_buffer.data(), payload.data(), short_buffer.size()) == 0);

    errno = 0;
    assert(ali::native_query::receive_message(nullptr, -1, nullptr, 0) == -1);
    assert(errno == ENOSYS);
    assert(close(sockets[0]) == 0);
    assert(close(sockets[1]) == 0);
}
}  // namespace

int main() {
    property_contract();
    receive_contract();
    std::puts("native query ABI and receive regression tests passed");
}
