#pragma once

#include "taobao_env_compat.hpp"

#include <cerrno>
#include <cstdio>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>

namespace ali::native_file {

inline int create_proc_buffer() {
    return static_cast<int>(::syscall(__NR_memfd_create, "proc", 1U /* MFD_CLOEXEC */));
}

inline int close_with_error(int fd, int error) {
    if (fd >= 0) ::close(fd);
    errno = error;
    return -1;
}

// Consumes input. A failed copy returns -1 so the caller can reopen the original.
template <typename CreateBuffer = int (*)()>
int filter_proc_fd(int input, ali::env::ProcKind kind,
                   CreateBuffer create_buffer = create_proc_buffer,
                   std::size_t* filtered_size = nullptr) {
    if (input < 0) return input;
    const int entry_errno = errno;
    constexpr std::size_t kMaxProcBytes = 4 * 1024 * 1024;
    std::string raw;
    char buffer[4096];
    for (;;) {
        const ssize_t count = ::read(input, buffer, sizeof(buffer));
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            return close_with_error(input, errno);
        }
        const auto size = static_cast<std::size_t>(count);
        if (size > kMaxProcBytes - raw.size()) {
            return close_with_error(input, EFBIG);
        }
        raw.append(buffer, size);
    }
    ::close(input);

    const std::string filtered = ali::env::filter_proc_content(raw, kind);
    const int output = create_buffer();
    if (output < 0) return -1;
    std::size_t offset = 0;
    while (offset < filtered.size()) {
        const ssize_t count = ::write(output, filtered.data() + offset,
                                      filtered.size() - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            return close_with_error(output, errno);
        }
        if (count == 0) return close_with_error(output, EIO);
        offset += static_cast<std::size_t>(count);
    }
    if (::lseek(output, 0, SEEK_SET) < 0) return close_with_error(output, errno);
    if (filtered_size) *filtered_size = filtered.size();
    errno = entry_errno;
    return output;
}

// fdopen takes ownership only on success.
inline FILE* fdopen_owned(int fd, const char* mode) {
    FILE* stream = ::fdopen(fd, mode);
    if (!stream) close_with_error(fd, errno);
    return stream;
}

}  // namespace ali::native_file
