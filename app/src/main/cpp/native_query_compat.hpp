#pragma once

#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#else
struct prop_info;
#endif

namespace ali::native_query {

using PropertyRead = int (*)(const prop_info*, char*, char*);
using Recvmsg = ssize_t (*)(int, struct msghdr*, int);

// The resolver may be intercepted, but the receive contract and bytes are not.
inline ssize_t receive_message(Recvmsg original, int fd, struct msghdr* message, int flags) {
    if (!original) {
        errno = ENOSYS;
        return -1;
    }
    return original(fd, message, flags);
}

template <typename Observer>
int read_property(PropertyRead original, const prop_info* property, char* name, char* value,
                  bool compat, Observer observer) {
    if (!original) {
        errno = ENOSYS;
        return -1;
    }
    int result = original(property, name, value);
    const int original_errno = errno;
    if (result >= 0 && name && value) {
        bool replaced = false;
        if (compat) {
            if (std::strcmp(name, "ro.debuggable") == 0 ||
                std::strcmp(name, "service.adb.root") == 0) {
                std::strcpy(value, "0");
                replaced = true;
            } else if (std::strcmp(name, "ro.secure") == 0) {
                std::strcpy(value, "1");
                replaced = true;
            }
        }
        if (replaced) result = static_cast<int>(std::strlen(value));
        observer(name, value);
    }
    // Logging can alter errno; expose only the original reader's errno.
    errno = original_errno;
    return result;
}

}  // namespace ali::native_query
