#include "native_api.hpp"
#include "policy.hpp"
#include "taobao_env_compat.hpp"
#include "trace_capture.hpp"
extern "C" {
#include "third_party/sha256.h"
}
#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <jni.h>
#include <link.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace {
constexpr const char* TAG = "AliLoginCompat";
struct Profile {
    const char* package;
    const char* library;
    const char* file_hash;
    std::uintptr_t append_offset;
    const char* instruction_hash;
    std::uintptr_t syscall_offset;
    const char* syscall_hash;
};
#include "profiles.inc"
using Append = void (*)(void*, const void*, std::int32_t);
using RawSyscall = long (*)(long, long, long, long, long, long, long);
using SgOpenFn = int (*)(const char*, int, mode_t);
using SgOpen2Fn = int (*)(const char*, int);
using SgFopenFn = FILE* (*)(const char*, const char*);
using SgAccessFn = int (*)(const char*, int);
using SgStatFn = int (*)(const char*, struct stat*);
using SgOpendirFn = DIR* (*)(const char*);
using SgPropGetFn = int (*)(const char*, char*);
using SgSyscallFn = long (*)(long, long, long, long, long, long, long);
using SgDlsymFn = void* (*)(void*, const char*);
Append original_append = nullptr;
RawSyscall original_syscall = nullptr;
SgOpenFn orig_sg_open = nullptr;
SgOpen2Fn orig_sg_open2 = nullptr;
SgFopenFn orig_sg_fopen = nullptr;
SgAccessFn orig_sg_access = nullptr;
SgStatFn orig_sg_stat = nullptr;
SgOpendirFn orig_sg_opendir = nullptr;
SgPropGetFn orig_sg_prop_get = nullptr;
SgSyscallFn orig_sg_syscall = nullptr;
SgDlsymFn orig_sg_dlsym = nullptr;
thread_local ali::TraceCapture business_capture;
std::atomic<ali::Format> target_format{ali::Format::Idlefish};
HookFunction hook_function = nullptr;
std::atomic<bool> configured{false}, rewriting{false}, installed{false};
std::atomic<bool> env_compat{false}, env_trace{false}, business_trace_enabled{false};
std::atomic<std::uint64_t> matched{0}, rewritten{0}, append_calls{0};
std::atomic<bool> diagnostics{false};
std::atomic<std::uintptr_t> library_base{0}, library_end{0};
std::mutex records_mutex;
std::vector<std::vector<unsigned char>> records;
std::mutex install_mutex;
std::string target_package;
bool checked = false;

std::string hex_digest(const BYTE* bytes) {
    char hex[65]{};
    for (int i = 0; i < 32; ++i) std::snprintf(hex + i * 2, 3, "%02x", bytes[i]);
    return hex;
}
std::string memory_hash(const void* data, std::size_t length) {
    SHA256_CTX ctx; BYTE digest[32];
    sha256_init(&ctx); sha256_update(&ctx, static_cast<const BYTE*>(data), length); sha256_final(&ctx, digest);
    return hex_digest(digest);
}
std::string file_hash(const char* path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};
    SHA256_CTX ctx; sha256_init(&ctx); BYTE block[8192];
    ssize_t length;
    while ((length = read(fd, block, sizeof(block))) > 0) sha256_update(&ctx, block, static_cast<std::size_t>(length));
    close(fd);
    if (length < 0) return {};
    BYTE digest[32]; sha256_final(&ctx, digest);
    return hex_digest(digest);
}

void append_hook(void* destination, const void* source, std::int32_t length) {
    if (business_capture.active()) {
        const auto caller = reinterpret_cast<std::uintptr_t>(
            __builtin_extract_return_addr(__builtin_return_address(0)));
        const auto base = library_base.load(std::memory_order_relaxed);
        const auto end = library_end.load(std::memory_order_relaxed);
        business_capture.append(source, length, caller >= base && caller < end ? caller - base : 0);
    }
    append_calls.fetch_add(1);
    if (diagnostics.load() && source && length >= 12 && length <= 64 &&
        (length == 18 || static_cast<const unsigned char*>(source)[0] == 0x11)) {
        std::lock_guard<std::mutex> lock(records_mutex);
        if (records.size() < 32) {
            const auto* bytes = static_cast<const unsigned char*>(source);
            records.emplace_back(bytes, bytes + length);
        }
    }
    if (!destination || !ali::matches(source, length, target_format.load(std::memory_order_relaxed))) {
        original_append(destination, source, length);
        return;
    }
    const auto count = matched.fetch_add(1) + 1;
    if (rewriting.load(std::memory_order_relaxed)) {
        auto replacement = ali::rewrite(source);
        if (std::memcmp(replacement.data(), source, replacement.size()) != 0) rewritten.fetch_add(1);
        original_append(destination, replacement.data(), length);
    } else {
        original_append(destination, source, length);
    }
    if (count <= 8) __android_log_print(ANDROID_LOG_INFO, TAG, "state record matched=%llu rewritten=%llu", static_cast<unsigned long long>(count), static_cast<unsigned long long>(rewritten.load()));
}

std::mutex syscall_log_mutex;
std::unordered_set<std::string> syscall_logged_paths;

std::uintptr_t caller_lib_offset(const void* return_addr) {
    const auto caller = reinterpret_cast<std::uintptr_t>(return_addr);
    const auto base = library_base.load(std::memory_order_relaxed);
    const auto end = library_end.load(std::memory_order_relaxed);
    return (caller >= base && caller < end) ? (caller - base) : 0;
}

void record_capture_event(const char* kind, const void* return_addr, const char* target, long ret) {
    if (!business_capture.active()) return;
    business_capture.record_event(kind, caller_lib_offset(return_addr), target, ret);
}

void log_syscall_once(const char* kind, long sysno, const char* path, long ret) {
    if (!env_trace.load(std::memory_order_relaxed) || !path) return;
    if (std::strncmp(path, "/data/user/0/com.taobao.taobao/", 31) == 0 ||
        std::strncmp(path, "/data/data/com.taobao.taobao/", 29) == 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(syscall_log_mutex);
    if (syscall_logged_paths.size() >= 1024) return;
    std::string key = std::string(kind) + ":" + std::to_string(sysno) + ":" + path;
    if (syscall_logged_paths.insert(key).second) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "[%s] sysno=%ld path=%s ret=%ld", kind, sysno, path, ret);
    }
}

int filter_proc_fd(int real_fd, const char* pathname, ali::env::ProcKind kind) {
    if (real_fd < 0) return real_fd;
    std::string raw;
    char buf[4096];
    ssize_t n = 0;
    while ((n = read(real_fd, buf, sizeof(buf))) > 0) {
        raw.append(buf, static_cast<std::size_t>(n));
        if (raw.size() >= 4 * 1024 * 1024) break;
    }
    close(real_fd);
    std::string filtered = ali::env::filter_proc_content(raw, kind);
#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif
    int mfd = static_cast<int>(syscall(__NR_memfd_create, "proc", 1 /* MFD_CLOEXEC */));
    if (mfd >= 0) {
        std::size_t off = 0;
        while (off < filtered.size()) {
            ssize_t w = write(mfd, filtered.data() + off, filtered.size() - off);
            if (w <= 0) break;
            off += static_cast<std::size_t>(w);
        }
        lseek(mfd, 0, SEEK_SET);
        log_syscall_once("filter_proc", 56, pathname, static_cast<long>(filtered.size()));
        return mfd;
    }
    return -1;
}

long syscall_hook(long a0, long a1, long a2, long a3, long a4, long a5, long sysno) {
    // ARM64 syscall numbers: faccessat=48, openat=56, readlinkat=78, newfstatat=79, statx=291
    const bool has_path = (sysno == 48 || sysno == 56 || sysno == 78 || sysno == 79 || sysno == 291);
    const char* pathname = has_path ? reinterpret_cast<const char*>(a1) : nullptr;
    const bool compat = env_compat.load(std::memory_order_relaxed);
    if (compat && pathname && ali::env::is_suspicious_path(pathname)) {
        log_syscall_once("hide_path", sysno, pathname, -ENOENT);
        record_capture_event("syscall_hide", __builtin_extract_return_addr(__builtin_return_address(0)), pathname, -ENOENT);
        return -ENOENT;
    }
    if (compat && sysno == 56 && pathname) {
        const auto kind = ali::env::classify_proc_file(pathname);
        if (kind != ali::env::ProcKind::None) {
            int real_fd = static_cast<int>(original_syscall(a0, a1, a2, a3, a4, a5, sysno));
            if (real_fd < 0) {
                record_capture_event("syscall_openat", __builtin_extract_return_addr(__builtin_return_address(0)), pathname, real_fd);
                return real_fd;
            }
            int mfd = filter_proc_fd(real_fd, pathname, kind);
            if (mfd >= 0) {
                record_capture_event("syscall_proc", __builtin_extract_return_addr(__builtin_return_address(0)), pathname, mfd);
                return mfd;
            }
            return original_syscall(a0, a1, a2, a3, a4, a5, sysno);
        }
    }
    long ret = original_syscall(a0, a1, a2, a3, a4, a5, sysno);
    if (pathname) {
        log_syscall_once("syscall", sysno, pathname, ret);
        record_capture_event("syscall", __builtin_extract_return_addr(__builtin_return_address(0)), pathname, ret);
    } else {
        record_capture_event("syscall_num", __builtin_extract_return_addr(__builtin_return_address(0)), std::to_string(sysno).c_str(), ret);
    }
    return ret;
}

int sg_open_hook(const char* path, int flags, mode_t mode) {
    const bool compat = env_compat.load(std::memory_order_relaxed);
    if (compat && path && ali::env::is_suspicious_path(path)) {
        log_syscall_once("sg_hide_open", 56, path, -ENOENT);
        record_capture_event("sg_open_hide", __builtin_extract_return_addr(__builtin_return_address(0)), path, -ENOENT);
        errno = ENOENT;
        return -1;
    }
    int fd = orig_sg_open(path, flags, mode);
    if (path) {
        log_syscall_once("sg_open", flags, path, fd >= 0 ? 0 : -errno);
        record_capture_event("sg_open", __builtin_extract_return_addr(__builtin_return_address(0)), path, fd >= 0 ? 0 : -errno);
    }
    if (compat && fd >= 0 && path) {
        const auto kind = ali::env::classify_proc_file(path);
        if (kind != ali::env::ProcKind::None) {
            int mfd = filter_proc_fd(fd, path, kind);
            if (mfd >= 0) return mfd;
            return orig_sg_open(path, flags, mode);
        }
    }
    return fd;
}

int sg_open2_hook(const char* path, int flags) {
    const bool compat = env_compat.load(std::memory_order_relaxed);
    if (compat && path && ali::env::is_suspicious_path(path)) {
        log_syscall_once("sg_hide_open2", 56, path, -ENOENT);
        record_capture_event("sg_open2_hide", __builtin_extract_return_addr(__builtin_return_address(0)), path, -ENOENT);
        errno = ENOENT;
        return -1;
    }
    int fd = orig_sg_open2(path, flags);
    if (path) {
        log_syscall_once("sg_open2", flags, path, fd >= 0 ? 0 : -errno);
        record_capture_event("sg_open2", __builtin_extract_return_addr(__builtin_return_address(0)), path, fd >= 0 ? 0 : -errno);
    }
    if (compat && fd >= 0 && path) {
        const auto kind = ali::env::classify_proc_file(path);
        if (kind != ali::env::ProcKind::None) {
            int mfd = filter_proc_fd(fd, path, kind);
            if (mfd >= 0) return mfd;
            return orig_sg_open2(path, flags);
        }
    }
    return fd;
}

FILE* sg_fopen_hook(const char* path, const char* mode) {
    const bool compat = env_compat.load(std::memory_order_relaxed);
    if (compat && path && ali::env::is_suspicious_path(path)) {
        log_syscall_once("sg_hide_fopen", 56, path, -ENOENT);
        record_capture_event("sg_fopen_hide", __builtin_extract_return_addr(__builtin_return_address(0)), path, -ENOENT);
        errno = ENOENT;
        return nullptr;
    }
    if (compat && path) {
        const auto kind = ali::env::classify_proc_file(path);
        if (kind != ali::env::ProcKind::None) {
            int fd = orig_sg_open(path, O_RDONLY, 0);
            if (fd >= 0) {
                int mfd = filter_proc_fd(fd, path, kind);
                if (mfd >= 0) return fdopen(mfd, mode ? mode : "r");
            }
        }
    }
    FILE* f = orig_sg_fopen(path, mode);
    if (path) {
        log_syscall_once("sg_fopen", 0, path, f ? 0 : -errno);
        record_capture_event("sg_fopen", __builtin_extract_return_addr(__builtin_return_address(0)), path, f ? 0 : -errno);
    }
    return f;
}

int sg_access_hook(const char* path, int mode) {
    const bool compat = env_compat.load(std::memory_order_relaxed);
    if (compat && path && ali::env::is_suspicious_path(path)) {
        log_syscall_once("sg_hide_access", 48, path, -ENOENT);
        record_capture_event("sg_access_hide", __builtin_extract_return_addr(__builtin_return_address(0)), path, -ENOENT);
        errno = ENOENT;
        return -1;
    }
    int r = orig_sg_access(path, mode);
    if (path) {
        log_syscall_once("sg_access", mode, path, r);
        record_capture_event("sg_access", __builtin_extract_return_addr(__builtin_return_address(0)), path, r);
    }
    return r;
}

int sg_stat_hook(const char* path, struct stat* st) {
    const bool compat = env_compat.load(std::memory_order_relaxed);
    if (compat && path && ali::env::is_suspicious_path(path)) {
        log_syscall_once("sg_hide_stat", 79, path, -ENOENT);
        record_capture_event("sg_stat_hide", __builtin_extract_return_addr(__builtin_return_address(0)), path, -ENOENT);
        errno = ENOENT;
        return -1;
    }
    int r = orig_sg_stat(path, st);
    if (path) {
        log_syscall_once("sg_stat", 0, path, r);
        record_capture_event("sg_stat", __builtin_extract_return_addr(__builtin_return_address(0)), path, r);
    }
    return r;
}

DIR* sg_opendir_hook(const char* path) {
    const bool compat = env_compat.load(std::memory_order_relaxed);
    if (compat && path && ali::env::is_suspicious_path(path)) {
        log_syscall_once("sg_hide_opendir", 56, path, -ENOENT);
        record_capture_event("sg_opendir_hide", __builtin_extract_return_addr(__builtin_return_address(0)), path, -ENOENT);
        errno = ENOENT;
        return nullptr;
    }
    DIR* d = orig_sg_opendir(path);
    if (path) {
        log_syscall_once("sg_opendir", 0, path, d ? 0 : -1);
        record_capture_event("sg_opendir", __builtin_extract_return_addr(__builtin_return_address(0)), path, d ? 0 : -1);
    }
    return d;
}

int sg_prop_get_hook(const char* name, char* value) {
    const bool compat = env_compat.load(std::memory_order_relaxed);
    if (compat && name && value) {
        if (std::strcmp(name, "ro.debuggable") == 0 ||
            std::strcmp(name, "service.adb.root") == 0) {
            std::strcpy(value, "0");
            record_capture_event("sg_prop_hide", __builtin_extract_return_addr(__builtin_return_address(0)), name, 1);
            return 1;
        }
        if (std::strcmp(name, "init.svc.adbd") == 0 ||
            ali::env::icontains(name, "magisk") || ali::env::icontains(name, "ksu") ||
            ali::env::icontains(name, "zygisk") || ali::env::icontains(name, "lsposed")) {
            value[0] = '\0';
            record_capture_event("sg_prop_hide", __builtin_extract_return_addr(__builtin_return_address(0)), name, 0);
            return 0;
        }
    }
    int n = orig_sg_prop_get(name, value);
    if (name) {
        log_syscall_once("sg_prop", 0, name, n);
        record_capture_event("sg_prop", __builtin_extract_return_addr(__builtin_return_address(0)), name, n);
    }
    return n;
}

static const void* sg_prop_find_hook(const char* name) {
    static auto orig_find = reinterpret_cast<const void* (*)(const char*)>(orig_sg_dlsym(RTLD_DEFAULT, "__system_property_find"));
    const bool compat = env_compat.load(std::memory_order_relaxed);
    if (name) {
        log_syscall_once("sg_prop_find", 0, name, 0);
        if (compat && (std::strcmp(name, "ro.debuggable") == 0 ||
            std::strcmp(name, "service.adb.root") == 0 ||
            std::strcmp(name, "init.svc.adbd") == 0 ||
            ali::env::icontains(name, "magisk") ||
            ali::env::icontains(name, "ksu") ||
            ali::env::icontains(name, "zygisk") ||
            ali::env::icontains(name, "lsposed"))) {
            record_capture_event("sg_prop_find_hide", __builtin_extract_return_addr(__builtin_return_address(0)), name, 0);
            return nullptr;
        }
        record_capture_event("sg_prop_find", __builtin_extract_return_addr(__builtin_return_address(0)), name, 1);
    }
    return orig_find ? orig_find(name) : nullptr;
}

long sg_syscall_hook(long sysno, long a0, long a1, long a2, long a3, long a4, long a5);

static void sg_prop_read_hook(const void* pi, char* name, char* value) {
    static auto orig_read = reinterpret_cast<void (*)(const void*, char*, char*)>(
        orig_sg_dlsym(RTLD_DEFAULT, "__system_property_read"));
    if (!orig_read) return;
    orig_read(pi, name, value);
    if (name && value) {
        if (env_compat.load(std::memory_order_relaxed)) {
            if (std::strcmp(name, "ro.debuggable") == 0 ||
                std::strcmp(name, "service.adb.root") == 0) {
                std::strcpy(value, "0");
            } else if (std::strcmp(name, "ro.secure") == 0) {
                std::strcpy(value, "1");
            }
        }
        std::string kv = std::string(name) + "=" + value;
        log_syscall_once("sg_prop_read", 0, kv.c_str(), 0);
        record_capture_event("sg_prop_read", __builtin_extract_return_addr(__builtin_return_address(0)), name, 0);
    }
}

static char* sg_if_indextoname_hook(unsigned int ifindex, char* ifname) {
    static auto orig_fn = reinterpret_cast<char* (*)(unsigned int, char*)>(
        orig_sg_dlsym(RTLD_DEFAULT, "if_indextoname"));
    if (!orig_fn) return nullptr;
    char* res = orig_fn(ifindex, ifname);
    if (res) {
        record_capture_event("sg_if_indextoname", __builtin_extract_return_addr(__builtin_return_address(0)), res, 0);
        if (env_compat.load(std::memory_order_relaxed) &&
            (std::strcmp(res, "magicnet0") == 0 || std::strncmp(res, "tun", 3) == 0)) {
            log_syscall_once("sg_if_hide", 0, res, 0);
            errno = ENXIO;
            return nullptr;
        }
        log_syscall_once("sg_if", 0, res, 0);
    }
    return res;
}

static ssize_t sg_recvmsg_hook(int sockfd, struct msghdr* msg, int flags) {
    static auto orig_fn = reinterpret_cast<ssize_t (*)(int, struct msghdr*, int)>(
        orig_sg_dlsym(RTLD_DEFAULT, "recvmsg"));
    if (!orig_fn) return -1;
    ssize_t ret = orig_fn(sockfd, msg, flags);
    if (env_compat.load(std::memory_order_relaxed) && ret > 0 && msg && msg->msg_iov) {
        for (size_t i = 0; i < static_cast<size_t>(msg->msg_iovlen); ++i) {
            auto* base = static_cast<char*>(msg->msg_iov[i].iov_base);
            size_t len = msg->msg_iov[i].iov_len;
            if (!base || len < 10) continue;
            for (size_t j = 0; j + 9 <= len; ++j) {
                if (std::memcmp(base + j, "magicnet0", 9) == 0) {
                    std::memcpy(base + j, "rmnet_da0", 9);
                    log_syscall_once("sg_nl_hide", 0, "magicnet0", 1);
                }
            }
        }
    }
    return ret;
}

void* sg_dlsym_hook(void* handle, const char* symbol) {
    if (symbol) {
        if (std::strcmp(symbol, "stat") == 0 && orig_sg_stat) return reinterpret_cast<void*>(sg_stat_hook);
        if (std::strcmp(symbol, "access") == 0 && orig_sg_access) return reinterpret_cast<void*>(sg_access_hook);
        if (std::strcmp(symbol, "opendir") == 0 && orig_sg_opendir) return reinterpret_cast<void*>(sg_opendir_hook);
        if (std::strcmp(symbol, "open") == 0 && orig_sg_open) return reinterpret_cast<void*>(sg_open_hook);
        if (std::strcmp(symbol, "fopen") == 0 && orig_sg_fopen) return reinterpret_cast<void*>(sg_fopen_hook);
        if (std::strcmp(symbol, "__system_property_get") == 0 && orig_sg_prop_get) return reinterpret_cast<void*>(sg_prop_get_hook);
        if (std::strcmp(symbol, "__system_property_find") == 0) return reinterpret_cast<void*>(sg_prop_find_hook);
        if (std::strcmp(symbol, "__system_property_read") == 0) return reinterpret_cast<void*>(sg_prop_read_hook);
        if (std::strcmp(symbol, "if_indextoname") == 0) return reinterpret_cast<void*>(sg_if_indextoname_hook);
        if (std::strcmp(symbol, "recvmsg") == 0) return reinterpret_cast<void*>(sg_recvmsg_hook);
        if (std::strcmp(symbol, "syscall") == 0 && orig_sg_syscall) return reinterpret_cast<void*>(sg_syscall_hook);
    }
    void* res = orig_sg_dlsym(handle, symbol);
    if (symbol && std::strncmp(symbol, "pthread_", 8) != 0 &&
        std::strcmp(symbol, "malloc") != 0 && std::strcmp(symbol, "free") != 0 &&
        std::strcmp(symbol, "calloc") != 0 && std::strcmp(symbol, "__errno") != 0) {
        log_syscall_once("sg_dlsym", 0, symbol, res ? 1 : 0);
        record_capture_event("sg_dlsym", __builtin_extract_return_addr(__builtin_return_address(0)), symbol, res ? 1 : 0);
    }
    return res;
}

long sg_syscall_hook(long sysno, long a0, long a1, long a2, long a3, long a4, long a5) {
    const bool has_path = (sysno == 48 || sysno == 56 || sysno == 78 || sysno == 79 ||
                           sysno == 291 || sysno == 437 || sysno == 439);
    const char* pathname = has_path ? reinterpret_cast<const char*>(a1) : nullptr;
    const bool compat = env_compat.load(std::memory_order_relaxed);
    if (compat && pathname && ali::env::is_suspicious_path(pathname)) {
        log_syscall_once("sg_libc_hide", sysno, pathname, -ENOENT);
        record_capture_event("sg_libc_hide", __builtin_extract_return_addr(__builtin_return_address(0)), pathname, -ENOENT);
        errno = ENOENT;
        return -1;
    }
    if (compat && (sysno == 56 || sysno == 437) && pathname) {
        const auto kind = ali::env::classify_proc_file(pathname);
        if (kind != ali::env::ProcKind::None) {
            int real_fd = static_cast<int>(orig_sg_syscall(sysno, a0, a1, a2, a3, a4, a5));
            if (real_fd >= 0) {
                int mfd = filter_proc_fd(real_fd, pathname, kind);
                if (mfd >= 0) return mfd;
                return orig_sg_syscall(sysno, a0, a1, a2, a3, a4, a5);
            }
            return real_fd;
        }
    }
    long ret = orig_sg_syscall(sysno, a0, a1, a2, a3, a4, a5);
    if (pathname) {
        log_syscall_once("sg_libc_sys", sysno, pathname, ret);
        record_capture_event("sg_libc_sys", __builtin_extract_return_addr(__builtin_return_address(0)), pathname, ret);
    } else {
        record_capture_event("sg_libc_sysno", __builtin_extract_return_addr(__builtin_return_address(0)), std::to_string(sysno).c_str(), ret);
    }
    return ret;
}

template <typename Fn>
bool patch_got_slot(std::uintptr_t base, std::uintptr_t offset, Fn replacement, Fn* original_out) {
    auto* slot = reinterpret_cast<void**>(base + offset);
    *original_out = reinterpret_cast<Fn>(*slot);
    *slot = reinterpret_cast<void*>(replacement);
    return true;
}

void install_sg_got_hooks(std::uintptr_t base) {
    const std::uintptr_t page_start = (base + 0x1c1350) & ~static_cast<std::uintptr_t>(0xfff);
    const std::uintptr_t page_end = ((base + 0x1c16b0) + 0xfff) & ~static_cast<std::uintptr_t>(0xfff);
    if (mprotect(reinterpret_cast<void*>(page_start), page_end - page_start, PROT_READ | PROT_WRITE) != 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "taobao GOT mprotect failed errno=%d", errno);
        return;
    }
    patch_got_slot(base, 0x1c1350, sg_stat_hook, &orig_sg_stat);
    patch_got_slot(base, 0x1c1358, sg_access_hook, &orig_sg_access);
    patch_got_slot(base, 0x1c1368, sg_opendir_hook, &orig_sg_opendir);
    patch_got_slot(base, 0x1c13c8, sg_dlsym_hook, &orig_sg_dlsym);
    patch_got_slot(base, 0x1c13e8, sg_open_hook, &orig_sg_open);
    patch_got_slot(base, 0x1c1570, sg_fopen_hook, &orig_sg_fopen);
    patch_got_slot(base, 0x1c1670, sg_open2_hook, &orig_sg_open2);
    patch_got_slot(base, 0x1c1680, sg_syscall_hook, &orig_sg_syscall);
    patch_got_slot(base, 0x1c16a8, sg_prop_get_hook, &orig_sg_prop_get);
    __android_log_print(ANDROID_LOG_INFO, TAG, "taobao GOT hooks installed compat=%d trace=%d",
                        env_compat.load() ? 1 : 0, env_trace.load() ? 1 : 0);
}

int inspect_library(dl_phdr_info* info, std::size_t, void*) {
    const char* path = info->dlpi_name;
    if (!path || !*path) return 0;
    const char* name = std::strrchr(path, '/'); name = name ? name + 1 : path;
    for (const auto& profile : PROFILES) {
        if (target_package != profile.package || std::strcmp(name, profile.library) != 0) continue;
        if (checked || installed.load()) return 1;
        checked = true;
        bool executable = false;
        for (std::size_t i = 0; i < info->dlpi_phnum; ++i) {
            const auto& segment = info->dlpi_phdr[i];
            if (segment.p_type == PT_LOAD && (segment.p_flags & PF_X) && profile.append_offset >= segment.p_vaddr && profile.append_offset + 64 <= segment.p_vaddr + segment.p_memsz) executable = true;
        }
        if (!executable || file_hash(path) != profile.file_hash) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "profile file validation failed; library retained unchanged");
            return 1;
        }
        auto target = reinterpret_cast<void*>(info->dlpi_addr + profile.append_offset);
        if (memory_hash(target, 64) != profile.instruction_hash) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "profile instruction validation failed; library retained unchanged");
            return 1;
        }
        std::uintptr_t end = info->dlpi_addr;
        for (std::size_t i = 0; i < info->dlpi_phnum; ++i) {
            const auto& segment = info->dlpi_phdr[i];
            if (segment.p_type == PT_LOAD) end = std::max<std::uintptr_t>(end, info->dlpi_addr + segment.p_vaddr + segment.p_memsz);
        }
        library_base.store(info->dlpi_addr, std::memory_order_relaxed);
        library_end.store(end, std::memory_order_relaxed);
        int status = hook_function(target, reinterpret_cast<void*>(append_hook), reinterpret_cast<void**>(&original_append));
        if (status == 0 && original_append) {
            installed.store(true);
            __android_log_print(ANDROID_LOG_INFO, TAG, "verified native profile installed: %s mode=%s", profile.library, rewriting.load() ? "rewrite" : "observe");
        } else __android_log_print(ANDROID_LOG_ERROR, TAG, "native hook installation failed: %d", status);
        if (profile.syscall_offset != 0 &&
            target_format.load(std::memory_order_relaxed) == ali::Format::Taobao &&
            (env_compat.load(std::memory_order_relaxed) ||
             env_trace.load(std::memory_order_relaxed) ||
             business_trace_enabled.load(std::memory_order_relaxed))) {
            auto sys_target = reinterpret_cast<void*>(info->dlpi_addr + profile.syscall_offset);
            if (memory_hash(sys_target, 64) == profile.syscall_hash) {
                int sys_status = hook_function(sys_target, reinterpret_cast<void*>(syscall_hook), reinterpret_cast<void**>(&original_syscall));
                __android_log_print(ANDROID_LOG_INFO, TAG, "taobao syscall hook status=%d compat=%d trace=%d",
                                    sys_status, env_compat.load() ? 1 : 0, env_trace.load() ? 1 : 0);
            } else {
                __android_log_print(ANDROID_LOG_WARN, TAG, "taobao syscall hash mismatch; retained unchanged");
            }
            install_sg_got_hooks(info->dlpi_addr);
        }
        return 1;
    }
    return 0;
}
void inspect_loaded_libraries() {
    if (!configured.load(std::memory_order_acquire) || !hook_function) return;
    std::lock_guard<std::mutex> lock(install_mutex);
    dl_iterate_phdr(inspect_library, nullptr);
}
void library_loaded(const char* name, void*) {
    if (name && std::strstr(name, "libsgmain")) inspect_loaded_libraries();
}
}

extern "C" __attribute__((visibility("default"), used))
LibraryLoaded native_init(const NativeAPIEntries* entries) {
    if (entries) hook_function = entries->hook_func;
    return library_loaded;
}

extern "C" JNIEXPORT void JNICALL
Java_io_github_lightjunction_alilogincompat_ModuleEntry_configureNative(
    JNIEnv* env, jclass, jboolean rewrite, jstring package, jboolean probe,
    jboolean compat, jboolean trace_env, jboolean trace_business) {
    const char* value = env->GetStringUTFChars(package, nullptr);
    if (!value) return;
    target_package = value; env->ReleaseStringUTFChars(package, value);
    target_format.store(target_package == "com.taobao.taobao" ? ali::Format::Taobao : ali::Format::Idlefish);
    rewriting.store(rewrite == JNI_TRUE);
    diagnostics.store(probe == JNI_TRUE);
    env_compat.store(compat == JNI_TRUE);
    env_trace.store(trace_env == JNI_TRUE);
    business_trace_enabled.store(trace_business == JNI_TRUE);
    configured.store(true, std::memory_order_release);
    if (!hook_function) __android_log_print(ANDROID_LOG_ERROR, TAG, "framework native API unavailable; no native changes");
    inspect_loaded_libraries();
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_io_github_lightjunction_alilogincompat_ModuleEntry_nativeCounters(JNIEnv* env, jclass) {
    inspect_loaded_libraries();
    jlong values[]{static_cast<jlong>(matched.load()), static_cast<jlong>(rewritten.load()), installed.load() ? 1 : 0, static_cast<jlong>(append_calls.load())};
    auto result = env->NewLongArray(4);
    if (result) env->SetLongArrayRegion(result, 0, 4, values);
    return result;
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_github_lightjunction_alilogincompat_ModuleEntry_nativeRecords(JNIEnv* env, jclass) {
    std::lock_guard<std::mutex> lock(records_mutex);
    std::string value;
    for (const auto& record : records) {
        for (auto byte : record) { char hex[3]; std::snprintf(hex, sizeof(hex), "%02x", byte); value += hex; }
        value += "\n";
    }
    return env->NewStringUTF(value.c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_lightjunction_alilogincompat_BusinessFactorTrace_beginCapture(JNIEnv*, jclass) {
    return installed.load() && business_capture.begin() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_github_lightjunction_alilogincompat_BusinessFactorTrace_endCapture(JNIEnv* env, jclass) {
    return env->NewStringUTF(business_capture.finish().c_str());
}

extern "C" JNIEXPORT jlong JNICALL
Java_io_github_lightjunction_alilogincompat_BusinessFactorTrace_capturePosition(JNIEnv*, jclass) {
    return business_capture.active() ? static_cast<jlong>(business_capture.position()) : -1;
}
