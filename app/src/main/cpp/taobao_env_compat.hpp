#pragma once

#include <cctype>
#include <cstddef>
#include <cstring>
#include <string>

namespace ali::env {

enum class ProcKind { None, Mount, Maps };

inline bool icontains(const char* haystack, const char* needle) {
    if (!haystack || !needle || !*needle) return false;
    for (const char* h = haystack; *h; ++h) {
        const char* a = h;
        const char* b = needle;
        while (*a && *b &&
               std::tolower(static_cast<unsigned char>(*a)) ==
                   std::tolower(static_cast<unsigned char>(*b))) {
            ++a;
            ++b;
        }
        if (!*b) return true;
    }
    return false;
}

inline bool is_digits_until_slash(const char* s, const char** rest) {
    if (!s || !std::isdigit(static_cast<unsigned char>(*s))) return false;
    while (std::isdigit(static_cast<unsigned char>(*s))) ++s;
    if (*s != '/') return false;
    *rest = s + 1;
    return true;
}

inline ProcKind classify_proc_file(const char* path) {
    if (!path) return ProcKind::None;
    if (std::string(path) == "/proc/mounts") return ProcKind::Mount;
    if (std::strncmp(path, "/proc/", 6) != 0) return ProcKind::None;
    const char* tail = path + 6;
    if (std::strncmp(tail, "self/", 5) == 0) {
        tail += 5;
    } else if (std::strncmp(tail, "thread-self/", 12) == 0) {
        tail += 12;
    } else if (!is_digits_until_slash(tail, &tail)) {
        return ProcKind::None;
    }
    if (std::strcmp(tail, "mountinfo") == 0 || std::strcmp(tail, "mounts") == 0) {
        return ProcKind::Mount;
    }
    if (std::strcmp(tail, "maps") == 0) {
        return ProcKind::Maps;
    }
    return ProcKind::None;
}

inline bool is_suspicious_path(const char* path) {
    if (!path) return false;
    static constexpr const char* kMarkers[] = {
        "/data/adb", "magisk", "kernelsu", "lsposed", "xposed",
        "zygisk", "frida", "magicap", "alilogincompat", "busybox",
        "rescuebrick", "cloudecalc", "sys-ca-copy",
        "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/vendor/bin/su", "/su/bin"
    };
    for (const char* marker : kMarkers) {
        if (icontains(path, marker)) return true;
    }
    return false;
}

inline bool should_hide_proc_line(const char* line, ProcKind kind) {
    if (!line || kind == ProcKind::None) return false;
    static constexpr const char* kCommon[] = {
        "alilogincompat", "lsposed", "xposed", "zygisk", "frida",
        "magisk", "kernelsu", "magicap", "rescuebrick"
    };
    for (const char* marker : kCommon) {
        if (icontains(line, marker)) return true;
    }
    if (kind == ProcKind::Mount) {
        if (icontains(line, "/adb/") || icontains(line, "sys-ca-copy") ||
            icontains(line, "/apex/com.android.conscrypt/cacerts")) {
            return true;
        }
    }
    return false;
}

inline std::string filter_proc_content(const std::string& input, ProcKind kind) {
    if (kind == ProcKind::None) return input;
    std::string out;
    out.reserve(input.size());
    std::size_t start = 0;
    while (start < input.size()) {
        std::size_t end = input.find('\n', start);
        if (end == std::string::npos) end = input.size();
        std::string line = input.substr(start, end - start);
        if (!should_hide_proc_line(line.c_str(), kind)) {
            out.append(line);
            if (end < input.size()) out.push_back('\n');
        }
        start = (end < input.size()) ? end + 1 : end;
    }
    return out;
}

}  // namespace ali::env
