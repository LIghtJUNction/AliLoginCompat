#include "native_api.hpp"
#include "policy.hpp"
#include "trace_capture.hpp"
extern "C" {
#include "third_party/sha256.h"
}
#include <android/log.h>
#include <jni.h>
#include <link.h>
#include <fcntl.h>
#include <unistd.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace {
constexpr const char* TAG = "AliLoginCompat";
struct Profile {
    const char* package;
    const char* library;
    const char* file_hash;
    std::uintptr_t append_offset;
    const char* instruction_hash;
};
#include "profiles.inc"
using Append = void (*)(void*, const void*, std::int32_t);
Append original_append = nullptr;
thread_local ali::TraceCapture business_capture;
std::atomic<ali::Format> target_format{ali::Format::Idlefish};
HookFunction hook_function = nullptr;
std::atomic<bool> configured{false}, rewriting{false}, installed{false};
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
Java_io_github_lightjunction_alilogincompat_ModuleEntry_configureNative(JNIEnv* env, jclass, jboolean rewrite, jstring package, jboolean probe) {
    const char* value = env->GetStringUTFChars(package, nullptr);
    if (!value) return;
    target_package = value; env->ReleaseStringUTFChars(package, value);
    target_format.store(target_package == "com.taobao.taobao" ? ali::Format::Taobao : ali::Format::Idlefish);
    rewriting.store(rewrite == JNI_TRUE);
    diagnostics.store(probe == JNI_TRUE);
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
