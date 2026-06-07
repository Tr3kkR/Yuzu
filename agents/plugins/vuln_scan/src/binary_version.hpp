#pragma once
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <vector>
#endif

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif

namespace yuzu::vuln {

// Remove Debian epoch prefix "N:" if present; returns version remainder as std::string.
inline std::string strip_linux_pkg_epoch(std::string_view v) {
    auto colon = v.find(':');
    if (colon == std::string_view::npos)
        return std::string(v);
    for (size_t i = 0; i < colon; ++i)
        if (v[i] < '0' || v[i] > '9')
            return std::string(v);
    return std::string(v.substr(colon + 1));
}

// ── Windows: PE VERSIONINFO resource ──────────────────────────────────────

#ifdef _WIN32
// Returns "MAJOR.MINOR.PATCH.BUILD" from a PE binary's VERSIONINFO resource,
// or "" on failure. Requires linking version.lib.
inline std::string get_pe_file_version(const std::string& path) {
    std::wstring wpath(path.begin(), path.end());
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(wpath.c_str(), &dummy);
    if (size == 0)
        return {};
    std::vector<BYTE> buf(size);
    if (!GetFileVersionInfoW(wpath.c_str(), 0, size, buf.data()))
        return {};
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT ffi_len = 0;
    if (!VerQueryValueW(buf.data(), L"\\",
                        reinterpret_cast<LPVOID*>(&ffi), &ffi_len) || ffi_len == 0)
        return {};
    return std::to_string(HIWORD(ffi->dwFileVersionMS)) + "." +
           std::to_string(LOWORD(ffi->dwFileVersionMS)) + "." +
           std::to_string(HIWORD(ffi->dwFileVersionLS)) + "." +
           std::to_string(LOWORD(ffi->dwFileVersionLS));
}
#endif // _WIN32

// ── macOS: Info.plist CFBundleShortVersionString ───────────────────────────

#ifdef __APPLE__
// Returns the CFBundleShortVersionString from an .app bundle's Info.plist,
// or "" on failure. Uses CoreFoundation only — no subprocess.
inline std::string get_bundle_version(const std::string& app_path) {
    std::string plist = app_path + "/Contents/Info.plist";
    CFStringRef path_ref = CFStringCreateWithCString(
        nullptr, plist.c_str(), kCFStringEncodingUTF8);
    if (!path_ref)
        return {};
    // Convert CFString path to C string for file reading
    const char* path_c = reinterpret_cast<const char*>(CFStringGetCStringPtr(path_ref, kCFStringEncodingUTF8));
    if (!path_c) {
        CFRelease(path_ref);
        return {};
    }
    // Read the plist file
    FILE* f = fopen(path_c, "rb");
    CFRelease(path_ref);
    if (!f)
        return {};
    // Get file size
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0) {
        fclose(f);
        return {};
    }
    // Read file into memory
    uint8_t* buf = static_cast<uint8_t*>(malloc(fsize));
    size_t nread = fread(buf, 1, fsize, f);
    fclose(f);
    if (nread != static_cast<size_t>(fsize)) {
        free(buf);
        return {};
    }
    // Create CFData from buffer (takes ownership)
    CFDataRef data = CFDataCreateWithBytesNoCopy(
        nullptr, buf, fsize, kCFAllocatorMalloc);
    CFPropertyListRef plist_ref = CFPropertyListCreateWithData(
        nullptr, data, kCFPropertyListImmutable, nullptr, nullptr);
    CFRelease(data);
    if (!plist_ref)
        return {};

    std::string result;
    if (CFGetTypeID(plist_ref) == CFDictionaryGetTypeID()) {
        auto dict = static_cast<CFDictionaryRef>(plist_ref);
        auto val = static_cast<CFStringRef>(
            CFDictionaryGetValue(dict, CFSTR("CFBundleShortVersionString")));
        if (val && CFGetTypeID(val) == CFStringGetTypeID()) {
            char buf[128]{};
            if (CFStringGetCString(val, buf, sizeof(buf), kCFStringEncodingUTF8))
                result = buf;
        }
    }
    CFRelease(plist_ref);
    return result;
}
#endif // __APPLE__

} // namespace yuzu::vuln
