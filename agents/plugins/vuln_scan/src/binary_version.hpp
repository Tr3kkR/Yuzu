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
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <system_error>
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
    // Convert the UTF-8 path to UTF-16 properly (a byte-wise widening would
    // corrupt any multibyte character).
    std::wstring wpath;
    if (!path.empty()) {
        int n = MultiByteToWideChar(CP_UTF8, 0, path.c_str(),
                                    static_cast<int>(path.size()), nullptr, 0);
        if (n <= 0)
            return {};
        wpath.resize(static_cast<size_t>(n));
        MultiByteToWideChar(CP_UTF8, 0, path.c_str(),
                            static_cast<int>(path.size()), wpath.data(), n);
    }
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

    // Bound the read: skip a missing, empty, or implausibly large plist so a
    // crafted path cannot drive an unbounded allocation.
    std::error_code ec;
    auto fsize = std::filesystem::file_size(plist, ec);
    if (ec || fsize == 0 || fsize > (16u * 1024u * 1024u))
        return {};

    std::ifstream f(plist, std::ios::binary);
    if (!f)
        return {};
    std::string bytes((std::istreambuf_iterator<char>(f)),
                      std::istreambuf_iterator<char>());
    if (bytes.empty())
        return {};

    // CFPropertyListCreateWithData parses both XML and binary plists.
    CFDataRef data = CFDataCreate(
        nullptr, reinterpret_cast<const UInt8*>(bytes.data()),
        static_cast<CFIndex>(bytes.size()));
    if (!data)
        return {};
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
