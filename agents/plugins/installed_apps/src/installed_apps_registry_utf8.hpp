#pragma once

// installed_apps_registry_utf8.hpp -- UTF-16 <-> UTF-8 conversion for the
// installed_apps plugin's Windows registry reads (#1662).
//
// Registry strings are UTF-16. Reading them via the *W APIs and converting to
// UTF-8 (rather than the *A APIs, which return the system ANSI code page /
// cp1252) is what keeps non-ASCII app/publisher names intact instead of being
// mangled to '?' and corrupting the typed software-inventory store's
// `WHERE name=$1` lookups.
//
// These helpers live in a header (not the plugin .cpp's anonymous namespace) so
// the #1662 regression test exercises the *same* code the plugin runs, rather
// than a re-implementation that could silently diverge (governance Gate 3
// quality-engineer BLOCKING F1). They are still duplicated from
// registry_plugin.cpp's equivalents for plugin build isolation -- each plugin is
// its own shared object with no shared internal linkage; the sharing here is
// header-only and within the installed_apps target + its unit test.
//
// Windows-only: the whole body is under _WIN32, so including this on Linux/macOS
// is a no-op (the plugin's registry code path does not exist off-Windows).

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <string_view>

// NOTE (#1681): this is the ONE conversion site deliberately NOT migrated to the shared
// `agents/shared/win_str.hpp`. `reg_sz_to_utf8` below strips ALL trailing NULs, whereas the
// shared helper stops at the FIRST NUL -- aligning would change output bytes for a value
// containing an interior NUL, so it is a separately-reviewed step (tracked follow-up), not
// an oversight. Do NOT fold this into the shared header without that review.
namespace yuzu::installed_apps::reg_utf8 {

// UTF-8 -> UTF-16 (for passing UTF-8 subkey / value names to the *W APIs).
inline std::wstring to_wide(std::string_view s) {
    if (s.empty())
        return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring ws(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), ws.data(), len);
    return ws;
}

// UTF-16 -> UTF-8. `len` is a WCHAR count; -1 means "NUL-terminated".
inline std::string from_wide(const wchar_t* ws, int len = -1) {
    if (!ws)
        return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, ws, len, nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(sz), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, len, s.data(), sz, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0')
        s.pop_back();
    return s;
}

// Convert a REG_SZ payload (size is in BYTES, may include trailing NUL(s)) to
// UTF-8. Length-aware: the trailing NUL(s) are stripped on the WCHAR side first,
// so the conversion never depends on the value being NUL-terminated (a valid
// REG_SZ may be stored without one).
inline std::string reg_sz_to_utf8(const wchar_t* buf, DWORD size_bytes) {
    size_t nch = size_bytes / sizeof(wchar_t);
    while (nch > 0 && buf[nch - 1] == L'\0')
        --nch;
    return from_wide(buf, static_cast<int>(nch));
}

} // namespace yuzu::installed_apps::reg_utf8

#endif // _WIN32
