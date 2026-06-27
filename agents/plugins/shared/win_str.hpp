// win_str.hpp -- shared Windows UTF-16 <-> UTF-8 string helpers.
//
// These three pure functions were duplicated byte-identically across ~6 agent
// plugins (registry, processes, wmi, interaction, tar_module_etw, installed_apps)
// under a "duplicated for build isolation" comment (#1681). They depend only on
// WideCharToMultiByte / MultiByteToWideChar -- no other Win32 surface -- so a single
// header-only home gives one source of truth while preserving build isolation:
// every plugin is its own shared object and still compiles its own inline copy, so
// there is no exported symbol to interpose across the plugin ABI boundary.
//
// Windows-only by construction (#ifdef _WIN32); the header is empty elsewhere.
// Deliberately free of Reg* I/O so the pure string conversion is unit-testable
// without advapi32 (tests/unit/test_win_str_utils.cpp). The Reg* read sites that
// consume these (installed_apps, vuln_scan, os_info, ...) stay integration-tested.
//
// Canonical source: the #1679-hardened installed_apps trio. The null / non-positive
// guards added here make the pure functions total (no UB on null or empty input),
// which the unit tests exercise directly; for valid inputs the behaviour is
// byte-identical to the plugin copies they replace.

#ifndef YUZU_PLUGINS_SHARED_WIN_STR_HPP
#define YUZU_PLUGINS_SHARED_WIN_STR_HPP

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

namespace yuzu::win {

// UTF-8 -> UTF-16. Converts an explicit length (not NUL-terminated) so embedded
// NULs survive and a non-NUL-terminated string_view is handled correctly. Returns
// an empty wstring for empty or untranslatable input.
inline std::wstring to_wide(std::string_view s) {
    if (s.empty())
        return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (len <= 0)
        return {};
    std::wstring ws(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), ws.data(), len);
    return ws;
}

// UTF-16 -> UTF-8. len == -1 treats ws as NUL-terminated and strips the single
// trailing NUL the API includes in its count; an explicit len converts exactly
// that many wchar_t. Lone surrogates map to U+FFFD (default WideCharToMultiByte
// behaviour -- no WC_ERR_INVALID_CHARS). Returns empty for a null pointer.
inline std::string from_wide(const wchar_t* ws, int len = -1) {
    if (!ws)
        return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, ws, len, nullptr, 0, nullptr, nullptr);
    if (sz <= 0)
        return {};
    std::string s(static_cast<size_t>(sz), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, len, s.data(), sz, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0')
        s.pop_back();
    return s;
}

// Convert a REG_SZ / REG_EXPAND_SZ payload to UTF-8. size_bytes is the byte count
// reported by RegQueryValueExW (the ACTUAL value length, not the buffer capacity)
// and may include one or more trailing NULs; they are stripped by wchar_t count
// before conversion. A size that is not a whole multiple of sizeof(wchar_t) floors
// to whole units. Returns empty for a null buffer or a sub-wchar_t size.
inline std::string reg_sz_to_utf8(const wchar_t* buf, DWORD size_bytes) {
    if (!buf)
        return {};
    size_t nch = size_bytes / sizeof(wchar_t);
    while (nch > 0 && buf[nch - 1] == L'\0')
        --nch;
    return from_wide(buf, static_cast<int>(nch));
}

} // namespace yuzu::win

#endif // _WIN32

#endif // YUZU_PLUGINS_SHARED_WIN_STR_HPP
