// win_str.hpp -- shared Windows UTF-16 <-> UTF-8 string helpers.
//
// A single canonical home (#1681) for the wide<->UTF-8 conversion that several
// agent plugins had each re-derived. The actual prior landscape (do NOT trust the
// originating issue's "~6 byte-identical" shorthand): the full trio existed only in
// installed_apps; `registry` carries to_wide + from_wide (no reg_sz_to_utf8 -- it
// inlines that); `wmi`/`interaction`/`tar_module_etw`/`services` each carry a single,
// sometimes-renamed wide converter; `processes` has none and no registry access.
// Those existing copies are deliberately NOT migrated in #1681/#1682 -- only the four
// previously-ANSI siblings (vuln_scan/os_info/sccm/windows_updates) consume this
// header so far; aligning the rest is a tracked follow-up.
//
// These depend only on WideCharToMultiByte / MultiByteToWideChar -- no other Win32
// surface -- so a header-only home gives one source of truth while preserving build
// isolation: every plugin is its own shared object and still compiles its own inline
// copy, so there is no exported symbol to interpose across the plugin ABI boundary.
//
// Windows-only by construction (#ifdef _WIN32); the header is empty elsewhere.
// Deliberately free of Reg* I/O so the pure string conversion is unit-testable
// without advapi32 (tests/unit/test_win_str_utils.cpp). The Reg* read sites that
// consume these (installed_apps, vuln_scan, os_info, ...) stay integration-tested.
//
// Derived from the #1679-hardened installed_apps trio, with two deliberate
// divergences: (1) null / non-positive guards make from_wide / reg_sz_to_utf8 total
// on null/empty input (to_wide takes a string_view, so it is total only for a valid,
// non-null view -- a null `const char*` is UB at the string_view ctor before any
// guard runs; every caller passes a compile-time ASCII literal); (2) reg_sz_to_utf8
// stops at the first NUL rather than only stripping trailing NULs (#1682 Gate-4 R6,
// see below). The de-dup follow-up will align installed_apps to match. Callers pass
// compile-time subkey/value names; a future runtime-derived name that fails to_wide
// would yield an empty wstring -- opening the ROOT key / reading the DEFAULT value --
// so validate any runtime-derived name before use.

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
// trailing NUL the API includes in its count. An explicit len converts that many
// wchar_t -- but the trailing-NUL pop still fires, so a single trailing NUL inside
// an explicit-len buffer is also stripped (benign: the only explicit-len caller,
// reg_sz_to_utf8, has already removed trailing NULs). Lone surrogates map to U+FFFD
// (default WideCharToMultiByte behaviour -- no WC_ERR_INVALID_CHARS). Returns empty
// for a null pointer.
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
// reported by RegQueryValueExW (the ACTUAL value length, not the buffer capacity).
// REG_SZ / REG_EXPAND_SZ are NUL-terminated by convention, so conversion stops at
// the FIRST NUL within the value: this drops single/double trailing termination AND
// a malformed interior NUL that would otherwise survive into the output and silently
// truncate the whole line at the SDK's `const char*` write_output boundary (#1682
// Gate-4 R6). A size that is not a whole multiple of sizeof(wchar_t) floors to whole
// units. Returns empty for a null buffer or a sub-wchar_t size. Assumes a bounded
// (registry-sized) buffer -- the int cast of the wchar count is safe for any value
// that fit a RegQueryValueExW read. NOT for REG_MULTI_SZ: there an interior NUL is a
// record separator, not a terminator, so this would truncate to the first record.
// (The first-NUL stop is a deliberate improvement over the installed_apps copy,
// which strips trailing NULs only; the de-dup follow-up aligns it.)
inline std::string reg_sz_to_utf8(const wchar_t* buf, DWORD size_bytes) {
    if (!buf)
        return {};
    size_t cap = size_bytes / sizeof(wchar_t);
    size_t nch = 0;
    while (nch < cap && buf[nch] != L'\0')
        ++nch;
    return from_wide(buf, static_cast<int>(nch));
}

} // namespace yuzu::win

#endif // _WIN32

#endif // YUZU_PLUGINS_SHARED_WIN_STR_HPP
