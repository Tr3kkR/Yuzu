/**
 * test_installed_apps_registry_utf8.cpp -- #1662 regression guard.
 *
 * The installed_apps plugin must read REG_SZ uninstall-key values as UTF-8.
 * Before #1679 it used the ANSI registry APIs (RegQueryValueExA), which return
 * the system code page (cp1252 on Western Windows), so the downstream
 * sanitize_utf8 scrub turned every non-ASCII byte into '?' ("Cafe<acute>" ->
 * "Caf?"), corrupting the typed software-inventory store and breaking its
 * exact-match `WHERE name=$1` lookups.
 *
 * This test exercises the *fixed* read technique end-to-end against the real
 * Windows registry: it stores genuine UTF-16 REG_SZ values under a scratch HKCU
 * key, reads them back via RegQueryValueExW + a length-aware
 * WideCharToMultiByte(CP_UTF8, ...) (exactly what the plugin's reg_sz_to_utf8
 * does -- see agents/plugins/installed_apps/src/installed_apps_plugin.cpp), and
 * asserts the bytes come back as correct UTF-8.
 *
 * It deliberately asserts ONLY the fix's guarantee (W path -> correct UTF-8),
 * which holds regardless of the host ANSI code page. It does NOT assert that the
 * old A path mangles, because a runner with the "Use Unicode UTF-8 for worldwide
 * language support" beta enabled has GetACP()==CP_UTF8 and the A path would not
 * mangle there.
 *
 * Source is pure ASCII (\u escapes in wide literals, \x bytes in the expected
 * UTF-8) so it does not depend on the MSVC /utf-8 flag or the source code page.
 *
 * Windows-only; the plugin's registry code is a no-op elsewhere. Uses a scratch
 * HKCU key the running user can always create/write, mirroring
 * test_guard_registry.cpp.
 */

#include <catch2/catch_test_macros.hpp>

#include <string>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace {

// Scratch key under the shared SOFTWARE\YuzuTest namespace (same convention as
// test_guard_registry.cpp) so it never collides with real uninstall data.
constexpr const wchar_t* kSubKeyW = L"SOFTWARE\\YuzuTest\\InstalledAppsUtf8";

// The fix under test: length-aware UTF-16 -> UTF-8. Mirrors reg_sz_to_utf8 +
// from_wide in installed_apps_plugin.cpp (each plugin is its own shared object
// with no exported internals, so the conversion is restated here -- the same
// reason the plugin restates it from registry_plugin.cpp).
std::string reg_sz_to_utf8(const wchar_t* buf, DWORD size_bytes) {
    size_t nch = size_bytes / sizeof(wchar_t);
    while (nch > 0 && buf[nch - 1] == L'\0') {
        --nch;
    }
    if (nch == 0) {
        return {};
    }
    int sz = WideCharToMultiByte(CP_UTF8, 0, buf, static_cast<int>(nch), nullptr, 0, nullptr,
                                 nullptr);
    if (sz <= 0) {
        return {};
    }
    std::string out(static_cast<size_t>(sz), '\0');
    WideCharToMultiByte(CP_UTF8, 0, buf, static_cast<int>(nch), out.data(), sz, nullptr, nullptr);
    return out;
}

// RAII for the scratch key: delete it (and our values) on scope exit.
struct ScratchKey {
    HKEY key{};
    bool ok{false};
    ScratchKey() {
        ok = RegCreateKeyExW(HKEY_CURRENT_USER, kSubKeyW, 0, nullptr, 0, KEY_READ | KEY_WRITE,
                             nullptr, &key, nullptr) == ERROR_SUCCESS;
    }
    ~ScratchKey() {
        if (key) {
            RegCloseKey(key);
        }
        RegDeleteKeyW(HKEY_CURRENT_USER, kSubKeyW);
    }
};

// Store a genuine UTF-16 REG_SZ value (the way Windows actually persists names).
void set_sz(HKEY key, const wchar_t* name, const wchar_t* value) {
    DWORD bytes = static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t));
    REQUIRE(RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value), bytes) ==
            ERROR_SUCCESS);
}

// Read back via the fixed (W) path and convert to UTF-8.
std::string read_utf8(HKEY key, const wchar_t* name) {
    wchar_t buf[512]{};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size) ==
            ERROR_SUCCESS &&
        type == REG_SZ) {
        return reg_sz_to_utf8(buf, size);
    }
    return {};
}

} // namespace

TEST_CASE("installed_apps #1662: non-ASCII REG_SZ round-trips as correct UTF-8",
          "[installed_apps][registry][utf8][windows]") {
    ScratchKey scratch;
    REQUIRE(scratch.ok);

    INFO("system ANSI code page (GetACP) = " << GetACP());

    struct Case {
        const char* label;         // ASCII, for INFO (streaming wchar_t* into a
                                   // narrow ostream is a deleted operator in C++20+)
        const wchar_t* name;
        const wchar_t* wide;       // stored UTF-16 (\u escapes -> code-page independent)
        std::string expected_utf8; // correct UTF-8 the fix must produce (\x bytes)
    };
    const Case cases[] = {
        // "Cafe<U+00E9> Manager"
        {"DisplayName", L"DisplayName", L"Caf\u00E9 Manager", std::string("Caf\xC3\xA9 Manager")},
        // "M<U+00FC>nchen GmbH"
        {"Publisher", L"Publisher", L"M\u00FCnchen GmbH", std::string("M\xC3\xBCnchen GmbH")},
        // Cyrillic "Kasperskiy" -- non-Latin, multi-byte UTF-8 throughout.
        {"DisplayNameCyr", L"DisplayNameCyr",
         L"\u041A\u0430\u0441\u043F\u0435\u0440\u0441\u043A\u0438\u0439",
         std::string("\xD0\x9A\xD0\xB0\xD1\x81\xD0\xBF\xD0\xB5\xD1\x80\xD1\x81\xD0\xBA\xD0\xB8\xD0"
                     "\xB9")},
    };

    for (const auto& c : cases) {
        set_sz(scratch.key, c.name, c.wide);
        const std::string got = read_utf8(scratch.key, c.name);
        INFO("value " << c.label);
        CHECK(got == c.expected_utf8);
    }
}

TEST_CASE("installed_apps #1662: a trailing-NUL-free REG_SZ is not truncated",
          "[installed_apps][registry][utf8][windows]") {
    // RegSetValueExW with a byte count that excludes the terminating NUL is a
    // legitimate REG_SZ; the length-aware conversion must still return the whole
    // string (the pre-fix `std::string(buf, size-1)` shape assumed a NUL).
    ScratchKey scratch;
    REQUIRE(scratch.ok);

    const wchar_t* value = L"Caf\u00E9"; // "Cafe<U+00E9>"
    DWORD bytes_no_nul = static_cast<DWORD>(wcslen(value) * sizeof(wchar_t)); // no NUL
    REQUIRE(RegSetValueExW(scratch.key, L"NoNul", 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(value), bytes_no_nul) == ERROR_SUCCESS);

    CHECK(read_utf8(scratch.key, L"NoNul") == std::string("Caf\xC3\xA9"));
}

#endif // _WIN32
