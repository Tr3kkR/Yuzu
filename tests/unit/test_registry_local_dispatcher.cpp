/**
 * test_registry_local_dispatcher.cpp -- PR1.7 remediation, fix #3.
 *
 * Loads the ACTUAL built registry plugin (registry.dll, the same artifact
 * the agent daemon loads in production) via PluginHandle::load and drives
 * it through yuzu::agent::LocalDispatcher -- the same in-process dispatch
 * mechanism used for the manual verification this PR's remediation was
 * checked against on a real Windows host. Unlike test_user_profile_model.cpp
 * (the pure ProfileList/HKU model, runs on every host), this exercises the
 * Win32 shell end to end: real RegOpenKeyExW/RegQueryValueExW calls against
 * the live HKEY_USERS hive for the account this test runs as.
 *
 * Scope, deliberately: only the LIVE-hive-first path is exercised. The
 * offline-mount fallback (RegLoadKeyW against a second, logged-out
 * profile's NTUSER.DAT) needs a second real user profile that isn't
 * guaranteed present on every CI runner -- that path stays covered by the
 * one-time manual verification this PR's description documents, not by an
 * automated test here. Likewise, forcing a genuine RegUnLoadKeyW failure to
 * pin fix #1's unload-warning-surfacing behaviour deterministically would
 * need to hold the mounted hive open from elsewhere while unmounting it, a
 * real Win32 race that isn't reliably reproducible on a shared CI host --
 * the regression pin below instead asserts the honest converse: the live
 * path never mounts anything, so unload_failed must never fire and no
 * "hive_unload_failed" warning line should ever appear on it.
 *
 * Windows-only; the plugin's registry code is a no-op elsewhere.
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

#include <sddl.h> // ConvertSidToStringSidW

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <optional>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Locate the real registry.dll built by agents/plugins/registry/meson.build.
// Mirrors test_plugin_loader.cpp's find_fixture_plugin, pointed at the
// production plugin's own build output directory rather than tests/.
// Returns an empty path (never fails) when not found -- a build invoked
// without the agent plugins (e.g. -Dbuild_examples=false, which currently
// gates the registry subdir()) must not fail this test, it must skip it.
fs::path find_registry_plugin() {
    const std::string lib_name = "registry.dll";

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "registry" /
                                lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "registry" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "registry" / lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

// The calling process's own SID, e.g. "S-1-5-21-...-1001" -- always backed
// by an already-loaded HKEY_USERS\<sid> hive (Windows loads the caller's
// profile hive at process start), so it is the one profile guaranteed
// reachable via the live-hive-first branch without needing admin rights or
// a second logged-in account.
std::optional<std::string> current_user_sid() {
    HANDLE token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return std::nullopt;
    struct TokenCloser {
        HANDLE h;
        ~TokenCloser() { CloseHandle(h); }
    } token_guard{token};

    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    if (needed == 0)
        return std::nullopt;
    std::vector<BYTE> buf(needed);
    if (!GetTokenInformation(token, TokenUser, buf.data(), needed, &needed))
        return std::nullopt;

    auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
    LPWSTR sid_str = nullptr;
    if (!ConvertSidToStringSidW(tu->User.Sid, &sid_str) || !sid_str)
        return std::nullopt;
    int n = WideCharToMultiByte(CP_UTF8, 0, sid_str, -1, nullptr, 0, nullptr, nullptr);
    std::string out;
    if (n > 0) {
        out.resize(static_cast<size_t>(n) - 1); // exclude the NUL WideCharToMultiByte counts
        WideCharToMultiByte(CP_UTF8, 0, sid_str, -1, out.data(), n, nullptr, nullptr);
    }
    LocalFree(sid_str);
    return out;
}

// Parses LocalDispatcher's newline-joined capture into
// render_profile_row's `profile|sid|name|path|state` lines and returns the
// row whose sid matches, if any.
struct ProfileRow {
    std::string sid, name, path, state;
};
std::optional<ProfileRow> find_profile_row(const std::string& captured, const std::string& sid) {
    std::istringstream iss(captured);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.starts_with("profile|"))
            continue;
        std::vector<std::string> fields;
        size_t pos = 8; // skip "profile|"
        while (pos <= line.size()) {
            auto p = line.find('|', pos);
            if (p == std::string::npos) {
                fields.push_back(line.substr(pos));
                break;
            }
            fields.push_back(line.substr(pos, p - pos));
            pos = p + 1;
        }
        if (fields.size() == 4 && fields[0] == sid)
            return ProfileRow{fields[0], fields[1], fields[2], fields[3]};
    }
    return std::nullopt;
}

std::string to_upper(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

} // namespace

TEST_CASE("registry plugin: list_profiles + get_user_value live-hive round-trip "
          "via LocalDispatcher (PR1.7 remediation)",
          "[registry][windows][local_dispatcher]") {
    auto plugin_path = find_registry_plugin();
    if (plugin_path.empty()) {
        WARN("registry.dll not found (build_examples=false?) -- skipping "
             "LocalDispatcher round-trip test");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* descriptor = handle->descriptor();
    REQUIRE(descriptor != nullptr);

    auto own_sid = current_user_sid();
    if (!own_sid) {
        WARN("could not resolve own SID -- skipping LocalDispatcher round-trip test");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;

    // list_profiles: real ProfileList enumeration + live HKEY_USERS scan.
    auto lp = dispatcher.run(descriptor, "list_profiles");
    CHECK(lp.rc == 0);

    auto own_row = find_profile_row(lp.captured, *own_sid);
    if (!own_row || own_row->name.empty() || own_row->name == "-") {
        // is_system_sid (S-1-5-18/19/20) or an unresolvable profile_name --
        // both correctly excluded/empty by build_profile_list; the
        // live-hive-first positive path below isn't exercisable through a
        // validated sid/username in that case.
        WARN("own sid " << *own_sid << " not in the enumerated, non-system profile "
             "list with a resolvable name (running as a system account?) -- "
             "skipping the get_user_value round-trip");
        return;
    }
    CHECK(own_row->state == "loaded"); // live hive, not the offline-mount fallback

    // Write a scratch REG_SZ value into OUR OWN live hive. HKEY_CURRENT_USER
    // is always the calling process's own already-loaded HKU\<own sid> --
    // guaranteed live + writable without admin rights, unlike any other
    // logged-in user's hive.
    const std::wstring key_path =
        L"Software\\YuzuTest\\RegistryPr17Ld_" + std::to_wstring(GetCurrentProcessId());
    HKEY scratch{};
    REQUIRE(RegCreateKeyExW(HKEY_CURRENT_USER, key_path.c_str(), 0, nullptr, 0,
                            KEY_READ | KEY_WRITE, nullptr, &scratch, nullptr) == ERROR_SUCCESS);
    struct ScratchCloser {
        HKEY key;
        std::wstring path;
        ~ScratchCloser() {
            if (key)
                RegCloseKey(key);
            RegDeleteKeyW(HKEY_CURRENT_USER, path.c_str());
        }
    } scratch_guard{scratch, key_path};

    const wchar_t* value = L"pr17-local-dispatcher-scratch";
    DWORD bytes = static_cast<DWORD>((wcslen(value) + 1) * sizeof(wchar_t));
    REQUIRE(RegSetValueExW(scratch, L"ScratchValue", 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(value), bytes) == ERROR_SUCCESS);

    const std::string key_path_utf8 =
        "Software\\YuzuTest\\RegistryPr17Ld_" + std::to_string(GetCurrentProcessId());

    SECTION("live-hive-first path resolves by sid and returns the scratch value") {
        std::vector<YuzuParam> params{
            {"sid", own_sid->c_str()},
            {"key", key_path_utf8.c_str()},
            {"name", "ScratchValue"},
        };
        auto result = dispatcher.run(descriptor, "get_user_value", params);
        CHECK(result.rc == 0);
        CHECK(result.captured.find("pr17-local-dispatcher-scratch") != std::string::npos);
        // Fix #1 regression pin: the live-hive path never mounts an offline
        // hive, so unload_failed must never be set on it.
        CHECK(result.captured.find("hive_unload_failed") == std::string::npos);
    }

    SECTION("username resolves case-insensitively to the same sid (fix #5)") {
        std::vector<YuzuParam> params{
            {"username", to_upper(own_row->name).c_str()},
            {"key", key_path_utf8.c_str()},
            {"name", "ScratchValue"},
        };
        auto result = dispatcher.run(descriptor, "get_user_value", params);
        CHECK(result.rc == 0);
        CHECK(result.captured.find("pr17-local-dispatcher-scratch") != std::string::npos);
    }

    SECTION("a sid absent from the enumerated profile list is rejected, not "
            "silently opened (fix #4)") {
        std::vector<YuzuParam> params{
            {"sid", "S-1-5-21-0-0-0-999999999"},
            {"key", key_path_utf8.c_str()},
            {"name", "ScratchValue"},
        };
        auto result = dispatcher.run(descriptor, "get_user_value", params);
        CHECK(result.rc != 0);
        CHECK(result.captured.find("not found in enumerated profiles") != std::string::npos);
    }
}

#endif // _WIN32
