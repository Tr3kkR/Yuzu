/**
 * installed_apps_plugin.cpp — Installed applications plugin for Yuzu
 *
 * Actions:
 *   "list"  — Lists all installed applications.
 *   "query" — Searches for a specific app by name (partial match).
 *             Params: name (required).
 *   "list_inventory" — machine-scope software inventory for the daily sync
 *             (blob contract v2, ADR-0016). Emits the extended 13-field rows;
 *             fields an ecosystem does not store are EMPTY, never synthesised
 *             (no "-" placeholders, no sentinel row on an empty result). On
 *             macOS, publisher/signature_status/bundle_id are derived via
 *             subprocess (codesign/mdls against the app bundle path) — never
 *             fabricated; EMPTY when the relevant tool is unavailable.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   app|name|version|publisher|install_date                       (list/query)
 *   inv|name|version|publisher|install_date|kind|ecosystem|epoch|release|arch|
 *       signature_status|distro_id|distro_version|bundle_id       (list_inventory)
 *
 * `list`/`query`/`list_per_user` output is a stable operator-facing contract
 * (content/definitions/installed_apps.yaml et al.) — extend `list_inventory`,
 * never those.
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

// Pure parse/format helpers for the list_inventory action (v2 rows). In a
// header so the unit test exercises the same code (pattern: #1662).
#include "installed_apps_inventory.hpp"

#if defined(__linux__) || defined(__APPLE__)
#include <sstream>
#endif

#ifdef __linux__
#include <fstream>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// UTF-16<->UTF-8 registry conversion (#1662). In a header so the #1662
// regression test exercises the same code, not a re-implementation.
#include "installed_apps_registry_utf8.hpp"
#endif

namespace {

// ── subprocess helper (Linux / macOS) ──────────────────────────────────────

#if defined(__linux__) || defined(__APPLE__)
std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
    // RAII owner: a raw FILE* would leak the pipe (and never reap the child)
    // if appending captured output throws before a manual pclose() ran. The
    // per-app codesign/mdls calls (A-1.10) exercise this path far more often
    // than the prior single system_profiler call, so the exception-safety
    // gap is worth closing now rather than deferring it.
    std::unique_ptr<FILE, decltype(&pclose)> pipe{popen(cmd, "r"), &pclose};
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe.get())) {
        result += buf.data();
    }
    pipe.reset(); // close + reap before scanning the trailing newline/CR
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

bool command_exists(const char* cmd) {
    auto check = std::string("command -v ") + cmd + " >/dev/null 2>&1";
    return system(check.c_str()) == 0;
}
#endif

// ── App record ────────────────────────────────────────────────────────────

struct AppInfo {
    std::string name;
    std::string version;
    std::string publisher;
    std::string install_date;
    std::string path; // macOS bundle path (system_profiler Location:) -- subprocess
                       // input for the v2 inventory's publisher/signature_status/
                       // bundle_id only; never part of the legacy list/query/
                       // list_per_user rows (empty on every other platform).
};

// Case-insensitive substring match
bool icontains(const std::string& haystack, const std::string& needle) {
    if (needle.empty())
        return true;
    if (haystack.size() < needle.size())
        return false;
    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                          [](char a, char b) {
                              return std::tolower(static_cast<unsigned char>(a)) ==
                                     std::tolower(static_cast<unsigned char>(b));
                          });
    return it != haystack.end();
}

// Replace invalid UTF-8 bytes with '?' to avoid protobuf serialization errors.
// Windows registry strings are now read via the *W APIs + WideCharToMultiByte(CP_UTF8)
// and are already valid UTF-8, so this is defence-in-depth there (#1662); it remains
// load-bearing for the Linux/macOS subprocess paths, whose output encoding is unknown.
std::string sanitize_utf8(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            // ASCII
            out += s[i];
            ++i;
        } else if ((c >> 5) == 0x06 && i + 1 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02) {
            // Valid 2-byte sequence
            out += s[i];
            out += s[i + 1];
            i += 2;
        } else if ((c >> 4) == 0x0E && i + 2 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02) {
            // Valid 3-byte sequence
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            i += 3;
        } else if ((c >> 3) == 0x1E && i + 3 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 3]) >> 6) == 0x02) {
            // Valid 4-byte sequence
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            out += s[i + 3];
            i += 4;
        } else {
            out += '?';
            ++i;
        }
    }
    return out;
}

// ── Windows: read apps from a registry uninstall key ──────────────────────

#ifdef _WIN32

// to_wide / from_wide / reg_sz_to_utf8 now live in
// installed_apps_registry_utf8.hpp (included above) so the #1662 regression test
// runs the same conversion the plugin does. Pull them into this anonymous
// namespace so the existing unqualified call sites resolve unchanged.
using namespace yuzu::installed_apps::reg_utf8;

// RAII closer for an HKEY. Closing every handle into a RegLoadKeyW-mounted hive
// BEFORE the unload is load-bearing: RegUnLoadKeyW fails (ERROR_ACCESS_DENIED)
// while any subtree handle is open, so a leaked HKEY on a throw path would defeat
// the HiveUnloadGuard in do_list_per_user. Destruction order guarantees these
// callee handles close as the exception leaves enumerate_uninstall_key, before
// the caller's unload guard runs (#1662 Gate-8).
struct HKeyCloser {
    HKEY h;
    explicit HKeyCloser(HKEY k) : h(k) {}
    ~HKeyCloser() {
        if (h)
            RegCloseKey(h);
    }
    HKeyCloser(const HKeyCloser&) = delete;
    HKeyCloser& operator=(const HKeyCloser&) = delete;
};

void enumerate_uninstall_key(HKEY root, const char* subkey, REGSAM extra_sam,
                             std::vector<AppInfo>& apps) {
    HKEY hkey{};
    if (RegOpenKeyExW(root, to_wide(subkey).c_str(), 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS | extra_sam, &hkey) != ERROR_SUCCESS) {
        return;
    }
    HKeyCloser hkey_guard{hkey};

    // RegEnumKeyExW's lpcchName is a WCHAR COUNT, not a byte size. Bind the array
    // size and every reset to one constant so the byte-vs-count unit cannot skew —
    // the #1662 A->W conversion missed one reset site (gov Gate 3/4 BLOCKING).
    constexpr DWORD kNameBufLen = 256;
    wchar_t name_buf[kNameBufLen]{};
    DWORD idx = 0;
    DWORD name_len = kNameBufLen;

    while (RegEnumKeyExW(hkey, idx++, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr) ==
           ERROR_SUCCESS) {
        HKEY app_key{};
        if (RegOpenKeyExW(hkey, name_buf, 0, KEY_READ | extra_sam, &app_key) == ERROR_SUCCESS) {
            HKeyCloser app_guard{app_key};
            auto read_str = [&](const char* value_name) -> std::string {
                wchar_t buf[512]{};
                DWORD size = sizeof(buf); // size in BYTES
                DWORD type = 0;
                if (RegQueryValueExW(app_key, to_wide(value_name).c_str(), nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS) {
                    if (type == REG_SZ && size >= sizeof(wchar_t)) {
                        return reg_sz_to_utf8(buf, size);
                    }
                }
                return {};
            };

            auto display_name = read_str("DisplayName");
            if (!display_name.empty()) {
                // Skip system components and updates without meaningful names
                auto sys_component = read_str("SystemComponent");
                if (sys_component == "1") {
                    name_len = kNameBufLen;
                    continue; // app_guard closes app_key
                }

                AppInfo app;
                app.name = std::move(display_name);
                app.version = read_str("DisplayVersion");
                app.publisher = read_str("Publisher");
                app.install_date = read_str("InstallDate");
                apps.push_back(std::move(app));
            }
        }
        name_len = kNameBufLen;
    }
}

std::vector<AppInfo> get_installed_apps_windows() {
    std::vector<AppInfo> apps;
    static const char* kUninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

    // 64-bit HKLM
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kUninstallKey, KEY_WOW64_64KEY, apps);
    // 32-bit HKLM (WoW6432Node)
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kUninstallKey, KEY_WOW64_32KEY, apps);
    // Current user
    enumerate_uninstall_key(HKEY_CURRENT_USER, kUninstallKey, 0, apps);

    // Deduplicate by name+version
    std::sort(apps.begin(), apps.end(), [](const AppInfo& a, const AppInfo& b) {
        return a.name < b.name || (a.name == b.name && a.version < b.version);
    });
    apps.erase(std::unique(apps.begin(), apps.end(),
                           [](const AppInfo& a, const AppInfo& b) {
                               return a.name == b.name && a.version == b.version;
                           }),
               apps.end());

    return apps;
}
#endif

// ── Linux: detect package manager and list packages ───────────────────────

#ifdef __linux__
std::vector<AppInfo> get_installed_apps_linux() {
    std::vector<AppInfo> apps;

    if (command_exists("dpkg-query")) {
        // Debian/Ubuntu
        auto out = run_command(
            "dpkg-query -W -f='${Package}|${Version}|${Maintainer}|${Status}\\n' 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            // Only include fully installed packages
            if (line.find("install ok installed") == std::string::npos)
                continue;

            std::istringstream ls(line);
            std::string name, version, publisher;
            std::getline(ls, name, '|');
            std::getline(ls, version, '|');
            std::getline(ls, publisher, '|');

            apps.push_back({name, version, publisher, "-"});
        }
    } else if (command_exists("rpm")) {
        // RHEL/Fedora/SUSE
        auto out = run_command(
            "rpm -qa --queryformat "
            "'%{NAME}|%{VERSION}-%{RELEASE}|%{VENDOR}|%{INSTALLTIME:date}\\n' 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            std::istringstream ls(line);
            std::string name, version, publisher, date;
            std::getline(ls, name, '|');
            std::getline(ls, version, '|');
            std::getline(ls, publisher, '|');
            std::getline(ls, date, '|');

            if (publisher == "(none)")
                publisher = "-";
            apps.push_back({name, version, publisher, date});
        }
    } else if (command_exists("pacman")) {
        // Arch Linux
        auto out = run_command("pacman -Q 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            // Format: "name version"
            auto sp = line.find(' ');
            if (sp != std::string::npos) {
                apps.push_back({line.substr(0, sp), line.substr(sp + 1), "-", "-"});
            }
        }
    }

    std::sort(apps.begin(), apps.end(),
              [](const AppInfo& a, const AppInfo& b) { return a.name < b.name; });
    return apps;
}
#endif

// ── macOS: list GUI apps and packages ─────────────────────────────────────

namespace inv = yuzu::installed_apps::inventory;

#ifdef __APPLE__
std::vector<AppInfo> get_installed_apps_macos() {
    std::vector<AppInfo> apps;

    // GUI applications from system_profiler. Location: (the bundle path) is
    // captured alongside Version:/Last Modified: -- it never reaches the
    // legacy list/query row (do_list/do_query never read AppInfo.path), but
    // the v2 inventory collector (get_inventory_macos, below) needs it to run
    // per-app codesign/mdls subprocess calls. The actual header-vs-metadata
    // parsing lives in inv::parse_macos_app_headers (installed_apps_inventory.hpp)
    // -- a pure function, so its indentation-depth handling (an app literally
    // named "Version"/"Last Modified"/"Location" must start a new record, not
    // be misread as the PRECEDING app's own field) is unit-testable without
    // system_profiler on the test host.
    auto out = run_command("system_profiler SPApplicationsDataType -detailLevel mini 2>/dev/null"
                           " | grep -E '^ {4}\\w|Version:|Last Modified:|Location:' ");
    for (auto& hdr : inv::parse_macos_app_headers(out)) {
        apps.push_back({std::move(hdr.name), std::move(hdr.version), "-",
                        std::move(hdr.last_modified), std::move(hdr.location)});
    }

    std::sort(apps.begin(), apps.end(),
              [](const AppInfo& a, const AppInfo& b) { return a.name < b.name; });
    return apps;
}
#endif

// ── list_inventory collectors (blob contract v2) ──────────────────────────

#ifdef _WIN32
std::vector<inv::InvRecord> get_inventory_windows() {
    std::vector<inv::InvRecord> recs;
    for (auto& app : get_installed_apps_windows()) {
        inv::InvRecord r;
        r.name = std::move(app.name);
        r.version = std::move(app.version);
        r.publisher = std::move(app.publisher);
        r.install_date = std::move(app.install_date);
        r.kind = "app";
        r.ecosystem = "windows";
        // epoch/release/signature honest-empty: the Uninstall hive stores no
        // NEVRA and no signature. arch stays empty too — inferring x64/x86
        // from which hive a key sat in would be synthesis, not storage.
        recs.push_back(std::move(r));
    }
    return recs;
}
#endif

#ifdef __linux__
std::vector<inv::InvRecord> get_inventory_linux() {
    std::vector<inv::InvRecord> recs;

    const auto collect = [&recs](const char* cmd, auto parse_line) {
        auto out = run_command(cmd);
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            if (auto r = parse_line(line))
                recs.push_back(std::move(*r));
        }
    };

    if (command_exists("dpkg-query")) {
        // ${db:Status-Abbrev} (want+status, 2 chars) keeps installed AND held
        // packages via its 2nd char == 'i' ("ii" want=install, "hi" want=hold)
        // — matches vuln_scan's vuln_identity.hpp (PR #1804) exactly, so the
        // two collectors agree on which packages are present. "rc"
        // (removed, config-files) and "un" (unknown) are correctly excluded;
        // this also supersedes the legacy `list` filter's narrower
        // "install ok installed" substring check, which excludes held.
        collect("dpkg-query -W -f='${Package}\\t${db:Status-Abbrev}\\t${Version}\\t"
                "${Architecture}\\t${Maintainer}\\n' 2>/dev/null",
                inv::parse_dpkg_inv_line);
    } else if (command_exists("rpm")) {
        // Raw SIGPGP (payload) + RSAHEADER (header) signature tags; signed vs
        // unsigned is computed in C++ by parse_rpm_inv_line/rpm_sig_present —
        // matches vuln_scan's vuln_identity.hpp (PR #1804) exactly, so the two
        // collectors agree on this field for the same rpm. Never a live
        // `rpm -K` verification. PACKAGER per the v2 spec (`list` keeps VENDOR
        // for its stable operator contract).
        collect("rpm -qa --queryformat '%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t"
                "%{ARCH}\\t%{PACKAGER}\\t%{INSTALLTIME:date}\\t%{SIGPGP}\\t%{RSAHEADER}\\n' "
                "2>/dev/null",
                inv::parse_rpm_inv_line);
    } else if (command_exists("pacman")) {
        collect("pacman -Q 2>/dev/null", inv::parse_pacman_inv_line);
    } else if (command_exists("apk")) {
        // Alpine — first apk enumeration on the sync path (the legacy `list`
        // has no apk branch; precedent is vuln_scan's enumerator).
        collect("apk info -v 2>/dev/null", inv::parse_apk_inv_line);
    }

    // Host-level distro identity, read once and stamped on every row (v2
    // contract). Honest-empty when /etc/os-release is absent (minimal
    // containers) or the keys are missing.
    std::string osrel;
    if (std::ifstream f{"/etc/os-release"}; f) {
        std::ostringstream buf;
        buf << f.rdbuf();
        osrel = buf.str();
    }
    const std::string distro_id = inv::parse_os_release(osrel, "ID");
    const std::string distro_version = inv::parse_os_release(osrel, "VERSION_ID");
    for (auto& r : recs) {
        r.distro_id = distro_id;
        r.distro_version = distro_version;
    }
    return recs;
}
#endif

#ifdef __APPLE__

// POSIX single-quote escaping for a subprocess argument interpolated into a
// shell command line (mirrors agents/plugins/license_scan/src/licensing_linux.cpp's
// shell_single_quote exactly): wrap in '...', turning each embedded ' into
// '\'' so run_command's popen(cmd, "r") (== `/bin/sh -c cmd`) can never
// misparse an app bundle path as extra shell syntax.
std::string shell_single_quote(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '\'';
    for (char c : s) {
        if (c == '\'')
            out += "'\\''";
        else
            out += c;
    }
    out += '\'';
    return out;
}

// codesign-derived signing identity for one macOS app bundle (subprocess
// only -- no Security.framework link, so installed_apps/meson.build stays
// unchanged). Maps to the EXISTING signed/unsigned vocabulary
// (installed_apps_inventory.hpp) via inv::parse_codesign_output -- see that
// function for the affirmative-negative-claim policy. `codesign_available`
// is resolved ONCE per collection by the caller (get_inventory_macos), not
// re-probed via a `command -v` subprocess for every app: the tool's presence
// on PATH cannot change mid-collection, so re-checking it N times only adds
// N blocking subprocess launches for a constant answer. Honest-empty ONLY
// when codesign itself is unavailable -- never based on the app's own
// properties.
inv::MacosSignature codesign_info(const std::string& app_path, bool codesign_available) {
    if (!codesign_available)
        return {}; // honest-empty: the tool itself is unavailable
    const std::string out =
        run_command(("codesign -dvvv " + shell_single_quote(app_path) + " 2>&1").c_str());
    return inv::parse_codesign_output(out);
}

// CFBundleIdentifier for one macOS app bundle, via `mdls` (Spotlight
// metadata -- subprocess only, no framework link). `mdls_available` is
// resolved ONCE per collection by the caller, for the same reason as
// `codesign_available` above. Parsing (honest-empty when mdls is unavailable,
// the path doesn't resolve, or the attribute is genuinely unset) lives in
// inv::parse_mdls_bundle_id_output.
std::string mdls_bundle_id(const std::string& app_path, bool mdls_available) {
    if (!mdls_available)
        return {};
    const std::string out = run_command(("mdls -name kMDItemCFBundleIdentifier " +
                                         shell_single_quote(app_path) + " 2>/dev/null")
                                             .c_str());
    return inv::parse_mdls_bundle_id_output(out);
}

std::vector<inv::InvRecord> get_inventory_macos() {
    std::vector<inv::InvRecord> recs;
    // Resolved ONCE for the whole collection, not per-app: `codesign`/`mdls`
    // either exist on PATH for this host or they don't, so probing that via
    // `command -v` (itself a subprocess launch) inside the per-app loop below
    // only multiplies blocking shell launches for an answer that cannot
    // change between apps in one collection pass.
    const bool codesign_available = command_exists("codesign");
    const bool mdls_available = command_exists("mdls");
    for (auto& app : get_installed_apps_macos()) {
        inv::InvRecord r;
        r.name = std::move(app.name);
        r.version = std::move(app.version);
        r.install_date = std::move(app.install_date); // Last Modified
        r.kind = "app";
        r.ecosystem = "macos";
        // publisher / signature_status / bundle_id: subprocess-derived
        // (codesign/mdls) against the bundle path system_profiler reported.
        // AppInfo.publisher (always "-", the legacy list placeholder) is
        // deliberately never read here -- honest-empty when the path is
        // unknown, never the placeholder, never fabricated.
        if (!app.path.empty()) {
            const inv::MacosSignature cs = codesign_info(app.path, codesign_available);
            r.publisher = cs.publisher;
            r.signature_status = cs.signature_status;
            r.bundle_id = mdls_bundle_id(app.path, mdls_available);
        }
        // "homebrew" stays a reserved ecosystem value: brew is per-user
        // (list_per_user) and out of machine-scope this slice.
        recs.push_back(std::move(r));
    }
    return recs;
}
#endif

int do_list_inventory(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    auto recs = get_inventory_windows();
#elif defined(__linux__)
    auto recs = get_inventory_linux();
#elif defined(__APPLE__)
    auto recs = get_inventory_macos();
#else
    std::vector<inv::InvRecord> recs;
#endif

    // No sentinel row: an empty result is empty output + rc 0. The sync
    // source's empty-parse guard skips the cycle rather than wiping state.
    for (const auto& r : recs) {
        if (r.name.empty())
            continue; // contract: row dropped if name is empty
        ctx.write_output(sanitize_utf8(inv::format_inv_row(r)));
    }
    return 0;
}

// ── list action ───────────────────────────────────────────────────────────

int do_list(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    auto apps = get_installed_apps_windows();
#elif defined(__linux__)
    auto apps = get_installed_apps_linux();
#elif defined(__APPLE__)
    auto apps = get_installed_apps_macos();
#else
    std::vector<AppInfo> apps;
#endif

    if (apps.empty()) {
        ctx.write_output("app|No applications found|-|-|-");
        return 0;
    }

    for (const auto& app : apps) {
        ctx.write_output(sanitize_utf8(
            std::format("app|{}|{}|{}|{}", app.name, app.version.empty() ? "-" : app.version,
                        app.publisher.empty() ? "-" : app.publisher,
                        app.install_date.empty() ? "-" : app.install_date)));
    }
    return 0;
}

// ── query action ──────────────────────────────────────────────────────────

int do_query(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto search = std::string(params.get("name"));
    if (search.empty()) {
        ctx.write_output("error|'name' parameter is required");
        return 1;
    }

#ifdef _WIN32
    auto apps = get_installed_apps_windows();
#elif defined(__linux__)
    auto apps = get_installed_apps_linux();
#elif defined(__APPLE__)
    auto apps = get_installed_apps_macos();
#else
    std::vector<AppInfo> apps;
#endif

    bool found = false;
    for (const auto& app : apps) {
        if (icontains(app.name, search)) {
            if (!found) {
                ctx.write_output("found|true");
                found = true;
            }
            ctx.write_output(sanitize_utf8(
                std::format("app|{}|{}|{}", app.name, app.version.empty() ? "-" : app.version,
                            app.publisher.empty() ? "-" : app.publisher)));
        }
    }

    if (!found) {
        ctx.write_output("found|false");
    }
    return 0;
}

} // namespace

class InstalledAppsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "installed_apps"; }
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Inventories installed applications and queries by name";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "query", "list_per_user", "list_inventory", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "list")
            return do_list(ctx);
        if (action == "query")
            return do_query(ctx, params);
        if (action == "list_per_user")
            return do_list_per_user(ctx);
        if (action == "list_inventory")
            return do_list_inventory(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_list_per_user([[maybe_unused]] yuzu::CommandContext& ctx) {
#ifdef _WIN32
        // Enumerate user profiles from the ProfileList registry key
        static const char* kProfileListKey =
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
        static const char* kUninstallKey =
            "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

        HKEY profiles_key{};
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, to_wide(kProfileListKey).c_str(), 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &profiles_key) != ERROR_SUCCESS) {
            ctx.write_output("error|failed to open ProfileList registry key");
            return 1;
        }

        wchar_t sid_buf[256]{};
        DWORD idx = 0;
        DWORD sid_len = 256; // RegEnumKeyExW counts WCHARs, not bytes

        while (RegEnumKeyExW(profiles_key, idx++, sid_buf, &sid_len,
                             nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            std::string sid = from_wide(sid_buf, static_cast<int>(sid_len));
            sid_len = 256;

            // Read ProfileImagePath to get the username
            HKEY sid_key{};
            if (RegOpenKeyExW(profiles_key, to_wide(sid).c_str(), 0, KEY_READ, &sid_key) !=
                ERROR_SUCCESS)
                continue;

            wchar_t path_buf[512]{};
            DWORD path_size = sizeof(path_buf); // size in BYTES
            DWORD type = 0;
            std::string username = sid;  // fallback to SID
            std::wstring profile_path_w; // kept wide for RegLoadKeyW below
            if (RegQueryValueExW(sid_key, L"ProfileImagePath", nullptr, &type,
                                 reinterpret_cast<LPBYTE>(path_buf), &path_size) == ERROR_SUCCESS) {
                size_t nch = path_size / sizeof(wchar_t);
                while (nch > 0 && path_buf[nch - 1] == L'\0')
                    --nch;
                profile_path_w.assign(path_buf, nch);
                std::string profile_path =
                    from_wide(profile_path_w.c_str(), static_cast<int>(profile_path_w.size()));
                auto last_sep = profile_path.find_last_of("\\/");
                if (last_sep != std::string::npos)
                    username = profile_path.substr(last_sep + 1);
            }
            RegCloseKey(sid_key);

            // Skip system SIDs (S-1-5-18, S-1-5-19, S-1-5-20)
            if (sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20")
                continue;

            // Try to read the user's Uninstall key from HKU\<SID>
            std::string user_uninstall = sid + "\\" + kUninstallKey;
            std::vector<AppInfo> user_apps;
            enumerate_uninstall_key(HKEY_USERS, user_uninstall.c_str(), 0, user_apps);

            // The !profile_path_w.empty() guard avoids mounting a hive from a bogus
            // "\NTUSER.DAT" path when ProfileImagePath failed to read (it also
            // blocked an empty-path hive-load the prior *A code permitted).
            if (user_apps.empty() && !profile_path_w.empty()) {
                // User hive may not be loaded — try loading NTUSER.DAT
                std::wstring ntuser_path_w = profile_path_w + L"\\NTUSER.DAT";
                std::string mount_key = "YUZU_APPS_" + sid;

                // Attempt to expand environment variables in the path
                wchar_t expanded[512]{};
                ExpandEnvironmentStringsW(ntuser_path_w.c_str(), expanded, 512);

                const std::wstring mount_w = to_wide(mount_key);
                LONG load_res = RegLoadKeyW(HKEY_USERS, mount_w.c_str(), expanded);
                if (load_res == ERROR_SUCCESS) {
                    // RAII: unload the mounted hive on EVERY exit, including a
                    // std::bad_alloc thrown by enumerate_uninstall_key. A leaked
                    // mount is system-wide, survives process death, and locks the
                    // user's NTUSER.DAT until reboot (gov Gate 6 sre / UP-1).
                    struct HiveUnloadGuard {
                        const std::wstring& mount;
                        ~HiveUnloadGuard() { RegUnLoadKeyW(HKEY_USERS, mount.c_str()); }
                    } unload_guard{mount_w};

                    std::string mounted_uninstall = mount_key + "\\" + kUninstallKey;
                    enumerate_uninstall_key(HKEY_USERS, mounted_uninstall.c_str(), 0, user_apps);
                }
            }

            for (const auto& app : user_apps) {
                ctx.write_output(sanitize_utf8(
                    std::format("user_app|{}|{}|{}|{}|{}", username,
                                app.name, app.version.empty() ? "-" : app.version,
                                app.publisher.empty() ? "-" : app.publisher,
                                app.install_date.empty() ? "-" : app.install_date)));
            }
        }
        RegCloseKey(profiles_key);
        return 0;

#elif defined(__linux__)
        // List packages installed per-user via dpkg or per-user snap/flatpak
        // For dpkg-based systems, packages are system-wide. Report them as system.
        auto apps = get_installed_apps_linux();
        for (const auto& app : apps) {
            ctx.write_output(sanitize_utf8(
                std::format("user_app|system|{}|{}|{}|{}", app.name,
                            app.version.empty() ? "-" : app.version,
                            app.publisher.empty() ? "-" : app.publisher,
                            app.install_date.empty() ? "-" : app.install_date)));
        }
        return 0;

#elif defined(__APPLE__)
        // On macOS, use brew list per user if Homebrew is installed
        // First list system apps
        auto apps = get_installed_apps_macos();
        for (const auto& app : apps) {
            ctx.write_output(sanitize_utf8(
                std::format("user_app|system|{}|{}|{}|{}", app.name,
                            app.version.empty() ? "-" : app.version,
                            app.publisher.empty() ? "-" : app.publisher,
                            app.install_date.empty() ? "-" : app.install_date)));
        }

        // Try Homebrew per-user (runs under current user)
        if (command_exists("brew")) {
            auto brew_out = run_command("brew list --versions 2>/dev/null");
            if (!brew_out.empty()) {
                std::istringstream ss(brew_out);
                std::string line;
                while (std::getline(ss, line)) {
                    auto sp = line.find(' ');
                    std::string name = (sp != std::string::npos) ? line.substr(0, sp) : line;
                    std::string version = (sp != std::string::npos) ? line.substr(sp + 1) : "-";
                    ctx.write_output(sanitize_utf8(
                        std::format("user_app|brew|{}|{}|-|-", name, version)));
                }
            }
        }
        return 0;
#else
        ctx.write_output("error|per-user app inventory not supported on this platform");
        return 1;
#endif
    }
};

YUZU_PLUGIN_EXPORT(InstalledAppsPlugin)
