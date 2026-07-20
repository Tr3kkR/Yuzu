/**
 * installed_apps_plugin.cpp — Installed applications plugin for Yuzu
 *
 * Actions:
 *   "list"  — Lists all installed applications.
 *   "query" — Searches for a specific app by name (partial match).
 *             Params: name (required).
 *   "list_inventory" — machine-scope software inventory for the daily sync
 *             (blob contract v2, ADR-0016). Emits the extended 12-field rows;
 *             fields an ecosystem does not store are EMPTY, never synthesised
 *             (no "-" placeholders, no sentinel row on an empty result).
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   app|name|version|publisher|install_date|signature_status|bundle_id  (list)
 *   app|name|version|publisher                                         (query)
 *   inv|name|version|publisher|install_date|kind|ecosystem|epoch|release|arch|
 *       signature_status|distro_id|distro_version                 (list_inventory)
 *
 * `list`'s trailing signature_status/bundle_id are real values on macOS
 * (codesign/plutil enrichment) and "-|-" placeholders elsewhere -- every
 * platform emits the same declared 6-column shape, including the empty/
 * no-results sentinel row, so a consumer never has to branch on OS.
 *
 * `list`/`query`/`list_per_user` output is a stable operator-facing contract
 * (content/definitions/installed_apps.yaml et al.) — extend `list_inventory`,
 * never those.
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <format>
#include <optional>
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

#ifdef __APPLE__
// system_profiler -json parse + row-assembly for the operator `list`
// action's macOS publisher/signature_status/bundle_id enrichment
// (#2273/1.10). In a header so the unit test exercises the same parse/
// format code the plugin runs (pattern: #1662, filesystem_macos_sig.hpp).
#include "installed_apps_macos_enrich.hpp"

#include <yuzu/agent/subprocess_runner.hpp>
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
    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
    pclose(pipe);
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

#ifdef __APPLE__
std::vector<AppInfo> get_installed_apps_macos() {
    std::vector<AppInfo> apps;

    // GUI applications from system_profiler
    auto out = run_command("system_profiler SPApplicationsDataType -detailLevel mini 2>/dev/null"
                           " | grep -E '^ {4}\\w|Version:|Last Modified:' ");
    if (!out.empty()) {
        std::istringstream ss(out);
        std::string line;
        std::string current_name;
        std::string current_version;
        std::string current_date;
        while (std::getline(ss, line)) {
            // Trim leading whitespace
            auto start = line.find_first_not_of(" \t");
            if (start == std::string::npos)
                continue;
            line = line.substr(start);

            if (line.find("Version:") == 0) {
                current_version = line.substr(line.find(':') + 2);
            } else if (line.find("Last Modified:") == 0) {
                current_date = line.substr(line.find(':') + 2);
            } else if (!line.empty() && line.back() == ':') {
                // Emit previous app
                if (!current_name.empty()) {
                    apps.push_back({current_name, current_version, "-", current_date});
                }
                current_name = line.substr(0, line.size() - 1);
                current_version.clear();
                current_date.clear();
            }
        }
        if (!current_name.empty()) {
            apps.push_back({current_name, current_version, "-", current_date});
        }
    }

    std::sort(apps.begin(), apps.end(),
              [](const AppInfo& a, const AppInfo& b) { return a.name < b.name; });
    return apps;
}
#endif

// ── list_inventory collectors (blob contract v2) ──────────────────────────

namespace inv = yuzu::installed_apps::inventory;

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
std::vector<inv::InvRecord> get_inventory_macos() {
    std::vector<inv::InvRecord> recs;
    for (auto& app : get_installed_apps_macos()) {
        inv::InvRecord r;
        r.name = std::move(app.name);
        r.version = std::move(app.version);
        // system_profiler mini exposes no publisher; the legacy collector
        // stores a "-" placeholder which must NOT leak into v2 rows.
        if (app.publisher != "-")
            r.publisher = std::move(app.publisher);
        r.install_date = std::move(app.install_date); // Last Modified
        r.kind = "app";
        r.ecosystem = "macos";
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

// ── macOS: operator `list` enrichment (A-1.10) ─────────────────────────────
//
// A SEPARATE collector from get_installed_apps_macos() above (PLAN-04): that
// one also feeds the daily-sync blob (get_inventory_macos) and the per-user
// query (do_list_per_user), neither of which should pay codesign/plutil
// subprocess cost for values they would only discard. This collector talks
// to `system_profiler -json` specifically because it -- unlike the
// `-detailLevel mini` text get_installed_apps_macos() scrapes -- carries
// each app's real bundle path (PLAN-05), which codesign/plutil need. Wired
// ONLY into do_list()'s macOS branch below; do_query() keeps calling
// get_installed_apps_macos() unchanged (byte-identical `query` output).
#ifdef __APPLE__

namespace mac_enrich = yuzu::installed_apps::macos_enrich;

// Bounds for the WHOLE listing (PLAN-04), not just each subprocess call:
// codesign can hang on a network volume, and a fleet endpoint can have
// hundreds of apps, so the per-call deadline alone would not stop a single
// `list` invocation from running for minutes. Once either bound is spent,
// remaining apps are still emitted -- just un-enriched, never dropped.
constexpr std::size_t kMaxEnrichedApps = 500;
constexpr std::chrono::seconds kEnrichmentBudget{60};
constexpr std::chrono::milliseconds kEnrichSubprocessDeadline{10000};
constexpr std::chrono::milliseconds kListingSubprocessDeadline{20000};

int do_list_macos(yuzu::CommandContext& ctx) {
    auto sp_result = yuzu::agent::run_bounded_subprocess(
        {"system_profiler", "-json", "SPApplicationsDataType"},
        yuzu::agent::SubprocessOptions{.deadline = kListingSubprocessDeadline});

    // Honest empty on any failure shape (missing tool, timeout, non-zero
    // exit) -- matches the "No applications found" convention below for a
    // genuinely empty result, rather than trying to interpret output
    // system_profiler itself didn't stand behind.
    auto apps = (sp_result.tool_ran && !sp_result.timed_out && sp_result.exit_code == 0)
                    ? mac_enrich::parse_system_profiler_apps_json(sp_result.output)
                    : std::vector<mac_enrich::MacAppRecord>{};

    // A capture that hit run_bounded_subprocess's internal size cap is an
    // honest partial, not a complete listing -- a >1MB system_profiler JSON
    // truncates mid-object, fails to parse, and would otherwise degrade
    // silently into the "No applications found" rc 0 case below, reporting
    // a false empty success. Report the truncation itself instead, with
    // nonzero rc, before that check ever runs. (Decision lives in
    // truncated_listing_outcome so a fixture test can exercise it directly.)
    if (auto truncated = mac_enrich::truncated_listing_outcome(sp_result)) {
        ctx.write_output(truncated->first);
        return truncated->second;
    }

    if (apps.empty()) {
        mac_enrich::MacAppRecord none;
        none.name = "No applications found";
        ctx.write_output(mac_enrich::format_operator_list_row(none, std::nullopt, std::nullopt));
        return 0;
    }

    const auto budget_deadline = std::chrono::steady_clock::now() + kEnrichmentBudget;
    std::size_t enriched_count = 0;

    for (const auto& app : apps) {
        const auto now = std::chrono::steady_clock::now();
        const bool attempt_enrich =
            !app.path.empty() && enriched_count < kMaxEnrichedApps && now < budget_deadline;

        std::optional<yuzu::agent::SubprocessResult> codesign_result;
        std::optional<yuzu::agent::SubprocessResult> plutil_result;
        if (attempt_enrich) {
            ++enriched_count;

            // Bound each call to whichever is smaller: its own per-call
            // deadline, or however much of the WHOLE-listing budget is left
            // -- so a listing near its 60s budget can't still hand codesign
            // (or plutil) a full fresh 10s on the last few apps and blow
            // past the budget by more than one bounded call.
            const auto codesign_deadline = std::min(
                kEnrichSubprocessDeadline,
                std::chrono::duration_cast<std::chrono::milliseconds>(budget_deadline - now));

            // merge_stderr=true: classify_codesign_result reads codesign's
            // diagnostic text, which codesign writes to stderr. plutil's
            // success path is stdout-only (`-o -`) and its failure path
            // reads only the exit code, so merging is harmless there --
            // done anyway so a plutil failure's diagnostic is at least
            // captured on the SubprocessResult for a future caller to log.
            codesign_result = yuzu::agent::run_bounded_subprocess(
                {"codesign", "--verify", "--deep", "--strict", app.path},
                yuzu::agent::SubprocessOptions{.deadline = codesign_deadline,
                                                .merge_stderr = true});

            // Re-check the budget after codesign (which can itself run up
            // to codesign_deadline) before spending anything on plutil; if
            // nothing is left, plutil_result stays nullopt -- an honest
            // "never attempted" (PLAN-02 short-circuit), never a fabricated
            // verdict.
            const auto after_codesign = std::chrono::steady_clock::now();
            if (after_codesign < budget_deadline) {
                const auto plutil_deadline =
                    std::min(kEnrichSubprocessDeadline,
                             std::chrono::duration_cast<std::chrono::milliseconds>(
                                 budget_deadline - after_codesign));
                plutil_result = yuzu::agent::run_bounded_subprocess(
                    {"plutil", "-extract", "CFBundleIdentifier", "raw", "-o", "-",
                     app.path + "/Contents/Info.plist"},
                    yuzu::agent::SubprocessOptions{.deadline = plutil_deadline,
                                                    .merge_stderr = true});
            }
        }

        ctx.write_output(sanitize_utf8(
            mac_enrich::format_operator_list_row(app, codesign_result, plutil_result)));
    }
    return 0;
}

#endif // __APPLE__

// ── list action ───────────────────────────────────────────────────────────

int do_list(yuzu::CommandContext& ctx) {
#ifdef __APPLE__
    return do_list_macos(ctx);
#else
#ifdef _WIN32
    auto apps = get_installed_apps_windows();
#elif defined(__linux__)
    auto apps = get_installed_apps_linux();
#else
    std::vector<AppInfo> apps;
#endif

    // Trailing "-|-": the macOS path's signature_status/bundle_id columns
    // (PLAN-03) don't exist here -- Windows/Linux have no codesign/plutil
    // equivalent wired up -- but every platform must emit the same
    // declared 6-column shape so a consumer parsing this row doesn't have
    // to branch on OS. That includes the empty/sentinel row below: it must
    // not degrade to a shorter row shape just because there's no app data
    // to append it to.
    if (apps.empty()) {
        ctx.write_output("app|No applications found|-|-|-|-|-");
        return 0;
    }

    for (const auto& app : apps) {
        ctx.write_output(sanitize_utf8(
            std::format("app|{}|{}|{}|{}|-|-", app.name, app.version.empty() ? "-" : app.version,
                        app.publisher.empty() ? "-" : app.publisher,
                        app.install_date.empty() ? "-" : app.install_date)));
    }
    return 0;
#endif
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
