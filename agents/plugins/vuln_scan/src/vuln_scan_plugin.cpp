/**
 * vuln_scan_plugin.cpp — Host vulnerability scanning plugin for Yuzu
 *
 * Actions:
 *   "scan"        — Full scan (CVE + configuration checks).
 *   "cve_scan"    — CVE-only: match installed software against known CVEs.
 *   "config_scan" — Configuration/compliance checks only.
 *   "summary"     — Quick severity counts from a full scan.
 *
 * Output is pipe-delimited via write_output():
 *   <severity>|cve|<CVE-ID>: <description>|<product> <installed_ver> (fixed in <fixed_ver>)
 *   <severity>|config|<title>|<detail>
 *   summary|<severity>|<count>
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <sstream>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include "binary_version.hpp"
#include "cis_checks.hpp"
#include "config_checks.hpp"
#include "cve_rules.hpp"
#include "kernel_detection.hpp"
#include "proc_exec.hpp"
#include "rules_integrity.hpp"

namespace {

// ── Plugin-scoped runtime state ────────────────────────────────────────────

std::string g_data_dir;
std::mutex g_dynamic_rules_mutex;
std::shared_ptr<std::vector<yuzu::vuln::CveRuleDynamic>> g_dynamic_rules;

// Underlying plugin context, cached at init() so command handlers (which only
// receive a CommandContext) can reach KV storage. The agent host guarantees the
// PluginContext outlives the plugin (plugin.hpp documents raw() as cache-safe).
YuzuPluginContext* g_plugin_ctx_raw = nullptr;

// SHA-256 verification of the staged rules file against its sidecar lives in
// rules_integrity.hpp (yuzu::vuln::verify_rules_sha256) so it is unit-testable.

// ── Subprocess helper (Linux / macOS) ──────────────────────────────────────

#if defined(__linux__) || defined(__APPLE__)
// Thin alias over the RAII helper (yuzu::vuln::capture_command, proc_exec.hpp)
// so the pipe/child are reclaimed even if output accumulation throws.
std::string run_command(const char* cmd) { return yuzu::vuln::capture_command(cmd); }

bool command_exists(const char* cmd) {
    auto check = std::string("command -v ") + cmd + " >/dev/null 2>&1";
    return system(check.c_str()) == 0;
}
#endif

// ── App record ────────────────────────────────────────────────────────────

struct AppInfo {
    std::string name;
    std::string version;
};

// Case-insensitive substring match
bool icontains(std::string_view haystack, std::string_view needle) {
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

// Replace invalid UTF-8 bytes with '?'
std::string sanitize_utf8(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            out += s[i];
            ++i;
        } else if ((c >> 5) == 0x06 && i + 1 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            i += 2;
        } else if ((c >> 4) == 0x0E && i + 2 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            i += 3;
        } else if ((c >> 3) == 0x1E && i + 3 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 3]) >> 6) == 0x02) {
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

// Escape pipe characters in output values
std::string escape_pipes(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '|')
            out += "\\|";
        else
            out += c;
    }
    return out;
}

// ── Get installed apps (same approach as installed_apps plugin) ────────────

#ifdef _WIN32
void enumerate_uninstall_key(HKEY root, const char* subkey, REGSAM extra_sam,
                             std::vector<AppInfo>& apps) {
    HKEY hkey{};
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | extra_sam, &hkey) !=
        ERROR_SUCCESS) {
        return;
    }

    char name_buf[256]{};
    DWORD idx = 0;
    DWORD name_len = sizeof(name_buf);

    while (RegEnumKeyExA(hkey, idx++, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr) ==
           ERROR_SUCCESS) {
        HKEY app_key{};
        if (RegOpenKeyExA(hkey, name_buf, 0, KEY_READ | extra_sam, &app_key) == ERROR_SUCCESS) {
            auto read_str = [&](const char* value_name) -> std::string {
                char buf[512]{};
                DWORD size = sizeof(buf);
                DWORD type = 0;
                if (RegQueryValueExA(app_key, value_name, nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS) {
                    if (type == REG_SZ && size > 0) {
                        return std::string(buf, size - 1);
                    }
                }
                return {};
            };

            auto display_name = read_str("DisplayName");
            if (!display_name.empty()) {
                auto sys_component = read_str("SystemComponent");
                if (sys_component != "1") {
                    auto version = read_str("DisplayVersion");
                    apps.push_back({std::move(display_name), std::move(version)});
                }
            }
            RegCloseKey(app_key);
        }
        name_len = sizeof(name_buf);
    }
    RegCloseKey(hkey);
}

std::vector<AppInfo> get_installed_apps() {
    std::vector<AppInfo> apps;
    static const char* kUninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kUninstallKey, KEY_WOW64_64KEY, apps);
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kUninstallKey, KEY_WOW64_32KEY, apps);
    enumerate_uninstall_key(HKEY_CURRENT_USER, kUninstallKey, 0, apps);

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
#elif defined(__linux__)
std::vector<AppInfo> get_installed_apps() {
    std::vector<AppInfo> apps;

    if (command_exists("dpkg-query")) {
        auto out = run_command("dpkg-query -W -f='${Package}|${Version}|${Status}\\n' 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.find("install ok installed") == std::string::npos)
                continue;
            std::istringstream ls(line);
            std::string name, version;
            std::getline(ls, name, '|');
            std::getline(ls, version, '|');
            apps.push_back({name, version});
        }
    } else if (command_exists("rpm")) {
        auto out =
            run_command("rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}\\n' 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            auto sep = line.find('|');
            if (sep != std::string::npos) {
                apps.push_back({line.substr(0, sep), line.substr(sep + 1)});
            }
        }
    } else if (command_exists("pacman")) {
        auto out = run_command("pacman -Q 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            auto sp = line.find(' ');
            if (sp != std::string::npos) {
                apps.push_back({line.substr(0, sp), line.substr(sp + 1)});
            }
        }
    } else if (command_exists("apk")) {
        // Alpine: `apk info -v` prints "<name>-<pkgver>-r<pkgrel>" per line.
        // pkgver/pkgrel never contain '-', so the last two '-'-delimited fields
        // are the version; everything before is the (possibly hyphenated) name.
        auto out = run_command("apk info -v 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
                line.pop_back();
            auto rel_sep = line.rfind('-');
            if (rel_sep == std::string::npos || rel_sep == 0)
                continue;
            auto ver_sep = line.rfind('-', rel_sep - 1);
            if (ver_sep == std::string::npos || ver_sep == 0)
                continue;
            apps.push_back({line.substr(0, ver_sep), line.substr(ver_sep + 1)});
        }
    }

    return apps;
}
#elif defined(__APPLE__)
std::vector<AppInfo> get_installed_apps() {
    std::vector<AppInfo> apps;

    auto out = run_command("system_profiler SPApplicationsDataType -detailLevel mini 2>/dev/null"
                           " | grep -E '^ {4}\\w|Version:'");
    if (!out.empty()) {
        std::istringstream ss(out);
        std::string line;
        std::string current_name;
        std::string current_version;
        while (std::getline(ss, line)) {
            auto start = line.find_first_not_of(" \t");
            if (start == std::string::npos)
                continue;
            line = line.substr(start);

            if (line.find("Version:") == 0) {
                current_version = line.substr(line.find(':') + 2);
            } else if (!line.empty() && line.back() == ':') {
                if (!current_name.empty()) {
                    apps.push_back({current_name, current_version});
                }
                current_name = line.substr(0, line.size() - 1);
                current_version.clear();
            }
        }
        if (!current_name.empty()) {
            apps.push_back({current_name, current_version});
        }
    }

    // Also check Homebrew packages
    if (command_exists("brew")) {
        auto brew_out = run_command("brew list --versions 2>/dev/null");
        std::istringstream ss(brew_out);
        std::string line;
        while (std::getline(ss, line)) {
            auto sp = line.find(' ');
            if (sp != std::string::npos) {
                apps.push_back({line.substr(0, sp), line.substr(sp + 1)});
            }
        }
    }

    return apps;
}
#else
std::vector<AppInfo> get_installed_apps() {
    return {};
}
#endif

// ── Enumeration / path helpers ─────────────────────────────────────────────

// Whether the host has any supported software-enumeration mechanism. When this
// is false, an empty installed-software list is an enumeration FAILURE, not a
// genuinely clean host — callers must not report "No vulnerabilities".
bool software_enumeration_available() {
#if defined(_WIN32) || defined(__APPLE__)
    return true;
#elif defined(__linux__)
    return command_exists("dpkg-query") || command_exists("rpm") ||
           command_exists("pacman") || command_exists("apk");
#else
    return false;
#endif
}

// Split a comma-separated list, trimming surrounding whitespace; drops empties.
std::vector<std::string> split_csv(std::string_view s) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= s.size()) {
        auto comma = s.find(',', start);
        auto tok = (comma == std::string_view::npos) ? s.substr(start)
                                                      : s.substr(start, comma - start);
        auto b = tok.find_first_not_of(" \t");
        auto e = tok.find_last_not_of(" \t");
        if (b != std::string_view::npos)
            out.emplace_back(tok.substr(b, e - b + 1));
        if (comma == std::string_view::npos)
            break;
        start = comma + 1;
    }
    return out;
}

// Final path component (trailing separators stripped).
std::string path_basename(std::string_view p) {
    while (p.size() > 1 && (p.back() == '/' || p.back() == '\\'))
        p.remove_suffix(1);
    auto pos = p.find_last_of("/\\");
    return std::string(pos == std::string_view::npos ? p : p.substr(pos + 1));
}

// Reject paths that are empty, oversized, contain control bytes, or don't exist.
// binary_scan paths are operator-supplied; they are only ever passed to file
// readers (PE/CoreFoundation) — never to a shell — but we still validate.
bool is_valid_scan_path(const std::string& p) {
    if (p.empty() || p.size() > 4096)
        return false;
    if (p.find('\0') != std::string::npos || p.find('\n') != std::string::npos ||
        p.find('\r') != std::string::npos)
        return false;
    std::error_code ec;
    return std::filesystem::exists(p, ec) && !ec;
}

// Read a file/bundle's embedded version. Windows reads PE VERSIONINFO; macOS
// reads the .app Info.plist. Other platforms have no file-embedded version.
std::string read_binary_file_version([[maybe_unused]] const std::string& path) {
#if defined(_WIN32)
    return yuzu::vuln::get_pe_file_version(path);
#elif defined(__APPLE__)
    return yuzu::vuln::get_bundle_version(path);
#else
    return {};
#endif
}

// ── Scan results ──────────────────────────────────────────────────────────

struct Finding {
    std::string severity;
    std::string category; // "cve" or "config"
    std::string title;
    std::string detail;
};

// ── CVE scan ──────────────────────────────────────────────────────────────

std::vector<Finding> do_cve_scan_impl() {
    std::vector<Finding> findings;
    auto apps = get_installed_apps();

    // Match one app against one rule; uses normalized comparison for
    // Debian epoch, RPM/Alpine release suffix, and semver pre-release.
    auto match_rule = [&](std::string_view product, std::string_view affected_below,
                          std::string_view severity, std::string_view cve_id,
                          std::string_view description, std::string_view fixed_in) {
        for (const auto& app : apps) {
            if (!icontains(app.name, product) || app.version.empty())
                continue;
            if (yuzu::vuln::compare_versions_normalized(app.version,
                                                        std::string(affected_below)) < 0) {
                findings.push_back(
                    {std::string(severity), "cve",
                     std::format("{}: {}", cve_id, description),
                     std::format("{} {} (fixed in {})", app.name, app.version, fixed_in)});
            }
        }
    };

    for (const auto& r : yuzu::vuln::kCveRules)
        match_rule(r.product, r.affected_below, r.severity, r.cve_id, r.description, r.fixed_in);

    // Safely copy dynamic rules ptr while holding lock
    auto dynamic = [&]() {
        std::lock_guard<std::mutex> lock(g_dynamic_rules_mutex);
        return g_dynamic_rules;
    }();
    if (dynamic) {
        for (const auto& r : *dynamic)
            match_rule(r.product, r.affected_below, r.severity, r.cve_id, r.description, r.fixed_in);
    }

    return findings;
}

// ── Kernel CVE scan ────────────────────────────────────────────────────────

std::vector<Finding> do_kernel_scan_impl() {
    std::vector<Finding> findings;
    auto ki = yuzu::vuln::get_kernel_info();
    if (ki.full_version.empty())
        return findings;

    // Kernel rules use product tokens "linux-kernel", "windows-kernel", or "macos".
    std::string product = ki.platform == "linux"   ? "linux-kernel" :
                          ki.platform == "windows" ? "windows-kernel" : "macos";

    auto match_rule = [&](std::string_view rule_product, std::string_view affected_below,
                          std::string_view severity, std::string_view cve_id,
                          std::string_view description, std::string_view fixed_in) {
        if (!icontains(product, rule_product))
            return;
        if (yuzu::vuln::compare_versions_normalized(ki.full_version,
                                                    std::string(affected_below)) < 0) {
            findings.push_back(
                {std::string(severity), "kernel",
                 std::format("{}: {}", cve_id, description),
                 std::format("{} {} (fixed in {})", product, ki.full_version, fixed_in)});
        }
    };

    for (const auto& r : yuzu::vuln::kCveRules)
        match_rule(r.product, r.affected_below, r.severity, r.cve_id, r.description, r.fixed_in);
    // Safely access dynamic rules
    auto dynamic_rules = [&]() {
        std::lock_guard<std::mutex> lock(g_dynamic_rules_mutex);
        return g_dynamic_rules;
    }();
    if (!dynamic_rules) dynamic_rules = std::make_shared<std::vector<yuzu::vuln::CveRuleDynamic>>();
    for (const auto& r : *dynamic_rules)
        match_rule(r.product, r.affected_below, r.severity, r.cve_id, r.description, r.fixed_in);

    return findings;
}

// ── Config scan (CIS Level 1 benchmarks) ──────────────────────────────────

std::vector<Finding> do_config_scan_impl() {
    std::vector<Finding> findings;
    auto checks = yuzu::vuln::run_all_cis_checks();

    for (const auto& c : checks) {
        findings.push_back(
            {c.status == "FAIL" ? c.severity : std::string("INFO"),
             "config",
             c.check_id + ": " + c.title,
             "status=" + c.status +
                 " expected=" + escape_pipes(c.expected) +
                 " actual="   + escape_pipes(c.actual)});
    }

    return findings;
}

// ── Output helpers ────────────────────────────────────────────────────────

void output_findings(yuzu::CommandContext& ctx, const std::vector<Finding>& findings) {
    if (findings.empty()) {
        ctx.write_output("INFO|scan|No vulnerabilities|No issues detected");
        return;
    }

    for (const auto& f : findings) {
        ctx.write_output(
            sanitize_utf8(std::format("{}|{}|{}|{}", f.severity, escape_pipes(f.category),
                                      escape_pipes(f.title), escape_pipes(f.detail))));
    }
}

void output_summary(yuzu::CommandContext& ctx, const std::vector<Finding>& findings) {
    std::map<std::string, int> counts;
    counts["CRITICAL"] = 0;
    counts["HIGH"] = 0;
    counts["MEDIUM"] = 0;
    counts["LOW"] = 0;
    counts["INFO"] = 0;

    for (const auto& f : findings) {
        counts[f.severity]++;
    }

    // Output total first
    int total = 0;
    int issues = 0;
    for (const auto& [sev, count] : counts) {
        total += count;
        if (sev != "INFO")
            issues += count;
    }

    ctx.write_output(std::format("summary|TOTAL|{} findings ({} issues)", total, issues));

    for (const auto& sev : {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}) {
        ctx.write_output(std::format("summary|{}|{}", sev, counts[sev]));
    }
}

} // namespace

class VulnScanPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "vuln_scan"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Host vulnerability scanning — CVE matching and configuration compliance checks";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"scan",        "cve_scan",   "config_scan",
                                     "summary",     "inventory",  "update_rules",
                                     "kernel_scan", "binary_scan", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        g_plugin_ctx_raw = ctx.raw();
        g_data_dir = std::string(ctx.get_config("agent.data_dir"));
        if (!g_data_dir.empty()) {
            auto rules_path = g_data_dir + "/staged/cve_rules.json";
            // Verify the staged file's SHA-256 against its sidecar before loading
            // (detects corruption/truncation; see rules_integrity.hpp threat model).
            if (!yuzu::vuln::verify_rules_sha256(rules_path))
                return {};  // Non-fatal: compiled-in rules remain active
            std::vector<yuzu::vuln::CveRuleDynamic> loaded;
            auto err = yuzu::vuln::load_rules_from_json(rules_path, loaded);
            if (err.empty()) {
                std::lock_guard<std::mutex> lock(g_dynamic_rules_mutex);
                g_dynamic_rules = std::make_shared<std::vector<yuzu::vuln::CveRuleDynamic>>(std::move(loaded));
                ctx.storage_set("rules.last_loaded", rules_path);
            }
            // Non-fatal: compiled-in rules remain active if file not present
        }
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                [[maybe_unused]] yuzu::Params params) override {

        if (action == "scan") {
            ctx.report_progress(0);
            // Integrity: if software enumeration is unavailable, the CVE portion
            // cannot run — say so explicitly rather than implying a clean host.
            // Configuration (CIS) checks are independent and still run.
            const bool enum_ok = software_enumeration_available();
            if (!enum_ok)
                ctx.write_output("ERROR|scan|Degraded coverage|software enumeration "
                                 "unavailable — CVE results incomplete; configuration "
                                 "checks still ran");
            auto cve_findings = enum_ok ? do_cve_scan_impl() : std::vector<Finding>{};
            ctx.report_progress(50);
            auto config_findings = do_config_scan_impl();
            ctx.report_progress(90);

            std::vector<Finding> all;
            all.reserve(cve_findings.size() + config_findings.size());
            all.insert(all.end(), cve_findings.begin(), cve_findings.end());
            all.insert(all.end(), config_findings.begin(), config_findings.end());

            // Suppress the misleading "No vulnerabilities" line when coverage was
            // degraded and nothing was found — the ERROR line above stands alone.
            if (!all.empty() || enum_ok)
                output_findings(ctx, all);
            ctx.report_progress(100);
            return 0;
        }

        if (action == "cve_scan") {
            ctx.report_progress(0);
            if (!software_enumeration_available()) {
                ctx.write_output("ERROR|cve_scan|Enumeration unavailable|no supported "
                                 "package manager found; cannot enumerate installed software");
                return 1;
            }
            auto findings = do_cve_scan_impl();
            output_findings(ctx, findings);
            ctx.report_progress(100);
            return 0;
        }

        if (action == "config_scan") {
            ctx.report_progress(0);
            auto findings = do_config_scan_impl();
            output_findings(ctx, findings);
            ctx.report_progress(100);
            return 0;
        }

        if (action == "inventory") {
            // Return raw software inventory for server-side NVD matching.
            // Format: name|version (one per line, pipe-delimited)
            if (!software_enumeration_available()) {
                ctx.write_output("ERROR|inventory|Enumeration unavailable|no supported "
                                 "package manager found; cannot enumerate installed software");
                return 1;
            }
            auto apps = get_installed_apps();
            for (const auto& app : apps) {
                ctx.write_output(std::format("{}|{}", escape_pipes(sanitize_utf8(app.name)),
                                             escape_pipes(sanitize_utf8(app.version))));
            }
            return 0;
        }

        if (action == "summary") {
            // CVE counts depend on software enumeration; flag degraded coverage
            // rather than silently under-reporting. CIS checks run regardless.
            const bool enum_ok = software_enumeration_available();
            if (!enum_ok)
                ctx.write_output("ERROR|summary|Degraded coverage|software enumeration "
                                 "unavailable — CVE counts incomplete");
            auto cve_findings = enum_ok ? do_cve_scan_impl() : std::vector<Finding>{};
            auto config_findings = do_config_scan_impl();

            std::vector<Finding> all;
            all.reserve(cve_findings.size() + config_findings.size());
            all.insert(all.end(), cve_findings.begin(), cve_findings.end());
            all.insert(all.end(), config_findings.begin(), config_findings.end());

            output_summary(ctx, all);
            return 0;
        }

        if (action == "update_rules") {
            if (g_data_dir.empty()) {
                ctx.write_output("ERROR|update_rules|Unavailable|agent data_dir is not configured");
                return 1;
            }
            auto rules_path = g_data_dir + "/staged/cve_rules.json";
            // Verify the staged file's SHA-256 against its sidecar before loading.
            if (!yuzu::vuln::verify_rules_sha256(rules_path)) {
                ctx.write_output("ERROR|update_rules|Verification failed|SHA-256 mismatch, corrupt file, or missing .sha256 sidecar");
                return 1;
            }
            std::vector<yuzu::vuln::CveRuleDynamic> loaded;
            auto err = yuzu::vuln::load_rules_from_json(rules_path, loaded);
            if (!err.empty()) {
                // Fail safe: keep the previously-active ruleset on load error.
                ctx.write_output("ERROR|update_rules|Load failed|" + escape_pipes(err));
                return 1;
            }
            size_t count = loaded.size();
            {
                std::lock_guard<std::mutex> lock(g_dynamic_rules_mutex);
                g_dynamic_rules = std::make_shared<std::vector<yuzu::vuln::CveRuleDynamic>>(std::move(loaded));
            }
            // KV write goes through the cached PluginContext — CommandContext has
            // no storage access.
            if (g_plugin_ctx_raw)
                yuzu::PluginContext(g_plugin_ctx_raw).storage_set("rules.last_loaded", rules_path);
            ctx.write_output("INFO|update_rules|Rules loaded|" + std::to_string(count) + " rules active");
            return 0;
        }

        if (action == "kernel_scan") {
            ctx.report_progress(0);
            auto findings = do_kernel_scan_impl();
            output_findings(ctx, findings);
            ctx.report_progress(100);
            return 0;
        }

        if (action == "binary_scan") {
            // File-level version scan.
            //
            // With a 'paths' parameter (comma-separated): read the version
            // directly from each binary/bundle — Windows reads the PE
            // VERSIONINFO resource, macOS reads the .app Info.plist
            // (CFBundleShortVersionString) — and match it against the CVE
            // rules. Linux ELF binaries carry no embedded version, so file
            // paths are not supported there.
            //
            // Without 'paths' (and always on Linux): fall back to the
            // package-manager inventory, stripping the Debian epoch before
            // comparison (e.g. "2:1.0.1f" → "1.0.1f").
            auto paths_param = std::string(params.get("paths", ""));
            std::vector<Finding> findings;

            // Match a (product, version) pair against compiled-in + dynamic rules.
            auto match_against_rules = [&](std::string_view product_name,
                                          const std::string& version,
                                          std::string_view source) {
                auto match_rule = [&](std::string_view product, std::string_view affected_below,
                                      std::string_view severity, std::string_view cve_id,
                                      std::string_view description, std::string_view fixed_in) {
                    if (!icontains(product_name, product))
                        return;
                    if (yuzu::vuln::compare_versions_normalized(
                            version, std::string(affected_below)) < 0) {
                        findings.push_back(
                            {std::string(severity), "binary",
                             std::format("{}: {}", cve_id, description),
                             std::format("{} {} (fixed in {})", source, version, fixed_in)});
                    }
                };
                for (const auto& r : yuzu::vuln::kCveRules)
                    match_rule(r.product, r.affected_below, r.severity, r.cve_id, r.description,
                               r.fixed_in);
                auto dynamic_rules = [&]() {
                    std::lock_guard<std::mutex> lock(g_dynamic_rules_mutex);
                    return g_dynamic_rules;
                }();
                if (dynamic_rules)
                    for (const auto& r : *dynamic_rules)
                        match_rule(r.product, r.affected_below, r.severity, r.cve_id,
                                   r.description, r.fixed_in);
            };

#if defined(_WIN32) || defined(__APPLE__)
            auto paths = split_csv(paths_param);
            if (!paths.empty()) {
                constexpr size_t kMaxPaths = 256;
                size_t scanned = 0;
                size_t considered = 0;
                for (const auto& p : paths) {
                    if (considered >= kMaxPaths)
                        break;
                    ++considered;
                    if (!is_valid_scan_path(p))
                        continue;
                    auto ver = read_binary_file_version(p);
                    if (ver.empty())
                        continue;
                    ++scanned;
                    match_against_rules(path_basename(p), ver, p);
                }
                // Integrity: an all-skip run must not read as a clean host.
                if (scanned == 0) {
                    ctx.write_output(std::format(
                        "ERROR|binary_scan|No readable binaries|0 of {} path(s) yielded a "
                        "version (missing, unreadable, or no embedded version)",
                        paths.size()));
                    return 1;
                }
                output_findings(ctx, findings);
                return 0;
            }
#endif

            // Fallback: package-manager inventory (also the only mode on Linux).
            if (!software_enumeration_available()) {
                ctx.write_output("ERROR|binary_scan|Enumeration unavailable|no supported "
                                 "package manager and no readable 'paths' supplied");
                return 1;
            }
            auto apps = get_installed_apps();
            for (const auto& app : apps) {
                if (app.version.empty())
                    continue;
                auto clean_ver = yuzu::vuln::strip_linux_pkg_epoch(app.version);
                match_against_rules(app.name, clean_ver, app.name);
            }
            output_findings(ctx, findings);
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(VulnScanPlugin)
