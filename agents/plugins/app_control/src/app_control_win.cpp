/**
 * app_control_win.cpp -- Windows leg of the app_control plugin: effective WDAC
 * (Code Integrity) and AppLocker application-control posture, read-only.
 *
 *   wdac_policy      HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy (every 32-bit and
 *                    string value; VerifiedAndReputablePolicyState mapped) + presence of
 *                    %SystemRoot%\System32\CodeIntegrity\CiPolicies\Active\*.cip.
 *   applocker_policy wmi_bounded.hpp run_bounded_wmi_query against
 *                    root\StandardCimv2\Security\ApplicationControl / MSFT_ApplockerPolicy;
 *                    when the class is absent, empty or failing, a walk of
 *                    HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\<collection>
 *                    (EnforcementMode + rule-subkey count).
 *
 * This TU owns ONLY the Win32 I/O; every mapping, row format, namespace floor and error
 * classification is the pure app_control_parsers.hpp (registry types stop at RegValueView).
 *
 * RIG PROBE (rig session A, 2026-09-21, Windows 11 Pro 10.0.26200, x64; NT AUTHORITY\SYSTEM
 * scheduled task, RunLevel Highest) -- COMPLETE for what this host can show. Real captures:
 * tests/unit/fixtures/wave8/app_control/windows/ and docs/samples/windows.txt.
 *   AppLocker CIM: the namespace root\StandardCimv2\Security\ApplicationControl does NOT exist.
 *             A throwaway probe calling yuzu::shared::wmi::run_bounded_wmi_query (the same helper
 *             this TU uses) returned `error=wmi_connect_failed_0x8004100e rows=0`
 *             (WBEM_E_INVALID_NAMESPACE); PowerShell Get-CimClass says "Invalid namespace"
 *             (managed HRESULT 0x80131500); root\StandardCimv2 holds only MS_409, MS_809,
 *             embedded. So MSFT_ApplockerPolicy's property names (Collection / EnforcementMode /
 *             RuleCount, pinned by parse_cim_applocker_row) are STILL UNVERIFIED on hardware.
 *   SrpV2 walk: `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2 /s` -> "ERROR: The
 *             system was unable to find the specified registry key or value." (no AppLocker policy
 *             configured); the plugin reports `applocker|none|absent|0`, OK / FULL / registry_srpv2.
 *             The rule-collection layout was therefore never read on an AppLocker-configured host.
 *   CI\Policy values as SYSTEM: EmodePolicyRequired=0, SkuPolicyRequired=0,
 *             VerifiedAndReputablePolicyState=0 (maps `disabled`), SAC_PreviousState=0xffffffff
 *             (`unmodelled`); 8 default .cip policies in CodeIntegrity\CiPolicies\Active. Only
 *             VerifiedAndReputablePolicyState=0 has been observed; 1/2 are mapped per documentation
 *             and unverified on hardware.
 * The probe decided the branch on this host: CIM class absent -> SrpV2 registry walk. Both
 * branches are implemented and chosen at runtime; the CIM-present branch is untested on hardware.
 *
 * FAILURE SEMANTICS: every failed step records a token on ConstraintAccumulator and is
 * never rendered as absent. ERROR_ACCESS_DENIED -> PERMISSION_DENIED, anything else ->
 * CONSTRAINED/PARTIAL; exit code 0 only on OK. The only "absent" outputs are a genuine
 * ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND of a key or directory.
 */
#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <win_reg_handle.hpp> // yuzu::win::RegKey
#include <win_str.hpp>        // yuzu::win::to_wide / from_wide / reg_sz_to_utf8
#include <wmi_bounded.hpp>    // yuzu::shared::wmi::run_bounded_wmi_query

#include "app_control_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <constraint_accumulator.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

namespace yuzu::app_control {

int collect_wdac(yuzu::CommandContext& ctx);
int collect_applocker(yuzu::CommandContext& ctx);

namespace {

constexpr wchar_t kCiPolicyKey[] = L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy";
constexpr wchar_t kSrpV2Key[] = L"SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2";
constexpr wchar_t kCipActiveSubdir[] = L"\\System32\\CodeIntegrity\\CiPolicies\\Active";

constexpr DWORD kMaxValueBytes = 4096;      // per-value data cap (CI\Policy values are tiny)
constexpr DWORD kMaxValueNameChars = 16384; // registry's documented maximum value-name length
constexpr DWORD kMaxValues = 256;
constexpr std::size_t kMaxCipFiles = 64;

struct Outcome {
    yuzu::shared::ConstraintAccumulator acc;
    bool denied = false;

    void fail_rc(const char* what, LONG rc) {
        if (rc == ERROR_ACCESS_DENIED) {
            denied = true;
            acc.add_failure("permission_denied");
        } else {
            acc.add_failure(std::format("{}_{:#x}", what, static_cast<std::uint32_t>(rc)));
        }
    }
};

/// Emits the constrained row on any failure, sets the typed status; exit 0 only when OK.
int finish(yuzu::CommandContext& ctx, const Outcome& o, std::string_view source) {
    if (!o.acc.any_failure()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, source);
        return 0;
    }
    ctx.write_output(format_constrained_row(o.acc.reason()));
    ctx.set_result_status(o.denied ? YUZU_RESULT_STATUS_PERMISSION_DENIED
                                   : YUZU_RESULT_STATUS_CONSTRAINED,
                          YUZU_RESULT_COMPLETENESS_PARTIAL, o.acc.reason());
    return 1;
}

bool is_absent_rc(LONG rc) {
    return rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND;
}

/// One REG_DWORD: ERROR_SUCCESS, the query error, or ERROR_INVALID_DATA (wrong type/size).
LONG read_u32(HKEY key, const wchar_t* name, std::uint32_t& out) {
    DWORD type = 0, size = sizeof(DWORD), value = 0;
    const LONG rc = RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(&value), &size);
    if (rc == ERROR_SUCCESS && (type != REG_DWORD || size != sizeof(DWORD)))
        return ERROR_INVALID_DATA;
    out = static_cast<std::uint32_t>(value);
    return rc;
}

void read_ci_policy_values(yuzu::CommandContext& ctx, Outcome& o) {
    yuzu::win::RegKey key;
    const LONG open_rc =
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, kCiPolicyKey, 0, KEY_READ | KEY_WOW64_64KEY, key.put());
    if (is_absent_rc(open_rc)) {
        ctx.write_output(format_wdac_key_absent_row());
        return;
    }
    if (open_rc != ERROR_SUCCESS) {
        o.fail_rc("ci_policy_open", open_rc);
        return;
    }

    std::vector<wchar_t> name(kMaxValueNameChars);
    std::vector<wchar_t> data(kMaxValueBytes / sizeof(wchar_t)); // aligned for reg_sz_to_utf8
    for (DWORD index = 0;; ++index) {
        if (index >= kMaxValues) {
            o.acc.add_failure("row_cap");
            break;
        }
        DWORD name_len = static_cast<DWORD>(name.size());
        DWORD data_len = kMaxValueBytes;
        DWORD type = 0;
        const LONG rc = RegEnumValueW(key.get(), index, name.data(), &name_len, nullptr, &type,
                                      reinterpret_cast<BYTE*>(data.data()), &data_len);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (rc == ERROR_MORE_DATA) {
            o.acc.add_failure("value_too_large"); // skipped; enumeration continues
            continue;
        }
        if (rc != ERROR_SUCCESS) {
            o.fail_rc("ci_policy_enum", rc);
            break;
        }

        RegValueView v;
        v.name = yuzu::win::from_wide(name.data(), static_cast<int>(name_len));
        if (type == REG_DWORD && data_len == sizeof(DWORD)) {
            DWORD raw = 0;
            std::memcpy(&raw, data.data(), sizeof(raw));
            v.kind = RegValueKind::u32;
            v.u32 = static_cast<std::uint32_t>(raw);
        } else if (type == REG_SZ || type == REG_EXPAND_SZ) {
            v.kind = RegValueKind::text;
            v.text = yuzu::win::reg_sz_to_utf8(data.data(), data_len);
        } else {
            v.kind = RegValueKind::other;
            v.byte_len = data_len;
        }
        ctx.write_output(format_wdac_row(v));
    }
}

void list_active_cip_files(yuzu::CommandContext& ctx, Outcome& o) {
    wchar_t win_dir[MAX_PATH] = {};
    const UINT n = GetSystemWindowsDirectoryW(win_dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        o.acc.add_failure("system_directory_unresolved");
        return;
    }
    const std::filesystem::path dir = std::wstring{win_dir} + kCipActiveSubdir;

    std::error_code ec;
    std::vector<std::string> names;
    auto it = std::filesystem::directory_iterator(dir, ec);
    if (ec == std::errc::no_such_file_or_directory) {
        ctx.write_output(format_cip_none_row());
        return;
    }
    for (; !ec && it != std::filesystem::directory_iterator{}; it.increment(ec)) {
        std::error_code stat_ec;
        const bool regular = it->is_regular_file(stat_ec);
        if (stat_ec) {
            o.acc.add_failure("cip_stat_failed"); // a failed stat is not "not a .cip"
            continue;
        }
        if (!regular)
            continue;
        const auto u8 = it->path().filename().u8string();
        std::string fname{u8.begin(), u8.end()};
        if (!is_cip_filename(fname))
            continue;
        if (names.size() >= kMaxCipFiles) {
            o.acc.add_failure("row_cap");
            break;
        }
        names.push_back(std::move(fname));
    }
    if (ec) {
        if (ec == std::errc::permission_denied) {
            o.denied = true;
            o.acc.add_failure("permission_denied");
        } else {
            o.acc.add_failure(std::format("cip_dir_failed_{}", ec.value()));
        }
    }
    std::sort(names.begin(), names.end());
    if (names.empty() && !ec)
        ctx.write_output(format_cip_none_row());
    for (const auto& fname : names)
        ctx.write_output(format_cip_row(fname));
}

/// Caller-side namespace floor (wmi_bounded.hpp does NO allowlisting).
yuzu::shared::wmi::BoundedQueryResult bounded_cim_query(std::string_view ns, std::string_view wql) {
    if (!is_allowed_cim_namespace(ns)) {
        yuzu::shared::wmi::BoundedQueryResult refused;
        refused.error = "namespace_not_allowed";
        return refused;
    }
    // sink: app_control/bounded_cim_query#1 -- rung 1, in-process CIM query (no PowerShell).
    return yuzu::shared::wmi::run_bounded_wmi_query(yuzu::win::to_wide(ns), yuzu::win::to_wide(wql));
}

/// SrpV2 registry walk. Returns the number of collection rows written.
std::size_t walk_srpv2(yuzu::CommandContext& ctx, Outcome& o) {
    yuzu::win::RegKey root;
    const LONG root_rc =
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, kSrpV2Key, 0, KEY_READ | KEY_WOW64_64KEY, root.put());
    if (is_absent_rc(root_rc))
        return 0;
    if (root_rc != ERROR_SUCCESS) {
        o.fail_rc("srpv2_open", root_rc);
        return 0;
    }

    std::size_t written = 0;
    for (const auto collection : kApplockerCollections) {
        yuzu::win::RegKey sub;
        const LONG sub_rc = RegOpenKeyExW(root.get(), yuzu::win::to_wide(collection).c_str(), 0,
                                          KEY_READ | KEY_WOW64_64KEY, sub.put());
        if (is_absent_rc(sub_rc))
            continue; // collection not configured
        if (sub_rc != ERROR_SUCCESS) {
            o.fail_rc("srpv2_collection_open", sub_rc);
            continue;
        }

        std::optional<std::uint32_t> mode;
        std::uint32_t raw_mode = 0;
        const LONG mode_rc = read_u32(sub.get(), L"EnforcementMode", raw_mode);
        if (mode_rc == ERROR_SUCCESS)
            mode = raw_mode;
        else if (!is_absent_rc(mode_rc)) {
            o.fail_rc("enforcement_mode_read", mode_rc); // wrong type / denied: never rendered as absent
            continue;
        }

        DWORD rule_subkeys = 0;
        const LONG info_rc = RegQueryInfoKeyW(sub.get(), nullptr, nullptr, nullptr, &rule_subkeys,
                                              nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                                              nullptr);
        if (info_rc != ERROR_SUCCESS) {
            o.fail_rc("srpv2_rule_count", info_rc);
            continue;
        }
        ctx.write_output(format_applocker_row(collection, mode, rule_subkeys));
        ++written;
    }
    return written;
}

} // namespace

int collect_wdac(yuzu::CommandContext& ctx) {
    Outcome o;
    read_ci_policy_values(ctx, o);
    list_active_cip_files(ctx, o);
    return finish(ctx, o, "registry_ci_policy");
}

int collect_applocker(yuzu::CommandContext& ctx) {
    Outcome o;
    std::string_view source = "registry_srpv2";

    const auto q = bounded_cim_query(kCimNamespace, kCimApplockerWql);
    bool cim_rows_emitted = false;
    switch (classify_cim_error(q.error)) {
    case CimOutcome::ok:
        for (const auto& row : q.rows) {
            const auto parsed = parse_cim_applocker_row(row);
            if (!parsed) {
                o.acc.add_failure("cim_row_unrecognised");
                continue;
            }
            ctx.write_output(format_applocker_row(parsed->collection, parsed->mode, parsed->rules));
            cim_rows_emitted = true;
        }
        if (q.truncated)
            o.acc.add_failure("row_cap");
        source = "cim_msft_applockerpolicy";
        break;
    case CimOutcome::class_absent:
        break; // expected on hosts without the class: not a failure
    case CimOutcome::permission_denied:
        o.denied = true;
        o.acc.add_failure("permission_denied");
        break;
    case CimOutcome::failed:
        o.acc.add_failure(*q.error); // stable wmi_bounded.hpp token
        break;
    }

    // No usable CIM rows (class absent / empty / failed): registry walk; CIM failures stay on `o`.
    if (!cim_rows_emitted) {
        source = "registry_srpv2";
        if (walk_srpv2(ctx, o) == 0 && !o.acc.any_failure())
            ctx.write_output(format_applocker_none_row());
    }
    return finish(ctx, o, source);
}

} // namespace yuzu::app_control

#endif // _WIN32
