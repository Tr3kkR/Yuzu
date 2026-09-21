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
 *             configured); the plugin reports `applocker|none|absent|0`, OK / FULL /
 * registry_srpv2. The rule-collection layout was therefore never read on an AppLocker-configured
 * host. CI\Policy values as SYSTEM: EmodePolicyRequired=0, SkuPolicyRequired=0,
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

// The pure classifier (app_control_parsers.hpp) carries these as plain integers.
static_assert(kErrorSuccess == static_cast<std::uint32_t>(ERROR_SUCCESS));
static_assert(kErrorFileNotFound == static_cast<std::uint32_t>(ERROR_FILE_NOT_FOUND));
static_assert(kErrorPathNotFound == static_cast<std::uint32_t>(ERROR_PATH_NOT_FOUND));
static_assert(kErrorAccessDenied == static_cast<std::uint32_t>(ERROR_ACCESS_DENIED));

struct Outcome {
    yuzu::shared::ConstraintAccumulator acc;
    bool denied = false;

    /// Classifies one Win32 read result, records its failure token (an absence carries none) and
    /// returns the state; the decision is the pure classify_win32_read.
    RegRead note(std::string_view what, LONG rc, ReadKind kind) {
        const auto f = classify_win32_read(what, static_cast<std::uint32_t>(rc), kind);
        if (f.access_denied)
            denied = true;
        if (!f.token.empty())
            acc.add_failure(f.token);
        return f.state;
    }
};

/// Emits the constrained row on any failure, sets the typed status; exit 0 only when OK.
int finish(yuzu::CommandContext& ctx, const Outcome& o, std::string_view source) {
    const auto v = select_verdict(o.acc, o.denied, source);
    if (v.constrained_row_due)
        ctx.write_output(format_constrained_row(o.acc.reason()));
    ctx.set_result_status(v.status, v.completeness, v.provenance);
    return v.rc;
}

/// One REG_DWORD: ERROR_SUCCESS, the query error, or ERROR_INVALID_DATA (wrong type/size).
LONG read_u32(HKEY key, const wchar_t* name, std::uint32_t& out) {
    DWORD type = 0, size = sizeof(DWORD), value = 0;
    const LONG rc =
        RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(&value), &size);
    if (rc == ERROR_SUCCESS && (type != REG_DWORD || size != sizeof(DWORD)))
        return ERROR_INVALID_DATA;
    out = static_cast<std::uint32_t>(value);
    return rc;
}

void read_ci_policy_values(yuzu::CommandContext& ctx, Outcome& o) {
    yuzu::win::RegKey key;
    const LONG open_rc =
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, kCiPolicyKey, 0, KEY_READ | KEY_WOW64_64KEY, key.put());
    const auto open = o.note("ci_policy_open", open_rc, ReadKind::open_or_query);
    if (open == RegRead::absent) {
        ctx.write_output(format_wdac_key_absent_row());
        return;
    }
    if (open != RegRead::ok)
        return;

    std::vector<wchar_t> name(kMaxValueNameChars);
    std::vector<wchar_t> data(kMaxValueBytes / sizeof(wchar_t)); // aligned for reg_sz_to_utf8
    for (DWORD index = 0;; ++index) {
        DWORD name_len = static_cast<DWORD>(name.size());
        DWORD data_len = kMaxValueBytes;
        DWORD type = 0;
        const LONG rc = RegEnumValueW(key.get(), index, name.data(), &name_len, nullptr, &type,
                                      reinterpret_cast<BYTE*>(data.data()), &data_len);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (index >= kMaxValues && (rc == ERROR_SUCCESS || rc == ERROR_MORE_DATA)) {
            o.acc.add_failure("row_cap"); // a value exists beyond the cap: truncated
            break;
        }
        if (rc == ERROR_MORE_DATA) {
            o.acc.add_failure("value_too_large"); // skipped; enumeration continues
            continue;
        }
        if (o.note("ci_policy_enum", rc, ReadKind::enumerate) != RegRead::ok)
            break;

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

    // The shell owns only the filesystem calls; CipScan decides what each result means (and when
    // "no policy files" is a definitive absence rather than a failed read).
    std::error_code ec;
    CipScan scan{o.acc, o.denied};
    auto it = std::filesystem::directory_iterator(dir, ec);
    for (; !ec && it != std::filesystem::directory_iterator{}; it.increment(ec)) {
        std::error_code stat_ec;
        const bool regular = it->is_regular_file(stat_ec);
        const auto u8 = it->path().filename().u8string();
        const std::string leaf{u8.begin(), u8.end()};
        if (!scan.observe(leaf, regular, stat_ec))
            break;
    }
    scan.finish(ec);
    if (scan.none_row_due())
        ctx.write_output(format_cip_none_row());
    for (const auto& fname : scan.names())
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
    return yuzu::shared::wmi::run_bounded_wmi_query(yuzu::win::to_wide(ns),
                                                    yuzu::win::to_wide(wql));
}

/// SrpV2 registry walk. Returns the number of collection rows written.
std::size_t walk_srpv2(yuzu::CommandContext& ctx, Outcome& o) {
    yuzu::win::RegKey root;
    const LONG root_rc =
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, kSrpV2Key, 0, KEY_READ | KEY_WOW64_64KEY, root.put());
    if (o.note("srpv2_open", root_rc, ReadKind::open_or_query) != RegRead::ok)
        return 0;

    std::size_t written = 0;
    for (const auto collection : kApplockerCollections) {
        yuzu::win::RegKey sub;
        const LONG sub_rc = RegOpenKeyExW(root.get(), yuzu::win::to_wide(collection).c_str(), 0,
                                          KEY_READ | KEY_WOW64_64KEY, sub.put());
        const auto sub_read = o.note("srpv2_collection_open", sub_rc, ReadKind::open_or_query);
        if (sub_read == RegRead::absent) { // collection not configured: a definitive row
            ctx.write_output(format_applocker_row(collection, std::nullopt, 0));
            ++written;
            continue;
        }
        if (sub_read != RegRead::ok)
            continue; // unreadable: recorded, never absent

        std::optional<std::uint32_t> mode;
        std::uint32_t raw_mode = 0;
        const LONG mode_rc = read_u32(sub.get(), L"EnforcementMode", raw_mode);
        const auto mode_read = o.note("enforcement_mode_read", mode_rc, ReadKind::open_or_query);
        if (mode_read == RegRead::unreadable)
            continue; // wrong type / denied: never rendered as absent
        if (mode_read == RegRead::ok)
            mode = raw_mode; // absent leaves it nullopt

        DWORD rule_subkeys = 0;
        const LONG info_rc =
            RegQueryInfoKeyW(sub.get(), nullptr, nullptr, nullptr, &rule_subkeys, nullptr, nullptr,
                             nullptr, nullptr, nullptr, nullptr, nullptr);
        if (o.note("srpv2_rule_count", info_rc, ReadKind::enumerate) != RegRead::ok)
            continue;
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

    // The shell only performs the query; plan_cim decides what its result means.
    const auto q = bounded_cim_query(kCimNamespace, kCimApplockerWql);
    const auto plan = plan_cim(q.error, q.rows, q.truncated);
    for (const auto& r : plan.rows)
        ctx.write_output(format_applocker_row(r.collection, r.mode, r.rules));
    for (const auto& token : plan.failures)
        o.acc.add_failure(token);
    o.denied |= plan.denied;

    // No usable CIM rows (class absent / empty / failed): registry walk; CIM failures stay on `o`.
    const std::size_t srpv2_rows = plan.use_cim ? 0 : walk_srpv2(ctx, o);
    if (applocker_none_row_due(plan.use_cim, srpv2_rows, o.acc))
        ctx.write_output(format_applocker_none_row());
    return finish(ctx, o, plan.use_cim ? "cim_msft_applockerpolicy" : "registry_srpv2");
}

} // namespace yuzu::app_control

#endif // _WIN32
