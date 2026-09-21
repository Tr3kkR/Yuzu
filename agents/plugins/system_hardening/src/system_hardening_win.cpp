/**
 * system_hardening_win.cpp -- Windows leg of the system_hardening `posture`
 * action; defines collect_posture_win() from system_hardening_legs.hpp. All
 * decode logic is in the pure system_hardening_win_parsers.hpp; this TU owns
 * only the Win32 reads (rung 1: no spawn, no WMI, no PowerShell):
 *   1. RegQueryValueExW on HKLM\SYSTEM\CurrentControlSet\Control\Session
 *      Manager\kernel : MitigationOptions, MitigationAuditOptions.
 *   2. GetProcessMitigationPolicy(GetCurrentProcess(), DEP/ASLR/CFG): the
 *      agent's OWN process only, as `self.*` rows.
 *
 * FAILURE SEMANTICS ("failure never reads as absent"), one token per cause:
 *   not found            -> `absent`,     <name>:not_found
 *   ERROR_ACCESS_DENIED  -> `unreadable`, <name>:access_denied, status
 *                           PERMISSION_DENIED
 *   other Win32 / wrong REG type / oversized / undecodable blob
 *                        -> `unreadable`, <name>:win32_<n> | type_<n> |
 *                           oversized | <decoder token>
 *   GetProcessMitigationPolicy ERROR_INVALID_PARAMETER/ERROR_NOT_SUPPORTED
 *                        -> `absent`,     <name>:unsupported
 * Tokens accumulate in ConstraintAccumulator; status is PERMISSION_DENIED,
 * else CONSTRAINED/PARTIAL when any token exists, else OK/FULL. A missing or
 * unreadable key never yields a non-zero exit: return 0 for every data-level
 * outcome, 1 only for an internal exception (constrained|internal_error).
 *
 * THE-RIG PROBE (rig session A, 2026-09-21, Windows 11 Pro 10.0.26200, x64) -- COMPLETE.
 * Run as NT AUTHORITY\SYSTEM (scheduled task, RunLevel Highest). Fixture + provenance:
 * tests/unit/fixtures/wave8/system_hardening/windows/mitigation_options.hex[.provenance.txt].
 *   whoami                  : nt authority\system
 *   date                    : 2026-09-21T15:29:55+01:00
 *   reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v MitigationOptions
 *                           : ERROR: The system was unable to find the specified registry key or value.
 *                             (ABSENT on this fresh install; MitigationAuditOptions likewise ABSENT)
 *   Get-ProcessMitigation -System, before: every policy NOTSET (DEP.Enable, SEHOP.Enable,
 *                             ASLR.BottomUp, ASLR.HighEntropy, CFG.Enable ... all NOTSET)
 *   After a TEMPORARY `Set-ProcessMitigation -System -Enable DEP,SEHOP,BottomUp,HighEntropy,CFG`
 *   (state then restored and verified identical: kernel + Memory Management keys, both values,
 *   bcdedit, Get-ProcessMitigation -System):
 *                             MitigationOptions REG_BINARY
 *                             110011000001000000000000000000000000000000000000 (24 bytes);
 *                             Get-ProcessMitigation -System: DEP.Enable ON, SEHOP.Enable ON,
 *                             ASLR.BottomUp ON, ASLR.HighEntropy ON, CFG.Enable ON.
 *   The five enabled options are exactly the set nibbles {0,1,4,5,10} of QWORD 0 -- this REFUTED
 *   the <winbase.h> flag layout the first decoder assumed (see system_hardening_win_parsers.hpp).
 *   GetProcessMitigationPolicy from a 64-bit SYSTEM process (throwaway MSVC probe, not committed):
 *                             ProcessDEPPolicy              BOOL=1 GetLastError=0 Flags=0x00000003
 *                             ProcessASLRPolicy             BOOL=1 GetLastError=0 Flags=0x00000005
 *                             ProcessControlFlowGuardPolicy BOOL=1 GetLastError=0 Flags=0x00000000
 *   => ProcessDEPPolicy SUCCEEDS on x64, so `self.dep` is a real row there; the
 *      ERROR_INVALID_PARAMETER/ERROR_NOT_SUPPORTED -> `absent` (`:unsupported`) branch below is
 *      kept for 32-bit hosts and older builds and was not exercised on this rig.
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

#include "system_hardening_legs.hpp"
#include "system_hardening_win_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <yuzu/plugin.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace yuzu::system_hardening {

namespace {

namespace mit = yuzu::system_hardening::mitigation;

constexpr wchar_t kKernelKey[] = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel";

/// One byte over the decoder's cap is enough to detect "oversized".
constexpr DWORD kReadCap = static_cast<DWORD>(mit::kMaxBlobBytes) + 1;

struct Probe {
    yuzu::shared::ConstraintAccumulator acc;
    bool denied{false};
};

std::string win32_token(std::string_view name, DWORD err) {
    if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
        return std::string{name} + ":not_found";
    if (err == ERROR_ACCESS_DENIED)
        return std::string{name} + ":access_denied";
    return std::string{name} + ":win32_" + std::to_string(err);
}

/// `absent` for not-found, `unreadable` otherwise; one token per cause.
void report_read_failure(yuzu::CommandContext& ctx, Probe& p, std::string_view row_name,
                         DWORD err) {
    const bool absent = (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND);
    if (err == ERROR_ACCESS_DENIED)
        p.denied = true;
    p.acc.add_failure(win32_token(row_name, err));
    p.acc.mark_incomplete();
    ctx.write_output(mit::format_posture_row(row_name, "-", absent ? "absent" : "unreadable"));
}

void report_unreadable(yuzu::CommandContext& ctx, Probe& p, std::string_view row_name,
                       const std::string& reason) {
    p.acc.add_failure(std::string{row_name} + ":" + reason);
    p.acc.mark_incomplete();
    ctx.write_output(mit::format_posture_row(row_name, "-", "unreadable"));
}

/// Reads + decodes one REG_BINARY value, emitting its rows or one absent/unreadable row.
void collect_blob(yuzu::CommandContext& ctx, Probe& p, HKEY kernel_key, const wchar_t* value_w,
                  std::string_view row_name, std::string_view row_prefix) {
    DWORD type = 0;
    DWORD size = kReadCap;
    std::vector<BYTE> buf(kReadCap);
    const LSTATUS rc = RegQueryValueExW(kernel_key, value_w, nullptr, &type, buf.data(), &size);
    if (rc == ERROR_MORE_DATA)
        return report_unreadable(ctx, p, row_name, "oversized");
    if (rc != ERROR_SUCCESS)
        return report_read_failure(ctx, p, row_name, static_cast<DWORD>(rc));
    if (type != REG_BINARY)
        return report_unreadable(ctx, p, row_name, "type_" + std::to_string(type));

    auto rows = mit::decode_mitigation_options(std::span<const uint8_t>{buf.data(), size},
                                               row_prefix);
    if (!rows)
        return report_unreadable(ctx, p, row_name, rows.error().token);
    for (const auto& r : *rows)
        ctx.write_output(mit::format_posture_row(r));
}

void collect_registry(yuzu::CommandContext& ctx, Probe& p) {
    yuzu::win::RegKey key;
    const LSTATUS orc =
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, kKernelKey, 0, KEY_READ | KEY_WOW64_64KEY, key.put());
    if (orc != ERROR_SUCCESS) {
        report_read_failure(ctx, p, "mitigation_options", static_cast<DWORD>(orc));
        report_read_failure(ctx, p, "mitigation_audit_options", static_cast<DWORD>(orc));
        return;
    }
    collect_blob(ctx, p, key.get(), L"MitigationOptions", "mitigation_options", "mitigation.");
    collect_blob(ctx, p, key.get(), L"MitigationAuditOptions", "mitigation_audit_options",
                 "mitigation_audit.");
}

/// One GetProcessMitigationPolicy call; the pure decoder consumes `Flags`.
template <class Policy>
void collect_self(yuzu::CommandContext& ctx, Probe& p, PROCESS_MITIGATION_POLICY which,
                  mit::SelfPolicy kind, std::string_view row_name) {
    Policy policy{};
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), which, &policy, sizeof(policy))) {
        const DWORD err = GetLastError();
        if (err == ERROR_INVALID_PARAMETER || err == ERROR_NOT_SUPPORTED) {
            p.acc.add_failure(std::string{row_name} + ":unsupported");
            p.acc.mark_incomplete();
            ctx.write_output(mit::format_posture_row(row_name, "-", "absent"));
            return;
        }
        return report_read_failure(ctx, p, row_name, err);
    }
    for (const auto& r : mit::decode_self_policy(kind, static_cast<uint32_t>(policy.Flags)))
        ctx.write_output(mit::format_posture_row(r));
}

} // namespace

int collect_posture_win(yuzu::CommandContext& ctx) {
    try {
        Probe p;
        collect_registry(ctx, p);
        collect_self<PROCESS_MITIGATION_DEP_POLICY>(ctx, p, ProcessDEPPolicy,
                                                    mit::SelfPolicy::dep, "self.dep");
        collect_self<PROCESS_MITIGATION_ASLR_POLICY>(ctx, p, ProcessASLRPolicy,
                                                     mit::SelfPolicy::aslr, "self.aslr");
        collect_self<PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY>(
            ctx, p, ProcessControlFlowGuardPolicy, mit::SelfPolicy::cfg, "self.cfg");

        if (p.denied)
            ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, p.acc.reason());
        else if (p.acc.any_failure())
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  p.acc.reason());
        else
            ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        return 0;
    } catch (...) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "internal_error");
        ctx.write_output("constrained|internal_error");
        return 1;
    }
}

} // namespace yuzu::system_hardening

#endif // _WIN32
