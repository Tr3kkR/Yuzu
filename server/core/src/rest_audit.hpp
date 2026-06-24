#pragma once

/// @file rest_audit.hpp
///
/// Shared "emit a behavioural-data access audit, surface a persist failure"
/// helper for the per-device / per-signal PII routes (`dex.device.view`,
/// `guardian.device.view`, `dex.signal.view`) across the REST API, the
/// dashboard fragments, and the MCP tool surface.
///
/// Factored out of the per-site copies that drifted (#1647): the original
/// fix-up of these routes happened endpoint-by-endpoint, so each surface grew
/// its own slightly-different snippet — some discarded the `AuditFn` bool
/// entirely, some set the header but lacked a `try/catch`, some failed closed
/// and some proceeded. Every behavioural-data route now routes through ONE
/// kernel here so the catch-arm log, the `Sec-Audit-Failed` header, and the
/// persist-bool contract can never diverge between surfaces again.
///
/// SOC 2 CC7.2 (audit-anomaly monitoring) + CC6.1 (access-event capture):
/// a per-person behavioural read whose audit row silently fails to persist —
/// the audit DB is locked/full, or a `bad_alloc`-class allocation throws —
/// must never look like a clean, audited read to the consumer. That is the
/// originating threat (#1623 review HIGH): a CMDB / ServiceNow integration
/// reading audited-evidence data with no `guardian.device.view` row AND no
/// out-of-band signal.
///
/// `try_persist_audit` is the channel-agnostic kernel; the per-channel
/// failure signal is layered on top:
///   * HTTP routes wrap it with `emit_behavioral_audit`, which sets the
///     `Sec-Audit-Failed: true` response header on failure. The caller then
///     picks its posture from the returned bool — HTML dashboard fragments
///     PROCEED and render (a transient audit hiccup must not blank the
///     operator's lens; the header carries the signal), REST JSON
///     integrations FAIL CLOSED (503) so a downstream CMDB never records
///     evidence-less PII as audited.
///   * MCP wraps the kernel itself (JSON-RPC has no response-header channel)
///     and surfaces the gap through its own body field.
///
/// A null / empty `audit_fn` means the deployment runs audit-off; that is NOT
/// a persistence failure, so the kernel returns `true` and sets no header —
/// the established `AuditFn` contract (callers that fail closed must keep
/// serving when audit is simply disabled).

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <string>

namespace yuzu::server::detail {

/// Channel-agnostic kernel: call the access-audit hook, capturing the persist
/// result behind a `try/catch`. The realistic false-return path is already
/// logged + metric-bumped inside `AuditStore::log` (it bumps
/// `yuzu_server_audit_emit_failed_total`); the throw arm (`bad_alloc`-class)
/// is otherwise SILENT, so we log it here — the catch-arm log #1647 asked for.
/// Returns the persist outcome (true == durably audited OR audit-off).
///
/// `AuditFn` is templated so either `RestApiV1::AuditFn`, `DexRoutes::AuditFn`,
/// or `mcp::McpServer::AuditFn` (all `std::function<bool(req, action, result,
/// target_type, target_id, detail)>`) binds without this header depending on
/// any one route class.
template <class AuditFn>
inline bool try_persist_audit(const AuditFn& audit_fn, const httplib::Request& req,
                              const std::string& action, const std::string& result,
                              const std::string& target_type, const std::string& target_id,
                              const std::string& detail) {
    if (!audit_fn)
        return true; // audit-off deployment — not a persist failure; serve.
    try {
        return audit_fn(req, action, result, target_type, target_id, detail);
    } catch (const std::exception& e) {
        spdlog::warn("audit_fn threw on behavioural-data route action={} target={}: {}", action,
                     target_id, e.what());
    } catch (...) {
        spdlog::warn("audit_fn threw (non-std exception) on behavioural-data route action={} "
                     "target={}",
                     action, target_id);
    }
    return false;
}

/// HTTP wrapper: `try_persist_audit` + set the `Sec-Audit-Failed: true`
/// response header on failure. Returns the persist outcome so the caller picks
/// its posture (HTML fragments PROCEED and render; REST JSON FAIL CLOSED 503).
template <class AuditFn>
inline bool emit_behavioral_audit(const AuditFn& audit_fn, const httplib::Request& req,
                                  httplib::Response& res, const std::string& action,
                                  const std::string& result, const std::string& target_type,
                                  const std::string& target_id, const std::string& detail) {
    const bool persisted =
        try_persist_audit(audit_fn, req, action, result, target_type, target_id, detail);
    if (!persisted)
        res.set_header("Sec-Audit-Failed", "true");
    return persisted;
}

} // namespace yuzu::server::detail
