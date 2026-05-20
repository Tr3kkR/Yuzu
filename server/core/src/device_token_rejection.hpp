#pragma once

/// @file device_token_rejection.hpp
/// Wire-boundary collapse + audit/metric expansion contract for
/// `DeviceTokenStore::validate_token` rejections (#1052 + #1053, W1.3).
///
/// **The hard rule.** Every caller that maps a `RejectedToken` to an
/// HTTP/gRPC response MUST go through `make_public_rejection()` (HTTP) or
/// `make_grpc_rejection_status()` (gRPC) and MUST NOT vary the wire shape
/// by variant. The typed `DeviceTokenValidateError` is visible ONLY in
/// operator-facing surfaces: audit rows (`rejection_audit_detail_for_storage()`
/// / `rejection_event_action()`) and Prometheus counters
/// (`rejection_metric_name()`).
///
/// **Why collapse?** Without this, an attacker holding a stolen valid
/// token could discriminate `binding_mismatch` from `not_found` /
/// `revoked` / `expired` / `unbound_legacy` by the wire response,
/// learning (a) the hash still exists, (b) it's not revoked, (c) it's
/// not expired, (d) it's bound to a different device. That's enough
/// intel for social engineering or lateral-movement targeting. SOC 2
/// CC6.1 + the auth-architecture standing invariant "every credential
/// rejection looks identical on the wire."
///
/// **Why audit AND metric the variant?** The same rule that hides the
/// variant from the attacker requires it to surface to the operator —
/// SOC 2 CC7.2/CC7.3 require attributable credential-rejection logs.
/// The audit row carries the typed variant + the bound-device context
/// (#1053); the Prometheus counters let the operator alert on a sudden
/// spike of `binding_mismatch` (an in-progress credential-theft attack)
/// without scanning audit logs.

#include "device_token_store.hpp"

#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>

#include <string>
#include <string_view>

namespace yuzu::server {

/// Public wire response for ALL rejection variants. Identical fields
/// across every variant — operator-visible variance lives in audit/metrics.
///
/// Status mapping:
///   * HTTP: `http_status` (always 401)
///   * gRPC: `grpc_status` (always UNAUTHENTICATED)
///
/// Body JSON shape (HTTP):
///   `{"error":{"code":"invalid_credentials","message":"invalid credentials"},
///     "meta":{"api_version":"v1"}}`
struct PublicRejection {
    int http_status{401};
    grpc::StatusCode grpc_status{grpc::StatusCode::UNAUTHENTICATED};
    std::string envelope_json;
    std::string short_message{"invalid credentials"};
};

inline constexpr std::string_view kDeviceTokenRejectionPublicCode = "invalid_credentials";
inline constexpr std::string_view kDeviceTokenRejectionPublicMessage = "invalid credentials";

/// Build the public-facing rejection envelope. Single function so a
/// reviewer can verify identical wire shape at one site rather than
/// auditing every handler.
inline PublicRejection make_public_rejection() {
    PublicRejection p;
    nlohmann::json envelope = {{"error",
                                {{"code", std::string(kDeviceTokenRejectionPublicCode)},
                                 {"message", std::string(kDeviceTokenRejectionPublicMessage)}}},
                               {"meta", {{"api_version", "v1"}}}};
    p.envelope_json = envelope.dump();
    return p;
}

/// gRPC Status with the same opaque message. Per the agentic-first
/// invariant (A4 — error envelope parity), the gRPC `details()` payload
/// is also a JSON envelope so an MCP / REST client sees the same shape.
inline grpc::Status make_grpc_rejection_status() {
    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                        std::string(kDeviceTokenRejectionPublicMessage));
}

/// Operator-facing variant name. Used in audit `detail` field and as a
/// Prometheus label value. Must be free of `:`, `=`, spaces — usable as
/// a label without escaping.
inline std::string_view rejection_variant_name(DeviceTokenValidateError e) noexcept {
    switch (e) {
    case DeviceTokenValidateError::invalid_input:
        return "invalid_input";
    case DeviceTokenValidateError::not_found:
        return "not_found";
    case DeviceTokenValidateError::revoked:
        return "revoked";
    case DeviceTokenValidateError::expired:
        return "expired";
    case DeviceTokenValidateError::unbound_legacy:
        return "unbound_legacy";
    case DeviceTokenValidateError::binding_mismatch:
        return "binding_mismatch";
    case DeviceTokenValidateError::internal_error:
        return "internal_error";
    }
    return "unknown";
}

/// Human-readable audit-row `detail` field. Includes the bound context
/// for `binding_mismatch` (#1053 audit-completeness goal) so an auditor
/// can reconstruct "agent X tried to use a token bound to agent Y
/// (issued by principal Z)" without joining additional tables.
///
/// **Trust boundary (#1060).** The `_for_storage` suffix is deliberate: the
/// returned string carries `bound_device_id` / `bound_principal_id`, which
/// are operator-only. The result MUST be written ONLY to the audit store —
/// never echoed onto a REST/dashboard "recent rejections" surface, or it
/// leaks token-binding context to an attacker holding a stolen token. Naming
/// the boundary at every call site is the compile-time-cheap guard against a
/// future caller surfacing it on a public response. See the `make_public_*`
/// helpers for the only sanctioned wire path.
inline std::string rejection_audit_detail_for_storage(const RejectedToken& r,
                                                      std::string_view presenting_agent_id) {
    std::string detail{rejection_variant_name(r.error)};
    if (!presenting_agent_id.empty())
        detail.append(": presenter=").append(presenting_agent_id);
    if (!r.bound_device_id.empty())
        detail.append(" bound=").append(r.bound_device_id);
    if (!r.bound_principal_id.empty())
        detail.append(" bound_principal=").append(r.bound_principal_id);
    if (!r.token_id.empty())
        detail.append(" token_id=").append(r.token_id);
    return detail;
}

/// Prometheus counter name for the rejection-variant time series.
/// The variant goes in the metric NAME (not a label) so SRE can wire
/// `rate(yuzu_device_token_binding_mismatch_total[5m]) > 0` directly
/// without having to remember a labels-list selector. Three high-signal
/// variants get their own counter (per task spec):
///
/// * `binding_mismatch` — most actionable: stolen-token impersonation
///   in progress. Pages on-call.
/// * `unbound_legacy` — operator action required: legacy any-device
///   token is being presented. Issue a re-bound replacement.
/// * `revoked` — replayed-revoked-token attempt. Investigate the
///   originating IP.
///
/// `not_found` / `expired` / `invalid_input` are bucketed together as
/// low-signal `yuzu_device_token_rejected_total{variant=...}` so SRE
/// can still see them without flooding the high-signal counters.
inline std::string_view rejection_metric_name(DeviceTokenValidateError e) noexcept {
    switch (e) {
    case DeviceTokenValidateError::binding_mismatch:
        return "yuzu_device_token_binding_mismatch_total";
    case DeviceTokenValidateError::unbound_legacy:
        return "yuzu_device_token_unbound_legacy_total";
    case DeviceTokenValidateError::revoked:
        return "yuzu_device_token_revoked_attempt_total";
    default:
        return "yuzu_device_token_rejected_total";
    }
}

/// Audit-event `action` value. Single value across variants — the
/// detailed variant lives in the `detail` field. Reduces audit-query
/// surface so an operator searching for "credential rejection" can
/// filter on one action name.
inline constexpr std::string_view kDeviceTokenRejectionAuditAction = "device_token.validate_failed";

inline std::string_view rejection_event_action() noexcept {
    return kDeviceTokenRejectionAuditAction;
}

} // namespace yuzu::server
