#pragma once

/// @file grpc_audit_signal.hpp
/// Shared gRPC audit-failure wire signal (#1063, W1.4).
///
/// REST surfaces set `Sec-Audit-Failed: true` (rest_api_v1.cpp) when an audit
/// row fails to persist, so an operator/SIEM sees the evidence-chain
/// degradation on the wire rather than only via the analytics-event severity
/// escalation. The gRPC Register / Subscribe paths had no equivalent — a
/// dropped audit row escalated analytics to `kError` but the wire response
/// carried no operator signal. This adds the symmetric signal: trailing
/// metadata `x-yuzu-audit-failed: true`. SOC 2 CC7.2 wants symmetric coverage.
///
/// Key must be lowercase and the value ASCII (gRPC metadata constraints).
/// Both `agent_service_impl.cpp` and `gateway_service_impl.cpp` route through
/// this single definition so the key cannot drift between them.

#include <grpcpp/grpcpp.h>

namespace yuzu::server {

/// gRPC trailing-metadata key set when an audit row fails to persist.
inline constexpr char kGrpcAuditFailedKey[] = "x-yuzu-audit-failed";

/// Attach the audit-failure trailer to the response. No-op on a null context.
/// Call only when an `audit_store_->log()` returned false.
inline void signal_grpc_audit_failed(grpc::ServerContext* context) {
    if (context)
        context->AddTrailingMetadata(kGrpcAuditFailedKey, "true");
}

} // namespace yuzu::server
