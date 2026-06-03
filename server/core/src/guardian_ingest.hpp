#pragma once

/// @file guardian_ingest.hpp
/// Shared ingest for Guardian "__guard__" side-channel CommandResponses.
///
/// Both the direct Subscribe read loop (AgentServiceImpl) and the
/// gateway-proxied path (GatewayUpstreamServiceImpl::ForwardGuardianMessage)
/// route unsolicited "__guard__" responses through this one function so the
/// two paths cannot diverge (the spec_json-style divergence bug class). The
/// `agent_id` is supplied by the caller — cert-bound on the direct path,
/// gateway-asserted on the gateway path — and is NEVER read from the frame.

#include <string>

#include "agent.pb.h"

namespace yuzu::server {
class GuaranteedStateStore;
}

namespace yuzu::server::detail {

namespace pb = ::yuzu::agent::v1;

/// Ingest one Guardian side-channel CommandResponse. The caller must have
/// already verified `resp.plugin() == "__guard__"`. Dispatches by `action`:
///   "event" → parse the GuaranteedStateEvent from `payload`, enrich severity
///             from the rule store, insert into the events table.
///   other   → logged and dropped (the channel is generic; a future "status"
///             message must not crash this path).
/// Never touches the response store / executions drawer.
void ingest_guardian_response(GuaranteedStateStore& store, const std::string& agent_id,
                              const pb::CommandResponse& resp);

} // namespace yuzu::server::detail
