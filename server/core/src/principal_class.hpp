// principal_class — bounded actor-class label for HTTP request metrics
// (ADR-1005 Consequences; execution-plan PR 1.2).
//
// Classification is by CREDENTIAL PRESENTATION, not by validated session:
// the label is a traffic-shape metric, not an authorization decision, and
// re-running session resolution in the post-routing handler (where the
// request counter is emitted) would double the per-request auth cost. A
// request offering a session cookie is browser/human-shaped traffic even if
// the cookie turns out invalid — the status label already carries the 401.
//
// Values are a CLOSED set (docs/observability-conventions.md — bounded
// labels only): "human" (session cookie), "agent" (bearer/API token — an
// agentic worker or automation), "none" (no credential offered). "engine"
// is RESERVED for Phase 4 engine principals and never emitted today; the
// value becomes live when engine-token sessions exist (execution-plan
// PR 4.5). The agent daemon never appears here — it speaks gRPC, not HTTP.

#pragma once

#include <string_view>

#include <httplib.h>

namespace yuzu::server {

[[nodiscard]] inline std::string_view principal_class_of(const httplib::Request& req) {
    // Order matters: a request carrying BOTH a cookie and a bearer token is
    // classified by the stronger machine signal — API/MCP clients sometimes
    // inherit ambient cookies from shared HTTP stacks, but a browser never
    // fabricates an Authorization header.
    if (req.has_header("Authorization") || req.has_header("X-Yuzu-Token")) {
        return "agent";
    }
    // Anchored match: the cookie NAME must be exactly yuzu_session — at the
    // start of the Cookie header or after a "; " separator — so a cookie
    // merely named e.g. not_yuzu_session doesn't classify as human.
    auto cookie = req.get_header_value("Cookie");
    if (cookie.starts_with("yuzu_session=") ||
        cookie.find("; yuzu_session=") != std::string::npos) {
        return "human";
    }
    return "none";
}

}  // namespace yuzu::server
