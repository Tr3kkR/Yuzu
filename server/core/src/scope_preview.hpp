#pragma once

/// @file scope_preview.hpp
/// PURE evaluate-scope-against-every-known-agent logic shared between MCP
/// `preview_scope_targets` and its new REST v1 twin, `POST
/// /api/v1/scope/preview` (#2146 Batch B2). Neither surface had this factored
/// out before this file: MCP carried the only implementation inline in
/// mcp_server.cpp. Extracted so the matched-agent set, the blast-radius
/// warning threshold, and the three error/degrade cases cannot drift between
/// the two transports (api-twin-recipe.md Rule 1). No httplib.h dependency.

#include <nlohmann/json.hpp>

#include <string>

namespace yuzu::server {

class TagStore;

/// Outcome of a scope-preview evaluation. Exactly one of the three shapes
/// below is populated, discriminated by `kind`:
///   - `kInvalidExpression`: `detail` is the caller-facing parse/validate
///     error message (already prefixed "Invalid scope: "/"Parse error: ",
///     matching the pre-extraction MCP wording verbatim).
///   - `kTagStoreDegraded`: the expression references `tag:<key>` atoms and
///     the bulk tag preload failed — a caller MUST NOT treat this as "no
///     matches" (that would silently under-report a scope's real blast
///     radius, the #2500-family fail-open class).
///   - `kOk`: `payload` is the full response object
///     `{expression, matched_count, matched_agents, [warning]}`.
struct ScopePreviewOutcome {
    enum class Kind { kInvalidExpression, kTagStoreDegraded, kOk } kind{Kind::kOk};
    std::string detail;      // kInvalidExpression only
    nlohmann::json payload;  // kOk only
};

/// `agents` is the SAME AgentsJsonFn()/get_agents() snapshot both REST and
/// MCP already share — an array of {agent_id, os, arch, hostname,
/// agent_version} objects. `tag_store` may be null (no tag:<key> preload —
/// matches how the pre-extraction MCP code behaved when its own tag_store
/// pointer was unset, since it treated a null store identically to "no
/// tag: atoms referenced": no preload attempted, no degrade possible).
ScopePreviewOutcome preview_scope_targets(const std::string& expression,
                                          const nlohmann::json& agents, TagStore* tag_store);

} // namespace yuzu::server
