#pragma once

/// @file guardian_model.hpp
/// Pure, no-httplib READ models shared by REST and MCP for the Guardian /
/// Guaranteed State surface (#4037, api-parity programme #2146 Batch A).
///
/// Follows the SAME real precedent as `access_review_model.hpp` /
/// `dex_app_perf_model.hpp` / `network_perf_model.hpp` — every function here
/// returns a plain value type (struct / vector / optional), never a JSON
/// string. `docs/api-twin-recipe.md` §1's own worked example (§8) shows a
/// JSON-string-returning shared builder, but that section is explicitly
/// illustrative-only ("no source files change as part of #3993, which is
/// docs-only") — no shipped model file in this tree actually does that,
/// because `JObj`/`JArr` are each defined LOCALLY inside `rest_api_v1.cpp`
/// and `mcp_server.cpp` (there is no header-exposed shared JSON builder to
/// return a string built from). What actually cannot drift between REST and
/// MCP by construction is the DATA — which store method gets called, with
/// what filter, and what it means — so that is what lives here. Each
/// transport still writes its own few lines of `JObj`/`JArr` field
/// enumeration over the struct returned below; that enumeration is
/// mechanical (list the struct's own fields) and low-risk compared to the
/// query/computation logic these functions centralise.
///
/// All four functions return `std::optional`/`nullopt` on a degraded store
/// read (ADR-0038 catastrophic-read set) — the caller MUST 503 (REST) or
/// otherwise refuse to render, never render an empty/zero result that would
/// misreport the fleet as compliant or a rule as having no reporting agents.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class GuaranteedStateStore;

/// Fleet Guardian status rollup — shared by `GET /api/v1/guaranteed-state/status`
/// and MCP `get_guardian_status`. Re-derives EXACTLY the fields the REST route
/// already built inline before this PR (rest_api_v1.cpp's own "ADR-1005
/// MCP-twin note" flagged the drift risk of a future rung completing one of
/// these placeholder fields on the REST side only). `compliant_rules`/
/// `drifted_rules` stay 0 until full status ingest lands (unchanged from
/// today) — this function does not widen the capability, only shares it.
struct GuardianStatusRollup {
    std::int64_t total_rules{0};
    std::int64_t compliant_rules{0};
    std::int64_t drifted_rules{0};
    std::int64_t errored_rules{0};
};

/// `agent_scope`: nullopt = whole fleet; engaged (including empty, ADR-0017
/// INV-2) = confine `errored_rules` to exactly these agents, applied in SQL
/// by `errored_rule_count` (INV-3) — never a C++ post-filter. `total_rules`
/// is the global rule-catalogue size and is NEVER confined (a rule has no
/// agent/management-group dimension of its own). Returns `nullopt` on a
/// degraded `rule_names()`/`errored_rule_count()` read.
std::optional<GuardianStatusRollup>
guardian_status_rollup(GuaranteedStateStore& store,
                       const std::optional<std::vector<std::string>>& agent_scope);

/// Per-guard fleet-wide agent-status drilldown row — one row per agent that
/// has reported THIS rule's state — shared by the new
/// `GET /api/v1/guaranteed-state/rules/{rule_id}/status` and MCP
/// `get_guardian_rule_status`. This is the data behind
/// `/fragments/guardian/guard/{id}/page`'s fleet-wide agent census
/// (`guardian_routes.cpp::render_guard_page_fragment`), factored out to a
/// pure function so the fragment, REST and MCP compute the SAME census.
///
/// Deliberately does NOT apply the dashboard fragment's own
/// online-folds-to-unknown rollup (an offline agent's LAST reported state
/// forced to "unknown") or its not-implemented-platform augmentation — same
/// "raw census, not the dashboard's offline-agent-folds-to-unknown rollup"
/// posture `GET /guaranteed-state/status` already established
/// (rest_api_v1.cpp) for the identical class of data. A caller wanting
/// online/offline or hostname context correlates `agent_id` against
/// `list_agents`/`GET /api/v1/agents` separately.
struct GuardianRuleAgentStatusRow {
    std::string agent_id;
    std::string state;      // "compliant" | "drifted" | "errored"
    std::string updated_at; // ISO-8601 of the event that set it
};

/// Returns `nullopt` on a degraded `agent_rule_statuses()` read — caller MUST
/// refuse to render (503 on REST), never render an empty list as "no device
/// reports this guard". Does NOT distinguish "rule not found" from "rule
/// exists, no agent has reported yet" (both return an empty, non-nullopt
/// vector) — callers needing that distinction check `get_rule(rule_id)`
/// first (three-state: found / genuinely absent / degraded).
std::optional<std::vector<GuardianRuleAgentStatusRow>>
guardian_rule_agent_status_rows(GuaranteedStateStore& store, const std::string& rule_id);

/// Per-device all-guards view row — one row per guard this device has
/// reported ANY status for, unscoped to any one Baseline — shared by the new
/// `GET /api/v1/guaranteed-state/agents/{agent_id}/rules` and MCP
/// `get_guardian_device_guards`. This is the data behind
/// `/fragments/device/guardian`'s per-device Guardian lens
/// (`device_routes.cpp`), which answers "what is every guard's state for
/// this device" — a genuinely different shape from
/// `GET /guaranteed-state/device-compliance`, which answers "is this device
/// compliant with this ONE Baseline" (requires both `agent_id` AND
/// `baseline`). See the route header comment in rest_api_v1.cpp for why this
/// is a distinct route rather than an optional-`baseline` extension of
/// `device-compliance` (that route's response is baseline-shaped —
/// `baseline{}`/`deployed`/`assessable`/`snapshot_total` — and making
/// `baseline` optional would produce a union-shaped response with no single
/// OpenAPI/output-schema honest description).
///
/// Uses `agent_rule_statuses_for_agent` (a bounded, server-side-filtered
/// query), not the fragment's own `agent_rule_statuses()` unfiltered fleet
/// scan post-filtered in C++ — same modernisation `device-compliance`
/// already made for this identical class of read.
struct GuardianDeviceGuardRow {
    std::string rule_id;
    std::string name;       // resolved rule name; falls back to rule_id if the
                             // rule has since been deleted from the catalogue
    std::string state;      // "compliant" | "drifted" | "errored"
    std::string updated_at; // ISO-8601 of the event that set it
};

/// Returns `nullopt` on a degraded `agent_rule_statuses_for_agent()`/
/// `rule_names_for()` read — caller MUST refuse to render (503 on REST),
/// never render an empty list as "this device has no guards".
std::optional<std::vector<GuardianDeviceGuardRow>>
guardian_device_all_guards(GuaranteedStateStore& store, const std::string& agent_id);

} // namespace yuzu::server
