/// @file app_usage_routes.cpp
/// `/api/v1/forensics/agents/{id}/app-usage` route registration (wave 7
/// PR7.2). One route: the per-agent app-usage projection read (GET). See
/// app_usage_routes.hpp for the auth posture. The handler chain mirrors
/// SleRoutes' drill (sle_routes.cpp): correlation id + header -> scoped gate
/// -> behavioural audit -> 503-on-degrade (never an empty 200); errors via
/// the A4 envelope.
///
/// A4 / JSON helpers are re-implemented locally (small, self-contained)
/// rather than shared from rest_api_v1.cpp, whose helpers are
/// translation-unit-local — the same self-contained-route-file discipline
/// SleRoutes/InventoryRoutes follow.

#include "app_usage_routes.hpp"

#include "http_route_sink.hpp"
#include "rest_audit.hpp" // detail::try_persist_audit / emit_behavioral_audit (#1647)

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

using nlohmann::json;

/// grep-token correlation id, `req-<hex-ms>-<hex-seq>` — same shape as
/// rest_api_v1.cpp's make_correlation_id (echoed in X-Correlation-Id + every A4
/// body). Process-global monotonic sequence so two ids minted in the same ms differ.
std::string make_cid() {
    static std::atomic<std::uint64_t> seq{0};
    const auto t = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
    return std::format("req-{:x}-{:x}", static_cast<std::uint64_t>(t), seq.fetch_add(1));
}

/// A4 error envelope. retry_after_ms is ALWAYS a key (null unless set), per
/// docs/agentic-first-principle.md §A4.
std::string a4_error(int code, std::string_view message, std::string_view cid,
                     std::optional<std::int64_t> retry_after_ms = std::nullopt,
                     std::string_view remediation = {}) {
    json err;
    err["code"] = code;
    err["message"] = std::string(message);
    err["correlation_id"] = std::string(cid);
    if (retry_after_ms)
        err["retry_after_ms"] = *retry_after_ms;
    else
        err["retry_after_ms"] = nullptr;
    if (!remediation.empty())
        err["remediation"] = std::string(remediation);
    json out;
    out["error"] = std::move(err);
    out["meta"] = json{{"api_version", "v1"}};
    return out.dump();
}

std::string ok_json(json data) {
    json out;
    out["data"] = std::move(data);
    out["meta"] = json{{"api_version", "v1"}};
    return out.dump();
}

void send_json(httplib::Response& res, int status, std::string body) {
    res.status = status;
    res.set_content(std::move(body), "application/json");
}

json app_usage_row_to_json(const AgentLastUsedRow& r) {
    json j;
    j["exe_key"] = r.exe_key;
    j["first_seen"] = r.first_seen;
    j["last_seen"] = r.last_seen;
    j["run_count_30d"] = r.run_count_30d;
    j["total_seconds_30d"] = r.total_seconds_30d;
    return j;
}

} // namespace

void AppUsageRoutes::register_routes(httplib::Server& svr, ScopedPermFn scoped_perm_fn,
                                     AgentLastUsedFn agent_last_used_fn, AuditFn audit_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(scoped_perm_fn), std::move(agent_last_used_fn),
                    std::move(audit_fn));
}

void AppUsageRoutes::register_routes(HttpRouteSink& sink, ScopedPermFn scoped_perm_fn,
                                     AgentLastUsedFn agent_last_used_fn, AuditFn audit_fn) {
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    agent_last_used_fn_ = std::move(agent_last_used_fn);
    audit_fn_ = std::move(audit_fn);

    // ── GET /api/v1/forensics/agents/{agent_id}/app-usage — per-agent projection ──
    // Forensics:Read SCOPED to the device (tier + management group, the SleRoutes
    // drill precedent). Behavioural data (what ran, when, how often), so it takes
    // the same per-open audit tier as the app-perf device drill.
    sink.Get(R"(/api/v1/forensics/agents/([^/]+)/app-usage)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 const auto cid = make_cid();
                 res.set_header("X-Correlation-Id", cid);
                 const std::string agent_id = req.matches.size() > 1 ? req.matches[1].str() : "";

                 // Per-device scope is MANDATORY — fail CLOSED if the gate is unwired
                 // rather than silently widening to a global read (mirrors the SLE
                 // drill; production always wires it from server.cpp).
                 if (!scoped_perm_fn_) {
                     send_json(res, 503, a4_error(503, "scope gate not configured", cid));
                     return;
                 }
                 if (!scoped_perm_fn_(req, res, "Forensics", "Read", agent_id))
                     return; // the gate wrote its own 401/403

                 // Per-open behavioural audit — set BEFORE the store read (matches the
                 // app-perf device drill's ordering). Behavioural PII (what ran, when,
                 // how often), so this FAILS CLOSED (503 + Sec-Audit-Failed) exactly
                 // like the SLE drill and the app-perf REST twin's documented posture
                 // when the access-audit row is KNOWN to have failed to persist.
                 if (!detail::emit_behavioral_audit(
                         audit_fn_, req, res, "app_usage.agent.view", "success", "Agent", agent_id,
                         "per-agent app-usage projection drill cid=" + cid)) {
                     send_json(res, 503,
                               a4_error(503,
                                        "audit subsystem unavailable; refusing to serve "
                                        "behavioural app-usage data without durable evidence",
                                        cid, 5000, "retry the request"));
                     spdlog::warn("app_usage.agent.view audit fail-closed (503) cid={} agent_id={}",
                                  cid, agent_id);
                     return;
                 }

                 std::optional<std::vector<AgentLastUsedRow>> rows;
                 if (agent_last_used_fn_)
                     rows = agent_last_used_fn_(agent_id);
                 if (!rows) {
                     // Store/pool/query degrade — a durable failure-audit (the SLE
                     // drill's pattern), then 503 (never a silent empty 200).
                     (void)detail::try_persist_audit(audit_fn_, req, "app_usage.agent.view",
                                                     "failure", "Agent", agent_id,
                                                     "app-usage store degraded; cid=" + cid);
                     send_json(res, 503,
                               a4_error(503, "app-usage store unavailable — read failed", cid, 5000,
                                        "retry the request"));
                     return;
                 }

                 json apps = json::array();
                 for (const auto& r : *rows)
                     apps.push_back(app_usage_row_to_json(r));
                 json data;
                 data["agent_id"] = agent_id;
                 data["apps"] = std::move(apps);
                 // collected_at is the agent-batch collection time (app_usage_store.hpp:
                 // every row in one replace_agent_last_used call shares it, per
                 // app_usage_ingestion.cpp), so it is hoisted to the top level rather
                 // than repeated per-app; an empty result carries 0 (never collected).
                 data["collected_at"] = rows->empty() ? std::int64_t{0} : rows->front().collected_at;
                 send_json(res, 200, ok_json(std::move(data)));
             });
}

} // namespace yuzu::server
