/**
 * viz_routes.cpp -- /viz/fleet REST + fragment routes (PR 3 of 11)
 *
 * Each handler:
 *  1. Tier/RBAC check via perm_fn_ ("Response", "Read") -- 401/403 paths
 *     fall out of the perm_fn_ contract and short-circuit before any
 *     dispatch. Tier-before-permission ordering is the security-guardian
 *     standing rule (docs/auth-architecture.md §3).
 *  2. Kill-switch consult -- 503 with structured envelope. Audited so
 *     enabling the kill switch leaves an evidence trail (DEP-1).
 *  3. Store-availability consult -- 503 if the store is null (server
 *     started with --no-viz or constructor never wired).
 *  4. Parse query params with strict numeric guards. Failures -> 400.
 *  5. Optional `?fresh=1` invalidates the cache before get(). Audited
 *     separately from the success row so the operator-driven cache flush
 *     is its own audit event.
 *  6. get(include_vuln) returns a non-null shared_ptr<TopologySnapshot>
 *     (UP-9 invariant from PR 2 hardening). Cache-hit/miss counters are
 *     observed by diffing the store's atomic counters across the call.
 *  7. machines_max gate -- M-1 cap-check DoS. Compared against the
 *     materialised count; 413 if over, with audit row. We do NOT serve
 *     a truncated snapshot -- truncation would mislead operators about
 *     which subset they're seeing.
 *  8. Serialise + ship. Per-request latency goes to the
 *     yuzu_viz_topology_request_seconds histogram.
 *
 * Fragment vs JSON routes share the same body via handle_topology(). The
 * fragment wraps the JSON in `<script type="application/json"
 * id="viz-data">` so the renderer can parse-on-swap without an extra
 * round-trip (agentic-first A1 -- dashboard parity).
 */

#include "viz_routes.hpp"

#include "fleet_topology_store.hpp"
#include "fleet_topology_types.hpp"
#include "http_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <stdexcept>
#include <string>
#include <utility>

namespace yuzu::server {

namespace {

/// Build a uniform JSON error envelope. Status code mirrors HTTP status.
/// Schema is stable so MCP / SDK clients can parse without ambiguity --
/// matches the shape used by `/api/responses/...` etc.
std::string error_envelope(int code, std::string_view message) {
    nlohmann::json j = {{"error", {{"code", code}, {"message", message}}},
                        {"meta", {{"api_version", "v1"}}}};
    return j.dump();
}

bool parse_bool_param(const httplib::Request& req, std::string_view key, bool default_value) {
    if (!req.has_param(std::string(key)))
        return default_value;
    auto v = req.get_param_value(std::string(key));
    return v == "1" || v == "true" || v == "yes" || v == "TRUE";
}

} // namespace

void VizRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                AuditFn audit_fn, FleetTopologyStore* store,
                                yuzu::MetricsRegistry* metrics,
                                const std::atomic<bool>* kill_switch) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn), store,
                    metrics, kill_switch);
}

void VizRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                AuditFn audit_fn, FleetTopologyStore* store,
                                yuzu::MetricsRegistry* metrics,
                                const std::atomic<bool>* kill_switch) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    store_ = store;
    metrics_ = metrics;
    kill_switch_ = kill_switch;

    sink.Get("/api/v1/viz/fleet/topology",
             [this](const httplib::Request& req, httplib::Response& res) {
                 handle_topology(req, res, /*as_fragment=*/false);
             });

    sink.Get("/fragments/viz/fleet/topology",
             [this](const httplib::Request& req, httplib::Response& res) {
                 handle_topology(req, res, /*as_fragment=*/true);
             });
}

void VizRoutes::handle_topology(const httplib::Request& req, httplib::Response& res,
                                bool as_fragment) {
    const auto t_start = std::chrono::steady_clock::now();

    // ── 1. RBAC ───────────────────────────────────────────────────────────
    // perm_fn_ writes the 401/403 body and status itself; bail on false.
    if (!perm_fn_(req, res, "Response", "Read"))
        return;

    // ── 2. Kill switch (DEP-1) ────────────────────────────────────────────
    if (kill_switch_ && kill_switch_->load(std::memory_order_acquire)) {
        res.status = 503;
        res.set_content(
            error_envelope(503, "viz endpoint disabled by operator (yuzu_viz_disabled)"),
            "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology", "denied", "viz_topology", "*", "kill_switch");
        return;
    }

    // ── 3. Store availability ────────────────────────────────────────────
    if (!store_) {
        res.status = 503;
        res.set_content(error_envelope(503, "fleet topology store not available"),
                        "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology", "error", "viz_topology", "*", "store_null");
        return;
    }

    // ── 4. Parse query params ────────────────────────────────────────────
    const bool include_vuln = parse_bool_param(req, "include_vuln", false);
    const bool fresh = parse_bool_param(req, "fresh", false);

    int machines_max = kDefaultMachinesMax;
    try {
        if (req.has_param("machines_max")) {
            machines_max = std::stoi(req.get_param_value("machines_max"));
            if (machines_max <= 0 || machines_max > kMachinesMaxCeiling) {
                res.status = 400;
                res.set_content(error_envelope(400, "machines_max must be in [1, 100000]"),
                                "application/json");
                if (audit_fn_)
                    audit_fn_(req, "viz.fleet_topology", "denied", "viz_topology", "*",
                              "bad_machines_max");
                return;
            }
        }
    } catch (const std::exception&) {
        res.status = 400;
        res.set_content(error_envelope(400, "invalid machines_max"), "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology", "denied", "viz_topology", "*", "bad_machines_max");
        return;
    }

    // ── 5. Optional fresh -- emit its own audit row before the get ────────
    if (fresh) {
        store_->invalidate();
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology.invalidate", "ok", "viz_topology", "*", "");
    }

    // ── 6. Fetch (cache-hit fast-path or single-flight refill) ────────────
    const auto pre_hits = store_->cache_hits();
    const auto pre_misses = store_->cache_misses();

    std::shared_ptr<const TopologySnapshot> snap;
    try {
        snap = store_->get(include_vuln);
    } catch (const std::exception& ex) {
        spdlog::error("VizRoutes: store->get threw: {}", ex.what());
        res.status = 500;
        res.set_content(error_envelope(500, "topology fetch failed"), "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology", "error", "viz_topology", "*", "fetch_threw");
        return;
    }
    // PR 2 invariant UP-9: get() never returns null. Defensive belt anyway.
    if (!snap) {
        res.status = 500;
        res.set_content(error_envelope(500, "topology fetch returned null"), "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology", "error", "viz_topology", "*", "snap_null");
        return;
    }

    if (metrics_) {
        if (store_->cache_hits() > pre_hits)
            metrics_->counter("yuzu_viz_cache_hit_total").increment();
        if (store_->cache_misses() > pre_misses)
            metrics_->counter("yuzu_viz_cache_miss_total").increment();
    }

    // ── 7. machines_max DoS gate (M-1) ────────────────────────────────────
    if (static_cast<int>(snap->machines.size()) > machines_max) {
        res.status = 413;
        res.set_content(
            error_envelope(413,
                           "fleet topology exceeds machines_max -- raise the cap or scope down"),
            "application/json");
        if (audit_fn_)
            audit_fn_(req, "viz.fleet_topology", "oversize", "viz_topology", "*",
                      "machines=" + std::to_string(snap->machines.size()) +
                          " cap=" + std::to_string(machines_max));
        if (metrics_)
            metrics_->counter("yuzu_viz_oversize_response_total").increment();
        return;
    }

    // ── 8. Serialise + respond ───────────────────────────────────────────
    nlohmann::json j = *snap;
    auto body = j.dump();

    if (as_fragment) {
        // HTMX fragment: parser-recoverable script tag carrying the JSON.
        // The id is fixed so the renderer can locate it deterministically
        // after htmx swaps the parent. No additional escaping needed --
        // a JSON document cannot contain a literal `</script>` (would be
        // an unescaped `<`, which json.dump emits as the escaped form).
        std::string fragment = "<script type=\"application/json\" id=\"viz-data\">";
        fragment.append(body);
        fragment.append("</script>");
        res.set_content(std::move(fragment), "text/html; charset=utf-8");
    } else {
        res.set_content(std::move(body), "application/json");
    }

    if (audit_fn_) {
        audit_fn_(req, "viz.fleet_topology", "ok", "viz_topology", "*",
                  "machines=" + std::to_string(snap->machines.size()) +
                      " include_vuln=" + (include_vuln ? "1" : "0") + (fresh ? " fresh=1" : "") +
                      (as_fragment ? " fragment=1" : ""));
    }

    if (metrics_) {
        const auto elapsed = std::chrono::steady_clock::now() - t_start;
        const double seconds = std::chrono::duration<double>(elapsed).count();
        metrics_->histogram("yuzu_viz_topology_request_seconds").observe(seconds);
    }
}

} // namespace yuzu::server
