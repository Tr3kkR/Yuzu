/**
 * test_viz_routes.cpp -- HTTP-level coverage for /api/v1/viz/fleet/topology
 * + /fragments/viz/fleet/topology (PR 3 of feat/viz-engine ladder).
 *
 * Mirrors test_rest_offload_targets.cpp: register VizRoutes against an
 * in-process TestRouteSink with a fake Fetcher and dispatch synthesised
 * requests directly into the captured handlers -- no socket, no acceptor
 * thread, TSan-safe.
 *
 * Coverage:
 *   - GET JSON returns 200 + valid fleet_topology.v1 envelope
 *   - GET fragment returns 200 + <script type="application/json"> wrapper
 *     carrying the same JSON body the API route would emit
 *   - 401/403 path: perm_fn denies -> handler short-circuits
 *   - 503 path: kill switch on -> structured envelope, audit "denied"
 *   - 503 path: store null -> structured envelope, audit "error"
 *   - 413 path: machines_max=N below actual -> oversize audit, oversize metric
 *   - 400 path: machines_max non-numeric / out-of-range -> structured 400
 *   - fresh=1 invalidates the cache + audits separately before get
 *   - Cache-hit metric increments on second hit-only call
 *   - Cache-miss metric increments on first call (from store counters)
 */

#include "fleet_topology_store.hpp"
#include "fleet_topology_types.hpp"
#include "test_route_sink.hpp"
#include "viz_routes.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRecord {
    std::string action, result, target_type, target_id, detail;
};

RawAgentSnapshot mk_agent(std::string id, std::string host) {
    RawAgentSnapshot r;
    r.agent_id = std::move(id);
    r.hostname = std::move(host);
    r.os = "linux";
    r.ts = 1715299200;
    return r;
}

FleetTopologyStore::Fetcher fixed_fetcher(std::vector<RawAgentSnapshot> data) {
    return [data = std::move(data)](std::chrono::milliseconds) {
        return data;
    };
}

/// In-process harness for VizRoutes — no httplib::Server / sockets / threads.
struct VizHarness {
    yuzu::server::test::TestRouteSink sink;
    std::unique_ptr<FleetTopologyStore> store;
    yuzu::MetricsRegistry metrics;
    std::atomic<bool> kill_switch{false};
    bool perm_grant{true};
    std::vector<AuditRecord> audit_log;
    VizRoutes routes;

    explicit VizHarness(std::vector<RawAgentSnapshot> seed = {}, bool with_store = true) {
        if (with_store) {
            store = std::make_unique<FleetTopologyStore>(
                fixed_fetcher(std::move(seed)),
                /*nvd*/ nullptr,
                /*ttl*/ std::chrono::seconds(60),
                /*fetch_deadline*/ std::chrono::milliseconds(50),
                /*max_snapshot_bytes*/ 0); // disable size cap for tests
        }

        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti, const std::string& d) {
            audit_log.push_back({a, r, tt, ti, d});
        };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, with_store ? store.get() : nullptr,
                               &metrics, &kill_switch);
    }
};

} // namespace

// =============================================================================
// 200 OK: JSON + fragment shape parity (agentic-first A1 invariant)
// =============================================================================

TEST_CASE("REST viz: GET JSON returns fleet_topology.v1 envelope", "[viz][routes]") {
    std::vector<RawAgentSnapshot> seed{mk_agent("a1", "host-1"), mk_agent("a2", "host-2")};
    VizHarness h(std::move(seed));

    auto res = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type").find("application/json") != std::string::npos);

    auto j = json::parse(res->body);
    CHECK(j.value("schema", "") == "fleet_topology.v1");
    CHECK(j.contains("machines"));
    REQUIRE(j["machines"].is_array());
    CHECK(j["machines"].size() == 2);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "viz.fleet_topology");
    CHECK(h.audit_log[0].result == "ok");
}

TEST_CASE("REST viz: GET fragment wraps the same JSON in <script> tag", "[viz][routes]") {
    std::vector<RawAgentSnapshot> seed{mk_agent("a1", "host-1")};
    VizHarness h(std::move(seed));

    auto res = h.sink.Get("/fragments/viz/fleet/topology");
    REQUIRE(res);
    CHECK(res->status == 200);
    CHECK(res->get_header_value("Content-Type").find("text/html") != std::string::npos);

    // The fragment body must wrap valid JSON in a parser-recoverable
    // script tag with the canonical id the renderer queries for.
    const std::string& body = res->body;
    auto open_pos = body.find("<script type=\"application/json\" id=\"viz-data\">");
    REQUIRE(open_pos != std::string::npos);
    auto close_pos = body.rfind("</script>");
    REQUIRE(close_pos != std::string::npos);
    auto json_text = body.substr(
        open_pos + std::string("<script type=\"application/json\" id=\"viz-data\">").size(),
        close_pos -
            (open_pos + std::string("<script type=\"application/json\" id=\"viz-data\">").size()));
    auto j = json::parse(json_text);
    CHECK(j.value("schema", "") == "fleet_topology.v1");

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].detail.find("fragment=1") != std::string::npos);
}

// =============================================================================
// RBAC + kill switch + store-null (503/403 paths)
// =============================================================================

TEST_CASE("REST viz: 403 when perm_fn denies", "[viz][routes][rbac]") {
    VizHarness h({mk_agent("a", "h")});
    h.perm_grant = false;

    auto res = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(res);
    CHECK(res->status == 403);
    // perm_fn short-circuits before the audit envelope -- no row.
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST viz: 503 when kill switch flipped", "[viz][routes][killswitch]") {
    VizHarness h({mk_agent("a", "h")});
    h.kill_switch.store(true);

    auto res = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(res);
    CHECK(res->status == 503);

    auto j = json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);
    CHECK(j["error"]["message"].get<std::string>().find("disabled") != std::string::npos);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "viz.fleet_topology");
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].detail == "kill_switch");
}

TEST_CASE("REST viz: 503 when store is null", "[viz][routes]") {
    VizHarness h({}, /*with_store=*/false);

    auto res = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(res);
    CHECK(res->status == 503);

    auto j = json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 503);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "error");
    CHECK(h.audit_log[0].detail == "store_null");
}

// =============================================================================
// machines_max DoS gate (M-1 follow-up)
// =============================================================================

TEST_CASE("REST viz: 413 when materialised count exceeds machines_max", "[viz][routes][cap]") {
    std::vector<RawAgentSnapshot> seed;
    for (int i = 0; i < 5; ++i)
        seed.push_back(mk_agent("a" + std::to_string(i), "h" + std::to_string(i)));
    VizHarness h(std::move(seed));

    auto res = h.sink.Get("/api/v1/viz/fleet/topology?machines_max=2");
    REQUIRE(res);
    CHECK(res->status == 413);

    auto j = json::parse(res->body);
    CHECK(j["error"]["code"].get<int>() == 413);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "oversize");
    CHECK(h.audit_log[0].detail.find("machines=5") != std::string::npos);
    CHECK(h.audit_log[0].detail.find("cap=2") != std::string::npos);
}

TEST_CASE("REST viz: 400 on non-numeric machines_max", "[viz][routes][cap]") {
    VizHarness h({mk_agent("a", "h")});
    auto res = h.sink.Get("/api/v1/viz/fleet/topology?machines_max=lots");
    REQUIRE(res);
    CHECK(res->status == 400);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].result == "denied");
    CHECK(h.audit_log[0].detail == "bad_machines_max");
}

TEST_CASE("REST viz: 400 on machines_max above ceiling", "[viz][routes][cap]") {
    VizHarness h({mk_agent("a", "h")});
    auto res = h.sink.Get("/api/v1/viz/fleet/topology?machines_max=2000000");
    REQUIRE(res);
    CHECK(res->status == 400);

    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].detail == "bad_machines_max");
}

TEST_CASE("REST viz: 400 on machines_max=0", "[viz][routes][cap]") {
    VizHarness h({mk_agent("a", "h")});
    auto res = h.sink.Get("/api/v1/viz/fleet/topology?machines_max=0");
    REQUIRE(res);
    CHECK(res->status == 400);
}

// =============================================================================
// Cache invalidate on ?fresh=1
// =============================================================================

TEST_CASE("REST viz: ?fresh=1 emits separate invalidate audit row", "[viz][routes]") {
    VizHarness h({mk_agent("a", "h")});

    auto res = h.sink.Get("/api/v1/viz/fleet/topology?fresh=1");
    REQUIRE(res);
    CHECK(res->status == 200);

    REQUIRE(h.audit_log.size() == 2);
    CHECK(h.audit_log[0].action == "viz.fleet_topology.invalidate");
    CHECK(h.audit_log[0].result == "ok");
    CHECK(h.audit_log[1].action == "viz.fleet_topology");
    CHECK(h.audit_log[1].result == "ok");
    CHECK(h.audit_log[1].detail.find("fresh=1") != std::string::npos);
}

// =============================================================================
// Cache hit/miss metric increments
// =============================================================================

TEST_CASE("REST viz: cache miss increments yuzu_viz_cache_miss_total", "[viz][routes][metrics]") {
    VizHarness h({mk_agent("a", "h")});

    // First call -- cache cold -> miss.
    auto r1 = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(r1);
    CHECK(r1->status == 200);

    auto& miss = h.metrics.counter("yuzu_viz_cache_miss_total");
    CHECK(miss.value() >= 1.0);

    // Second call within TTL -- cache warm -> hit.
    auto r2 = h.sink.Get("/api/v1/viz/fleet/topology");
    REQUIRE(r2);
    CHECK(r2->status == 200);

    auto& hit = h.metrics.counter("yuzu_viz_cache_hit_total");
    CHECK(hit.value() >= 1.0);
}

TEST_CASE("REST viz: 413 path increments oversize metric", "[viz][routes][metrics]") {
    std::vector<RawAgentSnapshot> seed;
    for (int i = 0; i < 3; ++i)
        seed.push_back(mk_agent("a" + std::to_string(i), "h"));
    VizHarness h(std::move(seed));

    auto res = h.sink.Get("/api/v1/viz/fleet/topology?machines_max=1");
    REQUIRE(res);
    CHECK(res->status == 413);

    auto& oversize = h.metrics.counter("yuzu_viz_oversize_response_total");
    CHECK(oversize.value() >= 1.0);
}

// =============================================================================
// include_vuln passes through (separate cache slot)
// =============================================================================

TEST_CASE("REST viz: include_vuln=1 returns include_vuln field set true", "[viz][routes][vuln]") {
    VizHarness h({mk_agent("a", "h")});
    auto res = h.sink.Get("/api/v1/viz/fleet/topology?include_vuln=1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto j = json::parse(res->body);
    CHECK(j.value("include_vuln", false) == true);
}
