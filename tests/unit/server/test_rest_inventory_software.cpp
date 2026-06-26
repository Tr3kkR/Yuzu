// test_rest_inventory_software.cpp — HTTP-level tests for the typed
// installed-software fleet read GET /api/v1/inventory/software (ADR-0016).
//
// This is the REST sibling of the governed MCP query_installed_software tool; the
// route mirrors that handler 1:1. The tests pin the REST-specific surface:
//   - Inventory:Read gate (RBAC deny → no data).
//   - Two DISTINCT 503 paths, both asserted "never an empty 200":
//       * null/closed store → 503 "not available", NO audit (the store was never
//         consulted, so there is no access to record);
//       * OPEN store, query_software → std::nullopt (pool-acquire timeout / query
//         error) → 503 "degraded" AND a "failure" audit row (CC7.2: a triage caller
//         under a sustained outage still leaves a who/when/what trail). These are
//         NOT the same path — they differ precisely in the audit emission — so both
//         are tested here (the degrade path via a size-1 pool whose only lease is
//         held in-test, forcing try_acquire_for to time out).
//   - Management-group scope FILTER (drops out-of-scope agents) + devices_omitted +
//     a distinct "denied" audit row.
//   - limit cap → result_truncated_by_cap; bad limit → 400.
//   - OpenAPI discoverability (A1): the path appears in /api/v1/openapi.json.
//
// Fixture mirrors the in-process TestRouteSink pattern (no socket, no acceptor
// thread, no TSan risk) from test_rest_software_packages.cpp.

#include "rest_api_v1.hpp"
#include "pg/pg_pool.hpp"
#include "software_inventory_store.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

// Wires GET /api/v1/inventory/software with a (borrowed, possibly null) typed
// store + a delegating scope predicate. `allow_perm`, `session_user`, and
// `scope_fn` are mutable so a single fixture instance can drive each branch.
struct InvHarness {
    yuzu::server::test::TestRouteSink sink;

    std::string session_user{"admin"};
    bool allow_perm{true};
    // null = unwired-equivalent (predicate always allows → no drops); set it to a
    // real allow/deny lambda to exercise the scope filter.
    std::function<bool(const std::string&, const std::string&)> scope_fn;
    std::vector<AuditRecord> audit_log;

    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    explicit InvHarness(SoftwareInventoryStore* store) {
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (session_user.empty()) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = session_user;
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (!allow_perm) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            return true;
        };
        // Always pass a non-null predicate that delegates to scope_fn; when scope_fn
        // is unset it allows every agent (legacy-open equivalent → no drops).
        RestApiV1::InventoryScopeFn inv_scope =
            [this](const std::string& u, const std::string& a) -> bool {
            return scope_fn ? scope_fn(u, a) : true;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr, /*quarantine_store=*/nullptr,
                            /*response_store=*/nullptr, /*instruction_store=*/nullptr,
                            /*execution_tracker=*/nullptr, /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr, /*service_group_fn=*/{}, /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr, /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/&metrics, /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{}, /*step_up_fn=*/{}, /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{}, /*net_perf_fn=*/{}, /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{}, store,
                            std::move(inv_scope));
    }

    bool has_audit(const std::string& result) const {
        for (const auto& a : audit_log)
            if (a.action == "inventory.software.query" && a.result == result)
                return true;
        return false;
    }
};

} // namespace

// ── No-PG branches (always run) ──────────────────────────────────────────────

TEST_CASE("REST inventory/software: null store → 503, never an empty 200",
          "[rest][inventory_software]") {
    InvHarness h{/*store=*/nullptr};
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    CHECK(res->status == 503);
    // A4 error envelope + correlation id echoed on every path.
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    CHECK(res->body.find("\"error\"") != std::string::npos);
    // Crucially NOT a success-with-empty-list (the fail-open A4 violation ADR-0016 §7
    // closes): a vuln-triage caller must read "unknown", not "installed nowhere".
    CHECK(res->body.find("\"software\"") == std::string::npos);
}

TEST_CASE("REST inventory/software: RBAC deny → 403, no success audit",
          "[rest][inventory_software][security]") {
    InvHarness h{/*store=*/nullptr};
    h.allow_perm = false;
    auto res = h.sink.Get("/api/v1/inventory/software?name=Chrome");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK_FALSE(h.has_audit("success"));
}

TEST_CASE("REST inventory/software: path is in the OpenAPI spec (A1 discoverability)",
          "[rest][inventory_software]") {
    InvHarness h{/*store=*/nullptr};
    auto res = h.sink.Get("/api/v1/openapi.json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto spec = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(spec.is_discarded());
    REQUIRE(spec.contains("paths"));
    REQUIRE(spec["paths"].contains("/inventory/software"));
    CHECK(spec["paths"]["/inventory/software"].contains("get"));
}

// ── Live-PG branches ─────────────────────────────────────────────────────────

namespace {
// Seed one agent's machine-scope software via the store's own ingest path.
void seed(SoftwareInventoryStore& store, const std::string& agent,
          std::vector<SoftwareEntry> rows) {
    const std::string h = SoftwareInventoryStore::canonical_hash(rows);
    REQUIRE(store.apply_installed_software(agent, h, rows, 1000) ==
            InventoryIngestOutcome::kStored);
}
} // namespace

TEST_CASE("REST inventory/software: fleet read returns rows, count, devices_omitted=0",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Google Chrome", "119", "Google", "2026-01-01"},
                          {"Firefox", "120", "Mozilla", ""}});

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& data = body.at("data");
    CHECK(data.at("count").get<int>() == 2);
    CHECK(data.at("devices_omitted").get<int>() == 0);
    CHECK(data.at("software").size() == 2);
    CHECK_FALSE(data.contains("result_truncated_by_cap"));
    CHECK(h.has_audit("success"));
    CHECK_FALSE(h.has_audit("denied"));
}

TEST_CASE("REST inventory/software: name filter narrows the fleet result",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Google Chrome", "119", "Google", ""}, {"Slack", "4.0", "Slack", ""}});
    seed(store, "dev-b", {{"Google Chrome", "120", "Google", ""}});

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?name=Google Chrome");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& sw = body.at("data").at("software");
    REQUIRE(sw.size() == 2); // one per agent, both Chrome
    for (const auto& row : sw)
        CHECK(row.at("name").get<std::string>() == "Google Chrome");
}

TEST_CASE("REST inventory/software: scope filter drops out-of-scope agent + audits denied",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"Google Chrome", "119", "Google", ""}});
    seed(store, "dev-b", {{"Google Chrome", "120", "Google", ""}});

    InvHarness h{&store};
    // Operator may see dev-a only — dev-b's row must be dropped (not leaked).
    h.scope_fn = [](const std::string&, const std::string& agent) { return agent == "dev-a"; };

    auto res = h.sink.Get("/api/v1/inventory/software?name=Google Chrome");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& data = body.at("data");
    REQUIRE(data.at("software").size() == 1);
    CHECK(data.at("software")[0].at("agent_id").get<std::string>() == "dev-a");
    // The false-negative guard: a positive count tells the caller matching software
    // exists outside their scope (not "absent fleet-wide").
    CHECK(data.at("devices_omitted").get<int>() == 1);
    CHECK(h.has_audit("denied"));
    CHECK(h.has_audit("success"));
}

TEST_CASE("REST inventory/software: limit cap flags result_truncated_by_cap",
          "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    seed(store, "dev-a", {{"AAA", "1", "", ""}, {"BBB", "1", "", ""}, {"CCC", "1", "", ""}});

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?limit=1");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& data = body.at("data");
    CHECK(data.at("count").get<int>() == 1);
    CHECK(data.at("result_truncated_by_cap").get<bool>() == true);
}

TEST_CASE("REST inventory/software: non-integer limit → 400", "[pg][rest][inventory_software]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?limit=abc");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("REST inventory/software: store degrade → 503 + failure audit, never empty",
          "[pg][rest][inventory_software][security]") {
    YUZU_REQUIRE_PG_DB(db);
    // size-1 pool: after the ctor migration releases its lease, the single connection
    // is free. We hold it for the duration of the request, so query_software's
    // try_acquire_for(kQueryAcquireTimeout) times out → std::nullopt → the route's
    // DEGRADE branch (distinct from null-store: it audits "failure"). This is the
    // authoritative-read contract (ADR-0016 §7) that drew a BLOCKING last round.
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    auto held = pool.acquire(); // starve the pool — the only connection is now ours
    InvHarness h{&store};
    auto res = h.sink.Get("/api/v1/inventory/software?name=Chrome");
    REQUIRE(res);
    CHECK(res->status == 503);
    // NEVER a success-with-empty-list: the body must not carry a software array.
    CHECK(res->body.find("\"software\"") == std::string::npos);
    CHECK_FALSE(res->get_header_value("X-Correlation-Id").empty());
    // The degrade path is distinct from null-store precisely in this audit emission.
    CHECK(h.has_audit("failure"));
    CHECK_FALSE(h.has_audit("success"));
}
