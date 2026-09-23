/**
 * test_guardian_routes.cpp — handler-level coverage for the Guardian dashboard
 * Baseline routes (POST /fragments/guardian/baseline*). Governance Gate-3 QA
 * found these handlers had zero handler-level tests — only the BaselineStore
 * underneath was covered, leaving the access-control surface (403 on Write /
 * Push / Delete) and the deploy fleet-convergence logic untested.
 *
 * Pattern follows test_rest_guaranteed_state.cpp: register GuardianRoutes
 * against an in-process TestRouteSink (the HttpRouteSink seam) and dispatch
 * synthesised requests through the captured handlers. No real HTTP server, no
 * acceptor thread, no #438 TSan trap.
 *
 * Form fields are supplied via the request's query string: httplib merges URL
 * query params and x-www-form-urlencoded body params into one req.params map,
 * and the handlers read req.get_param_value(...), so a query-string param is
 * indistinguishable from a posted form field to the handler under test.
 *
 * Coverage:
 *   - create: form → store round-trip + audit; dup-name conflict (inline 200);
 *     403 when Write is denied
 *   - deploy: lifecycle→deployed + snapshot written + push fan-out invoked +
 *     audit; 403 when Push is denied (and no push fired)
 *   - delete: removes the row; a deployed Baseline triggers a convergence push;
 *     403 when Delete is denied
 *   - SECURITY PROPERTY: editing a *deployed* Baseline's members does NOT change
 *     what the fleet enforces (deployed_member_rule_ids stays on the snapshot)
 *     until a Push-gated re-deploy — the membership half of the Write-without-
 *     Push fix.
 */

#include "baseline_store.hpp"
#include "guardian_routes.hpp"
#include "guaranteed_state_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_route_sink.hpp"
#include "web_utils.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every
// Harness below constructs its own GuaranteedStateStore against a clone of
// this schema (ADR-0038 migration). Shared key "guardianstate" with every
// other GuaranteedStateStore test file — same setup callback shape, so the
// shared-key REPLAY verification (test_helpers.hpp) passes.
yuzu::test::PgTestTemplate guardianstate_tpl{"guardianstate", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("guardianstate template: store failed to migrate");
}};

// Shared key "baselinestore" — SAME setup-callback shape as
// test_baseline_store.cpp's own template (ADR-0055 migration), so the
// shared-key replay verification (test_helpers.hpp) passes.
yuzu::test::PgTestTemplate baselinestore_tpl{"baselinestore", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    BaselineStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("baselinestore template: store failed to migrate");
}};

GuaranteedStateRuleRow make_rule(std::string rule_id, std::string name) {
    GuaranteedStateRuleRow r;
    r.rule_id = std::move(rule_id);
    r.name = std::move(name);
    r.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: GuaranteedStateRule\n";
    r.version = 1;
    r.enabled = true;
    r.enforcement_mode = "enforce";
    r.severity = "high";
    r.os_target = "windows";
    r.scope_expr = "";
    r.created_at = "2026-06-05T12:00:00Z";
    r.updated_at = "2026-06-05T12:00:00Z";
    r.created_by = "alice";
    r.updated_by = "alice";
    return r;
}

// #4252: make_rule() leaves spec_json empty, so its rule always falls back to
// the OS-only rule under guardian::guardian_guard_supported_on_platform. This
// variant stamps a minimal spec_json carrying a real spark.type (the input the
// guard-type-aware check actually reads), for tests exercising Service-vs-
// Registry/File platform-support differences. `os_target` defaults to "" (all
// OSes) since these tests need to reach agents on multiple platforms from one
// rule.
GuaranteedStateRuleRow make_rule_with_spark(std::string rule_id, std::string name,
                                            std::string spark_type, std::string os_target = "") {
    GuaranteedStateRuleRow r = make_rule(std::move(rule_id), std::move(name));
    r.os_target = std::move(os_target);
    r.spec_json = R"({"spark":{"type":")" + spark_type + R"("},"assertion":{},"remediation":{}})";
    return r;
}

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

// Original fictional application data; not derived from a third-party benchmark.
nlohmann::json benchmark_test_catalog() {
    return {{"expected_revision", 0}, {"catalog", {
        {"name", "Example application settings"}, {"version", "1.0"},
        {"controls", nlohmann::json::array({{
            {"control_id", "demo.cache.1"}, {"title", "Demo cache slots <script>alert(1)</script>"},
            {"profile", "L1"}, {"benchmark_value", "7 or more"}, {"suggested_value", "7"},
            {"suggested_rationale", "Example cache capacity for a fictional application"},
            {"sources", nlohmann::json::array({{{"url", "https://example.org/demo-settings"},
                {"title", "Synthetic example catalog"}, {"kind", "Benchmark"}}})}
        }})}
    }}};
}

struct PushCall {
    std::string scope;
    bool full_sync;
};

// Harness: real GuaranteedStateStore (Postgres, ADR-0038) + BaselineStore
// (Postgres, ADR-0055) behind GuardianRoutes, dispatched through TestRouteSink.
// `gs_db_pg`/`gs_pool` come FIRST (before `store`) so they outlive it even if
// construction throws. Mirrors AuthDbPg's shape exactly
// (test_auth_db_pg_helper.hpp): `gs_db_pg` stays `std::optional` and is
// `.emplace()`d only AFTER the Harness() body's own SKIP check — constructing
// PostgresTestDb unconditionally (e.g. via a default member-initializer) would
// touch Postgres before the SKIP-when-unconfigured check runs.
struct Harness {
    std::optional<yuzu::test::PostgresTestDb> gs_db_pg;
    std::optional<yuzu::server::pg::PgPool> gs_pool;
    // Separate clone + pool from gs_db_pg/gs_pool above (ADR-0055 migration,
    // its own "baselinestore" template) — BaselineStore and
    // GuaranteedStateStore are independent Postgres schemas; a single shared
    // clone would need a THIRD, harness-specific template key mirroring the
    // structural union of both, which no other file needs (test_access_
    // review_model.cpp's RbacStore/EnginePrincipalStore harness is the same
    // shape: one pool per store).
    std::optional<yuzu::test::PostgresTestDb> bl_db_pg;
    std::optional<yuzu::server::pg::PgPool> bl_pool;

    std::unique_ptr<GuaranteedStateStore> store;
    std::unique_ptr<BaselineStore> baselines;

    std::string session_user{"alice"};
    auth::Role session_role{auth::Role::admin};
    // Non-empty simulates a service-scoped API token session (SEC-2: the
    // fleet-wide/identity-bearing Guardian fragments blanket-deny these —
    // perm_fn_'s service-token branch checks only the ITServiceOwner role,
    // never the token's own service-tag scope). Default empty preserves every
    // other test's ordinary-operator session.
    std::string session_token_scope_service;

    // "Securable:Operation" entries the perm_fn should DENY (default: grant all).
    std::set<std::string> denied;

    // Registry JSON the agents_json_fn returns — tests set this to inject connected
    // agents (with "os") so the platform "not implemented" fold can be exercised.
    std::string agents_json{"[]"};

    std::vector<AuditRecord> audit_log;
    bool throw_audit{false};
    std::vector<PushCall> pushes;

    // Real MetricsRegistry (#4252) so tests can assert on
    // yuzu_server_guardian_platform_matrix_stale_total{spark_type} — the
    // detectability signal for the double-count exclusion predicate.
    yuzu::MetricsRegistry metrics;

    GuardianRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    // Default true: every existing test wires the real `metrics` member above.
    // `Harness(/*with_metrics=*/false)` exercises the `metrics_ == nullptr`
    // degrade path (the nullable-dependency default `register_routes` itself
    // documents) — cpp-safety flagged this path as untested in the #4252 Gate 3
    // review.
    explicit Harness(bool with_metrics = true) {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        gs_db_pg.emplace(guardianstate_tpl);
        INFO("[Harness] guaranteed-state fixture status (blank == database came up OK): "
             << gs_db_pg->error());
        REQUIRE(gs_db_pg->available());
        gs_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = gs_db_pg->dsn(), .size = 4});
        REQUIRE(gs_pool->valid());
        store = std::make_unique<GuaranteedStateStore>(*gs_pool);
        REQUIRE(store->is_open());

        bl_db_pg.emplace(baselinestore_tpl);
        INFO("[Harness] baseline fixture status (blank == database came up OK): "
             << bl_db_pg->error());
        REQUIRE(bl_db_pg->available());
        bl_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = bl_db_pg->dsn(), .size = 4});
        REQUIRE(bl_pool->valid());
        baselines = std::make_unique<BaselineStore>(*bl_pool);
        REQUIRE(baselines->is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
            s.token_scope_service = session_token_scope_service;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& securable, const std::string& op) -> bool {
            if (denied.count(securable + ":" + op)) {
                res.status = 403; // mirror production: the perm_fn owns the 403.
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) {
            if (throw_audit) throw std::runtime_error("test audit unavailable");
            audit_log.push_back({action, result, target_id, detail});
        };
        auto emit_fn = [](const std::string&, const httplib::Request&, const nlohmann::json&,
                          const nlohmann::json&) {};
        auto agents_json_fn = [this]() -> std::string { return agents_json; };
        auto push_fn = [this](const std::string& scope, bool full_sync) -> int {
            pushes.push_back({scope, full_sync});
            return 1;
        };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn, emit_fn, store.get(),
                               baselines.get(), agents_json_fn, push_fn,
                               with_metrics ? &metrics : nullptr);
    }

    void seed_guard(const std::string& rule_id, const std::string& name) {
        REQUIRE(store->create_rule(make_rule(rule_id, name)));
    }

    // Seed a rule directly (bypassing seed_guard's plain make_rule) — for tests
    // that need a real spark.type (#4252 guard-type-aware platform support).
    void seed_rule(const GuaranteedStateRuleRow& rule) {
        REQUIRE(store->create_rule(rule));
    }

    // Seed a real (agent, rule) status row via a Guardian event — mirrors
    // RestGsHarness::seed_status in test_rest_guaranteed_state.cpp. event_type
    // drives the derived state per event_state_from_type (guaranteed_state_
    // store.cpp): "guard.compliant"/"drift.remediated" -> compliant,
    // "drift.detected" -> drifted, "guard.unhealthy" -> errored. The upsert
    // keeps a row only when the new updated_at >= the existing one, so reuse a
    // strictly increasing ts per (agent, rule) across multiple seeds.
    void seed_status(const std::string& event_id, const std::string& agent_id,
                     const std::string& rule_id, const std::string& event_type,
                     const std::string& ts = "2026-09-01T00:00:00Z") {
        GuaranteedStateEventRow e;
        e.event_id = event_id;
        e.rule_id = rule_id;
        e.agent_id = agent_id;
        e.event_type = event_type;
        e.severity = "info";
        e.timestamp = ts;
        REQUIRE(store->insert_event(e).has_value());
    }

    // Set up a Baseline directly in the store (state setup for deploy/edit/delete
    // handler tests). Uses a caller-supplied id so the route path is predictable.
    void seed_baseline(const std::string& id, const std::string& name,
                       const std::vector<std::string>& member_rule_ids) {
        Baseline b;
        b.baseline_id = id;
        b.name = name;
        REQUIRE(baselines->create_baseline(b));
        if (!member_rule_ids.empty())
            REQUIRE(baselines->set_members(id, member_rule_ids));
    }

    int audit_count(const std::string& action, const std::string& result) const {
        int n = 0;
        for (const auto& a : audit_log)
            if (a.action == action && a.result == result)
                ++n;
        return n;
    }

    std::optional<Baseline> baseline_named(const std::string& name) const {
        for (auto& b : baselines->list_baselines())
            if (b.name == name)
                return b;
        return std::nullopt;
    }
};

constexpr const char* kBaselinesPath = "/fragments/guardian/baselines";

} // namespace

TEST_CASE("create_baseline_from_form persists the Baseline + members + audit",
          "[pg][guardian_routes][baseline][create]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_guard("g2", "GuardTwo");

    auto res = h.sink.dispatch("POST",
                               std::string(kBaselinesPath) + "?name=BL1&guards=GuardOne&guards=GuardTwo",
                               /*body=*/"", "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);

    auto bl = h.baseline_named("BL1");
    REQUIRE(bl.has_value());
    CHECK(bl->lifecycle == kBaselineDraft);
    auto members = h.baselines->get_members(bl->baseline_id);
    CHECK(members.size() == 2);
    CHECK(h.audit_count("guaranteed_state.baseline.create", "success") == 1);
}

TEST_CASE("create_baseline_from_form reports a duplicate name without a second row",
          "[pg][guardian_routes][baseline][create][conflict]") {
    Harness h;
    auto path = std::string(kBaselinesPath) + "?name=Dupe";
    REQUIRE(h.sink.dispatch("POST", path, "", "application/x-www-form-urlencoded") != nullptr);

    auto res = h.sink.dispatch("POST", path, "", "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    // htmx does not swap 4xx bodies, so the conflict surfaces as 200 + a banner.
    CHECK(res->status == 200);
    CHECK(res->body.find("already exists") != std::string::npos);
    CHECK(h.baselines->list_baselines().size() == 1);
}

TEST_CASE("create_baseline_from_form is gated on GuaranteedState:Write",
          "[pg][guardian_routes][baseline][create][rbac]") {
    Harness h;
    h.denied = {"GuaranteedState:Write"};

    auto res = h.sink.dispatch("POST", std::string(kBaselinesPath) + "?name=BL1", "",
                               "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    CHECK(res->status == 403);
    CHECK(h.baselines->list_baselines().empty());
    CHECK(h.audit_count("guaranteed_state.baseline.create", "success") == 0);
}

TEST_CASE("deploy_baseline marks deployed, writes the snapshot, and pushes fleet-wide",
          "[pg][guardian_routes][baseline][deploy]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_baseline("bl1", "BL1", {"g1"});

    auto res = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/deploy", "",
                               "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);

    auto bl = h.baselines->get_baseline("bl1");
    REQUIRE(bl.has_value());
    CHECK(bl->lifecycle == kBaselineDeployed);
    CHECK_FALSE(bl->deployed_snapshot.empty());

    // Fleet convergence: exactly one full_sync push, and the gate now enforces g1.
    REQUIRE(h.pushes.size() == 1);
    CHECK(h.pushes[0].full_sync == true);
    auto enforced = h.baselines->deployed_member_rule_ids();
    REQUIRE(enforced.has_value());
    CHECK(enforced->count("g1") == 1);
    CHECK(h.audit_count("guaranteed_state.baseline.deploy", "success") == 1);
}

TEST_CASE("deploy_baseline is gated on GuaranteedState:Push (no push when denied)",
          "[pg][guardian_routes][baseline][deploy][rbac]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_baseline("bl1", "BL1", {"g1"});
    h.denied = {"GuaranteedState:Push"};

    auto res = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/deploy", "",
                               "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    CHECK(res->status == 403);

    auto bl = h.baselines->get_baseline("bl1");
    REQUIRE(bl.has_value());
    CHECK(bl->lifecycle == kBaselineDraft); // still a draft
    CHECK(h.pushes.empty());                // the fleet was never touched
    auto enforced = h.baselines->deployed_member_rule_ids();
    REQUIRE(enforced.has_value());
    CHECK(enforced->empty());
}

TEST_CASE("deploy_baseline on a store degraded AFTER open reports degraded, never "
          "\"Baseline not found\"",
          "[pg][guardian_routes][baseline][deploy][degraded]") {
    // Pins governance UP-3 / the store_ok fix: get_baseline's is_open() is a
    // bool cached at construction, never re-probed, so a connection lost
    // AFTER open (not before) reaches a REAL query failure, not the trivial
    // "never opened" guard case. Pattern: test_access_review_model.cpp's R1
    // (`engine_db.reset()` mid-test, dropping the database out from under an
    // already-`is_open()==true` store). Also pins the compliance-officer
    // finding that the "degraded" audit emission on deploy_baseline was
    // itself untested.
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_baseline("bl1", "BL1", {"g1"}); // genuinely exists before the drop

    h.bl_db_pg.reset(); // DROP DATABASE ... WITH (FORCE) — kills bl_pool's connections

    auto res = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/deploy", "",
                               "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200); // errors render inline in the modal, not as an HTTP error
    CHECK(res->body.find("degraded") != std::string::npos);
    CHECK(res->body.find("not found") == std::string::npos); // must NOT misreport as absent

    CHECK(h.audit_count("guaranteed_state.baseline.deploy", "degraded") == 1);
    CHECK(h.audit_count("guaranteed_state.baseline.deploy", "denied") == 0);
    CHECK(h.pushes.empty()); // never reached the push fan-out
}

// ═════════════════════════════════════════════════════════════════════════
// Governance finding SEC-2 (governance.d/4037-guardian-read-twins.*.jsonl):
// ADR-0038 fix — a degraded agent_rule_statuses() read on the per-guard and
// per-baseline detail pages now renders a distinct "degraded" placeholder,
// never a silent empty census indistinguishable from "no devices report
// this guard/baseline". Sabotages ONLY the census table
// (guardian_agent_rule_status) via a raw connection — NOT the
// gs_db_pg.reset()/DROP-DATABASE pattern the deploy_baseline degrade test
// above uses — because get_rule() (a DIFFERENT table,
// guaranteed_state_rules) must keep succeeding so the page reaches the
// census read instead of falling through to the earlier, differently-
// handled "Guard/Baseline not found" placeholder (get_rule's own degrade
// posture is a separate, pre-existing, out-of-#4037-scope case — see its
// comment above real_rule's assignment).
// ═════════════════════════════════════════════════════════════════════════

TEST_CASE("guard detail page: a degraded status read renders a degrade placeholder, "
          "never an empty census",
          "[pg][guardian_routes][guard][degraded][adr0038]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.agents_json = R"([{"agent_id":"WS-1","hostname":"ws1","os":"windows"}])";

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.gs_db_pg->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE guaranteed_state_store.guardian_agent_rule_status")};
        REQUIRE(d.ok());
    }

    auto res = h.sink.Get("/fragments/guardian/guard/g1/page");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200); // fragments render inline, not as an HTTP error
    CHECK(res->body.find("degraded") != std::string::npos);
    // Must NOT render as though zero devices report this guard, and must not
    // fall through to the earlier "Guard not found" placeholder either — the
    // guard genuinely exists (get_rule still succeeds), only the status read
    // failed.
    CHECK(res->body.find("Guard not found") == std::string::npos);
}

TEST_CASE("baseline detail page: a degraded status read renders a degrade placeholder, "
          "never an empty per-member rollup",
          "[pg][guardian_routes][baseline][degraded][adr0038]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_baseline("bl1", "BL1", {"g1"});

    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.gs_db_pg->dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        yuzu::server::pg::PgResult d{
            PQexec(conn.get(), "DROP TABLE guaranteed_state_store.guardian_agent_rule_status")};
        REQUIRE(d.ok());
    }

    auto res = h.sink.Get("/fragments/guardian/baseline/bl1/page");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    CHECK(res->body.find("degraded") != std::string::npos);
    CHECK(res->body.find("Baseline not found") == std::string::npos);
}

TEST_CASE("editing a deployed Baseline does not change what the fleet enforces until re-deploy",
          "[pg][guardian_routes][baseline][snapshot][security]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_guard("g2", "GuardTwo");
    h.seed_baseline("bl1", "BL1", {"g1"});

    // Deploy with just g1 → that is the enforced set.
    REQUIRE(h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/deploy", "",
                            "application/x-www-form-urlencoded") != nullptr);
    {
        auto enforced = h.baselines->deployed_member_rule_ids();
        REQUIRE(enforced.has_value());
        CHECK(enforced->size() == 1);
        CHECK(enforced->count("g1") == 1);
    }
    const std::size_t pushes_after_deploy = h.pushes.size();

    // Edit members to {g1, g2} via the Write-gated update handler (no re-deploy).
    auto res = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1?name=BL1&guards=GuardOne&guards=GuardTwo",
                               "", "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);

    // Live membership changed...
    CHECK(h.baselines->get_members("bl1").size() == 2);
    // ...but the ENFORCED set (the deployed snapshot) did NOT — and no push fired.
    {
        auto enforced = h.baselines->deployed_member_rule_ids();
        REQUIRE(enforced.has_value());
        CHECK(enforced->size() == 1);
        CHECK(enforced->count("g1") == 1);
        CHECK(enforced->count("g2") == 0);
    }
    CHECK(h.pushes.size() == pushes_after_deploy); // update did not converge the fleet

    // A Push-gated re-deploy is what promotes the edit to the enforced set.
    REQUIRE(h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/deploy", "",
                            "application/x-www-form-urlencoded") != nullptr);
    auto enforced = h.baselines->deployed_member_rule_ids();
    REQUIRE(enforced.has_value());
    CHECK(enforced->size() == 2);
    CHECK(enforced->count("g2") == 1);
}

TEST_CASE("delete_baseline_action removes a deployed Baseline and converges the fleet",
          "[pg][guardian_routes][baseline][delete]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_baseline("bl1", "BL1", {"g1"});
    REQUIRE(h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/deploy", "",
                            "application/x-www-form-urlencoded") != nullptr);
    const std::size_t pushes_before_delete = h.pushes.size();

    auto res = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/delete", "",
                               "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);

    CHECK_FALSE(h.baselines->get_baseline("bl1").has_value());
    auto enforced_after_delete = h.baselines->deployed_member_rule_ids();
    REQUIRE(enforced_after_delete.has_value());
    CHECK(enforced_after_delete->empty());
    CHECK(h.pushes.size() == pushes_before_delete + 1); // convergence push for the removed set
    CHECK(h.audit_count("guaranteed_state.baseline.delete", "success") == 1);
}

TEST_CASE("delete_baseline_action is gated on GuaranteedState:Delete",
          "[pg][guardian_routes][baseline][delete][rbac]") {
    Harness h;
    h.seed_baseline("bl1", "BL1", {});
    h.denied = {"GuaranteedState:Delete"};

    auto res = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/delete", "",
                               "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    CHECK(res->status == 403);
    CHECK(h.baselines->get_baseline("bl1").has_value()); // still there
    CHECK(h.pushes.empty());                             // the fleet was never touched
}

TEST_CASE("update_baseline_from_form is gated on GuaranteedState:Write",
          "[pg][guardian_routes][baseline][update][rbac]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_baseline("bl1", "BL1", {"g1"});
    h.denied = {"GuaranteedState:Write"};

    auto res = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1?name=Renamed", "",
                               "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    CHECK(res->status == 403);
    auto bl = h.baselines->get_baseline("bl1");
    REQUIRE(bl.has_value());
    CHECK(bl->name == "BL1");                          // rename did not happen
    CHECK(h.baselines->get_members("bl1").size() == 1); // members untouched
}

TEST_CASE("create_baseline_from_form rejects an unknown member Guard name",
          "[pg][guardian_routes][baseline][create]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");

    auto res = h.sink.dispatch(
        "POST", std::string(kBaselinesPath) + "?name=BL1&guards=GuardOne&guards=NoSuchGuard", "",
        "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200); // htmx inline-banner convention
    CHECK(res->body.find("Unknown Guard") != std::string::npos);
    // The unknown name is rejected before the Baseline is created — nothing persists.
    CHECK(h.baselines->list_baselines().empty());
}

// ── Full-page detail routes (governance Gate-3 QA: the /page fragments + page
//    shells had zero handler-level tests; the GuaranteedState:Read gate and the
//    shell auth-redirect are the access-control properties these lock). ─────────

TEST_CASE("guard/baseline /page fragments are gated on GuaranteedState:Read",
          "[pg][guardian_routes][page][rbac]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_baseline("bl1", "BL1", {"g1"});
    h.denied = {"GuaranteedState:Read"};

    auto g = h.sink.dispatch("GET", "/fragments/guardian/guard/g1/page", "", "");
    REQUIRE(g != nullptr);
    CHECK(g->status == 403);
    auto b = h.sink.dispatch("GET", "/fragments/guardian/baseline/bl1/page", "", "");
    REQUIRE(b != nullptr);
    CHECK(b->status == 403);
}

// ── SEC-2 regression coverage: a service-scoped API token (e.g. a token
// carrying the seeded ITServiceOwner role's GuaranteedState:Read grant) must
// be blanket-denied on every fleet-wide/identity-bearing Guardian fragment —
// perm_fn_'s service-token branch checks only the ITServiceOwner ROLE, never
// the token's own service-tag scope, so perm_fn_ alone is not confinement.
// /status and /guards/ /events had NO permission-gate test at all before this. ──

TEST_CASE("Guardian data fragments deny a service-scoped token, regardless of "
          "GuaranteedState:Read",
          "[pg][guardian_routes][rbac][security]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_baseline("bl1", "BL1", {"g1"});
    h.session_token_scope_service = "printers"; // any non-empty service scope

    auto status = h.sink.dispatch("GET", "/fragments/guardian/status", "", "");
    REQUIRE(status != nullptr);
    CHECK(status->status == 403);

    auto guards = h.sink.dispatch("GET", "/fragments/guardian/guards", "", "");
    REQUIRE(guards != nullptr);
    CHECK(guards->status == 403);

    auto events = h.sink.dispatch("GET", "/fragments/guardian/events", "", "");
    REQUIRE(events != nullptr);
    CHECK(events->status == 403);

    auto guard_page = h.sink.dispatch("GET", "/fragments/guardian/guard/g1/page", "", "");
    REQUIRE(guard_page != nullptr);
    CHECK(guard_page->status == 403);
    CHECK(guard_page->body.find("GuardOne") == std::string::npos); // no identity leaked

    auto baselines = h.sink.dispatch("GET", "/fragments/guardian/baselines", "", "");
    REQUIRE(baselines != nullptr);
    CHECK(baselines->status == 403);

    auto baseline_page = h.sink.dispatch("GET", "/fragments/guardian/baseline/bl1/page", "", "");
    REQUIRE(baseline_page != nullptr);
    CHECK(baseline_page->status == 403);

    // Important finding from external review (PR #3156): the create/edit
    // FORM fragments were missed alongside the data-bearing fragments above
    // - baseline-form and the edit form both seed a Member-guards datalist
    // from store_->list_rules(), disclosing the fleet-wide rule catalogue
    // (and, for edit, one baseline's own name + members) to an otherwise-
    // unconfined service-scoped token.
    auto guard_form = h.sink.dispatch("GET", "/fragments/guardian/guard-form", "", "");
    REQUIRE(guard_form != nullptr);
    CHECK(guard_form->status == 403);

    auto baseline_form = h.sink.dispatch("GET", "/fragments/guardian/baseline-form", "", "");
    REQUIRE(baseline_form != nullptr);
    CHECK(baseline_form->status == 403);

    auto baseline_edit = h.sink.dispatch("GET", "/fragments/guardian/baseline/bl1/edit", "", "");
    REQUIRE(baseline_edit != nullptr);
    CHECK(baseline_edit->status == 403);
    CHECK(baseline_edit->body.find("BL1") == std::string::npos); // no identity leaked
    CHECK(baseline_edit->body.find("GuardOne") == std::string::npos);

    // Denied before any READ audit (no evidence of unauthorized DATA access to
    // conflate with a legitimate one) — but the denial itself IS recorded, one
    // row per fragment probed, so a probing service token leaves a trace.
    REQUIRE(h.audit_log.size() == 9);
    for (const auto& a : h.audit_log) {
        CHECK(a.action == "guaranteed_state.fragment.access_denied");
        CHECK(a.result == "denied");
    }
}

TEST_CASE("status/guards/events fragments are gated on GuaranteedState:Read (previously untested)",
          "[pg][guardian_routes][rbac]") {
    Harness h;
    h.denied = {"GuaranteedState:Read"};

    auto status = h.sink.dispatch("GET", "/fragments/guardian/status", "", "");
    REQUIRE(status != nullptr);
    CHECK(status->status == 403);

    auto guards = h.sink.dispatch("GET", "/fragments/guardian/guards", "", "");
    REQUIRE(guards != nullptr);
    CHECK(guards->status == 403);

    auto events = h.sink.dispatch("GET", "/fragments/guardian/events", "", "");
    REQUIRE(events != nullptr);
    CHECK(events->status == 403);

    auto baselines = h.sink.dispatch("GET", "/fragments/guardian/baselines", "", "");
    REQUIRE(baselines != nullptr);
    CHECK(baselines->status == 403);
}

TEST_CASE("an ordinary (non-service-scoped) session still reaches every Guardian fragment",
          "[pg][guardian_routes][rbac]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_baseline("bl1", "BL1", {"g1"});
    // session_token_scope_service left empty (default) — the ordinary path.

    for (const char* path :
         {"/fragments/guardian/status", "/fragments/guardian/guards",
          "/fragments/guardian/events", "/fragments/guardian/guard/g1/page",
          "/fragments/guardian/baselines", "/fragments/guardian/baseline/bl1/page",
          "/fragments/guardian/guard-form", "/fragments/guardian/baseline-form",
          "/fragments/guardian/baseline/bl1/edit"}) {
        auto res = h.sink.dispatch("GET", path, "", "");
        REQUIRE(res != nullptr);
        CHECK(res->status == 200);
    }
}

// ── Governance finding (guardian-confinement-2298 Gate 2/4/5/6, six
// independent confirmations): the six MUTATING fragments below had NO
// service-scoped-token deny at all, unlike their six GET siblings above in
// this same file — deploy_baseline's fleet-wide full_sync push meant a
// service-scoped token could change what every OTHER service's agents
// enforce, not just read it. Mutation-tested per chaos-injector's CH-1
// design: this test was confirmed to fail (403 becomes 200, h.pushes gains
// an entry) when deny_service_scoped_mutation_'s call sites are reverted,
// before being restored to this passing state. ──

TEST_CASE("Guardian MUTATING fragments deny a service-scoped token, regardless of "
          "GuaranteedState:Write/Push/Delete, and nothing changes",
          "[pg][guardian_routes][rbac][security]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_baseline("bl1", "BL1", {"g1"});
    h.session_token_scope_service = "printers"; // any non-empty service scope

    auto create_guard = h.sink.dispatch("POST", "/fragments/guardian/guards?name=NewGuard", "",
                                        "application/x-www-form-urlencoded");
    REQUIRE(create_guard != nullptr);
    CHECK(create_guard->status == 403);

    auto enable = h.sink.dispatch("POST", "/fragments/guardian/guard/g1/enabled?value=0", "",
                                  "application/x-www-form-urlencoded");
    REQUIRE(enable != nullptr);
    CHECK(enable->status == 403);

    auto create_baseline = h.sink.dispatch("POST", "/fragments/guardian/baselines?name=NewBL", "",
                                           "application/x-www-form-urlencoded");
    REQUIRE(create_baseline != nullptr);
    CHECK(create_baseline->status == 403);

    auto deploy = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/deploy", "",
                                  "application/x-www-form-urlencoded");
    REQUIRE(deploy != nullptr);
    CHECK(deploy->status == 403);

    auto update = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1?name=Renamed", "",
                                  "application/x-www-form-urlencoded");
    REQUIRE(update != nullptr);
    CHECK(update->status == 403);

    auto del = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/delete", "",
                               "application/x-www-form-urlencoded");
    REQUIRE(del != nullptr);
    CHECK(del->status == 403);

    // The load-bearing assertions: NOT ONE of the six attempts had any effect.
    CHECK(h.pushes.empty()); // deploy never reached push_fn_ — no fleet convergence
    auto rules = h.store->list_rules();
    REQUIRE(rules.has_value());
    CHECK(rules->size() == 1); // still just g1 — create_guard never persisted
    auto g1 = h.store->get_rule("g1");
    REQUIRE(g1.has_value());
    REQUIRE(g1->has_value());
    CHECK((*g1)->enabled == true); // enable(value=0) never applied
    CHECK(h.baselines->list_baselines().size() == 1); // still just BL1 — create_baseline never persisted
    auto bl1 = h.baseline_named("BL1");
    REQUIRE(bl1.has_value());
    CHECK(bl1->lifecycle == kBaselineDraft); // deploy never applied
    CHECK(bl1->baseline_id == "bl1");        // delete never applied (still present)

    // Each denial reuses its own action's real success-path verb (result=denied)
    // — deliberately NOT a shared generic verb, since (unlike the read fragments'
    // /status etc., which have no per-open success audit to extend) all six of
    // these mutations already have one.
    REQUIRE(h.audit_log.size() == 6);
    const std::vector<std::string> expected_actions = {
        "guaranteed_state.rule.create",     "guaranteed_state.rule.update",
        "guaranteed_state.baseline.create", "guaranteed_state.baseline.deploy",
        "guaranteed_state.baseline.update", "guaranteed_state.baseline.delete"};
    for (std::size_t i = 0; i < h.audit_log.size(); ++i) {
        CHECK(h.audit_log[i].action == expected_actions[i]);
        CHECK(h.audit_log[i].result == "denied");
    }
}

TEST_CASE("Guardian mutating fragments are still gated on GuaranteedState:Write/Push/Delete "
          "(previously untested)",
          "[pg][guardian_routes][rbac]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_baseline("bl1", "BL1", {"g1"});
    h.denied = {"GuaranteedState:Write", "GuaranteedState:Push", "GuaranteedState:Delete"};

    auto create_guard = h.sink.dispatch("POST", "/fragments/guardian/guards?name=NewGuard", "",
                                        "application/x-www-form-urlencoded");
    REQUIRE(create_guard != nullptr);
    CHECK(create_guard->status == 403);

    auto deploy = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/deploy", "",
                                  "application/x-www-form-urlencoded");
    REQUIRE(deploy != nullptr);
    CHECK(deploy->status == 403);

    auto del = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/delete", "",
                               "application/x-www-form-urlencoded");
    REQUIRE(del != nullptr);
    CHECK(del->status == 403);
}

TEST_CASE("the per-guard drilldown emits a guaranteed_state.rule.view audit-on-open, scoped to "
          "the CORRECT guard",
          "[pg][guardian_routes][audit][security]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_guard("g2", "GuardTwo"); // a second guard in scope, to prove target_id isn't hardcoded

    auto res = h.sink.dispatch("GET", "/fragments/guardian/guard/g2/page", "", "");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    REQUIRE(h.audit_count("guaranteed_state.rule.view", "success") == 1);
    CHECK(h.audit_log[0].target_id == "g2"); // the OPENED guard, not the first-seeded one
    // Every other fragment is NOT the worst-disclosure surface and stays
    // un-audited (matches its existing set-and-proceed dashboard-read posture).
    CHECK(h.audit_log.size() == 1);
}

TEST_CASE("Guardian descriptions and risk rationale render as text on guard and baseline pages",
          "[pg][guardian_routes][page][metadata]") {
    Harness h;
    auto row = make_rule("g1", "Example guard metadata");
    row.description = "Require signing <script>alert(1)</script> & verification";
    row.rationale = "Mitigate relay <img src=x onerror=alert(1)> attacks";
    h.seed_rule(row);
    h.seed_baseline("bl1", "BL1", {"g1"});

    for (const auto* path : {"/fragments/guardian/guard/g1/page",
                             "/fragments/guardian/baseline/bl1/page"}) {
        auto res = h.sink.Get(path);
        REQUIRE(res != nullptr);
        CHECK(res->status == 200);
        CHECK(res->body.find("Example guard metadata") != std::string::npos);
        CHECK(res->body.find("Risk rationale") != std::string::npos);
        CHECK(res->body.find("&lt;script&gt;alert(1)&lt;/script&gt; &amp; verification") != std::string::npos);
        CHECK(res->body.find("&lt;img src=x onerror=alert(1)&gt;") != std::string::npos);
        CHECK(res->body.find("<script>alert(1)</script>") == std::string::npos);
        CHECK(res->body.find("<img src=x onerror=alert(1)>") == std::string::npos);
    }
    CHECK(h.pushes.empty()); // Metadata display never dispatches to an endpoint.
}

TEST_CASE("Guardian form persists description and rationale without changing audit posture",
          "[pg][guardian_routes][form][metadata]") {
    Harness h;
    auto res = h.sink.dispatch("POST", "/fragments/guardian/guards",
        "name=DescribedGuard&description=Required+configuration&rationale=Reduce+exposure&"
        "mode=watch&trigger_type=file-exists&file-exists__path=C%3A%5Cconfig.txt",
        "application/x-www-form-urlencoded");
    REQUIRE(res != nullptr);
    REQUIRE(res->status == 200);
    auto rules = h.store->list_rules();
    REQUIRE(rules.has_value());
    REQUIRE(rules->size() == 1);
    CHECK(rules->front().description == "Required configuration");
    CHECK(rules->front().rationale == "Reduce exposure");
    CHECK(rules->front().enforcement_mode == "audit");
    CHECK(h.pushes.empty());
}

TEST_CASE("Benchmark routes import review and export decisions without deploying policy",
          "[pg][guardian_routes][benchmark]") {
    Harness h;
    h.seed_guard("g1", "Existing guard");
    h.seed_baseline("bl1", "Existing baseline", {"g1"});
    REQUIRE(h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/deploy", "",
                            "application/x-www-form-urlencoded")->status == 200);
    h.pushes.clear();
    const auto before = h.baselines->get_baseline("bl1");
    REQUIRE(before);
    const auto generation = h.store->current_policy_generation();
    REQUIRE(generation);
    const auto guard_before = h.store->get_rule("g1");
    REQUIRE(guard_before);
    REQUIRE(*guard_before);
    const std::string api = "/api/v1/guaranteed-state/baselines/bl1/benchmark";
    REQUIRE(h.sink.Get(api)->status == 404);
    const auto empty_page = h.sink.Get("/fragments/guardian/baseline/bl1/decisions/page");
    REQUIRE(empty_page->status == 200);
    CHECK(empty_page->body.find("No benchmark catalog has been imported.") != std::string::npos);
    CHECK(empty_page->body.find("import_guardian_benchmark") != std::string::npos);
    CHECK(h.sink.Get("/fragments/guardian/baseline/missing/decisions/page")->status == 404);
    auto catalog = benchmark_test_catalog();
    catalog["catalog"]["controls"][0]["profile"] = "L2";
    catalog["catalog"]["controls"][0]["research_status"] = "Partial review <unverified>";
    auto imported = h.sink.Put(api, catalog.dump());
    REQUIRE(imported);
    REQUIRE(imported->status == 200);
    CHECK(nlohmann::json::parse(imported->body)["data"]["catalog_revision"] == 1);
    auto read = h.sink.Get(api);
    REQUIRE(read->status == 200);
    auto document = nlohmann::json::parse(read->body)["data"];
    CHECK(document["catalog"] == catalog["catalog"]);
    CHECK(document["decisions"].empty());
    CHECK(h.sink.Put(api, catalog.dump())->status == 409);

    const std::string decision_path = api + "/decisions/demo.cache.1";
    nlohmann::json decision{{"value", "7"}, {"rationale", "Example capacity <img src=x onerror=alert(1)>"},
        {"status", "reviewed"}, {"expected_revision", 0}, {"catalog_revision", 1}};
    auto saved = h.sink.Put(decision_path, decision.dump());
    REQUIRE(saved->status == 200);
    auto saved_data = nlohmann::json::parse(saved->body)["data"];
    CHECK(saved_data["revision"] == 1);
    CHECK(saved_data["catalog_revision"] == 1);
    CHECK(saved_data["updated_by"] == "alice");
    CHECK(h.sink.Put(decision_path, decision.dump())->status == 409);
    CHECK(h.sink.Put(api + "/decisions/unknown", decision.dump())->status == 404);

    for (const auto* path : {"/guardian/baseline/bl1/decisions/export",
                             "/fragments/guardian/baseline/bl1/decisions/page"}) {
        auto html = h.sink.Get(path);
        REQUIRE(html->status == 200);
        CHECK(html->body.find("&lt;script&gt;alert(1)&lt;/script&gt;") != std::string::npos);
        CHECK(html->body.find("&lt;img src=x onerror=alert(1)&gt;") != std::string::npos);
        CHECK(html->body.find("<img src=x onerror=alert(1)>") == std::string::npos);
    }
    auto exported = h.sink.Get(api + "/export?format=markdown");
    REQUIRE(exported->status == 200);
    CHECK(nlohmann::json::parse(exported->body)["data"]["format"] == "markdown");
    const auto markdown = nlohmann::json::parse(exported->body)["data"]["content"].get<std::string>();
    CHECK(markdown.find("<script>alert(1)</script>") == std::string::npos);
    CHECK(markdown.find("<img src=x onerror=alert(1)>") == std::string::npos);
    CHECK(markdown.find("&lt;script&gt;alert(1)&lt;/script&gt;") != std::string::npos);
    CHECK(markdown.find("&lt;img src=x onerror=alert(1)&gt;") != std::string::npos);
    CHECK(markdown.find("Level 2 additional hardening") != std::string::npos);
    CHECK(markdown.find("Research: Partial review &lt;unverified&gt;") != std::string::npos);
    CHECK(markdown.find("not benchmark authority") != std::string::npos);
    auto summary = h.sink.Get("/guardian/baseline/bl1/decisions/export");
    REQUIRE(summary->status == 200);
    CHECK(summary->body.find("Level 2 additional hardening") != std::string::npos);
    CHECK(summary->body.find("Research: Partial review &lt;unverified&gt;") != std::string::npos);
    CHECK(summary->body.find("not benchmark authority") != std::string::npos);
    CHECK(h.sink.Get(api + "/export?format=executable")->status == 400);

    catalog["expected_revision"] = 1;
    REQUIRE(h.sink.Put(api, catalog.dump())->status == 200);
    decision["expected_revision"] = 1;
    CHECK(h.sink.Put(decision_path, decision.dump())->status == 409); // Old catalog.
    auto stale_html = h.sink.Get("/guardian/baseline/bl1/decisions/export");
    REQUIRE(stale_html->status == 200);
    CHECK(stale_html->body.find("Catalog changed; review this previous decision.") != std::string::npos);
    auto after = h.baselines->get_baseline("bl1");
    REQUIRE(after);
    CHECK(after->deployed_snapshot == before->deployed_snapshot);
    CHECK(after->deployed_at == before->deployed_at);
    CHECK(after->lifecycle == before->lifecycle);
    CHECK(h.store->current_policy_generation() == generation);
    auto guard_after = h.store->get_rule("g1");
    REQUIRE(guard_after);
    REQUIRE(*guard_after);
    CHECK((**guard_after).version == (**guard_before).version);
    CHECK((**guard_after).spec_json == (**guard_before).spec_json);
    CHECK(h.pushes.empty());
}

TEST_CASE("Benchmark routes reject unsafe catalogs and malformed decisions before storage",
          "[pg][guardian_routes][benchmark][validation]") {
    Harness h;
    h.seed_baseline("bl1", "Baseline", {});
    const std::string api = "/api/v1/guaranteed-state/baselines/bl1/benchmark";
    for (const auto& url : {"javascript:alert(1)", "data:text/html,test", "https://example.org/\nattack"}) {
        auto body = benchmark_test_catalog();
        body["catalog"]["controls"][0]["sources"][0]["url"] = url;
        CHECK(h.sink.Put(api, body.dump())->status == 400);
    }
    for (const auto& invalid : {nlohmann::json(4), nlohmann::json(nullptr), nlohmann::json::array()}) {
        auto body = benchmark_test_catalog();
        body["catalog"]["controls"][0]["title"] = invalid;
        CHECK(h.sink.Put(api, body.dump())->status == 400);
    }
    auto absent = h.baselines->benchmark_catalog("bl1");
    REQUIRE(absent);
    CHECK_FALSE(absent->has_value());
    REQUIRE(h.sink.Put(api, benchmark_test_catalog().dump())->status == 200);
    nlohmann::json valid{{"value", "7"}, {"rationale", "Reason"}, {"status", "reviewed"},
                         {"expected_revision", 0}, {"catalog_revision", 1}};
    for (const auto& invalid : {nlohmann::json(4), nlohmann::json(nullptr), nlohmann::json(std::string("x\0y", 3))}) {
        auto body = valid;
        body["value"] = invalid;
        CHECK(h.sink.Put(api + "/decisions/demo.cache.1", body.dump())->status == 400);
    }
    valid["rationale"] = "";
    CHECK(h.sink.Put(api + "/decisions/demo.cache.1", valid.dump())->status == 400);
    auto decisions = h.baselines->benchmark_decisions("bl1");
    REQUIRE(decisions);
    CHECK(decisions->empty());
    CHECK(h.pushes.empty());
}

TEST_CASE("Benchmark reviewed values enforce numeric bounds while exceptions remain explicit",
          "[pg][guardian_routes][benchmark][constraints]") {
    Harness h;
    h.seed_baseline("bl1", "Baseline", {});
    const std::string api = "/api/v1/guaranteed-state/baselines/bl1/benchmark";
    auto catalog = benchmark_test_catalog();
    auto& control = catalog["catalog"]["controls"][0];
    control["value_kind"] = "integer";
    control["minimum"] = 7;
    control["maximum"] = 14;
    REQUIRE(h.sink.Put(api, catalog.dump())->status == 200);
    nlohmann::json decision{{"value", "6"}, {"rationale", "Legacy compatibility"},
        {"status", "reviewed"}, {"expected_revision", 0}, {"catalog_revision", 1}};
    for (const auto* invalid : {"6", "15", "7x", "7.0", "999999999999999999999999999"}) {
        decision["value"] = invalid;
        CHECK(h.sink.Put(api + "/decisions/demo.cache.1", decision.dump())->status == 400);
    }
    auto empty = h.baselines->benchmark_decisions("bl1");
    REQUIRE(empty);
    CHECK(empty->empty());
    decision["value"] = "6";
    decision["status"] = "exception";
    auto saved = h.sink.Put(api + "/decisions/demo.cache.1", decision.dump());
    REQUIRE(saved->status == 200);
    auto data = nlohmann::json::parse(saved->body)["data"];
    CHECK(data["status"] == "exception");
    CHECK(data["value"] == "6");
    decision["expected_revision"] = 1;
    decision["status"] = "reviewed";
    decision["value"] = "7";
    CHECK(h.sink.Put(api + "/decisions/demo.cache.1", decision.dump())->status == 200);
    CHECK(h.pushes.empty());
}

TEST_CASE("Benchmark audit failure refuses import decisions and reads",
          "[pg][guardian_routes][benchmark][audit]") {
    Harness h;
    h.seed_baseline("bl1", "Baseline", {});
    const std::string api = "/api/v1/guaranteed-state/baselines/bl1/benchmark";
    h.throw_audit = true;
    const auto failed_import = h.sink.Put(api, benchmark_test_catalog().dump());
    REQUIRE(failed_import->status == 503);
    CHECK(nlohmann::json::parse(failed_import->body)["error"]["retry_after_ms"] == 5000);
    auto catalog = h.baselines->benchmark_catalog("bl1");
    REQUIRE(catalog);
    CHECK_FALSE(catalog->has_value());
    h.throw_audit = false;
    REQUIRE(h.sink.Put(api, benchmark_test_catalog().dump())->status == 200);
    h.throw_audit = true;
    nlohmann::json decision{{"value", "7"}, {"rationale", "Example capacity"},
        {"status", "reviewed"}, {"expected_revision", 0}, {"catalog_revision", 1}};
    CHECK(h.sink.Put(api + "/decisions/demo.cache.1", decision.dump())->status == 503);
    auto rows = h.baselines->benchmark_decisions("bl1");
    REQUIRE(rows);
    CHECK(rows->empty());
    CHECK(h.sink.Get(api)->status == 503);
    CHECK(h.sink.Get(api + "/export")->status == 503);
    CHECK(h.pushes.empty());
}

TEST_CASE("Benchmark routes enforce read write and service token boundaries",
          "[pg][guardian_routes][benchmark][rbac]") {
    Harness h;
    h.seed_baseline("bl1", "Baseline", {});
    const std::string api = "/api/v1/guaranteed-state/baselines/bl1/benchmark";
    REQUIRE(h.sink.Put(api, benchmark_test_catalog().dump())->status == 200);
    h.denied.insert("GuaranteedState:Write");
    CHECK(h.sink.Put(api, benchmark_test_catalog().dump())->status == 403);
    CHECK(h.sink.Put(api + "/decisions/demo.cache.1", "{}")->status == 403);
    CHECK(h.sink.Get(api)->status == 200);
    h.denied.insert("GuaranteedState:Read");
    CHECK(h.sink.Get(api)->status == 403);
    CHECK(h.sink.Get(api + "/export")->status == 403);
    CHECK(h.sink.Get("/fragments/guardian/baseline/bl1/decisions/page")->status == 403);
    h.denied.clear();
    h.session_token_scope_service = "some-service";
    CHECK(h.sink.Get(api)->status == 403);
    CHECK(h.sink.Put(api, benchmark_test_catalog().dump())->status == 403);
    CHECK(h.sink.Put(api + "/decisions/demo.cache.1", "{}")->status == 403);
    auto decisions = h.baselines->benchmark_decisions("bl1");
    REQUIRE(decisions);
    CHECK(decisions->empty());
    CHECK(h.pushes.empty());
}

TEST_CASE("Guardian overview counts unique online drifting agents across live guards",
          "[pg][guardian_routes][page][drift_counts][overview]") {
    Harness h;
    h.seed_guard("g1", "First control");
    h.seed_guard("g2", "Second control");
    h.agents_json = R"([{"agent_id":"one","hostname":"One","os":"windows"},
                         {"agent_id":"two","hostname":"Two","os":"windows"},
                         {"agent_id":"orphan","hostname":"Orphan","os":"windows"}])";
    const auto start = now_epoch_seconds() - 60;
    h.seed_status("e1", "one", "g1", "drift.detected", format_iso_utc(start));
    h.seed_status("e2", "one", "g2", "drift.detected", format_iso_utc(start + 1));
    h.seed_status("e3", "two", "g1", "guard.unhealthy", format_iso_utc(start + 2));
    h.seed_status("e4", "offline", "g1", "drift.detected", format_iso_utc(start + 3));
    // An online endpoint with only an orphan/deleted rule does not belong to
    // the fleet's live-rule rollup, even though its stale status remains stored.
    h.seed_status("e5", "orphan", "deleted-rule", "drift.detected", format_iso_utc(start + 4));

    auto check_overview = [&](int guards, int agents) {
        auto res = h.sink.Get("/fragments/guardian/status?view=fleet");
        REQUIRE(res != nullptr);
        REQUIRE(res->status == 200);
        const auto label_pos = res->body.find("<div class=\"stat-label\">Guards drifting</div>");
        REQUIRE(label_pos != std::string::npos);
        const auto number_pos = res->body.rfind("<div class=\"stat-num ", label_pos);
        REQUIRE(number_pos != std::string::npos);
        const auto value_pos = res->body.find('>', number_pos);
        const auto value_end = res->body.find("</div>", value_pos);
        REQUIRE(value_end < label_pos);
        CHECK(res->body.substr(value_pos + 1, value_end - value_pos - 1) == std::to_string(guards));
        const auto next_card = res->body.find("stat-card", label_pos);
        const auto card = res->body.substr(label_pos, next_card - label_pos);
        CHECK(card.find("on " + std::to_string(agents) + " agent(s) now") != std::string::npos);
    };
    check_overview(2, 1); // Two drifting controls on one endpoint; errors aren't drift.
    h.seed_status("e6", "two", "g1", "drift.detected", format_iso_utc(start + 5));
    check_overview(2, 2); // A second endpoint counts once despite sharing a control.
    h.agents_json = R"([{"agent_id":"two","hostname":"Two","os":"windows"},
                         {"agent_id":"orphan","hostname":"Orphan","os":"windows"}])";
    check_overview(1, 1); // Endpoint one is now offline, so its two states are unknown.
    h.seed_status("e7", "two", "g1", "guard.compliant", format_iso_utc(start + 6));
    check_overview(0, 0); // The remaining orphan row must not keep attention raised.
}

TEST_CASE("Guardian current drifting devices are distinct from repeated historical detections",
          "[pg][guardian_routes][page][drift_counts]") {
    Harness h;
    h.seed_guard("g1", "Example first control");
    h.seed_guard("g2", "Example second control");
    h.seed_guard("outside", "Unrelated control");
    h.seed_baseline("bl1", "Example baseline", {"g1", "g2"});
    h.agents_json = R"([{"agent_id":"example-device","hostname":"Example device","os":"windows"},
                         {"agent_id":"other","hostname":"Other","os":"windows"}])";
    const auto start = now_epoch_seconds() - 60;
    // Stay inside the rolling 7-day window, with strict timestamp ordering.
    h.seed_status("e1", "example-device", "g1", "drift.detected", format_iso_utc(start));
    h.seed_status("e2", "example-device", "g1", "drift.detected", format_iso_utc(start + 1));
    h.seed_status("e3", "example-device", "g1", "drift.detected", format_iso_utc(start + 2));
    h.seed_status("e4", "example-device", "g2", "drift.detected", format_iso_utc(start + 3));
    h.seed_status("e5", "other", "outside", "drift.detected", format_iso_utc(start + 4));

    auto page = [&](const char* path) {
        auto res = h.sink.Get(path);
        REQUIRE(res != nullptr);
        REQUIRE(res->status == 200);
        return res->body;
    };
    auto check_tile = [](const std::string& html, const std::string& label, int expected) {
        const auto label_pos = html.find("<div class=\"l\">" + label + "</div>");
        REQUIRE(label_pos != std::string::npos);
        const auto tile_pos = html.rfind("<div class=\"gp-tile\">", label_pos);
        REQUIRE(tile_pos != std::string::npos);
        const auto number_pos = html.find("<div class=\"n ", tile_pos);
        REQUIRE(number_pos != std::string::npos);
        const auto value_pos = html.find('>', number_pos);
        REQUIRE(value_pos < label_pos);
        const auto value_end = html.find("</div>", value_pos);
        REQUIRE(value_end < label_pos);
        CHECK(html.substr(value_pos + 1, value_end - value_pos - 1) == std::to_string(expected));
    };
    auto baseline = page("/fragments/guardian/baseline/bl1/page");
    check_tile(baseline, "Devices drifting", 1); // Two guards, one device; outsider excluded.
    CHECK(baseline.find("<th class=\"gp-num\">Devices drifting</th>") != std::string::npos);
    CHECK(baseline.find("Detected 7d") == std::string::npos);
    CHECK(baseline.find("Detection events (last 7 days): <b>4</b>") != std::string::npos);
    const auto member_pos = baseline.find("href=\"/guardian/guard/g1\"");
    REQUIRE(member_pos != std::string::npos);
    const auto member_end = baseline.find("</tr>", member_pos);
    REQUIRE(member_end != std::string::npos);
    const auto member = baseline.substr(member_pos, member_end - member_pos);
    CHECK(member.find("<td class=\"gp-num\">1</td>") != std::string::npos);

    auto guard = page("/fragments/guardian/guard/g1/page");
    check_tile(guard, "Devices drifting", 1);
    check_tile(guard, "Detection events", 3);
    CHECK(guard.find("last 7 days") != std::string::npos);
    CHECK(guard.find("repeated reports") != std::string::npos);

    // Recovery changes the current count, not the historical detection count.
    h.seed_status("e6", "example-device", "g1", "guard.compliant", format_iso_utc(start + 5));
    guard = page("/fragments/guardian/guard/g1/page");
    check_tile(guard, "Devices drifting", 0);
    check_tile(guard, "Detection events", 3);
    check_tile(page("/fragments/guardian/baseline/bl1/page"), "Devices drifting", 1);

    // An offline device's last known drift is unknown, not currently drifting.
    h.agents_json = R"([{"agent_id":"other","hostname":"Other","os":"windows"}])";
    baseline = page("/fragments/guardian/baseline/bl1/page");
    check_tile(baseline, "Devices drifting", 0);
    CHECK(baseline.find("Detection events (last 7 days): <b>4</b>") != std::string::npos);
    guard = page("/fragments/guardian/guard/g1/page");
    check_tile(guard, "Devices drifting", 0);
    check_tile(guard, "Detection events", 3);
    CHECK(guard.find("&#9679; unknown") != std::string::npos);
    check_tile(page("/fragments/guardian/guard/g2/page"), "Devices drifting", 0);
}

TEST_CASE("guard/baseline /page fragments render a seeded id",
          "[pg][guardian_routes][page][render]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_baseline("bl1", "BL1", {"g1"});

    auto g = h.sink.dispatch("GET", "/fragments/guardian/guard/g1/page", "", "");
    REQUIRE(g != nullptr);
    CHECK(g->status == 200);
    CHECK(g->body.find("GuardOne") != std::string::npos);
    CHECK(g->body.find("All guards") != std::string::npos); // back-link present

    auto b = h.sink.dispatch("GET", "/fragments/guardian/baseline/bl1/page", "", "");
    REQUIRE(b != nullptr);
    CHECK(b->status == 200);
    CHECK(b->body.find("BL1") != std::string::npos);
    CHECK(b->body.find("All baselines") != std::string::npos);
}

TEST_CASE("guard/baseline /page fragments return a graceful stub for an unknown id",
          "[pg][guardian_routes][page][notfound]") {
    Harness h;
    auto g = h.sink.dispatch("GET", "/fragments/guardian/guard/nope/page", "", "");
    REQUIRE(g != nullptr);
    CHECK(g->status == 200);
    CHECK(g->body.find("not found") != std::string::npos);

    auto b = h.sink.dispatch("GET", "/fragments/guardian/baseline/nope/page", "", "");
    REQUIRE(b != nullptr);
    CHECK(b->status == 200);
    CHECK(b->body.find("not found") != std::string::npos);
}

TEST_CASE("guard/baseline detail page shells redirect an unauthenticated request",
          "[pg][guardian_routes][page][auth]") {
    Harness h;
    h.session_user = ""; // unauthenticated → auth_fn returns nullopt

    auto g = h.sink.dispatch("GET", "/guardian/guard/g1", "", "");
    REQUIRE(g != nullptr);
    CHECK((g->status == 301 || g->status == 302 || g->status == 303));
    CHECK(g->get_header_value("Location") == "/login");

    auto b = h.sink.dispatch("GET", "/guardian/baseline/bl1", "", "");
    REQUIRE(b != nullptr);
    CHECK((b->status == 301 || b->status == 302 || b->status == 303));
    CHECK(b->get_header_value("Location") == "/login");
}

TEST_CASE("guard/baseline detail page shells serve the shell with the fragment URL substituted",
          "[pg][guardian_routes][page][auth]") {
    Harness h;
    auto g = h.sink.dispatch("GET", "/guardian/guard/g1", "", "");
    REQUIRE(g != nullptr);
    CHECK(g->status == 200);
    CHECK(g->body.find("/fragments/guardian/guard/g1/page") != std::string::npos); // {{FRAGMENT}}
    auto b = h.sink.dispatch("GET", "/guardian/baseline/bl1", "", "");
    REQUIRE(b != nullptr);
    CHECK(b->status == 200);
    CHECK(b->body.find("/fragments/guardian/baseline/bl1/page") != std::string::npos);
}

// Governance sec-H1: the Guard page renders `severity` into a CSS class attribute.
// A hostile severity (seeded straight into the store, bypassing create-time enum
// validation) must be html-escaped at the output, never reflected raw.
TEST_CASE("guard /page escapes a hostile severity in the class attribute",
          "[pg][guardian_routes][page][security]") {
    Harness h;
    auto r = make_rule("g1", "GuardOne");
    r.severity = "\"><img src=x onerror=alert(1)>";
    REQUIRE(h.store->create_rule(r));

    auto g = h.sink.dispatch("GET", "/fragments/guardian/guard/g1/page", "", "");
    REQUIRE(g != nullptr);
    CHECK(g->status == 200);
    // The security property: the payload's '<' and '"' must be HTML-escaped so it
    // cannot break out of the class attribute. (The inert text "onerror=alert"
    // survives escaping as harmless &lt;-quoted text — that's expected.)
    CHECK(g->body.find("<img") == std::string::npos);      // no raw tag injected
    CHECK(g->body.find("sev-\"><") == std::string::npos);  // attribute not broken out
    CHECK(g->body.find("&lt;img") != std::string::npos);   // proof it was escaped
}

// json-dump-depth-guard fix (#2437-class), C1: render_guard_page_fragment
// parses a rule's stored spec_json back out and render_assertion_values'
// as_str() dump()s any non-string params value (both named fields and the
// unknown-key catch-all loop). B1/B2 close the REST write side, but this
// read path stays reachable against a row written before that fix shipped,
// or by direct DB manipulation - seed the poisoned row DIRECTLY via the
// store (bypassing the now-guarded REST routes), mirroring this branch's
// established pattern for proving a read-side guard independently (see
// test_guardian_push_builder.cpp's build_agent_push depth tests). A raw
// string, never materialised as a live nlohmann::json object at this depth:
// kMcpMaxJsonDepth is 32, the 40-deep bracket chain below is comfortably
// past it and still trivially safe to construct/parse directly in this test
// process, orders of magnitude short of the ~100,000-level depth that
// actually SIGSEGVs the real as_str() dump() call this guard exists to
// prevent.
TEST_CASE("guard /page renders an explicit invalid-data state for a spec_json "
          "nested past the depth guard, never a crash or a false not-found",
          "[pg][guardian_routes][page][security][depth]") {
    Harness h;
    auto r = make_rule("g-deep", "DeepGuard");
    r.spec_json =
        R"({"spark":{"type":"registry-change","params":{}},)"
        R"("assertion":{"type":"registry-value-equals","params":{"hive":"HKLM","nested":)" +
        std::string(40, '[') + std::string(40, ']') +
        R"(}},"remediation":{"type":"alert-only"}})";
    REQUIRE(h.store->create_rule(r));

    auto g = h.sink.dispatch("GET", "/fragments/guardian/guard/g-deep/page", "", "");
    REQUIRE(g != nullptr);
    CHECK(g->status == 200); // fragments render inline, not as an HTTP error
    // The guard genuinely exists (get_rule succeeds) - must render as such,
    // never as though the rule were absent.
    CHECK(g->body.find("DeepGuard") != std::string::npos);
    CHECK(g->body.find("Guard not found") == std::string::npos);
    // Distinct, explicit invalid-data state - not a silently empty "What it
    // checks" section, and not the pre-existing "not available" wording used
    // for a genuinely absent/legacy spec (a different condition entirely).
    CHECK(g->body.find("could not be displayed") != std::string::npos);
    CHECK(g->body.find("structured spec is not available") == std::string::npos);
}

// Positive control: an ordinary, safely-nested structured spec_json still
// renders its assertion values normally - the depth guard above must not
// regress the happy-path "What it checks" render.
TEST_CASE("guard /page still renders assertion values normally for an "
          "ordinary structured spec_json",
          "[pg][guardian_routes][page][security][depth]") {
    Harness h;
    auto r = make_rule("g-safe", "SafeGuard");
    r.spec_json =
        R"({"spark":{"type":"registry-change","params":{}},)"
        R"("assertion":{"type":"registry-value-equals","params":{"hive":"HKLM",)"
        R"("key":"SOFTWARE\\YuzuTest","value_name":"Flag","value_type":"REG_DWORD",)"
        R"("expected":"1"}},"remediation":{"type":"alert-only"}})";
    REQUIRE(h.store->create_rule(r));

    auto g = h.sink.dispatch("GET", "/fragments/guardian/guard/g-safe/page", "", "");
    REQUIRE(g != nullptr);
    CHECK(g->status == 200);
    CHECK(g->body.find("SafeGuard") != std::string::npos);
    CHECK(g->body.find("could not be displayed") == std::string::npos);
    CHECK(g->body.find("HKLM") != std::string::npos); // real assertion value rendered
}

// ── Platform honesty: macOS/Linux agents are no-ops, never "armed" ──────────────
// The agent-side Guardian arms guards on Windows only today; an operator must never
// read a connected Mac as compliant/protected when it enforces nothing.

// Deploy `guard_id` via a fresh Baseline so it actually reaches the fleet — the
// not-implemented surfaces are gated on deployment (a draft Guard reaches no device).
namespace {
void deploy_via_baseline(Harness& h, const std::string& guard_id, const std::string& bid = "bl1") {
    h.seed_baseline(bid, bid, {guard_id});
    auto dep = h.sink.dispatch("POST", "/fragments/guardian/baseline/" + bid + "/deploy", "",
                               "application/x-www-form-urlencoded");
    REQUIRE(dep != nullptr);
    REQUIRE(dep->status == 200);
}
} // namespace

TEST_CASE("overview reports macOS agents as not-implemented, never compliant",
          "[pg][guardian_routes][platform][notimpl]") {
    Harness h;
    // A Guard that targets ALL OSes (empty os_target) so it also targets the Mac,
    // delivered by a DEPLOYED Baseline (not-implemented is gated on deployment).
    auto rule = make_rule("g1", "GuardOne");
    rule.os_target = "";
    REQUIRE(h.store->create_rule(rule));
    deploy_via_baseline(h, "g1");
    // One connected macOS agent (the agent reports os="darwin"); no Windows agents.
    h.agents_json = R"([{"agent_id":"mac-1","hostname":"macbook","os":"darwin"}])";

    SECTION("fleet overview shows the honesty banner + a not-implemented census class") {
        auto res = h.sink.Get("/fragments/guardian/status?view=fleet");
        REQUIRE(res != nullptr);
        const std::string& body = res->body;
        CHECK(body.find("Windows only") != std::string::npos);     // honesty banner
        CHECK(body.find("macOS 1") != std::string::npos);          // per-platform count
        CHECK(body.find("Not implemented") != std::string::npos);  // census legend entry
        // The lone agent is an unenforceable Mac — there is no compliant device-guard
        // cell, so the green "compliant" census segment is never emitted.
        CHECK(body.find("% compliant") == std::string::npos);
    }

    SECTION("per-device drill-down lists the Mac as 'not yet implemented'") {
        auto res = h.sink.Get("/fragments/guardian/guard/g1/page");
        REQUIRE(res != nullptr);
        const std::string& body = res->body;
        CHECK(body.find("not yet implemented") != std::string::npos);
        CHECK(body.find("macbook") != std::string::npos);
        CHECK(body.find("no-op on macOS") != std::string::npos);
        // It must NEVER render the Mac as compliant.
        CHECK(body.find("&#9679; compliant") == std::string::npos);
    }
}

TEST_CASE("an UNDEPLOYED all-OS Guard does not inflate the not-implemented census",
          "[pg][guardian_routes][platform][notimpl]") {
    Harness h;
    auto rule = make_rule("g1", "GuardOne");
    rule.os_target = "";  // targets macOS…
    REQUIRE(h.store->create_rule(rule));
    // …but it is a member of no deployed Baseline, so it reaches no device.
    h.agents_json = R"([{"agent_id":"mac-1","hostname":"macbook","os":"darwin"}])";

    SECTION("fleet census shows no not-implemented class, AND no banner, for the "
            "undeployed guard") {
        auto res = h.sink.Get("/fragments/guardian/status?view=fleet");
        REQUIRE(res != nullptr);
        // #4252 banner-semantics decision: PAIR-level, not agent-level. The
        // connected Mac owns zero actually-unenforced pairs (its only targeting
        // rule is undeployed, so it reaches no device) — the honesty banner must
        // NOT fire for it. Pre-#4252 this asserted the banner STILL fired here
        // (agent-level: "any connected Mac trips it"), which was itself the
        // over-attribution this fix corrects on the banner, mirroring the
        // census fix below.
        CHECK(res->body.find("Windows only") == std::string::npos);
        // …and the per-device-guard census has no not-implemented pairs (nothing deployed).
        CHECK(res->body.find("Not implemented") == std::string::npos);
    }
    SECTION("per-device drill-down lists no devices for the undeployed guard") {
        auto res = h.sink.Get("/fragments/guardian/guard/g1/page");
        REQUIRE(res != nullptr);
        CHECK(res->body.find("not yet implemented") == std::string::npos);
        CHECK(res->body.find("macbook") == std::string::npos);
    }
}

TEST_CASE("a deployed Windows-only Guard does not list connected macOS agents",
          "[pg][guardian_routes][platform][notimpl]") {
    Harness h;
    auto rule = make_rule("g1", "WinGuard");  // make_rule sets os_target = "windows"
    REQUIRE(h.store->create_rule(rule));
    deploy_via_baseline(h, "g1");
    h.agents_json = R"([{"agent_id":"mac-1","hostname":"macbook","os":"darwin"}])";

    // Even deployed, the guard targets Windows only, so the Mac is out of scope — not
    // listed as a device and not flagged not-implemented (os_target excludes it).
    auto res = h.sink.Get("/fragments/guardian/guard/g1/page");
    REQUIRE(res != nullptr);
    CHECK(res->body.find("not yet implemented") == std::string::npos);
    CHECK(res->body.find("macbook") == std::string::npos);
}

// ── #4252: guard-type-aware platform support — the double-count fix ──────────
// guardian_guard_supported_on_platform now knows Service guards arm (observe-
// only) on Linux, not just Windows. The core regression: a real Linux Service
// status row must be counted ONCE, never also folded into the synthetic
// not-implemented bucket for the same (agent, rule) pair, across every
// fragment route that computes the census.

TEST_CASE("#4252: a real Linux Service status row is never ALSO folded into "
          "not-implemented — 2 pairs / 50% compliant, not 3 pairs / 33%",
          "[pg][guardian_routes][platform][notimpl][4252]") {
    Harness h;
    auto rule = make_rule_with_spark("svc1", "ServiceGuard", "service-status-change");
    h.seed_rule(rule);
    deploy_via_baseline(h, "svc1");

    // One online Linux agent reporting real DRIFT, one online Windows agent
    // reporting real COMPLIANCE. Pre-#4252, guardian_enforced_on_platform's
    // blanket Windows-only check ALSO counted the Linux agent as
    // not-implemented for this rule — 3 pairs / 33% compliant instead of the
    // correct 2 pairs / 50%.
    h.agents_json = R"([
        {"agent_id":"lin-1","hostname":"linuxbox","os":"linux"},
        {"agent_id":"win-1","hostname":"winbox","os":"windows"}
    ])";
    h.seed_status("e1", "lin-1", "svc1", "drift.detected");
    h.seed_status("e2", "win-1", "svc1", "guard.compliant");

    SECTION("fleet overview (view=fleet): 50% compliant, no not-implemented, no banner") {
        auto res = h.sink.Get("/fragments/guardian/status?view=fleet");
        REQUIRE(res != nullptr);
        const std::string& body = res->body;
        CHECK(body.find("50% compliant") != std::string::npos);
        CHECK(body.find("Not implemented") == std::string::npos);
        // Both agents own a real, currently-enforced pair — the pair-level
        // honesty banner must not fire for either of them.
        CHECK(body.find("Windows only") == std::string::npos);
    }

    SECTION("by-guard view (view=guard): the card shows the real drift, not not-impl") {
        auto res = h.sink.Get("/fragments/guardian/status?view=guard");
        REQUIRE(res != nullptr);
        const std::string& body = res->body;
        CHECK(body.find("drifted on 1 of 2 agents") != std::string::npos);
        CHECK(body.find("not impl") == std::string::npos);
    }

    SECTION("by-baseline view (view=baseline): the card shows 50% compliant, no not-impl chip") {
        auto res = h.sink.Get("/fragments/guardian/status?view=baseline");
        REQUIRE(res != nullptr);
        const std::string& body = res->body;
        CHECK(body.find("50% compliant") != std::string::npos);
        CHECK(body.find("1 of 1 guards drifting") != std::string::npos);
        CHECK(body.find("not impl") == std::string::npos);
    }

    SECTION("guard detail page: both devices listed with real state, no not-implemented row") {
        auto res = h.sink.Get("/fragments/guardian/guard/svc1/page");
        REQUIRE(res != nullptr);
        const std::string& body = res->body;
        CHECK(body.find("linuxbox") != std::string::npos);
        CHECK(body.find("winbox") != std::string::npos);
        CHECK(body.find("&#9679; drifted") != std::string::npos);
        CHECK(body.find("&#9679; compliant") != std::string::npos);
        CHECK(body.find("not yet implemented") == std::string::npos);
    }

    SECTION("baseline detail page: 50% compliant, no not-implemented") {
        auto res = h.sink.Get("/fragments/guardian/baseline/bl1/page");
        REQUIRE(res != nullptr);
        const std::string& body = res->body;
        CHECK(body.find("50%") != std::string::npos);
        CHECK(body.find("Not implemented") == std::string::npos);
    }
}

TEST_CASE("#4252: Registry/File stay Windows-only, and Service stays unsupported "
          "on macOS — unaffected by the Linux Service fix",
          "[pg][guardian_routes][platform][notimpl][4252]") {
    Harness h;
    SECTION("a deployed Registry guard still flags a Linux agent as not-implemented") {
        auto rule = make_rule_with_spark("reg1", "RegGuard", "registry-change");
        h.seed_rule(rule);
        deploy_via_baseline(h, "reg1");
        h.agents_json = R"([{"agent_id":"lin-1","hostname":"linuxbox","os":"linux"}])";
        auto res = h.sink.Get("/fragments/guardian/guard/reg1/page");
        REQUIRE(res != nullptr);
        CHECK(res->body.find("not yet implemented") != std::string::npos);
        CHECK(res->body.find("linuxbox") != std::string::npos);
    }
    SECTION("a deployed File guard still flags a Linux agent as not-implemented") {
        auto rule = make_rule_with_spark("file1", "FileGuard", "file-change");
        h.seed_rule(rule);
        deploy_via_baseline(h, "file1");
        h.agents_json = R"([{"agent_id":"lin-1","hostname":"linuxbox","os":"linux"}])";
        auto res = h.sink.Get("/fragments/guardian/guard/file1/page");
        REQUIRE(res != nullptr);
        CHECK(res->body.find("not yet implemented") != std::string::npos);
        CHECK(res->body.find("linuxbox") != std::string::npos);
    }
    SECTION("a deployed Service guard still flags a macOS agent as not-implemented") {
        auto rule = make_rule_with_spark("svc2", "ServiceGuard2", "service-status-change");
        h.seed_rule(rule);
        deploy_via_baseline(h, "svc2");
        h.agents_json = R"([{"agent_id":"mac-1","hostname":"macbook","os":"darwin"}])";
        auto res = h.sink.Get("/fragments/guardian/guard/svc2/page");
        REQUIRE(res != nullptr);
        CHECK(res->body.find("not yet implemented") != std::string::npos);
        CHECK(res->body.find("macbook") != std::string::npos);
    }
}

TEST_CASE("#4252: a real status row for a DIFFERENT rule (same agent) does not "
          "wrongly suppress THIS rule's genuine not-implemented pair",
          "[pg][guardian_routes][platform][notimpl][4252]") {
    Harness h;
    // ruleA: no spec_json -> unknown spark.type -> falls back to the
    // Windows-only rule, targets all OSes so it also reaches the Mac.
    auto ruleA = make_rule("regA", "RegA");
    ruleA.os_target = "";
    h.seed_rule(ruleA);
    // ruleB: a Service guard (Linux+Windows supported, not macOS) — deployed
    // alongside ruleA so both are live at once.
    auto ruleB = make_rule_with_spark("svcB", "SvcB", "service-status-change");
    h.seed_rule(ruleB);
    h.seed_baseline("bl1", "bl1", {"regA", "svcB"});
    auto dep = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/deploy", "",
                               "application/x-www-form-urlencoded");
    REQUIRE(dep != nullptr);
    REQUIRE(dep->status == 200);

    h.agents_json = R"([{"agent_id":"mac-1","hostname":"macbook","os":"darwin"}])";
    // mac-1 has a REAL status row for ruleB only. The exclusion index is keyed
    // by (agent, rule) — this must NOT suppress ruleA's genuine
    // not-implemented pair for the SAME agent.
    h.seed_status("e1", "mac-1", "svcB", "guard.compliant");

    auto resA = h.sink.Get("/fragments/guardian/guard/regA/page");
    REQUIRE(resA != nullptr);
    CHECK(resA->body.find("not yet implemented") != std::string::npos);
    CHECK(resA->body.find("macbook") != std::string::npos);

    auto resB = h.sink.Get("/fragments/guardian/guard/svcB/page");
    REQUIRE(resB != nullptr);
    CHECK(resB->body.find("&#9679; compliant") != std::string::npos);
    CHECK(resB->body.find("not yet implemented") == std::string::npos);

    // Fleet view: 1 real compliant pair (svcB) + 1 genuine not-implemented pair
    // (regA), never folded together.
    auto resFleet = h.sink.Get("/fragments/guardian/status?view=fleet");
    REQUIRE(resFleet != nullptr);
    CHECK(resFleet->body.find("50% compliant") != std::string::npos);
    CHECK(resFleet->body.find("Not implemented") != std::string::npos);
}

TEST_CASE("#4252: malformed or unknown spark.type falls back to the Windows-only "
          "rule — never regresses Registry/File support",
          "[pg][guardian_routes][platform][notimpl][4252]") {
    Harness h;
    SECTION("non-string spark.type") {
        auto rule = make_rule("bad1", "Bad1");
        rule.os_target = "";
        rule.spec_json = R"({"spark":{"type":123}})";
        h.seed_rule(rule);
        deploy_via_baseline(h, "bad1");
        h.agents_json = R"([{"agent_id":"lin-1","hostname":"linuxbox","os":"linux"}])";
        auto res = h.sink.Get("/fragments/guardian/guard/bad1/page");
        REQUIRE(res != nullptr);
        CHECK(res->body.find("not yet implemented") != std::string::npos);
    }
    SECTION("missing spark block entirely") {
        auto rule = make_rule("bad2", "Bad2");
        rule.os_target = "";
        rule.spec_json = R"({"assertion":{}})";
        h.seed_rule(rule);
        deploy_via_baseline(h, "bad2");
        h.agents_json = R"([{"agent_id":"lin-1","hostname":"linuxbox","os":"linux"}])";
        auto res = h.sink.Get("/fragments/guardian/guard/bad2/page");
        REQUIRE(res != nullptr);
        CHECK(res->body.find("not yet implemented") != std::string::npos);
    }
    SECTION("unparseable spec_json") {
        auto rule = make_rule("bad3", "Bad3");
        rule.os_target = "";
        rule.spec_json = "{not valid json";
        h.seed_rule(rule);
        deploy_via_baseline(h, "bad3");
        h.agents_json = R"([{"agent_id":"lin-1","hostname":"linuxbox","os":"linux"}])";
        auto res = h.sink.Get("/fragments/guardian/guard/bad3/page");
        REQUIRE(res != nullptr);
        CHECK(res->body.find("not yet implemented") != std::string::npos);
    }
}

TEST_CASE("#4252: an agent with MULTIPLE unenforced pairs is counted ONCE in the "
          "pair-level honesty banner",
          "[pg][guardian_routes][platform][notimpl][4252]") {
    Harness h;
    auto rule1 = make_rule("reg1", "Reg1");
    rule1.os_target = "";
    auto rule2 = make_rule("reg2", "Reg2");
    rule2.os_target = "";
    h.seed_rule(rule1);
    h.seed_rule(rule2);
    h.seed_baseline("bl1", "bl1", {"reg1", "reg2"});
    auto dep = h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/deploy", "",
                               "application/x-www-form-urlencoded");
    REQUIRE(dep != nullptr);
    REQUIRE(dep->status == 200);
    // One Mac targeted by BOTH deployed rules -> 2 unenforced pairs, but the
    // SAME agent -> the banner's per-platform count must be 1, not 2.
    h.agents_json = R"([{"agent_id":"mac-1","hostname":"macbook","os":"darwin"}])";

    auto res = h.sink.Get("/fragments/guardian/status?view=fleet");
    REQUIRE(res != nullptr);
    CHECK(res->body.find("macOS 1") != std::string::npos);
    CHECK(res->body.find("macOS 2") == std::string::npos);
}

TEST_CASE("#4252: a Linux agent whose Service guard never arms and never reports "
          "vanishes from the denominator entirely — not double-counted a second way",
          "[pg][guardian_routes][platform][notimpl][4252]") {
    Harness h;
    auto rule = make_rule_with_spark("svc1", "ServiceGuard", "service-status-change");
    h.seed_rule(rule);
    deploy_via_baseline(h, "svc1");
    // Connected Linux agent targeted by the deployed Service rule, but it NEVER
    // reports any status event for it — the accepted #4252 limitation: agent-
    // side arm failure (D-Bus unavailable, hitting every containerized/compose
    // agent including this repo's own UAT rigs; a disabled build flag; or an
    // invalid unit name) leaves no event for the server to observe. Since
    // guardian_guard_supported_on_platform now says Linux Service IS
    // supported, this pair is no longer folded into "not implemented" either
    // — it must simply be ABSENT everywhere, exactly like an unreported
    // Windows pair already is, never counted twice.
    h.agents_json = R"([{"agent_id":"lin-1","hostname":"linuxbox","os":"linux"}])";

    SECTION("fleet overview: no pairs at all, no not-implemented, no banner") {
        auto res = h.sink.Get("/fragments/guardian/status?view=fleet");
        REQUIRE(res != nullptr);
        const std::string& body = res->body;
        CHECK(body.find("Not implemented") == std::string::npos);
        CHECK(body.find("Windows only") == std::string::npos);
        CHECK(body.find("No device check-ins recorded yet") != std::string::npos);
    }

    SECTION("guard detail page: the agent is not listed at all") {
        auto res = h.sink.Get("/fragments/guardian/guard/svc1/page");
        REQUIRE(res != nullptr);
        const std::string& body = res->body;
        CHECK(body.find("linuxbox") == std::string::npos);
        CHECK(body.find("not yet implemented") == std::string::npos);
        CHECK(body.find("No device has reported this Guard's state yet") != std::string::npos);
    }

    SECTION("baseline detail page: no pairs at all, no not-implemented") {
        auto res = h.sink.Get("/fragments/guardian/baseline/bl1/page");
        REQUIRE(res != nullptr);
        const std::string& body = res->body;
        CHECK(body.find("Not implemented") == std::string::npos);
        CHECK(body.find("No device check-ins recorded yet") != std::string::npos);
    }
}

TEST_CASE("#4252: a real status row for a pair the support matrix still calls "
          "unsupported fires the platform-matrix-stale detectability counter, "
          "and is not double-counted",
          "[pg][guardian_routes][platform][notimpl][4252]") {
    // NOTE on this fixture: registry-change is genuinely Windows-only, both
    // before and after #4252 — this is deliberate. The counter/exclusion
    // predicate is a GENERAL safety net for "the matrix says unsupported, but
    // a real status row exists anyway" (e.g. a future guard type shipping
    // agent-side before this file's matrix catches up), not something special
    // to Service/Linux specifically. Constructing that disagreement directly
    // (a real status row on a pair the matrix still calls unsupported) is the
    // only way to exercise the mechanism today, since the one case #4252
    // itself fixed (Service on Linux) is now correctly classified "supported"
    // and can never reach this code path (see the sibling double-count test
    // above, which asserts exactly that — 0 hits on this counter there).
    Harness h;
    auto rule = make_rule_with_spark("reg1", "RegGuard", "registry-change");
    h.seed_rule(rule);
    deploy_via_baseline(h, "reg1");
    h.agents_json = R"([{"agent_id":"lin-1","hostname":"linuxbox","os":"linux"}])";
    h.seed_status("e1", "lin-1", "reg1", "drift.detected");

    auto counter = [&] {
        return h.metrics
            .counter("yuzu_server_guardian_platform_matrix_stale_total",
                     {{"spark_type", "registry-change"}})
            .value();
    };
    CHECK(counter() == 0.0);

    // Fleet view (call site #1) detects + suppresses the double-count, firing once.
    auto resFleet = h.sink.Get("/fragments/guardian/status?view=fleet");
    REQUIRE(resFleet != nullptr);
    CHECK(resFleet->body.find("Not implemented") == std::string::npos);
    CHECK(counter() == 1.0);

    // Baseline detail page (call site #3) independently re-derives the same
    // condition for the SAME pair on its own render — a separate render-time
    // detection each time a fragment is loaded, not deduplicated across fragments.
    auto resBaseline = h.sink.Get("/fragments/guardian/baseline/bl1/page");
    REQUIRE(resBaseline != nullptr);
    CHECK(counter() == 2.0);

    // Guard detail page (call site #4) was ALREADY pair-deduped before #4252
    // (its `seen` set), so it was never at risk of the double-count and
    // deliberately does not fire this counter.
    auto resGuard = h.sink.Get("/fragments/guardian/guard/reg1/page");
    REQUIRE(resGuard != nullptr);
    CHECK(resGuard->body.find("&#9679; drifted") != std::string::npos);
    CHECK(resGuard->body.find("not yet implemented") == std::string::npos);
    CHECK(counter() == 2.0);
}

TEST_CASE("#4252: the fixed Linux-Service case never reaches the "
          "platform-matrix-stale counter (it is now correctly classified "
          "supported, not merely double-count-suppressed)",
          "[pg][guardian_routes][platform][notimpl][4252]") {
    Harness h;
    auto rule = make_rule_with_spark("svc1", "ServiceGuard", "service-status-change");
    h.seed_rule(rule);
    deploy_via_baseline(h, "svc1");
    h.agents_json = R"([{"agent_id":"lin-1","hostname":"linuxbox","os":"linux"}])";
    h.seed_status("e1", "lin-1", "svc1", "drift.detected");

    auto res = h.sink.Get("/fragments/guardian/status?view=fleet");
    REQUIRE(res != nullptr);
    CHECK(h.metrics
              .counter("yuzu_server_guardian_platform_matrix_stale_total",
                       {{"spark_type", "service-status-change"}})
              .value() == 0.0);
}

// ── #4252 consolidated round: governance Gate 2/3/6 findings ─────────────────
// A crafted agent_id/rule_id pair embedding the internal join separator must
// never be treated as equivalent to an unrelated (agent, rule) pair. This is a
// regression test for a HIGH finding independently confirmed by
// security-guardian, architect, and compliance-officer against a delimited-
// string composite key (`agent_id + '\x1f' + rule_id`) — the fold now uses a
// real PairStatusKey{agent_id, rule_id} struct + hash functor instead, so no
// separator choice matters.
TEST_CASE("#4252: a crafted \\x1f-embedded agent_id cannot collide with an "
          "unrelated pair's status row (PairStatusKey, not a delimited string)",
          "[pg][guardian_routes][platform][notimpl][4252][security]") {
    Harness h;
    // Genuinely unsupported on Linux (Windows-only guard type) — the pair under
    // test owns NO real status row of its own, so it must render "not
    // implemented".
    auto ruleX = make_rule_with_spark("ruleX", "RegistryGuard", "registry-change");
    h.seed_rule(ruleX);
    deploy_via_baseline(h, "ruleX", "bl1");

    // A second, unrelated rule whose id is chosen so that, under the OLD
    // delimited-string pair_key, agent "agentA" + this rule_id byte-for-byte
    // equals the crafted pair below: pair_key("agentA", "extra\x1fruleX") ==
    // "agentA" '\x1f' "extra" '\x1f' "ruleX" == pair_key("agentA\x1fextra", "ruleX").
    const std::string unrelated_rule_id = std::string("extra") + '\x1f' + "ruleX";
    auto unrelated = make_rule_with_spark(unrelated_rule_id, "Unrelated", "service-status-change");
    h.seed_rule(unrelated);
    deploy_via_baseline(h, unrelated_rule_id, "bl2");
    // A real status row for the UNRELATED pair only — agent "agentA" on
    // `unrelated_rule_id`, nothing to do with ruleX.
    h.seed_status("e1", "agentA", unrelated_rule_id, "guard.compliant");

    // The pair actually under test: a Linux agent whose id happens to embed the
    // separator byte, targeted by ruleX. It owns no status row of its own.
    // Built via nlohmann::json::dump() rather than a hand-typed literal — a raw
    // control byte is not legal unescaped inside a JSON string, and dump()
    // guarantees the correct escape (parse_online_agent_os round-trips it back
    // to the same raw byte create_rule/insert_event stored above via the store's
    // C++ API, which goes straight to parameterised SQL, no JSON envelope).
    const std::string crafted_agent_id = std::string("agentA") + '\x1f' + "extra";
    nlohmann::json agents = nlohmann::json::array();
    agents.push_back(
        {{"agent_id", crafted_agent_id}, {"hostname", "linuxbox"}, {"os", "linux"}});
    h.agents_json = agents.dump();

    auto res = h.sink.Get("/fragments/guardian/status?view=fleet");
    REQUIRE(res != nullptr);
    // Pre-fix, the collision made has_real_status() wrongly report a real
    // status row for (crafted_agent_id, "ruleX") — silently dropping it from
    // every bucket, so this pair never rendered "Not implemented" at all.
    CHECK(res->body.find("Not implemented") != std::string::npos);
}

// Detectability fix (#4252 consolidated round): an unrecognised spark.type
// token must fold to the "unknown" label, never leak as its own unbounded
// Prometheus series (governance Gate 2/3 finding, cheap fix already shipped —
// this pins it). Read via serialize(), not counter(garbage).value(), because
// calling counter() with an unseen label combination would itself create the
// phantom series this test exists to prove absent.
TEST_CASE("#4252: an unrecognised spark.type folds to the 'unknown' metric label, "
          "never its own series",
          "[pg][guardian_routes][platform][notimpl][4252]") {
    Harness h;
    auto rule = make_rule_with_spark("garbage1", "GarbageGuard", "garbage-xyz-not-a-real-type");
    h.seed_rule(rule);
    deploy_via_baseline(h, "garbage1");
    h.agents_json = R"([{"agent_id":"lin-1","hostname":"linuxbox","os":"linux"}])";
    // Real status row so the pair is a stale-matrix-vs-reality disagreement
    // (matrix falls back to Windows-only for an unrecognised type, so a Linux
    // report here is exactly the "already reports real status" trigger).
    h.seed_status("e1", "lin-1", "garbage1", "guard.compliant");

    auto res = h.sink.Get("/fragments/guardian/status?view=fleet");
    REQUIRE(res != nullptr);

    // quality-engineer (Gate 8 re-review): asserting the "unknown" label is
    // merely PRESENT in the dump is non-discriminating — register_routes
    // pre-seeds it at 0 regardless of whether this fold ever fires. Assert the
    // actual counter VALUE via the real MetricsRegistry API instead (safe here
    // — "unknown" is pre-seeded, so this read creates no phantom series, unlike
    // reading the raw garbage token directly would).
    CHECK(h.metrics
              .counter("yuzu_server_guardian_platform_matrix_stale_total",
                       {{"spark_type", "unknown"}})
              .value() == 1.0);
    const std::string dump = h.metrics.serialize();
    CHECK(dump.find("garbage-xyz-not-a-real-type") == std::string::npos);
}

// cpp-safety (#4252 Gate 3): the metrics_ == nullptr degrade path — every
// other test wires a real MetricsRegistry, so this path was untested. Must
// not crash, and must simply not emit the counter.
TEST_CASE("#4252: GuardianRoutes with metrics=nullptr degrades cleanly (no crash, "
          "no counter emission)",
          "[pg][guardian_routes][platform][notimpl][4252]") {
    Harness h{/*with_metrics=*/false};
    auto rule = make_rule_with_spark("reg1", "RegGuard", "registry-change");
    h.seed_rule(rule);
    deploy_via_baseline(h, "reg1");
    h.agents_json = R"([{"agent_id":"lin-1","hostname":"linuxbox","os":"linux"}])";
    // Real status row for a pair the matrix calls unsupported — exactly the
    // note_platform_matrix_stale() trigger, exercised here with metrics_ null.
    h.seed_status("e1", "lin-1", "reg1", "guard.compliant");

    auto res = h.sink.Get("/fragments/guardian/status?view=fleet");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    // No crash reaching this line already proves the null-check holds. The
    // exclusion logic itself doesn't depend on metrics_ at all — the real
    // status row still correctly suppresses the synthetic not-implemented
    // fold and renders as the sole, fully compliant pair.
    CHECK(res->body.find("100% compliant") != std::string::npos);
    CHECK(res->body.find("Not implemented") == std::string::npos);
}
