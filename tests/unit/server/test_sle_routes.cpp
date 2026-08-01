/// @file test_sle_routes.cpp
/// Tests for the /api/v1/sle/* in-server SLE surface (ADR-0024; the discovery
/// half kept in-server per "Placement under ADR-1005") — driven in-process
/// through TestRouteSink (no httplib acceptor, #438). Two routes:
///   * GET  /sle/agents/{id} — the raw per-agent detected-licence DRILL: scoped
///     gate (in-scope 200 / out-of-scope 403, D-4), the per-open behavioural audit
///     (sle.agent.view) that FAILS CLOSED (503 + Sec-Audit-Failed) on a persist
///     failure (G-2), and 503-on-degrade (never an empty 200, Decision 4).
///   * DELETE /sle/agents/{id} — the audited durable-erasure trigger: the scoped
///     SoftwareLicensing:Delete AND Inventory:Delete CONJUNCTION (the cascade erases
///     the ADR-0016 Inventory stores too, so it must authorize for its full blast
///     radius), AUDIT-BEFORE-ERASE fail-closed, and honest outcome (r.ok() → 200
///     decommissioned; a Failed store → 500).
/// Plus the SoftwareLicensing D-9 securable matrix, the G-1 fail-closed primitive,
/// and one [pg] end-to-end drill through a real SoftwareLicensingStore.
///
/// The posture/compliance reads (`/sle/summary`, `/sle/licenses`) and the fan-out
/// list are the SAM UCE module's interpretation surface — not built in-server, so
/// not tested here. The discovery read's MCP twin (`query_software_licenses`) is
/// covered by the `[mcp][sle]` cases in test_mcp_server.cpp — the scoped-gate
/// confinement, the fail-closed-when-unwired posture, the store-unavailable /
/// degrade A4 errors, and the Decision-11 user_ref/user_scope PII omission that
/// distinguishes the twin from this audited REST drill.

#include "sle_routes.hpp"
#include "test_route_sink.hpp"

#include "agent_decommission.hpp" // DecommissionResult (the DELETE route)
#include "rbac_store.hpp"
#include "software_licensing_store.hpp"

#include "pg/pg_pool.hpp"
#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using nlohmann::json;

namespace {

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

AgentLicenseRow lic(std::string product, std::string state) {
    AgentLicenseRow r;
    r.product = std::move(product);
    r.state = std::move(state);
    r.user_scope = "machine";
    return r;
}

/// Build a DecommissionResult with one Deleted store (a confirmed erasure).
DecommissionResult ok_result() {
    DecommissionResult r;
    r.agent_id = "a";
    r.deleted = 1;
    r.stores.push_back({"software_licensing", DecommissionOutcome::Deleted, ""});
    return r;
}

/// Build a DecommissionResult with a non-throwing Failed store (a rolled-back
/// PG DELETE) — ok() is false, the DELETE route must answer 500, never 200.
DecommissionResult partial_result() {
    DecommissionResult r;
    r.agent_id = "a";
    r.deleted = 1;
    r.failed = 1;
    r.stores.push_back({"inventory", DecommissionOutcome::Deleted, ""});
    r.stores.push_back({"software_licensing", DecommissionOutcome::Failed, "txn rolled back"});
    return r;
}

// ── Route harness — all providers injected, every flag re-read per call ──────────
struct SleHarness {
    yuzu::server::test::TestRouteSink sink;
    SleRoutes routes;

    bool allow_scoped_all = false;          // scoped gate admits every agent
    std::vector<std::string> scoped_agents; // ...or just these agents (D-4 in-scope set)
    // "type|op" pairs the principal does NOT hold — denied regardless of scope. Models
    // an operator-authored custom role (the erase conjunction's whole point: the seeded
    // roles hold both securables, a custom one need not).
    std::vector<std::string> denied_perms;
    bool degrade_agent = false;
    bool audit_should_fail = false;

    std::vector<AgentLicenseRow> agent_rows;
    DecommissionResult decommission_result{}; // returned by the injected cascade

    std::vector<std::string> audits;     // "action|result"
    std::vector<std::string> audit_full; // "action|result|target_type|target_id"
    // The (securable_type, operation, agent_id) each SCOPED gate check was ASKED —
    // recorded so a wrong-securable / wrong-op / wrong-scope regression is caught.
    std::vector<std::string> scoped_calls; // "type|op|agent_id"

    SleHarness() {
        auto scoped = [this](const httplib::Request&, httplib::Response& res,
                             const std::string& type, const std::string& op,
                             const std::string& agent_id) {
            scoped_calls.push_back(type + "|" + op + "|" + agent_id);
            bool ok = allow_scoped_all;
            for (const auto& a : scoped_agents)
                if (a == agent_id)
                    ok = true;
            for (const auto& d : denied_perms) // a permission the role simply lacks
                if (d == type + "|" + op)
                    ok = false;
            if (!ok) {
                res.status = 403;
                // Mirror production (require_scoped_permission writes an A4 denial body
                // naming the permission). Without a body the "no erasure" assertions
                // below would pass vacuously against an empty string.
                res.set_content(R"({"error":{"code":403,"permission":")" + type + ":" + op +
                                    R"("}})",
                                "application/json");
            }
            return ok;
        };
        auto agents_fn = [this](const std::string&) -> std::optional<std::vector<AgentLicenseRow>> {
            if (degrade_agent)
                return std::nullopt;
            return agent_rows;
        };
        auto decommission = [this](const std::string&) -> DecommissionResult {
            return decommission_result;
        };
        auto audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string& tt, const std::string& tid, const std::string&) {
            audits.push_back(a + "|" + r);
            audit_full.push_back(a + "|" + r + "|" + tt + "|" + tid);
            return !audit_should_fail;
        };
        routes.register_routes(sink, scoped, agents_fn, decommission, audit);
    }

    bool audited(const std::string& tok) const {
        for (const auto& a : audits)
            if (a == tok)
                return true;
        return false;
    }
};

bool role_can(RbacStore& s, const std::string& role, const std::string& type,
              const std::string& op) {
    for (const auto& p : s.get_role_permissions(role))
        if (p.securable_type == type && p.operation == op && p.effect == "allow")
            return true;
    return false;
}

// Pre-migrated + seeded template (RbacStore construction runs the migration AND
// seed_defaults). Every store-behaviour case clones this instead of
// re-migrating/re-seeding per test (docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate rbac_tpl{"rbacstore", [](const std::string& dsn) {
                                        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
                                        RbacStore store{pool};
                                        if (!store.is_open())
                                            throw std::runtime_error(
                                                "rbac template: store failed to migrate/seed");
                                    }};

} // namespace

// ───────────────────── /sle/agents/{id} drill — D-4 scoped gate + G-2 audit ──────

TEST_CASE("sle drill: denied (403) without an in-scope SoftwareLicensing:Read", "[sle_routes]") {
    SleHarness h; // allow_scoped_all=false, empty set → every agent out of scope
    auto res = h.sink.Get("/api/v1/sle/agents/a1");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK_FALSE(contains(res->body, "licenses"));
}

// F3: the drill demands EXACTLY SoftwareLicensing:Read and hands the agent id to
// the SCOPED gate. Without asserting the recorded (type, op, agent_id), a
// wrong-securable/wrong-op regression would pass silently.
TEST_CASE("sle drill: demands exactly SoftwareLicensing:Read via the scoped gate", "[sle_routes]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.sink.Get("/api/v1/sle/agents/agent-77");
    REQUIRE(h.scoped_calls.size() == 1);
    CHECK(h.scoped_calls[0] == "SoftwareLicensing|Read|agent-77");
}

TEST_CASE("sle/agents/{id}: scoped gate — in-scope 200, out-of-scope 403 (D-4)", "[sle][adr0017]") {
    SleHarness h;
    h.scoped_agents = {"agent-in"}; // only this agent is in the operator's scope
    h.agent_rows = {lic("Office", "subscription_active")};

    auto in = h.sink.Get("/api/v1/sle/agents/agent-in");
    REQUIRE(in);
    CHECK(in->status == 200);
    CHECK(contains(in->body, "Office"));

    auto out = h.sink.Get("/api/v1/sle/agents/agent-out");
    REQUIRE(out);
    CHECK(out->status == 403);
    CHECK_FALSE(contains(out->body, "Office")); // no licence data leaked outside scope
}

TEST_CASE("sle/agents/{id}: renders per-user user_scope/user_ref (why the drill is audited)",
          "[sle_routes]") {
    SleHarness h;
    h.allow_scoped_all = true;
    auto row = lic("JetBrains IDEA", "licensed");
    row.user_scope = "user";
    row.user_ref = "a1b2c3d4e5f60718"; // keyed-HMAC pseudonym
    h.agent_rows = {row};
    auto res = h.sink.Get("/api/v1/sle/agents/agent-1");
    REQUIRE(res);
    auto j = json::parse(res->body)["data"];
    CHECK(j["count"] == 1);
    CHECK(j["licenses"][0]["user_scope"] == "user");
    CHECK(j["licenses"][0]["user_ref"] == "a1b2c3d4e5f60718");
}

TEST_CASE("sle/agents/{id}: per-open behavioural audit is emitted (sle.agent.view)", "[sle_routes]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.agent_rows = {lic("Office", "licensed")};
    auto res = h.sink.Get("/api/v1/sle/agents/agent-9");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(h.audited("sle.agent.view|success"));
    // Correct tier + target: Agent-scoped (parity with dex.device.view), not a bare access log.
    bool target_ok = false;
    for (const auto& a : h.audit_full)
        if (a == "sle.agent.view|success|Agent|agent-9")
            target_ok = true;
    CHECK(target_ok);
}

TEST_CASE("sle/agents/{id}: audit FAILS CLOSED — 503 + Sec-Audit-Failed, PII withheld (G-2)",
          "[sle_routes]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.audit_should_fail = true;
    h.agent_rows = {lic("Office", "licensed")};
    auto res = h.sink.Get("/api/v1/sle/agents/agent-9");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->has_header("Sec-Audit-Failed"));
    CHECK_FALSE(contains(res->body, "Office")); // licence PII never served without durable evidence
}

TEST_CASE("sle/agents/{id}: scoped gate runs BEFORE the audit + read (out-of-scope → no audit)",
          "[sle_routes]") {
    SleHarness h; // scoped gate denies everything (allow_scoped_all=false, empty set)
    h.agent_rows = {lic("Office", "licensed")};
    auto res = h.sink.Get("/api/v1/sle/agents/agent-out");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.audits.empty()); // denied before the per-open audit fires — no read attempted
}

TEST_CASE("sle/agents/{id}: store degrade → 503 + audited failure, never an empty 200",
          "[sle_routes]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.degrade_agent = true;
    auto res = h.sink.Get("/api/v1/sle/agents/agent-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(contains(res->body, "unavailable"));
    // The per-open audit fired on open (before the degraded read); the degrade also
    // records a durable failure-audit (parity with the erasure route's pattern).
    CHECK(h.audited("sle.agent.view|success"));
    CHECK(h.audited("sle.agent.view|failure"));
}

// ─────────────── DELETE /sle/agents/{id} — audited durable-erasure trigger ───────

TEST_CASE("sle erase: scoped SoftwareLicensing:Delete gate — out-of-scope 403, no erasure",
          "[sle_routes]") {
    SleHarness h; // allow_scoped_all=false → denied
    h.decommission_result = ok_result();
    auto res = h.sink.Delete("/api/v1/sle/agents/agent-out");
    REQUIRE(res);
    CHECK(res->status == 403);
    REQUIRE(h.scoped_calls.size() == 1);
    CHECK(h.scoped_calls[0] == "SoftwareLicensing|Delete|agent-out"); // Delete, not Read
    CHECK(h.audits.empty()); // denied before the attempt audit / cascade
}

// The route is NAMED for licences but the cascade erases FIVE per-agent stores spanning
// THREE securables: SoftwareLicensing (software_licensing), Inventory (inventory,
// software_inventory, device_inventory — ADR-0016), and GuaranteedState (app_perf_daily —
// DEX behavioural PII, whose read routes gate on GuaranteedState:Read). The gate must
// therefore authorize for what it DESTROYS, not for what it is named. Each conjunct is
// tested for absence, because an operator-authored role may hold any subset (the seeded
// Administrator / ITServiceOwner hold all three, so this is latent on the shipped matrix).
TEST_CASE("sle erase: EVERY securable in the blast radius is required — missing any → 403",
          "[sle_routes][authz]") {
    struct Case {
        const char* missing;    // the "type|op" the custom role lacks
        const char* in_body;    // how the denial names it ("type:op")
        std::size_t asked;      // gate calls made before the refusal (order is fixed)
    };
    // Ordered exactly as the route asks them; a refusal short-circuits the rest.
    const Case cases[] = {
        {"SoftwareLicensing|Delete", "SoftwareLicensing:Delete", 1},
        {"Inventory|Delete", "Inventory:Delete", 2},
        // app_perf_daily — the conjunct the first cut of this gate MISSED, letting a
        // role destroy a device's DEX performance series it could not even read.
        {"GuaranteedState|Delete", "GuaranteedState:Delete", 3},
    };
    for (const auto& c : cases) {
        CAPTURE(c.missing);
        SleHarness h;
        h.allow_scoped_all = true;    // in scope for the device...
        h.denied_perms = {c.missing}; // ...but the role lacks this one permission
        h.decommission_result = ok_result();
        auto res = h.sink.Delete("/api/v1/sle/agents/agent-1");
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK(contains(res->body, c.in_body));      // the denial names the permission
        REQUIRE(h.scoped_calls.size() == c.asked);  // short-circuited at the right conjunct
        // Refused BEFORE the attempt audit and BEFORE the cascade — nothing was erased.
        CHECK(h.audits.empty());
        CHECK_FALSE(contains(res->body, "decommissioned"));
    }
}

TEST_CASE("sle erase: holding ALL THREE securables erases — the conjunction is not a wall",
          "[sle_routes][authz]") {
    // The seeded Administrator / ITServiceOwner shape (full CRUD on all three) still
    // erases: the conjunction narrows custom roles, it does not regress the shipped matrix.
    SleHarness h;
    h.allow_scoped_all = true;
    h.decommission_result = ok_result();
    auto res = h.sink.Delete("/api/v1/sle/agents/agent-1");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // All three conjuncts asked, in order, each scoped to the device.
    REQUIRE(h.scoped_calls.size() == 3);
    CHECK(h.scoped_calls[0] == "SoftwareLicensing|Delete|agent-1");
    CHECK(h.scoped_calls[1] == "Inventory|Delete|agent-1");
    CHECK(h.scoped_calls[2] == "GuaranteedState|Delete|agent-1");
    CHECK(json::parse(res->body)["data"]["decommissioned"] == true);
}

TEST_CASE("sle erase: audit-before-erase FAILS CLOSED — 503, cascade never invoked", "[sle_routes]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.audit_should_fail = true;
    h.decommission_result = ok_result();
    auto res = h.sink.Delete("/api/v1/sle/agents/agent-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->has_header("Sec-Audit-Failed"));
    CHECK_FALSE(contains(res->body, "decommissioned")); // no erase claimed
}

TEST_CASE("sle erase: all-Deleted → 200 decommissioned, attempt+success audited", "[sle_routes]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.decommission_result = ok_result();
    auto res = h.sink.Delete("/api/v1/sle/agents/agent-1");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = json::parse(res->body)["data"];
    CHECK(j["decommissioned"] == true);
    CHECK(j["deleted"] == 1);
    CHECK(j["failed"] == 0);
    CHECK(h.audited("sle.agent.decommission|attempt"));
    CHECK(h.audited("sle.agent.decommission|success"));
}

TEST_CASE("sle erase: a non-throwing Failed store → 500 partial, never a false success",
          "[sle_routes]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.decommission_result = partial_result(); // one store rolled back (failed>0)
    auto res = h.sink.Delete("/api/v1/sle/agents/agent-1");
    REQUIRE(res);
    CHECK(res->status == 500); // r.ok()==false → 500, NOT a 200 "decommissioned"
    CHECK_FALSE(contains(res->body, "\"decommissioned\":true"));
    CHECK(contains(res->body, "incomplete"));
    // The outcome is audited as partial (honest), not success.
    CHECK(h.audited("sle.agent.decommission|attempt"));
    CHECK(h.audited("sle.agent.decommission|partial"));
    CHECK_FALSE(h.audited("sle.agent.decommission|success"));
}

// ─────────────────────────── SoftwareLicensing securable D-9 matrix ──────────────

TEST_CASE("SoftwareLicensing securable seeds the D-9 matrix EXACTLY", "[sle][rbac][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(rbac_db_, rbac_tpl);
    yuzu::server::pg::PgPool rbac_pool_{{.conninfo = rbac_db_.dsn(), .size = 4}};
    REQUIRE(rbac_pool_.valid());
    RbacStore s{rbac_pool_};
    REQUIRE(s.is_open());

    // Viewer: Read only.
    CHECK(role_can(s, "Viewer", "SoftwareLicensing", "Read"));
    CHECK_FALSE(role_can(s, "Viewer", "SoftwareLicensing", "Write"));

    // PlatformEngineer: Read only.
    CHECK(role_can(s, "PlatformEngineer", "SoftwareLicensing", "Read"));
    CHECK_FALSE(role_can(s, "PlatformEngineer", "SoftwareLicensing", "Write"));

    // Operator: Read + Write, NOT Execute/Delete/Approve (that is the full-CRUD tier).
    CHECK(role_can(s, "Operator", "SoftwareLicensing", "Read"));
    CHECK(role_can(s, "Operator", "SoftwareLicensing", "Write"));
    CHECK_FALSE(role_can(s, "Operator", "SoftwareLicensing", "Execute"));
    CHECK_FALSE(role_can(s, "Operator", "SoftwareLicensing", "Delete"));
    CHECK_FALSE(role_can(s, "Operator", "SoftwareLicensing", "Approve"));

    // ITServiceOwner: full CRUD.
    for (const auto* op : {"Read", "Write", "Execute", "Delete", "Approve"})
        CHECK(role_can(s, "ITServiceOwner", "SoftwareLicensing", op));

    // ApiTokenManager: NONE.
    CHECK_FALSE(role_can(s, "ApiTokenManager", "SoftwareLicensing", "Read"));
    CHECK_FALSE(role_can(s, "ApiTokenManager", "SoftwareLicensing", "Write"));

    // Administrator: full CRUD incl. Approve (its global pattern).
    for (const auto* op : {"Read", "Write", "Execute", "Delete", "Approve"})
        CHECK(role_can(s, "Administrator", "SoftwareLicensing", op));

    // DISTINCT from Yuzu's own `License` securable (§22.3) — the SLE grants must not
    // have accidentally landed on `License` nor vice-versa.
    CHECK(role_can(s, "Operator", "License", "Read"));
    CHECK_FALSE(role_can(s, "Operator", "License", "Write")); // License stays Operator-Read-only
}

// ── G-1: the SLE route gate is built on the FAIL-CLOSED enforcement primitive
// (rbac_enforcement_in_effect), NOT the raw is_rbac_enabled() shape whose corrupt-
// rbac.db fall-through to a legacy-open Read is the #1717 fail-open. The route takes
// an INJECTED gate closure, so the production wiring (server.cpp's sle_gate_usable →
// require_scoped_permission, branched on this predicate) is exercised at the
// server.cpp boundary. Assert the primitive's fail-closed contract directly.
TEST_CASE("SLE gate uses the fail-closed enforcement primitive (G-1 / #1717)",
          "[sle][adr0017][pg]") {
    CHECK(rbac_enforcement_in_effect(nullptr)); // null store → enforcement in effect (deny, not legacy-open)

    YUZU_REQUIRE_PG_DB_TPL(rbac_disabled_db_, rbac_tpl);
    yuzu::server::pg::PgPool rbac_disabled_pool_{{.conninfo = rbac_disabled_db_.dsn(), .size = 4}};
    REQUIRE(rbac_disabled_pool_.valid());
    RbacStore disabled{rbac_disabled_pool_};
    REQUIRE(disabled.is_open());
    REQUIRE_FALSE(disabled.is_rbac_enabled());
    CHECK_FALSE(rbac_enforcement_in_effect(&disabled)); // loaded + explicitly disabled → legacy-open

    YUZU_REQUIRE_PG_DB_TPL(rbac_enabled_db_, rbac_tpl);
    yuzu::server::pg::PgPool rbac_enabled_pool_{{.conninfo = rbac_enabled_db_.dsn(), .size = 4}};
    REQUIRE(rbac_enabled_pool_.valid());
    RbacStore enabled{rbac_enabled_pool_};
    REQUIRE(enabled.is_open());
    enabled.set_rbac_enabled(true);
    CHECK(rbac_enforcement_in_effect(&enabled)); // enabled → enforcement in effect
}

// ─────────────────────────── [pg] end-to-end drill ───────────────────────────────

TEST_CASE("sle/agents/{id}: end-to-end through a real SoftwareLicensingStore renders user_ref",
          "[sle_routes][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareLicensingStore store{pool};
    REQUIRE(store.is_open());

    AgentLicenseRow row = lic("Office 365 ProPlus", "subscription_active");
    row.vendor = "Microsoft";
    row.user_scope = "user";
    row.user_ref = "a1b2c3d4e5f60718";
    REQUIRE(store.replace_agent_licenses("agent-pg-1", {row}, "rawhash-1", "hash"));

    yuzu::server::test::TestRouteSink sink;
    SleRoutes routes;
    std::vector<std::string> audits;
    routes.register_routes(
        sink,
        [](const httplib::Request&, httplib::Response&, const std::string&, const std::string&,
           const std::string&) { return true; }, // in-scope
        [&store](const std::string& id) -> std::optional<std::vector<AgentLicenseRow>> {
            return store.agent_licenses(id);
        },
        [](const std::string&) -> DecommissionResult { return {}; },
        [&audits](const httplib::Request&, const std::string& a, const std::string& r,
                  const std::string&, const std::string&, const std::string&) {
            audits.push_back(a + "|" + r);
            return true;
        });

    auto res = sink.Get("/api/v1/sle/agents/agent-pg-1");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = json::parse(res->body)["data"];
    CHECK(j["count"] == 1);
    CHECK(j["licenses"][0]["product"] == "Office 365 ProPlus");
    CHECK(j["licenses"][0]["user_scope"] == "user");
    CHECK(j["licenses"][0]["user_ref"] == "a1b2c3d4e5f60718");

    bool audited = false;
    for (const auto& a : audits)
        if (a == "sle.agent.view|success")
            audited = true;
    CHECK(audited);
}
