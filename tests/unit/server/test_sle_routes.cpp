/// @file test_sle_routes.cpp
/// Tests for the /api/v1/sle/* SLE read surface (ADR-0024, PR1a) — the four
/// Decision-3.5 read endpoints driven in-process through TestRouteSink (no
/// httplib acceptor, #438). Focus, in the security order the roadmap scrutinises:
///   * authz — 401 (no auth) / 403 (lacks SoftwareLicensing:Read) on every route;
///   * [sle][adr0017] — the fleet aggregates (summary, licenses) return 403 to a
///     group-confined/scoped principal, NEVER a partial rollup (pinned global-only);
///   * the /sle/agents/{id} DRILL scoped gate — in-scope 200 / out-of-scope 403 (D-4);
///   * the fan-out list is global-gated (the "filters before LIMIT" test is deferred
///     to the ADR-0017 PR-A flip — documented, not implemented here);
///   * 503-on-degrade renders an A4 error, NEVER an empty 200 (ADR-0024 Decision 4);
///   * limit clamp 1..1000 (0 -> 1, 5000 -> 1000);
///   * the drill's per-open behavioural audit (sle.agent.view) is emitted and FAILS
///     CLOSED (503 + Sec-Audit-Failed) on a persist failure (G-2);
///   * the SoftwareLicensing securable D-9 matrix is seeded EXACTLY (rbac_store);
///   * the G-1 fail-closed enforcement primitive is the one the production gates use.
/// Plus one [pg] end-to-end drill through a real SoftwareLicensingStore.

#include "sle_routes.hpp"
#include "test_route_sink.hpp"

#include "rbac_store.hpp"
#include "software_licensing_store.hpp"

#include "pg/pg_pool.hpp"
#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
using nlohmann::json;

namespace {

std::int64_t epoch_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

LicensePostureRow posture(std::string key, std::string title, std::string vendor) {
    LicensePostureRow r;
    r.product_key = std::move(key);
    r.title = std::move(title);
    r.vendor = std::move(vendor);
    r.refreshed_at = 5000;
    return r;
}

AgentLicenseRow lic(std::string product, std::string state) {
    AgentLicenseRow r;
    r.product = std::move(product);
    r.state = std::move(state);
    r.user_scope = "machine";
    return r;
}

// ── Route harness — all providers injected, every flag re-read per call ──────────
struct SleHarness {
    yuzu::server::test::TestRouteSink sink;
    SleRoutes routes;

    bool allow_perm = true;         // GLOBAL SoftwareLicensing:Read gate
    int perm_deny_status = 403;     // 401 or 403 when allow_perm is false
    bool allow_scoped_all = false;  // scoped gate admits every agent
    std::vector<std::string> scoped_agents; // ...or just these agents (D-4 in-scope set)
    bool degrade_posture = false;
    bool degrade_devices = false;
    bool degrade_agent = false;
    bool audit_should_fail = false;

    std::vector<LicensePostureRow> posture_rows;
    std::vector<SleLicenseDeviceRow> device_rows;
    std::vector<AgentLicenseRow> agent_rows;

    std::vector<std::string> audits;     // "action|result"
    std::vector<std::string> audit_full; // "action|result|target_type|target_id"

    SleHarness() {
        auto perm = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                           const std::string&) {
            if (!allow_perm)
                res.status = perm_deny_status;
            return allow_perm;
        };
        auto scoped = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                             const std::string&, const std::string& agent_id) {
            bool ok = allow_scoped_all;
            for (const auto& a : scoped_agents)
                if (a == agent_id)
                    ok = true;
            if (!ok)
                res.status = 403;
            return ok;
        };
        auto posture_fn = [this]() -> std::optional<std::vector<LicensePostureRow>> {
            if (degrade_posture)
                return std::nullopt;
            return posture_rows;
        };
        auto devices_fn = [this](const std::string&, int)
            -> std::optional<std::vector<SleLicenseDeviceRow>> {
            if (degrade_devices)
                return std::nullopt;
            return device_rows;
        };
        auto agents_fn = [this](const std::string&) -> std::optional<std::vector<AgentLicenseRow>> {
            if (degrade_agent)
                return std::nullopt;
            return agent_rows;
        };
        auto audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string& tt, const std::string& tid, const std::string&) {
            audits.push_back(a + "|" + r);
            audit_full.push_back(a + "|" + r + "|" + tt + "|" + tid);
            return !audit_should_fail;
        };
        routes.register_routes(sink, perm, scoped, posture_fn, devices_fn, agents_fn, audit);
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

} // namespace

// ───────────────────────────── authz ────────────────────────────────────────────

TEST_CASE("sle/summary: 401 without auth, 403 without SoftwareLicensing:Read", "[sle_routes]") {
    {
        SleHarness h;
        h.allow_perm = false;
        h.perm_deny_status = 401;
        auto res = h.sink.Get("/api/v1/sle/summary");
        REQUIRE(res);
        REQUIRE(res->status == 401);
        REQUIRE_FALSE(contains(res->body, "evaluated"));
    }
    {
        SleHarness h;
        h.allow_perm = false; // 403 by default
        auto res = h.sink.Get("/api/v1/sle/summary");
        REQUIRE(res);
        REQUIRE(res->status == 403);
        REQUIRE_FALSE(contains(res->body, "evaluated"));
    }
}

TEST_CASE("sle/licenses + fan-out + drill: denied without the securable", "[sle_routes]") {
    SleHarness h;
    h.allow_perm = false; // aggregates + fan-out gate on perm_fn
    // The drill gates on the scoped fn (allow_scoped_all=false → deny).
    for (const auto* path : {"/api/v1/sle/licenses", "/api/v1/sle/licenses/foo/devices",
                             "/api/v1/sle/agents/a1"}) {
        auto res = h.sink.Get(path);
        REQUIRE(res);
        CHECK(res->status == 403);
    }
}

// ── [sle][adr0017] — aggregates are pinned global-only: a group-confined principal
// is 403'd at the GLOBAL gate, NEVER served a partial/leaky rollup. Here the injected
// perm_fn models the global-gate denial (server.cpp resolves it via check_permission,
// the GLOBAL grant — a management-group-scoped operator holds only a scoped grant and
// is denied). We prove the rollup rows are populated yet NONE leak on a denied read.
TEST_CASE("sle aggregates return 403 to a scoped principal, never a partial rollup",
          "[sle][adr0017]") {
    SleHarness h;
    h.posture_rows = {posture("chrome", "Google Chrome", "Google"),
                      posture("office", "Microsoft Office", "Microsoft")};
    h.allow_perm = false; // group-confined principal → global gate denies (403)

    auto summary = h.sink.Get("/api/v1/sle/summary");
    REQUIRE(summary);
    CHECK(summary->status == 403);
    CHECK_FALSE(contains(summary->body, "Chrome"));
    CHECK_FALSE(contains(summary->body, "products")); // no aggregate leaked

    auto licenses = h.sink.Get("/api/v1/sle/licenses");
    REQUIRE(licenses);
    CHECK(licenses->status == 403);
    CHECK_FALSE(contains(licenses->body, "Chrome"));
    CHECK_FALSE(contains(licenses->body, "office")); // no partial rollup leaked
}

// ───────────────────────── summary aggregation + honesty ────────────────────────

TEST_CASE("sle/summary: honest empty in PR1a (evaluated=false), never a fabricated zero lie",
          "[sle_routes]") {
    SleHarness h; // posture_rows empty (the PR1b evaluator hasn't run)
    auto res = h.sink.Get("/api/v1/sle/summary");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto b = json::parse(res->body);
    CHECK(b["data"]["evaluated"] == false); // honest "not yet evaluated", not a real zero estate
    CHECK(b["data"]["as_of"] == 0);
    CHECK(b["data"]["products"] == 0);
    CHECK(h.audited("sle.summary|success"));
}

TEST_CASE("sle/summary: aggregates derive from the rollup", "[sle_routes]") {
    SleHarness h;
    auto a = posture("a", "A", "v");
    a.install_count = 10;
    a.expired_count = 2; // lapsed
    a.expiring_soon_count = 3;
    a.next_expiry_at = 1000;
    a.refreshed_at = 5000;
    auto b = posture("b", "B", "v");
    b.install_count = 5;
    b.expiring_soon_count = 1;
    b.next_expiry_at = 2000;
    b.refreshed_at = 6000;
    h.posture_rows = {a, b};
    auto res = h.sink.Get("/api/v1/sle/summary");
    REQUIRE(res);
    auto j = json::parse(res->body)["data"];
    CHECK(j["evaluated"] == true);
    CHECK(j["as_of"] == 6000);          // max refreshed_at
    CHECK(j["products"] == 2);
    CHECK(j["installs"] == 15);
    CHECK(j["lapsed_products"] == 1);   // only A has expired>0
    CHECK(j["expiring_soon"] == 4);
    CHECK(j["next_expiry_at"] == 1000); // min POSITIVE next_expiry_at
}

TEST_CASE("sle/summary: store degrade → 503 + audited failure, never an empty 200", "[sle_routes]") {
    SleHarness h;
    h.degrade_posture = true;
    auto res = h.sink.Get("/api/v1/sle/summary");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    CHECK(contains(res->body, "unavailable"));
    CHECK(res->has_header("X-Correlation-Id"));
    CHECK(h.audited("sle.summary|failure"));
}

// ───────────────────────── licenses: filters + clamp ────────────────────────────

TEST_CASE("sle/licenses: state / q / expiring filters", "[sle_routes]") {
    SleHarness h;
    auto chrome = posture("chrome", "Google Chrome", "Google");
    chrome.expired_count = 1;
    chrome.next_expiry_at = epoch_now() + 5 * 86400; // 5 days out
    auto office = posture("office", "Microsoft Office", "Microsoft");
    office.licensed_count = 1;
    office.next_expiry_at = 0; // perpetual
    h.posture_rows = {chrome, office};

    // state=expired → only Chrome (expired_count>0)
    auto s = json::parse(h.sink.Get("/api/v1/sle/licenses?state=expired")->body)["data"];
    CHECK(s["count"] == 1);
    CHECK(s["licenses"][0]["product_key"] == "chrome");

    // q=micro → only Office (case-insensitive substring on vendor)
    auto q = json::parse(h.sink.Get("/api/v1/sle/licenses?q=micro")->body)["data"];
    CHECK(q["count"] == 1);
    CHECK(q["licenses"][0]["product_key"] == "office");

    // expiring_within_days=10 → Chrome (5d) in, Office (perpetual) out
    auto e10 = json::parse(h.sink.Get("/api/v1/sle/licenses?expiring_within_days=10")->body)["data"];
    CHECK(e10["count"] == 1);
    // expiring_within_days=3 → Chrome (5d) now excluded
    auto e3 = json::parse(h.sink.Get("/api/v1/sle/licenses?expiring_within_days=3")->body)["data"];
    CHECK(e3["count"] == 0);
    CHECK(e3["licenses"].empty());
}

TEST_CASE("sle/licenses: limit clamp 1..1000 (0 -> 1, 5000 -> 1000)", "[sle_routes]") {
    SleHarness h;
    for (int i = 0; i < 1001; ++i)
        h.posture_rows.push_back(posture("k" + std::to_string(i), "T", "v"));

    // limit=0 clamps UP to 1 — one row on the page, but the full match count + truncation flag.
    auto lo = json::parse(h.sink.Get("/api/v1/sle/licenses?limit=0")->body)["data"];
    CHECK(lo["licenses"].size() == 1);
    CHECK(lo["count"] == 1001);
    CHECK(lo["result_truncated_by_cap"] == true);

    // limit=5000 clamps DOWN to 1000 — exactly the cap, not the full 1001.
    auto hi = json::parse(h.sink.Get("/api/v1/sle/licenses?limit=5000")->body)["data"];
    CHECK(hi["licenses"].size() == 1000);
    CHECK(hi["count"] == 1001);
    CHECK(hi["result_truncated_by_cap"] == true);

    // Default (no limit) = 200.
    auto def = json::parse(h.sink.Get("/api/v1/sle/licenses")->body)["data"];
    CHECK(def["licenses"].size() == 200);
}

TEST_CASE("sle/licenses: degrade → 503 not empty", "[sle_routes]") {
    SleHarness h;
    h.degrade_posture = true;
    auto res = h.sink.Get("/api/v1/sle/licenses");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    CHECK(h.audited("sle.licenses.query|failure"));
}

// ── fan-out list: global-gated NOW (ADR-0017 PR-A flip-wave consumer, #1634/#1715).
// The admit-then-filter management-group chokepoint and its "filters BEFORE the LIMIT"
// completeness test land AT THE FLIP, NOT in PR1a — deliberately NOT tested here. PR1a
// wires an honest-empty provider; a store degrade is still an honest 503.
TEST_CASE("sle/licenses/{key}/devices: global-gated; honest empty vs degrade", "[sle_routes]") {
    {
        SleHarness h; // wired provider returns an empty list (PR1a: no per-device breakdown yet)
        auto res = h.sink.Get("/api/v1/sle/licenses/chrome/devices");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        auto j = json::parse(res->body)["data"];
        CHECK(j["product_key"] == "chrome");
        CHECK(j["count"] == 0);
        CHECK(j["devices"].empty()); // honest empty, NOT a degrade
        CHECK(h.audited("sle.licenses.devices|success"));
    }
    {
        SleHarness h;
        h.degrade_devices = true;
        auto res = h.sink.Get("/api/v1/sle/licenses/chrome/devices");
        REQUIRE(res);
        REQUIRE(res->status == 503); // a real degrade is a 503, never an empty 200
        CHECK(h.audited("sle.licenses.devices|failure"));
    }
    {
        // With rows the provider would carry, they render + cap applies (foundation only).
        SleHarness h;
        SleLicenseDeviceRow d;
        d.agent_id = "agent-x";
        d.hostname = "WIN-X";
        d.state = "expired";
        h.device_rows = {d};
        auto j = json::parse(h.sink.Get("/api/v1/sle/licenses/chrome/devices")->body)["data"];
        CHECK(j["count"] == 1);
        CHECK(j["devices"][0]["agent_id"] == "agent-x");
    }
}

// ───────────────────── /sle/agents/{id} drill — D-4 scoped gate + G-2 audit ──────

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

TEST_CASE("sle/agents/{id}: store degrade → 503, never an empty 200", "[sle_routes]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.degrade_agent = true;
    auto res = h.sink.Get("/api/v1/sle/agents/agent-1");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(contains(res->body, "unavailable"));
    // The per-open audit still fired on open (before the degraded read) — access recorded.
    CHECK(h.audited("sle.agent.view|success"));
}

// ─────────────────────── SoftwareLicensing securable D-9 matrix ──────────────────

TEST_CASE("SoftwareLicensing securable seeds the D-9 matrix EXACTLY", "[sle][rbac]") {
    RbacStore s(":memory:");

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

    // Administrator: full CRUD (its global pattern).
    for (const auto* op : {"Read", "Write", "Execute", "Delete"})
        CHECK(role_can(s, "Administrator", "SoftwareLicensing", op));

    // DISTINCT from Yuzu's own `License` securable (§22.3) — the SLE grants must not
    // have accidentally landed on `License` nor vice-versa.
    CHECK(role_can(s, "Operator", "License", "Read"));
    CHECK_FALSE(role_can(s, "Operator", "License", "Write")); // License stays Operator-Read-only
}

// ── G-1: the SLE route gates are built on the FAIL-CLOSED enforcement primitive
// (rbac_enforcement_in_effect), NOT the raw is_rbac_enabled() shape whose corrupt-
// rbac.db fall-through to a legacy-open Read is the #1717 fail-open. The routes take
// an INJECTED gate closure, so the production wiring (server.cpp's sle_gate_usable →
// require_permission / require_scoped_permission, all branched on this predicate) is
// exercised at the server.cpp boundary and is not reachable through the injected
// closure at the route-unit level. Assert the primitive's fail-closed contract
// directly — the exact predicate server.cpp branches on (mirrors the #1498 test).
TEST_CASE("SLE gates use the fail-closed enforcement primitive (G-1 / #1717)", "[sle][adr0017]") {
    CHECK(rbac_enforcement_in_effect(nullptr)); // null store → enforcement in effect (deny, not legacy-open)

    RbacStore disabled(":memory:");
    REQUIRE(disabled.is_open());
    REQUIRE_FALSE(disabled.is_rbac_enabled());
    CHECK_FALSE(rbac_enforcement_in_effect(&disabled)); // loaded + explicitly disabled → legacy-open

    RbacStore enabled(":memory:");
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
        [](const httplib::Request&, httplib::Response&, const std::string&, const std::string&) {
            return true;
        },
        [](const httplib::Request&, httplib::Response&, const std::string&, const std::string&,
           const std::string&) { return true; }, // in-scope
        []() -> std::optional<std::vector<LicensePostureRow>> {
            return std::vector<LicensePostureRow>{};
        },
        [](const std::string&, int) -> std::optional<std::vector<SleLicenseDeviceRow>> {
            return std::vector<SleLicenseDeviceRow>{};
        },
        [&store](const std::string& id) -> std::optional<std::vector<AgentLicenseRow>> {
            return store.agent_licenses(id);
        },
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
