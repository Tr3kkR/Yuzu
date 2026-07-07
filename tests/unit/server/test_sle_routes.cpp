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

#include <algorithm>
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
    bool authed = true;         // /sle page-shell session gate
    bool degrade_meta = false;  // posture meta stamp (G-4) degrade
    // Explicit G-4 meta stamp; unset = mimic the row-derived as-of (max
    // refreshed_at over posture_rows) so the PR1a summary assertions hold
    // while the production wiring (meta ALWAYS consulted) is exercised.
    std::optional<std::int64_t> meta_stamp;
    bool degrade_user_ref_mode = false;       // D-10 read-back degrade
    std::optional<std::string> user_ref_mode; // nullopt = never synced (JSON null)
    // Live surfaces dispatch (D-10 second half).
    int dispatch_sent = 1;                   // agents reached; 0 = offline
    std::vector<std::string> dispatch_calls; // "plugin|action|agent_id"
    std::vector<SleCommandResponseRow> canned_rows;
    bool responses_degrade = false;
    // Decommission cascade (D-3): the canned per-store result + a recorder.
    DecommissionResult decommission_result;
    std::vector<std::string> decommission_calls;

    std::vector<LicensePostureRow> posture_rows;
    std::vector<SleLicenseDeviceRow> device_rows;
    std::vector<AgentLicenseRow> agent_rows;

    std::vector<std::string> audits;     // "action|result"
    std::vector<std::string> audit_full; // "action|result|target_type|target_id"
    // The (securable_type, operation[, agent_id]) each gate was ASKED to check —
    // recorded so a wrong-securable / wrong-op / wrong-scope regression in
    // sle_routes.cpp is caught (the args used to be discarded, so any securable
    // passed every test).
    std::vector<std::string> perm_calls;   // "type|op" per GLOBAL-gate check
    std::vector<std::string> scoped_calls; // "type|op|agent_id" per SCOPED-gate check

    SleHarness() {
        auto perm = [this](const httplib::Request&, httplib::Response& res,
                           const std::string& type, const std::string& op) {
            perm_calls.push_back(type + "|" + op);
            if (!allow_perm)
                res.status = perm_deny_status;
            return allow_perm;
        };
        auto scoped = [this](const httplib::Request&, httplib::Response& res,
                             const std::string& type, const std::string& op,
                             const std::string& agent_id) {
            scoped_calls.push_back(type + "|" + op + "|" + agent_id);
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
        auto meta_fn = [this]() -> std::optional<std::int64_t> {
            if (degrade_meta)
                return std::nullopt;
            if (meta_stamp)
                return *meta_stamp;
            std::int64_t derived = 0;
            for (const auto& r : posture_rows)
                derived = std::max(derived, r.refreshed_at);
            return derived;
        };
        auto mode_fn = [this](const std::string&)
            -> std::expected<std::optional<std::string>, LicensingReadError> {
            if (degrade_user_ref_mode)
                return std::unexpected(LicensingReadError::kDegraded);
            return user_ref_mode;
        };
        auto dispatch_fn = [this](const std::string& plugin, const std::string& action,
                                  const std::vector<std::string>& agent_ids, const std::string&,
                                  const std::unordered_map<std::string, std::string>&,
                                  const std::string&) -> std::pair<std::string, int> {
            dispatch_calls.push_back(plugin + "|" + action + "|" +
                                     (agent_ids.empty() ? "" : agent_ids[0]));
            return {"cmd-test-1", dispatch_sent};
        };
        auto responses_fn = [this](const std::string&)
            -> std::optional<std::vector<SleCommandResponseRow>> {
            if (responses_degrade)
                return std::nullopt;
            return canned_rows;
        };
        auto decommission_fn = [this](const std::string& agent_id) -> DecommissionResult {
            decommission_calls.push_back(agent_id);
            return decommission_result;
        };
        routes.register_routes(sink, perm, scoped, posture_fn, devices_fn, agents_fn, audit,
                               meta_fn, mode_fn, dispatch_fn, responses_fn, decommission_fn);
        auto auth = [this](const httplib::Request&,
                           httplib::Response&) -> std::optional<auth::Session> {
            if (!authed)
                return std::nullopt;
            return auth::Session{};
        };
        routes.register_page_routes(sink, auth, perm, posture_fn, meta_fn, audit);
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

// ── F3: each route demands EXACTLY the SoftwareLicensing:Read securable, and the
// drill hands the agent id to the SCOPED gate. Without asserting the recorded
// (type, op[, agent_id]), a wrong-securable/wrong-op regression would pass silently.
TEST_CASE("each SLE route demands exactly SoftwareLicensing:Read (drill via the scoped gate)",
          "[sle_routes]") {
    SleHarness h;
    h.allow_scoped_all = true; // let the drill reach + record the scoped check

    h.sink.Get("/api/v1/sle/summary");
    h.sink.Get("/api/v1/sle/licenses");
    h.sink.Get("/api/v1/sle/licenses/chrome/devices");
    // The three GLOBAL-gated reads each checked exactly SoftwareLicensing:Read.
    REQUIRE(h.perm_calls.size() == 3);
    for (const auto& c : h.perm_calls)
        CHECK(c == "SoftwareLicensing|Read");
    CHECK(h.scoped_calls.empty()); // none of the aggregates touched the scoped gate

    h.sink.Get("/api/v1/sle/agents/agent-77");
    // The drill uses the SCOPED gate ONLY (never the global one) and passes the id.
    CHECK(h.perm_calls.size() == 3); // unchanged — drill did not hit the global gate
    REQUIRE(h.scoped_calls.size() == 1);
    CHECK(h.scoped_calls[0] == "SoftwareLicensing|Read|agent-77");
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

// ───────────────────────── /sle page + Licences fragment (PR1b) ─────────────────

TEST_CASE("/sle page: unauthenticated redirects to /login; authenticated serves the shell "
          "with the SLE nav active",
          "[sle_routes][sle_page]") {
    {
        SleHarness h;
        h.authed = false;
        auto res = h.sink.Get("/sle");
        REQUIRE(res);
        REQUIRE(res->status == 302);
        CHECK(res->get_header_value("Location") == "/login");
    }
    {
        SleHarness h;
        auto res = h.sink.Get("/sle");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        // Active-nav pair: SLE on, the shell's Guardian default off.
        CHECK(contains(res->body, "<a href=\"/sle\" class=\"nav-link active\">SLE</a>"));
        CHECK(contains(res->body, "<a href=\"/guardian\" class=\"nav-link\">Guardian</a>"));
        CHECK_FALSE(contains(res->body, "nav-link active\">Guardian"));
        // Token substitution: title + the fragment mount.
        CHECK(contains(res->body, "Yuzu \xE2\x80\x94 SLE"));
        CHECK(contains(res->body, "/fragments/sle/licenses"));
        CHECK_FALSE(contains(res->body, "{{TITLE}}"));
        CHECK_FALSE(contains(res->body, "{{FRAGMENT}}"));
        CHECK(res->get_header_value("Cache-Control") == "no-cache, no-store, must-revalidate");
    }
}

TEST_CASE("sle fragment: gates on SoftwareLicensing:Read; denied renders no data",
          "[sle_routes][sle_page]") {
    SleHarness h;
    h.posture_rows = {posture("acme:reader", "Reader", "Acme")};
    h.allow_perm = false;
    auto res = h.sink.Get("/fragments/sle/licenses");
    REQUIRE(res);
    REQUIRE(res->status == 403);
    REQUIRE_FALSE(contains(res->body, "Reader"));
    // The gate was asked for exactly the SLE securable.
    bool asked = false;
    for (const auto& c : h.perm_calls)
        if (c == "SoftwareLicensing|Read")
            asked = true;
    CHECK(asked);
}

TEST_CASE("sle fragment: store degrade renders the banner, NEVER an empty table",
          "[sle_routes][sle_page]") {
    SleHarness h;
    h.degrade_posture = true;
    auto res = h.sink.Get("/fragments/sle/licenses");
    REQUIRE(res);
    REQUIRE(res->status == 200); // fragment swaps in-page; the banner carries the honesty
    CHECK(contains(res->body, "Licence posture unavailable"));
    CHECK_FALSE(contains(res->body, "<table"));
    CHECK(h.audited("sle.licenses.view|failure"));
}

TEST_CASE("sle fragment: never-evaluated vs evaluated-but-empty render DISTINCT copy (G-4)",
          "[sle_routes][sle_page]") {
    {
        SleHarness h; // empty rollup, meta derives 0 → never evaluated
        auto res = h.sink.Get("/fragments/sle/licenses");
        REQUIRE(res);
        CHECK(contains(res->body, "has not produced a posture rollup yet"));
        CHECK(contains(res->body, "not yet evaluated"));
    }
    {
        SleHarness h;
        h.meta_stamp = epoch_now(); // evaluated recently — but the estate is empty
        auto res = h.sink.Get("/fragments/sle/licenses");
        REQUIRE(res);
        CHECK(contains(res->body, "found no detected software licences"));
        CHECK_FALSE(contains(res->body, "has not produced a posture rollup yet"));
    }
}

TEST_CASE("sle fragment: KPI tiles carry the summary aggregates; table renders posture rows",
          "[sle_routes][sle_page]") {
    SleHarness h;
    auto a = posture("acme:reader", "Reader", "Acme");
    a.device_count = 4;
    a.install_count = 7;
    a.expired_count = 2;
    a.refreshed_at = epoch_now(); // fresh — no stale flag
    auto b = posture("", "", ""); // the unmatched bucket renders honestly
    b.device_count = 1;
    b.unknown_count = 1;
    b.refreshed_at = a.refreshed_at;
    h.posture_rows = {a, b};
    auto res = h.sink.Get("/fragments/sle/licenses");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    // KPI parity with /sle/summary: same helper, same numbers.
    auto sum = h.sink.Get("/api/v1/sle/summary");
    REQUIRE(sum);
    auto sj = json::parse(sum->body)["data"];
    CHECK(sj["products"] == 2);
    CHECK(sj["lapsed_products"] == 1);
    CHECK(contains(res->body, "Reader"));
    CHECK(contains(res->body, "acme:reader"));
    CHECK(contains(res->body, "(unmatched)"));
    CHECK(contains(res->body, "2 expired"));
    CHECK(h.audited("sle.licenses.view|success"));
}

TEST_CASE("sle fragment: state filter + cap note; KPI tiles stay unfiltered",
          "[sle_routes][sle_page]") {
    SleHarness h;
    auto a = posture("acme:reader", "Reader", "Acme");
    a.expired_count = 1;
    auto b = posture("acme:writer", "Writer", "Acme");
    b.licensed_count = 1;
    h.posture_rows = {a, b};
    {
        auto res = h.sink.Get("/fragments/sle/licenses?state=expired");
        REQUIRE(res);
        CHECK(contains(res->body, "Reader"));
        CHECK_FALSE(contains(res->body, "Writer"));
        // Products KPI still counts the UNFILTERED rollup.
        CHECK(contains(res->body, ">2</div><div class=\"s2\">with detected licences"));
    }
    {
        auto res = h.sink.Get("/fragments/sle/licenses?limit=1");
        REQUIRE(res);
        CHECK(contains(res->body, "list capped"));
    }
}

TEST_CASE("sle/summary: the G-4 meta stamp distinguishes evaluated-but-empty from never-run",
          "[sle_routes]") {
    {
        SleHarness h; // empty rollup, derived stamp 0 → never evaluated
        auto res = h.sink.Get("/api/v1/sle/summary");
        REQUIRE(res);
        auto j = json::parse(res->body)["data"];
        CHECK(j["evaluated"] == false);
        CHECK(j["as_of"] == 0);
    }
    {
        SleHarness h;
        h.meta_stamp = 900; // the evaluator ran; the estate rolled up empty
        auto res = h.sink.Get("/api/v1/sle/summary");
        REQUIRE(res);
        auto j = json::parse(res->body)["data"];
        CHECK(j["evaluated"] == true);
        CHECK(j["as_of"] == 900);
        CHECK(j["products"] == 0);
    }
    {
        SleHarness h;
        h.degrade_meta = true; // a degraded stamp read is a 503, never a false never-run
        auto res = h.sink.Get("/api/v1/sle/summary");
        REQUIRE(res);
        REQUIRE(res->status == 503);
        CHECK(h.audited("sle.summary|failure"));
    }
}

// ───────────────── effective_user_ref_mode read-back (D-10, PR1b) ───────────────

TEST_CASE("sle/agents/{id}: echoes the stored effective_user_ref_mode; null = never synced",
          "[sle_routes]") {
    {
        SleHarness h;
        h.allow_scoped_all = true;
        h.user_ref_mode = "hash";
        auto res = h.sink.Get("/api/v1/sle/agents/agent-1");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        auto j = json::parse(res->body)["data"];
        CHECK(j["effective_user_ref_mode"] == "hash");
    }
    {
        SleHarness h; // default: value holding nullopt = the agent never synced this source
        h.allow_scoped_all = true;
        auto res = h.sink.Get("/api/v1/sle/agents/agent-1");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        auto j = json::parse(res->body)["data"];
        REQUIRE(j.contains("effective_user_ref_mode"));
        CHECK(j["effective_user_ref_mode"].is_null());
    }
}

TEST_CASE("sle/agents/{id}: a degraded mode read is the drill's 503, never a fabricated null",
          "[sle_routes]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.agent_rows = {lic("Reader", "licensed")};
    h.degrade_user_ref_mode = true;
    auto res = h.sink.Get("/api/v1/sle/agents/agent-1");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    CHECK_FALSE(contains(res->body, "Reader")); // no partial body alongside the error
}

// ─────────────── live surfaces dispatch (D-10 second half, PR1b) ────────────────

namespace {
SleCommandResponseRow resp_row(std::string agent, int status, std::string output,
                               std::string error_detail = "") {
    SleCommandResponseRow r;
    r.agent_id = std::move(agent);
    r.status = status;
    r.output = std::move(output);
    r.error_detail = std::move(error_detail);
    return r;
}
} // namespace

TEST_CASE("sle surfaces: both scoped gates asked; out-of-scope never dispatches",
          "[sle_routes][sle_live]") {
    SleHarness h; // allow_scoped_all = false → deny
    auto res = h.sink.Post("/api/v1/sle/agents/agent-9/surfaces", "", "application/json");
    REQUIRE(res);
    REQUIRE(res->status == 403);
    CHECK(h.dispatch_calls.empty());
    // The FIRST gate asked was the SLE read scope for exactly this agent.
    REQUIRE_FALSE(h.scoped_calls.empty());
    CHECK(h.scoped_calls[0] == "SoftwareLicensing|Read|agent-9");
}

TEST_CASE("sle surfaces: Execute is gated separately after the read scope",
          "[sle_routes][sle_live]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.canned_rows = {resp_row("agent-9", 1, "probe_status|slp_wmi|ok|3")};
    auto res = h.sink.Post("/api/v1/sle/agents/agent-9/surfaces", "", "application/json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(h.scoped_calls.size() >= 2);
    CHECK(h.scoped_calls[0] == "SoftwareLicensing|Read|agent-9");
    CHECK(h.scoped_calls[1] == "Execution|Execute|agent-9");
    REQUIRE(h.dispatch_calls.size() == 1);
    CHECK(h.dispatch_calls[0] == "license_scan|surfaces|agent-9");
}

TEST_CASE("sle surfaces: offline device → honest 503, never fabricated diagnostics",
          "[sle_routes][sle_live]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.dispatch_sent = 0;
    auto res = h.sink.Post("/api/v1/sle/agents/agent-9/surfaces", "", "application/json");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    CHECK(contains(res->body, "offline"));
    CHECK_FALSE(contains(res->body, "surfaces\""));
}

TEST_CASE("sle surfaces: happy path parses probe_status lines into the live shape",
          "[sle_routes][sle_live]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.canned_rows = {resp_row("agent-9", 1,
                              "probe_status|slp_wmi|ok|3\n"
                              "probe_status|per_user_hives|error|privilege_missing\n")};
    auto res = h.sink.Post("/api/v1/sle/agents/agent-9/surfaces", "", "application/json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = json::parse(res->body)["data"];
    CHECK(j["agent_id"] == "agent-9");
    CHECK(j["live"] == true);
    CHECK(j["count"] == 2);
    REQUIRE(j["surfaces"].size() == 2);
    CHECK(j["surfaces"][0]["surface"] == "slp_wmi");
    CHECK(j["surfaces"][0]["status"] == "ok");
    CHECK(j["surfaces"][0]["rows"] == 3);
    CHECK(j["surfaces"][1]["surface"] == "per_user_hives");
    CHECK(j["surfaces"][1]["status"] == "error");
    CHECK(j["surfaces"][1]["detail"] == "privilege_missing");
}

TEST_CASE("sle surfaces: failure wins over partial output (502)", "[sle_routes][sle_live]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.canned_rows = {resp_row("agent-9", 2, "probe_status|slp_wmi|ok|3", "plugin crashed")};
    auto res = h.sink.Post("/api/v1/sle/agents/agent-9/surfaces", "", "application/json");
    REQUIRE(res);
    REQUIRE(res->status == 502);
    CHECK(contains(res->body, "plugin crashed"));
}

TEST_CASE("sle surfaces: another agent's rows are never rendered; poll budget → 504",
          "[sle_routes][sle_live]") {
    // Shrink the poll budget so the miss path resolves fast; restore after.
    auto& polls = sle_detail::sle_live_poll_max_polls();
    auto& interval = sle_detail::sle_live_poll_interval_ms();
    const int old_polls = polls.exchange(2);
    const int old_interval = interval.exchange(1);
    {
        SleHarness h;
        h.allow_scoped_all = true;
        h.canned_rows = {resp_row("someone-else", 1, "probe_status|slp_wmi|ok|3")};
        auto res = h.sink.Post("/api/v1/sle/agents/agent-9/surfaces", "", "application/json");
        REQUIRE(res);
        REQUIRE(res->status == 504);
        CHECK_FALSE(contains(res->body, "slp_wmi"));
    }
    polls.store(old_polls);
    interval.store(old_interval);
}

TEST_CASE("sle surfaces: in-flight cap → 429 with no dispatch", "[sle_routes][sle_live]") {
    auto& cap = sle_detail::sle_live_max_inflight();
    const int old_cap = cap.exchange(0);
    {
        SleHarness h;
        h.allow_scoped_all = true;
        auto res = h.sink.Post("/api/v1/sle/agents/agent-9/surfaces", "", "application/json");
        REQUIRE(res);
        REQUIRE(res->status == 429);
        CHECK(h.dispatch_calls.empty());
    }
    cap.store(old_cap);
}

TEST_CASE("sle surfaces: degraded response store → 503", "[sle_routes][sle_live]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.responses_degrade = true;
    auto res = h.sink.Post("/api/v1/sle/agents/agent-9/surfaces", "", "application/json");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    CHECK(contains(res->body, "response store"));
}

TEST_CASE("sle surfaces: hostile lic| lines can never reflect user_ref through the live "
          "route (whitelist parser)",
          "[sle_routes][sle_live]") {
    {
        SleHarness h;
        h.allow_scoped_all = true;
        h.canned_rows = {resp_row("agent-9", 1,
                                  "lic|Reader|Acme|1.0|subscription|licensed|0|||wmi|probable||"
                                  "user|alice|0\n"
                                  "probe_status|slp_wmi|ok|3\n")};
        auto res = h.sink.Post("/api/v1/sle/agents/agent-9/surfaces", "", "application/json");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        CHECK_FALSE(contains(res->body, "alice"));
        CHECK_FALSE(contains(res->body, "user_ref"));
        auto j = json::parse(res->body)["data"];
        CHECK(j["count"] == 1); // only the probe_status line survived
    }
    {
        SleHarness h; // output with ZERO valid lines is malformed, not empty
        h.allow_scoped_all = true;
        h.canned_rows = {resp_row("agent-9", 1, "lic|Reader|Acme|only|garbage")};
        auto res = h.sink.Post("/api/v1/sle/agents/agent-9/surfaces", "", "application/json");
        REQUIRE(res);
        REQUIRE(res->status == 502);
        CHECK(contains(res->body, "malformed"));
    }
    {
        // A WELL-FORMED error line whose reason smuggles a structured identifier
        // in free text (a hypothetical buggy plugin passing an OS error through
        // — the real plugin only emits bounded reason tokens like
        // privilege_missing / wmi_query_failed_<hex>). The token sanitizer
        // constrains the reflected surface + reason to the safe [a-z0-9_.-]
        // charset with a length cap, so the structured `DOMAIN\jdoe` form
        // (backslash + spaces = a recoverable AD identity) can never be
        // reflected verbatim (sec-M1: the guarantee is server-enforced, not a
        // trust assumption on the agent).
        SleHarness h;
        h.allow_scoped_all = true;
        h.canned_rows = {resp_row(
            "agent-9", 1, "probe_status|hkcu_per_user|error|access denied for DOMAIN\\jdoe\n")};
        auto res = h.sink.Post("/api/v1/sle/agents/agent-9/surfaces", "", "application/json");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        // No structured-identifier form survives: no backslash, no whitespace,
        // and the `DOMAIN\jdoe` composite is broken apart into safe tokens.
        CHECK_FALSE(contains(res->body, "\\"));
        CHECK_FALSE(contains(res->body, "DOMAIN\\jdoe"));
        CHECK_FALSE(contains(res->body, "access denied")); // the raw free-text form is gone
        auto j = json::parse(res->body)["data"];
        REQUIRE(j["surfaces"].size() == 1);
        CHECK(j["surfaces"][0]["surface"] == "hkcu_per_user"); // a clean name survives intact
        CHECK(j["surfaces"][0]["status"] == "error");
        // Only the safe charset (lowercased, invalid-byte runs collapsed to '_').
        const std::string detail = j["surfaces"][0]["detail"].get<std::string>();
        for (char c : detail) {
            const bool safe = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' ||
                              c == '.' || c == '-';
            CHECK(safe);
        }
    }
    {
        // The real bounded reason tokens survive intact (incl. the
        // variable-suffix wmi_query_failed_<hex> form — all safe charset).
        SleHarness h;
        h.allow_scoped_all = true;
        h.canned_rows = {resp_row("agent-9", 1,
                                  "probe_status|slp_wmi|error|wmi_query_failed_80041003\n"
                                  "probe_status|per_user_hives|error|privilege_missing\n")};
        auto res = h.sink.Post("/api/v1/sle/agents/agent-9/surfaces", "", "application/json");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        auto j = json::parse(res->body)["data"];
        REQUIRE(j["surfaces"].size() == 2);
        CHECK(j["surfaces"][0]["detail"] == "wmi_query_failed_80041003");
        CHECK(j["surfaces"][1]["detail"] == "privilege_missing");
    }
}

TEST_CASE("sle surfaces: audited set-and-proceed BEFORE dispatch (deliberate contrast with "
          "the drill's fail-closed tier)",
          "[sle_routes][sle_live]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.audit_should_fail = true; // a dropped audit row must NOT block the machine-health read
    h.canned_rows = {resp_row("agent-9", 1, "probe_status|slp_wmi|ok|3")};
    auto res = h.sink.Post("/api/v1/sle/agents/agent-9/surfaces", "", "application/json");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    CHECK(h.audited("sle.agent.surfaces|requested"));
}

TEST_CASE("sle surfaces: GET is not routed (POST-only side effect)", "[sle_routes][sle_live]") {
    SleHarness h;
    h.allow_scoped_all = true;
    auto res = h.sink.Get("/api/v1/sle/agents/agent-9/surfaces");
    CHECK_FALSE(res); // no GET handler matches — the dispatch is POST-only
}

// ──────────── DELETE /sle/agents/{id} — the erasure cascade trigger (D-3) ────────

TEST_CASE("sle DELETE: gated on scoped SoftwareLicensing:Delete; denied never erases",
          "[sle_routes][sle_delete]") {
    SleHarness h; // scoped gate denies by default
    h.decommission_result.agent_id = "agent-9";
    auto res = h.sink.Delete("/api/v1/sle/agents/agent-9");
    REQUIRE(res);
    REQUIRE(res->status == 403);
    CHECK(h.decommission_calls.empty());
    REQUIRE_FALSE(h.scoped_calls.empty());
    CHECK(h.scoped_calls[0] == "SoftwareLicensing|Delete|agent-9");
    // No erasure audit of any kind was written for a denied request.
    CHECK_FALSE(h.audited("sle.agent.decommission|attempt"));
}

TEST_CASE("sle DELETE: audit-before-erase FAILS CLOSED — 503 + Sec-Audit-Failed, no cascade",
          "[sle_routes][sle_delete]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.audit_should_fail = true;
    auto res = h.sink.Delete("/api/v1/sle/agents/agent-9");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    CHECK(res->get_header_value("Sec-Audit-Failed") == "true");
    CHECK(h.decommission_calls.empty()); // the load-bearing assertion: nothing was erased
}

TEST_CASE("sle DELETE: happy path — ordered attempt then success audits + per-store breakdown",
          "[sle_routes][sle_delete]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.decommission_result.agent_id = "agent-9";
    h.decommission_result.stores = {{"inventory", DecommissionOutcome::Deleted, ""},
                                    {"software_licensing", DecommissionOutcome::Deleted, ""},
                                    {"app_perf_daily", DecommissionOutcome::Skipped, ""}};
    h.decommission_result.deleted = 2;
    h.decommission_result.skipped = 1;
    auto res = h.sink.Delete("/api/v1/sle/agents/agent-9");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto j = json::parse(res->body)["data"];
    CHECK(j["decommissioned"] == true);
    CHECK(j["stores"]["inventory"] == "deleted");
    CHECK(j["stores"]["software_licensing"] == "deleted");
    CHECK(j["stores"]["app_perf_daily"] == "skipped");
    CHECK(j["deleted"] == 2);
    CHECK(j["skipped"] == 1);
    CHECK(j["failed"] == 0);
    REQUIRE(h.decommission_calls.size() == 1);
    CHECK(h.decommission_calls[0] == "agent-9");
    // Ordered evidence chain: attempt BEFORE the cascade, outcome after.
    REQUIRE(h.audits.size() >= 2);
    CHECK(h.audited("sle.agent.decommission|attempt"));
    CHECK(h.audited("sle.agent.decommission|success"));
    std::size_t attempt_at = 999, success_at = 999;
    for (std::size_t i = 0; i < h.audits.size(); ++i) {
        if (h.audits[i] == "sle.agent.decommission|attempt")
            attempt_at = i;
        if (h.audits[i] == "sle.agent.decommission|success")
            success_at = i;
    }
    CHECK(attempt_at < success_at);
}

TEST_CASE("sle DELETE: a store that threw → 500 + partial audit (idempotent retry story)",
          "[sle_routes][sle_delete]") {
    SleHarness h;
    h.allow_scoped_all = true;
    h.decommission_result.stores = {{"inventory", DecommissionOutcome::Deleted, ""},
                                    {"software_licensing", DecommissionOutcome::Failed, "boom"}};
    h.decommission_result.deleted = 1;
    h.decommission_result.failed = 1;
    auto res = h.sink.Delete("/api/v1/sle/agents/agent-9");
    REQUIRE(res);
    REQUIRE(res->status == 500);
    CHECK(contains(res->body, "incomplete"));
    CHECK(contains(res->body, "re-issue"));
    CHECK(h.audited("sle.agent.decommission|partial"));
}

TEST_CASE("sle DELETE: unwired cascade → 503 fail-closed, no attempt audit",
          "[sle_routes][sle_delete]") {
    // A bare registration with every trailing dep defaulted: the DELETE must
    // refuse (fail-closed) rather than pretend to erase — and must not write
    // an attempt audit for an operation it cannot perform.
    yuzu::server::test::TestRouteSink sink;
    SleRoutes routes;
    routes.register_routes(
        sink,
        [](const httplib::Request&, httplib::Response&, const std::string&,
           const std::string&) { return true; },
        [](const httplib::Request&, httplib::Response&, const std::string&, const std::string&,
           const std::string&) { return true; },
        {}, {}, {});
    auto res = sink.Delete("/api/v1/sle/agents/agent-9");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    CHECK(res->body.find("not configured") != std::string::npos);
}
