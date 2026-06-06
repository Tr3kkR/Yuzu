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
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;

namespace {

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

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_id;
    std::string detail;
};

struct PushCall {
    std::string scope;
    bool full_sync;
};

// Harness: real GuaranteedStateStore + BaselineStore behind GuardianRoutes,
// dispatched through TestRouteSink. TempDbFile members come FIRST so they
// outlive (and clean up after) the stores even if construction throws.
struct Harness {
    yuzu::test::TempDbFile gs_db{std::string_view{"guardian-routes-gs-"}};
    yuzu::test::TempDbFile bl_db{std::string_view{"guardian-routes-bl-"}};

    std::unique_ptr<GuaranteedStateStore> store;
    std::unique_ptr<BaselineStore> baselines;

    std::string session_user{"alice"};
    auth::Role session_role{auth::Role::admin};

    // "Securable:Operation" entries the perm_fn should DENY (default: grant all).
    std::set<std::string> denied;

    // Registry JSON the agents_json_fn returns — tests set this to inject connected
    // agents (with "os") so the platform "not implemented" fold can be exercised.
    std::string agents_json{"[]"};

    std::vector<AuditRecord> audit_log;
    std::vector<PushCall> pushes;

    GuardianRoutes routes;
    yuzu::server::test::TestRouteSink sink;

    Harness() {
        store = std::make_unique<GuaranteedStateStore>(gs_db.path);
        REQUIRE(store->is_open());
        baselines = std::make_unique<BaselineStore>(bl_db.path);
        REQUIRE(baselines->is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            if (session_user.empty())
                return std::nullopt;
            auth::Session s;
            s.username = session_user;
            s.role = session_role;
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
                               baselines.get(), agents_json_fn, push_fn);
    }

    void seed_guard(const std::string& rule_id, const std::string& name) {
        REQUIRE(store->create_rule(make_rule(rule_id, name)));
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
          "[guardian_routes][baseline][create]") {
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
          "[guardian_routes][baseline][create][conflict]") {
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
          "[guardian_routes][baseline][create][rbac]") {
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
          "[guardian_routes][baseline][deploy]") {
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
    CHECK(enforced.count("g1") == 1);
    CHECK(h.audit_count("guaranteed_state.baseline.deploy", "success") == 1);
}

TEST_CASE("deploy_baseline is gated on GuaranteedState:Push (no push when denied)",
          "[guardian_routes][baseline][deploy][rbac]") {
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
    CHECK(h.baselines->deployed_member_rule_ids().empty());
}

TEST_CASE("editing a deployed Baseline does not change what the fleet enforces until re-deploy",
          "[guardian_routes][baseline][snapshot][security]") {
    Harness h;
    h.seed_guard("g1", "GuardOne");
    h.seed_guard("g2", "GuardTwo");
    h.seed_baseline("bl1", "BL1", {"g1"});

    // Deploy with just g1 → that is the enforced set.
    REQUIRE(h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/deploy", "",
                            "application/x-www-form-urlencoded") != nullptr);
    {
        auto enforced = h.baselines->deployed_member_rule_ids();
        CHECK(enforced.size() == 1);
        CHECK(enforced.count("g1") == 1);
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
        CHECK(enforced.size() == 1);
        CHECK(enforced.count("g1") == 1);
        CHECK(enforced.count("g2") == 0);
    }
    CHECK(h.pushes.size() == pushes_after_deploy); // update did not converge the fleet

    // A Push-gated re-deploy is what promotes the edit to the enforced set.
    REQUIRE(h.sink.dispatch("POST", "/fragments/guardian/baseline/bl1/deploy", "",
                            "application/x-www-form-urlencoded") != nullptr);
    auto enforced = h.baselines->deployed_member_rule_ids();
    CHECK(enforced.size() == 2);
    CHECK(enforced.count("g2") == 1);
}

TEST_CASE("delete_baseline_action removes a deployed Baseline and converges the fleet",
          "[guardian_routes][baseline][delete]") {
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
    CHECK(h.baselines->deployed_member_rule_ids().empty());
    CHECK(h.pushes.size() == pushes_before_delete + 1); // convergence push for the removed set
    CHECK(h.audit_count("guaranteed_state.baseline.delete", "success") == 1);
}

TEST_CASE("delete_baseline_action is gated on GuaranteedState:Delete",
          "[guardian_routes][baseline][delete][rbac]") {
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
          "[guardian_routes][baseline][update][rbac]") {
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
          "[guardian_routes][baseline][create]") {
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

// ── Platform honesty: macOS/Linux agents are no-ops, never "armed" ──────────────
// The agent-side Guardian arms guards on Windows only today; an operator must never
// read a connected Mac as compliant/protected when it enforces nothing.

TEST_CASE("overview reports macOS agents as not-implemented, never compliant",
          "[guardian_routes][platform][notimpl]") {
    Harness h;
    // A Guard that targets ALL OSes (empty os_target) so it also targets the Mac.
    auto rule = make_rule("g1", "GuardOne");
    rule.os_target = "";
    REQUIRE(h.store->create_rule(rule));
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
        auto res = h.sink.Get("/fragments/guardian/guard/g1");
        REQUIRE(res != nullptr);
        const std::string& body = res->body;
        CHECK(body.find("not yet implemented") != std::string::npos);
        CHECK(body.find("macbook") != std::string::npos);
        CHECK(body.find("no-op on macOS") != std::string::npos);
        // It must NEVER render the Mac as compliant.
        CHECK(body.find("&#9679; compliant") == std::string::npos);
    }
}

TEST_CASE("a Windows-only Guard does not list connected macOS agents at all",
          "[guardian_routes][platform][notimpl]") {
    Harness h;
    auto rule = make_rule("g1", "WinGuard");  // make_rule sets os_target = "windows"
    REQUIRE(h.store->create_rule(rule));
    h.agents_json = R"([{"agent_id":"mac-1","hostname":"macbook","os":"darwin"}])";

    // The guard targets Windows only, so the Mac is out of scope — it is neither
    // listed as a device nor flagged not-implemented (it isn't a deployed-but-unarmed
    // pair; the guard was never meant for it).
    auto res = h.sink.Get("/fragments/guardian/guard/g1");
    REQUIRE(res != nullptr);
    CHECK(res->body.find("not yet implemented") == std::string::npos);
    CHECK(res->body.find("macbook") == std::string::npos);
}
