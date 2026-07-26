/**
 * test_dashboard_tar_fragments.cpp — route-handler coverage for the TAR
 * retention-paused DASHBOARD FRAGMENT POSTs (issue #1786):
 *   - POST /fragments/tar/retention-paused/purge   (destructive)
 *   - POST /fragments/tar/retention-paused/reenable
 *
 * Until #1786 these two handlers were registered directly on a raw
 * httplib::Server, so the in-process route harness could not reach them and
 * their security gates were untested — a refactor that dropped one would not
 * fail any test. `DashboardRoutes::register_routes` now has an HttpRouteSink
 * overload (the httplib::Server& overload wraps + delegates to it), so the
 * handlers are drivable here with no acceptor thread (#438 TSan trap).
 *
 * Pinned per handler:
 *   - the permission tier — Infrastructure:Delete for purge, Execution:Execute
 *     for reenable (a tier downgrade must fail here), plus the denied audit +
 *     `result="denied"` metric on rejection,
 *   - the CSRF same-site gate — cross-origin AND header-less POSTs are 403'd
 *     BEFORE dispatch (these fragments are stricter than the shared
 *     `origin_is_same_site` helper, which permits header-less non-browser
 *     clients; programmatic callers use the REST twin instead),
 *   - the {process,tcp,service,user} source allowlist and the
 *     required-field check → 400, no dispatch,
 *   - the per-device RBAC visibility gate → 404 collapsed with the offline
 *     case (no existence oracle) + a `scope_violation` audit recording the
 *     real reason server-side,
 *   - the offline (0 agents reached) path → 404 + `agent_not_connected`,
 *   - the success dispatch shape — tar/purge_source {source} and
 *     tar/configure {<source>_enabled=true}, targeting the one device only.
 *
 * The REST twin (POST /api/v1/tar/retention-paused/purge) is covered by
 * test_rest_tar_purge.cpp; the render-time button gating by
 * test_dashboard_tar_retention.cpp.
 */

#include "dashboard_routes.hpp"
#include "management_group_store.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

constexpr const char* kUser = "frag-op";
constexpr const char* kHost = "yuzu.example:8080";
constexpr const char* kPurgePath = "/fragments/tar/retention-paused/purge";
constexpr const char* kReenablePath = "/fragments/tar/retention-paused/reenable";

struct DispatchCall {
    std::string plugin, action, scope_expr;
    std::vector<std::string> agent_ids;
    std::unordered_map<std::string, std::string> params;
};
struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};
struct PermCall {
    std::string securable_type, op;
};

/// Make `agents` visible to kUser: members of a group on which kUser holds a
/// role (get_visible_agents is the role-scoped join, and fails CLOSED with the
/// rbac_enabled_probe unset — same posture as production with RBAC on).
void grant_visibility(ManagementGroupStore& mg, std::initializer_list<std::string> agents) {
    ManagementGroup g;
    g.name = "All Devices";
    g.membership_type = "static";
    auto gid = mg.create_group(g);
    REQUIRE(gid.has_value());
    for (const auto& a : agents)
        mg.add_member(*gid, a);
    GroupRoleAssignment ra;
    ra.group_id = *gid;
    ra.principal_type = "user";
    ra.principal_id = kUser;
    ra.role_name = "ITServiceOwner";
    REQUIRE(mg.assign_role(ra).has_value());
}

struct FragmentHarness {
    // `yuzu_test_` prefix so the path lands inside the Wee Tam Defender
    // exclusion wildcard `yuzu_*` (CLAUDE.md → Test conventions).
    yuzu::test::TempDbFile mg_db{std::string_view{"yuzu_test_tar_frag_mg_"}};
    ManagementGroupStore mg{mg_db.path};
    yuzu::MetricsRegistry metrics;
    yuzu::server::test::TestRouteSink sink;
    DashboardRoutes routes;

    std::vector<DispatchCall> calls;
    std::vector<AuditRow> audits;
    std::vector<PermCall> perms;
    bool perm_allow{true}; ///< perm_fn verdict (false → handler's 403 path)
    int dispatch_sent{1};  ///< agents reached per dispatch (0 → offline 404)

    /// @param with_dispatch false → register with an empty DispatchFn so the
    ///        "dispatch unavailable" 503 branch is reachable.
    explicit FragmentHarness(bool with_dispatch = true) {
        grant_visibility(mg, {"dev-A", "dev-B"});

        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = kUser;
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string& type, const std::string& op) -> bool {
            perms.push_back({type, op});
            if (!perm_allow)
                res.status = 403;
            return perm_allow;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& a,
                               const std::string& r, const std::string& tt,
                               const std::string& tid, const std::string& d) {
            audits.push_back({a, r, tt, tid, d});
        };
        DashboardRoutes::DispatchFn dispatch =
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& ids, const std::string& scope,
                   const std::unordered_map<std::string, std::string>& params)
            -> std::pair<std::string, int> {
            calls.push_back({plugin, action, scope, ids, params});
            return {"cmd-" + std::to_string(calls.size()), dispatch_sent};
        };

        routes.register_routes(sink, auth_fn, perm_fn, audit_fn,
                               /*response_store=*/nullptr, &mg, /*registry=*/nullptr,
                               /*tag_store=*/nullptr, /*event_bus=*/nullptr,
                               /*agents_json_fn=*/[] { return std::string{"[]"}; },
                               with_dispatch ? dispatch : DashboardRoutes::DispatchFn{},
                               /*resolve_fn=*/
                               [](const std::string&) {
                                   return std::pair<std::string, std::string>{};
                               },
                               &metrics, /*instruction_store=*/nullptr);
    }

    static std::unordered_map<std::string, std::string> same_site_headers() {
        return {{"Host", kHost}, {"Origin", std::string{"https://"} + kHost}};
    }

    std::unique_ptr<httplib::Response>
    post(const std::string& path, const std::string& body,
         const std::unordered_map<std::string, std::string>& headers = same_site_headers()) {
        auto res = sink.dispatch("POST", path, body, "application/x-www-form-urlencoded", headers);
        REQUIRE(res != nullptr);
        return res;
    }

    int audits_for(const std::string& action, const std::string& result) const {
        int n = 0;
        for (const auto& a : audits)
            if (a.action == action && a.result == result)
                ++n;
        return n;
    }
    /// Detail string of the first audit row matching (action, result); "" if none.
    std::string audit_detail(const std::string& action, const std::string& result) const {
        for (const auto& a : audits)
            if (a.action == action && a.result == result)
                return a.detail;
        return {};
    }
    double metric(const std::string& name, const std::string& result) {
        return metrics.counter(name, {{"result", result}}).value();
    }
};

bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

} // namespace

// ── Permission tier ─────────────────────────────────────────────────────────

TEST_CASE("fragment purge: gates on Infrastructure:Delete; denial audits + counts, no dispatch",
          "[server][tar][purge][fragment]") {
    FragmentHarness h;
    h.perm_allow = false;
    auto res = h.post(kPurgePath, "device_id=dev-A&source=process");
    CHECK(res->status == 403);
    REQUIRE(h.perms.size() == 1);
    CHECK(h.perms[0].securable_type == "Infrastructure");
    CHECK(h.perms[0].op == "Delete");
    CHECK(h.calls.empty());
    CHECK(h.audits_for("tar.source.purge", "denied") == 1);
    CHECK(h.audit_detail("tar.source.purge", "denied") == "rbac_denied");
    CHECK(h.metric("yuzu_tar_source_purge_total", "denied") == 1.0);
}

TEST_CASE("fragment reenable: gates on Execution:Execute; denial audits + counts, no dispatch",
          "[server][tar][reenable][fragment]") {
    FragmentHarness h;
    h.perm_allow = false;
    auto res = h.post(kReenablePath, "device_id=dev-A&source=process");
    CHECK(res->status == 403);
    REQUIRE(h.perms.size() == 1);
    CHECK(h.perms[0].securable_type == "Execution");
    CHECK(h.perms[0].op == "Execute");
    CHECK(h.calls.empty());
    CHECK(h.audits_for("tar.source.reenable", "denied") == 1);
    CHECK(h.audit_detail("tar.source.reenable", "denied") == "rbac_denied");
    CHECK(h.metric("yuzu_tar_source_reenable_total", "denied") == 1.0);
}

// ── CSRF same-site gate ─────────────────────────────────────────────────────

TEST_CASE("fragment purge: cross-origin and header-less POSTs are refused before dispatch",
          "[server][tar][purge][fragment][csrf]") {
    SECTION("cross-origin Origin") {
        FragmentHarness h;
        auto res = h.post(kPurgePath, "device_id=dev-A&source=process",
                          {{"Host", kHost}, {"Origin", "https://evil.example"}});
        CHECK(res->status == 403);
        CHECK(contains(res->body, "Cross-origin request refused"));
        CHECK(h.calls.empty());
        CHECK(h.audit_detail("tar.source.purge", "denied") == "csrf_cross_origin");
        CHECK(h.metric("yuzu_tar_source_purge_total", "denied") == 1.0);
    }
    SECTION("cross-origin Referer (no Origin)") {
        FragmentHarness h;
        auto res = h.post(kPurgePath, "device_id=dev-A&source=process",
                          {{"Host", kHost}, {"Referer", "https://evil.example/tar"}});
        CHECK(res->status == 403);
        CHECK(h.calls.empty());
    }
    SECTION("neither Origin nor Referer — stricter than origin_is_same_site's default") {
        FragmentHarness h;
        auto res = h.post(kPurgePath, "device_id=dev-A&source=process", {{"Host", kHost}});
        CHECK(res->status == 403);
        CHECK(h.calls.empty());
        CHECK(h.audit_detail("tar.source.purge", "denied") == "csrf_cross_origin");
    }
    SECTION("same-site Referer is accepted") {
        FragmentHarness h;
        auto res = h.post(kPurgePath, "device_id=dev-A&source=process",
                          {{"Host", kHost}, {"Referer", std::string{"https://"} + kHost + "/tar"}});
        CHECK(res->status == 200);
        CHECK(h.calls.size() == 1);
    }
}

TEST_CASE("fragment reenable: cross-origin and header-less POSTs are refused before dispatch",
          "[server][tar][reenable][fragment][csrf]") {
    SECTION("cross-origin") {
        FragmentHarness h;
        auto res = h.post(kReenablePath, "device_id=dev-A&source=process",
                          {{"Host", kHost}, {"Origin", "https://evil.example"}});
        CHECK(res->status == 403);
        CHECK(h.calls.empty());
        CHECK(h.audit_detail("tar.source.reenable", "denied") == "csrf_cross_origin");
        CHECK(h.metric("yuzu_tar_source_reenable_total", "denied") == 1.0);
    }
    SECTION("header-less") {
        FragmentHarness h;
        auto res = h.post(kReenablePath, "device_id=dev-A&source=process", {{"Host", kHost}});
        CHECK(res->status == 403);
        CHECK(h.calls.empty());
    }
}

// ── Input validation ────────────────────────────────────────────────────────

TEST_CASE("fragment purge: missing fields and forged sources are rejected 400, no dispatch",
          "[server][tar][purge][fragment]") {
    FragmentHarness h;
    CHECK(h.post(kPurgePath, "source=process")->status == 400);          // no device_id
    CHECK(h.post(kPurgePath, "device_id=dev-A")->status == 400);         // no source
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=")->status == 400); // empty source
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=evil")->status == 400);
    // A real TAR source deliberately outside the four-source frame scope.
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=software")->status == 400);
    CHECK(h.calls.empty());
    CHECK(h.metric("yuzu_tar_source_purge_total", "invalid_input") == 5.0);
}

TEST_CASE("fragment reenable: missing fields and forged sources are rejected 400, no dispatch",
          "[server][tar][reenable][fragment]") {
    FragmentHarness h;
    CHECK(h.post(kReenablePath, "source=process")->status == 400);
    CHECK(h.post(kReenablePath, "device_id=dev-A")->status == 400);
    CHECK(h.post(kReenablePath, "device_id=dev-A&source=evil")->status == 400);
    CHECK(h.calls.empty());
    CHECK(h.metric("yuzu_tar_source_reenable_total", "invalid_input") == 3.0);
}

TEST_CASE("fragment purge: every allowlisted source dispatches", "[server][tar][purge][fragment]") {
    FragmentHarness h;
    for (const char* src : {"process", "tcp", "service", "user"})
        CHECK(h.post(kPurgePath, std::string{"device_id=dev-A&source="} + src)->status == 200);
    CHECK(h.calls.size() == 4);
    CHECK(h.metric("yuzu_tar_source_purge_total", "success") == 4.0);
}

// ── RBAC device scope ───────────────────────────────────────────────────────

TEST_CASE("fragment purge: out-of-scope device 404s (no existence oracle) and audits the reason",
          "[server][tar][purge][fragment]") {
    FragmentHarness h;
    auto res = h.post(kPurgePath, "device_id=dev-OTHER&source=process");
    CHECK(res->status == 404);
    // Same body as the offline case — the response must not distinguish
    // "not yours" from "not connected".
    CHECK(contains(res->body, "Agent not reachable"));
    CHECK(h.calls.empty());
    CHECK(h.audit_detail("tar.source.purge", "failure") == "scope_violation source=process");
    CHECK(h.metric("yuzu_tar_source_purge_total", "scope_violation") == 1.0);
}

TEST_CASE("fragment reenable: out-of-scope device 404s and audits the reason",
          "[server][tar][reenable][fragment]") {
    FragmentHarness h;
    auto res = h.post(kReenablePath, "device_id=dev-OTHER&source=tcp");
    CHECK(res->status == 404);
    CHECK(contains(res->body, "Agent not reachable"));
    CHECK(h.calls.empty());
    CHECK(h.audit_detail("tar.source.reenable", "failure") == "scope_violation source=tcp");
    CHECK(h.metric("yuzu_tar_source_reenable_total", "scope_violation") == 1.0);
}

// ── Offline / unavailable ───────────────────────────────────────────────────

TEST_CASE("fragment purge: offline agent (0 reached) → 404 + agent_not_connected",
          "[server][tar][purge][fragment]") {
    FragmentHarness h;
    h.dispatch_sent = 0;
    auto res = h.post(kPurgePath, "device_id=dev-A&source=process");
    CHECK(res->status == 404);
    CHECK(contains(res->body, "Agent not reachable"));
    REQUIRE(h.calls.size() == 1); // dispatch was attempted, reached nobody
    CHECK(h.audit_detail("tar.source.purge", "failure") == "agent_not_connected source=process");
    CHECK(h.metric("yuzu_tar_source_purge_total", "agent_not_connected") == 1.0);
}

TEST_CASE("fragment reenable: offline agent (0 reached) → 404 + agent_not_connected",
          "[server][tar][reenable][fragment]") {
    FragmentHarness h;
    h.dispatch_sent = 0;
    auto res = h.post(kReenablePath, "device_id=dev-A&source=user");
    CHECK(res->status == 404);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.audit_detail("tar.source.reenable", "failure") == "agent_not_connected source=user");
    CHECK(h.metric("yuzu_tar_source_reenable_total", "agent_not_connected") == 1.0);
}

TEST_CASE("fragment purge/reenable: no dispatch wiring → 503, nothing attempted",
          "[server][tar][purge][fragment]") {
    FragmentHarness h{/*with_dispatch=*/false};
    CHECK(h.post(kPurgePath, "device_id=dev-A&source=process")->status == 503);
    CHECK(h.post(kReenablePath, "device_id=dev-A&source=process")->status == 503);
    CHECK(h.calls.empty());
}

// ── Success shape ───────────────────────────────────────────────────────────

TEST_CASE("fragment purge: success dispatches tar/purge_source to the one device",
          "[server][tar][purge][fragment]") {
    FragmentHarness h;
    auto res = h.post(kPurgePath, "device_id=dev-B&source=tcp");
    CHECK(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].plugin == "tar");
    CHECK(h.calls[0].action == "purge_source");
    CHECK(h.calls[0].scope_expr.empty()); // targeted, never a scope fan-out
    REQUIRE(h.calls[0].agent_ids.size() == 1);
    CHECK(h.calls[0].agent_ids[0] == "dev-B");
    REQUIRE(h.calls[0].params.count("source") == 1);
    CHECK(h.calls[0].params.at("source") == "tcp");
    CHECK(h.audit_detail("tar.source.purge", "success") == "device=dev-B source=tcp");
    CHECK(h.metric("yuzu_tar_source_purge_total", "success") == 1.0);
    // Purge leaves the source PAUSED, so the row stays and is annotated.
    CHECK(contains(res->body, "Purge dispatched"));
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
}

TEST_CASE("fragment reenable: success dispatches tar/configure with <source>_enabled=true",
          "[server][tar][reenable][fragment]") {
    FragmentHarness h;
    auto res = h.post(kReenablePath, "device_id=dev-A&source=service");
    CHECK(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].plugin == "tar");
    CHECK(h.calls[0].action == "configure");
    CHECK(h.calls[0].scope_expr.empty());
    REQUIRE(h.calls[0].agent_ids.size() == 1);
    CHECK(h.calls[0].agent_ids[0] == "dev-A");
    // Per-source independence (#539): ONLY the named source's key is set.
    REQUIRE(h.calls[0].params.size() == 1);
    REQUIRE(h.calls[0].params.count("service_enabled") == 1);
    CHECK(h.calls[0].params.at("service_enabled") == "true");
    CHECK(h.audit_detail("tar.source.reenable", "success") == "device=dev-A source=service");
    CHECK(h.metric("yuzu_tar_source_reenable_total", "success") == 1.0);
    CHECK(res->get_header_value("Cache-Control") == "no-store, private");
}

TEST_CASE("fragment purge: query-string params are honoured like form-body params",
          "[server][tar][purge][fragment]") {
    // htmx posts a urlencoded body, but the handler also accepts req.params —
    // both paths must land on the same dispatch.
    FragmentHarness h;
    auto res = h.post(std::string{kPurgePath} + "?device_id=dev-A&source=process", "");
    CHECK(res->status == 200);
    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].agent_ids[0] == "dev-A");
    CHECK(h.calls[0].params.at("source") == "process");
}
