/**
 * test_preflight_routes.cpp — #2691 finding 10: PreflightRoutes::render_run's
 * live path (called on every operator self-poll of a running run) must not
 * compute-and-persist a false "every device incomplete" grid over an already-
 * good stored one when the live read degrades — it must render the last
 * known-good stored grid with an honest degrade banner and skip persisting
 * entirely, retrying on the next poll.
 *
 * render_run and its inputs (run_store_, collect_fn_) are private; the
 * PreflightRoutesTestAccess friend seam (preflight_routes.hpp) wires them
 * without standing up an HTTP server, same shape as
 * test_dashboard_results_columns.cpp's DashboardResultsColumnsTestAccess.
 */

#include "preflight_routes.hpp"
#include "preflight_run_store.hpp"
#include "pg/pg_pool.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace yuzu::server {

struct PreflightRoutesTestAccess {
    PreflightRoutes routes;

    void set_stores(PreflightRunStore* rs) { routes.run_store_ = rs; }
    void set_collect(PreflightRoutes::CollectFn fn) { routes.collect_fn_ = std::move(fn); }
    std::string render(const PreflightRunRow& run, int attempt = 1) {
        return routes.render_run(run, attempt);
    }
};

} // namespace yuzu::server

namespace {

yuzu::test::PgTestTemplate preflight_tpl{"preflight", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    PreflightRunStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("preflight template: store failed to migrate");
}};

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

PreflightRunRow make_run(const std::string& id, std::int64_t created) {
    PreflightRunRow r;
    r.run_id = id;
    r.execution_id = "preflight-" + id;
    r.created_by = "alice";
    r.name = "test " + id;
    r.scope_label = "all visible devices";
    r.config_json = R"({"app_name":"","min_gib":20})";
    r.window_seconds = 300;
    r.created_at_ms = created;
    r.deadline_at_ms = created + 300000; // far future — not past_deadline
    r.status = "running";
    return r;
}

bool contains(const std::string& hay, std::string_view needle) {
    return hay.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("render_run: a degraded live read renders the last known-good stored "
          "grid with a degrade banner, and does not persist over it",
          "[pg][preflight][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-live-degrade-1";
    auto run = make_run(run_id, t);
    REQUIRE(run_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    // Prior GOOD state: agent-1 already resolved go-clean.
    PreflightRunDeviceRow good;
    good.agent_id = "agent-1";
    good.hostname = "host-1";
    good.os = "windows";
    good.bucket = "go";
    good.checks_json = "[]";
    good.updated_at_ms = t;
    REQUIRE(run_store.persist_grid(run_id, {good}, 1, /*go=*/1, /*warn=*/0, /*nogo=*/0, /*inc=*/0));

    PreflightRoutesTestAccess acc;
    acc.set_stores(&run_store);
    // collect_fn_ standing in for a degraded ResponseStore read: every
    // applicable check comes back with degraded=true, empty by_agent.
    acc.set_collect(
        [](const std::string&,
          const std::vector<std::pair<std::string, std::string>>& applicable) {
            std::vector<preflight::PreflightCheckResponses> out;
            for (const auto& [key, label] : applicable) {
                preflight::PreflightCheckResponses cr;
                cr.key = key;
                cr.label = label;
                cr.degraded = true;
                out.push_back(std::move(cr));
            }
            return out;
        });

    const std::string html = acc.render(run);

    CHECK(contains(html, "result-degrade-banner"));
    CHECK(contains(html, "temporarily unavailable"));

    // The stored grid must be UNCHANGED — the degraded poll must not persist.
    auto devices = run_store.get_devices(run_id);
    REQUIRE(devices.size() == 1);
    CHECK(devices[0].bucket == "go");

    auto stored_run = run_store.get_run(run_id, "alice");
    REQUIRE(stored_run.has_value());
    CHECK(stored_run->status == "running"); // not falsely completed
}

TEST_CASE("render_run: a genuinely pending (not degraded) live read still "
          "computes and persists normally",
          "[pg][preflight][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-live-pending-1";
    auto run = make_run(run_id, t);
    REQUIRE(run_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    PreflightRoutesTestAccess acc;
    acc.set_stores(&run_store);
    // Not degraded — genuinely no responses yet.
    acc.set_collect(
        [](const std::string&,
          const std::vector<std::pair<std::string, std::string>>& applicable) {
            std::vector<preflight::PreflightCheckResponses> out;
            for (const auto& [key, label] : applicable) {
                preflight::PreflightCheckResponses cr;
                cr.key = key;
                cr.label = label;
                cr.degraded = false;
                out.push_back(std::move(cr));
            }
            return out;
        });

    const std::string html = acc.render(run);

    CHECK_FALSE(contains(html, "result-degrade-banner"));

    // The fix must not suppress the ordinary compute-and-persist path.
    auto devices = run_store.get_devices(run_id);
    REQUIRE(devices.size() == 1);
    CHECK(devices[0].bucket == "inc"); // genuinely incomplete, correctly persisted
}

// SEC-2/SEC-3 confinement-gap class (found during Gate 2 governance review):
// resolve_targets() feeds devices_fn_(username) — the same username-keyed
// provider fixed elsewhere in this branch — into a DISPATCH (not just a
// read), via the shared command_dispatch_fn. Denied here, unlike the pure
// reads elsewhere in this branch, because /fragments/auto/run mutates
// (creates a run + dispatches commands) even though every dispatched check
// is itself read-only.
TEST_CASE("preflight routes: /fragments/auto/run denies a service-scoped "
          "token, denial audited, nothing dispatched",
          "[pg][preflight][routes][security]") {
    // A real, open store (rather than nullptr) so devices_fn_calls/dispatched
    // below actually discriminate the fix: with a null run_store the handler's
    // OWN unrelated "store unavailable" early-return would make both counters
    // read 0 regardless of whether the deny fired (gov QE review — a nullptr
    // store made the deny test's own dispatch-count assertions vacuous).
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    auto serviceScopedAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.token_scope_service = "printers";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    int devices_fn_calls = 0;
    auto devices = [&](const std::string&) {
        ++devices_fn_calls;
        DeviceRow d;
        d.agent_id = "WS-1";
        d.hostname = "WS-1-host";
        return std::vector<DeviceRow>{d};
    };
    int dispatched = 0;
    auto dispatch = [&dispatched](const std::string&, const std::string&,
                                  const std::vector<std::string>&, const std::string&,
                                  const std::unordered_map<std::string, std::string>&,
                                  const std::string&) -> std::pair<std::string, int> {
        ++dispatched;
        return {"cmd-1", 1};
    };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };

    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, serviceScopedAuth, okPerm, devices,
                           /*groups_fn=*/{}, /*group_members_fn=*/{}, dispatch,
                           /*collect_fn=*/{}, audit, &run_store);

    auto res = sink.Post("/fragments/auto/run", "", "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status == 403);
    // The deny fires before resolve_targets() is ever called — no fleet
    // enumeration and no dispatch reach a service-scoped token at all.
    CHECK(devices_fn_calls == 0);
    CHECK(dispatched == 0);
    REQUIRE(audit_log.size() == 1);
    CHECK(audit_log[0] == "preflight.run|denied");
}

TEST_CASE("preflight routes: /fragments/auto/run reaches resolve_targets + "
          "dispatch for an ordinary session",
          "[pg][preflight][routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    int devices_fn_calls = 0;
    auto devices = [&](const std::string&) {
        ++devices_fn_calls;
        DeviceRow d;
        d.agent_id = "WS-1";
        d.hostname = "WS-1-host";
        d.os = "windows";
        return std::vector<DeviceRow>{d};
    };
    int dispatched = 0;
    auto dispatch = [&dispatched](const std::string&, const std::string&,
                                  const std::vector<std::string>&, const std::string&,
                                  const std::unordered_map<std::string, std::string>&,
                                  const std::string&) -> std::pair<std::string, int> {
        ++dispatched;
        return {"cmd-1", 1};
    };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };

    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, okAuth, okPerm, devices, /*groups_fn=*/{},
                           /*group_members_fn=*/{}, dispatch, /*collect_fn=*/{}, audit, &run_store);

    auto res = sink.Post("/fragments/auto/run", "", "application/x-www-form-urlencoded");
    REQUIRE(res);
    CHECK(res->status != 403); // not denied — reaches resolve_targets, creates the run, dispatches
    CHECK(devices_fn_calls == 1);
    CHECK(dispatched >= 1); // at least one applicable check dispatched
    bool saw_success = false;
    for (const auto& a : audit_log)
        if (a == "preflight.run|success")
            saw_success = true;
    CHECK(saw_success);
}

// SEC-2/SEC-3 confinement-gap class (Gate 4 unhappy-path review, UP-1):
// /fragments/auto (rail), /fragments/auto/result, and /fragments/auto/delete
// all scope by session->username alone — but ApiToken::principal_id ("the
// username... who created it") means a service-scoped token shares its
// creating principal's username. A token scoped to e.g. "printers" whose
// principal ALSO happens to be the interactive creator of a fleet-wide
// pre-flight run could otherwise read/enumerate/delete that run — full
// fleet-wide device data, not just its own service's.
TEST_CASE("preflight routes: rail/result/delete deny a service-scoped token "
          "sharing the run creator's username, run survives and is not "
          "leaked",
          "[pg][preflight][routes][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, preflight_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    PreflightRunStore run_store{pool};
    REQUIRE(run_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-confinement-1";
    auto run = make_run(run_id, t); // created_by = "alice"
    REQUIRE(run_store.create_run(run, {{"agent-1", "host-1", "windows"}}));

    // The SAME principal ("alice") now authenticates with a service-scoped
    // token — mirrors ApiToken::principal_id sharing the creator's username.
    auto serviceScopedAuth = [](const httplib::Request&, httplib::Response&) {
        auth::Session s;
        s.username = "alice";
        s.token_scope_service = "printers";
        return std::optional<auth::Session>(s);
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    std::vector<std::string> audit_log;
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string& r,
                     const std::string&, const std::string&, const std::string&) -> bool {
        audit_log.push_back(a + "|" + r);
        return true;
    };

    PreflightRoutes routes;
    yuzu::server::test::TestRouteSink sink;
    routes.register_routes(sink, serviceScopedAuth, okPerm, /*devices_fn=*/{}, /*groups_fn=*/{},
                           /*group_members_fn=*/{}, /*dispatch_fn=*/{}, /*collect_fn=*/{}, audit,
                           &run_store);

    auto rail = sink.Get("/fragments/auto");
    REQUIRE(rail);
    CHECK(rail->status == 403);
    CHECK(rail->body.find(run_id) == std::string::npos);
    CHECK(rail->body.find(run.name) == std::string::npos);

    auto result = sink.Get("/fragments/auto/result?run=" + run_id);
    REQUIRE(result);
    CHECK(result->status == 403);
    CHECK(result->body.find(run.scope_label) == std::string::npos);
    CHECK(result->body.find("host-1") == std::string::npos); // no device identity leaked

    auto del = sink.Post("/fragments/auto/delete?run=" + run_id, "",
                         "application/x-www-form-urlencoded");
    REQUIRE(del);
    CHECK(del->status == 403);
    // The run survives — the deny fires before delete_run is ever called.
    REQUIRE(run_store.get_run(run_id, "alice").has_value());
    // Gate 8 (GC-7): delete is gated on Execution:Execute in production, not
    // Infrastructure:Read (deny_service_scoped_'s default) — the A4
    // .permission hint must name the grant actually missing, not a sibling's.
    auto del_body = nlohmann::json::parse(del->body, nullptr, false);
    REQUIRE_FALSE(del_body.is_discarded());
    CHECK(del_body["error"]["permission"] == "Execution:Execute");

    REQUIRE(audit_log.size() == 3);
    CHECK(audit_log[0] == "preflight.run|denied");         // rail
    CHECK(audit_log[1] == "preflight.run|denied");         // result poll
    CHECK(audit_log[2] == "preflight.run.delete|denied");  // delete — own verb
}
