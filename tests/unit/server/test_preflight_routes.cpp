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

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <stdexcept>
#include <string>

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
