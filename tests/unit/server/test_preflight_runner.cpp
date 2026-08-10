/**
 * test_preflight_runner.cpp — #2691 finding 10: a degraded ResponseStore read
 * during PreflightRunner::tick() must not overwrite an already-persisted grid
 * with a false "every device incomplete" verdict, and must not re-dispatch to
 * devices that already answered on a prior tick. Both would corrupt the
 * persisted go-cohort that deployment_routes.cpp later reads to build /auto
 * Deploy's target set — a transient Postgres blip must degrade to "retry next
 * tick", never to "silently downgrade a real Pass to Incomplete."
 */

#include "preflight_eval.hpp"
#include "preflight_parse.hpp"
#include "preflight_run_store.hpp"
#include "preflight_runner.hpp"
#include "pg/pg_pool.hpp"
#include "response_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// Shares the "preflight" / "responsestore" template keys with
// test_preflight_run_store.cpp / test_response_store.cpp (identical setup).
yuzu::test::PgTestTemplate preflight_tpl{"preflight", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    PreflightRunStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("preflight template: store failed to migrate");
}};

yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
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
    r.config_json = R"({"app_name":"","min_gib":20})"; // no app check applicable
    r.window_seconds = 300;
    r.created_at_ms = created;
    r.deadline_at_ms = created + 300000; // far future — not past_deadline
    r.status = "running";
    return r;
}

} // namespace

TEST_CASE("PreflightRunner tick: a degraded response-store read does not overwrite "
          "an already-good stored grid or re-dispatch",
          "[pg][preflight][runner]") {
    YUZU_REQUIRE_PG_DB_TPL(run_db, preflight_tpl);
    PgPool run_pool{{.conninfo = run_db.dsn(), .size = 4}};
    PreflightRunStore run_store{run_pool};
    REQUIRE(run_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-degrade-1";
    REQUIRE(run_store.create_run(make_run(run_id, t), {{"agent-1", "host-1", "windows"}}));

    // Simulate a prior GOOD tick: agent-1 already resolved go-clean.
    PreflightRunDeviceRow good;
    good.agent_id = "agent-1";
    good.hostname = "host-1";
    good.os = "windows";
    good.bucket = "go";
    good.checks_json = "[]";
    good.updated_at_ms = t;
    REQUIRE(run_store.persist_grid(run_id, {good}, 1, /*go=*/1, /*warn=*/0, /*nogo=*/0, /*inc=*/0));

    // A genuinely degraded ResponseStore: unreachable host, every read fails.
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore bad_rs{bad_pool};
    REQUIRE_FALSE(bad_rs.is_open());

    int dispatch_calls = 0;
    PreflightRunner runner(PreflightRunner::Deps{
        .run_store = &run_store,
        .response_store = &bad_rs,
        .dispatch_fn =
            [&](const std::string&, const std::string&, const std::vector<std::string>&,
                const std::string&, const std::unordered_map<std::string, std::string>&,
                const std::string&) -> std::pair<std::string, int> {
            ++dispatch_calls;
            return {"cmd-x", 1};
        },
        .now_ms_fn = [t] { return t + 1000; },
        .retention_days = 14,
    });

    runner.tick();

    CHECK(dispatch_calls == 0); // no re-dispatch to an already-answered device

    auto devices = run_store.get_devices(run_id);
    REQUIRE(devices.size() == 1);
    CHECK(devices[0].bucket == "go"); // NOT overwritten to "inc"

    auto run = run_store.get_run(run_id, "alice");
    REQUIRE(run.has_value());
    CHECK(run->status == "running"); // not falsely completed on a degraded read
}

TEST_CASE("PreflightRunner tick: a genuinely pending (not degraded) check still "
          "persists and re-dispatches normally",
          "[pg][preflight][runner]") {
    YUZU_REQUIRE_PG_DB_TPL(run_db, preflight_tpl);
    PgPool run_pool{{.conninfo = run_db.dsn(), .size = 4}};
    PreflightRunStore run_store{run_pool};
    REQUIRE(run_store.is_open());

    YUZU_REQUIRE_PG_DB_TPL(resp_db, responsestore_tpl);
    PgPool resp_pool{{.conninfo = resp_db.dsn(), .size = 4}};
    ResponseStore resp_store{resp_pool};
    REQUIRE(resp_store.is_open());

    const auto t = now_ms();
    const std::string run_id = "run-pending-1";
    REQUIRE(run_store.create_run(make_run(run_id, t), {{"agent-1", "host-1", "windows"}}));

    int dispatch_calls = 0;
    PreflightRunner runner(PreflightRunner::Deps{
        .run_store = &run_store,
        .response_store = &resp_store, // real, open, just no responses stored yet
        .dispatch_fn =
            [&](const std::string&, const std::string&, const std::vector<std::string>&,
                const std::string&, const std::unordered_map<std::string, std::string>&,
                const std::string&) -> std::pair<std::string, int> {
            ++dispatch_calls;
            return {"cmd-x", 1};
        },
        .now_ms_fn = [t] { return t + 1000; },
        .retention_days = 14,
    });

    runner.tick();

    // The fix must not suppress the ordinary re-dispatch-to-pending-devices path.
    CHECK(dispatch_calls > 0);

    auto devices = run_store.get_devices(run_id);
    REQUIRE(devices.size() == 1);
    CHECK(devices[0].bucket == "inc"); // genuinely incomplete, correctly persisted
}
