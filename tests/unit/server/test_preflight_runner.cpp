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

// #3495 governance (chaos-injector HIGH + codex external tie-break,
// 2026-08-24): tick()'s per-run loop had NO interior cancellation check —
// once started, a single tick() call could work through every `running` run
// with no way to interrupt it, compounding with ServerImpl::stop()'s
// preflight_runner_thread_.join() ahead of it. Deps::should_stop closes
// this, ported from QuarantineContainmentReconciler::Deps: checked once per
// run, before that run's dispatch begins, so a run already in progress
// still finishes cleanly — this only stops the NEXT run from starting.
TEST_CASE("PreflightRunner tick: stops starting further runs once should_stop() "
          "reports true, deferring the rest to the next tick",
          "[pg][preflight][runner]") {
    YUZU_REQUIRE_PG_DB_TPL(run_db, preflight_tpl);
    PgPool run_pool{{.conninfo = run_db.dsn(), .size = 4}};
    PreflightRunStore run_store{run_pool};
    REQUIRE(run_store.is_open());

    // A real, open ResponseStore with zero rows — matching the "genuinely
    // pending" test above. response_store == nullptr would make `checks`
    // stay empty (see PreflightRunner::tick()), which makes
    // compute_device_results iterate zero per-check entries and skip
    // `any_pending` entirely: every device reads "go" trivially and nothing
    // ever dispatches, which would falsely appear as should_stop working.
    YUZU_REQUIRE_PG_DB_TPL(resp_db, responsestore_tpl);
    PgPool resp_pool{{.conninfo = resp_db.dsn(), .size = 4}};
    ResponseStore resp_store{resp_pool};
    REQUIRE(resp_store.is_open());

    const auto t = now_ms();
    REQUIRE(run_store.create_run(make_run("run-a", t), {{"agent-1", "host-1", "windows"}}));
    REQUIRE(run_store.create_run(make_run("run-b", t), {{"agent-2", "host-2", "windows"}}));

    // kPreflightChecks has 5 entries and cfg's empty app_name makes exactly
    // 4 of them applicable (every key but "app" is unconditionally
    // applicable) — so a single run in progress fires several dispatch_fn
    // calls before the outer loop ever revisits should_stop. Track WHICH
    // agent each call targeted, rather than asserting a magic total count,
    // so this stays correct if that check count ever changes.
    std::vector<std::vector<std::string>> calls;
    PreflightRunner runner(PreflightRunner::Deps{
        .run_store = &run_store,
        .response_store = &resp_store,
        .dispatch_fn =
            [&](const std::string&, const std::string&, const std::vector<std::string>& agent_ids,
                const std::string&, const std::unordered_map<std::string, std::string>&,
                const std::string&) -> std::pair<std::string, int> {
            calls.push_back(agent_ids);
            return {"cmd-x", 1};
        },
        .now_ms_fn = [t] { return t + 1000; },
        .retention_days = 14,
        // Stop signals true once the first run has dispatched at least once.
        // should_stop is checked once per run, at the TOP of the loop — a run
        // already in progress finishes ALL of its own applicable checks
        // before should_stop is consulted again, so this proves should_stop
        // defers the SECOND run entirely, not that it cuts the first one off
        // mid-way (it does not, by design).
        .should_stop = [&calls] { return !calls.empty(); },
    });

    runner.tick();

    REQUIRE_FALSE(calls.empty());
    REQUIRE(calls[0].size() == 1);
    // list_running() order isn't asserted — whichever run went first, EVERY
    // dispatch this tick must target that SAME run's one agent; the other
    // run's agent must never appear (its checks never started).
    const std::string processed_agent = calls[0][0];
    const std::string deferred_run = (processed_agent == "agent-1") ? "run-b" : "run-a";
    const std::string processed_run = (processed_agent == "agent-1") ? "run-a" : "run-b";
    for (const auto& agent_ids : calls) {
        REQUIRE(agent_ids.size() == 1);
        CHECK(agent_ids[0] == processed_agent);
    }

    // Both runs' devices exist from create_run's frozen-cohort insert (bucket
    // seeded 'inc' regardless), so device PRESENCE doesn't distinguish
    // processed from deferred — updated_at_ms does. create_run stamps it with
    // real wall-clock `now_ms()` (≈ `t`, captured just above); this runner's
    // injected `.now_ms_fn` returns `t + 1000` and persist_and_maybe_complete
    // stamps whatever it processes with that value. So the deferred run's row
    // stays at its create_run timestamp (≈ t) while the processed run's jumps
    // to t + 1000 — a >=500ms gap comfortably separates the two given normal
    // test execution jitter.
    auto processed_devices = run_store.get_devices(processed_run);
    auto deferred_devices = run_store.get_devices(deferred_run);
    REQUIRE(processed_devices.size() == 1);
    REQUIRE(deferred_devices.size() == 1);
    CHECK(processed_devices[0].updated_at_ms >= t + 500); // touched THIS tick
    CHECK(deferred_devices[0].updated_at_ms < t + 500);   // untouched — still its create_run stamp
}
