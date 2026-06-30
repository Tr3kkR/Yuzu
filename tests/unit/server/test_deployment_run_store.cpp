// DeploymentRunStore tests: the execute-once CAS (claim_for_exec is idempotent),
// the guarded transitions, owner-scope boundary, the settled-gated complete, and
// FK cascade. Born-on-Postgres, schema `deployment_run_store`. PG-gated: skips when
// YUZU_TEST_POSTGRES_DSN is unset, fails when it is set but broken.

#include <catch2/catch_test_macros.hpp>

#include "deployment_run_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <chrono>
#include <string>

using yuzu::server::DeploymentDeviceRow;
using yuzu::server::DeploymentRow;
using yuzu::server::DeploymentRunStore;
using yuzu::server::DeviceTransition;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::preflight::PreflightTarget;

namespace {

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

DeploymentRow make_dep(const std::string& id, const std::string& owner, std::int64_t created) {
    DeploymentRow d;
    d.deployment_id = id;
    d.source_run_id = "run-" + id;
    d.created_by = owner;
    d.name = "test " + id;
    d.artifact_url = "https://repo.lan/pkg.msi";
    d.artifact_filename = "pkg.msi";
    d.artifact_sha256 = std::string(64, 'a');
    d.exec_args = "/qn";
    d.status = "running";
    d.created_at_ms = created;
    return d;
}

PreflightTarget tgt(const std::string& aid) { return {aid, "host-" + aid, "windows"}; }

std::string step_of(DeploymentRunStore& s, const std::string& id, const std::string& agent) {
    for (const auto& d : s.get_devices(id))
        if (d.agent_id == agent)
            return d.step;
    return "<absent>";
}

} // namespace

TEST_CASE("DeploymentRunStore execute-once CAS + guarded transitions",
          "[pg][deployment][store]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeploymentRunStore store{pool};
    REQUIRE(store.is_open());

    const auto t = now_ms();
    REQUIRE(store.create_deployment(make_dep("d1", "alice", t),
                                    {tgt("a1"), tgt("a2"), tgt("a3")}));
    REQUIRE(store.get_devices("d1").size() == 3);

    SECTION("claim_for_stage moves pending→staging exactly once") {
        auto first = store.claim_for_stage("d1", {"a1", "a2", "a3"});
        CHECK(first.size() == 3);
        // already staging → a second claim returns nothing (guarded on step='pending')
        auto again = store.claim_for_stage("d1", {"a1", "a2", "a3"});
        CHECK(again.empty());
        CHECK(step_of(store, "d1", "a1") == "staging");
    }

    SECTION("execute-once: claim_for_exec only claims a 'staged' row, once") {
        // can't claim for exec while pending
        CHECK(store.claim_for_exec("d1", {"a1"}).empty());
        // advance a1 to staged via a guarded stage result
        store.claim_for_stage("d1", {"a1"});
        REQUIRE(store.apply_results("d1", {{"a1", "staging", "staged", 0, ""}}));
        CHECK(step_of(store, "d1", "a1") == "staged");
        // FIRST exec claim wins
        auto c1 = store.claim_for_exec("d1", {"a1"});
        CHECK(c1.size() == 1);
        CHECK(step_of(store, "d1", "a1") == "executing");
        // SECOND claim (concurrent advance / restart) finds it 'executing' → empty.
        // This is the installer-runs-at-most-once guarantee.
        auto c2 = store.claim_for_exec("d1", {"a1"});
        CHECK(c2.empty());
    }

    SECTION("a > int4 exit_code round-trips (BIGINT column, not int4)") {
        // An out-of-int4 exit code must not abort the batched apply_results UPDATE
        // (which would wedge the whole deployment); the column is BIGINT and
        // parse_i64 saturates to INT64_MAX (#governance HIGH).
        store.claim_for_stage("d1", {"a1"});
        store.apply_results("d1", {{"a1", "staging", "staged", 0, ""}});
        store.claim_for_exec("d1", {"a1"});
        REQUIRE(store.apply_results("d1", {{"a1", "executing", "failed", 3000000000LL, "huge"}}));
        std::int64_t got = -1;
        for (const auto& d : store.get_devices("d1"))
            if (d.agent_id == "a1")
                got = d.exit_code;
        CHECK(got == 3000000000LL);
    }

    SECTION("apply_results is source-step guarded (stale transition is a no-op)") {
        store.claim_for_stage("d1", {"a1"});                            // a1 → staging
        // a transition that names the WRONG from_step does nothing
        REQUIRE(store.apply_results("d1", {{"a1", "executing", "succeeded", 0, ""}}));
        CHECK(step_of(store, "d1", "a1") == "staging"); // unchanged
        // the right from_step applies
        REQUIRE(store.apply_results("d1", {{"a1", "staging", "staged", 0, ""}}));
        CHECK(step_of(store, "d1", "a1") == "staged");
    }

    SECTION("mark_skipped only moves not-yet-executed (pending/staged) rows") {
        store.claim_for_stage("d1", {"a1"}); // a1 staging (in-flight)
        // a2 pending, a3 pending; skip a2 + a1 → only a2 (pending) moves, a1 (staging) stays
        int n = store.mark_skipped("d1", {"a1", "a2"});
        CHECK(n == 1);
        CHECK(step_of(store, "d1", "a2") == "skipped");
        CHECK(step_of(store, "d1", "a1") == "staging");
    }

    SECTION("complete is settled-gated; refresh_counts is exact") {
        // drive a1 succeeded, a2 failed, a3 skipped → all terminal
        store.claim_for_stage("d1", {"a1", "a2"});
        store.apply_results("d1", {{"a1", "staging", "staged", 0, ""},
                                   {"a2", "staging", "failed", 0, "boom"}});
        store.claim_for_exec("d1", {"a1"});
        store.apply_results("d1", {{"a1", "executing", "succeeded", 0, ""}});
        // a3 still pending → NOT settled → complete is a no-op
        CHECK_FALSE(store.complete_deployment("d1", t));
        store.mark_skipped("d1", {"a3"});
        REQUIRE(store.refresh_counts("d1"));
        auto row = store.get_deployment("d1");
        REQUIRE(row);
        CHECK(row->succeeded == 1);
        CHECK(row->failed == 1);
        CHECK(row->skipped == 1);
        CHECK(row->active == 0);
        // now settled → completes once, then no-op
        CHECK(store.complete_deployment("d1", t));
        CHECK_FALSE(store.complete_deployment("d1", t));
        CHECK(store.get_deployment("d1")->status == "complete");
    }
}

TEST_CASE("DeploymentRunStore owner-scope + cascade", "[pg][deployment][store]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeploymentRunStore store{pool};
    REQUIRE(store.is_open());

    const auto t = now_ms();
    REQUIRE(store.create_deployment(make_dep("oA", "alice", t), {tgt("a1"), tgt("a2")}));
    REQUIRE(store.create_deployment(make_dep("oB", "bob", t), {tgt("b1")}));

    SECTION("get/list are owner-scoped; admin sees all") {
        CHECK(store.get_deployment("oA", "alice").has_value());
        CHECK_FALSE(store.get_deployment("oA", "bob").has_value()); // not-yours == not-found
        CHECK(store.get_deployment("oA").has_value());              // unscoped (engine)
        CHECK(store.list_deployments("alice", false, 50).size() == 1);
        CHECK(store.list_deployments("anyone", /*is_admin=*/true, 50).size() >= 2);
    }

    SECTION("delete is owner-scoped at the seam; device rows cascade") {
        CHECK_FALSE(store.delete_deployment("oA", "bob")); // wrong owner = no-op
        CHECK(store.get_devices("oA").size() == 2);
        CHECK(store.delete_deployment("oA", "alice"));
        CHECK_FALSE(store.get_deployment("oA").has_value());
        CHECK(store.get_devices("oA").empty()); // FK ON DELETE CASCADE
    }
}

TEST_CASE("DeploymentRunStore allows one running deployment per source run",
          "[pg][deployment][store]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeploymentRunStore store{pool};
    REQUIRE(store.is_open());

    const auto t = now_ms();
    auto d1 = make_dep("g1", "alice", t);
    d1.source_run_id = "runX";
    auto d2 = make_dep("g2", "alice", t);
    d2.source_run_id = "runX"; // same source run
    REQUIRE(store.create_deployment(d1, {tgt("a1")}));

    // find_running_for_run finds it, owner-scoped (the resume-guard seam).
    auto running = store.find_running_for_run("runX", "alice");
    REQUIRE(running);
    CHECK(*running == "g1");
    CHECK_FALSE(store.find_running_for_run("runX", "bob").has_value()); // not yours
    CHECK_FALSE(store.find_running_for_run("nope", "alice").has_value());

    // A SECOND running deployment for the same run is rejected by the partial unique
    // index (the race-safe backstop to the create-time resume guard).
    CHECK_FALSE(store.create_deployment(d2, {tgt("a2")}));

    // Once the first completes, a fresh deployment for the same run is allowed.
    store.mark_skipped("g1", {"a1"});
    REQUIRE(store.complete_deployment("g1", t));
    CHECK_FALSE(store.find_running_for_run("runX", "alice").has_value());
    auto d3 = make_dep("g3", "alice", t);
    d3.source_run_id = "runX";
    CHECK(store.create_deployment(d3, {tgt("a3")}));
}

// ADR-0012 §1: construction must be fail-CLOSED — a reachable DB whose schema can't
// migrate leaves the store !is_open() (server.cpp → startup_failed_).
TEST_CASE("DeploymentRunStore reports !is_open on a migration failure",
          "[pg][deployment][store]") {
    YUZU_REQUIRE_PG_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA deployment_run_store")};
        REQUIRE(s.ok());
        PgResult tb{PQexec(conn.get(), "CREATE TABLE deployment_run_store.deployments (bogus int)")};
        REQUIRE(tb.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    DeploymentRunStore store{pool};
    CHECK_FALSE(store.is_open());
}
