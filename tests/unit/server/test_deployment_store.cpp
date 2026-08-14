/**
 * test_deployment_store.cpp — `DeploymentStore` (operator-initiated ad-hoc
 * deployment jobs: SSH / group-policy / manual agent installs, Issue 7.7).
 *
 * NOT a test for `DeploymentRunStore` (the `/auto` Deploy feature's
 * stage->execute state machine) — same English word, unrelated store; see
 * deployment_store.hpp's file header for the naming trap.
 *
 * Covers:
 *  - fail-closed construction, both the migration-drift case (a live but
 *    unmigratable database) and the unreachable-pool case (mirrors
 *    test_access_review_store.cpp's two fail-closed cases).
 *  - create_job validation (target_host DNS-char/length, os, method).
 *  - list_jobs / get_job: typed reads — a genuine DB error is
 *    distinguishable from "no jobs"/"not found" (ADR-0036 program policy).
 *  - update_status: per-status timestamp stamping (started_at on 'running',
 *    completed_at on 'completed'/'failed'), invalid-status rejection,
 *    not-found rejection.
 *  - cancel_job: only pending/running jobs are cancellable; the guarded
 *    single-UPDATE shape distinguishes not-found from wrong-state.
 *  - migrate_from_sqlite backfill contract: idempotent marker, safe no-op on
 *    a missing legacy file, copies a populated legacy file exactly once,
 *    aborts unstamped on a mid-scan legacy read failure.
 *
 * Born-on-... migrated-to-Postgres store (ADR-0012 §1, authoritative/
 * fail-hard). PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails
 * when set but broken (test_helpers.hpp skip-vs-fail contract).
 * Store-behaviour cases use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the two fail-closed cases use
 * YUZU_REQUIRE_PG_DB / no gate at all, per the plain-migration-test
 * carve-out documented on that macro.
 */

#include "deployment_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::DeploymentJob;
using yuzu::server::DeploymentStore;
using yuzu::server::SqliteDb;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// RAII log capture (mirrors test_licensing_sync.cpp's "k_agent never leaks
// into the blob or the logs" pattern) — swaps in an ostream-backed logger for
// its lifetime and restores the previous default logger/level on scope exit,
// including on an exception. Used to ASSERT which specific failure branch a
// production code path took, not just that it failed — governance
// quality-engineer finding: the mid-scan corruption test previously only
// checked `CHECK_FALSE(migrate_from_sqlite(...))`, which would still pass if
// a future change silently regressed the corruption technique back to
// prepare-time failure instead of the intended step-time one.
class LogCapture {
public:
    LogCapture() {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(oss_);
        auto logger = std::make_shared<spdlog::logger>("test_deployment_store_capture", sink);
        logger->set_level(spdlog::level::trace);
        prev_logger_ = spdlog::default_logger();
        prev_level_ = spdlog::get_level();
        spdlog::set_default_logger(logger);
        spdlog::set_level(spdlog::level::trace);
    }
    ~LogCapture() {
        spdlog::set_default_logger(prev_logger_);
        spdlog::set_level(prev_level_);
    }
    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;

    [[nodiscard]] std::string str() const { return oss_.str(); }

private:
    std::ostringstream oss_;
    std::shared_ptr<spdlog::logger> prev_logger_;
    spdlog::level::level_enum prev_level_{spdlog::level::info};
};

yuzu::test::PgTestTemplate deployment_store_tpl{
    "deploystore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        DeploymentStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("deployment_store template: store failed to migrate");
    }};

void write_legacy_sqlite_db(const std::filesystem::path& path,
                            const std::vector<DeploymentJob>& jobs) {
    // SqliteDb (gov cpp-safety BLOCKING, policy floor): a raw sqlite3* with a
    // trailing sqlite3_close(db) leaks on any REQUIRE() failure between open
    // and close — including sqlite3_open itself, which may allocate the
    // handle even on failure (SqliteDb::addr()'s own doc comment). RAII
    // covers every such early-unwind path.
    SqliteDb db;
    REQUIRE(sqlite3_open(path.string().c_str(), db.addr()) == SQLITE_OK);
    const char* ddl = "CREATE TABLE deployment_jobs ("
                      "  id TEXT PRIMARY KEY, target_host TEXT NOT NULL,"
                      "  os TEXT NOT NULL DEFAULT 'linux', method TEXT NOT NULL DEFAULT 'manual',"
                      "  status TEXT NOT NULL DEFAULT 'pending',"
                      "  created_at INTEGER NOT NULL DEFAULT 0,"
                      "  started_at INTEGER NOT NULL DEFAULT 0,"
                      "  completed_at INTEGER NOT NULL DEFAULT 0,"
                      "  error TEXT NOT NULL DEFAULT '');";
    REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, nullptr) == SQLITE_OK);
    for (const auto& j : jobs) {
        std::string sql = "INSERT INTO deployment_jobs (id, target_host, os, method, status, "
                          "created_at, started_at, completed_at, error) VALUES ('" +
                          j.id + "', '" + j.target_host + "', '" + j.os + "', '" + j.method +
                          "', '" + j.status + "', " + std::to_string(j.created_at) + ", " +
                          std::to_string(j.started_at) + ", " + std::to_string(j.completed_at) +
                          ", '" + j.error + "');";
        REQUIRE(sqlite3_exec(db.get(), sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
    }
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("DeploymentStore reports !is_open on a migration failure", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA deployment_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE deployment_store.deployment_jobs (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    DeploymentStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE("DeploymentStore reports !is_open on an unreachable pool, and every method fails "
          "closed",
          "[deployment_store]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    DeploymentStore store{pool};
    CHECK_FALSE(store.is_open());

    // Every failure here is a genuine store-unavailable condition, never a
    // validation/not-found business error — each must carry
    // kDeploymentDbErrorPrefix so discovery_routes.cpp's classifier maps it
    // to 503, not 400/404. Locks the contract create_job/cancel_job's route
    // handlers depend on (gov quality-engineer finding #1): a future error
    // string that drops the prefix would silently regress a genuine outage
    // back to "bad request", with no test to catch it.
    auto create_res = store.create_job("host.example.com", "linux", "manual");
    CHECK_FALSE(create_res.has_value());
    CHECK(create_res.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));

    auto list_res = store.list_jobs();
    CHECK_FALSE(list_res.has_value());
    CHECK(list_res.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));

    auto get_res = store.get_job("x");
    CHECK_FALSE(get_res.has_value());
    CHECK(get_res.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));

    auto update_res = store.update_status("x", "running");
    CHECK_FALSE(update_res.has_value());
    CHECK(update_res.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));

    auto cancel_res = store.cancel_job("x");
    CHECK_FALSE(cancel_res.has_value());
    CHECK(cancel_res.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));
}

// ── create_job validation ───────────────────────────────────────────────────

TEST_CASE("create_job validates target_host/os/method before writing", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    SECTION("empty target_host is rejected") {
        auto r = store.create_job("", "linux", "manual");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("a shell-metacharacter host is rejected") {
        auto r = store.create_job("host;rm -rf /", "linux", "manual");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("an over-length host is rejected") {
        auto r = store.create_job(std::string(254, 'a'), "linux", "manual");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("an SSH-option-injection-shaped leading-dash host is rejected") {
        // gov fjarvis MEDIUM — empirically these passed the char-allowlist
        // before the leading/trailing '-' check existed: real SSH option
        // shapes ("-oProxyCommand=...", "-Jjump.host", "-Ffile") a future
        // ssh-method executor could pass straight to a command line.
        auto r = store.create_job("-Jjump.evil.com", "linux", "ssh");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("a trailing-dash host is rejected") {
        auto r = store.create_job("host.example.com-", "linux", "manual");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("an unrecognised os is rejected") {
        auto r = store.create_job("host.example.com", "beos", "manual");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("an unrecognised method is rejected") {
        auto r = store.create_job("host.example.com", "linux", "telepathy");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("a valid job is created as pending") {
        auto r = store.create_job("host.example.com", "linux", "ssh");
        REQUIRE(r.has_value());
        CHECK_FALSE(r->empty());

        auto job = store.get_job(*r);
        REQUIRE(job.has_value());
        REQUIRE(job->has_value());
        CHECK((*job)->target_host == "host.example.com");
        CHECK((*job)->os == "linux");
        CHECK((*job)->method == "ssh");
        CHECK((*job)->status == "pending");
        CHECK((*job)->created_at > 0);
        CHECK((*job)->started_at == 0);
        CHECK((*job)->completed_at == 0);
    }
}

// ── list_jobs / get_job — typed reads ───────────────────────────────────────

TEST_CASE("list_jobs: empty when no job has ever been created", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto jobs = store.list_jobs();
    REQUIRE(jobs.has_value()); // a genuine empty result, never unexpected
    CHECK(jobs->empty());
}

TEST_CASE("list_jobs: returns every job newest-first", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto a = store.create_job("a.example.com", "linux", "manual");
    auto b = store.create_job("b.example.com", "windows", "ssh");
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());

    auto jobs = store.list_jobs();
    REQUIRE(jobs.has_value());
    REQUIRE(jobs->size() == 2);
    // created_at DESC, ties possible within the same second — assert set
    // membership rather than a strict order that a fast test run could flake.
    std::vector<std::string> ids;
    for (const auto& j : *jobs)
        ids.push_back(j.id);
    CHECK(std::find(ids.begin(), ids.end(), *a) != ids.end());
    CHECK(std::find(ids.begin(), ids.end(), *b) != ids.end());
}

TEST_CASE("get_job: nullopt for an unknown id, distinct from a store failure",
          "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto job = store.get_job("no-such-id");
    REQUIRE(job.has_value()); // a genuine successful read of zero rows
    CHECK_FALSE(job->has_value());
}

TEST_CASE("list_jobs/get_job report a genuine store failure as unexpected, never a silent "
          "empty/not-found",
          "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult d{PQexec(conn.get(), "DROP TABLE deployment_store.deployment_jobs CASCADE")};
        REQUIRE(d.ok());
    }

    auto jobs = store.list_jobs();
    CHECK_FALSE(jobs.has_value());
    CHECK(jobs.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));

    auto job = store.get_job(*created);
    CHECK_FALSE(job.has_value());
    CHECK(job.error().starts_with(yuzu::server::kDeploymentDbErrorPrefix));
}

// ── update_status ────────────────────────────────────────────────────────────

TEST_CASE("update_status rejects an unrecognised status", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());

    auto r = store.update_status(*created, "sideways");
    REQUIRE_FALSE(r.has_value());
}

TEST_CASE("update_status on an unknown id is not_found", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.update_status("no-such-id", "running");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "job not found");
}

TEST_CASE("update_status stamps started_at on a transition to running", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());

    REQUIRE(store.update_status(*created, "running").has_value());
    auto job = store.get_job(*created);
    REQUIRE(job.has_value());
    REQUIRE(job->has_value());
    CHECK((*job)->status == "running");
    CHECK((*job)->started_at > 0);
    CHECK((*job)->completed_at == 0);
}

TEST_CASE("update_status stamps completed_at and error on a transition to failed",
          "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());
    REQUIRE(store.update_status(*created, "running").has_value());

    REQUIRE(store.update_status(*created, "failed", "install script exited 1").has_value());
    auto job = store.get_job(*created);
    REQUIRE(job.has_value());
    REQUIRE(job->has_value());
    CHECK((*job)->status == "failed");
    CHECK((*job)->completed_at > 0);
    CHECK((*job)->error == "install script exited 1");
    CHECK((*job)->started_at > 0); // untouched by the completed/failed branch
}

// ── cancel_job ───────────────────────────────────────────────────────────────

TEST_CASE("cancel_job cancels a pending job", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());

    REQUIRE(store.cancel_job(*created).has_value());
    auto job = store.get_job(*created);
    REQUIRE(job.has_value());
    REQUIRE(job->has_value());
    CHECK((*job)->status == "cancelled");
    CHECK((*job)->error == "cancelled by operator");
    CHECK((*job)->completed_at == 0); // cancel never stamps completed_at
}

TEST_CASE("cancel_job cancels a running job", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());
    REQUIRE(store.update_status(*created, "running").has_value());

    REQUIRE(store.cancel_job(*created).has_value());
    auto job = store.get_job(*created);
    REQUIRE(job.has_value());
    REQUIRE(job->has_value());
    CHECK((*job)->status == "cancelled");
}

TEST_CASE("cancel_job rejects an already-completed job", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_job("host.example.com", "linux", "manual");
    REQUIRE(created.has_value());
    REQUIRE(store.update_status(*created, "running").has_value());
    REQUIRE(store.update_status(*created, "completed").has_value());

    auto r = store.cancel_job(*created);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "only pending or running jobs can be cancelled");

    // Rejected cancel must not have touched the row.
    auto job = store.get_job(*created);
    REQUIRE(job.has_value());
    REQUIRE(job->has_value());
    CHECK((*job)->status == "completed");
}

TEST_CASE("cancel_job on an unknown id is not_found", "[deployment_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.cancel_job("no-such-id");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "job not found");
}

// ── migrate_from_sqlite backfill contract ───────────────────────────────────

TEST_CASE("DeploymentStore::migrate_from_sqlite backfill contract",
          "[deployment_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    SECTION("no legacy file: stamps the marker and returns true, idempotently") {
        auto missing =
            yuzu::test::unique_temp_path("yuzu_test_deploy_missing") / "deployment-jobs.db";
        CHECK(store.migrate_from_sqlite(missing));
        CHECK(store.migrate_from_sqlite(missing)); // second call is a no-op success
    }

    SECTION("already backfilled: a second call is a cheap no-op success") {
        auto missing =
            yuzu::test::unique_temp_path("yuzu_test_deploy_missing2") / "deployment-jobs.db";
        REQUIRE(store.migrate_from_sqlite(missing));
        CHECK(store.migrate_from_sqlite(missing));
    }
}

// This is THE regression test for the HIGH-severity defect an adversarial
// review (Kimi + Codex) found and confirmed: the original single-row
// "backfill_complete" marker let a fileless replica's stamp permanently wave
// through a DIFFERENT, holder replica's real legacy data (playbook's "Local
// source absence never creates terminal migration state on its own"). The
// two SECTIONs above each call migrate_from_sqlite only once per (missing)
// path — neither proves a SOURCELESS stamp doesn't block a SUBSEQUENT real
// backfill on the SAME store (gov quality-engineer finding #2). This test
// exercises exactly that sequence.
TEST_CASE("migrate_from_sqlite: a sourceless (fileless) boot never blocks a later boot's real "
          "legacy data — the anti-pattern this store's fingerprint design closes",
          "[deployment_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    // Step 1: simulate a FILELESS replica's boot — no local legacy file.
    // Under the single-marker design this replaced, this alone would have
    // permanently stamped the store "backfilled" fleet-wide.
    auto missing_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_sourceless_first") / "deployment-jobs.db";
    REQUIRE(store.migrate_from_sqlite(missing_path));

    // Step 2: simulate a DIFFERENT, HOLDER replica's later boot — a real
    // legacy file with real operator-authored jobs. Under the anti-pattern
    // this fix closes, this call would have short-circuited on the
    // sourceless marker from step 1 and returned success WITHOUT copying
    // anything. It must instead actually copy the real data.
    DeploymentJob legacy;
    legacy.id = "cccccccccccccccc";
    legacy.target_host = "holder-replica.example.com";
    legacy.os = "linux";
    legacy.method = "manual";
    legacy.status = "completed";
    legacy.created_at = 5000;
    legacy.started_at = 5001;
    legacy.completed_at = 5002;
    legacy.error = "";
    auto holder_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_sourceless_second") / "deployment-jobs.db";
    std::filesystem::create_directories(holder_path.parent_path());
    write_legacy_sqlite_db(holder_path, {legacy});

    REQUIRE(store.migrate_from_sqlite(holder_path));

    auto got = store.get_job(legacy.id);
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->target_host == legacy.target_host);
    CHECK((*got)->status == "completed");

    // Step 3: a third boot against the SAME holder file (this replica
    // rebooting) is a no-op — its own fingerprint is now recorded — but does
    // NOT duplicate the row.
    REQUIRE(store.migrate_from_sqlite(holder_path));
    auto jobs = store.list_jobs();
    REQUIRE(jobs.has_value());
    CHECK(jobs->size() == 1);
}

// Regression test for gov fjarvis BLOCKING: a job id already present in
// Postgres (from an EARLIER, successful backfill of a DIFFERENT legacy
// file) with DIFFERENT IDENTITY than a LATER legacy file's row sharing that
// same id must never be silently discarded by `ON CONFLICT (id) DO
// NOTHING` while the later file's fingerprint gets stamped complete anyway
// — the exact "trust PGRES_COMMAND_OK to mean YOUR row won" anti-pattern
// docs/postgres-store-playbook.md's "Anti-patterns reviewers reject"
// section documents (AuditStore::stamp_complete, ADR-0040, #2697, is the
// worked example that motivated the rule). This can happen in practice via
// two legacy files that share an id by construction — e.g. one replica's
// data directory cloned to provision another, then each independently
// mutated before either migrates. The two rows below differ on
// `target_host` — an IDENTITY field (deployment_store.cpp's design note
// above migrate_from_sqlite) — which is what makes this the fail-closed
// case rather than the benign lifecycle-drift no-op covered separately
// below.
TEST_CASE("migrate_from_sqlite fails closed (not silently) when a legacy row's id already "
          "exists in Postgres with different identity",
          "[deployment_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    const std::string shared_id = "dddddddddddddddd";

    DeploymentJob first;
    first.id = shared_id;
    first.target_host = "first-replica.example.com";
    first.os = "linux";
    first.method = "manual";
    first.status = "pending";
    first.created_at = 1000;
    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_conflict_first") / "deployment-jobs.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {first});
    REQUIRE(store.migrate_from_sqlite(first_path));

    auto got1 = store.get_job(shared_id);
    REQUIRE(got1.has_value());
    REQUIRE(got1->has_value());
    CHECK((*got1)->status == "pending");

    // A SECOND legacy file, DIFFERENT overall content (so its fingerprint
    // differs and it is not short-circuited by the marker check), sharing
    // the SAME job id but a DIFFERENT `target_host` — an IDENTITY field,
    // which is what makes this the fail-closed case (the incidentally
    // different `status` below would, on its own with matching identity,
    // hit the separate lifecycle-direction check — see the "legacy AHEAD"
    // test further down — not this one). The scenario a cloned/restored
    // data directory can produce.
    DeploymentJob second;
    second.id = shared_id;
    second.target_host = "second-replica.example.com";
    second.os = "linux";
    second.method = "manual";
    second.status = "completed";
    second.created_at = 1000;
    second.completed_at = 2000;
    auto second_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_conflict_second") / "deployment-jobs.db";
    std::filesystem::create_directories(second_path.parent_path());
    write_legacy_sqlite_db(second_path, {second});

    CHECK_FALSE(store.migrate_from_sqlite(second_path));

    // The original row must survive UNCHANGED — no silent partial
    // overwrite AND no silent discard-with-stamped-success.
    auto got2 = store.get_job(shared_id);
    REQUIRE(got2.has_value());
    REQUIRE(got2->has_value());
    CHECK((*got2)->status == "pending");
    CHECK((*got2)->target_host == "first-replica.example.com");

    // The failed pass must not have stamped its fingerprint complete — a
    // retry (e.g. after an operator reconciles the two files by hand)
    // fails the SAME way again, never silently "succeeds" on a stale
    // no-op.
    CHECK_FALSE(store.migrate_from_sqlite(second_path));
}

// Companion to the conflict-with-different-identity test above: an `ON
// CONFLICT` match is on id ALONE, so a conflict does not by itself mean the
// content differs (gov security-guardian/docs-writer SHOULD, hardening
// round 2). A legacy file that is a SUPERSET of what's already migrated —
// re-encountering a byte-identical row alongside genuinely new ones, e.g. a
// cloned replica's file with a few local additions — must succeed, not be
// refused as if it were the differing-content case.
TEST_CASE("migrate_from_sqlite treats an identical-content id conflict as a benign no-op, not "
          "a failure",
          "[deployment_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    DeploymentJob shared;
    shared.id = "eeeeeeeeeeeeeeee";
    shared.target_host = "shared.example.com";
    shared.os = "linux";
    shared.method = "manual";
    shared.status = "pending";
    shared.created_at = 3000;

    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_identical_first") / "deployment-jobs.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {shared});
    REQUIRE(store.migrate_from_sqlite(first_path));

    // A SECOND, larger legacy file: the SAME shared row (byte-identical)
    // plus one genuinely NEW row. Different overall file content means a
    // different fingerprint, so this is not short-circuited by the marker
    // check — it must reach the per-row conflict path for `shared` and
    // correctly treat it as benign.
    DeploymentJob new_job;
    new_job.id = "ffffffffffffffff";
    new_job.target_host = "new.example.com";
    new_job.os = "linux";
    new_job.method = "manual";
    new_job.status = "pending";
    new_job.created_at = 3001;
    auto superset_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_identical_superset") /
        "deployment-jobs.db";
    std::filesystem::create_directories(superset_path.parent_path());
    write_legacy_sqlite_db(superset_path, {shared, new_job});

    REQUIRE(store.migrate_from_sqlite(superset_path));

    // Both rows present: the identical-content conflict did not abort the
    // pass, and the genuinely new sibling row landed too.
    auto jobs = store.list_jobs();
    REQUIRE(jobs.has_value());
    CHECK(jobs->size() == 2);
    auto new_got = store.get_job(new_job.id);
    REQUIRE(new_got.has_value());
    REQUIRE(new_got->has_value());
    CHECK((*new_got)->target_host == "new.example.com");
}

// Regression test for gov unhappy-path UP-1 (SHOULD, hardening round 3): a
// job already migrated once and then legitimately progressed via live
// traffic (update_status) must NOT be treated as a content conflict when a
// legacy file whose snapshot predates that progress is backfilled again —
// e.g. a slower-booting replica sharing the same original legacy content,
// re-migrating after a restart, while a sibling replica already advanced
// the SAME job's status. The prior design compared status/started_at/
// completed_at/error as part of "identical content" and would have failed
// this boot closed on every retry, forever, for a scenario that is not
// corruption. The fix: only IDENTITY fields (target_host/os/method/
// created_at) gate fail-closed; a LIFECYCLE-only difference is a benign
// no-op that keeps Postgres's live value and logs a WARNING instead of
// blocking the boot.
TEST_CASE("migrate_from_sqlite treats a lifecycle-only difference as a benign no-op, keeps "
          "Postgres's live value, and warns rather than failing closed",
          "[deployment_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    const std::string shared_id = "9999999999999999";

    // First legacy file: the job as originally created, still pending.
    DeploymentJob original;
    original.id = shared_id;
    original.target_host = "progressed.example.com";
    original.os = "linux";
    original.method = "manual";
    original.status = "pending";
    original.created_at = 4000;
    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_lifecycle_first") / "deployment-jobs.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {original});
    REQUIRE(store.migrate_from_sqlite(first_path));

    // Live traffic on THIS replica (standing in for "some replica") advances
    // the job past what the legacy snapshot shows — the ordinary lifecycle
    // update_status/cancel_job already cover elsewhere in this file.
    REQUIRE(store.update_status(shared_id, "completed").has_value());
    auto progressed = store.get_job(shared_id);
    REQUIRE(progressed.has_value());
    REQUIRE(progressed->has_value());
    CHECK((*progressed)->status == "completed");

    // A SECOND legacy file — different overall content (so its fingerprint
    // differs and it reaches the per-row conflict path), same shared id,
    // SAME identity as `original`, but its own lifecycle snapshot still
    // shows the PRE-progress state. This models a sibling replica's stale
    // legacy copy, or this same replica re-migrating from an unmoved legacy
    // file after a restart.
    DeploymentJob stale_snapshot = original; // identity fields byte-identical
    DeploymentJob padding_job;
    padding_job.id = "8888888888888888";
    padding_job.target_host = "padding.example.com";
    padding_job.os = "linux";
    padding_job.method = "manual";
    padding_job.status = "pending";
    padding_job.created_at = 4001;
    auto second_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_lifecycle_second") / "deployment-jobs.db";
    std::filesystem::create_directories(second_path.parent_path());
    write_legacy_sqlite_db(second_path, {stale_snapshot, padding_job});

    std::string captured;
    {
        LogCapture capture;
        CHECK(store.migrate_from_sqlite(second_path)); // succeeds — never fails closed
        captured = capture.str();
    }
    CHECK(captured.find("already migrated with lifecycle progress") != std::string::npos);

    // Postgres's live (more advanced) value survives untouched — the stale
    // legacy snapshot never reverts it.
    auto after = store.get_job(shared_id);
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->status == "completed");

    // The genuinely new sibling row in the same file still lands.
    auto padding_got = store.get_job(padding_job.id);
    REQUIRE(padding_got.has_value());
    REQUIRE(padding_got->has_value());
}

// Regression test for gov unhappy-path Finding A (SHOULD, hardening round
// 4) — the direct structural counterpart of UP-1 above, in the OPPOSITE
// direction. ADR-0009's rollback-then-roll-forward window means the
// pre-migration SQLite-only binary can run again after a rollback and
// genuinely progress a job's lifecycle further than Postgres ever saw
// (Postgres isn't written to while rolled back). If the backfill then
// silently kept Postgres's LESS-advanced value on roll-forward — as a
// same-identity/different-lifecycle conflict alone would suggest is always
// safe — that real progress would be discarded with only a WARNING log as
// evidence, inside a legacy-file retention window that itself expires
// after one release. The fix: when the LEGACY row's status ranks strictly
// ahead of Postgres's current value, the direction is treated as
// suspicious rather than benign, and the whole backfill fails closed the
// same way an identity mismatch does.
TEST_CASE("migrate_from_sqlite fails closed when a legacy row's lifecycle is AHEAD of "
          "Postgres's current value",
          "[deployment_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    const std::string shared_id = "7777777777777777";

    // First legacy file: the job as originally created, still pending —
    // migrated normally.
    DeploymentJob original;
    original.id = shared_id;
    original.target_host = "rolled-back.example.com";
    original.os = "linux";
    original.method = "manual";
    original.status = "pending";
    original.created_at = 5000;
    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_ahead_first") / "deployment-jobs.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {original});
    REQUIRE(store.migrate_from_sqlite(first_path));

    // A SECOND legacy file — same identity, but its lifecycle snapshot is
    // now AHEAD of Postgres's current ("pending") value: this stands in for
    // the pre-migration binary having completed the job while the
    // deployment was rolled back to it, with Postgres never touched during
    // that window.
    DeploymentJob rolled_back_progress = original;
    rolled_back_progress.status = "completed";
    rolled_back_progress.completed_at = 5500;
    rolled_back_progress.error = "";
    auto second_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_ahead_second") / "deployment-jobs.db";
    std::filesystem::create_directories(second_path.parent_path());
    write_legacy_sqlite_db(second_path, {rolled_back_progress});

    CHECK_FALSE(store.migrate_from_sqlite(second_path)); // fails closed, not silently kept

    // Postgres's stale "pending" value is untouched (no partial write), and
    // the legacy file's more-advanced "completed" state was never adopted
    // either — the operator must reconcile, same remediation shape as an
    // identity mismatch.
    auto after = store.get_job(shared_id);
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->status == "pending");

    // The failed pass must not have stamped its fingerprint complete — a
    // retry fails the SAME way again until an operator reconciles.
    CHECK_FALSE(store.migrate_from_sqlite(second_path));
}

// Regression test for gov unhappy-path Finding UP-E / cpp-expert Finding 1
// (SHOULD, hardening round 5): `lifecycle_rank` ties the three terminal
// statuses (completed/failed/cancelled) at the same rank, so a legacy row
// and its Postgres counterpart DISAGREEING on which terminal outcome
// occurred — not just "who's further along" — must not fall through the
// rank-only `>` check into the benign no-op path. Same rollback-then-roll-
// forward mechanism as the AHEAD test above, but landing on a tied rank
// with a different status rather than a strictly higher one.
TEST_CASE("migrate_from_sqlite fails closed when a legacy row reports a DIFFERENT terminal "
          "outcome than Postgres's current value, even at the same lifecycle rank",
          "[deployment_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    const std::string shared_id = "6666666666666666";

    DeploymentJob original;
    original.id = shared_id;
    original.target_host = "diverged-terminal.example.com";
    original.os = "linux";
    original.method = "manual";
    original.status = "running";
    original.created_at = 6000;
    original.started_at = 6100;
    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_terminal_first") / "deployment-jobs.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {original});
    REQUIRE(store.migrate_from_sqlite(first_path));

    REQUIRE(store.update_status(shared_id, "completed").has_value());

    // A SECOND legacy file — same identity, but this snapshot reached a
    // DIFFERENT terminal outcome (failed, with an error) than what Postgres
    // now holds (completed). Both rank 2 — a tie, not "legacy ahead" — so
    // this specifically exercises the terminal_disagreement branch, not the
    // legacy_ahead one already covered above.
    DeploymentJob diverged = original;
    diverged.status = "failed";
    diverged.completed_at = 6500;
    diverged.error = "connection refused";
    auto second_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_terminal_second") / "deployment-jobs.db";
    std::filesystem::create_directories(second_path.parent_path());
    write_legacy_sqlite_db(second_path, {diverged});

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(second_path)); // fails closed, not silently kept
        captured = capture.str();
    }
    CHECK(captured.find("different terminal outcome") != std::string::npos);

    // Postgres's "completed" value is untouched — neither side was silently
    // adopted or discarded.
    auto after = store.get_job(shared_id);
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->status == "completed");

    // Retries fail the same way until an operator reconciles.
    CHECK_FALSE(store.migrate_from_sqlite(second_path));
}

// Regression test for gov docs-writer (hardening round 5): a legacy file's
// `status` column is read raw from untrusted SQLite with no validation —
// unlike `create_job`/`update_status`, which both reject anything outside
// the 5 known values before it ever reaches Postgres. Without this check,
// a hand-edited/corrupted legacy file's garbage status could land in
// Postgres on a row's first (non-conflicting) insert, and — because
// `lifecycle_rank`'s unrecognised-value fallback (3) is already maximal —
// no future legitimate legacy row could ever be seen as "ahead" of it,
// permanently masking the corruption as benign.
TEST_CASE("migrate_from_sqlite fails closed on a legacy row with an unrecognised status, "
          "before ever reaching Postgres",
          "[deployment_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    DeploymentJob garbage;
    garbage.id = "5555555555555555";
    garbage.target_host = "corrupt.example.com";
    garbage.os = "linux";
    garbage.method = "manual";
    garbage.status = "not-a-real-status"; // outside the 5 known values
    garbage.created_at = 7000;
    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_bad_status") / "deployment-jobs.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_sqlite_db(legacy_path, {garbage});

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
        captured = capture.str();
    }
    CHECK(captured.find("unrecognised status") != std::string::npos);

    // Nothing landed — the row never reached Postgres at all.
    auto jobs = store.list_jobs();
    REQUIRE(jobs.has_value());
    CHECK(jobs->empty());
}

// Regression test for gov unhappy-path Finding UP-H (SHOULD, hardening
// round 5, verification pass): a genuine DB-level failure (not a row-vs-row
// content disagreement) must NOT get the row-conflict remediation text
// ("compare it against Postgres's current row for the same id") — there is
// no row-level failure_detail for that guidance to refer to. DROPping the
// table mid-transaction (same technique as the existing "genuine store
// failure" test above) forces the per-row INSERT itself to fail with a
// real Postgres error, exercising the row_conflict_guidance=false path.
TEST_CASE("migrate_from_sqlite gives generic (not row-comparison) guidance on a genuine "
          "database failure",
          "[deployment_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    DeploymentJob job;
    job.id = "4444444444444444";
    job.target_host = "db-error.example.com";
    job.os = "linux";
    job.method = "manual";
    job.status = "pending";
    job.created_at = 8000;
    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_db_error") / "deployment-jobs.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_sqlite_db(legacy_path, {job});

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult d{PQexec(conn.get(), "DROP TABLE deployment_store.deployment_jobs CASCADE")};
        REQUIRE(d.ok());
    }

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
        captured = capture.str();
    }
    CHECK(captured.find("database or legacy-file-read failure") != std::string::npos);
    CHECK(captured.find("which side to reconcile") == std::string::npos);
    CHECK(captured.find("compare it against Postgres's current row") == std::string::npos);
}

// Regression test for the fingerprint canonicalization's injectivity (gov
// quality-engineer SHOULD): id="a", target_host="b\x1fc" and
// id="a\x1fb", target_host="c" (all other fields equal) canonicalize to the
// BYTE-IDENTICAL string under the OLD raw-delimiter (\x1f/\x1e) encoding —
// verified by hand: "a" + \x1f + "b\x1fc" + \x1f... == "a\x1fb" + \x1f +
// "c" + \x1f... — because a delimiter byte embedded in one field is
// indistinguishable from a real field boundary. Under the CURRENT
// length-prefixed encoding they must NOT collide. This is observable
// through the public API: backfilling both (different-id, so never
// row-conflicting) single-job legacy files must land BOTH ids — under the
// old encoding, the second file's fingerprint would equal the first's,
// short-circuiting via the "already processed" marker and silently
// dropping the second row entirely.
TEST_CASE("migrate_from_sqlite: two files whose rows differ only by a shifted field boundary "
          "do not collide (fingerprint injectivity)",
          "[deployment_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    DeploymentJob job_a;
    job_a.id = "a";
    // Adjacent string literal concatenation, NOT "b\x1fc": a \x hex escape
    // greedily consumes every following hex digit, so "b\x1fc" would parse
    // as 'b' + the single (out-of-range, truncating) escape \x1fc == 0x1fc
    // -> 0xfc, not the intended 'b' + 0x1f + 'c' three-byte sequence.
    job_a.target_host = "b\x1f" "c";
    job_a.os = "linux";
    job_a.method = "manual";
    job_a.status = "pending";
    job_a.created_at = 1000;
    auto path_a = yuzu::test::unique_temp_path("yuzu_test_deploy_boundary_a") /
                 "deployment-jobs.db";
    std::filesystem::create_directories(path_a.parent_path());
    write_legacy_sqlite_db(path_a, {job_a});
    REQUIRE(store.migrate_from_sqlite(path_a));

    DeploymentJob job_b;
    job_b.id = "a\x1f" "b"; // see the adjacent-literal note above
    job_b.target_host = "c";
    job_b.os = "linux";
    job_b.method = "manual";
    job_b.status = "pending";
    job_b.created_at = 1000;
    auto path_b = yuzu::test::unique_temp_path("yuzu_test_deploy_boundary_b") /
                 "deployment-jobs.db";
    std::filesystem::create_directories(path_b.parent_path());
    write_legacy_sqlite_db(path_b, {job_b});
    REQUIRE(store.migrate_from_sqlite(path_b));

    // Both ids must be present. Under a delimiter-byte-collision regression,
    // job_b's file would hash identically to job_a's, the marker check
    // would report "already processed", and job_b would never land.
    auto got_a = store.get_job(job_a.id);
    REQUIRE(got_a.has_value());
    REQUIRE(got_a->has_value());
    CHECK((*got_a)->target_host == "b\x1f" "c");

    auto got_b = store.get_job(job_b.id);
    REQUIRE(got_b.has_value());
    REQUIRE(got_b->has_value());
    CHECK((*got_b)->target_host == "c");
}

TEST_CASE("DeploymentStore::migrate_from_sqlite copies a populated legacy file exactly once",
          "[deployment_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_populated") / "deployment-jobs.db";
    std::filesystem::create_directories(legacy_path.parent_path());

    DeploymentJob j1;
    j1.id = "aaaaaaaaaaaaaaaa";
    j1.target_host = "legacy-a.example.com";
    j1.os = "linux";
    j1.method = "ssh";
    j1.status = "completed";
    j1.created_at = 1000;
    j1.started_at = 1001;
    j1.completed_at = 1002;
    j1.error = "";

    DeploymentJob j2;
    j2.id = "bbbbbbbbbbbbbbbb";
    j2.target_host = "legacy-b.example.com";
    j2.os = "windows";
    j2.method = "manual";
    j2.status = "failed";
    j2.created_at = 2000;
    j2.started_at = 2001;
    j2.completed_at = 2002;
    j2.error = "install timed out";

    write_legacy_sqlite_db(legacy_path, {j1, j2});

    REQUIRE(store.migrate_from_sqlite(legacy_path));

    auto got1 = store.get_job(j1.id);
    REQUIRE(got1.has_value());
    REQUIRE(got1->has_value());
    CHECK((*got1)->target_host == j1.target_host);
    CHECK((*got1)->status == "completed");
    CHECK((*got1)->completed_at == 1002);

    auto got2 = store.get_job(j2.id);
    REQUIRE(got2.has_value());
    REQUIRE(got2->has_value());
    CHECK((*got2)->error == "install timed out");

    // Second call against the SAME populated file is a no-op (marker
    // idempotency) — must not error on a duplicate-key conflict and must not
    // duplicate rows.
    REQUIRE(store.migrate_from_sqlite(legacy_path));
    auto jobs = store.list_jobs();
    REQUIRE(jobs.has_value());
    CHECK(jobs->size() == 2);
}

TEST_CASE("DeploymentStore::migrate_from_sqlite aborts unstamped on a mid-scan legacy read "
          "failure",
          "[deployment_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deployment_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_truncated") / "deployment-jobs.db";
    std::filesystem::create_directories(legacy_path.parent_path());

    std::vector<DeploymentJob> bulk;
    for (int i = 0; i < 3000; ++i) {
        DeploymentJob j;
        char idbuf[17];
        std::snprintf(idbuf, sizeof(idbuf), "%016x", i + 1);
        j.id = idbuf;
        j.target_host = "bulk-host-" + std::to_string(i) + ".example.com-padding-for-size-xxxxx";
        j.os = "linux";
        j.method = "manual";
        j.status = "pending";
        j.created_at = 1000 + i;
        bulk.push_back(j);
    }
    write_legacy_sqlite_db(legacy_path, bulk);

    auto full_size = std::filesystem::file_size(legacy_path);
    REQUIRE(full_size > 65536); // sanity: spans many SQLite pages

    // Corrupt a LATER region IN PLACE (same file length — no truncation).
    // Truncation trips SQLite's page-count-vs-file-size consistency check
    // immediately, which fails uniformly at prepare/schema-probe time
    // regardless of table size — exactly the false-precision the
    // adversarial-review LOW finding caught (the test claimed "mid-scan"
    // coverage but the truncation technique actually exercised
    // prepare-time failure). Overwriting bytes well into the file, with the
    // header/schema pages and the B-tree's early pages left intact, lets
    // `sqlite3_prepare_v2` and the schema probe succeed and several rows
    // land via SQLITE_ROW before the table scan's cursor reaches the
    // corrupted page and `sqlite3_step` returns a non-SQLITE_DONE terminal
    // code — genuinely exercising the `step_rc != SQLITE_DONE` guard
    // (deployment_store.cpp) this test is named for.
    {
        std::fstream f(legacy_path, std::ios::in | std::ios::out | std::ios::binary);
        REQUIRE(f.is_open());
        const auto corrupt_at = static_cast<std::streamoff>(full_size * 3 / 4);
        f.seekp(corrupt_at);
        std::vector<char> garbage(4096, '\xff');
        f.write(garbage.data(), static_cast<std::streamsize>(garbage.size()));
        REQUIRE(f.good());
    }

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
        captured = capture.str();
    }

    // Assert WHICH failure branch actually fired, not just that migration
    // failed — deployment_store.cpp logs a distinct message per branch:
    // "legacy deployment_jobs query failed" is the prepare-time failure
    // (schema/statement compile), "scan aborted mid-read" is the step-time
    // failure (step_rc != SQLITE_DONE) this test is named for. Without this,
    // the test would still CHECK_FALSE-pass if the corruption technique ever
    // regressed back to only exercising prepare-time failure (exactly the
    // false-precision an adversarial review caught in the truncation-based
    // predecessor of this test).
    CHECK(captured.find("scan aborted mid-read") != std::string::npos);
    CHECK(captured.find("legacy deployment_jobs query failed") == std::string::npos);

    // No partial rows landed.
    auto jobs = store.list_jobs();
    REQUIRE(jobs.has_value());
    CHECK(jobs->empty());

    // A subsequent migrate_from_sqlite against a freshly-written, INTACT file
    // succeeds — proving the aborted pass never stamped the marker.
    auto intact_path =
        yuzu::test::unique_temp_path("yuzu_test_deploy_intact") / "deployment-jobs.db";
    std::filesystem::create_directories(intact_path.parent_path());
    write_legacy_sqlite_db(intact_path, {bulk.front()});
    REQUIRE(store.migrate_from_sqlite(intact_path));

    auto jobs2 = store.list_jobs();
    REQUIRE(jobs2.has_value());
    CHECK(jobs2->size() == 1);
}
