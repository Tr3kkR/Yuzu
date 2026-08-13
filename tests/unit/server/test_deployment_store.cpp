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
// file) with DIFFERENT content than a LATER legacy file's row sharing that
// same id must never be silently discarded by `ON CONFLICT (id) DO
// NOTHING` while the later file's fingerprint gets stamped complete anyway
// — the exact "trust PGRES_COMMAND_OK to mean YOUR row won" anti-pattern
// docs/postgres-store-playbook.md's "Anti-patterns reviewers reject"
// section documents (AuditStore::stamp_complete, ADR-0040, #2697, is the
// worked example that motivated the rule). This can happen in practice via
// two legacy files that share an id by construction — e.g. one replica's
// data directory cloned to provision another, then each independently
// mutated before either migrates.
TEST_CASE("migrate_from_sqlite fails closed (not silently) when a legacy row's id already "
          "exists in Postgres with different content",
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
    // differs and it is not short-circuited by the marker check), but
    // sharing the SAME job id with a DIFFERENT status — the scenario a
    // cloned/restored data directory can produce.
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
