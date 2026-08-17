/**
 * test_software_deployment_store.cpp — `SoftwareDeploymentStore` (capability
 * 7.6 — software packaging + fleet deployment catalog).
 *
 * Covers: fail-closed construction (migration drift + unreachable pool),
 * package CRUD (incl. the enforced-FK delete-block), deployment lifecycle
 * (create/start/cancel/rollback, guarded transitions), agent status +
 * refresh_counts + active_count, list filters, a full end-to-end lifecycle,
 * and the ADR-0009/ADR-0051 migrate_from_sqlite backfill contract across all
 * three tables (fingerprint idempotency, IDENTITY-vs-LIFECYCLE conflict
 * partition for both status enums, referential-closure orphan detection,
 * partial-legacy-schema fail-closed, mid-scan corruption).
 *
 * Born-on-Postgres migrated store (ADR-0012 §1, authoritative/fail-hard).
 * PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set but
 * broken (test_helpers.hpp skip-vs-fail contract). Store-behaviour cases use
 * the pre-migrated PgTestTemplate variant (docs/postgres-store-playbook.md
 * step 7); the two fail-closed cases use YUZU_REQUIRE_PG_DB / no gate at
 * all, per the plain-migration-test carve-out documented on that macro.
 */

#include "software_deployment_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::AgentDeploymentStatus;
using yuzu::server::SoftwareDeployment;
using yuzu::server::SoftwareDeploymentStore;
using yuzu::server::SoftwarePackage;
using yuzu::server::SqliteDb;
using yuzu::server::SqliteStmt;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// RAII log capture — mirrors test_deployment_store.cpp's LogCapture. Used to
// assert WHICH failure branch actually fired, not just that a call failed.
class LogCapture {
public:
    LogCapture() {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(oss_);
        auto logger =
            std::make_shared<spdlog::logger>("test_software_deployment_store_capture", sink);
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

yuzu::test::PgTestTemplate sw_deploy_store_tpl{
    "swdeploystore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        SoftwareDeploymentStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("software_deployment_store template: failed to migrate");
    }};

SoftwarePackage make_package(const std::string& name = "Firefox",
                             const std::string& version = "125.0",
                             const std::string& platform = "windows") {
    SoftwarePackage pkg;
    pkg.name = name;
    pkg.version = version;
    pkg.platform = platform;
    pkg.installer_type = "msi";
    pkg.content_hash = "abc123def456";
    pkg.content_url = "https://content.example.com/firefox-125.msi";
    pkg.silent_args = "/qn /norestart";
    pkg.verify_command = "reg query HKLM\\Software\\Mozilla";
    pkg.rollback_command = "msiexec /x {id} /qn";
    pkg.size_bytes = 85000000;
    pkg.created_by = "admin";
    return pkg;
}

SoftwareDeployment make_deployment(const std::string& package_id,
                                   const std::string& scope = "ostype = 'windows'",
                                   int agents_targeted = 5) {
    SoftwareDeployment dep;
    dep.package_id = package_id;
    dep.scope_expression = scope;
    dep.agents_targeted = agents_targeted;
    dep.created_by = "admin";
    return dep;
}

// Writes a legacy SQLite file with all three tables, no PRAGMA foreign_keys
// (matches the pre-migration store's own constructor — FKs were never
// enforced there). Bound parameters throughout (never string concatenation)
// — an earlier version of this helper concatenated raw values and broke on
// make_deployment's own default scope_expression, "ostype = 'windows'",
// which contains an embedded single quote.
void write_legacy_sqlite_db(const std::filesystem::path& path,
                            const std::vector<SoftwarePackage>& pkgs,
                            const std::vector<SoftwareDeployment>& deps,
                            const std::vector<AgentDeploymentStatus>& agents) {
    SqliteDb db;
    REQUIRE(sqlite3_open(path.string().c_str(), db.addr()) == SQLITE_OK);
    const char* ddl =
        "CREATE TABLE software_packages (id TEXT PRIMARY KEY, name TEXT NOT NULL,"
        "  version TEXT NOT NULL DEFAULT '', platform TEXT NOT NULL DEFAULT '',"
        "  installer_type TEXT NOT NULL DEFAULT '', content_hash TEXT NOT NULL DEFAULT '',"
        "  content_url TEXT NOT NULL DEFAULT '', silent_args TEXT NOT NULL DEFAULT '',"
        "  verify_command TEXT NOT NULL DEFAULT '', rollback_command TEXT NOT NULL DEFAULT '',"
        "  size_bytes INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT 0,"
        "  created_by TEXT NOT NULL DEFAULT '');"
        "CREATE TABLE software_deployments (id TEXT PRIMARY KEY, package_id TEXT NOT NULL,"
        "  scope_expression TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'staged',"
        "  created_by TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT 0,"
        "  started_at INTEGER NOT NULL DEFAULT 0, completed_at INTEGER NOT NULL DEFAULT 0,"
        "  agents_targeted INTEGER NOT NULL DEFAULT 0, agents_success INTEGER NOT NULL DEFAULT 0,"
        "  agents_failure INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE agent_software_status (deployment_id TEXT NOT NULL, agent_id TEXT NOT NULL,"
        "  status TEXT NOT NULL DEFAULT 'pending', started_at INTEGER NOT NULL DEFAULT 0,"
        "  completed_at INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '',"
        "  PRIMARY KEY (deployment_id, agent_id));";
    REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, nullptr) == SQLITE_OK);

    // Bound parameters (never raw string concatenation) — test data such as
    // scope_expression legitimately contains single quotes (e.g.
    // "ostype = 'windows'"), which a naive concatenated INSERT would
    // mis-parse as a premature string terminator.
    for (const auto& p : pkgs) {
        SqliteStmt s;
        REQUIRE(sqlite3_prepare_v2(db.get(),
                                   "INSERT INTO software_packages (id, name, version, platform, "
                                   "installer_type, content_hash, content_url, silent_args, "
                                   "verify_command, rollback_command, size_bytes, created_at, "
                                   "created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                   -1, s.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(s.get(), 1, p.id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 2, p.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 3, p.version.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 4, p.platform.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 5, p.installer_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 6, p.content_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 7, p.content_url.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 8, p.silent_args.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 9, p.verify_command.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 10, p.rollback_command.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(s.get(), 11, p.size_bytes);
        sqlite3_bind_int64(s.get(), 12, p.created_at);
        sqlite3_bind_text(s.get(), 13, p.created_by.c_str(), -1, SQLITE_TRANSIENT);
        REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
    }
    for (const auto& d : deps) {
        SqliteStmt s;
        REQUIRE(sqlite3_prepare_v2(
                    db.get(),
                    "INSERT INTO software_deployments (id, package_id, scope_expression, "
                    "status, created_by, created_at, started_at, completed_at, agents_targeted, "
                    "agents_success, agents_failure) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    -1, s.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(s.get(), 1, d.id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 2, d.package_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 3, d.scope_expression.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 4, d.status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 5, d.created_by.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(s.get(), 6, d.created_at);
        sqlite3_bind_int64(s.get(), 7, d.started_at);
        sqlite3_bind_int64(s.get(), 8, d.completed_at);
        sqlite3_bind_int(s.get(), 9, d.agents_targeted);
        sqlite3_bind_int(s.get(), 10, d.agents_success);
        sqlite3_bind_int(s.get(), 11, d.agents_failure);
        REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
    }
    for (const auto& a : agents) {
        SqliteStmt s;
        REQUIRE(sqlite3_prepare_v2(db.get(),
                                   "INSERT INTO agent_software_status (deployment_id, agent_id, "
                                   "status, started_at, completed_at, error) VALUES "
                                   "(?,?,?,?,?,?)",
                                   -1, s.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(s.get(), 1, a.deployment_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 2, a.agent_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 3, a.status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(s.get(), 4, a.started_at);
        sqlite3_bind_int64(s.get(), 5, a.completed_at);
        sqlite3_bind_text(s.get(), 6, a.error.c_str(), -1, SQLITE_TRANSIENT);
        REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
    }
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore reports !is_open on a migration failure",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA software_deployment_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(
            conn.get(), "CREATE TABLE software_deployment_store.software_packages (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    SoftwareDeploymentStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE("SoftwareDeploymentStore reports !is_open on an unreachable pool, and every method "
          "fails closed",
          "[software_deployment]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    SoftwareDeploymentStore store{pool};
    CHECK_FALSE(store.is_open());

    auto create_pkg = store.create_package(make_package());
    CHECK_FALSE(create_pkg.has_value());
    CHECK(create_pkg.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto list_pkg = store.list_packages();
    CHECK_FALSE(list_pkg.has_value());
    CHECK(list_pkg.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto get_pkg = store.get_package("x");
    CHECK_FALSE(get_pkg.has_value());
    CHECK(get_pkg.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto del_pkg = store.delete_package("x");
    CHECK_FALSE(del_pkg.has_value());
    CHECK(del_pkg.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto create_dep = store.create_deployment(make_deployment("pkg-x"));
    CHECK_FALSE(create_dep.has_value());
    CHECK(create_dep.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto list_dep = store.list_deployments();
    CHECK_FALSE(list_dep.has_value());
    CHECK(list_dep.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto get_dep = store.get_deployment("x");
    CHECK_FALSE(get_dep.has_value());
    CHECK(get_dep.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto start = store.start_deployment("x");
    CHECK_FALSE(start.has_value());
    CHECK(start.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto cancel = store.cancel_deployment("x");
    CHECK_FALSE(cancel.has_value());
    CHECK(cancel.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto rollback = store.rollback_deployment("x");
    CHECK_FALSE(rollback.has_value());
    CHECK(rollback.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    AgentDeploymentStatus s;
    s.agent_id = "agent-1";
    s.status = "pending";
    auto upd = store.update_agent_status("x", s);
    CHECK_FALSE(upd.has_value());
    CHECK(upd.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto refresh = store.refresh_counts("x");
    CHECK_FALSE(refresh.has_value());
    CHECK(refresh.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto statuses = store.get_agent_statuses("x");
    CHECK_FALSE(statuses.has_value());
    CHECK(statuses.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    auto active = store.active_count();
    CHECK_FALSE(active.has_value());
    CHECK(active.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));
}

// ── Package CRUD ─────────────────────────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore: create package and get", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_package(make_package());
    REQUIRE(result.has_value());
    CHECK(!result->empty());

    auto pkg = store.get_package(*result);
    REQUIRE(pkg.has_value());
    REQUIRE(pkg->has_value());
    CHECK((*pkg)->id == *result);
    CHECK((*pkg)->name == "Firefox");
    CHECK((*pkg)->version == "125.0");
    CHECK((*pkg)->platform == "windows");
    CHECK((*pkg)->installer_type == "msi");
    CHECK((*pkg)->content_hash == "abc123def456");
    CHECK((*pkg)->silent_args == "/qn /norestart");
    CHECK((*pkg)->size_bytes == 85000000);
    CHECK((*pkg)->created_at > 0);
    CHECK((*pkg)->created_by == "admin");
}

TEST_CASE("SoftwareDeploymentStore: list packages", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create_package(make_package("Firefox", "125.0")).has_value());
    REQUIRE(store.create_package(make_package("Chrome", "124.0")).has_value());
    REQUIRE(store.create_package(make_package("VSCode", "1.89")).has_value());

    auto pkgs = store.list_packages();
    REQUIRE(pkgs.has_value());
    CHECK(pkgs->size() == 3);
}

TEST_CASE("SoftwareDeploymentStore: delete package", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto id = store.create_package(make_package());
    REQUIRE(id.has_value());

    CHECK(store.delete_package(*id).has_value());

    auto pkg = store.get_package(*id);
    REQUIRE(pkg.has_value());
    CHECK_FALSE(pkg->has_value());

    auto list = store.list_packages();
    REQUIRE(list.has_value());
    CHECK(list->empty());
}

TEST_CASE("SoftwareDeploymentStore: delete nonexistent package fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.delete_package("nonexistent-id");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "package not found");
}

// Postgres enforces the software_deployments.package_id FK (the
// pre-migration SQLite store never did) — deleting a package a live
// deployment references must fail, not silently orphan the deployment.
TEST_CASE("SoftwareDeploymentStore: delete package referenced by a deployment fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    REQUIRE(store.create_deployment(make_deployment(*pkg_id)).has_value());

    auto r = store.delete_package(*pkg_id);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("referenced") != std::string::npos);
    CHECK_FALSE(r.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));

    // The package must survive the rejected delete.
    auto pkg = store.get_package(*pkg_id);
    REQUIRE(pkg.has_value());
    CHECK(pkg->has_value());
}

TEST_CASE("SoftwareDeploymentStore: create package empty name fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg = make_package();
    pkg.name = "";
    auto result = store.create_package(pkg);
    CHECK_FALSE(result.has_value());
    CHECK_FALSE(result.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));
}

// ── Deployment lifecycle ─────────────────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore: create deployment has staged status",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "staged");
    CHECK((*dep)->package_id == *pkg_id);
    CHECK((*dep)->agents_targeted == 5);
    CHECK((*dep)->created_at > 0);
    CHECK((*dep)->started_at == 0);
}

TEST_CASE("SoftwareDeploymentStore: create deployment with nonexistent package_id fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_deployment(make_deployment("no-such-package"));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "package_id does not exist");
    CHECK_FALSE(r.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));
}

TEST_CASE("SoftwareDeploymentStore: start deployment staged to deploying",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    CHECK(store.start_deployment(*dep_id).has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "deploying");
    CHECK((*dep)->started_at > 0);
}

TEST_CASE("SoftwareDeploymentStore: start non-staged deployment fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());
    REQUIRE(store.start_deployment(*dep_id).has_value());

    auto r = store.start_deployment(*dep_id);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "deployment is not staged");
}

TEST_CASE("SoftwareDeploymentStore: start unknown deployment is not_found",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.start_deployment("no-such-id");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "deployment not found");
}

TEST_CASE("SoftwareDeploymentStore: cancel from staged", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    CHECK(store.cancel_deployment(*dep_id).has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "cancelled");
    CHECK((*dep)->completed_at > 0);
}

TEST_CASE("SoftwareDeploymentStore: cancel from deploying", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());
    REQUIRE(store.start_deployment(*dep_id).has_value());

    CHECK(store.cancel_deployment(*dep_id).has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "cancelled");
}

TEST_CASE("SoftwareDeploymentStore: cancel an already-cancelled deployment fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());
    REQUIRE(store.cancel_deployment(*dep_id).has_value());

    auto r = store.cancel_deployment(*dep_id);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "only staged or deploying deployments can be cancelled");
}

TEST_CASE("SoftwareDeploymentStore: rollback deployment", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());
    REQUIRE(store.start_deployment(*dep_id).has_value());

    CHECK(store.rollback_deployment(*dep_id).has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "rolled_back");
    CHECK((*dep)->completed_at > 0);
}

TEST_CASE("SoftwareDeploymentStore: rollback staged fails", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    auto r = store.rollback_deployment(*dep_id);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "only deploying, verifying, or completed deployments can be rolled back");
}

// ── Agent status & refresh counts ───────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore: update agent status", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id, "all", 3));
    REQUIRE(dep_id.has_value());

    AgentDeploymentStatus s1;
    s1.agent_id = "agent-1";
    s1.status = "success";
    s1.started_at = 1000;
    s1.completed_at = 1010;
    REQUIRE(store.update_agent_status(*dep_id, s1).has_value());

    auto statuses = store.get_agent_statuses(*dep_id);
    REQUIRE(statuses.has_value());
    REQUIRE(statuses->size() == 1);
    CHECK((*statuses)[0].agent_id == "agent-1");
    CHECK((*statuses)[0].status == "success");
    CHECK((*statuses)[0].started_at == 1000);
    CHECK((*statuses)[0].completed_at == 1010);
}

TEST_CASE("SoftwareDeploymentStore: update agent status rejects an unrecognised status",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    AgentDeploymentStatus s;
    s.agent_id = "agent-1";
    s.status = "sideways";
    auto r = store.update_agent_status(*dep_id, s);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "invalid status");
}

TEST_CASE("SoftwareDeploymentStore: update agent status on nonexistent deployment fails",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    AgentDeploymentStatus s;
    s.agent_id = "agent-1";
    s.status = "pending";
    auto r = store.update_agent_status("no-such-deployment", s);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "deployment_id does not exist");
    CHECK_FALSE(r.error().starts_with(yuzu::server::kSwDeployDbErrorPrefix));
}

TEST_CASE("SoftwareDeploymentStore: refresh counts", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id, "all", 3));
    REQUIRE(dep_id.has_value());

    AgentDeploymentStatus s1;
    s1.agent_id = "agent-1";
    s1.status = "success";
    REQUIRE(store.update_agent_status(*dep_id, s1).has_value());
    AgentDeploymentStatus s2;
    s2.agent_id = "agent-2";
    s2.status = "success";
    REQUIRE(store.update_agent_status(*dep_id, s2).has_value());
    AgentDeploymentStatus s3;
    s3.agent_id = "agent-3";
    s3.status = "failed";
    s3.error = "download timeout";
    REQUIRE(store.update_agent_status(*dep_id, s3).has_value());

    REQUIRE(store.refresh_counts(*dep_id).has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->agents_success == 2);
    CHECK((*dep)->agents_failure == 1);
}

TEST_CASE("SoftwareDeploymentStore: refresh counts on unknown deployment is not_found",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.refresh_counts("no-such-id");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error() == "deployment not found");
}

TEST_CASE("SoftwareDeploymentStore: get agent statuses returns all agents",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    for (int i = 1; i <= 5; ++i) {
        AgentDeploymentStatus s;
        s.agent_id = "agent-" + std::to_string(i);
        s.status = (i <= 3) ? "success" : "failed";
        REQUIRE(store.update_agent_status(*dep_id, s).has_value());
    }

    auto statuses = store.get_agent_statuses(*dep_id);
    REQUIRE(statuses.has_value());
    CHECK(statuses->size() == 5);
}

// ── Active count ─────────────────────────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore: active count", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep1 = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep1.has_value());
    auto ac0 = store.active_count();
    REQUIRE(ac0.has_value());
    CHECK(*ac0 == 0);

    REQUIRE(store.start_deployment(*dep1).has_value());
    auto ac1 = store.active_count();
    REQUIRE(ac1.has_value());
    CHECK(*ac1 == 1);

    auto dep2 = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep2.has_value());
    REQUIRE(store.start_deployment(*dep2).has_value());
    auto ac2 = store.active_count();
    REQUIRE(ac2.has_value());
    CHECK(*ac2 == 2);

    REQUIRE(store.cancel_deployment(*dep1).has_value());
    auto ac3 = store.active_count();
    REQUIRE(ac3.has_value());
    CHECK(*ac3 == 1);
}

// ── List deployments ─────────────────────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore: list deployments with status filter",
          "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep1 = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep1.has_value());
    auto dep2 = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep2.has_value());
    REQUIRE(store.start_deployment(*dep2).has_value());

    auto all = store.list_deployments();
    REQUIRE(all.has_value());
    CHECK(all->size() == 2);

    auto staged = store.list_deployments("staged");
    REQUIRE(staged.has_value());
    CHECK(staged->size() == 1);

    auto deploying = store.list_deployments("deploying");
    REQUIRE(deploying.has_value());
    CHECK(deploying->size() == 1);
}

// ── Full lifecycle ───────────────────────────────────────────────────────────

TEST_CASE("SoftwareDeploymentStore: full lifecycle", "[software_deployment][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package("Firefox", "125.0", "windows"));
    REQUIRE(pkg_id.has_value());
    auto pkg = store.get_package(*pkg_id);
    REQUIRE(pkg.has_value());
    REQUIRE(pkg->has_value());
    CHECK((*pkg)->name == "Firefox");

    auto dep_id = store.create_deployment(make_deployment(*pkg_id, "ostype = 'windows'", 3));
    REQUIRE(dep_id.has_value());
    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "staged");

    REQUIRE(store.start_deployment(*dep_id).has_value());
    auto ac = store.active_count();
    REQUIRE(ac.has_value());
    CHECK(*ac == 1);

    dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->status == "deploying");
    CHECK((*dep)->started_at > 0);

    AgentDeploymentStatus s1;
    s1.agent_id = "agent-1";
    s1.status = "success";
    s1.started_at = 100;
    s1.completed_at = 110;
    REQUIRE(store.update_agent_status(*dep_id, s1).has_value());

    AgentDeploymentStatus s2;
    s2.agent_id = "agent-2";
    s2.status = "success";
    s2.started_at = 100;
    s2.completed_at = 115;
    REQUIRE(store.update_agent_status(*dep_id, s2).has_value());

    AgentDeploymentStatus s3;
    s3.agent_id = "agent-3";
    s3.status = "failed";
    s3.error = "installer exit code 1603";
    s3.started_at = 100;
    s3.completed_at = 112;
    REQUIRE(store.update_agent_status(*dep_id, s3).has_value());

    REQUIRE(store.refresh_counts(*dep_id).has_value());

    dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    REQUIRE(dep->has_value());
    CHECK((*dep)->agents_success == 2);
    CHECK((*dep)->agents_failure == 1);

    auto statuses = store.get_agent_statuses(*dep_id);
    REQUIRE(statuses.has_value());
    CHECK(statuses->size() == 3);

    bool found_failed = false;
    for (const auto& a : *statuses) {
        if (a.agent_id == "agent-3") {
            CHECK(a.status == "failed");
            CHECK(a.error == "installer exit code 1603");
            found_failed = true;
        }
    }
    CHECK(found_failed);
}

// ── migrate_from_sqlite backfill contract ───────────────────────────────────

TEST_CASE("SoftwareDeploymentStore::migrate_from_sqlite: no legacy file is idempotent",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto missing =
        yuzu::test::unique_temp_path("yuzu_test_swdep_missing") / "software-deployment.db";
    CHECK(store.migrate_from_sqlite(missing));
    CHECK(store.migrate_from_sqlite(missing)); // second call is a no-op success
}

// Regression test for the anti-pattern DeploymentStore/ADR-0043 closed: a
// sourceless (fileless) boot must never permanently block a LATER boot's
// real legacy data.
TEST_CASE("migrate_from_sqlite: a sourceless boot never blocks a later boot's real legacy data",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto missing_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_sourceless") / "software-deployment.db";
    REQUIRE(store.migrate_from_sqlite(missing_path));

    SoftwarePackage pkg;
    pkg.id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    pkg.name = "HolderApp";
    pkg.created_at = 100;
    auto holder_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_holder") / "software-deployment.db";
    std::filesystem::create_directories(holder_path.parent_path());
    write_legacy_sqlite_db(holder_path, {pkg}, {}, {});

    REQUIRE(store.migrate_from_sqlite(holder_path));

    auto got = store.get_package(pkg.id);
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->name == "HolderApp");
}

TEST_CASE("migrate_from_sqlite copies a populated legacy snapshot across all three tables "
          "exactly once",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    SoftwarePackage pkg;
    pkg.id = "11111111111111111111111111111111";
    pkg.name = "Firefox";
    pkg.version = "125.0";
    pkg.platform = "windows";
    pkg.created_at = 1000;

    SoftwareDeployment dep;
    dep.id = "22222222222222222222222222222222";
    dep.package_id = pkg.id;
    dep.status = "completed";
    dep.created_at = 1001;
    dep.started_at = 1002;
    dep.completed_at = 1003;
    dep.agents_targeted = 1;
    dep.agents_success = 1;

    AgentDeploymentStatus agent;
    agent.deployment_id = dep.id;
    agent.agent_id = "agent-1";
    agent.status = "success";
    agent.started_at = 1002;
    agent.completed_at = 1003;

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_populated") / "software-deployment.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_sqlite_db(legacy_path, {pkg}, {dep}, {agent});

    REQUIRE(store.migrate_from_sqlite(legacy_path));

    auto got_pkg = store.get_package(pkg.id);
    REQUIRE(got_pkg.has_value());
    REQUIRE(got_pkg->has_value());
    CHECK((*got_pkg)->name == "Firefox");

    auto got_dep = store.get_deployment(dep.id);
    REQUIRE(got_dep.has_value());
    REQUIRE(got_dep->has_value());
    CHECK((*got_dep)->status == "completed");

    auto got_agents = store.get_agent_statuses(dep.id);
    REQUIRE(got_agents.has_value());
    REQUIRE(got_agents->size() == 1);
    CHECK((*got_agents)[0].status == "success");

    // Second call against the same populated file is a no-op.
    REQUIRE(store.migrate_from_sqlite(legacy_path));
    auto pkgs = store.list_packages();
    REQUIRE(pkgs.has_value());
    CHECK(pkgs->size() == 1);
}

TEST_CASE("migrate_from_sqlite fails closed on a legacy package row with different content on "
          "an id conflict",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    const std::string shared_id = "33333333333333333333333333333333";
    SoftwarePackage first;
    first.id = shared_id;
    first.name = "Firefox";
    first.created_at = 2000;
    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_pkgconflict_first") /
        "software-deployment.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {first}, {}, {});
    REQUIRE(store.migrate_from_sqlite(first_path));

    SoftwarePackage second = first;
    second.name = "Chrome"; // different content on the SAME id
    auto second_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_pkgconflict_second") /
        "software-deployment.db";
    std::filesystem::create_directories(second_path.parent_path());
    write_legacy_sqlite_db(second_path, {second}, {}, {});

    CHECK_FALSE(store.migrate_from_sqlite(second_path));

    auto got = store.get_package(shared_id);
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->name == "Firefox"); // original survives unchanged

    CHECK_FALSE(store.migrate_from_sqlite(second_path)); // retry fails the same way
}

TEST_CASE("migrate_from_sqlite fails closed when a legacy deployment row's identity differs on "
          "an id conflict",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    SoftwarePackage pkg_a;
    pkg_a.id = "44444444444444444444444444444444";
    pkg_a.name = "PkgA";
    pkg_a.created_at = 3000;
    SoftwarePackage pkg_b;
    pkg_b.id = "55555555555555555555555555555555";
    pkg_b.name = "PkgB";
    pkg_b.created_at = 3000;

    const std::string shared_dep_id = "66666666666666666666666666666666";
    SoftwareDeployment first_dep;
    first_dep.id = shared_dep_id;
    first_dep.package_id = pkg_a.id;
    first_dep.status = "staged";
    first_dep.created_at = 3001;
    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_depconflict_first") /
        "software-deployment.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {pkg_a, pkg_b}, {first_dep}, {});
    REQUIRE(store.migrate_from_sqlite(first_path));

    SoftwareDeployment second_dep = first_dep;
    second_dep.package_id = pkg_b.id; // different IDENTITY (package_id) on the same dep id
    auto second_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_depconflict_second") /
        "software-deployment.db";
    std::filesystem::create_directories(second_path.parent_path());
    write_legacy_sqlite_db(second_path, {pkg_a, pkg_b}, {second_dep}, {});

    CHECK_FALSE(store.migrate_from_sqlite(second_path));

    auto got = store.get_deployment(shared_dep_id);
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->package_id == pkg_a.id); // original survives unchanged
}

// Regression test for the store-specific rank fix (ADR-0051, see
// deployment_lifecycle_rank's doc comment): `completed` is NOT terminal in
// THIS store (rollback_deployment can follow it), unlike DeploymentStore's
// enum. A legacy row that has progressed to `rolled_back` past a Postgres
// value of `completed` must be the ordinary "legacy behind, Postgres
// already progressed further" no-op — NOT misclassified as a terminal
// disagreement the way it would be if `completed` were tied into the
// terminal band.
TEST_CASE("migrate_from_sqlite treats Postgres rolled_back vs a stale legacy completed snapshot "
          "as a benign no-op, not a terminal disagreement",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());
    REQUIRE(store.start_deployment(*dep_id).has_value());
    REQUIRE(store.rollback_deployment(*dep_id).has_value()); // now rolled_back in Postgres

    // A legacy snapshot taken BEFORE the rollback, still showing 'completed'
    // — identity fields must match what create_deployment actually wrote.
    // Includes the referenced package row too (a real legacy file always
    // holds every table together — see write_legacy_sqlite_db's callers
    // elsewhere in this file; the referential-closure check validates
    // within one snapshot, so a snapshot must be internally complete).
    auto current_pkg = store.get_package(*pkg_id);
    REQUIRE(current_pkg.has_value());
    REQUIRE(current_pkg->has_value());
    auto current = store.get_deployment(*dep_id);
    REQUIRE(current.has_value());
    REQUIRE(current->has_value());
    SoftwareDeployment stale_snapshot;
    stale_snapshot.id = *dep_id;
    stale_snapshot.package_id = (*current)->package_id;
    stale_snapshot.scope_expression = (*current)->scope_expression;
    stale_snapshot.created_by = (*current)->created_by;
    stale_snapshot.created_at = (*current)->created_at;
    stale_snapshot.status = "completed";
    stale_snapshot.started_at = 500;
    stale_snapshot.completed_at = 600;

    // Padding row so the fingerprint differs from any earlier pass.
    SoftwareDeployment padding_dep;
    padding_dep.id = "77777777777777777777777777777777";
    padding_dep.package_id = *pkg_id;
    padding_dep.status = "staged";
    padding_dep.created_at = 4000;

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_rank_fix") / "software-deployment.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_sqlite_db(legacy_path, {**current_pkg}, {stale_snapshot, padding_dep}, {});

    std::string captured;
    {
        LogCapture capture;
        CHECK(store.migrate_from_sqlite(legacy_path)); // succeeds — benign no-op, not a failure
        captured = capture.str();
    }
    CHECK(captured.find("already migrated with lifecycle progress") != std::string::npos);

    auto after = store.get_deployment(*dep_id);
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->status == "rolled_back"); // Postgres's live value survives untouched
}

TEST_CASE("migrate_from_sqlite fails closed when a legacy deployment reports a DIFFERENT "
          "terminal outcome than Postgres's current value",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());
    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());
    REQUIRE(store.cancel_deployment(*dep_id).has_value()); // terminal: cancelled

    auto current_pkg = store.get_package(*pkg_id);
    REQUIRE(current_pkg.has_value());
    REQUIRE(current_pkg->has_value());
    auto current = store.get_deployment(*dep_id);
    REQUIRE(current.has_value());
    REQUIRE(current->has_value());
    SoftwareDeployment diverged;
    diverged.id = *dep_id;
    diverged.package_id = (*current)->package_id;
    diverged.scope_expression = (*current)->scope_expression;
    diverged.created_by = (*current)->created_by;
    diverged.created_at = (*current)->created_at;
    diverged.status = "rolled_back"; // different terminal outcome, same rank as cancelled
    diverged.completed_at = 900;

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_terminal_disagree") /
        "software-deployment.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_sqlite_db(legacy_path, {**current_pkg}, {diverged}, {});

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
        captured = capture.str();
    }
    CHECK(captured.find("different terminal outcome") != std::string::npos);

    auto after = store.get_deployment(*dep_id);
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->status == "cancelled"); // untouched
}

TEST_CASE("migrate_from_sqlite fails closed on a legacy deployment with an unrecognised status",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    SoftwarePackage pkg;
    pkg.id = "88888888888888888888888888888888";
    pkg.name = "PkgX";
    pkg.created_at = 5000;
    SoftwareDeployment garbage;
    garbage.id = "99999999999999999999999999999999";
    garbage.package_id = pkg.id;
    garbage.status = "not-a-real-status";
    garbage.created_at = 5001;

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_bad_status") / "software-deployment.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_sqlite_db(legacy_path, {pkg}, {garbage}, {});

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
        captured = capture.str();
    }
    CHECK(captured.find("unrecognised status") != std::string::npos);

    // Nothing landed at all — not even the parent package (fail-closed
    // before any Postgres round trip, same as DeploymentStore).
    auto pkgs = store.list_packages();
    REQUIRE(pkgs.has_value());
    CHECK(pkgs->empty());
}

TEST_CASE("migrate_from_sqlite fails closed on a legacy agent status row with an unrecognised "
          "status",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    SoftwarePackage pkg;
    pkg.id = "aaaabbbbccccddddeeeeffff11112222";
    pkg.name = "PkgY";
    pkg.created_at = 6000;
    SoftwareDeployment dep;
    dep.id = "bbbbccccddddeeeeffff111122223333";
    dep.package_id = pkg.id;
    dep.status = "staged";
    dep.created_at = 6001;
    AgentDeploymentStatus garbage;
    garbage.deployment_id = dep.id;
    garbage.agent_id = "agent-1";
    garbage.status = "teleporting";

    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_swdep_bad_agent_status") /
                       "software-deployment.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_sqlite_db(legacy_path, {pkg}, {dep}, {garbage});

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
        captured = capture.str();
    }
    CHECK(captured.find("unrecognised status") != std::string::npos);

    auto pkgs = store.list_packages();
    REQUIRE(pkgs.has_value());
    CHECK(pkgs->empty());
}

// Regression test for the ADR-0051 referential-closure decision (advisor-
// flagged trap this store adds beyond the DeploymentStore precedent):
// Postgres enforces the package_id FK the legacy SQLite store never did, so
// a wired-era legacy file can hold a genuine orphan deployment. There is no
// valid parent to satisfy the FK with — the whole backfill must fail closed
// rather than crash mid-transaction on a raw FK-violation error or silently
// drop the orphan.
TEST_CASE("migrate_from_sqlite fails closed on a legacy deployment whose package_id has no "
          "matching package in the same snapshot",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    SoftwareDeployment orphan;
    orphan.id = "cccccccccccccccccccccccccccccccc";
    orphan.package_id = "no-such-package-ever-existed";
    orphan.status = "staged";
    orphan.created_at = 7000;

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_orphan_dep") / "software-deployment.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_sqlite_db(legacy_path, {}, {orphan}, {});

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
        captured = capture.str();
    }
    CHECK(captured.find("does not exist in this legacy snapshot") != std::string::npos);

    auto deps = store.list_deployments();
    REQUIRE(deps.has_value());
    CHECK(deps->empty());
    // Retry fails the same way — the marker was never stamped.
    CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
}

TEST_CASE("migrate_from_sqlite fails closed on a legacy agent status row whose deployment_id "
          "has no matching deployment in the same snapshot",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    AgentDeploymentStatus orphan;
    orphan.deployment_id = "no-such-deployment-ever-existed";
    orphan.agent_id = "agent-1";
    orphan.status = "pending";

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_orphan_agent") / "software-deployment.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_sqlite_db(legacy_path, {}, {}, {orphan});

    CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
}

// Regression test for the partial-legacy-schema ADR-0051 decision: the
// pre-migration store's own migration always creates all three tables
// together in one statement, so a real legacy file has all three or none —
// a file with SOME but not all tables present cannot be a genuine
// fresh-install case and must fail closed, not be treated as sourceless.
TEST_CASE("migrate_from_sqlite fails closed on a legacy file with a partial schema",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_partial_schema") / "software-deployment.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    {
        SqliteDb legacy_db;
        REQUIRE(sqlite3_open(legacy_path.string().c_str(), legacy_db.addr()) == SQLITE_OK);
        // Only software_packages — software_deployments/agent_software_status
        // deliberately absent, simulating corruption/hand-editing.
        REQUIRE(sqlite3_exec(legacy_db.get(),
                             "CREATE TABLE software_packages (id TEXT PRIMARY KEY, name TEXT);",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    }

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
        captured = capture.str();
    }
    CHECK(captured.find("missing") != std::string::npos);
}

// Regression test for the governance-round fix (Gate 3/4 BLOCKING, converged
// on independently by 6 reviewers): the ORIGINAL guard only checked this
// direction (software_packages present, others missing) and silently took
// the sourceless branch on the REVERSE — software_packages missing but
// software_deployments/agent_software_status present, holding real data.
// This is the companion direction the fix above must also cover.
TEST_CASE("migrate_from_sqlite fails closed on a legacy file missing ONLY software_packages, "
          "with real deployment data in the other two tables",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_swdep_partial_no_pkg") /
                       "software-deployment.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    {
        SqliteDb legacy_db;
        REQUIRE(sqlite3_open(legacy_path.string().c_str(), legacy_db.addr()) == SQLITE_OK);
        // software_packages deliberately absent — software_deployments and
        // agent_software_status hold real, would-be-lost data.
        REQUIRE(sqlite3_exec(legacy_db.get(),
                             "CREATE TABLE software_deployments (id TEXT PRIMARY KEY, "
                             "package_id TEXT, status TEXT);"
                             "CREATE TABLE agent_software_status (deployment_id TEXT, agent_id "
                             "TEXT, status TEXT, PRIMARY KEY (deployment_id, agent_id));"
                             "INSERT INTO software_deployments (id, package_id, status) VALUES "
                             "('11111111111111111111111111111111', "
                             "'22222222222222222222222222222222', 'deploying');"
                             "INSERT INTO agent_software_status (deployment_id, agent_id, status) "
                             "VALUES ('11111111111111111111111111111111', 'agent-1', "
                             "'installing');",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    }

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
        captured = capture.str();
    }
    // Pre-fix this would have logged "nothing to backfill" (INFO) and
    // returned true, permanently discarding the deployment/agent rows above.
    CHECK(captured.find("nothing to backfill") == std::string::npos);
    CHECK(captured.find("software_packages") != std::string::npos);

    auto deps = store.list_deployments();
    REQUIRE(deps.has_value());
    CHECK(deps->empty()); // nothing landed — refused before any Postgres write
}

// Regression test for the coupled root-cause: fixing the branch above alone
// does not close this. A legacy file that fails ALL THREE table-existence
// probes (corrupt/non-SQLite bytes) must not be treated as "all absent, so
// sourceless" — a probe FAILURE is a distinct, always-fail-closed outcome
// from genuine absence (see LegacyTableStatus in the .cpp). Mirrors
// AuditStore's own reference regression test for the identical defect class
// ("38 bytes of junk is never treated as a fresh install",
// test_audit_store.cpp) — `sqlite3_open_v2(SQLITE_OPEN_READONLY)` succeeds
// lazily on junk bytes; the corruption surfaces only at the first real read.
TEST_CASE("migrate_from_sqlite never treats a corrupt/non-SQLite legacy file as a fresh install",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_corrupt") / "software-deployment.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    {
        std::ofstream f(legacy_path, std::ios::binary);
        f << "not a sqlite database, just some junk bytes";
    }
    REQUIRE(std::filesystem::exists(legacy_path));

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
        captured = capture.str();
    }
    CHECK(captured.find("nothing to backfill") == std::string::npos);
    CHECK(captured.find("probe failed") != std::string::npos);
    CHECK(std::filesystem::exists(legacy_path)); // untouched
}

// Companion control for the fix above: a genuinely ZERO-BYTE legacy file is
// NOT corrupt in the sense the previous test covers — SQLite treats 0 bytes
// as a valid, uninitialized database, so all three probes succeed and
// legitimately report Absent, not Error. This must still take the
// sourceless path — asserting it explicitly guards against an over-eager
// fix that fails closed on every empty/fresh legacy file (chaos-injector's
// Gate 5 "Required control" for this exact scenario).
TEST_CASE("migrate_from_sqlite: a zero-byte legacy file is legitimately sourceless, not corrupt",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_zerobyte") / "software-deployment.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    { std::ofstream f(legacy_path, std::ios::binary); } // 0 bytes
    REQUIRE(std::filesystem::exists(legacy_path));
    REQUIRE(std::filesystem::file_size(legacy_path) == 0);

    CHECK(store.migrate_from_sqlite(legacy_path));
}

TEST_CASE("SoftwareDeploymentStore::migrate_from_sqlite aborts unstamped on a mid-scan legacy "
          "read failure",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_truncated") / "software-deployment.db";
    std::filesystem::create_directories(legacy_path.parent_path());

    std::vector<SoftwarePackage> bulk;
    for (int i = 0; i < 3000; ++i) {
        SoftwarePackage p;
        char idbuf[33];
        std::snprintf(idbuf, sizeof(idbuf), "%032x", i + 1);
        p.id = idbuf;
        p.name = "bulk-pkg-" + std::to_string(i) + "-padding-for-size-xxxxxxxxxxxxxxxxxxxxx";
        p.created_at = 1000 + i;
        bulk.push_back(p);
    }
    write_legacy_sqlite_db(legacy_path, bulk, {}, {});

    auto full_size = std::filesystem::file_size(legacy_path);
    REQUIRE(full_size > 65536); // sanity: spans many SQLite pages

    // Corrupt a LATER region in place (same file length — see
    // test_deployment_store.cpp's identical technique and rationale: a
    // truncation trips SQLite's page-count check at prepare time uniformly,
    // which does not exercise the mid-scan step_rc != SQLITE_DONE guard).
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
    CHECK(captured.find("software_packages scan aborted mid-read") != std::string::npos);

    auto pkgs = store.list_packages();
    REQUIRE(pkgs.has_value());
    CHECK(pkgs->empty());

    // A subsequent pass against a freshly-written, intact file succeeds —
    // proving the aborted pass never stamped the marker.
    auto intact_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_intact") / "software-deployment.db";
    std::filesystem::create_directories(intact_path.parent_path());
    write_legacy_sqlite_db(intact_path, {bulk.front()}, {}, {});
    REQUIRE(store.migrate_from_sqlite(intact_path));

    auto pkgs2 = store.list_packages();
    REQUIRE(pkgs2.has_value());
    CHECK(pkgs2->size() == 1);
}

// Reproduces (and proves fixed) the torn cross-table read a code-review
// adversarial pass found in migrate_from_sqlite: before the enclosing
// snapshot transaction was added, each of the three per-table reads was its
// own separate autocommit transaction, so a concurrent writer could commit a
// change in the GAP between them -- e.g. atomically replacing a package
// (delete old id, insert new id, repoint the deployment) between the
// packages-read and the deployments-read, leaving the migrated snapshot with
// a deployment pointing at a package that was never captured.
//
// The writer thread below busy-retries a fast-failing (busy_timeout=0)
// BEGIN IMMEDIATE throughout migrate_from_sqlite's run, doing one atomic
// package-replace-and-repoint the instant it gets a window. 10,000 padding
// packages (measured: ~2-3ms to scan on this hardware, vs. microsecond-scale
// thread start-up) give it a comfortably wide, reliable target -- but the
// test's CORRECTNESS does not depend on hitting an exact window. Whether the
// writer's swap lands before, during, or after migrate_from_sqlite's read
// phase, the ONLY property this test asserts is the one that actually
// matters: the migrated snapshot is self-consistent (its deployment's
// package_id resolves to a package that was itself backfilled). A torn
// cross-table read is exactly the scenario where that property fails despite
// referential closure appearing to hold -- see migrate_from_sqlite's own
// header comment on this file. (Asserting "the writer never succeeds mid-run"
// would be the wrong, and non-portable, invariant: SQLite's default
// rollback-journal locking already makes the writer's FIRST attempt likely
// to win outright before migrate_from_sqlite's own BEGIN, on a fast box --
// that is a benign race for who-gets-there-first, not evidence of a torn
// read, so this test does not assert on it.)
TEST_CASE("SoftwareDeploymentStore::migrate_from_sqlite reads one consistent cross-table "
          "snapshot under a concurrent writer (no torn read)",
          "[software_deployment][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, sw_deploy_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SoftwareDeploymentStore store{pool};
    REQUIRE(store.is_open());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_swdep_torn") / "software-deployment.db";
    std::filesystem::create_directories(legacy_path.parent_path());

    std::vector<SoftwarePackage> bulk;
    SoftwarePackage pkg_old = make_package("Original");
    pkg_old.id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    pkg_old.created_at = 9999999; // sorts LAST -- read-1 reaches it only after all padding rows

    SoftwareDeployment dep = make_deployment(pkg_old.id);
    dep.id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    dep.status = "staged";
    dep.created_at = 1;

    write_legacy_sqlite_db(legacy_path, {pkg_old}, {dep}, {});

    // Bulk-pad AFTER write_legacy_sqlite_db (which deliberately does one
    // fsync'd autocommit transaction per row, to mirror a real legacy
    // process's own writes elsewhere in this file's other tests) -- wrapped
    // in a single transaction here purely for setup speed, since this
    // padding's only job is to widen the read-side race window below, not
    // to exercise the write path itself. Kept small (10,000, not the
    // 50,000+ some other tests in this file use) because every one of these
    // rows also gets individually round-tripped into Postgres once
    // migrate_from_sqlite's own backfill runs -- padding wide enough for the
    // SQLite-side race, not wider than that.
    {
        SqliteDb padder;
        REQUIRE(sqlite3_open(legacy_path.string().c_str(), padder.addr()) == SQLITE_OK);
        REQUIRE(sqlite3_exec(padder.get(), "BEGIN", nullptr, nullptr, nullptr) == SQLITE_OK);
        SqliteStmt s;
        REQUIRE(sqlite3_prepare_v2(padder.get(),
                                   "INSERT INTO software_packages (id, name, created_at) "
                                   "VALUES (?, ?, ?)",
                                   -1, s.addr(), nullptr) == SQLITE_OK);
        for (int i = 0; i < 10000; ++i) {
            char idbuf[33];
            std::snprintf(idbuf, sizeof(idbuf), "%032x", i + 1);
            std::string name =
                "bulk-pkg-" + std::to_string(i) + "-padding-for-size-xxxxxxxxxxxxxxxxxxxxx";
            sqlite3_bind_text(s.get(), 1, idbuf, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 2, name.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(s.get(), 3, 1000 + i);
            REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
            sqlite3_reset(s.get());
        }
        REQUIRE(sqlite3_exec(padder.get(), "COMMIT", nullptr, nullptr, nullptr) == SQLITE_OK);
    }

    const std::string pkg_new_id = "cccccccccccccccccccccccccccccccc";

    std::atomic<bool> migrate_done{false};
    std::atomic<bool> writer_landed_mid_migrate{false};
    std::thread writer([&] {
        SqliteDb w;
        REQUIRE(sqlite3_open(legacy_path.string().c_str(), w.addr()) == SQLITE_OK);
        sqlite3_busy_timeout(w.get(), 0); // fail fast; we retry ourselves, never block the reader
        while (!migrate_done.load(std::memory_order_acquire)) {
            if (sqlite3_exec(w.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK)
                continue; // lock held by the reader's transaction -- retry
            bool ok = true;
            {
                SqliteStmt s;
                ok = ok &&
                     sqlite3_prepare_v2(w.get(), "DELETE FROM software_packages WHERE id=?", -1,
                                        s.addr(), nullptr) == SQLITE_OK;
                if (ok) {
                    sqlite3_bind_text(s.get(), 1, pkg_old.id.c_str(), -1, SQLITE_TRANSIENT);
                    ok = sqlite3_step(s.get()) == SQLITE_DONE;
                }
            }
            {
                SqliteStmt s;
                ok = ok && sqlite3_prepare_v2(w.get(),
                                              "INSERT INTO software_packages (id, name, "
                                              "created_at) VALUES (?, 'Replacement', 999999)",
                                              -1, s.addr(), nullptr) == SQLITE_OK;
                if (ok) {
                    sqlite3_bind_text(s.get(), 1, pkg_new_id.c_str(), -1, SQLITE_TRANSIENT);
                    ok = sqlite3_step(s.get()) == SQLITE_DONE;
                }
            }
            {
                SqliteStmt s;
                ok = ok && sqlite3_prepare_v2(
                               w.get(), "UPDATE software_deployments SET package_id=? WHERE id=?",
                               -1, s.addr(), nullptr) == SQLITE_OK;
                if (ok) {
                    sqlite3_bind_text(s.get(), 1, pkg_new_id.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_text(s.get(), 2, dep.id.c_str(), -1, SQLITE_TRANSIENT);
                    ok = sqlite3_step(s.get()) == SQLITE_DONE;
                }
            }
            if (ok && sqlite3_exec(w.get(), "COMMIT", nullptr, nullptr, nullptr) == SQLITE_OK) {
                if (!migrate_done.load(std::memory_order_acquire))
                    writer_landed_mid_migrate = true;
                return; // one successful swap is all this test needs
            }
            sqlite3_exec(w.get(), "ROLLBACK", nullptr, nullptr, nullptr);
        }
    });

    std::string captured;
    bool migrated;
    {
        LogCapture capture;
        migrated = store.migrate_from_sqlite(legacy_path);
        captured = capture.str();
    }
    migrate_done.store(true, std::memory_order_release);
    writer.join();

    INFO("writer's swap landed while migrate_from_sqlite was still running: "
         << (writer_landed_mid_migrate.load() ? "yes" : "no (benign -- see comment above)"));
    if (!migrated)
        UNSCOPED_INFO("migrate_from_sqlite log: " << captured);
    REQUIRE(migrated);

    auto got_dep = store.get_deployment(dep.id);
    REQUIRE(got_dep.has_value());
    REQUIRE(got_dep->has_value());
    // Whichever package the migrated snapshot captured, it must actually be
    // one that was itself backfilled -- never a torn reference to a package
    // version the migration never saw. This is the property that fails on a
    // torn cross-table read despite referential closure appearing to hold.
    auto got_pkg = store.get_package((*got_dep)->package_id);
    REQUIRE(got_pkg.has_value());
    CHECK(got_pkg->has_value());
}
