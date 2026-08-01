/**
 * test_audit_store.cpp — Unit tests for AuditStore (PostgreSQL, ADR-0040)
 *
 * Covers: logging (fail-hard), querying + filters + action-prefix scoping +
 * random-sample, degrade-distinguishable reads, the mandatory SQLite→PG backfill
 * (idempotent/resumable/reconciled/fail-closed), and the retention clock guard
 * (#2360) ported to a single-sweeper advisory lease with durable dedup.
 *
 * PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when it is set but
 * broken. Store-behaviour tests use a pre-migrated template clone; backfill /
 * fresh-DB tests use plain YUZU_REQUIRE_PG_DB.
 */

#include "audit_store.hpp"
#include "audit_retention_rules.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <sqlite3.h>

#include <cstdint>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template: every store-behaviour test clones this schema.
yuzu::test::PgTestTemplate auditstore_tpl{"auditstore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("auditstore template: store failed to migrate");
}};

void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

std::string query_scalar(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
    if (PQntuples(r.get()) == 0)
        return "";
    return PQgetvalue(r.get(), 0, 0);
}

AuditEvent mk(const std::string& principal, const std::string& action,
              const std::string& result = "success") {
    AuditEvent e;
    e.principal = principal;
    e.principal_role = "admin";
    e.action = action;
    e.result = result;
    return e;
}

// ── Retention-guard fixtures ────────────────────────────────────────────────
constexpr int kGuardRetentionDays = 1;
constexpr std::int64_t kWindow = static_cast<std::int64_t>(kGuardRetentionDays) * 86400;
constexpr std::int64_t kNow = 1'700'000'000;

// Seed `count` rows all carrying the same ttl_expires_at (and timestamp), via a
// second connection, so a test can place rows at a chosen distance from the
// `now` it passes to cleanup_once().
void seed_rows_with_ttl(const std::string& dsn, std::int64_t ttl, int count) {
    exec_sql(dsn, "INSERT INTO audit_store.audit_events (timestamp, principal, principal_role, "
                  "action, result, ttl_expires_at) SELECT " +
                      std::to_string(ttl) + ", 'admin', 'admin', 'auth.login', 'success', " +
                      std::to_string(ttl) + " FROM generate_series(1, " + std::to_string(count) +
                      ")");
}

std::int64_t row_count(const std::string& dsn) {
    return std::stoll(query_scalar(dsn, "SELECT COUNT(*) FROM audit_store.audit_events"));
}

// ── Legacy SQLite audit.db builder for the backfill tests ────────────────────
// Writes the production v3 SQLite schema (all three legacy migrations collapsed)
// and `count` rows, so migrate_from_sqlite has a realistic source.
void build_legacy_audit_db(const std::filesystem::path& path, int count,
                           bool with_principal_class = true, bool with_meta = true) {
    // TempDir computes a unique path but does NOT create the directory.
    std::filesystem::create_directories(path.parent_path());
    SqliteDb db;
    REQUIRE(sqlite3_open(path.string().c_str(), db.addr()) == SQLITE_OK);
    const char* schema =
        "CREATE TABLE audit_events ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, principal TEXT NOT NULL,"
        " principal_role TEXT NOT NULL, action TEXT NOT NULL, target_type TEXT, target_id TEXT,"
        " detail TEXT, source_ip TEXT, user_agent TEXT, session_id TEXT, result TEXT NOT NULL,"
        " ttl_expires_at INTEGER DEFAULT 0);";
    REQUIRE(sqlite3_exec(db.get(), schema, nullptr, nullptr, nullptr) == SQLITE_OK);
    if (with_principal_class)
        REQUIRE(sqlite3_exec(db.get(),
                             "ALTER TABLE audit_events ADD COLUMN principal_class TEXT NOT NULL "
                             "DEFAULT '';",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    if (with_meta)
        REQUIRE(sqlite3_exec(db.get(),
                             "CREATE TABLE audit_retention_meta (key TEXT PRIMARY KEY, value "
                             "INTEGER NOT NULL);",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    REQUIRE(sqlite3_exec(db.get(), "BEGIN", nullptr, nullptr, nullptr) == SQLITE_OK);
    SqliteStmt stmt;
    const char* ins =
        with_principal_class
            ? "INSERT INTO audit_events (timestamp, principal, principal_role, action, detail, "
              "result, ttl_expires_at, principal_class) VALUES (?,?,?,?,?,?,?,?)"
            : "INSERT INTO audit_events (timestamp, principal, principal_role, action, detail, "
              "result, ttl_expires_at) VALUES (?,?,?,?,?,?,?)";
    REQUIRE(sqlite3_prepare_v2(db.get(), ins, -1, stmt.addr(), nullptr) == SQLITE_OK);
    for (int i = 0; i < count; ++i) {
        sqlite3_reset(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, 1000 + i);
        sqlite3_bind_text(stmt.get(), 2, "admin", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 3, "admin", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, "auth.login", -1, SQLITE_STATIC);
        const std::string detail = "legacy-" + std::to_string(i);
        sqlite3_bind_text(stmt.get(), 5, detail.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 6, "success", -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt.get(), 7, 0);
        if (with_principal_class)
            sqlite3_bind_text(stmt.get(), 8, "human", -1, SQLITE_STATIC);
        REQUIRE(sqlite3_step(stmt.get()) == SQLITE_DONE);
    }
    stmt.reset();
    if (with_meta)
        REQUIRE(sqlite3_exec(db.get(),
                             "INSERT INTO audit_retention_meta (key, value) VALUES "
                             "('last_pass_now', 1699000000);",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    REQUIRE(sqlite3_exec(db.get(), "COMMIT", nullptr, nullptr, nullptr) == SQLITE_OK);
}

} // namespace

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("AuditStore: open against a fresh template clone", "[pg][audit_store][db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
}

TEST_CASE("AuditStore: bad-path constructor (unroutable DSN) is closed and fails hard/degrades",
          "[audit_store]") {
    PgPool bad{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    AuditStore store(bad);
    REQUIRE_FALSE(store.is_open());
    // Write fails hard (false); reads degrade to nullopt — never a false-empty.
    CHECK_FALSE(store.log(mk("admin", "auth.login")));
    CHECK(store.emit_failed_count() == 1);
    CHECK_FALSE(store.query().has_value());
    CHECK_FALSE(store.total_count().has_value());
}

// ── Logging + queries ───────────────────────────────────────────────────────

TEST_CASE("AuditStore: log and retrieve", "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());

    AuditEvent e = mk("admin", "auth.login");
    e.source_ip = "192.168.1.1";
    CHECK(store.log(e));

    auto results = store.query();
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].principal == "admin");
    CHECK((*results)[0].action == "auth.login");
    CHECK((*results)[0].result == "success");
    CHECK((*results)[0].source_ip == "192.168.1.1");
}

TEST_CASE("AuditStore: filter by principal / action / target", "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);

    for (const auto& u : {"admin", "admin", "viewer"})
        CHECK(store.log(mk(u, "auth.login")));
    AuditEvent tgt = mk("admin", "agent.approve");
    tgt.target_type = "agent";
    tgt.target_id = "agent-001";
    CHECK(store.log(tgt));

    AuditQuery byp;
    byp.principal = "admin";
    auto rp = store.query(byp);
    REQUIRE(rp.has_value());
    CHECK(rp->size() == 3); // 2 logins + 1 approve

    AuditQuery bya;
    bya.action = "agent.approve";
    auto ra = store.query(bya);
    REQUIRE(ra.has_value());
    REQUIRE(ra->size() == 1);

    AuditQuery byt;
    byt.target_type = "agent";
    byt.target_id = "agent-001";
    auto rt = store.query(byt);
    REQUIRE(rt.has_value());
    REQUIRE(rt->size() == 1);
}

TEST_CASE("AuditStore: timestamp ordering, limit/offset, total_count", "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);

    for (int i = 0; i < 10; ++i) {
        AuditEvent e = mk("admin", "test");
        e.timestamp = 100 + i * 10;
        CHECK(store.log(e));
    }
    auto all = store.query();
    REQUIRE(all.has_value());
    REQUIRE(all->size() == 10);
    CHECK((*all)[0].timestamp >= (*all)[1].timestamp); // newest first

    AuditQuery q;
    q.limit = 3;
    auto p1 = store.query(q);
    REQUIRE(p1.has_value());
    REQUIRE(p1->size() == 3);
    q.offset = 3;
    auto p2 = store.query(q);
    REQUIRE(p2.has_value());
    REQUIRE(p2->size() == 3);
    CHECK((*p1)[0].timestamp != (*p2)[0].timestamp);

    auto total = store.total_count();
    REQUIRE(total.has_value());
    CHECK(*total == 10);
}

TEST_CASE("AuditStore: all fields stored; principal_class round-trips and defaults honest-empty",
          "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);

    AuditEvent e = mk("admin", "setting.update");
    e.target_type = "setting";
    e.target_id = "tls_enabled";
    e.detail = "changed to true";
    e.source_ip = "10.0.0.1";
    e.user_agent = "Mozilla/5.0";
    e.session_id = "sess-abc";
    e.principal_class = "human";
    CHECK(store.log(e));
    // A server-internal writer that leaves principal_class unset → honest-empty.
    CHECK(store.log(mk("system", "cert.reload")));

    AuditQuery q;
    q.action = "setting.update";
    auto r = store.query(q);
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 1);
    CHECK((*r)[0].target_id == "tls_enabled");
    CHECK((*r)[0].detail == "changed to true");
    CHECK((*r)[0].user_agent == "Mozilla/5.0");
    CHECK((*r)[0].session_id == "sess-abc");
    CHECK((*r)[0].principal_class == "human");

    AuditQuery q2;
    q2.action = "cert.reload";
    auto r2 = store.query(q2);
    REQUIRE(r2.has_value());
    REQUIRE(r2->size() == 1);
    CHECK((*r2)[0].principal_class.empty());
}

TEST_CASE("AuditStore: time range filter", "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    for (int64_t ts : {100, 200, 300, 400, 500}) {
        AuditEvent e = mk("admin", "test");
        e.timestamp = ts;
        CHECK(store.log(e));
    }
    AuditQuery q;
    q.since = 200;
    q.until = 400;
    auto r = store.query(q);
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 3);
}

TEST_CASE("AuditStore: non-UTF-8 / embedded-NUL free text is defanged, the write still lands",
          "[pg][audit_store]") {
    // FAIL-HARD write must never be taken down by a hostile/mis-encoded byte —
    // sanitize_pg_text scrubs it to U+FFFD so a real audit event still surfaces.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    AuditEvent e = mk("admin", "auth.login");
    e.detail = std::string("bad\xff\xfe") + '\0' + "tail"; // invalid UTF-8 + embedded NUL
    e.source_ip = std::string("1.2.3.4\xc0");
    CHECK(store.log(e));
    auto r = store.query();
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 1);
    // The whole value survived (nothing truncated at the NUL) and no raw NUL
    // remains.
    CHECK((*r)[0].detail.find("tail") != std::string::npos);
    CHECK((*r)[0].detail.find('\0') == std::string::npos);
}

// ── #4: action-prefix scoping + random-sample ────────────────────────────────

TEST_CASE("AuditStore: action_prefixes scopes to the auth surface",
          "[pg][audit_store][auth-sample]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    for (const auto& a : {"auth.login", "auth.login_failed", "mfa.step_up.passed",
                          "session.revoke_all", "instruction.execute", "ca.cert.issued"})
        CHECK(store.log(mk("admin", a)));

    AuditQuery q;
    q.action_prefixes = {"auth.", "mfa.", "session."};
    auto r = store.query(q);
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 4);
    for (const auto& e : *r) {
        const bool scoped = e.action.rfind("auth.", 0) == 0 || e.action.rfind("mfa.", 0) == 0 ||
                            e.action.rfind("session.", 0) == 0;
        CHECK(scoped);
    }
}

TEST_CASE("AuditStore: wildcard-bearing / all-empty prefixes fail closed (M-2)",
          "[pg][audit_store][auth-sample]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    CHECK(store.log(mk("admin", "auth.login")));
    CHECK(store.log(mk("admin", "instruction.execute")));

    // A smuggled LIKE wildcard must NOT widen to all actions — dropped → empty.
    AuditQuery q;
    q.action_prefixes = {"%"};
    auto r = store.query(q);
    REQUIRE(r.has_value());
    CHECK(r->empty());

    // Valid prefix alongside a wildcard one: only the valid prefix applies.
    AuditQuery q2;
    q2.action_prefixes = {"auth.", "ins%"};
    auto r2 = store.query(q2);
    REQUIRE(r2.has_value());
    REQUIRE(r2->size() == 1);
    CHECK((*r2)[0].action == "auth.login");

    // Degenerate all-empty filter must not widen.
    AuditQuery q3;
    q3.action_prefixes = {"", ""};
    auto r3 = store.query(q3);
    REQUIRE(r3.has_value());
    CHECK(r3->empty());
}

TEST_CASE("AuditStore: random_sample over the scan cap is recency-capped + bounded by limit",
          "[pg][audit_store][auth-sample][slow]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    const int n = static_cast<int>(kAuditSampleScanCap) + 250;
    // Bulk-seed in-window auth events with ascending timestamps.
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_events (timestamp, principal, principal_role, "
                       "action, result, ttl_expires_at) SELECT 1000 + g, 'admin','admin',"
                       "'auth.login','success',0 FROM generate_series(1," +
                           std::to_string(n) + ") g");

    AuditQuery q;
    q.action_prefixes = {"auth."};
    q.random_sample = true;
    q.limit = 25;
    std::size_t pool_size = 0;
    auto r = store.query(q, &pool_size);
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 25);                // bounded by limit
    CHECK(pool_size == kAuditSampleScanCap); // pool hit the cap (recency-biased)
    for (const auto& e : *r)
        CHECK(e.timestamp >=
              static_cast<int64_t>(1000 + n - static_cast<int>(kAuditSampleScanCap)));
}

// ── Mandatory backfill (ADR-0009 / ADR-0040) ─────────────────────────────────

TEST_CASE("AuditStore: backfill streams the legacy audit.db and reconciles",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf_"}};
    auto legacy = dir.path / "audit.db";
    build_legacy_audit_db(legacy, /*count=*/2500); // spans two backfill batches

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.migrate_from_sqlite(legacy));

    CHECK(row_count(db.dsn()) == 2500);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_events WHERE "
                                 "principal_class = 'human'") == "2500");
    CHECK(query_scalar(db.dsn(), "SELECT value FROM audit_store.audit_retention_meta WHERE key = "
                                 "'last_pass_now'") == "1699000000");
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'backfill_complete'") == "1");
    CHECK_FALSE(std::filesystem::exists(legacy)); // moved aside

    // A live log() must NOT collide with a backfilled id (sequence advanced).
    CHECK(store.log(mk("admin", "post.backfill")));
    CHECK(row_count(db.dsn()) == 2501);
}

TEST_CASE("AuditStore: backfill is idempotent (second call is a no-op)",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf2_"}};
    auto legacy = dir.path / "audit.db";
    build_legacy_audit_db(legacy, /*count=*/10);

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.migrate_from_sqlite(legacy));
    CHECK(row_count(db.dsn()) == 10);
    // Second call short-circuits on the marker (the legacy file is already gone).
    REQUIRE(store.migrate_from_sqlite(legacy));
    CHECK(row_count(db.dsn()) == 10);
}

TEST_CASE("AuditStore: backfill resumes from MAX(id) after a partial run",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf3_"}};
    auto legacy = dir.path / "audit.db";
    build_legacy_audit_db(legacy, /*count=*/50);

    // Simulate a crash mid-backfill: pre-insert the first 20 legacy rows (ids
    // 1..20) into PG with explicit ids, no marker.
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_events (id, timestamp, principal, "
                       "principal_role, action, result, ttl_expires_at) OVERRIDING SYSTEM VALUE "
                       "SELECT g, 1000+g, 'admin','admin','auth.login','success',0 FROM "
                       "generate_series(1,20) g");

    REQUIRE(store.migrate_from_sqlite(legacy));
    // All 50 present exactly once (ON CONFLICT (id) DO NOTHING — no duplicates).
    CHECK(row_count(db.dsn()) == 50);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(DISTINCT id) FROM audit_store.audit_events") == "50");
}

TEST_CASE("AuditStore: backfill on a fresh install (no legacy) marks complete",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.migrate_from_sqlite("/nonexistent-yuzu-test/audit.db"));
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'backfill_complete'") == "1");
}

TEST_CASE("AuditStore: backfill handles a legacy DB without the principal_class column",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf4_"}};
    auto legacy = dir.path / "audit.db";
    build_legacy_audit_db(legacy, /*count=*/5, /*with_principal_class=*/false,
                          /*with_meta=*/false);

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.migrate_from_sqlite(legacy));
    CHECK(row_count(db.dsn()) == 5);
    CHECK(query_scalar(db.dsn(),
                       "SELECT COUNT(*) FROM audit_store.audit_events WHERE principal_class = ''") ==
          "5");
}

// ── #2360: retention clock guard (single-sweeper advisory lease) ─────────────

TEST_CASE("AuditStore #2360: a first pass that would wipe every datable row declines once, "
          "then drains",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());
    seed_rows_with_ttl(db.dsn(), kNow - 100, 10); // every row already expired

    CHECK(store.cleanup_once(kNow) == 0); // declines (would_wipe)
    CHECK(row_count(db.dsn()) == 10);
    CHECK(store.clock_anomaly_skips_count() == 1);
    CHECK(store.cleanup_failed_count() == 0);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'last_anomaly_facts'") == "1");

    // Identical next pass: suppressed repeat → drains, capped.
    CHECK(store.cleanup_once(kNow + 1) == 10);
    CHECK(row_count(db.dsn()) == 0);
    CHECK(store.clock_anomaly_skips_count() == 1); // not counted twice
    CHECK(store.rows_deleted_count() == 10);

    // A clean pass clears the durable anomaly fact set.
    CHECK(store.cleanup_once(kNow + 2) == 0);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'last_anomaly_facts'") == "0");
}

TEST_CASE("AuditStore #2360: a datable survivor means no wipe, so the pass deletes immediately",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    seed_rows_with_ttl(db.dsn(), kNow - 100, 10);    // expired
    seed_rows_with_ttl(db.dsn(), kNow + kWindow, 1); // healthy survivor

    CHECK(store.cleanup_once(kNow) == 10);
    CHECK(row_count(db.dsn()) == 1);
    CHECK(store.clock_anomaly_skips_count() == 0);
}

TEST_CASE("AuditStore #2360: one forward-skew far-future row cannot disarm the guard",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    seed_rows_with_ttl(db.dsn(), kNow - 100, 10);
    seed_rows_with_ttl(db.dsn(), kNow + kWindow + kAuditTtlFutureSlackSec + 1000, 1); // implausible

    CHECK(store.cleanup_once(kNow) == 0); // still declines — far-future row is not a survivor
    CHECK(row_count(db.dsn()) == 11);
    CHECK(store.clock_anomaly_skips_count() == 1);
}

TEST_CASE("AuditStore #2360: the per-pass cap paces a large expiry and reports a backlog",
          "[pg][audit_store][retention][clock-guard][slow]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    constexpr int kSurplus = 7;
    seed_rows_with_ttl(db.dsn(), kNow - 100, static_cast<int>(kMaxAuditDeletesPerPass) + kSurplus);
    seed_rows_with_ttl(db.dsn(), kNow + kWindow, 1); // survivor → not a would_wipe

    CHECK(store.cleanup_once(kNow) == kMaxAuditDeletesPerPass);
    CHECK(store.cap_reached_count() == 1);
    CHECK(store.rows_deleted_count() == kMaxAuditDeletesPerPass);
    CHECK(store.clock_anomaly_skips_count() == 0); // an over-cap backlog is NOT an anomaly

    // The pass that clears the backlog does NOT count as cap-reached.
    CHECK(store.cleanup_once(kNow + 1) == kSurplus);
    CHECK(store.cap_reached_count() == 1);
    CHECK(row_count(db.dsn()) == 1);
}

TEST_CASE("AuditStore #2360: the clock-step guard survives a restart via durable meta",
          "[pg][audit_store][retention][clock-guard]") {
    // The elapsed-time step is the only detector that survives a write landing
    // after the jump. Held in memory it would compare against nothing on the
    // first pass of a new process; the durable last_pass_now closes that.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    {
        AuditStore first(pool, kGuardRetentionDays, 0);
        REQUIRE(first.is_open());
        seed_rows_with_ttl(db.dsn(), kNow - 100, 5);
        seed_rows_with_ttl(db.dsn(), kNow + kWindow, 1); // survivor: no would_wipe
        REQUIRE(first.cleanup_once(kNow) == 5);
        REQUIRE(first.clock_anomaly_skips_count() == 0);
    }
    // A fresh store (new process) over the same DB. The clock is now more than a
    // whole retention window ahead and a write has landed at the new time, so the
    // outcome test alone sees nothing wrong — only the durable step catches it.
    AuditStore second(pool, kGuardRetentionDays, 0);
    REQUIRE(second.is_open());
    const std::int64_t jumped = kNow + kAuditMinBigStepSec + 1;
    seed_rows_with_ttl(db.dsn(), kNow + 10, 5);     // expired at the new reading
    seed_rows_with_ttl(db.dsn(), jumped + 3600, 1); // survivor at the new reading
    CHECK(second.cleanup_once(jumped) == 0);
    CHECK(second.clock_anomaly_skips_count() == 1);
}

TEST_CASE("AuditStore #2360: a closed store counts a failed pass, not silence",
          "[audit_store][retention][clock-guard]") {
    PgPool bad{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    AuditStore store(bad, kGuardRetentionDays, 0);
    REQUIRE_FALSE(store.is_open());
    CHECK(store.cleanup_once(kNow) == 0);
    CHECK(store.cleanup_failed_count() == 1);
    CHECK(store.clock_anomaly_skips_count() == 0);
    CHECK(store.retention_passes_count() == 1); // liveness still moves
}

TEST_CASE("AuditStore #2360: an implausible caller clock is refused before any arithmetic",
          "[audit_store][retention][clock-guard]") {
    PgPool bad{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    AuditStore store(bad, kGuardRetentionDays, 0);
    const std::int64_t huge = std::numeric_limits<std::int64_t>::max() / 2;
    CHECK(store.cleanup_once(huge) == 0);
    CHECK(store.cleanup_failed_count() == 1);
    CHECK(store.retention_passes_count() == 1);
    CHECK(store.last_pass_unixtime() == 0); // a refused reading is NOT stamped
}

TEST_CASE("AuditStore #2360: a sibling holding the advisory lease skips the pass quietly",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    seed_rows_with_ttl(db.dsn(), kNow - 100, 5);
    seed_rows_with_ttl(db.dsn(), kNow + kWindow, 1); // a survivor: a lone pass WOULD delete

    // Hold the fleet-wide reap lease on a separate connection's open txn.
    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    PgResult begin{PQexec(locker.get(), "BEGIN")};
    REQUIRE(begin.ok());
    PgResult lk{PQexec(locker.get(),
                       "SELECT pg_advisory_xact_lock(hashtextextended('audit_store:reap', 0))")};
    REQUIRE(lk.ok());

    CHECK(store.cleanup_once(kNow) == 0);     // skipped — lease held elsewhere
    CHECK(row_count(db.dsn()) == 6);          // nothing deleted
    CHECK(store.cleanup_failed_count() == 0); // a skip is NOT a failure
    CHECK(store.clock_anomaly_skips_count() == 0);

    PgResult rollback{PQexec(locker.get(), "ROLLBACK")};
    REQUIRE(rollback.ok());
}

TEST_CASE("AuditStore #2360: classify pins the anomaly precedence with no database",
          "[audit_store][retention][clock-guard]") {
    using namespace yuzu::server::audit_retention;
    CHECK(classify({.has_expired = true, .would_wipe = true, .big_step = false,
                    .prev_unusable = false}) == Anomaly::Wipe);
    CHECK(classify({.has_expired = true, .would_wipe = true, .big_step = true,
                    .prev_unusable = false}) == Anomaly::Step); // Step outranks Wipe
    CHECK(classify({.has_expired = true, .would_wipe = true, .big_step = true,
                    .prev_unusable = true}) == Anomaly::BadState); // BadState outranks all
    CHECK(classify({.has_expired = false, .would_wipe = false, .big_step = false,
                    .prev_unusable = false}) == Anomaly::None);
}
