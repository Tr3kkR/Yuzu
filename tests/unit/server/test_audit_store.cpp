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

#include <yuzu/metrics.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <sqlite3.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
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

/// Put a store in the state of one that has already completed a pass, so the
/// bootstrap trigger (#2579) does not fire.
///
/// Needed because #2579 makes "no stored reading, and rows already expired" a
/// decline in its own right. Almost every guard test here is about something
/// else -- the cap, the dedup rule, one specific trigger -- and each would
/// otherwise spend its first pass absorbing a bootstrap decline it never meant
/// to exercise. This states the precondition those tests always assumed
/// implicitly; the ones that ARE about the bootstrap do not call it.
///
/// A pass over an EMPTY table is the whole mechanism, and it is exact rather
/// than approximate: `cleanup_once` anchors the reading and settles the marker
/// before it probes, and with nothing expired the rule short-circuits to `None`,
/// so no counter moves, nothing is deleted and no anomaly is recorded. Call it
/// BEFORE seeding. The default is an hour back, comfortably inside the 7-day
/// step threshold, so it cannot itself provoke a `Step`.
void anchor_guard(AuditStore& store, std::int64_t last_pass_now = kNow - 3600) {
    REQUIRE(store.cleanup_once(last_pass_now) == 0);
    REQUIRE(store.clock_anomaly_skips_count() == 0);
    REQUIRE(store.bootstrap_declines_count() == 0);
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

TEST_CASE("AuditStore::sanitized_detail is idempotent and leaves an empty detail alone",
          "[audit_store][secret]") {
    // Rows written after the writer fix already hold the placeholder; applying the
    // read-time rule again must not double-wrap or invent content.
    CHECK(AuditStore::sanitized_detail("RuntimeConfig", "oidc_client_secret",
                                       "value=<redacted>") == "value=<redacted>");
    CHECK(AuditStore::sanitized_detail("RuntimeConfig", "oidc_client_secret", "").empty());
    CHECK(AuditStore::sanitized_detail("RuntimeConfig", "oidc_issuer", "value=https://idp") ==
          "value=https://idp");
    // No leading `value=`: we cannot tell which part is the credential, so the whole
    // detail goes. Fail safe, not fail open.
    CHECK(AuditStore::sanitized_detail("RuntimeConfig", "oidc_client_secret", "raw-leak") ==
          "<redacted>");
    // The credential written BEFORE a value= token -- the case the old prefix-
    // preserving rule leaked verbatim.
    CHECK(AuditStore::sanitized_detail("RuntimeConfig", "oidc_client_secret", "s3cr3t value=x") ==
          "<redacted>");
}

TEST_CASE("AuditStore: a pre-existing config.update secret detail is redacted on READ",
          "[pg][audit_store][secret]") {
    // Defence in depth behind the backfill-time redaction: a row that reaches the
    // table by any other route (a restore, a hand-written import) must still not
    // disclose the credential through the six readers. The port dropped this
    // entirely at one point, which is why it is pinned here.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    exec_sql(db.dsn(),
             "INSERT INTO audit_store.audit_events (timestamp, principal, principal_role, action, "
             "target_type, target_id, detail, result, ttl_expires_at) VALUES "
             "(1000,'admin','admin','config.update','RuntimeConfig','oidc_client_secret',"
             "'value=hunter2-the-real-secret','success',0)");

    auto r = store.query();
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 1);
    CHECK((*r)[0].detail == "value=<redacted>");
    CHECK((*r)[0].detail.find("hunter2") == std::string::npos);
}

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

    // A limit ABOVE the cap must not lift the cap. The pool is the bound the
    // header promises and the REST layer reports as `recency_capped`; a caller
    // asking for more evidence than the cap gets the capped pool, not a bigger
    // scan. (The fetch used to be max(limit, cap), so this returned 10250.)
    AuditQuery over;
    over.action_prefixes = {"auth."};
    over.random_sample = true;
    over.limit = 12000;
    std::size_t over_pool = 0;
    auto ro = store.query(over, &over_pool);
    REQUIRE(ro.has_value());
    CHECK(over_pool == kAuditSampleScanCap);
    CHECK(ro->size() <= kAuditSampleScanCap);
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
    // 999+g mirrors build_legacy_audit_db's own stamping (id g carries timestamp
    // 1000+(g-1)). It has to MATCH: a resume prefix is a copy of these very rows,
    // and the prefix proof compares their content, not just their ids.
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_events (id, timestamp, principal, "
                       "principal_role, action, result, ttl_expires_at) OVERRIDING SYSTEM VALUE "
                       "SELECT g, 999+g, 'admin','admin','auth.login','success',0 FROM "
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

// Adversarial review (Kimi H1 / Codex C-P2-1), and the reason the A-3 alert is
// keyed the way it is. `YuzuAuditBackfillFailing` fires on the ABSENCE of a
// success outcome, so the family has to exist on a healthy server — and the
// ordinary restart of an already-migrated server reaches NO outcome at all: it
// returns at the marker check. Without the pre-seed in `set_metrics`, that
// healthy restart exports nothing and the critical alert pages every time.
// Both halves are asserted here: the seed exists, and the marker-present restart
// leaves it at 0 rather than incrementing something untrue.
TEST_CASE("AuditStore: wiring metrics pre-seeds both closed label sets",
          "[pg][audit_store][metrics]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());

    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    const std::string seeded = metrics.serialize();
    for (const char* result : {"completed", "fresh", "failed"})
        CHECK(seeded.find(std::string("yuzu_server_audit_backfill_total{result=\"") + result +
                          "\"} 0") != std::string::npos);
    for (const char* reason : {"store_not_open", "pool_acquire_timeout", "query_error"})
        CHECK(seeded.find(std::string("yuzu_server_audit_read_degrade_total{reason=\"") + reason +
                          "\"} 0") != std::string::npos);

    // An already-migrated server restarting: marker present, so migrate_from_sqlite
    // short-circuits. The success series must still be THERE (else the alert
    // pages) and must still read 0 (else the counter lies about what happened).
    REQUIRE(store.migrate_from_sqlite("/nonexistent-yuzu-test/audit.db")); // stamps the marker
    AuditStore restarted(pool);
    REQUIRE(restarted.is_open());
    yuzu::MetricsRegistry restart_metrics;
    restarted.set_metrics(&restart_metrics);
    REQUIRE(restarted.migrate_from_sqlite("/nonexistent-yuzu-test/audit.db"));
    const std::string after = restart_metrics.serialize();
    CHECK(after.find("yuzu_server_audit_backfill_total{result=\"completed\"} 0") !=
          std::string::npos);
    CHECK(after.find("yuzu_server_audit_backfill_total{result=\"fresh\"} 0") != std::string::npos);
}

// Gate 3 cpp-expert, who measured both halves on PG 18: `result` and
// `principal_class` were bound verbatim as "enum-controlled". An embedded NUL
// stored `"suc"` — a silently truncated audit RESULT — and invalid UTF-8 failed
// the INSERT outright, losing the event on a fail-hard write path. Every caller
// in the tree passes a literal today; this pins the store so that stays a
// property of the store rather than of every caller remembering.
TEST_CASE("AuditStore: a NUL or invalid UTF-8 in result does not truncate or lose the row",
          "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());

    AuditEvent e = mk("admin", "auth.login");
    e.result = std::string("suc\0cess", 8); // embedded NUL
    e.principal_class = "\xff\xfe";         // invalid UTF-8
    REQUIRE(store.log(e));                   // the event is NOT lost

    auto rows = store.query();
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    // Scrubbed, not truncated: the tail after the NUL survives.
    CHECK(rows->at(0).result != "suc");
    CHECK(rows->at(0).result.find("cess") != std::string::npos);
}

// Gate 2 security / Gate 3 cpp-expert: a negative limit reached PostgreSQL as
// `LIMIT -1`, which errors — and this store reports a query error as a DEGRADE,
// which is the series `YuzuAuditReadDegraded` pages on. So any read-privileged
// client could fire the evidence-availability alert at will and send the on-call
// after a database fault that does not exist. The parsers reject it as a 400;
// the store clamps as defence in depth. Both halves matter: the assertion that
// the DEGRADE COUNTER DID NOT MOVE is the one that pins the security property,
// and it is only meaningful because set_metrics pre-seeds the series to 0.
TEST_CASE("AuditStore: a negative limit clamps rather than reporting a degrade",
          "[pg][audit_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    REQUIRE(store.log(mk("admin", "auth.login")));

    AuditQuery q;
    q.limit = -1;
    auto rows = store.query(q);
    REQUIRE(rows.has_value()); // a degrade would be nullopt -> 503
    CHECK(rows->empty());
    CHECK(metrics.serialize().find(
              "yuzu_server_audit_read_degrade_total{reason=\"query_error\"} 0") !=
          std::string::npos);

    // A negative offset is already inert at this seam (the OFFSET clause is
    // emitted only when offset > 0) — pin that so it stays inert.
    AuditQuery q2;
    q2.offset = -5;
    auto rows2 = store.query(q2);
    REQUIRE(rows2.has_value());
    CHECK(rows2->size() == 1);
    CHECK(metrics.serialize().find(
              "yuzu_server_audit_read_degrade_total{reason=\"query_error\"} 0") !=
          std::string::npos);
}

// Gate 3 quality-engineer, on a fix of mine: it reverted the retention probe to
// the counting form PERF-1 replaced and the ENTIRE suite stayed green — the only
// evidence the fix worked was a hand-run EXPLAIN in a commit message, so a
// future revert would ship silently. This pins the two properties that make the
// probe index-eligible. It asserts SHAPE, not a query plan: the planner is
// cost-based and at this table size a sequential scan is legitimately cheaper,
// so a plan assertion here would pin an accident rather than the contract.
TEST_CASE("AuditStore: the retention probe stays EXISTS-shaped and index-eligible",
          "[audit_store][retention]") {
    const std::string sql{kAuditRetentionProbeSql};
    // EXISTS, never a counting aggregate: a count with no statement-level WHERE
    // must visit the ttl_expires_at = 0 majority, which sits outside the partial
    // index, so it degenerates to a full scan of the evidence table every pass.
    CHECK(sql.find("EXISTS(") != std::string::npos);
    CHECK(sql.find("count(") == std::string::npos);
    CHECK(sql.find("COUNT(") == std::string::npos);
    CHECK(sql.find("FILTER") == std::string::npos);
    // Both halves must carry the partial index's own predicate, or the index is
    // not eligible at all.
    std::size_t at = 0, predicates = 0;
    while ((at = sql.find("ttl_expires_at > 0", at)) != std::string::npos) {
        ++predicates;
        at += 1;
    }
    CHECK(predicates == 2);
}

// Gate 3 performance: at one capped pass per hour the 25k cap stops being a
// per-pass bound and becomes a permanent drain ceiling, below the rate the
// store's own write path sustains. A pass that hits the cap AND leaves a real
// backlog must therefore re-arm in seconds; anything else keeps the interval.
TEST_CASE("AuditStore: a binding cap re-arms in seconds, everything else waits the interval",
          "[audit_store][retention]") {
    CHECK(audit_next_wait_s(/*cap_bound_with_backlog=*/true, 60) == kAuditBacklogRearmSec);
    CHECK(audit_next_wait_s(/*cap_bound_with_backlog=*/true, 1) == kAuditBacklogRearmSec);
    // No backlog: the configured cadence, untouched.
    CHECK(audit_next_wait_s(/*cap_bound_with_backlog=*/false, 60) == 3600);
    CHECK(audit_next_wait_s(/*cap_bound_with_backlog=*/false, 1) == 60);
    // The re-arm is a floor on responsiveness, not on load: it must stay well
    // above the measured per-pass cost and well below the default interval.
    STATIC_REQUIRE(kAuditBacklogRearmSec > 0);
    STATIC_REQUIRE(kAuditBacklogRearmSec < 60);
}

// Gate 3 quality-engineer: no test drove a legacy audit.db whose audit_events
// table EXISTS but is EMPTY. It is a distinct path from the sourceless exits —
// there IS a source, so the prefix proof and reconciliation run; they just run
// over zero rows.
TEST_CASE("AuditStore: an empty legacy audit_events table completes as a real backfill",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf14_"}};
    auto legacy = dir.path / "audit.db";
    build_legacy_audit_db(legacy, /*count=*/0); // table present, zero rows

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.migrate_from_sqlite(legacy));

    CHECK(row_count(db.dsn()) == 0);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'backfill_complete'") == "1");
    CHECK_FALSE(std::filesystem::exists(legacy)); // moved aside like any verified backfill
    // The write gate cleared, and the identity sequence is usable.
    CHECK(store.log(mk("admin", "post.empty.backfill")));
    CHECK(row_count(db.dsn()) == 1);
}

// Gate 3 cpp-safety. A backfill that STARTED and did not finish gates the write
// path. `ServerImpl`'s constructor sets `startup_failed_` and then keeps
// constructing — several of its audit hooks are guarded only on `is_open()` —
// so without the gate a boot that refuses to serve still writes native rows
// ahead of the marker, and the prefix proof then refuses every later boot.
TEST_CASE("AuditStore: a failed backfill declines writes until one succeeds",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf13_"}};
    auto legacy = dir.path / "audit.db";
    build_legacy_audit_db(legacy, /*count=*/100);

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    // Another deployment's rows: same id shape, different event times, so the
    // prefix proof rejects them and the backfill fails.
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_events (id, timestamp, principal, "
                       "principal_role, action, result, ttl_expires_at) OVERRIDING SYSTEM VALUE "
                       "SELECT g, 500000 + g, 'admin','admin','auth.login','success',0 "
                       "FROM generate_series(1,50) g");
    REQUIRE_FALSE(store.migrate_from_sqlite(legacy));

    // The gate is armed. A write here would be the native row that wedges the
    // next boot, so it is declined and counted as a write failure.
    const auto failed_before = store.emit_failed_count();
    CHECK_FALSE(store.log(mk("admin", "post.failed.backfill")));
    CHECK(store.emit_failed_count() == failed_before + 1);
    CHECK(row_count(db.dsn()) == 50); // nothing written

    // Not a one-way latch: clear the obstruction, complete the backfill, and
    // writes resume.
    exec_sql(db.dsn(), "DELETE FROM audit_store.audit_events");
    REQUIRE(store.migrate_from_sqlite(legacy));
    CHECK(store.log(mk("admin", "post.good.backfill")));
}

// Gate 3 architect A-4. A one-shot CLI may COMPLETE a real backfill, but it must
// never declare the migration done merely because THIS host holds no legacy
// audit.db — that stamps the marker over an empty table, and the host that does
// hold the trail then skips the mandatory backfill on that marker and reports
// success.
TEST_CASE("AuditStore: a sourceless Refuse caller may not stamp; boot still may",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());

    CHECK_FALSE(store.migrate_from_sqlite("/nonexistent-yuzu-test/audit.db",
                                          AuditStore::Sourceless::Refuse));
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'backfill_complete'") == "0");
    // Refusing arms the write gate too — the caller is expected to abort.
    CHECK_FALSE(store.log(mk("root", "mfa.reset.breakglass")));

    // The boot path, over the same empty table, still stamps and re-opens writes.
    REQUIRE(store.migrate_from_sqlite("/nonexistent-yuzu-test/audit.db"));
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'backfill_complete'") == "1");
    CHECK(store.log(mk("root", "mfa.reset.breakglass")));
}

// Gate 3 quality-engineer: the retention thread's lifecycle had no test at all.
// This pins start -> stop -> stop-again -> destroy. It deliberately does NOT
// call start_cleanup() twice: that is a KNOWN defect in the non-jthread arm
// (move-assigning over a joinable std::thread is std::terminate), and a test
// that crashes the suite is not a regression net. Tracked separately.
TEST_CASE("AuditStore: the cleanup thread stops idempotently and joins on destroy",
          "[pg][audit_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    {
        // A 1-minute interval: the first pass never fires inside the test, so
        // this exercises teardown, not the pass itself.
        AuditStore store(pool, kGuardRetentionDays, 1);
        REQUIRE(store.is_open());
        store.start_cleanup();
        store.stop_cleanup();
        store.stop_cleanup(); // idempotent
    }                         // ~AuditStore joins an already-stopped thread
    SUCCEED("cleanup thread torn down without hang or terminate");
}

// Gate 3 architect A-1. A "nothing to migrate" exit may stamp the marker only
// over an EMPTY table: the marker asserts the trail is COMPLETE, and with no
// source in hand nothing on that path can establish it. Reachable when replica 2
// boots without a local audit.db while replica 1 is still streaming — before the
// guard, replica 2 stamped `backfill_complete` over the partial trail and
// replica 1's retry then short-circuited on the marker and returned true on a
// knowingly-incomplete evidence chain.
TEST_CASE("AuditStore: backfill with no legacy source refuses to mark a NON-EMPTY table complete",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    // A sibling replica's partial backfill: rows present, marker absent.
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_events (id, timestamp, principal, "
                       "principal_role, action, result, ttl_expires_at) OVERRIDING SYSTEM VALUE "
                       "SELECT g, 999 + g, 'admin','admin','auth.login','success',0 "
                       "FROM generate_series(1,20) g");

    CHECK_FALSE(store.migrate_from_sqlite("/nonexistent-yuzu-test/audit.db"));
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'backfill_complete'") == "0");
    CHECK(row_count(db.dsn()) == 20); // the partial trail is left alone
}

// Same rule on the other sourceless exit: a legacy file that carries no
// audit_events table is not a migration source either.
TEST_CASE("AuditStore: backfill with a table-less legacy file refuses over a NON-EMPTY table",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf11_"}};
    auto legacy = dir.path / "audit.db";
    std::filesystem::create_directories(dir.path);
    {
        SqliteDb ldb;
        REQUIRE(sqlite3_open(legacy.string().c_str(), ldb.addr()) == SQLITE_OK);
        REQUIRE(sqlite3_exec(ldb.get(),
                             "CREATE TABLE audit_retention_meta (key TEXT PRIMARY KEY, value "
                             "INTEGER NOT NULL);",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_events (id, timestamp, principal, "
                       "principal_role, action, result, ttl_expires_at) OVERRIDING SYSTEM VALUE "
                       "SELECT g, 999 + g, 'admin','admin','auth.login','success',0 "
                       "FROM generate_series(1,20) g");

    CHECK_FALSE(store.migrate_from_sqlite(legacy));
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'backfill_complete'") == "0");

    // And the same file over an EMPTY table still completes — the guard is the
    // row count, not the shape of the legacy file.
    YUZU_REQUIRE_PG_DB(db2);
    PgPool pool2{{.conninfo = db2.dsn(), .size = 4}};
    AuditStore store2(pool2);
    REQUIRE(store2.is_open());
    CHECK(store2.migrate_from_sqlite(legacy));
    CHECK(query_scalar(db2.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key "
                                  "= 'backfill_complete'") == "1");
}

// Gate 3 architect A-2 — the ORDER CONTRACT the one-shot CLI paths must follow.
// `--mfa-reset` / `--break-glass-arm` write a NATIVE audit row without going
// through boot. Doing that before the backfill marker exists wedges an upgraded
// host permanently: the prefix proof compares Postgres's rows against the legacy
// rows at or below the resume cursor, a native row is not one of them, and the
// mismatch refuses the backfill on EVERY later boot. main.cpp's
// `open_one_shot_audit` runs the backfill first for exactly this reason.
TEST_CASE("AuditStore: a native row ahead of the backfill wedges it; backfill-then-log does not",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf12_"}};
    auto legacy = dir.path / "audit.db";
    build_legacy_audit_db(legacy, /*count=*/50);

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());

    SECTION("native row first — the upgraded host can no longer migrate") {
        REQUIRE(store.log(mk("root", "mfa.reset.breakglass")));
        CHECK_FALSE(store.migrate_from_sqlite(legacy));
        CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE "
                                     "key = 'backfill_complete'") == "0");
        CHECK(std::filesystem::exists(legacy)); // evidence still recoverable
    }

    SECTION("backfill first, then the row — the order open_one_shot_audit enforces") {
        REQUIRE(store.migrate_from_sqlite(legacy));
        REQUIRE(store.log(mk("root", "mfa.reset.breakglass")));
        CHECK(row_count(db.dsn()) == 51);
        CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE "
                                     "key = 'backfill_complete'") == "1");
    }
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

// Boot must not proceed with an INCOMPLETE evidence chain (Gate 3 QE BLOCKING —
// it was untested). Pre-insert a row whose id is HIGHER than every legacy id,
// with NO marker, so the resume cursor would jump past all 50 legacy rows. The
// prefix proof rejects that first (Postgres holds 1 row at/below the cursor
// where the legacy db holds 50), with the reconcile shortfall guard behind it —
// either way: return false, marker unstamped, legacy file left in place.
TEST_CASE("AuditStore: backfill reconcile shortfall fails closed and does not mark complete",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf5_"}};
    auto legacy = dir.path / "audit.db";
    build_legacy_audit_db(legacy, /*count=*/50);

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    // Resume cursor jumps past every legacy id (1..50) → nothing gets migrated.
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_events (id, timestamp, principal, "
                       "principal_role, action, result, ttl_expires_at) OVERRIDING SYSTEM VALUE "
                       "VALUES (100000, 1000, 'admin','admin','auth.login','success',0)");

    CHECK_FALSE(store.migrate_from_sqlite(legacy)); // reconcile shortfall → fail-closed
    // Marker NOT stamped — the next boot retries rather than serving an
    // incomplete SOC-2 evidence chain.
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'backfill_complete'") == "0");
    // The legacy file is left in place for the retry (not moved aside).
    CHECK(std::filesystem::exists(legacy));
}

// The shortfall guard above is NOT sufficient on its own: give Postgres enough
// unrelated high-id rows and `pg_count >= legacy_count` holds, so the migration
// would stamp the MANDATORY audit backfill complete having copied ZERO rows and
// then move the legacy evidence aside. ADR-0009's trigger is "finds its
// Postgres schema EMPTY and a legacy .db present"; the MAX(id) resume cursor
// relaxes that for crash-resume, and the prefix proof is what keeps the
// relaxation sound. Adversarial review reproduced the un-guarded behaviour
// (migrate returned true, marker stamped, legacy moved aside, 0 rows copied).
TEST_CASE("AuditStore: backfill refuses a non-prefix Postgres table (no silent zero-row completion)",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf7_"}};
    auto legacy = dir.path / "audit.db";
    build_legacy_audit_db(legacy, /*count=*/50);

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    // 50 rows that are NOT part of this legacy stream, all above its id range —
    // enough that a count-only check cannot tell the difference.
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_events (id, timestamp, principal, "
                       "principal_role, action, result, ttl_expires_at) OVERRIDING SYSTEM VALUE "
                       "SELECT 100000 + g, 1000, 'admin','admin','auth.login','success',0 "
                       "FROM generate_series(1,50) g");

    CHECK_FALSE(store.migrate_from_sqlite(legacy));
    // Not marked complete: the next boot retries instead of serving an evidence
    // chain that never received the pre-cutover rows.
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'backfill_complete'") == "0");
    // The legacy evidence is still where the operator can recover it.
    CHECK(std::filesystem::exists(legacy));
    // And nothing was half-copied on top of the foreign rows.
    CHECK(row_count(db.dsn()) == 50);
}

// A resumed backfill is the case the MAX(id) cursor exists for: Postgres already
// holds a genuine PREFIX of this legacy stream (ids 1..20 of 1..50), so the
// prefix proof must ACCEPT it and the remaining rows must stream. Pins that the
// guard above closes the hole without breaking crash-resume.
TEST_CASE("AuditStore: backfill redacts a pre-fix config.update secret during the copy",
          "[pg][audit_store][backfill][secret]") {
    // The ladder's migration contract makes this an explicit decision rather than
    // a default: rows are deliberately never rewritten in SQLite, so an
    // un-redacted copy would land a plaintext credential in the Postgres
    // substrate, where there is no rekey story for a secret embedded in free
    // text. Reads redact identically, so nothing legitimately readable is lost.
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf11_"}};
    auto legacy = dir.path / "audit.db";
    std::filesystem::create_directories(legacy.parent_path());
    {
        SqliteDb ldb;
        REQUIRE(sqlite3_open(legacy.string().c_str(), ldb.addr()) == SQLITE_OK);
        REQUIRE(sqlite3_exec(ldb.get(),
                             "CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                             "timestamp INTEGER NOT NULL, principal TEXT NOT NULL, principal_role "
                             "TEXT NOT NULL, action TEXT NOT NULL, target_type TEXT, target_id "
                             "TEXT, detail TEXT, source_ip TEXT, user_agent TEXT, session_id TEXT, "
                             "result TEXT NOT NULL, ttl_expires_at INTEGER DEFAULT 0, "
                             "principal_class TEXT NOT NULL DEFAULT '');",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
        REQUIRE(sqlite3_exec(ldb.get(),
                             "INSERT INTO audit_events (timestamp, principal, principal_role, "
                             "action, target_type, target_id, detail, result, ttl_expires_at) "
                             "VALUES (1000,'admin','admin','config.update','RuntimeConfig',"
                             "'oidc_client_secret','value=hunter2-the-real-secret','success',0);",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.migrate_from_sqlite(legacy));

    // The plaintext is not in the substrate at all — checked against the column,
    // not through a reader that would redact it either way.
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_events WHERE detail LIKE "
                                 "'%hunter2%'") == "0");
    CHECK(query_scalar(db.dsn(), "SELECT detail FROM audit_store.audit_events") ==
          "value=<redacted>");
}

TEST_CASE("AuditStore: backfill refuses a foreign table whose ids are CONTIGUOUS from 1",
          "[pg][audit_store][backfill]") {
    // The case the id-shape fingerprint could not see, and the one that actually
    // occurs. Ids are GENERATED ALWAYS AS IDENTITY here and rowid in the legacy
    // file, so BOTH run 1..k in every deployment: a foreign table holding ids
    // 1..50 has exactly the same count and id-sum as this legacy file's own first
    // 50 rows. The cursor then skips those 50 legacy rows, 50 more stream in, and
    // the equality reconciliation balances at 100 == 100 — a completed mandatory
    // backfill that destroyed 50 rows of pre-cutover evidence.
    //
    // The timestamps are what differ between two deployments, which is why they
    // are in the fingerprint.
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf10_"}};
    auto legacy = dir.path / "audit.db";
    build_legacy_audit_db(legacy, /*count=*/100); // legacy ids 1..100, timestamps 1000..1099

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    // Another deployment's first 50 rows: same id shape, different event times.
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_events (id, timestamp, principal, "
                       "principal_role, action, result, ttl_expires_at) OVERRIDING SYSTEM VALUE "
                       "SELECT g, 500000 + g, 'admin','admin','auth.login','success',0 "
                       "FROM generate_series(1,50) g");

    CHECK_FALSE(store.migrate_from_sqlite(legacy));
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'backfill_complete'") == "0");
    CHECK(std::filesystem::exists(legacy)); // evidence still recoverable
    CHECK(row_count(db.dsn()) == 50);       // nothing streamed on top
}

TEST_CASE("AuditStore: backfill resumes from a genuine prefix and completes",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf8_"}};
    auto legacy = dir.path / "audit.db";
    build_legacy_audit_db(legacy, /*count=*/50);

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    // Simulate a backfill that crashed after copying ids 1..20.
    // Same content as the legacy rows it stands in for (id g -> timestamp 999+g).
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_events (id, timestamp, principal, "
                       "principal_role, action, result, ttl_expires_at) OVERRIDING SYSTEM VALUE "
                       "SELECT g, 999 + g, 'admin','admin','auth.login','success',0 "
                       "FROM generate_series(1,20) g");

    REQUIRE(store.migrate_from_sqlite(legacy));
    CHECK(row_count(db.dsn()) == 50); // 20 already there + 30 streamed, no duplicates
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'backfill_complete'") == "1");
    CHECK_FALSE(std::filesystem::exists(legacy));
}

// The legacy audit.db is moved aside as the one-release rollback net (ADR-0009).
// A clean shutdown checkpoints the WAL away, but after an unclean stop the
// committed tail is in `audit.db-wal` — and the main file WITHOUT it does not
// even expose the audit_events table. Moving only the main file would therefore
// retain a copy that cannot be opened standalone.
TEST_CASE("AuditStore: backfill moves the legacy WAL/SHM sidecars with the main file",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf9_"}};
    auto legacy = dir.path / "audit.db";
    build_legacy_audit_db(legacy, /*count=*/5);
    // An empty WAL is a valid one SQLite will open; it stands in for the tail a
    // crashed writer leaves behind without needing to crash a writer.
    const auto wal = std::filesystem::path{legacy.string() + "-wal"};
    { std::ofstream touch(wal, std::ios::binary); }
    REQUIRE(std::filesystem::exists(wal));

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.migrate_from_sqlite(legacy));

    CHECK_FALSE(std::filesystem::exists(legacy));
    CHECK_FALSE(std::filesystem::exists(wal)); // not orphaned in the live db dir
    // It travelled with the main file: exactly one `audit.db.migrated-*` and a
    // matching `-wal` beside it.
    int moved_main = 0, moved_wal = 0;
    for (const auto& e : std::filesystem::directory_iterator(dir.path)) {
        const auto n = e.path().filename().string();
        if (n.rfind("audit.db.migrated-", 0) != 0)
            continue;
        if (n.size() > 4 && n.compare(n.size() - 4, 4, "-wal") == 0)
            ++moved_wal;
        else
            ++moved_main;
    }
    CHECK(moved_main == 1);
    CHECK(moved_wal == 1);
}

// A legacy audit.db is UNTRUSTED-at-rest: years of free-text fields may hold
// invalid UTF-8 or an embedded NUL — in ANY column, including result/
// principal_class. Without sanitizing those two on the backfill path, one bad
// byte fails the fail-hard batch INSERT (SQLSTATE 22021), fails the MANDATORY
// backfill, and bricks boot forever (Gate 4 cpp-safety/unhappy #2). This proves
// the row lands, defanged, and the backfill succeeds.
TEST_CASE("AuditStore: backfill sanitizes invalid-UTF-8 legacy bytes in every text column",
          "[pg][audit_store][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    yuzu::test::TempDir dir{std::string_view{"yuzu_test_audit_bf6_"}};
    auto legacy = dir.path / "audit.db";
    std::filesystem::create_directories(legacy.parent_path());
    {
        SqliteDb ldb;
        REQUIRE(sqlite3_open(legacy.string().c_str(), ldb.addr()) == SQLITE_OK);
        REQUIRE(sqlite3_exec(ldb.get(),
                             "CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                             "timestamp INTEGER NOT NULL, principal TEXT NOT NULL, principal_role "
                             "TEXT NOT NULL, action TEXT NOT NULL, target_type TEXT, target_id "
                             "TEXT, detail TEXT, source_ip TEXT, user_agent TEXT, session_id TEXT, "
                             "result TEXT NOT NULL, ttl_expires_at INTEGER DEFAULT 0, "
                             "principal_class TEXT NOT NULL DEFAULT '');",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
        SqliteStmt s;
        REQUIRE(sqlite3_prepare_v2(ldb.get(),
                                   "INSERT INTO audit_events (timestamp, principal, principal_role, "
                                   "action, detail, result, ttl_expires_at, principal_class) VALUES "
                                   "(?,?,?,?,?,?,?,?)",
                                   -1, s.addr(), nullptr) == SQLITE_OK);
        // Invalid UTF-8 (0xff) + embedded NUL in detail, result, principal_class.
        const std::string bad_detail = std::string("d") + '\xff' + '\0' + "x";
        const std::string bad_result = std::string("succ") + '\xff' + "ess"; // non-enum, non-UTF8
        const std::string bad_class = std::string("hum") + '\xff' + "an";
        sqlite3_bind_int64(s.get(), 1, 1000);
        sqlite3_bind_text(s.get(), 2, "admin", -1, SQLITE_STATIC);
        sqlite3_bind_text(s.get(), 3, "admin", -1, SQLITE_STATIC);
        sqlite3_bind_text(s.get(), 4, "auth.login", -1, SQLITE_STATIC);
        sqlite3_bind_text(s.get(), 5, bad_detail.data(), static_cast<int>(bad_detail.size()),
                          SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 6, bad_result.data(), static_cast<int>(bad_result.size()),
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(s.get(), 7, 0);
        sqlite3_bind_text(s.get(), 8, bad_class.data(), static_cast<int>(bad_class.size()),
                          SQLITE_TRANSIENT);
        REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.migrate_from_sqlite(legacy)); // must NOT brick on the bad bytes
    CHECK(row_count(db.dsn()) == 1);
    // The row landed with valid UTF-8 (U+FFFD defanged). That the INSERT
    // committed at all proves result/principal_class no longer fail the batch;
    // chr(65533) is U+FFFD, so its presence proves the bytes were scrubbed, not
    // dropped.
    //
    // The NUL is scrubbed the same way, and there IS something to assert about
    // it: `detail` is "d\xff\0x", so the byte AFTER the NUL must survive. A
    // C-string read of the legacy column stops at the NUL and drops it — the
    // sanitizer then never sees the suffix, and the truncation reads as clean
    // data. Anchoring on the last character is what makes that distinguishable.
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_events WHERE detail LIKE "
                                 "'%' || chr(65533) || '%'") == "1");
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_events WHERE "
                                 "principal_class LIKE '%' || chr(65533) || '%'") == "1");
    // The byte after the embedded NUL survived, and the NUL itself became U+FFFD
    // rather than an end-of-field.
    CHECK(query_scalar(db.dsn(), "SELECT RIGHT(detail,1) FROM audit_store.audit_events") == "x");
    CHECK(query_scalar(db.dsn(), "SELECT length(detail) FROM audit_store.audit_events") == "4");
}

// Dead-CMOS-then-NTP, driven through the real reap flow (Gate 3 QE SHOULD — the
// catastrophic-protection claim for the dropped is_event exemption was only
// proven at the pure classify() level). A corrupt durable last_pass_now
// (prev_unusable) stacked under a would_wipe condition (every row expired) must
// DECLINE, never drain the evidence chain on the corrupt pass.
TEST_CASE("AuditStore #2360: a corrupt clock reading under a would-wipe declines, never drains",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());
    seed_rows_with_ttl(db.dsn(), kNow - 100, 10); // every row expired → would_wipe
    // Poison the durable clock reading with a non-numeric value → prev_unusable.
    exec_sql(db.dsn(), "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
                       "('last_pass_now', 'not-a-number') ON CONFLICT (key) DO UPDATE SET value = "
                       "EXCLUDED.value");

    CHECK(store.cleanup_once(kNow) == 0);          // declines (BadState/prev_unusable)
    CHECK(row_count(db.dsn()) == 10);              // nothing deleted on the corrupt pass
    CHECK(store.clock_anomaly_skips_count() == 1); // reported
    CHECK(store.rows_deleted_count() == 0);
    // The pass re-anchored an honest reading, so a durable anomaly fact set was
    // recorded rather than the evidence being wiped.
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM audit_store.audit_retention_meta WHERE key = "
                                 "'last_anomaly_facts'") == "1");
}

// ── #2360: retention clock guard (single-sweeper advisory lease) ─────────────

TEST_CASE("AuditStore #2360: a first pass that would wipe every datable row declines once, "
          "then drains",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());
    anchor_guard(store); // #2579 precondition: this test is not about the bootstrap
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
    anchor_guard(store); // #2579 precondition: this test is not about the bootstrap
    seed_rows_with_ttl(db.dsn(), kNow - 100, 10);    // expired
    seed_rows_with_ttl(db.dsn(), kNow + kWindow, 1); // healthy survivor

    CHECK(store.cleanup_once(kNow) == 10);
    CHECK(row_count(db.dsn()) == 1);
    CHECK(store.clock_anomaly_skips_count() == 0);
}

TEST_CASE("AuditStore #2579: no stored reading + rows already expired declines, once",
          "[pg][audit_store][retention][clock-guard]") {
    // The disclosed shape, end to end. A host whose clock was ALREADY skewed
    // forward before its first guarded pass: rows written before the skew look
    // expired, rows written after it are still inside the window, so the
    // would-expire-everything test does not fire and -- before this trigger --
    // nothing else did either. The pass deleted, with no decline, no counter and
    // no warning.
    //
    // Deliberately NOT anchored: the absence of a stored reading IS the input.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    REQUIRE(store.is_open());
    seed_rows_with_ttl(db.dsn(), kNow - 100, 10);    // expired: written before the skew
    seed_rows_with_ttl(db.dsn(), kNow + kWindow, 2); // datable survivors: written after it

    REQUIRE(store.cleanup_once(kNow) == 0); // was 10 before #2579
    CHECK(row_count(db.dsn()) == 12);
    CHECK(store.bootstrap_declines_count() == 1);
    // The signal separation is the contract, not an implementation detail: this
    // decline must not fire the alert that means "the clock moved".
    CHECK(store.clock_anomaly_skips_count() == 0);

    // Once, not forever. The declining pass settled the marker, so the next pass
    // has a comparison point and proceeds -- paced by the cap as always.
    CHECK(store.cleanup_once(kNow + 1) == 10);
    CHECK(row_count(db.dsn()) == 2);
    CHECK(store.bootstrap_declines_count() == 1); // and NOT counted twice
}

TEST_CASE("AuditStore #2579: a probe-failed pass does not spend the bootstrap trigger",
          "[pg][audit_store][retention][clock-guard]") {
    // `cleanup_once` re-anchors BEFORE it probes, so a pass whose probes then
    // fail has consumed the anchor without ever reaching a verdict. Deriving the
    // trigger from the stored reading would let ONE transient probe failure
    // disarm it permanently: pass 2 sees a reading, calls itself anchored, and
    // deletes with every detector false -- the exact defect #2579 closes,
    // reinstated. The marker is therefore settled at the VERDICT, and every
    // early return before it rolls the whole transaction back.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    REQUIRE(store.is_open());
    seed_rows_with_ttl(db.dsn(), kNow - 100, 10);
    seed_rows_with_ttl(db.dsn(), kNow + kWindow, 2);

    // Pass 1 cannot probe -- and DOES re-anchor on its way past.
    exec_sql(db.dsn(), "ALTER TABLE audit_store.audit_events RENAME TO audit_events_hidden");
    CHECK(store.cleanup_once(kNow) == 0);
    CHECK(store.cleanup_failed_count() == 1);
    CHECK(store.bootstrap_declines_count() == 0); // no verdict was reached
    exec_sql(db.dsn(), "ALTER TABLE audit_store.audit_events_hidden RENAME TO audit_events");

    // Pass 2 must STILL decline. Without the verdict-point settle it deleted all 10.
    CHECK(store.cleanup_once(kNow + 1) == 0);
    CHECK(store.bootstrap_declines_count() == 1);
    CHECK(row_count(db.dsn()) == 12);

    // ...and having now reached a verdict, it is spent: pass 3 drains.
    CHECK(store.cleanup_once(kNow + 2) == 10);
    CHECK(row_count(db.dsn()) == 2);
}

TEST_CASE("AuditStore #2579: consecutive probe failures do not erode the trigger",
          "[pg][audit_store][retention][clock-guard]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    REQUIRE(store.is_open());
    seed_rows_with_ttl(db.dsn(), kNow - 100, 10);
    seed_rows_with_ttl(db.dsn(), kNow + kWindow, 2);

    exec_sql(db.dsn(), "ALTER TABLE audit_store.audit_events RENAME TO audit_events_hidden");
    for (int i = 0; i < 3; ++i)
        CHECK(store.cleanup_once(kNow + i) == 0);
    CHECK(store.cleanup_failed_count() == 3);
    CHECK(store.bootstrap_declines_count() == 0); // no verdict on any of them
    exec_sql(db.dsn(), "ALTER TABLE audit_store.audit_events_hidden RENAME TO audit_events");

    // Still armed after three failures.
    CHECK(store.cleanup_once(kNow + 10) == 0);
    CHECK(store.bootstrap_declines_count() == 1);
    CHECK(row_count(db.dsn()) == 12);
}

TEST_CASE("AuditStore #2579: nothing expired means no bootstrap decline",
          "[pg][audit_store][retention][clock-guard]") {
    // The cost control. A fresh install has no stored reading either, and if the
    // trigger fired on that it would declare an anomaly on every server's first
    // boot -- which is why `no_anchor` is tested AFTER `has_expired`.
    YUZU_REQUIRE_PG_DB_TPL(db, auditstore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    AuditStore store(pool, kGuardRetentionDays, 0);
    REQUIRE(store.is_open());
    seed_rows_with_ttl(db.dsn(), kNow + kWindow, 3); // nothing expired

    CHECK(store.cleanup_once(kNow) == 0);
    CHECK(store.bootstrap_declines_count() == 0);
    CHECK(store.clock_anomaly_skips_count() == 0);
    CHECK(row_count(db.dsn()) == 3);
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
    anchor_guard(store); // #2579 precondition: this test is not about the bootstrap
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
        anchor_guard(first); // #2579 precondition: this test is about the durable STEP
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
    // #2579 precondition, and here it is load-bearing rather than cosmetic:
    // without it this pass declines for the MISSING ANCHOR, every assertion below
    // passes for the wrong reason, and the test stays green through an advisory
    // lock that does not work at all. Verified by deleting the lock acquisition —
    // with this line the no-lock case fails as it must; without it it passes.
    anchor_guard(store);
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
