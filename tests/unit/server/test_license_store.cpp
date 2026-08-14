/**
 * test_license_store.cpp — `LicenseStore` (product license activation/entitlement,
 * capability 22.3, ADR-0048).
 *
 * **This store is deliberately DORMANT on `dev`** — nothing in `server.cpp` constructs a
 * `LicenseStore` (see license_store.hpp's file header). These tests exercise the store's public
 * API directly, exactly as `test_rest_api_t2.cpp`'s license-flow cases and a future re-wiring do.
 *
 * Covers:
 *  - fail-closed construction, both the migration-drift case (a live but unmigratable database)
 *    and the unreachable-pool case (mirrors test_deployment_store.cpp's two fail-closed cases).
 *  - activate_license validation (empty key, empty organization) and the atomic
 *    ON CONFLICT (license_key_hash) duplicate-key detection.
 *  - list_licenses / get_active_license: typed reads — a genuine DB error is distinguishable
 *    from "no licenses" (ADR-0036 program policy); get_active_license's `nullopt`-inside-
 *    `expected` double layer specifically.
 *  - remove_license: not-found vs success, atomic license+alerts delete.
 *  - validate(): expiry/seat-limit/warning alert generation, status transitions, one-transaction
 *    atomicity.
 *  - get_status / list_alerts / acknowledge_alert / has_feature / seat_count / days_remaining.
 *  - migrate_from_sqlite backfill contract (ADR-0009/0048): sourceless-then-holder anti-pattern
 *    regression, IDENTITY-mismatch fail-closed, LIFECYCLE-benign-no-op, LIFECYCLE-ahead
 *    fail-closed, terminal-disagreement fail-closed, unrecognised status/alert_type fail-closed
 *    before ever reaching Postgres, half-schema legacy file fail-closed (two-table-specific,
 *    ADR-0048), license_alerts' UNIQUE-constraint backfill dedup, mid-scan corruption.
 *
 * Migrated-to-Postgres store (ADR-0012 §1, authoritative/fail-hard). PG-gated: skips when
 * YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken (test_helpers.hpp skip-vs-fail
 * contract). Store-behaviour cases use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the two fail-closed cases use YUZU_REQUIRE_PG_DB / no
 * gate at all, per the plain-migration-test carve-out documented on that macro.
 */

#include "license_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <future>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::License;
using yuzu::server::LicenseAlert;
using yuzu::server::LicenseStore;
using yuzu::server::SqliteDb;
using yuzu::server::SqliteStmt;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::PgTxn;

namespace {

// RAII log capture (mirrors test_deployment_store.cpp) — swaps in an ostream-backed logger for
// its lifetime, restored on scope exit including on an exception. Used to assert WHICH branch a
// production code path took, not just that it failed.
class LogCapture {
public:
    LogCapture() {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(oss_);
        auto logger = std::make_shared<spdlog::logger>("test_license_store_capture", sink);
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

yuzu::test::PgTestTemplate license_store_tpl{
    "licensestore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        LicenseStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("license_store template: store failed to migrate");
    }};

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

License make_license(const std::string& org = "Acme Corp", int64_t seats = 100,
                     int64_t expires_at = 0, const std::string& edition = "enterprise",
                     const std::string& features =
                         R"(["admin_read","remote_execute","policy_engine"])") {
    License lic;
    lic.organization = org;
    lic.seat_count = seats;
    lic.expires_at = expires_at;
    lic.edition = edition;
    lic.features_json = features;
    return lic;
}

// Legacy-fixture row shapes — the public License/LicenseAlert structs deliberately omit
// license_key_hash/activated_at (License) and id (LicenseAlert, PG-assigned), so backfill test
// fixtures need their own local shapes carrying every legacy SQLite column.
struct LegacyLicenseFixture {
    std::string id;
    std::string license_key_hash;
    std::string organization;
    int64_t seat_count{0};
    int64_t issued_at{0};
    int64_t expires_at{0};
    std::string edition{"community"};
    std::string features_json{"[]"};
    std::string status{"active"};
    int64_t activated_at{0};
};

struct LegacyAlertFixture {
    std::string license_id;
    std::string alert_type;
    std::string message;
    int64_t triggered_at{0};
    bool acknowledged{false};
};

// Writes a legacy license.db fixture. `with_licenses_table`/`with_alerts_table` let a test
// construct the half-schema shape ADR-0048 fails closed on — the shipped pre-migration binary
// never produces a file with exactly one of the two tables, so this parameter exists ONLY for
// tests to synthesize that otherwise-unreachable shape.
void write_legacy_sqlite_db(const std::filesystem::path& path,
                            const std::vector<LegacyLicenseFixture>& licenses,
                            const std::vector<LegacyAlertFixture>& alerts,
                            bool with_licenses_table = true, bool with_alerts_table = true) {
    SqliteDb db;
    REQUIRE(sqlite3_open(path.string().c_str(), db.addr()) == SQLITE_OK);

    if (with_licenses_table) {
        const char* ddl =
            "CREATE TABLE licenses ("
            "  id TEXT PRIMARY KEY, license_key_hash TEXT NOT NULL UNIQUE,"
            "  organization TEXT NOT NULL DEFAULT '', seat_count INTEGER NOT NULL DEFAULT 0,"
            "  issued_at INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL DEFAULT 0,"
            "  edition TEXT NOT NULL DEFAULT 'community', features_json TEXT NOT NULL DEFAULT "
            "'[]',"
            "  status TEXT NOT NULL DEFAULT 'active', activated_at INTEGER NOT NULL DEFAULT 0);";
        REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, nullptr) == SQLITE_OK);
        for (const auto& l : licenses) {
            SqliteStmt s;
            const char* isql =
                "INSERT INTO licenses (id, license_key_hash, organization, seat_count, "
                "issued_at, expires_at, edition, features_json, status, activated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?);";
            REQUIRE(sqlite3_prepare_v2(db.get(), isql, -1, s.addr(), nullptr) == SQLITE_OK);
            sqlite3_bind_text(s.get(), 1, l.id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 2, l.license_key_hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 3, l.organization.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(s.get(), 4, l.seat_count);
            sqlite3_bind_int64(s.get(), 5, l.issued_at);
            sqlite3_bind_int64(s.get(), 6, l.expires_at);
            sqlite3_bind_text(s.get(), 7, l.edition.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 8, l.features_json.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 9, l.status.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(s.get(), 10, l.activated_at);
            REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
        }
    }

    if (with_alerts_table) {
        const char* ddl2 =
            "CREATE TABLE license_alerts ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT, license_id TEXT NOT NULL,"
            "  alert_type TEXT NOT NULL, message TEXT NOT NULL DEFAULT '',"
            "  triggered_at INTEGER NOT NULL DEFAULT 0, acknowledged INTEGER NOT NULL DEFAULT "
            "0);";
        REQUIRE(sqlite3_exec(db.get(), ddl2, nullptr, nullptr, nullptr) == SQLITE_OK);
        for (const auto& a : alerts) {
            SqliteStmt s;
            const char* isql = "INSERT INTO license_alerts (license_id, alert_type, message, "
                               "triggered_at, acknowledged) VALUES (?,?,?,?,?);";
            REQUIRE(sqlite3_prepare_v2(db.get(), isql, -1, s.addr(), nullptr) == SQLITE_OK);
            sqlite3_bind_text(s.get(), 1, a.license_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 2, a.alert_type.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(s.get(), 3, a.message.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(s.get(), 4, a.triggered_at);
            sqlite3_bind_int64(s.get(), 5, a.acknowledged ? 1 : 0);
            REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
        }
    }
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("LicenseStore reports !is_open on a migration failure", "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA license_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE license_store.licenses (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    LicenseStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE("LicenseStore reports !is_open on an unreachable pool, and every method fails closed",
          "[license_store]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    LicenseStore store{pool};
    CHECK_FALSE(store.is_open());

    auto activate_res = store.activate_license(make_license(), "KEY-1");
    CHECK_FALSE(activate_res.has_value());
    CHECK(activate_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto list_res = store.list_licenses();
    CHECK_FALSE(list_res.has_value());
    CHECK(list_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto active_res = store.get_active_license();
    CHECK_FALSE(active_res.has_value());
    CHECK(active_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto remove_res = store.remove_license("x");
    CHECK_FALSE(remove_res.has_value());
    CHECK(remove_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto validate_res = store.validate(10);
    CHECK_FALSE(validate_res.has_value());
    CHECK(validate_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto status_res = store.get_status();
    CHECK_FALSE(status_res.has_value());
    CHECK(status_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto alerts_res = store.list_alerts();
    CHECK_FALSE(alerts_res.has_value());
    CHECK(alerts_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto ack_res = store.acknowledge_alert(1);
    CHECK_FALSE(ack_res.has_value());
    CHECK(ack_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto feat_res = store.has_feature("x");
    CHECK_FALSE(feat_res.has_value());
    CHECK(feat_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto seats_res = store.seat_count();
    CHECK_FALSE(seats_res.has_value());
    CHECK(seats_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    auto days_res = store.days_remaining();
    CHECK_FALSE(days_res.has_value());
    CHECK(days_res.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));

    CHECK_FALSE(store.migrate_from_sqlite("/nonexistent/does/not/matter"));
}

// ── activate_license / get_active_license round-trip ────────────────────────

TEST_CASE("activate_license validates key/organization before writing", "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    SECTION("empty key is rejected") {
        auto r = store.activate_license(make_license(), "");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("empty organization is rejected") {
        License lic;
        lic.organization = "";
        lic.seat_count = 50;
        auto r = store.activate_license(lic, "VALID-KEY-123");
        REQUIRE_FALSE(r.has_value());
    }
    SECTION("a valid activation round-trips through get_active_license") {
        auto future = now_epoch() + 86400 * 365;
        auto lic = make_license("Acme Corp", 100, future, "enterprise");
        auto result = store.activate_license(lic, "LICENSE-KEY-ABC123");
        REQUIRE(result.has_value());
        CHECK_FALSE(result->empty());

        auto active = store.get_active_license();
        REQUIRE(active.has_value());
        REQUIRE(active->has_value());
        CHECK((*active)->id == *result);
        CHECK((*active)->organization == "Acme Corp");
        CHECK((*active)->seat_count == 100);
        CHECK((*active)->edition == "enterprise");
        CHECK((*active)->status == "active");
        CHECK((*active)->expires_at == future);
    }
}

TEST_CASE("activate_license detects a duplicate key atomically", "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto lic = make_license();
    auto first = store.activate_license(lic, "SAME-KEY-ABC");
    REQUIRE(first.has_value());

    auto second = store.activate_license(lic, "SAME-KEY-ABC");
    CHECK_FALSE(second.has_value());
    CHECK(second.error() == "license key already activated");
    // A genuine business-rule rejection, never the db_error prefix (would misclassify as 503).
    CHECK_FALSE(second.error().starts_with(yuzu::server::kLicenseDbErrorPrefix));
}

TEST_CASE("get_active_license: nullopt-inside-expected distinguishes 'none active' from a "
          "store failure",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto active = store.get_active_license();
    REQUIRE(active.has_value()); // a genuine successful read of zero rows
    CHECK_FALSE(active->has_value());
}

// ── list_licenses / remove_license ───────────────────────────────────────────

TEST_CASE("list_licenses returns every license, empty when none exist", "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto empty = store.list_licenses();
    REQUIRE(empty.has_value());
    CHECK(empty->empty());

    REQUIRE(store.activate_license(make_license("Org A"), "KEY-A").has_value());
    REQUIRE(store.activate_license(make_license("Org B"), "KEY-B").has_value());

    auto list = store.list_licenses();
    REQUIRE(list.has_value());
    CHECK(list->size() == 2);
}

TEST_CASE("remove_license deletes the license and its alerts atomically, and reports "
          "not_found for an unknown id",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    SECTION("removing an unknown id is not_found") {
        auto r = store.remove_license("nonexistent-id");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().starts_with("not_found:"));
    }
    SECTION("removing a real license clears it and its alerts") {
        auto past = now_epoch() - 86400;
        auto id = store.activate_license(make_license("Cleanup Org", 50, past), "KEY-CLEANUP");
        REQUIRE(id.has_value());
        REQUIRE(store.validate(10).has_value()); // generates an "expired" alert

        auto alerts_before = store.list_alerts();
        REQUIRE(alerts_before.has_value());
        CHECK_FALSE(alerts_before->empty());

        auto removed = store.remove_license(*id);
        CHECK(removed.has_value());

        auto list = store.list_licenses();
        REQUIRE(list.has_value());
        CHECK(list->empty());

        auto alerts_after = store.list_alerts();
        REQUIRE(alerts_after.has_value());
        CHECK(alerts_after->empty());

        auto active = store.get_active_license();
        REQUIRE(active.has_value());
        CHECK_FALSE(active->has_value());
    }
}

// ── validate() / get_status ───────────────────────────────────────────────

TEST_CASE("get_status reports the most recent license's status, or unlicensed",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto none = store.get_status();
    REQUIRE(none.has_value());
    CHECK(*none == "unlicensed");

    auto future = now_epoch() + 86400 * 365;
    REQUIRE(store.activate_license(make_license("Acme", 100, future), "KEY-ACTIVE").has_value());

    auto active = store.get_status();
    REQUIRE(active.has_value());
    CHECK(*active == "active");
}

TEST_CASE("validate detects an expired license, updates status, and emits an alert",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto past = now_epoch() - 86400;
    REQUIRE(
        store.activate_license(make_license("Expired Org", 50, past), "KEY-EXPIRED").has_value());

    REQUIRE(store.validate(10).has_value());

    auto status = store.get_status();
    REQUIRE(status.has_value());
    CHECK(*status == "expired");

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    CHECK_FALSE(alerts->empty());
    bool found_expired_alert = false;
    for (const auto& a : *alerts) {
        if (a.alert_type == "expired")
            found_expired_alert = true;
    }
    CHECK(found_expired_alert);
}

TEST_CASE("validate detects a seat-limit-exceeded license", "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365;
    REQUIRE(
        store.activate_license(make_license("Small Org", 10, future), "KEY-SEATS").has_value());

    REQUIRE(store.validate(15).has_value()); // 15 agents exceed the 10-seat limit

    auto status = store.get_status();
    REQUIRE(status.has_value());
    CHECK(*status == "exceeded");

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    bool found_exceeded = false;
    for (const auto& a : *alerts) {
        if (a.alert_type == "exceeded")
            found_exceeded = true;
    }
    CHECK(found_exceeded);
}

TEST_CASE("validate generates a near-expiry warning without changing status",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto near_expiry = now_epoch() + 86400 * 15; // within the 30-day warning window
    REQUIRE(store.activate_license(make_license("Warning Org", 100, near_expiry), "KEY-NEAREXPIRY")
               .has_value());

    REQUIRE(store.validate(5).has_value());

    auto status = store.get_status();
    REQUIRE(status.has_value());
    CHECK(*status == "active");

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    bool found_warning = false;
    for (const auto& a : *alerts) {
        if (a.alert_type == "expiry_warning")
            found_warning = true;
    }
    CHECK(found_warning);
}

TEST_CASE("validate: calling twice in quick succession dedups the alert within 24h",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto past = now_epoch() - 86400;
    REQUIRE(store.activate_license(make_license("Dedup Org", 50, past), "KEY-DEDUP").has_value());

    REQUIRE(store.validate(10).has_value());
    REQUIRE(store.validate(10).has_value());

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    int expired_count = 0;
    for (const auto& a : *alerts) {
        if (a.alert_type == "expired")
            ++expired_count;
    }
    CHECK(expired_count == 1);
}

TEST_CASE("validate: SELECT ... FOR UPDATE serializes overlapping status transitions "
          "(gov Gate 4 unhappy-path UP-1 regression)",
          "[license_store][pg][concurrency]") {
    // Defect this catches: without a row lock on the initial SELECT, two overlapping
    // validate() transactions (e.g. two server replicas sharing this Postgres) each read the
    // pre-transition status under their own snapshot and the later COMMIT silently clobbers
    // the earlier one's write with no error. Reproducing the exact lost-update byte-for-byte
    // needs precise interleaving this store has no clock-injection seam to control, so this
    // proves the mechanism directly instead: hold a manual row lock open on a second raw
    // connection, confirm a concurrent validate() call blocks for as long as the lock is
    // held, then confirm it completes correctly once released — the observable behaviour
    // FOR UPDATE is responsible for.
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365;
    REQUIRE(store.activate_license(make_license("Lock Org", 10, future), "KEY-LOCK").has_value());
    // Establish the row as 'active' before contending for its lock.
    REQUIRE(store.validate(5).has_value());
    REQUIRE(*store.get_status() == "active");

    // Hold a manual FOR UPDATE lock on the license row from a second raw connection.
    PgPool::Lease locker = pool.acquire();
    REQUIRE(locker);
    PgResult begin{PQexec(locker.get(), "BEGIN")};
    REQUIRE(begin.ok());
    // PgTxn (defense-in-depth per gov Gate 8 cpp-safety SHOULD): rolls back on any exception
    // anywhere below, rather than relying solely on PgPool::release()'s own fallback rollback
    // for a not-PQTRANS_IDLE connection.
    PgTxn locker_txn{locker.get()};
    PgResult lock{PQexec(locker.get(), "SELECT id FROM license_store.licenses "
                                       "WHERE status = 'active' FOR UPDATE")};
    REQUIRE(lock.ok());

    std::promise<std::expected<void, std::string>> result_promise;
    auto result_future = result_promise.get_future();
    std::thread validator([&] {
        result_promise.set_value(store.validate(15)); // 15 exceeds the 10-seat limit
    });
    // Gov Gate 8 cpp-safety (BLOCKING, policy floor): a bare std::thread left joinable when a
    // REQUIRE between here and the explicit join() throws (Catch2 unwinds via exception) calls
    // std::terminate() in ~thread(), crashing the whole test binary instead of failing red.
    // Not std::jthread — that exact substitution broke Apple Clang's libc++ once already in
    // this codebase (CLAUDE.md Gate 8 history) — a plain RAII join-guard is portable.
    struct JoinGuard {
        std::thread& t;
        ~JoinGuard() {
            if (t.joinable())
                t.join();
        }
    } join_guard{validator};

    // The concurrent validate() must still be blocked on the row lock — it must NOT have
    // raced ahead and read/written the row while the manual lock is held.
    CHECK(result_future.wait_for(std::chrono::milliseconds(300)) != std::future_status::ready);

    REQUIRE(locker_txn.commit());

    REQUIRE(result_future.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    REQUIRE(result_future.get().has_value());

    auto status = store.get_status();
    REQUIRE(status.has_value());
    CHECK(*status == "exceeded");
}

TEST_CASE("migrate_from_sqlite: a legacy acknowledged=true alert survives a second, "
          "conflicting backfill pass (gov Gate 4 unhappy-path UP-2 regression)",
          "[license_store][pg][backfill]") {
    // Defect this catches: the pre-fix backfill inserted alerts with ON CONFLICT ... DO
    // NOTHING, which left `acknowledged` entirely untouched on a conflict. Two replicas with
    // divergent legacy files — one recording an operator's real dismissal (acknowledged=true),
    // one not — would silently lose that dismissal if the unacknowledged copy backfilled
    // first, with no error and no log line naming the alerts table specifically.
    // `acknowledged` is write-once monotonic (acknowledge_alert() only ever sets it true), so
    // the fix ORs the two sides on conflict. This drives the unacknowledged pass FIRST — the
    // only arrival order that distinguishes the old DO-NOTHING behaviour (would leave it
    // false) from the fixed OR-merge (leaves it true).
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    LegacyLicenseFixture lic;
    lic.id = std::string(32, '4');
    lic.license_key_hash = std::string(64, 'c');
    lic.organization = "AckMerge Org";
    lic.seat_count = 5;
    lic.issued_at = 9000;
    lic.status = "active";
    lic.activated_at = 9000;

    LegacyAlertFixture alert;
    alert.license_id = lic.id;
    alert.alert_type = "expired";
    alert.message = "expired";
    alert.triggered_at = 9500;
    alert.acknowledged = false;

    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_license_ackmerge_first") / "license.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {lic}, {alert});
    REQUIRE(store.migrate_from_sqlite(first_path));

    alert.acknowledged = true; // a second, divergent legacy snapshot recording the dismissal
    auto second_path =
        yuzu::test::unique_temp_path("yuzu_test_license_ackmerge_second") / "license.db";
    std::filesystem::create_directories(second_path.parent_path());
    write_legacy_sqlite_db(second_path, {lic}, {alert});
    REQUIRE(store.migrate_from_sqlite(second_path));

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    REQUIRE(alerts->size() == 1);
    CHECK((*alerts)[0].acknowledged); // the true seen on either pass must stick
}

// ── Alerts ────────────────────────────────────────────────────────────────

TEST_CASE("acknowledge_alert flips the flag and is excluded from the unacknowledged filter",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto past = now_epoch() - 86400;
    REQUIRE(store.activate_license(make_license("Ack Org", 50, past), "KEY-ACK").has_value());
    REQUIRE(store.validate(10).has_value());

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    REQUIRE_FALSE(alerts->empty());
    auto alert_id = (*alerts)[0].id;
    CHECK_FALSE((*alerts)[0].acknowledged);

    auto acked = store.acknowledge_alert(alert_id);
    CHECK(acked.has_value());

    auto unacked = store.list_alerts(true);
    REQUIRE(unacked.has_value());
    for (const auto& a : *unacked)
        CHECK(a.id != alert_id);

    auto all = store.list_alerts(false);
    REQUIRE(all.has_value());
    bool found = false;
    for (const auto& a : *all) {
        if (a.id == alert_id) {
            CHECK(a.acknowledged);
            found = true;
        }
    }
    CHECK(found);
}

TEST_CASE("acknowledge_alert on an unknown id is not_found", "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.acknowledge_alert(99999);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().starts_with("not_found:"));
}

// ── Feature / seat / expiry checks ──────────────────────────────────────────

TEST_CASE("has_feature matches exactly, never a substring or superstring",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365;
    REQUIRE(store.activate_license(
                       make_license("Acme", 100, future, "enterprise", R"(["admin_read"])"),
                       "KEY-PARTIAL")
               .has_value());

    auto admin = store.has_feature("admin");
    REQUIRE(admin.has_value());
    CHECK_FALSE(*admin);
    auto admin_rw = store.has_feature("admin_read_write");
    REQUIRE(admin_rw.has_value());
    CHECK_FALSE(*admin_rw);
    auto admin_read = store.has_feature("admin_read");
    REQUIRE(admin_read.has_value());
    CHECK(*admin_read);
}

TEST_CASE("has_feature: empty feature and no license both report false, not an error",
          "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto empty_feature = store.has_feature("");
    REQUIRE(empty_feature.has_value());
    CHECK_FALSE(*empty_feature);

    auto no_license = store.has_feature("some_feature");
    REQUIRE(no_license.has_value());
    CHECK_FALSE(*no_license);
}

TEST_CASE("seat_count and days_remaining", "[license_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    SECTION("seat_count with no license is 0") {
        auto s = store.seat_count();
        REQUIRE(s.has_value());
        CHECK(*s == 0);
    }
    SECTION("seat_count reflects the active license") {
        auto future = now_epoch() + 86400 * 365;
        REQUIRE(
            store.activate_license(make_license("Acme", 250, future), "KEY-SEATS250").has_value());
        auto s = store.seat_count();
        REQUIRE(s.has_value());
        CHECK(*s == 250);
    }
    SECTION("days_remaining for a fixed-term license") {
        auto expires = now_epoch() + 86400 * 90; // exactly 90 days
        REQUIRE(store.activate_license(make_license("Acme", 100, expires), "KEY-90DAYS")
                   .has_value());
        auto d = store.days_remaining();
        REQUIRE(d.has_value());
        CHECK(*d >= 89); // 1-day tolerance for timing edge cases
        CHECK(*d <= 90);
    }
    SECTION("days_remaining for a perpetual license is 0") {
        REQUIRE(store.activate_license(make_license("Acme", 100, 0), "KEY-PERPETUAL")
                   .has_value());
        auto d = store.days_remaining();
        REQUIRE(d.has_value());
        CHECK(*d == 0);
    }
    SECTION("days_remaining with no license is 0") {
        auto d = store.days_remaining();
        REQUIRE(d.has_value());
        CHECK(*d == 0);
    }
}

// ── migrate_from_sqlite backfill contract (ADR-0009/0048) ───────────────────

TEST_CASE("migrate_from_sqlite: no legacy file stamps the sourceless marker, idempotently",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto missing = yuzu::test::unique_temp_path("yuzu_test_license_missing") / "license.db";
    CHECK(store.migrate_from_sqlite(missing));
    CHECK(store.migrate_from_sqlite(missing)); // second call is a no-op success
}

// THE regression test for the anti-pattern the fingerprint design closes (mirrors
// DeploymentStore's identical test): a sourceless (fileless) boot must never permanently block a
// LATER boot's real legacy data from a holder replica.
TEST_CASE("migrate_from_sqlite: a sourceless boot never blocks a later boot's real legacy data",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto missing_path =
        yuzu::test::unique_temp_path("yuzu_test_license_sourceless_first") / "license.db";
    REQUIRE(store.migrate_from_sqlite(missing_path));

    LegacyLicenseFixture legacy;
    legacy.id = "cccccccccccccccccccccccccccccccc";
    legacy.license_key_hash = "411586c0ebfa154ef4af3e0b5a90d4cf1103189288d7aa4e40d3e37d799ebc0d";
    legacy.organization = "Holder Replica Org";
    legacy.seat_count = 42;
    legacy.issued_at = 5000;
    legacy.expires_at = 0;
    legacy.edition = "enterprise";
    legacy.features_json = R"(["sso"])";
    legacy.status = "active";
    legacy.activated_at = 5000;
    auto holder_path =
        yuzu::test::unique_temp_path("yuzu_test_license_sourceless_second") / "license.db";
    std::filesystem::create_directories(holder_path.parent_path());
    write_legacy_sqlite_db(holder_path, {legacy}, {});

    REQUIRE(store.migrate_from_sqlite(holder_path));

    auto licenses = store.list_licenses();
    REQUIRE(licenses.has_value());
    REQUIRE(licenses->size() == 1);
    CHECK((*licenses)[0].organization == "Holder Replica Org");

    // A third boot against the SAME holder file is a no-op — no duplicate row.
    REQUIRE(store.migrate_from_sqlite(holder_path));
    auto again = store.list_licenses();
    REQUIRE(again.has_value());
    CHECK(again->size() == 1);
}

TEST_CASE("migrate_from_sqlite copies a populated legacy file (licenses + alerts) exactly once",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto legacy_path = yuzu::test::unique_temp_path("yuzu_test_license_populated") / "license.db";
    std::filesystem::create_directories(legacy_path.parent_path());

    LegacyLicenseFixture l1;
    l1.id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    l1.license_key_hash = "400075069c197bbcb0114c66fdcaefa53e224de63bbe58f67f9af54691c996fa";
    l1.organization = "Legacy A";
    l1.seat_count = 10;
    l1.issued_at = 1000;
    l1.expires_at = 0;
    l1.edition = "community";
    l1.features_json = "[]";
    l1.status = "active";
    l1.activated_at = 1000;

    LegacyLicenseFixture l2;
    l2.id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    l2.license_key_hash = "580e36de86fe5fde24c0d67de903eacf0531bedc5c7e15020580624bf3fbd2f5";
    l2.organization = "Legacy B";
    l2.seat_count = 20;
    l2.issued_at = 2000;
    l2.expires_at = 2500;
    l2.edition = "professional";
    l2.features_json = R"(["mfa"])";
    l2.status = "expired";
    l2.activated_at = 2000;

    LegacyAlertFixture a1;
    a1.license_id = l2.id;
    a1.alert_type = "expired";
    a1.message = "License 'b' has expired";
    a1.triggered_at = 2600;
    a1.acknowledged = false;

    write_legacy_sqlite_db(legacy_path, {l1, l2}, {a1});

    REQUIRE(store.migrate_from_sqlite(legacy_path));

    auto licenses = store.list_licenses();
    REQUIRE(licenses.has_value());
    CHECK(licenses->size() == 2);

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    REQUIRE(alerts->size() == 1);
    CHECK((*alerts)[0].license_id == l2.id);
    CHECK((*alerts)[0].alert_type == "expired");

    // Second call against the SAME populated file is a no-op (marker idempotency).
    REQUIRE(store.migrate_from_sqlite(legacy_path));
    auto again = store.list_licenses();
    REQUIRE(again.has_value());
    CHECK(again->size() == 2);
    auto alerts_again = store.list_alerts();
    REQUIRE(alerts_again.has_value());
    CHECK(alerts_again->size() == 1);
}

TEST_CASE("migrate_from_sqlite fails closed when a legacy license id already exists with "
          "different identity",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    const std::string shared_id = "dddddddddddddddddddddddddddddddd";

    LegacyLicenseFixture first;
    first.id = shared_id;
    first.license_key_hash = "231c3d94a2bd219956a1d6e98e6294f1cf21f2a0c49bf7d064ae94c4916eb23b";
    first.organization = "First Org";
    first.seat_count = 10;
    first.issued_at = 1000;
    first.status = "active";
    first.activated_at = 1000;
    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_license_conflict_first") / "license.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {first}, {});
    REQUIRE(store.migrate_from_sqlite(first_path));

    // Different overall content (different fingerprint) so this reaches the per-row conflict
    // path; DIFFERENT organization is an IDENTITY field.
    LegacyLicenseFixture second = first;
    second.organization = "Second Org (different identity)";
    second.seat_count = 99;
    auto second_path =
        yuzu::test::unique_temp_path("yuzu_test_license_conflict_second") / "license.db";
    std::filesystem::create_directories(second_path.parent_path());
    write_legacy_sqlite_db(second_path, {second}, {});

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(second_path));
        captured = capture.str();
    }
    CHECK(captured.find("different IDENTITY") != std::string::npos);

    // The original row survives unchanged.
    auto licenses = store.list_licenses();
    REQUIRE(licenses.has_value());
    REQUIRE(licenses->size() == 1);
    CHECK((*licenses)[0].organization == "First Org");

    // Retries fail the same way — the marker was not stamped.
    CHECK_FALSE(store.migrate_from_sqlite(second_path));
}

// Regression test for gov security-guardian HIGH: seat_count is IDENTITY (activate_license sets
// it once at INSERT, no other method mutates it — same write-once criterion as organization/
// edition/etc.) but was initially omitted from BOTH identity_matches and lifecycle_matches,
// so a legacy row differing ONLY in seat_count was misclassified as "identical content" and the
// legacy value silently discarded. Isolates seat_count as the ONLY differing field — every
// other identity-mismatch test in this file co-varies seat_count with another field, which
// would not have caught this gap.
TEST_CASE("migrate_from_sqlite fails closed when a legacy license's seat_count differs, even "
          "when every other column matches",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    const std::string shared_id = "2222222222222222222222222222222b";

    LegacyLicenseFixture first;
    first.id = shared_id;
    first.license_key_hash = "872583a7bea1528eca57638560cc4bd65cd1843bbf86b25b73798986d573d551";
    first.organization = "SeatCount Org";
    first.seat_count = 10;
    first.issued_at = 1000;
    first.status = "active";
    first.activated_at = 1000;
    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_license_seatcount_first") / "license.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {first}, {});
    REQUIRE(store.migrate_from_sqlite(first_path));

    // ONLY seat_count differs — every other IDENTITY field (organization/edition/etc.) and
    // every LIFECYCLE field (status/activated_at) is byte-identical to `first`.
    LegacyLicenseFixture second = first;
    second.seat_count = 500;
    auto second_path =
        yuzu::test::unique_temp_path("yuzu_test_license_seatcount_second") / "license.db";
    std::filesystem::create_directories(second_path.parent_path());
    write_legacy_sqlite_db(second_path, {second}, {});

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(second_path));
        captured = capture.str();
    }
    CHECK(captured.find("different IDENTITY") != std::string::npos);

    // The original row's seat_count survives unchanged — never silently overwritten OR
    // silently discarded as "identical".
    auto licenses = store.list_licenses();
    REQUIRE(licenses.has_value());
    REQUIRE(licenses->size() == 1);
    CHECK((*licenses)[0].seat_count == 10);

    CHECK_FALSE(store.migrate_from_sqlite(second_path)); // retries fail the same way
}

TEST_CASE("migrate_from_sqlite treats an identical-content id conflict as a benign no-op",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    LegacyLicenseFixture shared;
    shared.id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    shared.license_key_hash = "4013d508e12061815ff5cf8de84009f5fd622e47efe4426a19defc85f8407bd2";
    shared.organization = "Shared Org";
    shared.seat_count = 10;
    shared.issued_at = 3000;
    shared.status = "active";
    shared.activated_at = 3000;

    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_license_identical_first") / "license.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {shared}, {});
    REQUIRE(store.migrate_from_sqlite(first_path));

    // A superset file: the SAME shared row (byte-identical) plus a genuinely new one — different
    // overall fingerprint, so it reaches the per-row conflict path.
    LegacyLicenseFixture new_lic;
    new_lic.id = "ffffffffffffffffffffffffffffffff";
    new_lic.license_key_hash = "b8465df8db6bbd15016aa10533813ca96ea51eb75dca4f1b60ce98ebcc964d2c";
    new_lic.organization = "New Org";
    new_lic.seat_count = 5;
    new_lic.issued_at = 3001;
    new_lic.status = "active";
    new_lic.activated_at = 3001;
    auto superset_path =
        yuzu::test::unique_temp_path("yuzu_test_license_identical_superset") / "license.db";
    std::filesystem::create_directories(superset_path.parent_path());
    write_legacy_sqlite_db(superset_path, {shared, new_lic}, {});

    REQUIRE(store.migrate_from_sqlite(superset_path));

    auto licenses = store.list_licenses();
    REQUIRE(licenses.has_value());
    CHECK(licenses->size() == 2);
}

TEST_CASE("migrate_from_sqlite treats a LIFECYCLE-only difference as a benign no-op and keeps "
          "Postgres's live value",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    const std::string shared_id = "9999999999999999999999999999999a";

    LegacyLicenseFixture original;
    original.id = shared_id;
    original.license_key_hash = "c3dc727e8a4ba1916eab901de821194563abb8bb6408f7238e5d43b4397a5c82";
    original.organization = "Progressed Org";
    original.seat_count = 10;
    original.issued_at = 4000;
    original.expires_at = now_epoch() - 100; // already expired
    original.status = "active";              // legacy snapshot predates the expiry recompute
    original.activated_at = 4000;
    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_license_lifecycle_first") / "license.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {original}, {});
    REQUIRE(store.migrate_from_sqlite(first_path));

    // Live traffic on this replica advances the license past what the legacy snapshot shows.
    REQUIRE(store.validate(1).has_value());
    auto status = store.get_status();
    REQUIRE(status.has_value());
    CHECK(*status == "expired");

    // A second legacy file — different overall content (padding row), same shared id, SAME
    // identity, but its own lifecycle snapshot still shows 'active' (the pre-progress state).
    LegacyLicenseFixture stale_snapshot = original; // identity fields byte-identical
    LegacyLicenseFixture padding;
    padding.id = "8888888888888888888888888888888b";
    padding.license_key_hash = "2c5da24544a6a39f6d6b5681daff085fac91d8d27f3de348df5f465094356f49";
    padding.organization = "Padding Org";
    padding.seat_count = 5;
    padding.issued_at = 4001;
    padding.status = "active";
    padding.activated_at = 4001;
    auto second_path =
        yuzu::test::unique_temp_path("yuzu_test_license_lifecycle_second") / "license.db";
    std::filesystem::create_directories(second_path.parent_path());
    write_legacy_sqlite_db(second_path, {stale_snapshot, padding}, {});

    std::string captured;
    {
        LogCapture capture;
        CHECK(store.migrate_from_sqlite(second_path)); // succeeds — never fails closed
        captured = capture.str();
    }
    CHECK(captured.find("already migrated with lifecycle progress") != std::string::npos);

    // Postgres's live (more advanced) value survives untouched. Looked up by id, not
    // get_status() — `padding` has a LATER activated_at than `shared_id`, so get_status()'s
    // "most recently activated" semantics would read padding's status instead.
    auto licenses = store.list_licenses();
    REQUIRE(licenses.has_value());
    CHECK(licenses->size() == 2); // the genuinely new sibling row landed too
    bool found_shared = false;
    for (const auto& l : *licenses) {
        if (l.id == shared_id) {
            CHECK(l.status == "expired");
            found_shared = true;
        }
    }
    CHECK(found_shared);
}

TEST_CASE("migrate_from_sqlite fails closed when a legacy license's lifecycle is AHEAD of "
          "Postgres's current value",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    const std::string shared_id = "7777777777777777777777777777777c";

    LegacyLicenseFixture original;
    original.id = shared_id;
    original.license_key_hash = "ee063bbed55f3dcf976a57e62ecf07a9f46c7ae77e20d3f5875f3860e6d4ffe7";
    original.organization = "Rolled Back Org";
    original.seat_count = 10;
    original.issued_at = 5000;
    original.status = "active";
    original.activated_at = 5000;
    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_license_ahead_first") / "license.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {original}, {});
    REQUIRE(store.migrate_from_sqlite(first_path));

    // A second legacy file — same identity, but lifecycle AHEAD of Postgres's current 'active'
    // value: stands in for the pre-migration binary having expired the license while rolled
    // back, with Postgres never touched during that window.
    LegacyLicenseFixture rolled_back_progress = original;
    rolled_back_progress.status = "invalid"; // a terminal status Postgres never saw

    auto second_path =
        yuzu::test::unique_temp_path("yuzu_test_license_ahead_second") / "license.db";
    std::filesystem::create_directories(second_path.parent_path());
    write_legacy_sqlite_db(second_path, {rolled_back_progress}, {});

    CHECK_FALSE(store.migrate_from_sqlite(second_path));

    auto status = store.get_status();
    REQUIRE(status.has_value());
    CHECK(*status == "active"); // untouched — neither side silently adopted

    CHECK_FALSE(store.migrate_from_sqlite(second_path)); // retries fail the same way
}

TEST_CASE("migrate_from_sqlite fails closed when a legacy license reports a DIFFERENT terminal "
          "outcome than Postgres's current value, at the same lifecycle rank",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    const std::string shared_id = "6666666666666666666666666666666d";

    LegacyLicenseFixture original;
    original.id = shared_id;
    original.license_key_hash = "efae9fda6c7921adc73deed474d3e62e2efd31547f3c05bb82376e167ea52718";
    original.organization = "Diverged Org";
    original.seat_count = 5;
    original.issued_at = 6000;
    original.expires_at = now_epoch() + 86400 * 365;
    original.status = "active";
    original.activated_at = 6000;
    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_license_terminal_first") / "license.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {original}, {});
    REQUIRE(store.migrate_from_sqlite(first_path));

    // Postgres progresses to 'exceeded' via live traffic.
    REQUIRE(store.validate(100).has_value());
    auto status = store.get_status();
    REQUIRE(status.has_value());
    CHECK(*status == "exceeded");

    // A second legacy file — same identity, but reached a DIFFERENT terminal outcome
    // ('expired') than Postgres now holds ('exceeded'). Both rank 1 (tied), not "legacy ahead".
    LegacyLicenseFixture diverged = original;
    diverged.status = "expired";
    auto second_path =
        yuzu::test::unique_temp_path("yuzu_test_license_terminal_second") / "license.db";
    std::filesystem::create_directories(second_path.parent_path());
    write_legacy_sqlite_db(second_path, {diverged}, {});

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(second_path));
        captured = capture.str();
    }
    CHECK(captured.find("different terminal outcome") != std::string::npos);

    auto after = store.get_status();
    REQUIRE(after.has_value());
    CHECK(*after == "exceeded"); // untouched
}

TEST_CASE("migrate_from_sqlite fails closed on a legacy license with an unrecognised status, "
          "before ever reaching Postgres",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    LegacyLicenseFixture garbage;
    garbage.id = "5555555555555555555555555555555e";
    garbage.license_key_hash = "29b62fa4d56a4075b9e43cd90acecc8ebfc31bfb89737e39b76c5ef7e05f86cf";
    garbage.organization = "Corrupt Org";
    garbage.seat_count = 5;
    garbage.issued_at = 7000;
    garbage.status = "not-a-real-status"; // outside the 4 known values
    garbage.activated_at = 7000;
    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_license_bad_status") / "license.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_sqlite_db(legacy_path, {garbage}, {});

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
        captured = capture.str();
    }
    CHECK(captured.find("unrecognised status") != std::string::npos);

    auto licenses = store.list_licenses();
    REQUIRE(licenses.has_value());
    CHECK(licenses->empty()); // nothing landed
}

TEST_CASE("migrate_from_sqlite fails closed on a legacy alert with an unrecognised alert_type, "
          "before ever reaching Postgres",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    LegacyLicenseFixture lic;
    lic.id = "4444444444444444444444444444444f";
    lic.license_key_hash = "a8c68819511695b29e7feedfbc77cfe765d3c36d4f43e849767de7ebd119e776";
    lic.organization = "AlertType Org";
    lic.seat_count = 5;
    lic.issued_at = 8000;
    lic.status = "active";
    lic.activated_at = 8000;

    LegacyAlertFixture bad_alert;
    bad_alert.license_id = lic.id;
    bad_alert.alert_type = "not-a-real-alert-type";
    bad_alert.message = "garbage";
    bad_alert.triggered_at = 8100;

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_license_bad_alert_type") / "license.db";
    std::filesystem::create_directories(legacy_path.parent_path());
    write_legacy_sqlite_db(legacy_path, {lic}, {bad_alert});

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
        captured = capture.str();
    }
    CHECK(captured.find("unrecognised alert_type") != std::string::npos);

    // Nothing landed — including the license, since the whole transaction never even started.
    auto licenses = store.list_licenses();
    REQUIRE(licenses.has_value());
    CHECK(licenses->empty());
}

// Regression test for gov architect SHOULD (Gate 3): the Gate-2 security-guardian MEDIUM fix
// (is_valid_lowercase_hex gating legacy id/license_key_hash before either can reach Postgres)
// had no dedicated test. Both fixtures below use a VALID status — the status check runs BEFORE
// the hex checks in the scan loop (license_store.cpp), so an invalid-status fixture would trip
// that gate first and false-green this test.
TEST_CASE("migrate_from_sqlite fails closed on a legacy license with a malformed id or "
          "license_key_hash, before ever reaching Postgres",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    SECTION("id is not 32 lowercase hex chars") {
        LegacyLicenseFixture bad_id;
        bad_id.id = "not-a-valid-hex-id";
        bad_id.license_key_hash = std::string(64, '1'); // otherwise-valid 64-hex-char hash
        bad_id.organization = "BadId Org";
        bad_id.seat_count = 5;
        bad_id.issued_at = 9000;
        bad_id.status = "active"; // valid — isolates the id check
        bad_id.activated_at = 9000;
        auto path = yuzu::test::unique_temp_path("yuzu_test_license_bad_id") / "license.db";
        std::filesystem::create_directories(path.parent_path());
        write_legacy_sqlite_db(path, {bad_id}, {});

        std::string captured;
        {
            LogCapture capture;
            CHECK_FALSE(store.migrate_from_sqlite(path));
            captured = capture.str();
        }
        CHECK(captured.find("invalid id") != std::string::npos);
    }
    SECTION("license_key_hash is not 64 lowercase hex chars") {
        LegacyLicenseFixture bad_hash;
        bad_hash.id = std::string(32, '1'); // otherwise-valid 32-hex-char id
        bad_hash.license_key_hash = "not-a-valid-hex-hash";
        bad_hash.organization = "BadHash Org";
        bad_hash.seat_count = 5;
        bad_hash.issued_at = 9100;
        bad_hash.status = "active"; // valid — isolates the hash check
        bad_hash.activated_at = 9100;
        auto path = yuzu::test::unique_temp_path("yuzu_test_license_bad_hash") / "license.db";
        std::filesystem::create_directories(path.parent_path());
        write_legacy_sqlite_db(path, {bad_hash}, {});

        std::string captured;
        {
            LogCapture capture;
            CHECK_FALSE(store.migrate_from_sqlite(path));
            captured = capture.str();
        }
        CHECK(captured.find("invalid license_key_hash") != std::string::npos);
    }

    // Nothing landed under either malformed-fixture path.
    auto licenses = store.list_licenses();
    REQUIRE(licenses.has_value());
    CHECK(licenses->empty());
}

// ADR-0048-specific: the shipped pre-migration binary always creates `licenses` and
// `license_alerts` together, so a file holding exactly one is never a real fresh-install/
// upgrade artifact.
TEST_CASE("migrate_from_sqlite fails closed on a legacy file holding exactly one of the two "
          "expected tables",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    SECTION("licenses table present, license_alerts absent") {
        auto path = yuzu::test::unique_temp_path("yuzu_test_license_half_schema_a") /
                   "license.db";
        std::filesystem::create_directories(path.parent_path());
        write_legacy_sqlite_db(path, {}, {}, /*with_licenses_table=*/true,
                               /*with_alerts_table=*/false);
        CHECK_FALSE(store.migrate_from_sqlite(path));
    }
    SECTION("license_alerts table present, licenses absent") {
        auto path = yuzu::test::unique_temp_path("yuzu_test_license_half_schema_b") /
                   "license.db";
        std::filesystem::create_directories(path.parent_path());
        write_legacy_sqlite_db(path, {}, {}, /*with_licenses_table=*/false,
                               /*with_alerts_table=*/true);
        CHECK_FALSE(store.migrate_from_sqlite(path));
    }

    auto licenses = store.list_licenses();
    REQUIRE(licenses.has_value());
    CHECK(licenses->empty());
}

// license_alerts' UNIQUE(license_id, alert_type, triggered_at) backfill dedup (ADR-0048): an
// overlapping-but-differently-fingerprinted legacy snapshot must not duplicate an alert already
// migrated, since license_alerts.id is always freshly minted and can never be an ON CONFLICT
// target the way licenses.id is.
TEST_CASE("migrate_from_sqlite: an overlapping legacy alert snapshot dedups via the "
          "UNIQUE(license_id, alert_type, triggered_at) constraint",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    LegacyLicenseFixture lic;
    lic.id = "3333333333333333333333333333333a";
    lic.license_key_hash = "e1b9288decdda00a2d1ca03e8947b4bd404e831ad8647d66f471ee6eb847a626";
    lic.organization = "AlertDedup Org";
    lic.seat_count = 5;
    lic.issued_at = 9000;
    lic.status = "active";
    lic.activated_at = 9000;

    LegacyAlertFixture shared_alert;
    shared_alert.license_id = lic.id;
    shared_alert.alert_type = "expiry_warning";
    shared_alert.message = "shared alert";
    shared_alert.triggered_at = 9100;

    auto first_path =
        yuzu::test::unique_temp_path("yuzu_test_license_alert_dedup_first") / "license.db";
    std::filesystem::create_directories(first_path.parent_path());
    write_legacy_sqlite_db(first_path, {lic}, {shared_alert});
    REQUIRE(store.migrate_from_sqlite(first_path));

    // A second legacy file: same license (byte-identical -> benign IDENTITY/LIFECYCLE no-op),
    // the SAME alert (same license_id/alert_type/triggered_at), plus one genuinely new alert —
    // different overall fingerprint, so this reaches the per-row paths.
    LegacyAlertFixture new_alert;
    new_alert.license_id = lic.id;
    new_alert.alert_type = "seat_limit_warning";
    new_alert.message = "a genuinely new alert";
    new_alert.triggered_at = 9200;

    auto second_path =
        yuzu::test::unique_temp_path("yuzu_test_license_alert_dedup_second") / "license.db";
    std::filesystem::create_directories(second_path.parent_path());
    write_legacy_sqlite_db(second_path, {lic}, {shared_alert, new_alert});

    REQUIRE(store.migrate_from_sqlite(second_path));

    auto alerts = store.list_alerts();
    REQUIRE(alerts.has_value());
    // The shared alert must NOT be duplicated; the new one must land. Total: 2, not 3.
    CHECK(alerts->size() == 2);
    int shared_count = 0;
    for (const auto& a : *alerts) {
        if (a.alert_type == "expiry_warning" && a.triggered_at == 9100)
            ++shared_count;
    }
    CHECK(shared_count == 1);
}

TEST_CASE("migrate_from_sqlite aborts unstamped on a mid-scan legacy read failure",
          "[license_store][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, license_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    LicenseStore store{pool};
    REQUIRE(store.is_open());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_license_truncated") / "license.db";
    std::filesystem::create_directories(legacy_path.parent_path());

    std::vector<LegacyLicenseFixture> bulk;
    for (int i = 0; i < 3000; ++i) {
        LegacyLicenseFixture l;
        char idbuf[33];
        std::snprintf(idbuf, sizeof(idbuf), "%032x", i + 1);
        l.id = idbuf;
        // 64 lowercase hex chars, unique per row (60 zeros + a 4-hex-digit row index) — must
        // stay exactly 64 chars to satisfy is_valid_lowercase_hex's format validation.
        char hashbuf[65];
        std::snprintf(hashbuf, sizeof(hashbuf), "%060x%04x", 0, i);
        l.license_key_hash = hashbuf;
        l.organization = "bulk-org-" + std::to_string(i) + "-padding-for-size-xxxxxxxxxxxxxxx";
        l.seat_count = i;
        l.issued_at = 1000 + i;
        l.status = "active";
        l.activated_at = 1000 + i;
        bulk.push_back(std::move(l));
    }
    write_legacy_sqlite_db(legacy_path, bulk, {});

    auto full_size = std::filesystem::file_size(legacy_path);
    REQUIRE(full_size > 65536); // sanity: spans many SQLite pages

    // Corrupt a LATER region in place (same file length, no truncation — see
    // test_deployment_store.cpp's identical technique and its rationale) so the scan lands
    // several rows before sqlite3_step returns a non-SQLITE_DONE terminal code.
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
    // The full "legacy licenses scan aborted..." phrase, not just "scan aborted mid-read" (gov
    // quality-engineer NICE) — that shorter substring is shared with the license_alerts scan's
    // own abort message, so it wouldn't prove WHICH table's scan actually aborted. This fixture
    // has 3000 license rows and 0 alerts, so only the licenses-scan branch can fire.
    CHECK(captured.find("legacy licenses scan aborted mid-read") != std::string::npos);

    auto licenses = store.list_licenses();
    REQUIRE(licenses.has_value());
    CHECK(licenses->empty()); // no partial rows landed

    // A subsequent migrate_from_sqlite against a freshly-written, intact file succeeds — proving
    // the aborted pass never stamped the marker.
    auto intact_path = yuzu::test::unique_temp_path("yuzu_test_license_intact") / "license.db";
    std::filesystem::create_directories(intact_path.parent_path());
    write_legacy_sqlite_db(intact_path, {bulk.front()}, {});
    REQUIRE(store.migrate_from_sqlite(intact_path));

    auto after = store.list_licenses();
    REQUIRE(after.has_value());
    CHECK(after->size() == 1);
}
