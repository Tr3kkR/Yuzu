/**
 * test_notification_store.cpp -- Unit tests for NotificationStore
 * (Postgres-backed, ADR-0006 Wave 2 migration, schema `notification_store`).
 *
 * Covers: lifecycle, create/list_unread/list_all/mark_read/dismiss/
 * count_unread, and the ADR-0009 mandatory migrate_from_sqlite backfill
 * (idempotency, id preservation + sequence advance, fail-closed on an
 * unreadable legacy file, and the holder-side-fingerprint verification
 * mechanism from docs/postgres-store-playbook.md "Local source absence
 * never creates terminal migration state on its own").
 */

#include "notification_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <sqlite3.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated template (docs/postgres-store-playbook.md step 7). Every
// store-behaviour case clones this instead of re-migrating per test.
yuzu::test::PgTestTemplate notif_tpl{"notifstore", [](const std::string& dsn) {
                                         PgPool pool{{.conninfo = dsn, .size = 1}};
                                         NotificationStore store{pool};
                                         if (!store.is_open())
                                             throw std::runtime_error(
                                                 "notification template: store failed to migrate");
                                     }};

// Legacy (pre-migration) SQLite schema — matches notification_store.cpp's
// pre-PG shape exactly (id/timestamp/level/title/message/read/dismissed).
// Explicit non-contiguous ids (5, 9) so the sequence-advance-past-max test
// below cannot pass by coincidentally starting at 1.
void make_legacy_notification_db(const std::filesystem::path& path) {
    SqliteDb db;
    REQUIRE(sqlite3_open_v2(path.string().c_str(), db.addr(),
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
    const char* ddl =
        "CREATE TABLE notifications ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  timestamp   INTEGER NOT NULL,"
        "  level       TEXT    NOT NULL DEFAULT 'info',"
        "  title       TEXT    NOT NULL,"
        "  message     TEXT    NOT NULL DEFAULT '',"
        "  read        INTEGER NOT NULL DEFAULT 0,"
        "  dismissed   INTEGER NOT NULL DEFAULT 0"
        ");"
        "INSERT INTO notifications (id, timestamp, level, title, message, read, dismissed) VALUES"
        "  (5, 1000, 'info', 'Agent connected', 'Agent abc123 registered successfully', 0, 0),"
        "  (9, 2000, 'warn', 'Disk space low', 'Volume C: at 92%', 1, 0);";
    SqliteErrMsg err;
    REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, err.addr()) == SQLITE_OK);
}

const Notification* find_title(const std::vector<Notification>& v, const std::string& title) {
    for (const auto& n : v)
        if (n.title == title)
            return &n;
    return nullptr;
}

} // namespace

// Fixture: a fresh cloned PG database, a pool, and an open NotificationStore.
// Expands to statements (includes the SKIP-if-no-DSN guard), so it must lead
// a block. The db/pool must outlive `store_var`; declaring all three here
// keeps that order.
#define NOTIFICATION_STORE(store_var)                                                             \
    YUZU_REQUIRE_PG_DB_TPL(notif_db_fx_, notif_tpl);                                               \
    PgPool notif_pool_fx_{{.conninfo = notif_db_fx_.dsn(), .size = 4}};                            \
    REQUIRE(notif_pool_fx_.valid());                                                               \
    NotificationStore store_var{notif_pool_fx_};                                                   \
    REQUIRE(store_var.is_open())

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: migrates and opens", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);
    CHECK(store.list_all().empty());
}

// ── Create and retrieve ────────────────────────────────────────────────────

TEST_CASE("NotificationStore: create and list_unread", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    auto id = store.create("info", "Agent connected", "Agent abc123 registered successfully");
    REQUIRE(id > 0);

    auto unread = store.list_unread();
    REQUIRE(unread.size() == 1);
    CHECK(unread[0].id == id);
    CHECK(unread[0].level == "info");
    CHECK(unread[0].title == "Agent connected");
    CHECK(unread[0].message == "Agent abc123 registered successfully");
    CHECK(unread[0].read == false);
    CHECK(unread[0].dismissed == false);
    CHECK(unread[0].timestamp > 0);
}

// ── Multiple notifications ─────────────────────────────────────────────────

TEST_CASE("NotificationStore: multiple creates and list_all", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    store.create("info", "First", "First message");
    store.create("warn", "Second", "Second message");
    store.create("error", "Third", "Third message");

    auto all = store.list_all();
    REQUIRE(all.size() == 3);
    // Newest first (ORDER BY ts_ms DESC, id DESC — inserted in this order,
    // same-millisecond ties broken by id).
    CHECK(all[0].title == "Third");
    CHECK(all[2].title == "First");
}

// ── Mark read ──────────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: mark_read removes from unread", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    auto id = store.create("info", "Test", "Test notification");
    REQUIRE(store.count_unread() == 1);

    CHECK(store.mark_read(id));

    auto unread = store.list_unread();
    CHECK(unread.empty());
    CHECK(store.count_unread() == 0);

    // Should still appear in list_all.
    auto all = store.list_all();
    REQUIRE(all.size() == 1);
    CHECK(all[0].read == true);
}

// ── Dismiss ────────────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: dismiss removes from unread", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    auto id = store.create("warn", "Alert", "Something happened");
    REQUIRE(store.count_unread() == 1);

    CHECK(store.dismiss(id));

    CHECK(store.count_unread() == 0);
    auto unread = store.list_unread();
    CHECK(unread.empty());
}

// Regression test for the fixed audit-integrity defect (adversarial-review,
// fjarvis): mark_read/dismiss must report whether the write actually
// affected a row, not just that the statement executed — an UPDATE against
// a nonexistent id returns PGRES_COMMAND_OK either way, and the REST layer
// relies on this return value to avoid asserting a "success" audit row for
// a mutation that never landed.
TEST_CASE("NotificationStore: mark_read and dismiss report false for a nonexistent id",
          "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    auto id = store.create("info", "Real notification", "exists");
    REQUIRE(id > 0);
    const int64_t bogus_id = id + 999999;

    CHECK_FALSE(store.mark_read(bogus_id));
    CHECK_FALSE(store.dismiss(bogus_id));

    // The real row is untouched by either no-op call.
    CHECK(store.count_unread() == 1);
    auto all = store.list_all();
    REQUIRE(all.size() == 1);
    CHECK(all[0].read == false);
    CHECK(all[0].dismissed == false);
}

// ── Count unread ───────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: count_unread tracks correctly", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    CHECK(store.count_unread() == 0);

    auto id1 = store.create("info", "A", "msg");
    auto id2 = store.create("info", "B", "msg");
    store.create("error", "C", "msg");

    CHECK(store.count_unread() == 3);

    CHECK(store.mark_read(id1));
    CHECK(store.count_unread() == 2);

    CHECK(store.dismiss(id2));
    CHECK(store.count_unread() == 1);
}

// ── Empty store ────────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: empty store returns empty lists", "[notification_store][pg]") {
    NOTIFICATION_STORE(store);

    CHECK(store.list_unread().empty());
    CHECK(store.list_all().empty());
    CHECK(store.count_unread() == 0);
}

// ── Backfill (ADR-0009, mandatory) ───────────────────────────────────────────

TEST_CASE("NotificationStore: migrate_from_sqlite returns false on an unopened store",
          "[notification_store][pg]") {
    PgPool bad{{.conninfo = "host=127.0.0.1 port=1 dbname=nope user=nope connect_timeout=1",
               .size = 1}};
    NotificationStore broken{bad};
    REQUIRE_FALSE(broken.is_open());
    CHECK_FALSE(broken.migrate_from_sqlite("/nonexistent/path/notifications.db"));
}

TEST_CASE("NotificationStore: migrate_from_sqlite with no legacy file is a clean idempotent no-op",
          "[notification_store][pg]") {
    NOTIFICATION_STORE(store);
    CHECK(store.migrate_from_sqlite("/nonexistent/path/notifications.db")); // fresh install
    CHECK(store.migrate_from_sqlite("/nonexistent/path/notifications.db")); // marker present -> no-op
    CHECK(store.list_all().empty());
}

TEST_CASE("NotificationStore: migrate_from_sqlite backfills legacy notifications, preserving ids, "
          "idempotently",
          "[notification_store][pg]") {
    NOTIFICATION_STORE(store);
    yuzu::test::TempDbFile legacy{"yuzu_test_notif_legacy-"};
    std::filesystem::remove(legacy.path);
    make_legacy_notification_db(legacy.path);

    REQUIRE(store.migrate_from_sqlite(legacy.path));

    auto all = store.list_all(100, 0);
    REQUIRE(all.size() == 2);
    const auto* connected = find_title(all, "Agent connected");
    REQUIRE(connected != nullptr);
    CHECK(connected->id == 5);
    CHECK(connected->timestamp == 1000);
    CHECK(connected->level == "info");
    CHECK(connected->message == "Agent abc123 registered successfully");
    CHECK(connected->read == false);
    CHECK(connected->dismissed == false);
    const auto* low_disk = find_title(all, "Disk space low");
    REQUIRE(low_disk != nullptr);
    CHECK(low_disk->id == 9);
    CHECK(low_disk->read == true);

    // Legacy file moved aside after a verified backfill.
    CHECK_FALSE(std::filesystem::exists(legacy.path));

    // Idempotent: a second call (marker present) is a no-op success, no
    // duplicate rows.
    CHECK(store.migrate_from_sqlite(legacy.path));
    CHECK(store.list_all().size() == 2);
}

TEST_CASE("NotificationStore: migrate_from_sqlite advances the id sequence past backfilled ids "
          "so a post-backfill create() cannot collide",
          "[notification_store][pg]") {
    NOTIFICATION_STORE(store);
    yuzu::test::TempDbFile legacy{"yuzu_test_notif_seq-"};
    std::filesystem::remove(legacy.path);
    make_legacy_notification_db(legacy.path); // ids 5, 9

    REQUIRE(store.migrate_from_sqlite(legacy.path));

    auto new_id = store.create("info", "Live one", "created after backfill");
    REQUIRE(new_id > 0);
    CHECK(new_id > 9);
    // No collision with either backfilled row.
    auto all = store.list_all();
    CHECK(all.size() == 3);
}

// Regression test for the fixed backfill data-loss defect (adversarial-review,
// HIGH — empirically reproduced against a live Postgres container): a bare
// `ON CONFLICT (id) DO NOTHING` only reports PGRES_COMMAND_OK whether the row
// landed or silently no-opped, so a stray/partial prior write at a legacy id
// could be dropped while the transaction still stamped completion. The fix is
// a pre-backfill emptiness check inside the SAME transaction as the row
// inserts — this seeds exactly that scenario (a row present with NO
// completion marker) and confirms the backfill refuses outright rather than
// silently proceeding.
TEST_CASE("NotificationStore: migrate_from_sqlite refuses to backfill when the table already "
          "holds a row with no completion marker present (adversarial-review regression)",
          "[notification_store][pg]") {
    NOTIFICATION_STORE(store);
    // Seed a stray row directly — simulating a partial/crashed prior write
    // that never reached the marker stamp.
    {
        auto lease = notif_pool_fx_.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO notification_store.notifications (ts_ms, level, title, message) "
            "VALUES (1, 'info', 'Stray pre-existing row', 'not part of any backfill')",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    yuzu::test::TempDbFile legacy{"yuzu_test_notif_conflict-"};
    std::filesystem::remove(legacy.path);
    make_legacy_notification_db(legacy.path); // ids 5, 9

    CHECK_FALSE(store.migrate_from_sqlite(legacy.path));
    // Refused, not silently accepted OR partially migrated — only the
    // pre-seeded stray row exists, neither legacy row landed.
    auto all = store.list_all();
    REQUIRE(all.size() == 1);
    CHECK(all[0].title == "Stray pre-existing row");
    // Legacy file untouched on refusal.
    CHECK(std::filesystem::exists(legacy.path));
}

TEST_CASE("NotificationStore: migrate_from_sqlite fails closed on an unreadable legacy file",
          "[notification_store][pg]") {
    NOTIFICATION_STORE(store);
    yuzu::test::TempDbFile corrupt{"yuzu_test_notif_corrupt-"};
    {
        std::ofstream f(corrupt.path, std::ios::binary | std::ios::trunc);
        REQUIRE(f.is_open());
        f << "not a valid sqlite database at all";
    }
    CHECK_FALSE(store.migrate_from_sqlite(corrupt.path));
    // No marker stamped -> a later boot with a repaired/absent file retries
    // and can still complete (proves the failure did not stamp the marker).
    CHECK(store.migrate_from_sqlite("/nonexistent/notifications.db"));
}

TEST_CASE("NotificationStore: migrate_from_sqlite verifies a matching fingerprint when this "
          "replica's own already-migrated legacy file is still present",
          "[notification_store][pg]") {
    NOTIFICATION_STORE(store);
    yuzu::test::TempDbFile legacy{"yuzu_test_notif_fp_match-"};
    std::filesystem::remove(legacy.path);
    make_legacy_notification_db(legacy.path);
    REQUIRE(store.migrate_from_sqlite(legacy.path));
    CHECK_FALSE(std::filesystem::exists(legacy.path)); // moved aside as usual

    // Recreate a file with IDENTICAL logical content at the same path —
    // simulating a failed move-aside on a real restart.
    make_legacy_notification_db(legacy.path);
    NotificationStore reopened{notif_pool_fx_};
    REQUIRE(reopened.is_open());
    CHECK(reopened.migrate_from_sqlite(legacy.path));
    // Verified, not re-migrated: still exactly 2 rows.
    CHECK(reopened.list_all().size() == 2);
    // The matched-fingerprint branch retries move_legacy_aside.
    CHECK_FALSE(std::filesystem::exists(legacy.path));
}

TEST_CASE("NotificationStore: migrate_from_sqlite refuses a HOLDER-SIDE fingerprint mismatch "
          "(some other replica's legacy data was migrated, not this one's)",
          "[notification_store][pg]") {
    NOTIFICATION_STORE(store);
    yuzu::test::TempDbFile legacy_a{"yuzu_test_notif_holder_a-"};
    std::filesystem::remove(legacy_a.path);
    make_legacy_notification_db(legacy_a.path);
    REQUIRE(store.migrate_from_sqlite(legacy_a.path)); // stamps fingerprint(A)

    NotificationStore replica_b{notif_pool_fx_};
    REQUIRE(replica_b.is_open());
    yuzu::test::TempDbFile legacy_b{"yuzu_test_notif_holder_b-"};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_b.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        const char* ddl =
            "CREATE TABLE notifications ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL,"
            "  level TEXT NOT NULL DEFAULT 'info', title TEXT NOT NULL,"
            "  message TEXT NOT NULL DEFAULT '', read INTEGER NOT NULL DEFAULT 0,"
            "  dismissed INTEGER NOT NULL DEFAULT 0);"
            "INSERT INTO notifications (id, timestamp, level, title, message, read, dismissed) "
            "VALUES (1, 42, 'error', 'A completely different legacy file', 'content B', 0, 0);";
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, err.addr()) == SQLITE_OK);
    }

    // Refused, not silently accepted OR silently re-migrated.
    CHECK_FALSE(replica_b.migrate_from_sqlite(legacy_b.path));
    CHECK(std::filesystem::exists(legacy_b.path));
    // Store B's own view still reflects replica A's migrated content only.
    CHECK(replica_b.list_all().size() == 2);
}

TEST_CASE("NotificationStore: migrate_from_sqlite refuses a sourceless sibling's marker on a "
          "later boot even though this replica genuinely holds the legacy file",
          "[notification_store][pg]") {
    NOTIFICATION_STORE(store);
    // "Replica A" — no local legacy file, stamps the shared marker sourceless.
    CHECK(store.migrate_from_sqlite("/nonexistent/path/notifications.db"));

    // "Replica B" — same shared Postgres, genuinely holds a legacy file with
    // real content, boots AFTER the marker was already stamped sourceless.
    NotificationStore replica_b{notif_pool_fx_};
    REQUIRE(replica_b.is_open());
    yuzu::test::TempDbFile legacy{"yuzu_test_notif_sourceless_race-"};
    std::filesystem::remove(legacy.path);
    make_legacy_notification_db(legacy.path);

    CHECK_FALSE(replica_b.migrate_from_sqlite(legacy.path));
    CHECK(std::filesystem::exists(legacy.path));
    CHECK(replica_b.list_all().empty());
}
