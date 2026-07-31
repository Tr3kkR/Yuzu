// InventoryStore tests (ADR-0037): the generic per-source blob store's
// Postgres migration. Covers the authoritative read contract (degrade vs
// genuinely-absent vs found/empty), fail-soft ingest, delete_agent's
// empty-id guard, and the ADR-0009 first-boot backfill from a legacy SQLite
// `inventory.db` (idempotent, never clobbers a live row, fails closed on a
// broken legacy file).

#include <catch2/catch_test_macros.hpp>

#include "inventory_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <sqlite3.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using yuzu::server::InventoryQuery;
using yuzu::server::InventoryRecord;
using yuzu::server::InventoryStore;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every
// store-behaviour test clones an already-migrated database instead of
// re-running the migrations.
yuzu::test::PgTestTemplate inventory_tpl{"inventory", [](const std::string& dsn) {
                                             PgPool pool{{.conninfo = dsn, .size = 1}};
                                             InventoryStore store{pool};
                                             if (!store.is_open())
                                                 throw std::runtime_error(
                                                     "inventory template: store failed to migrate");
                                         }};

// One migrated clone and persistent pool for this file. Every case resets both
// mutable tables, avoiding repeated CREATE DATABASE and backend startup costs
// on the contended [pg] shard while preserving case isolation.
struct InventoryShared {
    yuzu::test::PostgresTestDb db{inventory_tpl};
    std::optional<PgPool> pool;
    InventoryShared() {
        REQUIRE(db.available());
        pool.emplace(PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};

InventoryShared& inventory_shared() {
    static InventoryShared shared;
    return shared;
}

void inventory_reset() {
    auto lease = inventory_shared().pool->acquire();
    REQUIRE(lease);
    auto trunc =
        pg::exec_params(lease.get(),
                        "TRUNCATE inventory_store.inventory_data, inventory_store.backfill_state "
                        "RESTART IDENTITY CASCADE",
                        std::vector<std::string>{});
    REQUIRE(trunc.status() == PGRES_COMMAND_OK);
}

#define INVENTORY_SHARED(store, pool)                                                              \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                              \
    inventory_reset();                                                                             \
    [[maybe_unused]] PgPool& pool = *inventory_shared().pool;                                      \
    InventoryStore store{pool};                                                                    \
    REQUIRE(store.is_open())

// Seed a legacy SQLite `inventory.db` with the pre-migration schema (matches
// the store's original CREATE TABLE) at `path`, containing `rows`.
void seed_legacy_db(const std::filesystem::path& path, const std::vector<InventoryRecord>& rows) {
    yuzu::server::SqliteDb db;
    REQUIRE(sqlite3_open_v2(path.string().c_str(), db.addr(),
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
    REQUIRE(sqlite3_exec(db.get(),
                         "CREATE TABLE inventory_data ("
                         "  agent_id TEXT NOT NULL,"
                         "  plugin TEXT NOT NULL,"
                         "  data_json TEXT NOT NULL DEFAULT '{}',"
                         "  collected_at INTEGER NOT NULL DEFAULT 0,"
                         "  PRIMARY KEY (agent_id, plugin));",
                         nullptr, nullptr, nullptr) == SQLITE_OK);
    for (const auto& r : rows) {
        yuzu::server::SqliteStmt stmt;
        REQUIRE(sqlite3_prepare_v2(db.get(),
                                   "INSERT INTO inventory_data (agent_id, plugin, data_json, "
                                   "collected_at) VALUES (?, ?, ?, ?)",
                                   -1, stmt.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(stmt.get(), 1, r.agent_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 2, r.plugin.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 3, r.data_json.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt.get(), 4, r.collected_at);
        REQUIRE(sqlite3_step(stmt.get()) == SQLITE_DONE);
    }
}

void seed_oversized_legacy_blob(const std::filesystem::path& path) {
    yuzu::server::SqliteDb db;
    REQUIRE(sqlite3_open_v2(path.string().c_str(), db.addr(), SQLITE_OPEN_READWRITE, nullptr) ==
            SQLITE_OK);
    // Generate the payload inside SQLite: the test does not need an 8 MiB
    // client-side std::string merely to prove the pre-copy guard.
    REQUIRE(sqlite3_exec(db.get(),
                         "INSERT INTO inventory_data "
                         "(agent_id, plugin, data_json, collected_at) VALUES "
                         "('legacy-oversized', 'custom_oversized', zeroblob(8388609), 600)",
                         nullptr, nullptr, nullptr) == SQLITE_OK);
}

// Wall-clock now, mirroring the store's internal `now_secs()` — used only to
// bound assertions on the store's own clamping, never to construct fixture
// data that would itself need clamping.
std::int64_t test_now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t legacy_agent_rows(const std::filesystem::path& path, std::string_view agent_id) {
    yuzu::server::SqliteDb db;
    REQUIRE(sqlite3_open_v2(path.string().c_str(), db.addr(), SQLITE_OPEN_READONLY, nullptr) ==
            SQLITE_OK);
    yuzu::server::SqliteStmt stmt;
    REQUIRE(sqlite3_prepare_v2(db.get(), "SELECT COUNT(*) FROM inventory_data WHERE agent_id = ?",
                               -1, stmt.addr(), nullptr) == SQLITE_OK);
    sqlite3_bind_text(stmt.get(), 1, agent_id.data(), static_cast<int>(agent_id.size()),
                      SQLITE_TRANSIENT);
    REQUIRE(sqlite3_step(stmt.get()) == SQLITE_ROW);
    return sqlite3_column_int64(stmt.get(), 0);
}

} // namespace

TEST_CASE("InventoryStore degrades (not empty) on a broken pool", "[inventory]") {
    // No live PG needed: an unreachable conninfo → the store never opens, and
    // every read reports a degrade, never a silent empty.
    PgPool pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1 dbname=x user=x", .size = 1}};
    InventoryStore store{pool};
    REQUIRE(!store.is_open());

    CHECK(!store.list_tables().has_value());
    CHECK(!store.query({}).has_value());
    CHECK(!store.get_agent_inventory("a").has_value());
    CHECK(!store.count().has_value());

    // Governance M1: the `truncated` out-param must be reset on the early
    // degrade return, not left at whatever the caller pre-set it to — a
    // stale `true` here would wrongly tell a from-inventory-query caller
    // "capped, refuse to materialise" on top of the already-reported degrade.
    bool truncated = true;
    CHECK(!store.query({}, &truncated).has_value());
    CHECK_FALSE(truncated);
    auto g = store.get("a", "p");
    CHECK(!g.has_value());
    CHECK(g.error() == yuzu::server::InventoryReadError::kDegraded);
    CHECK_FALSE(store.delete_agent("a")); // ingest/delete: fail-soft, false, no crash
    store.upsert("a", "p", "{}", 1);      // fail-soft: does not throw
    CHECK_FALSE(store.migrate_from_sqlite("/nonexistent/path/inventory.db")); // !open_ -> false
}

TEST_CASE("InventoryStore upsert/get/query/list_tables/count round-trip", "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);

    store.upsert("agent-1", "installed_software", R"({"n":1})", 1000);
    store.upsert("agent-1", "device_ci", R"({"n":2})", 1000);
    store.upsert("agent-2", "installed_software", R"({"n":3})", 2000);

    SECTION("get: found, absent, degrade-free") {
        auto found = store.get("agent-1", "installed_software");
        REQUIRE(found.has_value());
        REQUIRE(found->has_value());
        CHECK((*found)->data_json == R"({"n":1})");
        CHECK((*found)->collected_at == 1000);

        auto absent = store.get("agent-1", "no-such-plugin");
        REQUIRE(absent.has_value());      // not a degrade
        CHECK_FALSE(absent->has_value()); // genuinely no row
    }

    SECTION("upsert replaces an existing (agent_id, plugin) row") {
        store.upsert("agent-1", "installed_software", R"({"n":99})", 5000);
        auto found = store.get("agent-1", "installed_software");
        REQUIRE(found.has_value());
        REQUIRE(found->has_value());
        CHECK((*found)->data_json == R"({"n":99})");
        CHECK((*found)->collected_at == 5000);
    }

    SECTION("query filters by agent_id and plugin") {
        InventoryQuery q;
        q.agent_id = "agent-1";
        auto by_agent = store.query(q);
        REQUIRE(by_agent.has_value());
        CHECK(by_agent->size() == 2);

        InventoryQuery q2;
        q2.plugin = "installed_software";
        auto by_plugin = store.query(q2);
        REQUIRE(by_plugin.has_value());
        CHECK(by_plugin->size() == 2);
    }

    SECTION("get_agent_inventory returns all of one agent's rows") {
        auto rows = store.get_agent_inventory("agent-1");
        REQUIRE(rows.has_value());
        CHECK(rows->size() == 2);
    }

    SECTION("list_tables aggregates per-plugin agent counts") {
        auto tables = store.list_tables();
        REQUIRE(tables.has_value());
        bool found_installed = false;
        for (const auto& t : *tables) {
            if (t.plugin == "installed_software") {
                found_installed = true;
                CHECK(t.agent_count == 2); // agent-1 + agent-2
            }
        }
        CHECK(found_installed);
    }

    SECTION("count reflects total rows") {
        auto c = store.count();
        REQUIRE(c.has_value());
        CHECK(*c == 3);
    }

    SECTION("upsert rejects a blank agent_id/plugin (GDPR orphan guard, IS5/UP-7)") {
        store.upsert("", "installed_software", R"({"x":1})", 1000);
        store.upsert("agent-blank-plugin", "  ", R"({"x":1})", 1000);
        auto blank_id = store.get("", "installed_software");
        REQUIRE(blank_id.has_value());
        CHECK_FALSE(blank_id->has_value()); // never written
        auto blank_plugin = store.get_agent_inventory("agent-blank-plugin");
        REQUIRE(blank_plugin.has_value());
        CHECK(blank_plugin->empty());
    }

    SECTION("upsert never lets an older report overwrite a newer row (stale guard, IS6/UP-8)") {
        // agent-1/installed_software is already seeded at collected_at=1000.
        store.upsert("agent-1", "installed_software", R"({"n":"older"})", 500); // older: rejected
        auto after_older = store.get("agent-1", "installed_software");
        REQUIRE(after_older.has_value());
        REQUIRE(after_older->has_value());
        CHECK((*after_older)->data_json == R"({"n":1})");
        CHECK((*after_older)->collected_at == 1000);

        store.upsert("agent-1", "installed_software", R"({"n":"same-instant"})",
                     1000); // equal: still updates
        auto after_equal = store.get("agent-1", "installed_software");
        REQUIRE(after_equal.has_value());
        REQUIRE(after_equal->has_value());
        CHECK((*after_equal)->data_json == R"({"n":"same-instant"})");

        store.upsert("agent-1", "installed_software", R"({"n":"newer"})", 2000); // newer: updates
        auto after_newer = store.get("agent-1", "installed_software");
        REQUIRE(after_newer.has_value());
        REQUIRE(after_newer->has_value());
        CHECK((*after_newer)->data_json == R"({"n":"newer"})");
        CHECK((*after_newer)->collected_at == 2000);
    }

    SECTION("delete_agent: empty-id guard, commit status, idempotent") {
        CHECK_FALSE(store.delete_agent(""));
        auto still_there = store.get_agent_inventory("agent-1");
        REQUIRE(still_there.has_value());
        CHECK(still_there->size() == 2);

        CHECK(store.delete_agent("agent-1"));
        auto gone = store.get_agent_inventory("agent-1");
        REQUIRE(gone.has_value());
        CHECK(gone->empty());

        // Idempotent: a 0-row delete of an already-erased agent still commits.
        CHECK(store.delete_agent("agent-1"));

        // The bystander is untouched.
        auto bystander = store.get_agent_inventory("agent-2");
        REQUIRE(bystander.has_value());
        CHECK(bystander->size() == 1);
    }
}

TEST_CASE("InventoryStore upsert clamps a far-future collected_at to server receipt "
          "time and does not freeze the row (H2)",
          "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);

    const std::int64_t now_before = test_now_secs();
    const std::int64_t far_future = now_before + 10'000'000;

    store.upsert("agent-clamp", "installed_software", R"({"n":1})", far_future);
    const std::int64_t now_after = test_now_secs();

    // Read via both single-record `get` and the list-shaped
    // `get_agent_inventory` — the clamp must hold on both read paths.
    auto found = store.get("agent-clamp", "installed_software");
    REQUIRE(found.has_value());
    REQUIRE(found->has_value());
    CHECK((*found)->data_json == R"({"n":1})");
    CHECK((*found)->collected_at >= now_before);
    CHECK((*found)->collected_at <= now_after); // clamped, NOT the far-future value supplied

    auto rows = store.get_agent_inventory("agent-clamp");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK(rows->front().collected_at <= now_after);

    // The pre-clamp defect: a future-skewed row pinned itself forever because
    // every later HONEST report failed the stale-overwrite conflict
    // predicate (its real collected_at could never reach the far-future
    // stored value). With the clamp, an honest report at ~now for the same
    // (agent, plugin) must still land.
    store.upsert("agent-clamp", "installed_software", R"({"n":2})", 0 /* now */);
    auto landed = store.get("agent-clamp", "installed_software");
    REQUIRE(landed.has_value());
    REQUIRE(landed->has_value());
    CHECK((*landed)->data_json == R"({"n":2})"); // lands — the regression net for the freeze bug
}

TEST_CASE("InventoryStore upsert: an older report after a fresh one is suppressed and "
          "counted stale (H2 observability)",
          "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    store.upsert("agent-stale", "installed_software", R"({"n":"fresh"})", 10'000); // T
    store.upsert("agent-stale", "installed_software", R"({"n":"older"})", 9'900); // T-100: rejected

    auto row = store.get("agent-stale", "installed_software");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->data_json == R"({"n":"fresh"})"); // unchanged
    CHECK((*row)->collected_at == 10'000);

    CHECK(metrics.counter("yuzu_inventory_ingest_dropped_total", {{"reason", "stale"}}).value() ==
          1.0);
}

TEST_CASE("InventoryStore query: the truncated out-param signals a capped read (M1)",
          "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);

    store.upsert("agent-t1", "installed_software", R"({"n":1})", 1000);
    store.upsert("agent-t2", "installed_software", R"({"n":2})", 2000);
    store.upsert("agent-t3", "installed_software", R"({"n":3})", 3000);

    SECTION("limit below the row count returns the cap and sets truncated=true") {
        InventoryQuery q;
        q.limit = 2;
        bool truncated = false;
        auto rows = store.query(q, &truncated);
        REQUIRE(rows.has_value());
        CHECK(rows->size() == 2);
        CHECK(truncated);
    }

    SECTION("limit at/above the row count returns everything and resets truncated=false") {
        InventoryQuery q;
        q.limit = 5;
        bool truncated = true; // pre-set true to prove query() resets it, not just leaves it
        auto rows = store.query(q, &truncated);
        REQUIRE(rows.has_value());
        CHECK(rows->size() == 3);
        CHECK_FALSE(truncated);
    }
}

TEST_CASE("InventoryStore query: aggregate blob bytes are bounded before libpq materialises them",
          "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto seeded =
        pg::exec_params(lease.get(),
                        "INSERT INTO inventory_store.inventory_data "
                        "(agent_id, plugin, data_json, collected_at) "
                        "SELECT 'byte-agent-' || g, 'custom_large', repeat('x', 3145728), g "
                        "FROM generate_series(1, 3) AS g",
                        std::vector<std::string>{});
    REQUIRE(seeded.status() == PGRES_COMMAND_OK);
    lease.reset();

    InventoryQuery q;
    q.limit = 10;
    bool truncated = false;
    auto rows = store.query(q, &truncated);
    REQUIRE(rows.has_value());
    CHECK(truncated);
    CHECK(rows->size() == 2);
}

TEST_CASE("InventoryStore migrate_from_sqlite: no legacy file is a clean no-op",
          "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);

    CHECK(store.migrate_from_sqlite("/nonexistent/path/inventory.db"));
    auto c = store.count();
    REQUIRE(c.has_value());
    CHECK(*c == 0);

    // Idempotent: a second call (already stamped) is still a clean success.
    CHECK(store.migrate_from_sqlite("/nonexistent/path/inventory.db"));
}

TEST_CASE("InventoryStore migration upgrades published v2 and repairs the incomplete v3 state",
          "[pg][inventory][migration]") {
    // Migration tests deliberately use one private database rather than the
    // pre-migrated shared fixture: both scenarios rewrite schema_meta and DDL.
    // Reusing that one database keeps this regression cheap on the [pg] shard.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());

    const auto seed_historical_schema = [&](int version) {
        auto lease = pool.acquire();
        REQUIRE(lease);
        const auto exec = [&](const char* sql) {
            auto result = pg::exec_params(lease.get(), sql, std::vector<std::string>{});
            REQUIRE(result.status() == PGRES_COMMAND_OK);
        };

        exec("CREATE TABLE IF NOT EXISTS public.schema_meta ("
             "store TEXT PRIMARY KEY, version INTEGER NOT NULL, upgraded_at BIGINT NOT NULL)");
        exec("CREATE SCHEMA inventory_store");
        exec("CREATE TABLE inventory_store.inventory_data ("
             "agent_id TEXT NOT NULL, plugin TEXT NOT NULL, data_json TEXT NOT NULL DEFAULT '{}', "
             "collected_at BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (agent_id, plugin))");
        exec("CREATE INDEX inventory_data_plugin_idx "
             "ON inventory_store.inventory_data (plugin)");
        exec("CREATE INDEX inventory_data_collected_idx "
             "ON inventory_store.inventory_data (collected_at)");
        // Exact backfill_state shape published by v2 at 55ba45d8.
        exec("CREATE TABLE inventory_store.backfill_state ("
             "id INT PRIMARY KEY, migrated_at BIGINT NOT NULL, "
             "legacy_rows BIGINT NOT NULL DEFAULT 0)");
        if (version == 3) {
            // c21e330b can commit this v3 before the later stamp fails because
            // skipped_bad is absent. V4 must repair that already-recorded state.
            exec("ALTER TABLE inventory_store.backfill_state "
                 "ADD COLUMN source_rows BIGINT NOT NULL DEFAULT 0, "
                 "ADD COLUMN conflicts BIGINT NOT NULL DEFAULT 0, "
                 "ADD COLUMN skipped_blank_key BIGINT NOT NULL DEFAULT 0, "
                 "ADD COLUMN skipped_typed BIGINT NOT NULL DEFAULT 0");
        }
        auto meta = pg::exec_params(lease.get(),
                                    "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                                    "VALUES ('inventory_store', $1::int, 0)",
                                    std::vector<std::string>{std::to_string(version)});
        REQUIRE(meta.status() == PGRES_COMMAND_OK);
    };

    const auto require_upgrade_and_stamp = [&] {
        InventoryStore store{pool};
        REQUIRE(store.is_open());
        REQUIRE(store.migrate_from_sqlite("/nonexistent/path/inventory.db"));

        auto lease = pool.acquire();
        REQUIRE(lease);
        auto state = pg::exec_params(
            lease.get(),
            "SELECT m.version, COUNT(*) FILTER (WHERE c.column_name = 'skipped_bad'), "
            "(SELECT COUNT(*) FROM inventory_store.backfill_state WHERE id = 1) "
            "FROM public.schema_meta m "
            "JOIN information_schema.columns c ON c.table_schema = 'inventory_store' "
            "AND c.table_name = 'backfill_state' "
            "WHERE m.store = 'inventory_store' GROUP BY m.version",
            std::vector<std::string>{});
        REQUIRE(state.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(state.get()) == 1);
        CHECK(std::string(PQgetvalue(state.get(), 0, 0)) == "4");
        CHECK(std::string(PQgetvalue(state.get(), 0, 1)) == "1");
        CHECK(std::string(PQgetvalue(state.get(), 0, 2)) == "1");
    };

    seed_historical_schema(2);
    require_upgrade_and_stamp();

    // Reuse the same ephemeral database for the second historical state. The
    // store and all leases above are already out of scope, so no session owns
    // an object in the schema while it is replaced.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto drop = pg::exec_params(lease.get(), "DROP SCHEMA inventory_store CASCADE",
                                    std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
        auto forget = pg::exec_params(
            lease.get(), "DELETE FROM public.schema_meta WHERE store = 'inventory_store'",
            std::vector<std::string>{});
        REQUIRE(forget.status() == PGRES_COMMAND_OK);
    }

    seed_historical_schema(3);
    require_upgrade_and_stamp();
}

TEST_CASE("InventoryStore migrate_from_sqlite: backfills legacy rows, idempotent, "
          "never clobbers a live row",
          "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);

    yuzu::test::TempDbFile legacy{"yuzu_test_"};
    InventoryRecord r1;
    r1.agent_id = "legacy-agent-1";
    r1.plugin = "custom_source";
    r1.data_json = R"({"legacy":true})";
    r1.collected_at = 500;
    InventoryRecord r2;
    r2.agent_id = "legacy-agent-2";
    r2.plugin = "custom_other";
    r2.data_json = R"({"legacy":true})";
    r2.collected_at = 600;
    // Round-2 governance LOW: a legacy row written by a pre-clamp deployment
    // carries a far-future collected_at — the backfill's own INSERT must
    // clamp it too (`std::min(r.collected_at, now_secs())`), or this row
    // would survive the backfill and freeze out every later honest upsert
    // exactly like the pre-clamp ingest bug (H2).
    const std::int64_t now_before = test_now_secs();
    InventoryRecord r3;
    r3.agent_id = "legacy-agent-3";
    r3.plugin = "custom_future";
    r3.data_json = R"({"legacy":true})";
    r3.collected_at = now_before + 10'000'000;
    InventoryRecord typed;
    typed.agent_id = "legacy-typed";
    typed.plugin = "installed_software";
    typed.data_json = R"({"must_not_cross_securables":true})";
    typed.collected_at = 700;
    seed_legacy_db(legacy.path, {r1, r2, r3, typed});

    // A live agent has already reported for (legacy-agent-1, installed_software)
    // BEFORE the backfill runs — the backfill must never clobber it.
    store.upsert("legacy-agent-1", "custom_source", R"({"live":true})", 9000);

    REQUIRE(store.migrate_from_sqlite(legacy.path));

    auto live_row = store.get("legacy-agent-1", "custom_source");
    REQUIRE(live_row.has_value());
    REQUIRE(live_row->has_value());
    CHECK((*live_row)->data_json == R"({"live":true})"); // live row wins, not clobbered

    auto backfilled = store.get("legacy-agent-2", "custom_other");
    REQUIRE(backfilled.has_value());
    REQUIRE(backfilled->has_value());
    CHECK((*backfilled)->data_json == R"({"legacy":true})");
    CHECK((*backfilled)->collected_at == 600);

    const std::int64_t now_after = test_now_secs();
    auto clamped = store.get("legacy-agent-3", "custom_future");
    REQUIRE(clamped.has_value());
    REQUIRE(clamped->has_value());
    CHECK((*clamped)->data_json == R"({"legacy":true})");
    CHECK((*clamped)->collected_at <= now_after); // clamped, NOT the far-future value seeded
    CHECK((*clamped)->collected_at >= now_before);

    auto typed_row = store.get("legacy-typed", "installed_software");
    REQUIRE(typed_row.has_value());
    CHECK_FALSE(typed_row->has_value());

    // Whole-device erasure also reaches the retained rollback file, so a
    // rollback cannot resurrect data after a successful decommission.
    REQUIRE(legacy_agent_rows(legacy.path, "legacy-agent-2") == 1);
    REQUIRE(store.delete_agent("legacy-agent-2"));
    CHECK(legacy_agent_rows(legacy.path, "legacy-agent-2") == 0);
    auto erased = store.get("legacy-agent-2", "custom_other");
    REQUIRE(erased.has_value());
    CHECK_FALSE(erased->has_value());

    // Idempotent: a second call is a cheap no-op (already stamped) and does not
    // error or duplicate rows.
    REQUIRE(store.migrate_from_sqlite(legacy.path));
    auto c = store.count();
    REQUIRE(c.has_value());
    // live legacy-agent-1 + future-clamped legacy-agent-3; agent-2 was erased
    // from both stores and the typed source was never copied.
    CHECK(*c == 2);

    auto lease = pool.acquire();
    REQUIRE(lease);
    auto stamp = pg::exec_params(lease.get(),
                                 "SELECT legacy_rows, source_rows, conflicts, skipped_typed "
                                 "FROM inventory_store.backfill_state WHERE id = 1",
                                 std::vector<std::string>{});
    REQUIRE(stamp.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(stamp.get()) == 1);
    CHECK(std::string(PQgetvalue(stamp.get(), 0, 0)) == "2");
    CHECK(std::string(PQgetvalue(stamp.get(), 0, 1)) == "4");
    CHECK(std::string(PQgetvalue(stamp.get(), 0, 2)) == "1");
    CHECK(std::string(PQgetvalue(stamp.get(), 0, 3)) == "1");
}

TEST_CASE("InventoryStore migrate_from_sqlite fails closed on an unreadable legacy file",
          "[pg][inventory]") {
    INVENTORY_SHARED(store, pool);

    // A file that exists but is not a valid SQLite database — the legacy open/
    // prepare must fail, and the backfill must fail CLOSED (false), never
    // silently proceed as "nothing to backfill".
    yuzu::test::TempDbFile corrupt{"yuzu_test_"};
    {
        std::ofstream f(corrupt.path, std::ios::binary);
        f << "not a sqlite database";
    }
    CHECK_FALSE(store.migrate_from_sqlite(corrupt.path));
}

TEST_CASE("InventoryStore migrate_from_sqlite leaves no stamp or rows on retryable PG failure",
          "[pg][inventory]") {
    // DDL fault injection is deliberately isolated from the shared fixture:
    // TRUNCATE cannot remove a trigger, and randomized/filtered runs must not
    // inherit it.
    YUZU_REQUIRE_PG_DB_TPL(db, inventory_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    InventoryStore store{pool};
    REQUIRE(store.is_open());
    auto lease = pool.acquire();
    REQUIRE(lease);
    auto function =
        pg::exec_params(lease.get(),
                        "CREATE FUNCTION inventory_store.reject_infra_row() RETURNS trigger "
                        "LANGUAGE plpgsql AS $fn$ BEGIN "
                        "IF NEW.plugin = 'infra_fail' THEN "
                        "RAISE EXCEPTION 'injected cancellation' USING ERRCODE = '57014'; "
                        "END IF; RETURN NEW; END $fn$",
                        std::vector<std::string>{});
    REQUIRE(function.status() == PGRES_COMMAND_OK);
    auto trigger = pg::exec_params(
        lease.get(),
        "CREATE TRIGGER reject_infra_row BEFORE INSERT ON inventory_store.inventory_data "
        "FOR EACH ROW EXECUTE FUNCTION inventory_store.reject_infra_row()",
        std::vector<std::string>{});
    REQUIRE(trigger.status() == PGRES_COMMAND_OK);
    lease.reset();

    yuzu::test::TempDbFile legacy{"yuzu_test_"};
    seed_legacy_db(legacy.path, {{.agent_id = "good-before-failure",
                                  .plugin = "custom_good",
                                  .data_json = "{}",
                                  .collected_at = 1},
                                 {.agent_id = "injected-failure",
                                  .plugin = "infra_fail",
                                  .data_json = "{}",
                                  .collected_at = 2}});
    CHECK_FALSE(store.migrate_from_sqlite(legacy.path));

    auto check = pool.acquire();
    REQUIRE(check);
    auto state = pg::exec_params(check.get(),
                                 "SELECT (SELECT COUNT(*) FROM inventory_store.inventory_data), "
                                 "(SELECT COUNT(*) FROM inventory_store.backfill_state)",
                                 std::vector<std::string>{});
    REQUIRE(state.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(state.get()) == 1);
    CHECK(std::string(PQgetvalue(state.get(), 0, 0)) == "0");
    CHECK(std::string(PQgetvalue(state.get(), 0, 1)) == "0");
}

TEST_CASE("InventoryStore migrate_from_sqlite skips invalid, oversized, and blank-key rows "
          "without bricking boot — good rows still land",
          "[pg][inventory]") {
    // IB2/UP-1: InventoryStore is FAIL-SOFT/self-healing (the agent re-pushes), so
    // a single malformed legacy row must never abort the whole backfill/boot.
    INVENTORY_SHARED(store, pool);

    yuzu::test::TempDbFile legacy{"yuzu_test_"};
    InventoryRecord good;
    good.agent_id = "legacy-good";
    good.plugin = "custom_good";
    good.data_json = R"({"ok":true})";
    good.collected_at = 100;

    // Invalid-UTF-8 bytes (a lone continuation byte + overlong sequence) — SQLite
    // stores TEXT as raw bytes with no encoding validation, but Postgres's UTF8
    // client/server encoding validation rejects this on INSERT — the per-row
    // SAVEPOINT must recover from exactly this failure mode.
    InventoryRecord bad;
    bad.agent_id = "legacy-bad";
    bad.plugin = "custom_bad";
    bad.data_json = std::string("\xFF\xFE\xFA\xFB");
    bad.collected_at = 200;

    InventoryRecord blank_id;
    blank_id.agent_id = "";
    blank_id.plugin = "custom_blank_id";
    blank_id.data_json = R"({"orphan":true})";
    blank_id.collected_at = 300;

    InventoryRecord blank_plugin;
    blank_plugin.agent_id = "legacy-blank-plugin";
    blank_plugin.plugin = "";
    blank_plugin.data_json = R"({"orphan":true})";
    blank_plugin.collected_at = 400;

    InventoryRecord good2;
    good2.agent_id = "legacy-good-2";
    good2.plugin = "custom_good_2";
    good2.data_json = R"({"ok":true})";
    good2.collected_at = 500;

    // Bad/blank rows interleaved with good ones so the SAVEPOINT recovery must
    // actually resume the loop, not just tolerate a trailing failure.
    seed_legacy_db(legacy.path, {good, bad, blank_id, blank_plugin, good2});
    seed_oversized_legacy_blob(legacy.path);

    REQUIRE(store.migrate_from_sqlite(legacy.path)); // must NOT fail closed — no infra error

    auto g1 = store.get("legacy-good", "custom_good");
    REQUIRE(g1.has_value());
    REQUIRE(g1->has_value());
    CHECK((*g1)->data_json == R"({"ok":true})");

    auto g2 = store.get("legacy-good-2", "custom_good_2");
    REQUIRE(g2.has_value());
    REQUIRE(g2->has_value());

    auto bad_row = store.get("legacy-bad", "custom_bad");
    REQUIRE(bad_row.has_value());      // not a degrade
    CHECK_FALSE(bad_row->has_value()); // skipped, never landed

    auto blank_plugin_row = store.get_agent_inventory("legacy-blank-plugin");
    REQUIRE(blank_plugin_row.has_value());
    CHECK(blank_plugin_row->empty()); // skipped, never landed

    auto oversized = store.get("legacy-oversized", "custom_oversized");
    REQUIRE(oversized.has_value());
    CHECK_FALSE(oversized->has_value());

    auto c = store.count();
    REQUIRE(c.has_value());
    CHECK(*c == 2); // only two good rows; bad, oversized, and blank-key rows skipped

    // Governance H1: `skipped_bad` makes the row-data skip AUDITABLE after the
    // fact via `backfill_state`, independent of the in-memory counters above —
    // read it back over a second connection the way an operator/tool would.
    // Invalid UTF-8 and the oversized blob increment skipped_bad; the two
    // blank-key rows take the separate GDPR-orphan-guard path.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::PgResult stamp = pg::exec_params(
            lease.get(),
            "SELECT legacy_rows, skipped_bad, source_rows, conflicts, skipped_blank_key, "
            "skipped_typed FROM inventory_store.backfill_state WHERE id = 1",
            std::vector<std::string>{});
        REQUIRE(stamp.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(stamp.get()) == 1);
        CHECK(std::string(PQgetvalue(stamp.get(), 0, 0)) == "2"); // legacy_rows == good-row count
        CHECK(std::string(PQgetvalue(stamp.get(), 0, 1)) == "2"); // bad UTF-8 + oversized
        CHECK(std::string(PQgetvalue(stamp.get(), 0, 2)) == "6"); // every source row seen
        CHECK(std::string(PQgetvalue(stamp.get(), 0, 3)) == "0");
        CHECK(std::string(PQgetvalue(stamp.get(), 0, 4)) == "2");
        CHECK(std::string(PQgetvalue(stamp.get(), 0, 5)) == "0");
    }

    // Idempotent: a second call is a cheap no-op (already stamped).
    REQUIRE(store.migrate_from_sqlite(legacy.path));
    auto c2 = store.count();
    REQUIRE(c2.has_value());
    CHECK(*c2 == 2);
}
