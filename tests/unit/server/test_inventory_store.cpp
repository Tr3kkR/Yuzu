// InventoryStore tests (ADR-0037): the generic per-source blob store's
// Postgres migration. Covers the authoritative read contract (degrade vs
// genuinely-absent vs found/empty), fail-soft ingest, delete_agent's
// empty-id guard, and the ADR-0009 first-boot backfill from a legacy SQLite
// `inventory.db` (idempotent, never clobbers a live row, fails closed on a
// broken legacy file).

#include <catch2/catch_test_macros.hpp>

#include "inventory_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <sqlite3.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::InventoryQuery;
using yuzu::server::InventoryRecord;
using yuzu::server::InventoryStore;
using yuzu::server::pg::PgPool;

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every
// store-behaviour test clones an already-migrated database instead of
// re-running the migrations.
yuzu::test::PgTestTemplate inventory_tpl{"inventory", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    InventoryStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("inventory template: store failed to migrate");
}};

// Seed a legacy SQLite `inventory.db` with the pre-migration schema (matches
// the store's original CREATE TABLE) at `path`, containing `rows`.
void seed_legacy_db(const std::filesystem::path& path,
                    const std::vector<InventoryRecord>& rows) {
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open_v2(path.string().c_str(), &db,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
    REQUIRE(sqlite3_exec(db,
                         "CREATE TABLE inventory_data ("
                         "  agent_id TEXT NOT NULL,"
                         "  plugin TEXT NOT NULL,"
                         "  data_json TEXT NOT NULL DEFAULT '{}',"
                         "  collected_at INTEGER NOT NULL DEFAULT 0,"
                         "  PRIMARY KEY (agent_id, plugin));",
                         nullptr, nullptr, nullptr) == SQLITE_OK);
    for (const auto& r : rows) {
        sqlite3_stmt* stmt = nullptr;
        REQUIRE(sqlite3_prepare_v2(db,
                                   "INSERT INTO inventory_data (agent_id, plugin, data_json, "
                                   "collected_at) VALUES (?, ?, ?, ?)",
                                   -1, &stmt, nullptr) == SQLITE_OK);
        sqlite3_bind_text(stmt, 1, r.agent_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, r.plugin.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, r.data_json.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, r.collected_at);
        REQUIRE(sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
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
    auto g = store.get("a", "p");
    CHECK(!g.has_value());
    CHECK(g.error() == yuzu::server::InventoryReadError::kDegraded);
    CHECK_FALSE(store.delete_agent("a")); // ingest/delete: fail-soft, false, no crash
    store.upsert("a", "p", "{}", 1); // fail-soft: does not throw
    CHECK_FALSE(store.migrate_from_sqlite("/nonexistent/path/inventory.db")); // !open_ -> false
}

TEST_CASE("InventoryStore upsert/get/query/list_tables/count round-trip", "[pg][inventory]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inventory_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    InventoryStore store{pool};
    REQUIRE(store.is_open());

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
        REQUIRE(absent.has_value()); // not a degrade
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

TEST_CASE("InventoryStore migrate_from_sqlite: no legacy file is a clean no-op", "[pg][inventory]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inventory_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    InventoryStore store{pool};
    REQUIRE(store.is_open());

    CHECK(store.migrate_from_sqlite("/nonexistent/path/inventory.db"));
    auto c = store.count();
    REQUIRE(c.has_value());
    CHECK(*c == 0);

    // Idempotent: a second call (already stamped) is still a clean success.
    CHECK(store.migrate_from_sqlite("/nonexistent/path/inventory.db"));
}

TEST_CASE("InventoryStore migrate_from_sqlite: backfills legacy rows, idempotent, "
          "never clobbers a live row",
          "[pg][inventory]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inventory_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    InventoryStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_"};
    InventoryRecord r1;
    r1.agent_id = "legacy-agent-1";
    r1.plugin = "installed_software";
    r1.data_json = R"({"legacy":true})";
    r1.collected_at = 500;
    InventoryRecord r2;
    r2.agent_id = "legacy-agent-2";
    r2.plugin = "device_ci";
    r2.data_json = R"({"legacy":true})";
    r2.collected_at = 600;
    seed_legacy_db(legacy.path, {r1, r2});

    // A live agent has already reported for (legacy-agent-1, installed_software)
    // BEFORE the backfill runs — the backfill must never clobber it.
    store.upsert("legacy-agent-1", "installed_software", R"({"live":true})", 9000);

    REQUIRE(store.migrate_from_sqlite(legacy.path));

    auto live_row = store.get("legacy-agent-1", "installed_software");
    REQUIRE(live_row.has_value());
    REQUIRE(live_row->has_value());
    CHECK((*live_row)->data_json == R"({"live":true})"); // live row wins, not clobbered

    auto backfilled = store.get("legacy-agent-2", "device_ci");
    REQUIRE(backfilled.has_value());
    REQUIRE(backfilled->has_value());
    CHECK((*backfilled)->data_json == R"({"legacy":true})");
    CHECK((*backfilled)->collected_at == 600);

    // Idempotent: a second call is a cheap no-op (already stamped) and does not
    // error or duplicate rows.
    REQUIRE(store.migrate_from_sqlite(legacy.path));
    auto c = store.count();
    REQUIRE(c.has_value());
    CHECK(*c == 2); // legacy-agent-1/installed_software + legacy-agent-2/device_ci
}

TEST_CASE("InventoryStore migrate_from_sqlite fails closed on an unreadable legacy file",
          "[pg][inventory]") {
    YUZU_REQUIRE_PG_DB_TPL(db, inventory_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    InventoryStore store{pool};
    REQUIRE(store.is_open());

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

TEST_CASE("InventoryStore migrate_from_sqlite skips a bad row (invalid UTF-8) and a "
          "blank-key row without bricking boot — good rows still land",
          "[pg][inventory]") {
    // IB2/UP-1: InventoryStore is FAIL-SOFT/self-healing (the agent re-pushes), so
    // a single malformed legacy row must never abort the whole backfill/boot.
    YUZU_REQUIRE_PG_DB_TPL(db, inventory_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    InventoryStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_"};
    InventoryRecord good;
    good.agent_id = "legacy-good";
    good.plugin = "installed_software";
    good.data_json = R"({"ok":true})";
    good.collected_at = 100;

    // Invalid-UTF-8 bytes (a lone continuation byte + overlong sequence) — SQLite
    // stores TEXT as raw bytes with no encoding validation, but Postgres's UTF8
    // client/server encoding validation rejects this on INSERT — the per-row
    // SAVEPOINT must recover from exactly this failure mode.
    InventoryRecord bad;
    bad.agent_id = "legacy-bad";
    bad.plugin = "installed_software";
    bad.data_json = std::string("\xFF\xFE\xFA\xFB");
    bad.collected_at = 200;

    InventoryRecord blank_id;
    blank_id.agent_id = "";
    blank_id.plugin = "installed_software";
    blank_id.data_json = R"({"orphan":true})";
    blank_id.collected_at = 300;

    InventoryRecord blank_plugin;
    blank_plugin.agent_id = "legacy-blank-plugin";
    blank_plugin.plugin = "";
    blank_plugin.data_json = R"({"orphan":true})";
    blank_plugin.collected_at = 400;

    InventoryRecord good2;
    good2.agent_id = "legacy-good-2";
    good2.plugin = "device_ci";
    good2.data_json = R"({"ok":true})";
    good2.collected_at = 500;

    // Bad/blank rows interleaved with good ones so the SAVEPOINT recovery must
    // actually resume the loop, not just tolerate a trailing failure.
    seed_legacy_db(legacy.path, {good, bad, blank_id, blank_plugin, good2});

    REQUIRE(store.migrate_from_sqlite(legacy.path)); // must NOT fail closed — no infra error

    auto g1 = store.get("legacy-good", "installed_software");
    REQUIRE(g1.has_value());
    REQUIRE(g1->has_value());
    CHECK((*g1)->data_json == R"({"ok":true})");

    auto g2 = store.get("legacy-good-2", "device_ci");
    REQUIRE(g2.has_value());
    REQUIRE(g2->has_value());

    auto bad_row = store.get("legacy-bad", "installed_software");
    REQUIRE(bad_row.has_value()); // not a degrade
    CHECK_FALSE(bad_row->has_value()); // skipped, never landed

    auto blank_plugin_row = store.get_agent_inventory("legacy-blank-plugin");
    REQUIRE(blank_plugin_row.has_value());
    CHECK(blank_plugin_row->empty()); // skipped, never landed

    auto c = store.count();
    REQUIRE(c.has_value());
    CHECK(*c == 2); // only the two good rows — bad + both blank-key rows skipped

    // Idempotent: a second call is a cheap no-op (already stamped).
    REQUIRE(store.migrate_from_sqlite(legacy.path));
    auto c2 = store.count();
    REQUIRE(c2.has_value());
    CHECK(*c2 == 2);
}
