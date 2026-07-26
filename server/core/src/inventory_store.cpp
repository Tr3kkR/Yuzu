#include "inventory_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <system_error>
#include <utility>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "inventory_store";

// Bounded acquires (ADR-0012 lease discipline). Ingest runs on the gRPC/
// gateway thread so it must give up fast on a saturated pool — best-effort,
// the agent's next report re-sends the same blob. Reads get a longer budget
// since they back interactive REST/MCP/dashboard callers.
constexpr std::chrono::milliseconds kIngestAcquireTimeout{500};
constexpr std::chrono::milliseconds kQueryAcquireTimeout{3000};
// Hard ceiling on rows a single query will materialise, independent of the
// caller's `limit`, so the store can never allocate an unbounded result set.
constexpr int kQueryRowCap = 100000;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so these tables land in `inventory_store`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE inventory_data ("
         "  agent_id     TEXT NOT NULL,"
         "  plugin       TEXT NOT NULL,"
         "  data_json    TEXT NOT NULL DEFAULT '{}',"
         "  collected_at BIGINT NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (agent_id, plugin));"
         "CREATE INDEX inventory_data_plugin_idx ON inventory_data (plugin);"
         "CREATE INDEX inventory_data_collected_idx ON inventory_data (collected_at);"},
        {2,
         // Backfill stamp (ADR-0009/0037): a single-row sentinel so
         // migrate_from_sqlite() is a cheap no-op on every boot after the
         // first. `legacy_rows` is a diagnostic breadcrumb, not load-bearing.
         "CREATE TABLE backfill_state ("
         "  id           INT PRIMARY KEY,"
         "  migrated_at  BIGINT NOT NULL,"
         "  legacy_rows  BIGINT NOT NULL DEFAULT 0);"},
    };
    return kMigrations;
}

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Parse a Postgres text-format integer cell into int64 (count(*)/MAX()/etc.
// are text on the wire). Mirrors SoftwareInventoryStore::result_i64.
std::int64_t result_i64(const pg::PgResult& res, int row, int col) {
    const char* txt = PQgetvalue(res.get(), row, col);
    const auto len = static_cast<std::size_t>(PQgetlength(res.get(), row, col));
    std::int64_t v = 0;
    std::from_chars(txt, txt + len, v); // leaves v=0 on parse failure/NULL
    return v;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

InventoryStore::InventoryStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("InventoryStore: no database connection at construction ({}) — generic "
                      "inventory persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("InventoryStore: schema migration failed — generic inventory persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

// ── Backfill (ADR-0009/0037) ─────────────────────────────────────────────────

bool InventoryStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    // Idempotency check on a short-lived lease, released BEFORE any legacy
    // SQLite I/O or the write transaction below — holding two connections
    // from this call at once would deadlock a size-1 pool (e.g. a test pool).
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("InventoryStore: migrate_from_sqlite: no database connection ({})",
                          pool_.last_error());
            return false;
        }
        pg::PgResult stamp_check = pg::exec_params(
            lease.get(), "SELECT 1 FROM inventory_store.backfill_state WHERE id = 1",
            std::vector<std::string>{});
        if (stamp_check.status() != PGRES_TUPLES_OK) {
            spdlog::error("InventoryStore: migrate_from_sqlite: backfill_state lookup failed: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        if (PQntuples(stamp_check.get()) > 0) {
            spdlog::debug("InventoryStore: migrate_from_sqlite already completed, skipping");
            return true;
        }
    }

    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("InventoryStore: migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        return false;
    }

    struct LegacyRow {
        std::string agent_id;
        std::string plugin;
        std::string data_json;
        std::int64_t collected_at{0};
    };
    std::vector<LegacyRow> legacy_rows;

    if (legacy_exists) {
        sqlite3* legacy = nullptr;
        // READONLY: the legacy file is retained as a read-only rollback net
        // for one release (ADR-0009) — this call never writes to it.
        if (sqlite3_open_v2(legacy_db_path.string().c_str(), &legacy, SQLITE_OPEN_READONLY,
                            nullptr) != SQLITE_OK) {
            spdlog::error("InventoryStore: migrate_from_sqlite: failed to open legacy db {}: {}",
                          legacy_db_path.string(), legacy ? sqlite3_errmsg(legacy) : "open failed");
            if (legacy)
                sqlite3_close(legacy);
            return false;
        }

        sqlite3_stmt* stmt = nullptr;
        const char* sql = "SELECT agent_id, plugin, data_json, collected_at FROM inventory_data";
        if (sqlite3_prepare_v2(legacy, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            spdlog::error("InventoryStore: migrate_from_sqlite: legacy prepare failed: {}",
                          sqlite3_errmsg(legacy));
            sqlite3_close(legacy);
            return false;
        }

        auto col_text = [&](int i) {
            auto p = sqlite3_column_text(stmt, i);
            return p ? std::string(reinterpret_cast<const char*>(p)) : std::string{};
        };

        int rc = SQLITE_DONE;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            LegacyRow r;
            r.agent_id = col_text(0);
            r.plugin = col_text(1);
            r.data_json = col_text(2);
            r.collected_at = sqlite3_column_int64(stmt, 3);
            legacy_rows.push_back(std::move(r));
        }
        const bool read_ok = (rc == SQLITE_DONE);
        sqlite3_finalize(stmt);
        sqlite3_close(legacy);
        if (!read_ok) {
            spdlog::error("InventoryStore: migrate_from_sqlite: legacy read failed (rc={})", rc);
            return false;
        }
    }

    // One transaction: insert every legacy row (ON CONFLICT DO NOTHING — a
    // live agent may have already re-reported since this boot started, and
    // that live row must win, never be clobbered by a stale legacy copy)
    // then stamp completion, atomically. A one-time cost (row-by-row insert
    // is fine for a boot-time backfill of this scale; a fleet-scale batched
    // insert is the follow-up if a future fleet's legacy table proves large).
    const auto rows_copied = static_cast<std::int64_t>(legacy_rows.size());
    const bool ok = pool_.with_txn([&](PGconn* c) -> bool {
        for (const auto& r : legacy_rows) {
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO inventory_store.inventory_data "
                "(agent_id, plugin, data_json, collected_at) "
                "VALUES ($1, $2, $3, $4::bigint) ON CONFLICT (agent_id, plugin) DO NOTHING",
                std::vector<std::string>{r.agent_id, r.plugin, r.data_json,
                                         std::to_string(r.collected_at)});
            if (ins.status() != PGRES_COMMAND_OK)
                return false;
        }
        pg::PgResult stamp = pg::exec_params(
            c,
            "INSERT INTO inventory_store.backfill_state (id, migrated_at, legacy_rows) "
            "VALUES (1, $1::bigint, $2::bigint) ON CONFLICT (id) DO NOTHING",
            std::vector<std::string>{std::to_string(now_secs()), std::to_string(rows_copied)});
        return stamp.status() == PGRES_COMMAND_OK;
    });
    if (!ok) {
        spdlog::error("InventoryStore: migrate_from_sqlite: backfill transaction failed for {}",
                      legacy_db_path.string());
        return false;
    }

    spdlog::info("InventoryStore: migrate_from_sqlite backfilled {} legacy row(s) from {}",
                 rows_copied, legacy_db_path.string());
    return true;
}

// ── Upsert (fail-soft ingest) ────────────────────────────────────────────────

void InventoryStore::upsert(const std::string& agent_id, const std::string& plugin,
                            const std::string& data_json, int64_t collected_at) {
    if (collected_at == 0)
        collected_at = now_secs();
    if (!open_) {
        spdlog::warn("InventoryStore: upsert skipped for agent={} plugin={}, store not open",
                     agent_id, plugin);
        return;
    }
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease) {
        spdlog::warn("InventoryStore: upsert skipped for agent={} plugin={}, no connection ({})",
                     agent_id, plugin, pool_.last_error());
        return;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO inventory_store.inventory_data (agent_id, plugin, data_json, collected_at) "
        "VALUES ($1, $2, $3, $4::bigint) "
        "ON CONFLICT (agent_id, plugin) DO UPDATE SET "
        "data_json = EXCLUDED.data_json, collected_at = EXCLUDED.collected_at",
        std::vector<std::string>{agent_id, plugin, data_json, std::to_string(collected_at)});
    if (res.status() != PGRES_COMMAND_OK)
        spdlog::warn("InventoryStore: upsert failed for agent={} plugin={}: {}", agent_id, plugin,
                     PQerrorMessage(lease.get()));
}

// ── List tables (authoritative read) ─────────────────────────────────────────

std::optional<std::vector<InventoryTable>> InventoryStore::list_tables() const {
    if (!open_) {
        spdlog::warn("InventoryStore: list_tables degraded — store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::warn("InventoryStore: list_tables degraded — no connection ({})",
                     pool_.last_error());
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT plugin, COUNT(DISTINCT agent_id) AS agent_count, "
        "MAX(collected_at) AS last_collected "
        "FROM inventory_store.inventory_data GROUP BY plugin ORDER BY plugin",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("InventoryStore: list_tables degraded — query failed: {}",
                     PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    std::vector<InventoryTable> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        InventoryTable t;
        t.plugin = PQgetvalue(res.get(), i, 0);
        t.agent_count = result_i64(res, i, 1);
        t.last_collected = result_i64(res, i, 2);
        out.push_back(std::move(t));
    }
    return out;
}

// ── Get single record (authoritative, three-state) ──────────────────────────

std::expected<std::optional<InventoryRecord>, InventoryReadError>
InventoryStore::get(const std::string& agent_id, const std::string& plugin) const {
    if (!open_) {
        spdlog::warn("InventoryStore: get degraded — store not open");
        return std::unexpected(InventoryReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::warn("InventoryStore: get degraded — no connection ({})", pool_.last_error());
        return std::unexpected(InventoryReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, plugin, data_json, collected_at "
        "FROM inventory_store.inventory_data WHERE agent_id = $1 AND plugin = $2",
        std::vector<std::string>{agent_id, plugin});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("InventoryStore: get degraded — query failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(InventoryReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<InventoryRecord>{std::nullopt}; // genuinely absent, not a degrade

    InventoryRecord r;
    r.agent_id = PQgetvalue(res.get(), 0, 0);
    r.plugin = PQgetvalue(res.get(), 0, 1);
    r.data_json = PQgetvalue(res.get(), 0, 2);
    r.collected_at = result_i64(res, 0, 3);
    return std::optional<InventoryRecord>{std::move(r)};
}

// ── Query (authoritative read) ───────────────────────────────────────────────

std::optional<std::vector<InventoryRecord>> InventoryStore::query(const InventoryQuery& q) const {
    if (!open_) {
        spdlog::warn("InventoryStore: query degraded — store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::warn("InventoryStore: query degraded — no connection ({})", pool_.last_error());
        return std::nullopt;
    }

    int limit = q.limit > 0 ? q.limit : 100;
    if (limit > kQueryRowCap)
        limit = kQueryRowCap;
    const int offset = q.offset > 0 ? q.offset : 0;

    std::string sql =
        "SELECT agent_id, plugin, data_json, collected_at FROM inventory_store.inventory_data "
        "WHERE 1=1";
    std::vector<std::string> params;
    int p = 0;
    if (!q.agent_id.empty()) {
        sql += " AND agent_id = $" + std::to_string(++p);
        params.push_back(q.agent_id);
    }
    if (!q.plugin.empty()) {
        sql += " AND plugin = $" + std::to_string(++p);
        params.push_back(q.plugin);
    }
    if (q.since > 0) {
        sql += " AND collected_at >= $" + std::to_string(++p) + "::bigint";
        params.push_back(std::to_string(q.since));
    }
    if (q.until > 0) {
        sql += " AND collected_at <= $" + std::to_string(++p) + "::bigint";
        params.push_back(std::to_string(q.until));
    }
    sql += " ORDER BY collected_at DESC LIMIT $" + std::to_string(++p) + "::bigint OFFSET $" +
           std::to_string(++p) + "::bigint";
    params.push_back(std::to_string(limit));
    params.push_back(std::to_string(offset));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("InventoryStore: query degraded — query failed: {}", PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    std::vector<InventoryRecord> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        InventoryRecord r;
        r.agent_id = PQgetvalue(res.get(), i, 0);
        r.plugin = PQgetvalue(res.get(), i, 1);
        r.data_json = PQgetvalue(res.get(), i, 2);
        r.collected_at = result_i64(res, i, 3);
        out.push_back(std::move(r));
    }
    return out;
}

// ── Get agent inventory (delegates to query) ─────────────────────────────────

std::optional<std::vector<InventoryRecord>> InventoryStore::get_agent_inventory(
    const std::string& agent_id) const {
    InventoryQuery q;
    q.agent_id = agent_id;
    q.limit = 1000;
    return query(q);
}

// ── Delete agent ──────────────────────────────────────────────────────────────

bool InventoryStore::delete_agent(const std::string& agent_id) {
    // Empty-id guard, matching every sibling PG store: never run a
    // `DELETE ... WHERE agent_id = ''` (a footgun, never a fleet wipe). The
    // decommission cascade already short-circuits an empty id to all-Skipped,
    // but guarding here keeps that safety local to the store.
    if (agent_id.empty())
        return false;
    if (!open_) {
        spdlog::debug("InventoryStore: delete_agent skipped for agent={}, store not open",
                      agent_id);
        return false;
    }
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease) {
        spdlog::debug("InventoryStore: delete_agent skipped for agent={}, no connection ({})",
                      agent_id, pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM inventory_store.inventory_data WHERE agent_id = $1",
        std::vector<std::string>{agent_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::debug("InventoryStore: delete_agent failed for agent={}: {}", agent_id,
                      PQerrorMessage(lease.get()));
        return false;
    }
    return true;
}

// ── Count (authoritative read) ───────────────────────────────────────────────

std::optional<int64_t> InventoryStore::count() const {
    if (!open_) {
        spdlog::warn("InventoryStore: count degraded — store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::warn("InventoryStore: count degraded — no connection ({})", pool_.last_error());
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(lease.get(),
                                       "SELECT COUNT(*) FROM inventory_store.inventory_data",
                                       std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("InventoryStore: count degraded — query failed: {}", PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    return result_i64(res, 0, 0);
}

} // namespace yuzu::server
