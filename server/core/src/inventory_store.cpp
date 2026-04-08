#include "inventory_store.hpp"

#include <spdlog/spdlog.h>

#include <chrono>

namespace yuzu::server {

// ── Helpers ──────────────────────────────────────────────────────────────────

namespace {

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string col_text(sqlite3_stmt* stmt, int col) {
    auto p = sqlite3_column_text(stmt, col);
    return p ? std::string(reinterpret_cast<const char*>(p)) : std::string{};
}

} // namespace

// ── Construction / destruction ──────────────────────────────────────────────

InventoryStore::InventoryStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("InventoryStore: failed to open DB {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);

    create_tables();
    spdlog::info("InventoryStore: opened {}", db_path.string());
}

InventoryStore::~InventoryStore() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool InventoryStore::is_open() const {
    return db_ != nullptr;
}

void InventoryStore::create_tables() {
    const char* ddl = R"(
        CREATE TABLE IF NOT EXISTS inventory_data (
            agent_id TEXT NOT NULL,
            plugin TEXT NOT NULL,
            data_json TEXT NOT NULL DEFAULT '{}',
            collected_at INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (agent_id, plugin)
        );

        CREATE INDEX IF NOT EXISTS idx_inventory_plugin ON inventory_data(plugin);
        CREATE INDEX IF NOT EXISTS idx_inventory_collected ON inventory_data(collected_at);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, ddl, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("InventoryStore: DDL failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

// ── Upsert ──────────────────────────────────────────────────────────────────

void InventoryStore::upsert(const std::string& agent_id, const std::string& plugin,
                            const std::string& data_json, int64_t collected_at) {
    if (collected_at == 0)
        collected_at = now_epoch();

    std::unique_lock lock(mtx_);

    const char* sql =
        "INSERT INTO inventory_data (agent_id, plugin, data_json, collected_at) "
        "VALUES (?, ?, ?, ?) "
        "ON CONFLICT(agent_id, plugin) DO UPDATE SET "
        "data_json = excluded.data_json, collected_at = excluded.collected_at";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("InventoryStore: upsert prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, plugin.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, data_json.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, collected_at);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        spdlog::error("InventoryStore: upsert failed: {}", sqlite3_errmsg(db_));
    }
    sqlite3_finalize(stmt);
}

// ── List tables ─────────────────────────────────────────────────────────────

std::vector<InventoryTable> InventoryStore::list_tables() const {
    std::shared_lock lock(mtx_);
    std::vector<InventoryTable> result;

    const char* sql =
        "SELECT plugin, COUNT(DISTINCT agent_id) AS agent_count, MAX(collected_at) AS last_collected "
        "FROM inventory_data "
        "GROUP BY plugin "
        "ORDER BY plugin";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return result;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        InventoryTable t;
        t.plugin = col_text(stmt, 0);
        t.agent_count = sqlite3_column_int64(stmt, 1);
        t.last_collected = sqlite3_column_int64(stmt, 2);
        result.push_back(std::move(t));
    }
    sqlite3_finalize(stmt);
    return result;
}

// ── Get single record ───────────────────────────────────────────────────────

std::optional<InventoryRecord> InventoryStore::get(const std::string& agent_id,
                                                    const std::string& plugin) const {
    std::shared_lock lock(mtx_);

    const char* sql =
        "SELECT agent_id, plugin, data_json, collected_at "
        "FROM inventory_data WHERE agent_id = ? AND plugin = ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, plugin.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    InventoryRecord r;
    r.agent_id = col_text(stmt, 0);
    r.plugin = col_text(stmt, 1);
    r.data_json = col_text(stmt, 2);
    r.collected_at = sqlite3_column_int64(stmt, 3);
    sqlite3_finalize(stmt);
    return r;
}

// ── Query ───────────────────────────────────────────────────────────────────

std::vector<InventoryRecord> InventoryStore::query(const InventoryQuery& q) const {
    std::shared_lock lock(mtx_);
    std::vector<InventoryRecord> result;

    std::string sql =
        "SELECT agent_id, plugin, data_json, collected_at FROM inventory_data WHERE 1=1";
    std::vector<std::string> text_binds;
    std::vector<int64_t> int_binds;

    // Track bind order: 't' for text, 'i' for int64
    std::string bind_order;

    if (!q.agent_id.empty()) {
        sql += " AND agent_id = ?";
        text_binds.push_back(q.agent_id);
        bind_order += 't';
    }
    if (!q.plugin.empty()) {
        sql += " AND plugin = ?";
        text_binds.push_back(q.plugin);
        bind_order += 't';
    }
    if (q.since > 0) {
        sql += " AND collected_at >= ?";
        int_binds.push_back(q.since);
        bind_order += 'i';
    }
    if (q.until > 0) {
        sql += " AND collected_at <= ?";
        int_binds.push_back(q.until);
        bind_order += 'i';
    }

    sql += " ORDER BY collected_at DESC LIMIT ? OFFSET ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return result;

    int idx = 1;
    size_t ti = 0, ii = 0;
    for (char c : bind_order) {
        if (c == 't') {
            sqlite3_bind_text(stmt, idx++, text_binds[ti].c_str(), -1, SQLITE_TRANSIENT);
            ++ti;
        } else {
            sqlite3_bind_int64(stmt, idx++, int_binds[ii]);
            ++ii;
        }
    }
    sqlite3_bind_int(stmt, idx++, q.limit);
    sqlite3_bind_int(stmt, idx, q.offset);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        InventoryRecord r;
        r.agent_id = col_text(stmt, 0);
        r.plugin = col_text(stmt, 1);
        r.data_json = col_text(stmt, 2);
        r.collected_at = sqlite3_column_int64(stmt, 3);
        result.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return result;
}

// ── Get agent inventory ─────────────────────────────────────────────────────

std::vector<InventoryRecord> InventoryStore::get_agent_inventory(
    const std::string& agent_id) const {
    InventoryQuery q;
    q.agent_id = agent_id;
    q.limit = 1000;
    return query(q);
}

// ── Delete agent ────────────────────────────────────────────────────────────

void InventoryStore::delete_agent(const std::string& agent_id) {
    std::unique_lock lock(mtx_);

    const char* sql = "DELETE FROM inventory_data WHERE agent_id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ── Count ───────────────────────────────────────────────────────────────────

int64_t InventoryStore::count() const {
    std::shared_lock lock(mtx_);

    const char* sql = "SELECT COUNT(*) FROM inventory_data";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return 0;

    int64_t c = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        c = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return c;
}

} // namespace yuzu::server
