#include "response_store.hpp"
#include "migration_runner.hpp"
#include "result_parsing.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <shared_mutex>
#include <unordered_map>

namespace yuzu::server {

ResponseStore::ResponseStore(const std::filesystem::path& db_path, int retention_days,
                             int cleanup_interval_min)
    : db_path_(db_path), retention_days_(retention_days),
      cleanup_interval_min_(cleanup_interval_min) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("ResponseStore: failed to open {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }

    // Enable WAL mode and busy timeout
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    create_tables();
    prepare_insert_stmt();
    if (db_)
        spdlog::info("ResponseStore: opened {} (retention={}d)", db_path.string(), retention_days_);
}

ResponseStore::~ResponseStore() {
    stop_cleanup();
    if (facet_insert_stmt_)
        sqlite3_finalize(facet_insert_stmt_);
    if (insert_stmt_)
        sqlite3_finalize(insert_stmt_);
    if (db_)
        sqlite3_close(db_);
}

bool ResponseStore::is_open() const {
    return db_ != nullptr;
}

void ResponseStore::create_tables() {
    // Legacy compat: bring pre-v0.10 databases up to v1's schema before stamping.
    // v1's CREATE TABLE IF NOT EXISTS is a no-op on existing tables, so the
    // `plugin` column must still be applied here.
    sqlite3_exec(db_, "ALTER TABLE responses ADD COLUMN plugin TEXT DEFAULT ''", nullptr, nullptr,
                 nullptr);

    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS responses (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                instruction_id  TEXT    NOT NULL,
                agent_id        TEXT    NOT NULL,
                timestamp       INTEGER NOT NULL,
                status          INTEGER NOT NULL,
                output          TEXT    NOT NULL,
                error_detail    TEXT,
                ttl_expires_at  INTEGER DEFAULT 0,
                plugin          TEXT    DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_resp_instr_ts
                ON responses(instruction_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_resp_agent_ts
                ON responses(agent_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_resp_ttl
                ON responses(ttl_expires_at) WHERE ttl_expires_at > 0;
            CREATE INDEX IF NOT EXISTS idx_resp_instr_status
                ON responses(instruction_id, status);

            CREATE TABLE IF NOT EXISTS response_facets (
                response_id    INTEGER NOT NULL,
                instruction_id TEXT    NOT NULL,
                agent_id       TEXT    NOT NULL,
                col_idx        INTEGER NOT NULL,
                value          TEXT    NOT NULL,
                line_count     INTEGER DEFAULT 1,
                PRIMARY KEY (response_id, col_idx, value)
            );
            CREATE INDEX IF NOT EXISTS idx_facets_query
                ON response_facets(instruction_id, col_idx, value);
            CREATE INDEX IF NOT EXISTS idx_facets_agent
                ON response_facets(instruction_id, agent_id);
        )"},
        // v2 (PR 2 of executions-history ladder): exact correlation between
        // a response and the execution that produced it. Pre-v2 rows carry
        // execution_id='' as the legacy sentinel; the detail handler in
        // workflow_routes falls back to the timestamp-window join on those.
        // SQLite's ALTER TABLE ADD COLUMN is not idempotent; the probe
        // below pre-stamps schema_meta to v2 if the column already exists
        // (e.g. a developer ran an iterated build), matching the precedent
        // at instruction_store.cpp:197-216 (governance arch-B2 / CP-5).
        {2, R"(
            ALTER TABLE responses ADD COLUMN execution_id TEXT NOT NULL DEFAULT '';
            CREATE INDEX IF NOT EXISTS idx_resp_execution_ts
                ON responses(execution_id, timestamp) WHERE execution_id != '';
        )"},
        // v3 (UAT 2026-05-06 #10): add millisecond-precision server-side
        // ingest timestamp. The legacy `timestamp` column is seconds and
        // is used by retention math + indexes — we don't migrate its
        // semantics. The new column is what the executions drawer renders
        // as the per-agent wall-clock arrival time.
        {3, R"(
            ALTER TABLE responses ADD COLUMN received_at_ms INTEGER NOT NULL DEFAULT 0;
        )"},
    };
    // Pre-migration probe (mirrors instruction_store.cpp:197-216): if the
    // execution_id column already exists and schema_meta is below v2, stamp
    // v2 directly so the runner skips the duplicate ALTER. The probe is a
    // read-only PRAGMA — safe on any DB state.
    {
        sqlite3_stmt* probe = nullptr;
        bool col_exists = false;
        if (sqlite3_prepare_v2(db_,
                               "SELECT 1 FROM pragma_table_info('responses') "
                               "WHERE name='execution_id' LIMIT 1",
                               -1, &probe, nullptr) == SQLITE_OK) {
            col_exists = (sqlite3_step(probe) == SQLITE_ROW);
            sqlite3_finalize(probe);
        }
        int current_v = MigrationRunner::current_version(db_, "response_store");
        if (col_exists && current_v < 2) {
            sqlite3_stmt* stamp = nullptr;
            if (sqlite3_prepare_v2(db_,
                                   "INSERT OR REPLACE INTO schema_meta "
                                   "(store, version, upgraded_at) VALUES (?, 2, ?)",
                                   -1, &stamp, nullptr) == SQLITE_OK) {
                auto now = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
                sqlite3_bind_text(stamp, 1, "response_store", -1, SQLITE_STATIC);
                sqlite3_bind_int64(stamp, 2, now);
                sqlite3_step(stamp);
                sqlite3_finalize(stamp);
            }
        }
    }
    // v3 pre-migration probe (governance UAT 2026-05-06 architect S-1 /
    // consistency S-2 / unhappy UP-13). Mirrors the v2 pattern above:
    // a developer who pre-added the `received_at_ms` column on an iterated
    // build hits SQLITE_ERROR: duplicate column name on the next ALTER,
    // which the runner treats as migration failure -> db_ = nullptr ->
    // every response is silently dropped. Probe + stamp avoids the trap.
    {
        sqlite3_stmt* probe = nullptr;
        bool col_exists = false;
        if (sqlite3_prepare_v2(db_,
                               "SELECT 1 FROM pragma_table_info('responses') "
                               "WHERE name='received_at_ms' LIMIT 1",
                               -1, &probe, nullptr) == SQLITE_OK) {
            col_exists = (sqlite3_step(probe) == SQLITE_ROW);
            sqlite3_finalize(probe);
        }
        int current_v = MigrationRunner::current_version(db_, "response_store");
        if (col_exists && current_v < 3) {
            sqlite3_stmt* stamp = nullptr;
            if (sqlite3_prepare_v2(db_,
                                   "INSERT OR REPLACE INTO schema_meta "
                                   "(store, version, upgraded_at) VALUES (?, 3, ?)",
                                   -1, &stamp, nullptr) == SQLITE_OK) {
                auto now = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
                sqlite3_bind_text(stamp, 1, "response_store", -1, SQLITE_STATIC);
                sqlite3_bind_int64(stamp, 2, now);
                sqlite3_step(stamp);
                sqlite3_finalize(stamp);
            }
        }
    }
    if (!MigrationRunner::run(db_, "response_store", kMigrations)) {
        spdlog::error("ResponseStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

void ResponseStore::prepare_insert_stmt() {
    if (!db_)
        return;
    const char* sql = R"(
        INSERT INTO responses (instruction_id, agent_id, timestamp, status, output,
                               error_detail, ttl_expires_at, plugin, execution_id,
                               received_at_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &insert_stmt_, nullptr) != SQLITE_OK) {
        spdlog::error("ResponseStore: failed to prepare insert statement: {}", sqlite3_errmsg(db_));
        insert_stmt_ = nullptr;
    }

    const char* facet_sql = R"(
        INSERT OR REPLACE INTO response_facets
            (response_id, instruction_id, agent_id, col_idx, value, line_count)
        VALUES (?, ?, ?, ?, ?, ?)
    )";
    if (sqlite3_prepare_v2(db_, facet_sql, -1, &facet_insert_stmt_, nullptr) != SQLITE_OK) {
        spdlog::error("ResponseStore: failed to prepare facet insert: {}", sqlite3_errmsg(db_));
        facet_insert_stmt_ = nullptr;
    }
}

void ResponseStore::store(const StoredResponse& resp) {
    std::unique_lock lock(mtx_);
    if (!db_ || !insert_stmt_)
        return;

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
    auto now = now_ms / 1000;
    auto ts = resp.timestamp > 0 ? resp.timestamp : now;
    auto ttl = resp.ttl_expires_at > 0
                   ? resp.ttl_expires_at
                   : (retention_days_ > 0 ? now + retention_days_ * 86400LL : 0);
    // UAT 2026-05-06 #10: stamp the server-side ingest wall-clock with
    // millisecond precision. Caller's pre-set value (e.g. tests using
    // a deterministic clock) wins; default 0 means "stamp now".
    auto received_ms = resp.received_at_ms > 0 ? resp.received_at_ms : now_ms;

    sqlite3_exec(db_, "BEGIN", nullptr, nullptr, nullptr);

    sqlite3_reset(insert_stmt_);
    sqlite3_clear_bindings(insert_stmt_);

    sqlite3_bind_text(insert_stmt_, 1, resp.instruction_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert_stmt_, 2, resp.agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(insert_stmt_, 3, ts);
    sqlite3_bind_int(insert_stmt_, 4, resp.status);
    sqlite3_bind_text(insert_stmt_, 5, resp.output.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(insert_stmt_, 6, resp.error_detail.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(insert_stmt_, 7, ttl);
    sqlite3_bind_text(insert_stmt_, 8, resp.plugin.c_str(), -1, SQLITE_TRANSIENT);
    // PR 2: execution_id column. Empty when the dispatch path didn't
    // register a command_id→execution_id mapping (out-of-band callers,
    // legacy code paths). The detail handler uses the timestamp-window
    // fallback for empty values.
    sqlite3_bind_text(insert_stmt_, 9, resp.execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(insert_stmt_, 10, received_ms);

    if (sqlite3_step(insert_stmt_) != SQLITE_DONE) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return;
    }

    auto response_id = sqlite3_last_insert_rowid(db_);

    // Extract facets from the output using the plugin schema
    if (facet_insert_stmt_ && !resp.plugin.empty() && !resp.output.empty()) {
        auto lines = split_output_lines(resp.output);

        // Accumulate (col_idx, value) → line_count.
        // col_idx is 0-based offset into the *field* array (excludes the Agent
        // column which is always column 0 in the schema).
        std::unordered_map<int, std::unordered_map<std::string, int>> facets;
        for (const auto& line : lines) {
            auto fields = split_fields(resp.plugin, line);
            for (int i = 0; i < static_cast<int>(fields.size()); ++i) {
                if (!fields[i].empty()) {
                    facets[i][fields[i]]++;
                }
            }
        }

        for (const auto& [col_idx, value_counts] : facets) {
            for (const auto& [value, count] : value_counts) {
                sqlite3_reset(facet_insert_stmt_);
                sqlite3_clear_bindings(facet_insert_stmt_);
                sqlite3_bind_int64(facet_insert_stmt_, 1, response_id);
                sqlite3_bind_text(facet_insert_stmt_, 2, resp.instruction_id.c_str(), -1,
                                  SQLITE_TRANSIENT);
                sqlite3_bind_text(facet_insert_stmt_, 3, resp.agent_id.c_str(), -1,
                                  SQLITE_TRANSIENT);
                sqlite3_bind_int(facet_insert_stmt_, 4, col_idx);
                sqlite3_bind_text(facet_insert_stmt_, 5, value.c_str(), -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(facet_insert_stmt_, 6, count);
                sqlite3_step(facet_insert_stmt_);
            }
        }
    }

    sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr);
}

ResponseStore::FinalizeResult ResponseStore::finalize_terminal_status(
    const std::string& instruction_id, const std::string& agent_id, int terminal_status,
    const std::string& error_detail, const std::string& execution_id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return FinalizeResult::Error;

    sqlite3_stmt* stmt = nullptr;
    const char* sql = R"(
        UPDATE responses
           SET status = ?, error_detail = ?
         WHERE instruction_id = ? AND agent_id = ? AND status = 0
           AND execution_id = ?
    )";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("ResponseStore::finalize_terminal_status: prepare failed: {}",
                      sqlite3_errmsg(db_));
        return FinalizeResult::Error;
    }
    sqlite3_bind_int(stmt, 1, terminal_status);
    sqlite3_bind_text(stmt, 2, error_detail.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, instruction_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, execution_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        // Real SQL error (SQLITE_BUSY, SQLITE_LOCKED, SQLITE_CORRUPT, …).
        // Distinct from "no row matched" — caller MUST NOT fall through to
        // insert here because that re-creates the empty-output sentinel
        // row the UAT-#11 fix removed (governance UAT 2026-05-06 UP-3 /
        // chaos CH-1).
        spdlog::error("ResponseStore::finalize_terminal_status: step failed: rc={} err={}", rc,
                      sqlite3_errmsg(db_));
        return FinalizeResult::Error;
    }
    return changes > 0 ? FinalizeResult::Updated : FinalizeResult::NoRow;
}

std::vector<StoredResponse> ResponseStore::query(const std::string& instruction_id,
                                                 const ResponseQuery& q) const {
    std::shared_lock lock(mtx_);
    std::vector<StoredResponse> results;
    if (!db_)
        return results;

    std::string sql = "SELECT id, instruction_id, agent_id, timestamp, status, output, "
                      "error_detail, ttl_expires_at, COALESCE(plugin,''), "
                      "COALESCE(execution_id,''), "
                      "COALESCE(received_at_ms, 0) FROM responses"
                      " WHERE instruction_id = ?";
    std::vector<std::string> bind_texts;
    // int64_binds: (param_index, value) pairs for integer parameters
    std::vector<std::pair<int, int64_t>> int_binds;
    int bind_idx = 1;
    bind_texts.push_back(instruction_id);
    bind_idx++;

    if (!q.agent_id.empty()) {
        sql += " AND agent_id = ?";
        bind_texts.push_back(q.agent_id);
        bind_idx++;
    }
    if (q.status >= 0) {
        sql += " AND status = ?";
        int_binds.emplace_back(bind_idx++, static_cast<int64_t>(q.status));
    }
    if (q.since > 0) {
        sql += " AND timestamp >= ?";
        int_binds.emplace_back(bind_idx++, q.since);
    }
    if (q.until > 0) {
        sql += " AND timestamp <= ?";
        int_binds.emplace_back(bind_idx++, q.until);
    }
    sql += " ORDER BY timestamp DESC";
    sql += " LIMIT ?";
    int limit_idx = bind_idx++;
    int offset_idx = 0;
    if (q.offset > 0) {
        sql += " OFFSET ?";
        offset_idx = bind_idx++;
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    for (int i = 0; i < static_cast<int>(bind_texts.size()); ++i) {
        sqlite3_bind_text(stmt, i + 1, bind_texts[i].c_str(), -1, SQLITE_TRANSIENT);
    }
    for (const auto& [idx, val] : int_binds) {
        sqlite3_bind_int64(stmt, idx, val);
    }
    sqlite3_bind_int64(stmt, limit_idx, q.limit);
    if (offset_idx > 0) {
        sqlite3_bind_int64(stmt, offset_idx, q.offset);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        StoredResponse r;
        r.id = sqlite3_column_int64(stmt, 0);
        r.instruction_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        r.agent_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        r.timestamp = sqlite3_column_int64(stmt, 3);
        r.status = sqlite3_column_int(stmt, 4);
        auto out = sqlite3_column_text(stmt, 5);
        if (out)
            r.output = reinterpret_cast<const char*>(out);
        auto err = sqlite3_column_text(stmt, 6);
        if (err)
            r.error_detail = reinterpret_cast<const char*>(err);
        r.ttl_expires_at = sqlite3_column_int64(stmt, 7);
        auto pl = sqlite3_column_text(stmt, 8);
        if (pl)
            r.plugin = reinterpret_cast<const char*>(pl);
        auto ex = sqlite3_column_text(stmt, 9);
        if (ex)
            r.execution_id = reinterpret_cast<const char*>(ex);
        r.received_at_ms = sqlite3_column_int64(stmt, 10);
        results.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return results;
}

// PR 2: exact-correlation lookup via the new execution_id column. Falls
// back to no-op (empty result) on the legacy sentinel `''` so callers can
// detect "no PR 2 data for this id" and use `query()` for the legacy
// timestamp-window join. Same filter surface as `query()` minus the
// outer instruction_id (replaced with execution_id) — agent / status /
// since / until / limit / offset still work.
std::vector<StoredResponse> ResponseStore::query_by_execution(const std::string& execution_id,
                                                              const ResponseQuery& q) const {
    std::shared_lock lock(mtx_);
    std::vector<StoredResponse> results;
    if (!db_)
        return results;
    if (execution_id.empty()) {
        // arch-B1: empty execution_id is the legacy sentinel and indicates
        // a caller bug (Execution.id was uninitialized) rather than a
        // legitimate empty-result query. Log at debug rather than warn so
        // a misbehaving caller doesn't flood production logs; the bug
        // surfaces in operator-debug runs where verbose logging is on.
        spdlog::debug("ResponseStore::query_by_execution called with empty "
                      "execution_id — legacy sentinel; returning no rows. "
                      "Caller should guard upstream and use query() for "
                      "legacy-correlation needs.");
        return results;
    }

    // perf-B1 fix: include the partial-index predicate `execution_id != ''`
    // EXPLICITLY in the WHERE clause so SQLite's planner uses
    // `idx_resp_execution_ts`. Without this redundant clause the planner
    // refuses to match a partial index against a `WHERE execution_id = ?`
    // bind alone — it requires the WHERE clause to syntactically subsume
    // the partial-index predicate. The early-return at the top of this
    // method guarantees `execution_id` is non-empty, so the extra clause
    // is always trivially true; it exists solely for the planner.
    std::string sql = "SELECT id, instruction_id, agent_id, timestamp, status, output, "
                      "error_detail, ttl_expires_at, COALESCE(plugin,''), "
                      "COALESCE(execution_id,''), "
                      "COALESCE(received_at_ms, 0) FROM responses"
                      " WHERE execution_id != '' AND execution_id = ?";
    std::vector<std::string> bind_texts;
    std::vector<std::pair<int, int64_t>> int_binds;
    int bind_idx = 1;
    bind_texts.push_back(execution_id);
    bind_idx++;

    if (!q.agent_id.empty()) {
        sql += " AND agent_id = ?";
        bind_texts.push_back(q.agent_id);
        bind_idx++;
    }
    if (q.status >= 0) {
        sql += " AND status = ?";
        int_binds.emplace_back(bind_idx++, static_cast<int64_t>(q.status));
    }
    if (q.since > 0) {
        sql += " AND timestamp >= ?";
        int_binds.emplace_back(bind_idx++, q.since);
    }
    if (q.until > 0) {
        sql += " AND timestamp <= ?";
        int_binds.emplace_back(bind_idx++, q.until);
    }
    sql += " ORDER BY timestamp DESC LIMIT ?";
    int limit_idx = bind_idx++;
    int offset_idx = 0;
    if (q.offset > 0) {
        sql += " OFFSET ?";
        offset_idx = bind_idx++;
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    for (int i = 0; i < static_cast<int>(bind_texts.size()); ++i) {
        sqlite3_bind_text(stmt, i + 1, bind_texts[i].c_str(), -1, SQLITE_TRANSIENT);
    }
    for (const auto& [idx, val] : int_binds) {
        sqlite3_bind_int64(stmt, idx, val);
    }
    sqlite3_bind_int64(stmt, limit_idx, q.limit);
    if (offset_idx > 0) {
        sqlite3_bind_int64(stmt, offset_idx, q.offset);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        StoredResponse r;
        r.id = sqlite3_column_int64(stmt, 0);
        r.instruction_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        r.agent_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        r.timestamp = sqlite3_column_int64(stmt, 3);
        r.status = sqlite3_column_int(stmt, 4);
        auto out = sqlite3_column_text(stmt, 5);
        if (out)
            r.output = reinterpret_cast<const char*>(out);
        auto err = sqlite3_column_text(stmt, 6);
        if (err)
            r.error_detail = reinterpret_cast<const char*>(err);
        r.ttl_expires_at = sqlite3_column_int64(stmt, 7);
        auto pl = sqlite3_column_text(stmt, 8);
        if (pl)
            r.plugin = reinterpret_cast<const char*>(pl);
        auto ex = sqlite3_column_text(stmt, 9);
        if (ex)
            r.execution_id = reinterpret_cast<const char*>(ex);
        r.received_at_ms = sqlite3_column_int64(stmt, 10);
        results.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::vector<StoredResponse>
ResponseStore::get_by_instruction(const std::string& instruction_id) const {
    return query(instruction_id);
}

std::vector<AggregationResult> ResponseStore::aggregate(const std::string& instruction_id,
                                                        const AggregationQuery& aq,
                                                        const ResponseQuery& filter) const {
    std::shared_lock lock(mtx_);
    std::vector<AggregationResult> results;
    if (!db_)
        return results;

    // Whitelist group_by columns to prevent SQL injection
    static const std::vector<std::string> allowed_group = {"status", "agent_id"};
    if (std::find(allowed_group.begin(), allowed_group.end(), aq.group_by) == allowed_group.end()) {
        spdlog::warn("ResponseStore::aggregate: invalid group_by '{}'", aq.group_by);
        return results;
    }

    // Whitelist op columns
    static const std::vector<std::string> allowed_op_col = {"timestamp", "status", "id"};
    auto effective_op_col = aq.op_column.empty() ? "id" : aq.op_column;
    if (std::find(allowed_op_col.begin(), allowed_op_col.end(), effective_op_col) ==
        allowed_op_col.end()) {
        spdlog::warn("ResponseStore::aggregate: invalid op_column '{}'", effective_op_col);
        return results;
    }

    // Build aggregate function
    std::string agg_func;
    switch (aq.op) {
    case AggregateOp::Count:
        agg_func = "COUNT(*)";
        break;
    case AggregateOp::Sum:
        agg_func = "SUM(" + effective_op_col + ")";
        break;
    case AggregateOp::Avg:
        agg_func = "AVG(" + effective_op_col + ")";
        break;
    case AggregateOp::Min:
        agg_func = "MIN(" + effective_op_col + ")";
        break;
    case AggregateOp::Max:
        agg_func = "MAX(" + effective_op_col + ")";
        break;
    }

    std::string sql = "SELECT " + aq.group_by + ", COUNT(*), " + agg_func +
                      " FROM responses WHERE instruction_id = ?";
    std::vector<std::string> bind_texts;
    // int64_binds: (param_index, value) pairs for integer parameters
    std::vector<std::pair<int, int64_t>> int_binds;
    int bind_idx = 1;
    bind_texts.push_back(instruction_id);
    bind_idx++;

    if (!filter.agent_id.empty()) {
        sql += " AND agent_id = ?";
        bind_texts.push_back(filter.agent_id);
        bind_idx++;
    }
    if (filter.status >= 0) {
        sql += " AND status = ?";
        int_binds.emplace_back(bind_idx++, static_cast<int64_t>(filter.status));
    }
    if (filter.since > 0) {
        sql += " AND timestamp >= ?";
        int_binds.emplace_back(bind_idx++, filter.since);
    }
    if (filter.until > 0) {
        sql += " AND timestamp <= ?";
        int_binds.emplace_back(bind_idx++, filter.until);
    }

    sql += " GROUP BY " + aq.group_by + " ORDER BY COUNT(*) DESC";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    for (int i = 0; i < static_cast<int>(bind_texts.size()); ++i) {
        sqlite3_bind_text(stmt, i + 1, bind_texts[i].c_str(), -1, SQLITE_TRANSIENT);
    }
    for (const auto& [idx, val] : int_binds) {
        sqlite3_bind_int64(stmt, idx, val);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AggregationResult r;
        auto gv = sqlite3_column_text(stmt, 0);
        if (gv)
            r.group_value = reinterpret_cast<const char*>(gv);
        r.count = sqlite3_column_int64(stmt, 1);
        r.aggregate_value = sqlite3_column_double(stmt, 2);
        results.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::size_t ResponseStore::total_count() const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return 0;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM responses", -1, &stmt, nullptr) != SQLITE_OK)
        return 0;
    std::size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return count;
}

std::uintmax_t ResponseStore::db_size_bytes() const {
    if (db_path_.empty() || db_path_.string() == ":memory:")
        return 0;
    std::error_code ec;
    return std::filesystem::file_size(db_path_, ec);
}

// -- Faceted query methods -----------------------------------------------------

std::vector<FacetValue> ResponseStore::facet_values(const std::string& instruction_id,
                                                    int col_idx) const {
    std::shared_lock lock(mtx_);
    std::vector<FacetValue> results;
    if (!db_)
        return results;

    const char* sql = "SELECT value, SUM(line_count) FROM response_facets"
                      " WHERE instruction_id = ? AND col_idx = ?"
                      " GROUP BY value ORDER BY SUM(line_count) DESC";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return results;
    sqlite3_bind_text(stmt, 1, instruction_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, col_idx);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        FacetValue fv;
        auto v = sqlite3_column_text(stmt, 0);
        if (v)
            fv.value = reinterpret_cast<const char*>(v);
        fv.line_count = sqlite3_column_int64(stmt, 1);
        results.push_back(std::move(fv));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::vector<std::string>
ResponseStore::facet_agent_ids(const std::string& instruction_id,
                               const std::vector<FacetFilter>& filters) const {
    std::shared_lock lock(mtx_);
    std::vector<std::string> results;
    if (!db_ || filters.empty())
        return results;

    // Build query with one subquery per filter (intersection)
    std::string sql = "SELECT DISTINCT agent_id FROM response_facets"
                      " WHERE instruction_id = ?";
    for (size_t i = 0; i < filters.size(); ++i) {
        sql += " AND response_id IN (SELECT response_id FROM response_facets"
               " WHERE instruction_id = ? AND col_idx = ? AND value = ?)";
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    int idx = 1;
    sqlite3_bind_text(stmt, idx++, instruction_id.c_str(), -1, SQLITE_TRANSIENT);
    for (const auto& f : filters) {
        sqlite3_bind_text(stmt, idx++, instruction_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, idx++, f.col_idx);
        sqlite3_bind_text(stmt, idx++, f.value.c_str(), -1, SQLITE_TRANSIENT);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto v = sqlite3_column_text(stmt, 0);
        if (v)
            results.emplace_back(reinterpret_cast<const char*>(v));
    }
    sqlite3_finalize(stmt);
    return results;
}

int64_t ResponseStore::facet_agent_count(const std::string& instruction_id,
                                         const std::vector<FacetFilter>& filters) const {
    std::shared_lock lock(mtx_);
    if (!db_ || filters.empty())
        return 0;

    std::string sql = "SELECT COUNT(DISTINCT agent_id) FROM response_facets"
                      " WHERE instruction_id = ?";
    for (size_t i = 0; i < filters.size(); ++i) {
        sql += " AND response_id IN (SELECT response_id FROM response_facets"
               " WHERE instruction_id = ? AND col_idx = ? AND value = ?)";
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return 0;

    int idx = 1;
    sqlite3_bind_text(stmt, idx++, instruction_id.c_str(), -1, SQLITE_TRANSIENT);
    for (const auto& f : filters) {
        sqlite3_bind_text(stmt, idx++, instruction_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, idx++, f.col_idx);
        sqlite3_bind_text(stmt, idx++, f.value.c_str(), -1, SQLITE_TRANSIENT);
    }

    int64_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

int64_t ResponseStore::facet_line_count(const std::string& instruction_id,
                                        const std::vector<FacetFilter>& filters) const {
    std::shared_lock lock(mtx_);
    if (!db_ || filters.empty())
        return 0;

    std::string sql = "SELECT SUM(line_count) FROM response_facets"
                      " WHERE instruction_id = ? AND col_idx = ? AND value = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return 0;

    // Use the first filter for the line count — this gives the total lines
    // matching that filter. For multi-filter intersection, the count is an
    // upper bound (true intersection count requires row-level parsing).
    sqlite3_bind_text(stmt, 1, instruction_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, filters[0].col_idx);
    sqlite3_bind_text(stmt, 3, filters[0].value.c_str(), -1, SQLITE_TRANSIENT);

    int64_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

std::vector<int64_t> ResponseStore::facet_response_ids(const std::string& instruction_id,
                                                       const std::vector<FacetFilter>& filters,
                                                       int limit, int offset) const {
    std::shared_lock lock(mtx_);
    std::vector<int64_t> results;
    if (!db_ || filters.empty())
        return results;

    std::string sql = "SELECT DISTINCT response_id FROM response_facets"
                      " WHERE instruction_id = ?";
    for (size_t i = 0; i < filters.size(); ++i) {
        sql += " AND response_id IN (SELECT response_id FROM response_facets"
               " WHERE instruction_id = ? AND col_idx = ? AND value = ?)";
    }
    sql += " ORDER BY response_id LIMIT ? OFFSET ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    int idx = 1;
    sqlite3_bind_text(stmt, idx++, instruction_id.c_str(), -1, SQLITE_TRANSIENT);
    for (const auto& f : filters) {
        sqlite3_bind_text(stmt, idx++, instruction_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, idx++, f.col_idx);
        sqlite3_bind_text(stmt, idx++, f.value.c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(stmt, idx++, limit);
    sqlite3_bind_int(stmt, idx, offset);

    while (sqlite3_step(stmt) == SQLITE_ROW)
        results.push_back(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return results;
}

std::vector<StoredResponse>
ResponseStore::query_by_ids(const std::vector<int64_t>& response_ids) const {
    std::shared_lock lock(mtx_);
    std::vector<StoredResponse> results;
    if (!db_ || response_ids.empty())
        return results;

    // Build IN list — safe because the values are int64_t, not user strings
    std::string in_list;
    for (size_t i = 0; i < response_ids.size(); ++i) {
        if (i > 0)
            in_list += ',';
        in_list += std::to_string(response_ids[i]);
    }
    std::string sql = "SELECT id, instruction_id, agent_id, timestamp, status, output,"
                      " error_detail, ttl_expires_at, COALESCE(plugin,''),"
                      " COALESCE(execution_id,''),"
                      " COALESCE(received_at_ms, 0) FROM responses"
                      " WHERE id IN (" +
                      in_list + ") ORDER BY id";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        StoredResponse r;
        r.id = sqlite3_column_int64(stmt, 0);
        r.instruction_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        r.agent_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        r.timestamp = sqlite3_column_int64(stmt, 3);
        r.status = sqlite3_column_int(stmt, 4);
        auto out = sqlite3_column_text(stmt, 5);
        if (out)
            r.output = reinterpret_cast<const char*>(out);
        auto err = sqlite3_column_text(stmt, 6);
        if (err)
            r.error_detail = reinterpret_cast<const char*>(err);
        r.ttl_expires_at = sqlite3_column_int64(stmt, 7);
        auto pl = sqlite3_column_text(stmt, 8);
        if (pl)
            r.plugin = reinterpret_cast<const char*>(pl);
        auto ex = sqlite3_column_text(stmt, 9);
        if (ex)
            r.execution_id = reinterpret_cast<const char*>(ex);
        r.received_at_ms = sqlite3_column_int64(stmt, 10);
        results.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return results;
}

void ResponseStore::start_cleanup() {
    if (!db_ || cleanup_interval_min_ <= 0)
        return;
#ifdef __cpp_lib_jthread
    cleanup_thread_ = std::jthread([this](std::stop_token stop) { run_cleanup(stop); });
#else
    stop_requested_ = false;
    cleanup_thread_ = std::thread([this]() { run_cleanup(); });
#endif
}

void ResponseStore::stop_cleanup() {
#ifdef __cpp_lib_jthread
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.request_stop();
        cleanup_thread_.join();
    }
#else
    stop_requested_ = true;
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
#endif
}

#ifdef __cpp_lib_jthread
void ResponseStore::run_cleanup(std::stop_token stop) {
    while (!stop.stop_requested()) {
        for (int i = 0; i < cleanup_interval_min_ * 60 && !stop.stop_requested(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stop.stop_requested())
            break;
#else
void ResponseStore::run_cleanup() {
    while (!stop_requested_.load()) {
        for (int i = 0; i < cleanup_interval_min_ * 60 && !stop_requested_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stop_requested_.load())
            break;
#endif

        auto now = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();

        {
            std::unique_lock lock(mtx_);
            sqlite3_stmt* cleanup_stmt = nullptr;
            if (sqlite3_prepare_v2(
                    db_, "DELETE FROM responses WHERE ttl_expires_at > 0 AND ttl_expires_at < ?",
                    -1, &cleanup_stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int64(cleanup_stmt, 1, now);
                if (sqlite3_step(cleanup_stmt) == SQLITE_DONE) {
                    auto deleted = sqlite3_changes(db_);
                    if (deleted > 0) {
                        spdlog::info("ResponseStore: expired {} rows", deleted);
                        // Cascade: remove orphaned facets
                        sqlite3_exec(db_,
                                     "DELETE FROM response_facets WHERE response_id NOT IN"
                                     " (SELECT id FROM responses)",
                                     nullptr, nullptr, nullptr);
                    }
                } else {
                    spdlog::warn("ResponseStore: cleanup error: {}", sqlite3_errmsg(db_));
                }
                sqlite3_finalize(cleanup_stmt);
            }
        }
    }
}

} // namespace yuzu::server
