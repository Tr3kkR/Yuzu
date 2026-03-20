#include "response_store.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>

namespace yuzu::server {

ResponseStore::ResponseStore(const std::filesystem::path& db_path, int retention_days,
                             int cleanup_interval_min)
    : db_path_(db_path), retention_days_(retention_days),
      cleanup_interval_min_(cleanup_interval_min) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
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
    spdlog::info("ResponseStore: opened {} (retention={}d)", db_path.string(), retention_days_);
}

ResponseStore::~ResponseStore() {
    stop_cleanup();
    if (db_)
        sqlite3_close(db_);
}

bool ResponseStore::is_open() const {
    return db_ != nullptr;
}

void ResponseStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS responses (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            instruction_id  TEXT    NOT NULL,
            agent_id        TEXT    NOT NULL,
            timestamp       INTEGER NOT NULL,
            status          INTEGER NOT NULL,
            output          TEXT    NOT NULL,
            error_detail    TEXT,
            ttl_expires_at  INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_resp_instr_ts
            ON responses(instruction_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_resp_agent_ts
            ON responses(agent_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_resp_ttl
            ON responses(ttl_expires_at) WHERE ttl_expires_at > 0;
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("ResponseStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

void ResponseStore::store(const StoredResponse& resp) {
    if (!db_)
        return;

    const char* sql = R"(
        INSERT INTO responses (instruction_id, agent_id, timestamp, status, output, error_detail, ttl_expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto ts = resp.timestamp > 0 ? resp.timestamp : now;
    auto ttl = resp.ttl_expires_at > 0
                   ? resp.ttl_expires_at
                   : (retention_days_ > 0 ? now + retention_days_ * 86400LL : 0);

    sqlite3_bind_text(stmt, 1, resp.instruction_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, resp.agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, ts);
    sqlite3_bind_int(stmt, 4, resp.status);
    sqlite3_bind_text(stmt, 5, resp.output.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, resp.error_detail.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 7, ttl);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<StoredResponse> ResponseStore::query(const std::string& instruction_id,
                                                 const ResponseQuery& q) const {
    std::vector<StoredResponse> results;
    if (!db_)
        return results;

    std::string sql = "SELECT id, instruction_id, agent_id, timestamp, status, output, "
                      "error_detail, ttl_expires_at FROM responses WHERE instruction_id = ?";
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

        sqlite3_stmt* cleanup_stmt = nullptr;
        if (sqlite3_prepare_v2(
                db_, "DELETE FROM responses WHERE ttl_expires_at > 0 AND ttl_expires_at < ?",
                -1, &cleanup_stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(cleanup_stmt, 1, now);
            if (sqlite3_step(cleanup_stmt) == SQLITE_DONE) {
                auto deleted = sqlite3_changes(db_);
                if (deleted > 0) {
                    spdlog::info("ResponseStore: expired {} rows", deleted);
                }
            } else {
                spdlog::warn("ResponseStore: cleanup error: {}", sqlite3_errmsg(db_));
            }
            sqlite3_finalize(cleanup_stmt);
        }
    }
}

} // namespace yuzu::server
