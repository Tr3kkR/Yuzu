#include "guaranteed_state_store.hpp"
#include "migration_runner.hpp"
#include "store_errors.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <shared_mutex>
#include <string_view>

namespace yuzu::server {

namespace {

std::string col_text(sqlite3_stmt* stmt, int c) {
    auto t = sqlite3_column_text(stmt, c);
    return t ? reinterpret_cast<const char*>(t) : std::string{};
}

std::vector<uint8_t> col_blob(sqlite3_stmt* stmt, int c) {
    auto len = sqlite3_column_bytes(stmt, c);
    auto data = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, c));
    if (!data || len <= 0)
        return {};
    return std::vector<uint8_t>(data, data + len);
}

// Is the SQLite extended error code a UNIQUE or PRIMARY KEY constraint
// violation? Treat both as a duplicate-resource conflict so the route
// layer can map either to HTTP 409.
bool is_sqlite_uniqueness_violation(int extended) {
    return extended == SQLITE_CONSTRAINT_UNIQUE ||
           extended == SQLITE_CONSTRAINT_PRIMARYKEY;
}

std::string format_conflict(std::string_view detail) {
    return std::string(kConflictPrefix) + " " + std::string(detail);
}

} // namespace

GuaranteedStateStore::GuaranteedStateStore(const std::filesystem::path& db_path,
                                             int retention_days,
                                             int cleanup_interval_min)
    : retention_days_{retention_days},
      cleanup_interval_min_{cleanup_interval_min} {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("GuaranteedStateStore: failed to open {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }

    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    sqlite3_extended_result_codes(db_, 1);
    create_tables();
    if (db_)
        spdlog::info("GuaranteedStateStore: opened {} (retention={}d, interval={}m)",
                     db_path.string(), retention_days_, cleanup_interval_min_);
}

GuaranteedStateStore::~GuaranteedStateStore() {
    // Stop the reaper before taking the write lock so its in-flight DELETE
    // (which needs mtx_) doesn't deadlock us at shutdown. stop_cleanup is
    // idempotent — safe if start_cleanup was never called.
    stop_cleanup();
    // Acquire unique_lock before closing the sqlite3* so any concurrent
    // reader (shared_lock holder mid-query) has released the lock and
    // returned from SQLite before we call sqlite3_close. Without this
    // barrier a reader racing with server shutdown would use-after-free on
    // the handle (UP-14 from PR 1 governance). httplib's server-stop
    // drains handlers in practice, but the contract shouldn't depend on
    // unwritten coordination between the web server and store lifetimes.
    std::unique_lock lock(mtx_);
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool GuaranteedStateStore::is_open() const {
    return db_ != nullptr;
}

void GuaranteedStateStore::create_tables() {
    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS guaranteed_state_rules (
                rule_id          TEXT PRIMARY KEY,
                name             TEXT NOT NULL UNIQUE,
                yaml_source      TEXT NOT NULL,
                version          INTEGER NOT NULL DEFAULT 1,
                enabled          INTEGER NOT NULL DEFAULT 1,
                enforcement_mode TEXT NOT NULL DEFAULT 'enforce',
                severity         TEXT NOT NULL DEFAULT 'medium',
                os_target        TEXT NOT NULL DEFAULT '',
                scope_expr       TEXT,
                signature        BLOB,
                created_at       TEXT NOT NULL,
                updated_at       TEXT NOT NULL,
                created_by       TEXT NOT NULL DEFAULT '',
                updated_by       TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_gsr_os
                ON guaranteed_state_rules(os_target);
            -- Deliberately no index on `enabled` (boolean, cardinality 2):
            -- SQLite will skip a low-selectivity index and full-scan anyway.

            CREATE TABLE IF NOT EXISTS guaranteed_state_events (
                event_id               TEXT PRIMARY KEY,
                rule_id                TEXT NOT NULL,
                agent_id               TEXT NOT NULL,
                event_type             TEXT NOT NULL,
                severity               TEXT NOT NULL,
                guard_type             TEXT,
                guard_category         TEXT,
                detected_value         TEXT,
                expected_value         TEXT,
                remediation_action     TEXT,
                remediation_success    INTEGER,
                detection_latency_us   INTEGER,
                remediation_latency_us INTEGER,
                timestamp              TEXT NOT NULL,
                ttl_expires_at         INTEGER NOT NULL DEFAULT 0
            );
            -- Composite indexes cover the three documented filter paths
            -- (rule / agent / severity), each combined with the timestamp
            -- sort direction used by query_events. SQLite can satisfy the
            -- WHERE + ORDER BY with an index range scan and no filesort.
            CREATE INDEX IF NOT EXISTS idx_gse_rule_time
                ON guaranteed_state_events(rule_id, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_gse_agent_time
                ON guaranteed_state_events(agent_id, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_gse_severity_time
                ON guaranteed_state_events(severity, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_gse_time
                ON guaranteed_state_events(timestamp DESC);
            -- Reaper predicate is `ttl_expires_at > 0 AND ttl_expires_at < ?`;
            -- a partial index keyed on the TTL column keeps the periodic
            -- DELETE from scanning the whole table at multi-GB scale.
            CREATE INDEX IF NOT EXISTS idx_gse_ttl
                ON guaranteed_state_events(ttl_expires_at)
                WHERE ttl_expires_at > 0;
        )"},
    };
    if (!MigrationRunner::run(db_, "guaranteed_state_store", kMigrations)) {
        // Include enough detail in the log for an on-call operator to triage
        // at 03:00 without reading source. `db_filename()` returns the path
        // of the main database file on this connection; if open succeeded
        // far enough to land here, it is non-null.
        const char* db_file = sqlite3_db_filename(db_, "main");
        spdlog::error("GuaranteedStateStore: schema migration failed for {}; "
                      "closing database. Recovery: stop server, move or "
                      "rename that file, and restart — rules must be "
                      "re-imported from server-authoritative source.",
                      db_file ? db_file : "<unknown>");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

int64_t GuaranteedStateStore::compute_ttl_epoch() const {
    if (retention_days_ <= 0)
        return 0;  // sentinel: never expire
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    return now + static_cast<int64_t>(retention_days_) * 86400;
}

std::expected<void, std::string>
GuaranteedStateStore::create_rule(const GuaranteedStateRuleRow& row) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    const char* sql = R"(
        INSERT INTO guaranteed_state_rules
            (rule_id, name, yaml_source, version, enabled, enforcement_mode,
             severity, os_target, scope_expr, signature, created_at, updated_at,
             created_by, updated_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    sqlite3_bind_text(stmt, 1, row.rule_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, row.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, row.yaml_source.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, row.version);
    sqlite3_bind_int(stmt, 5, row.enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 6, row.enforcement_mode.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, row.severity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, row.os_target.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, row.scope_expr.c_str(), -1, SQLITE_TRANSIENT);
    if (row.signature.empty()) {
        sqlite3_bind_null(stmt, 10);
    } else {
        sqlite3_bind_blob(stmt, 10, row.signature.data(),
                          static_cast<int>(row.signature.size()), SQLITE_TRANSIENT);
    }
    sqlite3_bind_text(stmt, 11, row.created_at.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, row.updated_at.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 13, row.created_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 14, row.updated_by.c_str(), -1, SQLITE_TRANSIENT);

    const int step = sqlite3_step(stmt);
    std::expected<void, std::string> result;
    if (step != SQLITE_DONE) {
        const int ext = sqlite3_extended_errcode(db_);
        const std::string err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        if (is_sqlite_uniqueness_violation(ext)) {
            // SQLite surfaces which constraint triggered in the errmsg
            // (e.g. "UNIQUE constraint failed: guaranteed_state_rules.name"
            // vs ".rule_id"). Name the offending column in the error so
            // operator-facing 409 bodies explain the collision.
            const bool name_collision = err.find(".name") != std::string::npos;
            const std::string what =
                name_collision ? ("rule name '" + row.name + "' already exists")
                               : ("rule_id '" + row.rule_id + "' already exists");
            return std::unexpected(format_conflict(what));
        }
        return std::unexpected("insert failed: " + err);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::expected<void, std::string>
GuaranteedStateStore::update_rule(const GuaranteedStateRuleRow& row) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    const char* sql = R"(
        UPDATE guaranteed_state_rules SET
            name = ?, yaml_source = ?, version = ?, enabled = ?,
            enforcement_mode = ?, severity = ?, os_target = ?,
            scope_expr = ?, signature = ?, updated_at = ?, updated_by = ?
        WHERE rule_id = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    sqlite3_bind_text(stmt, 1, row.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, row.yaml_source.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, row.version);
    sqlite3_bind_int(stmt, 4, row.enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 5, row.enforcement_mode.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, row.severity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, row.os_target.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, row.scope_expr.c_str(), -1, SQLITE_TRANSIENT);
    if (row.signature.empty()) {
        sqlite3_bind_null(stmt, 9);
    } else {
        sqlite3_bind_blob(stmt, 9, row.signature.data(),
                          static_cast<int>(row.signature.size()), SQLITE_TRANSIENT);
    }
    sqlite3_bind_text(stmt, 10, row.updated_at.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, row.updated_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 12, row.rule_id.c_str(), -1, SQLITE_TRANSIENT);

    const int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE) {
        const int ext = sqlite3_extended_errcode(db_);
        const std::string err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        if (is_sqlite_uniqueness_violation(ext)) {
            return std::unexpected(
                format_conflict("rule name '" + row.name + "' already exists"));
        }
        return std::unexpected("update failed: " + err);
    }
    const auto changed = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    if (changed == 0)
        return std::unexpected("not found: rule_id '" + row.rule_id + "'");
    return {};
}

std::expected<void, std::string>
GuaranteedStateStore::delete_rule(const std::string& rule_id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM guaranteed_state_rules WHERE rule_id = ?", -1, &stmt,
                           nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
    sqlite3_bind_text(stmt, 1, rule_id.c_str(), -1, SQLITE_TRANSIENT);
    const int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE) {
        const std::string err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        return std::unexpected("delete failed: " + err);
    }
    const auto changed = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    if (changed == 0)
        return std::unexpected("not found: rule_id '" + rule_id + "'");
    return {};
}

std::optional<GuaranteedStateRuleRow>
GuaranteedStateStore::get_rule(const std::string& rule_id) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return std::nullopt;

    const char* sql = R"(
        SELECT rule_id, name, yaml_source, version, enabled, enforcement_mode,
               severity, os_target, scope_expr, signature, created_at, updated_at,
               created_by, updated_by
        FROM guaranteed_state_rules WHERE rule_id = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(stmt, 1, rule_id.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<GuaranteedStateRuleRow> out;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        GuaranteedStateRuleRow r;
        r.rule_id = col_text(stmt, 0);
        r.name = col_text(stmt, 1);
        r.yaml_source = col_text(stmt, 2);
        r.version = sqlite3_column_int64(stmt, 3);
        r.enabled = sqlite3_column_int(stmt, 4) != 0;
        r.enforcement_mode = col_text(stmt, 5);
        r.severity = col_text(stmt, 6);
        r.os_target = col_text(stmt, 7);
        r.scope_expr = col_text(stmt, 8);
        r.signature = col_blob(stmt, 9);
        r.created_at = col_text(stmt, 10);
        r.updated_at = col_text(stmt, 11);
        r.created_by = col_text(stmt, 12);
        r.updated_by = col_text(stmt, 13);
        out = std::move(r);
    }
    sqlite3_finalize(stmt);
    return out;
}

std::vector<GuaranteedStateRuleRow> GuaranteedStateStore::list_rules() const {
    std::shared_lock lock(mtx_);
    std::vector<GuaranteedStateRuleRow> rows;
    if (!db_)
        return rows;

    const char* sql = R"(
        SELECT rule_id, name, yaml_source, version, enabled, enforcement_mode,
               severity, os_target, scope_expr, signature, created_at, updated_at,
               created_by, updated_by
        FROM guaranteed_state_rules ORDER BY name
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return rows;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        GuaranteedStateRuleRow r;
        r.rule_id = col_text(stmt, 0);
        r.name = col_text(stmt, 1);
        r.yaml_source = col_text(stmt, 2);
        r.version = sqlite3_column_int64(stmt, 3);
        r.enabled = sqlite3_column_int(stmt, 4) != 0;
        r.enforcement_mode = col_text(stmt, 5);
        r.severity = col_text(stmt, 6);
        r.os_target = col_text(stmt, 7);
        r.scope_expr = col_text(stmt, 8);
        r.signature = col_blob(stmt, 9);
        r.created_at = col_text(stmt, 10);
        r.updated_at = col_text(stmt, 11);
        r.created_by = col_text(stmt, 12);
        r.updated_by = col_text(stmt, 13);
        rows.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return rows;
}

std::expected<void, std::string>
GuaranteedStateStore::insert_event(const GuaranteedStateEventRow& row) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    const char* sql = R"(
        INSERT INTO guaranteed_state_events
            (event_id, rule_id, agent_id, event_type, severity,
             guard_type, guard_category, detected_value, expected_value,
             remediation_action, remediation_success,
             detection_latency_us, remediation_latency_us, timestamp,
             ttl_expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    sqlite3_bind_text(stmt, 1, row.event_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, row.rule_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, row.agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, row.event_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, row.severity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, row.guard_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, row.guard_category.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, row.detected_value.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, row.expected_value.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, row.remediation_action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 11, row.remediation_success ? 1 : 0);
    sqlite3_bind_int64(stmt, 12, row.detection_latency_us);
    sqlite3_bind_int64(stmt, 13, row.remediation_latency_us);
    sqlite3_bind_text(stmt, 14, row.timestamp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 15, compute_ttl_epoch());

    const int step = sqlite3_step(stmt);
    if (step != SQLITE_DONE) {
        const int ext = sqlite3_extended_errcode(db_);
        const std::string err = sqlite3_errmsg(db_);
        sqlite3_finalize(stmt);
        if (is_sqlite_uniqueness_violation(ext)) {
            return std::unexpected(
                format_conflict("event_id '" + row.event_id + "' already exists"));
        }
        return std::unexpected("insert failed: " + err);
    }
    sqlite3_finalize(stmt);
    events_written_.fetch_add(1, std::memory_order_relaxed);
    return {};
}

std::expected<std::size_t, std::string>
GuaranteedStateStore::insert_events(const std::vector<GuaranteedStateEventRow>& rows) {
    if (rows.empty())
        return 0;

    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    // Single BEGIN..COMMIT envelope — on any failure the whole batch rolls
    // back so the REST layer never has to reason about partial inserts.
    if (sqlite3_exec(db_, "BEGIN", nullptr, nullptr, nullptr) != SQLITE_OK) {
        return std::unexpected(std::string("BEGIN failed: ") + sqlite3_errmsg(db_));
    }

    const char* sql = R"(
        INSERT INTO guaranteed_state_events
            (event_id, rule_id, agent_id, event_type, severity,
             guard_type, guard_category, detected_value, expected_value,
             remediation_action, remediation_success,
             detection_latency_us, remediation_latency_us, timestamp,
             ttl_expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        const std::string err = sqlite3_errmsg(db_);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return std::unexpected("prepare failed: " + err);
    }

    const int64_t ttl = compute_ttl_epoch();

    for (const auto& row : rows) {
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);

        sqlite3_bind_text(stmt, 1, row.event_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, row.rule_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, row.agent_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, row.event_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, row.severity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, row.guard_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 7, row.guard_category.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, row.detected_value.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 9, row.expected_value.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 10, row.remediation_action.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 11, row.remediation_success ? 1 : 0);
        sqlite3_bind_int64(stmt, 12, row.detection_latency_us);
        sqlite3_bind_int64(stmt, 13, row.remediation_latency_us);
        sqlite3_bind_text(stmt, 14, row.timestamp.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 15, ttl);

        const int step = sqlite3_step(stmt);
        if (step != SQLITE_DONE) {
            const int ext = sqlite3_extended_errcode(db_);
            const std::string err = sqlite3_errmsg(db_);
            sqlite3_finalize(stmt);
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            if (is_sqlite_uniqueness_violation(ext)) {
                return std::unexpected(
                    format_conflict("event_id '" + row.event_id + "' already exists"));
            }
            return std::unexpected("insert failed: " + err);
        }
    }

    sqlite3_finalize(stmt);

    if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK) {
        const std::string err = sqlite3_errmsg(db_);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return std::unexpected("COMMIT failed: " + err);
    }
    events_written_.fetch_add(rows.size(), std::memory_order_relaxed);
    return rows.size();
}

std::vector<GuaranteedStateEventRow>
GuaranteedStateStore::query_events(const GuaranteedStateEventQuery& q) const {
    std::shared_lock lock(mtx_);
    std::vector<GuaranteedStateEventRow> rows;
    if (!db_)
        return rows;

    std::string sql =
        "SELECT event_id, rule_id, agent_id, event_type, severity, guard_type, guard_category, "
        "detected_value, expected_value, remediation_action, remediation_success, "
        "detection_latency_us, remediation_latency_us, timestamp "
        "FROM guaranteed_state_events WHERE 1=1";
    std::vector<std::pair<int, std::string>> text_binds;
    int bind_idx = 1;

    if (!q.rule_id.empty()) {
        sql += " AND rule_id = ?";
        text_binds.emplace_back(bind_idx++, q.rule_id);
    }
    if (!q.agent_id.empty()) {
        sql += " AND agent_id = ?";
        text_binds.emplace_back(bind_idx++, q.agent_id);
    }
    if (!q.severity.empty()) {
        sql += " AND severity = ?";
        text_binds.emplace_back(bind_idx++, q.severity);
    }
    // Secondary sort by event_id for deterministic tie-break when multiple
    // events share the same timestamp (common under fleet-wide drift bursts
    // where many agents timestamp with second-granularity clocks).
    sql += " ORDER BY timestamp DESC, event_id DESC LIMIT ?";
    int limit_idx = bind_idx++;
    int offset_idx = 0;
    if (q.offset > 0) {
        sql += " OFFSET ?";
        offset_idx = bind_idx++;
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return rows;

    for (const auto& [idx, val] : text_binds)
        sqlite3_bind_text(stmt, idx, val.c_str(), -1, SQLITE_TRANSIENT);
    // Clamp limit: defence-in-depth against a misconfigured or malicious
    // caller who could otherwise materialise the entire events table into
    // a vector (GB-scale RSS spike).
    //
    // Lower bound is 0, not 1 — `LIMIT 0` is a valid SQLite query returning
    // zero rows, and that's the semantic sibling stores (`audit_store`,
    // `workflow_engine`, `inventory_store`) expose to callers. Clamping up
    // to 1 would silently promote `limit=0` into a one-row result, breaking
    // cross-store consistency. Negative limits are clamped to 0 for the
    // same reason.
    const int clamped_limit = std::clamp(q.limit, 0, kMaxEventsLimit);
    sqlite3_bind_int64(stmt, limit_idx, clamped_limit);
    if (offset_idx > 0)
        sqlite3_bind_int64(stmt, offset_idx, q.offset);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        GuaranteedStateEventRow r;
        r.event_id = col_text(stmt, 0);
        r.rule_id = col_text(stmt, 1);
        r.agent_id = col_text(stmt, 2);
        r.event_type = col_text(stmt, 3);
        r.severity = col_text(stmt, 4);
        r.guard_type = col_text(stmt, 5);
        r.guard_category = col_text(stmt, 6);
        r.detected_value = col_text(stmt, 7);
        r.expected_value = col_text(stmt, 8);
        r.remediation_action = col_text(stmt, 9);
        r.remediation_success = sqlite3_column_int(stmt, 10) != 0;
        r.detection_latency_us = sqlite3_column_int64(stmt, 11);
        r.remediation_latency_us = sqlite3_column_int64(stmt, 12);
        r.timestamp = col_text(stmt, 13);
        rows.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return rows;
}

std::size_t GuaranteedStateStore::rule_count() const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return 0;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM guaranteed_state_rules", -1, &stmt,
                           nullptr) != SQLITE_OK)
        return 0;
    std::size_t n = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        n = static_cast<std::size_t>(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return n;
}

std::size_t GuaranteedStateStore::event_count() const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return 0;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM guaranteed_state_events", -1, &stmt,
                           nullptr) != SQLITE_OK)
        return 0;
    std::size_t n = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        n = static_cast<std::size_t>(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return n;
}

// ── Retention reaper ─────────────────────────────────────────────────────────

void GuaranteedStateStore::start_cleanup() {
    if (!db_)
        return;
#ifdef __cpp_lib_jthread
    cleanup_thread_ = std::jthread([this](std::stop_token stop) { run_cleanup(stop); });
#else
    stop_requested_ = false;
    cleanup_thread_ = std::thread([this]() { run_cleanup(); });
#endif
}

void GuaranteedStateStore::stop_cleanup() {
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
void GuaranteedStateStore::run_cleanup(std::stop_token stop) {
    while (!stop.stop_requested()) {
        // Short sleep slices so tests + shutdown see request_stop within ~1s
        // instead of waiting out the full cleanup_interval_min_.
        for (int i = 0; i < cleanup_interval_min_ * 60 && !stop.stop_requested(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stop.stop_requested())
            break;
#else
void GuaranteedStateStore::run_cleanup() {
    while (!stop_requested_.load()) {
        for (int i = 0; i < cleanup_interval_min_ * 60 && !stop_requested_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stop_requested_.load())
            break;
#endif

        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();

        std::unique_lock lock(mtx_);
        if (!db_)
            continue;
        sqlite3_stmt* cleanup_stmt = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "DELETE FROM guaranteed_state_events "
                               "WHERE ttl_expires_at > 0 AND ttl_expires_at < ?",
                               -1, &cleanup_stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(cleanup_stmt, 1, now);
            if (sqlite3_step(cleanup_stmt) == SQLITE_DONE) {
                const auto deleted = sqlite3_changes(db_);
                if (deleted > 0) {
                    events_reaped_.fetch_add(static_cast<uint64_t>(deleted),
                                             std::memory_order_relaxed);
                    spdlog::info("GuaranteedStateStore: expired {} events", deleted);
                }
            } else {
                spdlog::warn("GuaranteedStateStore: cleanup error: {}", sqlite3_errmsg(db_));
            }
            sqlite3_finalize(cleanup_stmt);
        }
    }
}

} // namespace yuzu::server
