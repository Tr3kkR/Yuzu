#include "guaranteed_state_store.hpp"
#include "migration_runner.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

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

} // namespace

GuaranteedStateStore::GuaranteedStateStore(const std::filesystem::path& db_path) {
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
    create_tables();
    if (db_)
        spdlog::info("GuaranteedStateStore: opened {}", db_path.string());
}

GuaranteedStateStore::~GuaranteedStateStore() {
    if (db_)
        sqlite3_close(db_);
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
                updated_at       TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_gsr_os
                ON guaranteed_state_rules(os_target);
            CREATE INDEX IF NOT EXISTS idx_gsr_enabled
                ON guaranteed_state_rules(enabled);

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
                timestamp              TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_gse_rule
                ON guaranteed_state_events(rule_id);
            CREATE INDEX IF NOT EXISTS idx_gse_agent
                ON guaranteed_state_events(agent_id);
            CREATE INDEX IF NOT EXISTS idx_gse_time
                ON guaranteed_state_events(timestamp);
        )"},
    };
    if (!MigrationRunner::run(db_, "guaranteed_state_store", kMigrations)) {
        spdlog::error("GuaranteedStateStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool GuaranteedStateStore::create_rule(const GuaranteedStateRuleRow& row) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    const char* sql = R"(
        INSERT INTO guaranteed_state_rules
            (rule_id, name, yaml_source, version, enabled, enforcement_mode,
             severity, os_target, scope_expr, signature, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

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

    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

bool GuaranteedStateStore::update_rule(const GuaranteedStateRuleRow& row) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    const char* sql = R"(
        UPDATE guaranteed_state_rules SET
            name = ?, yaml_source = ?, version = ?, enabled = ?,
            enforcement_mode = ?, severity = ?, os_target = ?,
            scope_expr = ?, signature = ?, updated_at = ?
        WHERE rule_id = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

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
    sqlite3_bind_text(stmt, 11, row.rule_id.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db_) > 0;
    sqlite3_finalize(stmt);
    return ok;
}

bool GuaranteedStateStore::delete_rule(const std::string& rule_id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM guaranteed_state_rules WHERE rule_id = ?", -1, &stmt,
                           nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_text(stmt, 1, rule_id.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db_) > 0;
    sqlite3_finalize(stmt);
    return ok;
}

std::optional<GuaranteedStateRuleRow>
GuaranteedStateStore::get_rule(const std::string& rule_id) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return std::nullopt;

    const char* sql = R"(
        SELECT rule_id, name, yaml_source, version, enabled, enforcement_mode,
               severity, os_target, scope_expr, signature, created_at, updated_at
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
               severity, os_target, scope_expr, signature, created_at, updated_at
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
        rows.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return rows;
}

bool GuaranteedStateStore::insert_event(const GuaranteedStateEventRow& row) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    const char* sql = R"(
        INSERT INTO guaranteed_state_events
            (event_id, rule_id, agent_id, event_type, severity,
             guard_type, guard_category, detected_value, expected_value,
             remediation_action, remediation_success,
             detection_latency_us, remediation_latency_us, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

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

    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
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
    sql += " ORDER BY timestamp DESC LIMIT ?";
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
    sqlite3_bind_int64(stmt, limit_idx, q.limit);
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

} // namespace yuzu::server
