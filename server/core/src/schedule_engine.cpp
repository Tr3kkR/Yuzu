#include "schedule_engine.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <random>

namespace yuzu::server {

namespace {

std::string generate_id() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    auto hi = dist(rng);
    auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx", static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string col_text(sqlite3_stmt* stmt, int col) {
    auto p = sqlite3_column_text(stmt, col);
    return p ? std::string(reinterpret_cast<const char*>(p)) : std::string{};
}

InstructionSchedule row_to_schedule(sqlite3_stmt* stmt) {
    InstructionSchedule s;
    s.id = col_text(stmt, 0);
    s.name = col_text(stmt, 1);
    s.definition_id = col_text(stmt, 2);
    s.frequency_type = col_text(stmt, 3);
    s.interval_minutes = sqlite3_column_int(stmt, 4);
    s.time_of_day = col_text(stmt, 5);
    s.day_of_week = sqlite3_column_int(stmt, 6);
    s.day_of_month = sqlite3_column_int(stmt, 7);
    s.scope_expression = col_text(stmt, 8);
    s.requires_approval = sqlite3_column_int(stmt, 9) != 0;
    s.enabled = sqlite3_column_int(stmt, 10) != 0;
    s.next_execution_at = sqlite3_column_int64(stmt, 11);
    s.last_executed_at = sqlite3_column_int64(stmt, 12);
    s.execution_count = sqlite3_column_int(stmt, 13);
    s.created_by = col_text(stmt, 14);
    s.created_at = sqlite3_column_int64(stmt, 15);
    return s;
}

const char* kSelectAllCols = "id, name, definition_id, frequency_type, interval_minutes, "
                             "time_of_day, day_of_week, day_of_month, scope_expression, "
                             "requires_approval, enabled, next_execution_at, last_executed_at, "
                             "execution_count, created_by, created_at";

bool is_valid_frequency(const std::string& freq) {
    return freq == "once" || freq == "interval" || freq == "daily" || freq == "weekly" ||
           freq == "monthly";
}

int64_t compute_initial_next_execution(const std::string& frequency_type, int interval_minutes) {
    auto now = now_epoch();

    if (frequency_type == "once") {
        return now;
    }
    if (frequency_type == "interval") {
        return now + static_cast<int64_t>(interval_minutes) * 60;
    }
    if (frequency_type == "daily") {
        return now + 86400;
    }
    if (frequency_type == "weekly") {
        return now + 7 * 86400;
    }
    if (frequency_type == "monthly") {
        return now + 30 * 86400;
    }

    return now;
}

} // namespace

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

ScheduleEngine::ScheduleEngine(sqlite3* db) : db_(db) {}

void ScheduleEngine::create_tables() {
    if (!db_)
        return;

    const char* ddl = R"(
        CREATE TABLE IF NOT EXISTS schedules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            definition_id TEXT NOT NULL,
            frequency_type TEXT NOT NULL DEFAULT 'once',
            interval_minutes INTEGER NOT NULL DEFAULT 60,
            time_of_day TEXT NOT NULL DEFAULT '00:00',
            day_of_week INTEGER NOT NULL DEFAULT 0,
            day_of_month INTEGER NOT NULL DEFAULT 1,
            scope_expression TEXT NOT NULL DEFAULT '',
            requires_approval INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            next_execution_at INTEGER NOT NULL DEFAULT 0,
            last_executed_at INTEGER NOT NULL DEFAULT 0,
            execution_count INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL DEFAULT 0
        );
    )";
    sqlite3_exec(db_, ddl, nullptr, nullptr, nullptr);
}

void ScheduleEngine::stop() {
    // stub -- will stop the scheduler tick thread when implemented
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

std::vector<InstructionSchedule> ScheduleEngine::query_schedules(const ScheduleQuery& q) const {
    std::vector<InstructionSchedule> results;
    if (!db_)
        return results;

    std::string sql = std::string("SELECT ") + kSelectAllCols + " FROM schedules WHERE 1=1";
    std::vector<std::string> binds;

    if (!q.definition_id.empty()) {
        sql += " AND definition_id = ?";
        binds.push_back(q.definition_id);
    }
    if (q.enabled_only) {
        sql += " AND enabled = 1";
    }
    sql += " ORDER BY name ASC LIMIT 100";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    for (int i = 0; i < static_cast<int>(binds.size()); ++i)
        sqlite3_bind_text(stmt, i + 1, binds[i].c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW)
        results.push_back(row_to_schedule(stmt));

    sqlite3_finalize(stmt);
    return results;
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

std::expected<std::string, std::string>
ScheduleEngine::create_schedule(const InstructionSchedule& sched) {
    if (!db_)
        return std::unexpected("database not open");
    if (sched.name.empty())
        return std::unexpected("name is required");
    if (sched.definition_id.empty())
        return std::unexpected("definition_id is required");
    if (!is_valid_frequency(sched.frequency_type))
        return std::unexpected(
            "frequency_type must be one of: once, interval, daily, weekly, monthly");

    auto id = sched.id.empty() ? generate_id() : sched.id;
    auto now = now_epoch();
    auto next = sched.next_execution_at > 0
                    ? sched.next_execution_at
                    : compute_initial_next_execution(sched.frequency_type, sched.interval_minutes);

    const char* sql = R"(
        INSERT INTO schedules
        (id, name, definition_id, frequency_type, interval_minutes,
         time_of_day, day_of_week, day_of_month, scope_expression,
         requires_approval, enabled, next_execution_at, last_executed_at,
         execution_count, created_by, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    int i = 1;
    sqlite3_bind_text(stmt, i++, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, sched.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, sched.definition_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, sched.frequency_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, i++, sched.interval_minutes);
    sqlite3_bind_text(stmt, i++, sched.time_of_day.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, i++, sched.day_of_week);
    sqlite3_bind_int(stmt, i++, sched.day_of_month);
    sqlite3_bind_text(stmt, i++, sched.scope_expression.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, i++, sched.requires_approval ? 1 : 0);
    sqlite3_bind_int(stmt, i++, sched.enabled ? 1 : 0);
    sqlite3_bind_int64(stmt, i++, next);
    sqlite3_bind_int64(stmt, i++, sched.last_executed_at);
    sqlite3_bind_int(stmt, i++, sched.execution_count);
    sqlite3_bind_text(stmt, i++, sched.created_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, i++, sched.created_at > 0 ? sched.created_at : now);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        auto err = std::string(sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("insert failed: " + err);
    }
    sqlite3_finalize(stmt);
    spdlog::info("ScheduleEngine: created schedule '{}' (id={}, freq={})", sched.name, id,
                 sched.frequency_type);
    return id;
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

bool ScheduleEngine::delete_schedule(const std::string& id) {
    if (!db_)
        return false;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM schedules WHERE id=?", -1, &stmt, nullptr) !=
        SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    auto changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    return changes > 0;
}

// ---------------------------------------------------------------------------
// Enable / Disable
// ---------------------------------------------------------------------------

void ScheduleEngine::set_enabled(const std::string& id, bool enabled) {
    if (!db_)
        return;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "UPDATE schedules SET enabled=? WHERE id=?", -1, &stmt, nullptr) !=
        SQLITE_OK)
        return;

    sqlite3_bind_int(stmt, 1, enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ---------------------------------------------------------------------------
// Evaluate due schedules
// ---------------------------------------------------------------------------

std::vector<InstructionSchedule> ScheduleEngine::evaluate_due() const {
    std::vector<InstructionSchedule> results;
    if (!db_)
        return results;

    auto now = now_epoch();

    std::string sql = std::string("SELECT ") + kSelectAllCols +
                      " FROM schedules WHERE enabled = 1"
                      " AND next_execution_at > 0"
                      " AND next_execution_at <= ?"
                      " ORDER BY next_execution_at ASC";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    sqlite3_bind_int64(stmt, 1, now);

    while (sqlite3_step(stmt) == SQLITE_ROW)
        results.push_back(row_to_schedule(stmt));

    sqlite3_finalize(stmt);
    return results;
}

// ---------------------------------------------------------------------------
// Advance schedule after firing
// ---------------------------------------------------------------------------

void ScheduleEngine::advance_schedule(const std::string& id) {
    if (!db_)
        return;

    // Read current schedule state
    std::string select_sql =
        std::string("SELECT ") + kSelectAllCols + " FROM schedules WHERE id = ?";
    sqlite3_stmt* sel = nullptr;
    if (sqlite3_prepare_v2(db_, select_sql.c_str(), -1, &sel, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(sel, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(sel) != SQLITE_ROW) {
        sqlite3_finalize(sel);
        return;
    }

    auto sched = row_to_schedule(sel);
    sqlite3_finalize(sel);

    auto now = now_epoch();
    int64_t next = 0;

    if (sched.frequency_type == "once") {
        next = 0; // disable after single execution
    } else if (sched.frequency_type == "interval") {
        next = now + static_cast<int64_t>(sched.interval_minutes) * 60;
    } else if (sched.frequency_type == "daily") {
        next = now + 86400;
    } else if (sched.frequency_type == "weekly") {
        next = now + 7 * 86400;
    } else if (sched.frequency_type == "monthly") {
        next = now + 30 * 86400; // approximate
    }

    const char* update_sql = R"(
        UPDATE schedules
        SET next_execution_at = ?,
            last_executed_at = ?,
            execution_count = execution_count + 1
        WHERE id = ?
    )";
    sqlite3_stmt* upd = nullptr;
    if (sqlite3_prepare_v2(db_, update_sql, -1, &upd, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_int64(upd, 1, next);
    sqlite3_bind_int64(upd, 2, now);
    sqlite3_bind_text(upd, 3, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(upd);
    sqlite3_finalize(upd);

    spdlog::debug("ScheduleEngine: advanced schedule id={} (freq={}, next_at={})", id,
                  sched.frequency_type, next);
}

} // namespace yuzu::server
