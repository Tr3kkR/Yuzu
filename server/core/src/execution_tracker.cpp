#include "execution_tracker.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <random>

namespace yuzu::server {

namespace {

std::string generate_id() {
    static std::mt19937_64 rng(std::random_device{}());
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

Execution row_to_exec(sqlite3_stmt* stmt) {
    Execution e;
    e.id = col_text(stmt, 0);
    e.definition_id = col_text(stmt, 1);
    e.status = col_text(stmt, 2);
    e.scope_expression = col_text(stmt, 3);
    e.parameter_values = col_text(stmt, 4);
    e.dispatched_by = col_text(stmt, 5);
    e.dispatched_at = sqlite3_column_int64(stmt, 6);
    e.agents_targeted = sqlite3_column_int(stmt, 7);
    e.agents_responded = sqlite3_column_int(stmt, 8);
    e.agents_success = sqlite3_column_int(stmt, 9);
    e.agents_failure = sqlite3_column_int(stmt, 10);
    e.completed_at = sqlite3_column_int64(stmt, 11);
    e.parent_id = col_text(stmt, 12);
    e.rerun_of = col_text(stmt, 13);
    return e;
}

const char* kSelectAll = "id, definition_id, status, scope_expression, parameter_values, "
                         "dispatched_by, dispatched_at, agents_targeted, agents_responded, "
                         "agents_success, agents_failure, completed_at, parent_id, rerun_of";

} // namespace

ExecutionTracker::ExecutionTracker(sqlite3* db) : db_(db) {}

void ExecutionTracker::create_tables() {
    if (!db_)
        return;

    const char* ddl = R"(
        CREATE TABLE IF NOT EXISTS executions (
            id TEXT PRIMARY KEY,
            definition_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            scope_expression TEXT NOT NULL DEFAULT '',
            parameter_values TEXT NOT NULL DEFAULT '',
            dispatched_by TEXT NOT NULL DEFAULT '',
            dispatched_at INTEGER NOT NULL DEFAULT 0,
            agents_targeted INTEGER NOT NULL DEFAULT 0,
            agents_responded INTEGER NOT NULL DEFAULT 0,
            agents_success INTEGER NOT NULL DEFAULT 0,
            agents_failure INTEGER NOT NULL DEFAULT 0,
            completed_at INTEGER NOT NULL DEFAULT 0,
            parent_id TEXT NOT NULL DEFAULT '',
            rerun_of TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS agent_exec_status (
            execution_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            dispatched_at INTEGER NOT NULL DEFAULT 0,
            first_response_at INTEGER NOT NULL DEFAULT 0,
            completed_at INTEGER NOT NULL DEFAULT 0,
            exit_code INTEGER NOT NULL DEFAULT 0,
            error_detail TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (execution_id, agent_id)
        );
    )";
    sqlite3_exec(db_, ddl, nullptr, nullptr, nullptr);
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

std::vector<Execution> ExecutionTracker::query_executions(const ExecutionQuery& q) const {
    std::vector<Execution> results;
    if (!db_)
        return results;

    std::string sql = std::string("SELECT ") + kSelectAll + " FROM executions WHERE 1=1";
    std::vector<std::string> binds;

    if (!q.definition_id.empty()) {
        sql += " AND definition_id = ?";
        binds.push_back(q.definition_id);
    }
    if (!q.status.empty()) {
        sql += " AND status = ?";
        binds.push_back(q.status);
    }
    sql += " ORDER BY dispatched_at DESC LIMIT ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    for (int i = 0; i < static_cast<int>(binds.size()); ++i)
        sqlite3_bind_text(stmt, i + 1, binds[i].c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, static_cast<int>(binds.size()) + 1, q.limit);

    while (sqlite3_step(stmt) == SQLITE_ROW)
        results.push_back(row_to_exec(stmt));

    sqlite3_finalize(stmt);
    return results;
}

std::optional<Execution> ExecutionTracker::get_execution(const std::string& id) const {
    if (!db_)
        return std::nullopt;

    auto sql = std::string("SELECT ") + kSelectAll + " FROM executions WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<Execution> result;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        result = row_to_exec(stmt);

    sqlite3_finalize(stmt);
    return result;
}

ExecutionSummary ExecutionTracker::get_summary(const std::string& id) const {
    ExecutionSummary s;
    s.id = id;
    auto exec = get_execution(id);
    if (!exec)
        return s;

    s.status = exec->status;
    s.agents_targeted = exec->agents_targeted;
    s.agents_responded = exec->agents_responded;
    s.agents_success = exec->agents_success;
    s.agents_failure = exec->agents_failure;
    s.progress_pct = s.agents_targeted > 0 ? (s.agents_responded * 100 / s.agents_targeted) : 0;
    return s;
}

std::vector<AgentExecStatus>
ExecutionTracker::get_agent_statuses(const std::string& execution_id) const {
    std::vector<AgentExecStatus> results;
    if (!db_)
        return results;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT agent_id, status, dispatched_at, first_response_at, completed_at, exit_code, "
            "error_detail FROM agent_exec_status WHERE execution_id = ? ORDER BY agent_id",
            -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    sqlite3_bind_text(stmt, 1, execution_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AgentExecStatus a;
        a.agent_id = col_text(stmt, 0);
        a.status = col_text(stmt, 1);
        a.dispatched_at = sqlite3_column_int64(stmt, 2);
        a.first_response_at = sqlite3_column_int64(stmt, 3);
        a.completed_at = sqlite3_column_int64(stmt, 4);
        a.exit_code = sqlite3_column_int(stmt, 5);
        a.error_detail = col_text(stmt, 6);
        results.push_back(std::move(a));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::vector<Execution> ExecutionTracker::get_children(const std::string& parent_id) const {
    std::vector<Execution> results;
    if (!db_)
        return results;

    auto sql = std::string("SELECT ") + kSelectAll +
               " FROM executions WHERE parent_id = ? ORDER BY dispatched_at DESC";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    sqlite3_bind_text(stmt, 1, parent_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW)
        results.push_back(row_to_exec(stmt));

    sqlite3_finalize(stmt);
    return results;
}

// ---------------------------------------------------------------------------
// Mutation
// ---------------------------------------------------------------------------

std::expected<std::string, std::string> ExecutionTracker::create_execution(const Execution& exec) {
    if (!db_)
        return std::unexpected("database not open");

    auto id = exec.id.empty() ? generate_id() : exec.id;
    auto now = now_epoch();

    const char* sql = R"(
        INSERT INTO executions
        (id, definition_id, status, scope_expression, parameter_values,
         dispatched_by, dispatched_at, agents_targeted, agents_responded,
         agents_success, agents_failure, completed_at, parent_id, rerun_of)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    int i = 1;
    sqlite3_bind_text(stmt, i++, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, exec.definition_id.c_str(), -1, SQLITE_TRANSIENT);
    auto status = exec.status.empty() ? "running" : exec.status;
    sqlite3_bind_text(stmt, i++, status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, exec.scope_expression.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, exec.parameter_values.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, exec.dispatched_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, i++, exec.dispatched_at > 0 ? exec.dispatched_at : now);
    sqlite3_bind_int(stmt, i++, exec.agents_targeted);
    sqlite3_bind_int(stmt, i++, exec.agents_responded);
    sqlite3_bind_int(stmt, i++, exec.agents_success);
    sqlite3_bind_int(stmt, i++, exec.agents_failure);
    sqlite3_bind_int64(stmt, i++, exec.completed_at);
    sqlite3_bind_text(stmt, i++, exec.parent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, exec.rerun_of.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        auto err = std::string(sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("insert failed: " + err);
    }
    sqlite3_finalize(stmt);
    return id;
}

void ExecutionTracker::update_agent_status(const std::string& execution_id,
                                           const AgentExecStatus& s) {
    if (!db_)
        return;

    const char* sql = R"(
        INSERT INTO agent_exec_status
        (execution_id, agent_id, status, dispatched_at, first_response_at, completed_at, exit_code, error_detail)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(execution_id, agent_id) DO UPDATE SET
            status=excluded.status,
            first_response_at=CASE WHEN agent_exec_status.first_response_at=0 THEN excluded.first_response_at ELSE agent_exec_status.first_response_at END,
            completed_at=excluded.completed_at,
            exit_code=excluded.exit_code,
            error_detail=excluded.error_detail
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    auto now = now_epoch();
    int i = 1;
    sqlite3_bind_text(stmt, i++, execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, s.agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, i++, s.status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, i++, s.dispatched_at > 0 ? s.dispatched_at : now);
    sqlite3_bind_int64(stmt, i++, s.first_response_at > 0 ? s.first_response_at : now);
    sqlite3_bind_int64(stmt, i++, s.completed_at);
    sqlite3_bind_int(stmt, i++, s.exit_code);
    sqlite3_bind_text(stmt, i++, s.error_detail.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void ExecutionTracker::refresh_counts(const std::string& execution_id) {
    if (!db_)
        return;

    // Recompute aggregate counts from agent_exec_status
    const char* sql = R"(
        UPDATE executions SET
            agents_responded = (SELECT COUNT(*) FROM agent_exec_status WHERE execution_id=? AND status IN ('success','failure','timeout','rejected')),
            agents_success   = (SELECT COUNT(*) FROM agent_exec_status WHERE execution_id=? AND status='success'),
            agents_failure   = (SELECT COUNT(*) FROM agent_exec_status WHERE execution_id=? AND status IN ('failure','timeout','rejected'))
        WHERE id=?
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // Check if all agents responded and update status
    auto exec = get_execution(execution_id);
    if (exec && exec->agents_targeted > 0 && exec->agents_responded >= exec->agents_targeted) {
        auto final_status = (exec->agents_failure == 0) ? "succeeded" : "completed";
        sqlite3_stmt* upd = nullptr;
        if (sqlite3_prepare_v2(
                db_,
                "UPDATE executions SET status=?, completed_at=? WHERE id=? AND status='running'",
                -1, &upd, nullptr) == SQLITE_OK) {
            auto now = now_epoch();
            sqlite3_bind_text(upd, 1, final_status, -1, SQLITE_STATIC);
            sqlite3_bind_int64(upd, 2, now);
            sqlite3_bind_text(upd, 3, execution_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(upd);
            sqlite3_finalize(upd);
        }
    }
}

std::expected<std::string, std::string>
ExecutionTracker::create_rerun(const std::string& original_id, const std::string& user,
                               bool failed_only) {
    auto orig = get_execution(original_id);
    if (!orig)
        return std::unexpected("original execution not found");

    Execution rerun;
    rerun.definition_id = orig->definition_id;
    rerun.scope_expression = orig->scope_expression;
    rerun.parameter_values = orig->parameter_values;
    rerun.dispatched_by = user;
    rerun.parent_id = original_id;
    rerun.rerun_of = original_id;
    rerun.status = "pending";

    if (failed_only) {
        // Count only failed agents as targets
        auto agents = get_agent_statuses(original_id);
        int failed_count = 0;
        for (const auto& a : agents) {
            if (a.status == "failure" || a.status == "timeout" || a.status == "rejected")
                ++failed_count;
        }
        rerun.agents_targeted = failed_count;
    } else {
        rerun.agents_targeted = orig->agents_targeted;
    }

    return create_execution(rerun);
}

void ExecutionTracker::mark_cancelled(const std::string& id, const std::string& /*user*/) {
    if (!db_)
        return;

    auto now = now_epoch();
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "UPDATE executions SET status='cancelled', completed_at=? WHERE id=?",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_int64(stmt, 1, now);
    sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

} // namespace yuzu::server
