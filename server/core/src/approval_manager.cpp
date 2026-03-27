#include "approval_manager.hpp"

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

Approval row_to_approval(sqlite3_stmt* stmt) {
    Approval a;
    a.id = col_text(stmt, 0);
    a.definition_id = col_text(stmt, 1);
    a.status = col_text(stmt, 2);
    a.submitted_by = col_text(stmt, 3);
    a.submitted_at = sqlite3_column_int64(stmt, 4);
    a.reviewed_by = col_text(stmt, 5);
    a.reviewed_at = sqlite3_column_int64(stmt, 6);
    a.review_comment = col_text(stmt, 7);
    a.scope_expression = col_text(stmt, 8);
    return a;
}

} // namespace

ApprovalManager::ApprovalManager(sqlite3* db) : db_(db) {}

void ApprovalManager::create_tables() {
    if (!db_)
        return;

    const char* ddl = R"(
        CREATE TABLE IF NOT EXISTS approvals (
            id TEXT PRIMARY KEY,
            definition_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            submitted_by TEXT NOT NULL DEFAULT '',
            submitted_at INTEGER NOT NULL DEFAULT 0,
            reviewed_by TEXT NOT NULL DEFAULT '',
            reviewed_at INTEGER NOT NULL DEFAULT 0,
            review_comment TEXT NOT NULL DEFAULT '',
            scope_expression TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_approvals_status
            ON approvals(status);
        CREATE INDEX IF NOT EXISTS idx_approvals_submitted_at
            ON approvals(submitted_at);
        CREATE INDEX IF NOT EXISTS idx_approvals_definition
            ON approvals(definition_id);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, ddl, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("ApprovalManager: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

// ---------------------------------------------------------------------------
// Submit
// ---------------------------------------------------------------------------

std::expected<std::string, std::string>
ApprovalManager::submit(const std::string& definition_id, const std::string& submitted_by,
                        const std::string& scope_expression) {
    if (!db_)
        return std::unexpected("database not open");
    if (definition_id.empty())
        return std::unexpected("definition_id is required");
    if (submitted_by.empty())
        return std::unexpected("submitted_by is required");

    auto id = generate_id();
    auto ts = now_epoch();

    const char* sql = R"(
        INSERT INTO approvals (id, definition_id, status, submitted_by, submitted_at,
                               reviewed_by, reviewed_at, review_comment, scope_expression)
        VALUES (?, ?, 'pending', ?, ?, '', 0, '', ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, definition_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, submitted_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, ts);
    sqlite3_bind_text(stmt, 5, scope_expression.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        auto err = std::string(sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("insert failed: " + err);
    }
    sqlite3_finalize(stmt);

    spdlog::info("ApprovalManager: submitted approval {} for definition {} by {}", id,
                 definition_id, submitted_by);
    return id;
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

std::vector<Approval> ApprovalManager::query(const ApprovalQuery& q) const {
    std::vector<Approval> results;
    if (!db_)
        return results;

    std::string sql = "SELECT id, definition_id, status, submitted_by, submitted_at, "
                      "reviewed_by, reviewed_at, review_comment, scope_expression "
                      "FROM approvals WHERE 1=1";
    std::vector<std::string> binds;

    if (!q.status.empty()) {
        sql += " AND status = ?";
        binds.push_back(q.status);
    }
    if (!q.submitted_by.empty()) {
        sql += " AND submitted_by = ?";
        binds.push_back(q.submitted_by);
    }
    sql += " ORDER BY submitted_at DESC LIMIT 100";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    for (int i = 0; i < static_cast<int>(binds.size()); ++i)
        sqlite3_bind_text(stmt, i + 1, binds[i].c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW)
        results.push_back(row_to_approval(stmt));

    sqlite3_finalize(stmt);
    return results;
}

// ---------------------------------------------------------------------------
// Pending count
// ---------------------------------------------------------------------------

int ApprovalManager::pending_count() const {
    if (!db_)
        return 0;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM approvals WHERE status = 'pending'", -1,
                           &stmt, nullptr) != SQLITE_OK)
        return 0;

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);

    sqlite3_finalize(stmt);
    return count;
}

// ---------------------------------------------------------------------------
// Approve / Reject
// ---------------------------------------------------------------------------

std::expected<void, std::string> ApprovalManager::approve(const std::string& id,
                                                          const std::string& reviewer,
                                                          const std::string& comment) {
    return set_review_status(id, "approved", reviewer, comment);
}

std::expected<void, std::string> ApprovalManager::reject(const std::string& id,
                                                         const std::string& reviewer,
                                                         const std::string& comment) {
    return set_review_status(id, "rejected", reviewer, comment);
}

std::expected<void, std::string> ApprovalManager::set_review_status(const std::string& id,
                                                                    const std::string& status,
                                                                    const std::string& reviewer,
                                                                    const std::string& comment) {
    if (!db_)
        return std::unexpected("database not open");
    if (id.empty())
        return std::unexpected("approval id is required");
    if (reviewer.empty())
        return std::unexpected("reviewer is required");

    // Fetch the current approval to validate state
    sqlite3_stmt* sel = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT status, submitted_by FROM approvals WHERE id = ?", -1, &sel,
                           nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    sqlite3_bind_text(sel, 1, id.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(sel) != SQLITE_ROW) {
        sqlite3_finalize(sel);
        return std::unexpected("approval not found: " + id);
    }

    auto current_status = col_text(sel, 0);
    auto submitted_by = col_text(sel, 1);
    sqlite3_finalize(sel);

    // Cannot review an already-reviewed approval
    if (current_status != "pending")
        return std::unexpected("approval already reviewed (status: " + current_status + ")");

    // Ownership rule: reviewer must not be the submitter
    if (reviewer == submitted_by)
        return std::unexpected("reviewer cannot be the same as the submitter");

    // Perform the update
    const char* sql = R"(
        UPDATE approvals SET status = ?, reviewed_by = ?, reviewed_at = ?, review_comment = ?
        WHERE id = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, reviewer.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, now_epoch());
    sqlite3_bind_text(stmt, 4, comment.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, id.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        auto err = std::string(sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("update failed: " + err);
    }

    auto changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (changes == 0)
        return std::unexpected("approval not found: " + id);

    spdlog::info("ApprovalManager: {} approval {} by {}", status, id, reviewer);
    return {};
}

} // namespace yuzu::server
