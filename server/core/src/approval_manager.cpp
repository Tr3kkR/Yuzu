#include "approval_manager.hpp"
#include "migration_runner.hpp"
#include "secure_random.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <random>

namespace yuzu::server {

namespace {

// Approval ids are BEARER CAPABILITIES: an MCP approval-ticket recall (#289) is
// authorized by presenting the id, and the bound args are not secret. A
// predictable id — e.g. mt19937 state recovered from prior outputs — would let
// an attacker ride another operator's approved-but-unconsumed ticket
// (governance UP-4). Draw from the CSPRNG (RAND_bytes / BCryptGenRandom) instead;
// 16 bytes = 128-bit unguessable. Entropy failure fails the mint closed.
std::expected<std::string, std::string> generate_id() {
    auto hex = yuzu::server::random_hex(16);
    if (!hex)
        return std::unexpected(std::string("secure approval-id generation failed"));
    return *hex;
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
    a.consumed_at = sqlite3_column_int64(stmt, 9);
    a.consumed_by = col_text(stmt, 10);
    a.schedule_id = col_text(stmt, 11);
    return a;
}

// THE canonical column list — every SELECT that feeds row_to_approval uses
// this constant so the column order can never drift between call sites.
const char* kSelectAllCols = "id, definition_id, status, submitted_by, submitted_at, "
                             "reviewed_by, reviewed_at, review_comment, scope_expression, "
                             "consumed_at, consumed_by, schedule_id";

} // namespace

ApprovalManager::ApprovalManager(sqlite3* db) : db_(db) {}

void ApprovalManager::create_tables() {
    if (!db_)
        return;

    static const std::vector<Migration> kMigrations = {
        {1, R"(
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
        )"},
        // v2 (#289 / Issue 13.5): one-time-consumption stamp for the MCP
        // approval-ticket flow. Additive column, NOT NULL DEFAULT 0 (0 =
        // unconsumed) so it also back-fills every pre-existing row — keeps the
        // eventual Postgres port a trivial ADD COLUMN.
        {2, R"(
            ALTER TABLE approvals ADD COLUMN consumed_at INTEGER NOT NULL DEFAULT 0;
        )"},
        // v3 (PR #1796 review H3/N2, SOC-2 CC7.2): WHO consumed the ticket.
        // consume_ticket() stamps the recalling principal in the same CAS
        // UPDATE that sets consumed_at, completing the evidence chain
        // submitted_by → reviewed_by → consumed_by. Additive, '' = unconsumed
        // (back-fills pre-existing rows; consistent with the v2 pattern).
        {3, R"(
            ALTER TABLE approvals ADD COLUMN consumed_by TEXT NOT NULL DEFAULT '';
        )"},
        // v4 (M-02, #1806): discriminates a scheduled-fire submission by the
        // owning schedule so one approval no longer matches every schedule
        // sharing (submitted_by, definition_id, scope_expression). Empty for
        // interactive (workflow_routes.cpp) and MCP-minted (mcp_server.cpp)
        // submissions, which never match a real schedule id.
        {4, R"(
            ALTER TABLE approvals ADD COLUMN schedule_id TEXT NOT NULL DEFAULT '';
            CREATE INDEX IF NOT EXISTS idx_approvals_schedule_id
                ON approvals(schedule_id);
        )"},
    };
    if (!MigrationRunner::run(db_, "approval_manager", kMigrations)) {
        // Fail closed (governance sre-BLOCKING-1 / HC-1): a failed v2 migration
        // means the `consumed_at` column is absent, so every get/find_pending/
        // consume_ticket/query SELECT would fail — the whole MCP write + approval
        // surface would be silently dead behind a green readyz. NULL db_ so
        // is_open() reports false and /readyz goes red. Do NOT close: the handle
        // is BORROWED (shared with ExecutionTracker/ScheduleEngine on the
        // instruction pool); the pool owner closes it.
        spdlog::error("ApprovalManager: schema migration failed — marking store unavailable");
        db_ = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Submit
// ---------------------------------------------------------------------------

std::expected<std::string, std::string>
ApprovalManager::submit(const std::string& definition_id, const std::string& submitted_by,
                        const std::string& scope_expression, const std::string& schedule_id) {
    if (!db_)
        return std::unexpected("database not open");
    if (definition_id.empty())
        return std::unexpected("definition_id is required");
    if (submitted_by.empty())
        return std::unexpected("submitted_by is required");

    std::lock_guard lock(mtx_);

    // Queue size limit: prevent unbounded growth (G4-UHP-MCP-004)
    constexpr int kMaxPendingApprovals = 1000;
    {
        sqlite3_stmt* cnt = nullptr;
        if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM approvals WHERE status = 'pending'",
                               -1, &cnt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(cnt) == SQLITE_ROW) {
                int pending = sqlite3_column_int(cnt, 0);
                if (pending >= kMaxPendingApprovals) {
                    sqlite3_finalize(cnt);
                    return std::unexpected("approval queue is full (" +
                                           std::to_string(kMaxPendingApprovals) + " pending)");
                }
            }
            sqlite3_finalize(cnt);
        }
    }

    // Lazy expiry sweep (runs on every mint, under mtx_). One shared 7-day
    // window, deliberately simple:
    //   * PENDING tickets nobody reviewed within 7 days of submission expire.
    //   * APPROVED-but-unconsumed tickets expire 7 days after their review
    //     (PR #1796 review N3): an approved ticket is a live one-time
    //     capability — the recall executes the gated tool with no further
    //     human step — so without a TTL a forgotten approval leaks a
    //     forever-valid capability token into backups/log dumps. The recall
    //     path treats an expired ticket exactly like a rejected one (submit a
    //     fresh request); consumed tickets (consumed_at != 0) are history, not
    //     capabilities, and are never touched.
    // Counts come from stepping RETURNING rows on the statement itself —
    // NEVER sqlite3_changes() after step on this shared FULLMUTEX connection
    // (#1033; the L2 convention finding on PR #1796).
    constexpr int64_t k7Days = 7 * 24 * 3600;
    {
        auto cutoff = now_epoch() - k7Days;
        sqlite3_stmt* exp = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "UPDATE approvals SET status = 'expired' "
                               "WHERE status = 'pending' AND submitted_at < ? "
                               "RETURNING 1",
                               -1, &exp, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(exp, 1, cutoff);
            int expired = 0;
            while (sqlite3_step(exp) == SQLITE_ROW)
                ++expired;
            sqlite3_finalize(exp);
            if (expired > 0)
                spdlog::info("ApprovalManager: expired {} stale pending approvals", expired);
        }
        sqlite3_stmt* expa = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "UPDATE approvals SET status = 'expired' "
                               "WHERE status = 'approved' AND consumed_at = 0 "
                               "AND reviewed_at < ? RETURNING 1",
                               -1, &expa, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(expa, 1, cutoff);
            int expired = 0;
            while (sqlite3_step(expa) == SQLITE_ROW)
                ++expired;
            sqlite3_finalize(expa);
            if (expired > 0)
                spdlog::info("ApprovalManager: expired {} approved-but-unconsumed approval tickets",
                             expired);
        }
    }

    auto id_r = generate_id();
    if (!id_r)
        return std::unexpected(id_r.error());
    auto id = *id_r;
    auto ts = now_epoch();

    const char* sql = R"(
        INSERT INTO approvals (id, definition_id, status, submitted_by, submitted_at,
                               reviewed_by, reviewed_at, review_comment, scope_expression,
                               schedule_id)
        VALUES (?, ?, 'pending', ?, ?, '', 0, '', ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, definition_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, submitted_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, ts);
    sqlite3_bind_text(stmt, 5, scope_expression.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, schedule_id.c_str(), -1, SQLITE_TRANSIENT);

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

    std::lock_guard lock(mtx_);

    std::string sql = std::string("SELECT ") + kSelectAllCols + " FROM approvals WHERE 1=1";
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

    std::lock_guard lock(mtx_);

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

int ApprovalManager::pending_count_for(const std::string& submitted_by) const {
    if (!db_ || submitted_by.empty())
        return 0;

    std::lock_guard lock(mtx_);

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(
            db_, "SELECT COUNT(*) FROM approvals WHERE status = 'pending' AND submitted_by = ?", -1,
            &stmt, nullptr) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, submitted_by.c_str(), -1, SQLITE_TRANSIENT);

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);

    sqlite3_finalize(stmt);
    return count;
}

// ---------------------------------------------------------------------------
// Get by id (#289 — MCP approval-ticket recall)
// ---------------------------------------------------------------------------

std::optional<Approval> ApprovalManager::get(const std::string& id) const {
    if (!db_ || id.empty())
        return std::nullopt;

    std::lock_guard lock(mtx_);

    std::string sql = std::string("SELECT ") + kSelectAllCols + " FROM approvals WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<Approval> out;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        out = row_to_approval(stmt);

    sqlite3_finalize(stmt);
    return out;
}

// ---------------------------------------------------------------------------
// Find an existing PENDING approval matching (definition_id, submitted_by,
// scope_expression) — the MCP approval-ticket mint dedup key (#289 / governance
// UP-1). Returning the extant ticket instead of minting a new one makes the mint
// idempotent and bounds a single principal's junk to distinct (tool,args) tuples,
// so a supervised token can no longer flood the GLOBAL pending-approval cap
// shared with the REST instruction-approval workflow. Newest match wins.
// ---------------------------------------------------------------------------

std::optional<Approval> ApprovalManager::find_pending(const std::string& definition_id,
                                                      const std::string& submitted_by,
                                                      const std::string& scope_expression) const {
    if (!db_ || definition_id.empty() || submitted_by.empty())
        return std::nullopt;

    std::lock_guard lock(mtx_);

    std::string sql = std::string("SELECT ") + kSelectAllCols +
                      " FROM approvals WHERE definition_id = ? AND submitted_by = ? "
                      "AND scope_expression = ? AND status = 'pending' "
                      "ORDER BY submitted_at DESC LIMIT 1";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, definition_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, submitted_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, scope_expression.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<Approval> out;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        out = row_to_approval(stmt);

    sqlite3_finalize(stmt);
    return out;
}

// ---------------------------------------------------------------------------
// Consume (#289 — one-time MCP approval ticket)
// ---------------------------------------------------------------------------

std::expected<void, std::string> ApprovalManager::consume_ticket(const std::string& id,
                                                                 const std::string& consumed_by) {
    auto r = consume_ticket(id, consumed_by, {});
    if (r)
        return {};
    // The two-argument overload is the pre-#2443 contract: one flat string, and
    // the same strings as before so its callers keep reporting identically.
    return std::unexpected(r.error().message);
}

std::expected<void, ConsumeError>
ApprovalManager::consume_ticket(const std::string& id, const std::string& consumed_by,
                                const ConsumePrecondition& precondition) {
    if (!db_)
        return std::unexpected(ConsumeError{ConsumeFailure::kStoreError, "database not open"});
    if (id.empty())
        return std::unexpected(
            ConsumeError{ConsumeFailure::kStoreError, "approval id is required"});
    // SOC-2 CC7.2 (PR #1796 H3/N2): a consumption with no attributable principal
    // would be an evidence-chain hole — fail the recall closed instead.
    if (consumed_by.empty())
        return std::unexpected(
            ConsumeError{ConsumeFailure::kStoreError, "consumed_by is required"});

    // Pre-consume recheck (#2443). Skipped entirely when no precondition was
    // supplied, so the two-argument path issues the exact same single statement
    // it always has.
    if (precondition) {
        auto row = get(id); // takes mtx_ itself — must be outside the lock below
        // A row that cannot transition is reported WITHOUT running the
        // precondition: the callback may be costly or emit audit, and the CAS
        // below would decline this row anyway. Same message as the CAS decline,
        // so the two paths are indistinguishable to the caller (they mean the
        // same thing).
        if (!row || row->status != "approved" || row->consumed_at != 0)
            return std::unexpected(ConsumeError{
                ConsumeFailure::kNotConsumable,
                "approval not consumable (already used, not approved, or absent)"});
        auto ok = precondition(*row);
        if (!ok) {
            spdlog::info("ApprovalManager: pre-consume recheck declined ticket {} for {}: {}", id,
                         consumed_by, ok.error());
            return std::unexpected(ConsumeError{ConsumeFailure::kPrecondition, ok.error()});
        }
    }

    std::lock_guard lock(mtx_);

    // Atomic CAS: only an approved, not-yet-consumed ticket transitions.
    // RETURNING carries the "row matched" signal in the step return code, so we
    // never call sqlite3_changes() on the shared FULLMUTEX connection (#1033).
    // SQLITE_ROW == this call consumed it; SQLITE_DONE == already used / not
    // approved / absent (replay-safe: a second concurrent recall loses here).
    // consumed_by rides the same UPDATE so who/when can never disagree.
    const char* sql = R"(
        UPDATE approvals SET consumed_at = ?, consumed_by = ?
        WHERE id = ? AND status = 'approved' AND consumed_at = 0
        RETURNING 1
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(ConsumeError{ConsumeFailure::kStoreError,
                                            std::string("prepare failed: ") + sqlite3_errmsg(db_)});

    sqlite3_bind_int64(stmt, 1, now_epoch());
    sqlite3_bind_text(stmt, 2, consumed_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, id.c_str(), -1, SQLITE_TRANSIENT);

    auto rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_ROW) {
        spdlog::info("ApprovalManager: consumed approval ticket {} by {}", id, consumed_by);
        return {};
    }
    if (rc == SQLITE_DONE)
        return std::unexpected(
            ConsumeError{ConsumeFailure::kNotConsumable,
                         "approval not consumable (already used, not approved, or absent)"});
    return std::unexpected(ConsumeError{ConsumeFailure::kStoreError,
                                        std::string("consume failed: ") + sqlite3_errmsg(db_)});
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

    std::lock_guard lock(mtx_);

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

    // Atomic update; WHERE status = 'pending' prevents TOCTOU double-approve
    // (G4-UHP-MCP-005). RETURNING carries the "row matched" signal in the step
    // return code (SQLITE_ROW = this call transitioned it; SQLITE_DONE = already
    // reviewed / not pending), so we never call sqlite3_changes() on the shared
    // FULLMUTEX connection — approve/reject is now reachable via MCP, and the
    // changes()-race would mis-report a security decision (#1033 / governance UP-2).
    const char* sql = R"(
        UPDATE approvals SET status = ?, reviewed_by = ?, reviewed_at = ?, review_comment = ?
        WHERE id = ? AND status = 'pending' RETURNING 1
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, reviewer.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, now_epoch());
    sqlite3_bind_text(stmt, 4, comment.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, id.c_str(), -1, SQLITE_TRANSIENT);

    auto rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        sqlite3_finalize(stmt);
        spdlog::info("ApprovalManager: {} approval {} by {}", status, id, reviewer);
        return {};
    }
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return std::unexpected("approval already reviewed by another user");
    }
    auto err = std::string(sqlite3_errmsg(db_));
    sqlite3_finalize(stmt);
    return std::unexpected("update failed: " + err);
}

} // namespace yuzu::server
