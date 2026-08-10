#include "approval_manager.hpp"

#include "sqlite_raii.hpp"
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

// An approval id is a BEARER CAPABILITY (see generate_id above): presenting it
// is what authorizes an MCP recall. Logs are read by more people than may
// redeem a ticket, so log a prefix that is enough to correlate two lines about
// the same ticket and not enough to redeem it. 8 hex chars of a 128-bit id.
std::string redact_id(const std::string& id) {
    constexpr std::size_t kKeep = 8;
    return id.size() <= kKeep ? id : id.substr(0, kKeep) + "...";
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

} // namespace

// Guarded the same way as `consume_denial_reason`, and this is the one that
// needed it more: a missing arm here falls through to `return ""`, which
// `approval_origin_from_string` decodes as kUnspecified — the value that GRANTS
// at redemption. So the failure direction of an unhandled enumerator is
// fail-OPEN, where the denial-reason table's is merely a wrong log token. See
// that function's header comment for why the MSVC arm is ordered as it is and
// why it is best-effort.
const char* to_string(ApprovalOrigin origin) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(1 : 4062) // off by default; `error:` alone does NOT enable it
#pragma warning(error : 4062)
#endif
    switch (origin) {
    case ApprovalOrigin::kInstruction:
        return "instruction";
    case ApprovalOrigin::kSchedule:
        return "schedule";
    case ApprovalOrigin::kMcp:
        return "mcp";
    case ApprovalOrigin::kUnspecified:
    case ApprovalOrigin::kUnrecognised:
        // Neither is written as a surface. kUnrecognised only ever comes OUT of
        // a decode; storing it would round-trip to kUnspecified, which grants.
        break;
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
    return "";
}

ApprovalOrigin approval_origin_from_string(std::string_view text) {
    if (text == "instruction")
        return ApprovalOrigin::kInstruction;
    if (text == "schedule")
        return ApprovalOrigin::kSchedule;
    if (text == "mcp")
        return ApprovalOrigin::kMcp;
    // Empty is an UNDECLARED MINT — today only the MCP gate — and it is
    // redeemable. It is NOT the pre-column row: migration v7 rewrote every ''
    // it found to the sentinel, so a row that predates the column decodes
    // below as kUnrecognised and is refused. Anything ELSE is a value this build does not
    // know, and it must NOT fold into that case — kUnspecified is what grants
    // (#2442), so folding would make a row written by a newer binary redeemable
    // here. Decode it as its own value and let the predicate refuse it.
    if (text.empty())
        return ApprovalOrigin::kUnspecified;
    return ApprovalOrigin::kUnrecognised;
}

// Guarded like the other closed-set switch over this enum, `to_string` above.
// (`consume_denial_reason` in the header carries the same guard, but over
// `ConsumeFailure` — a different enum, so it is not part of this set.)
//
// The trailing `return true` already fails closed, so a missing arm cannot
// grant — but it would silently pick the REFUSE side for a surface that may
// have been added precisely to be redeemable, and the author would never be
// told. Guarding one of the two was an inconsistency, not a judgement.
//
// DO NOT ADD A `default:` LABEL HERE. `-Wswitch` only fires while the switch
// has none, so a defensive `default: return true;` — which looks like
// belt-and-braces, and does exactly what the statement below already does —
// silently deletes this guard, with no warning and no failing test. MEASURED
// on GCC 15.2: with a default label added, a missing enumerator stops erroring
// here while still erroring in `to_string`. The trailing return living OUTSIDE
// the switch is what keeps the guard armed, and that is the whole reason it is
// out there rather than in a default arm.
bool declares_non_mcp_surface(ApprovalOrigin origin) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wswitch"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(1 : 4062) // off by default; `error:` alone does NOT enable it
#pragma warning(error : 4062)
#endif
    switch (origin) {
    case ApprovalOrigin::kInstruction:
    case ApprovalOrigin::kSchedule:
    case ApprovalOrigin::kUnrecognised:
        return true;
    case ApprovalOrigin::kMcp:
    case ApprovalOrigin::kUnspecified:
        return false;
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
    return true; // unreachable; fail closed if the enum grows
}

namespace {

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
    a.origin = approval_origin_from_string(col_text(stmt, 12));
    return a;
}

// THE canonical column list — every SELECT that feeds row_to_approval uses
// this constant so the column order can never drift between call sites.
const char* kSelectAllCols = "id, definition_id, status, submitted_by, submitted_at, "
                             "reviewed_by, reviewed_at, review_comment, scope_expression, "
                             "consumed_at, consumed_by, schedule_id, origin";

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
        // v5 (#2442): WHICH surface minted the ticket. Additive, '' = no
        // declared origin — the honest reading for both a pre-v5 row and the
        // MCP mint that cannot yet declare itself. Deliberately NOT back-filled
        // to 'instruction': every pre-v5 row would then claim a surface it may
        // not have come from, and these rows are approval evidence.
        //
        // Unchanged from the form that shipped to origin/dev. An earlier cut of
        // this branch added `UPDATE approvals SET origin = 'legacy'` here as
        // well as in v7. That edit changed no outcome: v5 runs only on a store
        // below v5 and v7 runs immediately after it with no write in between
        // (`migration_runner.cpp`, `if (m.version <= current) continue;` inside
        // the apply loop), and `DEFAULT ''` leaves exactly the rows v7's
        // `WHERE origin = ''` already matches. What it cost was real — a
        // numbered migration is the definition of a data state, so editing one
        // in place means two stores both stamped 5 can differ. The back-fill
        // lives in v7 alone.
        {5, R"(
            ALTER TABLE approvals ADD COLUMN origin TEXT NOT NULL DEFAULT '';
        )"},
        // v6: make the two status-scoped access patterns index-covered. Neither
        // is new, but both became load-bearing when mtx_ started covering the
        // readers: a consumed ticket keeps status='approved' (consume stamps
        // consumed_at, it does not restatus the row) and nothing prunes, so the
        // 'approved' bucket only grows, and idx_approvals_status alone left both
        // the ORDER BY in query() and the expiry sweep walking it. MEASURED on a
        // synthetic table: at 1M rows query() 112 ms -> 0.34 ms and the
        // approved-unconsumed sweep 100 ms -> 0.01 ms, temp B-tree gone. That
        // matters beyond latency because ScheduleRunner issues three query()
        // calls per tick on the same mutex an MCP approval recall needs.
        {6, R"(
            CREATE INDEX IF NOT EXISTS idx_approvals_status_submitted
                ON approvals(status, submitted_at);
            CREATE INDEX IF NOT EXISTS idx_approvals_status_consumed_reviewed
                ON approvals(status, consumed_at, reviewed_at);
        )"},
        // v7 (#2442): the ONLY back-fill. '' is the GRANTING case at redemption,
        // so every row carrying it — whether it predates the column or predates
        // this migration — has to be moved off it. This reaches both populations
        // in one step: a store below v5 gets the column from v5 (all rows '')
        // and is rewritten here in the same loop, and a store already at >= 5,
        // which never re-runs v5, is rewritten here too. No release carries the
        // column, but every dev/CI/UAT database tracking origin/dev since
        // 2026-08-02 does.
        //
        // Rewrites EVERY remaining '' row, not just the pre-column ones. A
        // discriminator was attempted and does not exist: the obvious one is
        // `submitted_at < schema_meta.upgraded_at`, but the runner re-stamps
        // `upgraded_at` after EVERY migration, so by the time v7 runs the value
        // names when v6 finished — seconds ago — not when the column appeared.
        // A test caught this by asserting a post-column undeclared mint SURVIVES;
        // it did not. v6 COULD have observed v5's stamp — `set_version` fires
        // after each migration's SQL, so during v6 the value still named v5's
        // completion. But v6 has already shipped to exactly the databases this
        // needs to reach, so the window closed before it was noticed. No
        // migration addable NOW can see it: every later one overwrites the
        // stamp. Stated precisely because "impossible" would send the next
        // author looking for a different mechanism that does not exist, when
        // the real lesson is that a migration carrying a back-fill must be
        // written in the same step as the column.
        //
        // So this is deliberately blunt: an undeclared MCP ticket outstanding at
        // upgrade stops redeeming and must be re-requested. That is fail-closed,
        // bounded by the 7-day approval window, and identical whether the
        // database arrives via a release or via origin/dev.
        //
        // Surgical about everything else, though: `WHERE origin = ''` is what
        // keeps a DECLARED surface intact. Drop the predicate and every row from
        // every surface is clobbered to the sentinel and refused. Pinned.
        //
        // Matches nothing on a fresh install: v1..v6 run first and the table is
        // empty. Idempotent: `origin = ''` is false once rewritten.
        {7, R"(
            UPDATE approvals SET origin = 'legacy' WHERE origin = '';
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
                        const std::string& scope_expression, const std::string& schedule_id,
                        ApprovalOrigin origin) {
    if (!db_)
        return std::unexpected("database not open");
    if (definition_id.empty())
        return std::unexpected("definition_id is required");
    if (submitted_by.empty())
        return std::unexpected("submitted_by is required");
    // NO mint-time refusal for the reserved namespace. #2442 is defended at
    // REDEMPTION (see consume_ticket) instead, deliberately:
    //
    //  - Refusing here strands pre-existing operator content. A definition
    //    already under `mcp.` with a schedule submits via kSchedule on every
    //    fire; refused at mint, that schedule can never run again, and moving a
    //    schedule between definitions is not supported (#2742).
    //  - The redemption guard covers more: a ticket minted before the GUARD
    //    existed, or by a surface that declares itself later, is refused at the
    //    point of use rather than only at the point of mint. NOT "strictly
    //    more" — that claim was false and is why migration v7 back-fills a
    //    sentinel. A row minted before the COLUMN existed carries no surface at
    //    all, and '' is the granting case; only the back-fill closes it. A
    //    future caller that omits the defaulted `origin` argument is in the
    //    same class.
    //  - Authoring is still refused where authoring happens —
    //    `instruction_yaml.cpp` and `instruction_store.cpp` both call
    //    `is_reserved_definition_id`, and `reserved_definition_id.hpp` warns
    //    that a further call site is "a fourth chance to diverge". This was it.

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
                               schedule_id, origin)
        VALUES (?, ?, 'pending', ?, ?, '', 0, '', ?, ?, ?)
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
    sqlite3_bind_text(stmt, 7, to_string(origin), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        auto err = std::string(sqlite3_errmsg(db_));
        sqlite3_finalize(stmt);
        return std::unexpected("insert failed: " + err);
    }
    sqlite3_finalize(stmt);

    spdlog::info("ApprovalManager: submitted approval {} for definition {} by {}", redact_id(id),
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
    auto r = get_checked(id);
    return r ? std::move(*r) : std::nullopt;
}

std::expected<std::optional<Approval>, StoreReadError>
ApprovalManager::get_checked(const std::string& id) const {
    if (!db_)
        return std::unexpected(StoreReadError{"database not open"});
    if (id.empty())
        return std::unexpected(StoreReadError{"approval id is required"});

    std::lock_guard lock(mtx_);

    std::string sql = std::string("SELECT ") + kSelectAllCols + " FROM approvals WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected(StoreReadError{std::string("prepare failed: ") + sqlite3_errmsg(db_),
                                              sqlite3_extended_errcode(db_)});

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<Approval> out;
    const auto rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
        out = row_to_approval(stmt);

    // A read that FAILED is not a read that found nothing. Collapsing the two
    // is what let a store error be reported to the operator as "this one-time
    // capability is spent" — see the pre-consume path in consume_ticket.
    //
    // Only the primitive `int` is captured before `sqlite3_finalize` — the
    // throw-capable std::string build is deferred until after, matching this
    // file's own CAS-site convention (finalize doesn't clear a connection's
    // error state; `sqlite3_errmsg`/`sqlite3_extended_errcode` read the same
    // before or after). A std::string built ahead of finalize would leak
    // `stmt` on a bad_alloc between the two.
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
        const int extended = sqlite3_extended_errcode(db_);
        sqlite3_finalize(stmt);
        return std::unexpected(
            StoreReadError{std::string("read failed: ") + sqlite3_errmsg(db_), extended});
    }
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

    // NO `LIMIT 1`. The newest match is not necessarily a usable one: since the
    // mint-time namespace refusal was removed, a ticket carrying a declared
    // non-MCP surface can sit in this dedup key. Handing one back would return a
    // ticket THIS CALLER'S OWN RECALL WILL REFUSE (`kForeignOrigin`) — so an
    // administrator reviews and approves a request that can never complete, and
    // a human approval is spent on a flow with no successful outcome.
    //
    // Filtered in C++ through the SHARED predicate rather than a second,
    // hand-written SQL copy of the rule. A copy in a WHERE clause is a second
    // home for `declares_non_mcp_surface`, and the two would drift the first
    // time the enum grows.
    //
    // Walk newest-first and take the first REDEEMABLE candidate, rather than
    // taking the newest and rejecting it — an older undeclared ticket under the
    // same key is a perfectly good dedup hit, and skipping it would mint a
    // duplicate.
    std::string sql = std::string("SELECT ") + kSelectAllCols +
                      " FROM approvals WHERE definition_id = ? AND submitted_by = ? "
                      "AND scope_expression = ? AND status = 'pending' "
                      "ORDER BY submitted_at DESC";
    SqliteStmt stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, stmt.addr(), nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt.get(), 1, definition_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, submitted_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, scope_expression.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        Approval a = row_to_approval(stmt.get());
        if (!declares_non_mcp_surface(a.origin))
            return a;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Consume (#289 — one-time MCP approval ticket)
// ---------------------------------------------------------------------------

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

    // #2442 CROSS-SURFACE BINDING. Approvals are one shared store with three
    // mint paths, and this recall matches a ticket on its definition id and
    // scope expression — neither of which names the minting surface. So an
    // approval raised through the REST instruction gate, where both fields are
    // caller-influenced, could line up with an MCP tool's canonical arguments
    // and be redeemed against it. What that buys is the HUMAN APPROVAL itself:
    // the reviewer sees a ticket id, a submitter and a scope expression, and
    // nothing that names the SURFACE it was raised on. (The tool is named:
    // `definition_id` is on the row, and must be exactly `mcp.<tool>` for the
    // confusion to work at all — that is the premise of the reserved prefix.)
    //
    // get_checked, not get: a FAILED read must not decode as "no declared
    // origin", which is the value that grants.
    //
    // Runs BEFORE the precondition block because that block is conditional —
    // a caller supplying no precondition must not skip this.
    //
    // TEST DEPENDENCY: with no precondition supplied (today's only production
    // caller, the MCP recall), this is the 2nd top-level SELECT this call
    // issues against the store — the 1st is the caller's own pre-consume
    // lookup (e.g. mcp_server.cpp's rung-1 get_checked). The MCP integration
    // test "a store fault AT the origin check masks a foreign-origin ticket's
    // kind" isolates a fault to THIS read specifically via a countdown
    // `sqlite3_set_authorizer` that lets the 1st SELECT through and denies
    // the 2nd. A future read added between the caller's lookup and this one
    // (on the same connection) would shift that test onto the wrong read
    // without it failing loudly — update the countdown if you add one.
    {
        auto row = get_checked(id); // takes mtx_ itself — must be outside any lock
        if (!row) {
            // #2786 arm 1: this read failing means the origin comparison below
            // never runs, so a foreign-origin ticket is exactly as likely to be
            // sitting behind this refusal as an innocent one — the forgery
            // signal is masked for the duration of the fault. Flag it and log
            // it here, at the store, so every consume_ticket caller (today only
            // the MCP recall) gets the signal without duplicating this check.
            spdlog::warn("ApprovalManager: origin check for ticket {} could not be evaluated "
                        "(store fault: {}); refusing closed",
                        redact_id(id), row.error().message);
            return std::unexpected(ConsumeError{ConsumeFailure::kStoreError, row.error().message,
                                                row.error().extended_errcode,
                                                /*origin_check_unevaluated=*/true});
        }
        if (*row && declares_non_mcp_surface((*row)->origin))
            return std::unexpected(
                ConsumeError{ConsumeFailure::kForeignOrigin, kNotConsumableMessage});
    }

    // Pre-consume recheck (#2443). Skipped entirely when no precondition was
    // supplied, so the two-argument path issues the exact same single statement
    // it always has.
    if (precondition) {
        // get_checked, not get: a FAILED read must not be reported as a row that
        // is not there. Telling the operator a live human-approved ticket is
        // spent, because SQLite was busy for a moment, is the burn class #2443
        // exists to close, re-entered through the taxonomy.
        auto row = get_checked(id); // takes mtx_ itself — must be outside the lock below
        if (!row)
            return std::unexpected(ConsumeError{ConsumeFailure::kStoreError, row.error().message,
                                                row.error().extended_errcode});
        // A row that cannot transition is reported WITHOUT running the
        // precondition: the callback may be costly or emit audit, and the CAS
        // below would decline this row anyway. Same message as the CAS decline,
        // so the two paths are indistinguishable to the caller (they mean the
        // same thing).
        if (!*row || (*row)->status != "approved" || (*row)->consumed_at != 0)
            return std::unexpected(ConsumeError{
                ConsumeFailure::kNotConsumable,
                kNotConsumableMessage});
        // The callback is caller code. If it throws, that must not escape a
        // store method as an unhandled exception on an httplib worker: the
        // ticket is untouched either way, so report it as a store error and let
        // the caller answer with its own envelope. Deliberately NOT
        // kPrecondition — a callback that threw did not decide anything.
        std::expected<void, std::string> ok;
        try {
            ok = precondition(**row);
        } catch (const std::exception& e) {
            spdlog::warn("ApprovalManager: pre-consume recheck threw for ticket {}: {}",
                         redact_id(id), e.what());
            // e.what() goes to the LOG, not into the returned message: this
            // string reaches the MCP error envelope, and e.what() is unvetted
            // text from caller code. A precondition's OWN error message does
            // ride along, deliberately — it is authored under the constraints
            // on ConsumePrecondition. Unvetted is the distinction, not origin.
            return std::unexpected(
                ConsumeError{ConsumeFailure::kStoreError, "pre-consume recheck failed"});
        } catch (...) {
            spdlog::warn("ApprovalManager: pre-consume recheck threw a non-std exception for "
                         "ticket {}",
                         redact_id(id));
            return std::unexpected(
                ConsumeError{ConsumeFailure::kStoreError, "pre-consume recheck failed"});
        }
        if (!ok) {
            spdlog::info("ApprovalManager: pre-consume recheck declined ticket {} for {}: {}",
                         redact_id(id), consumed_by, ok.error());
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
                                            std::string("prepare failed: ") + sqlite3_errmsg(db_),
                                            sqlite3_extended_errcode(db_)});

    sqlite3_bind_int64(stmt, 1, now_epoch());
    sqlite3_bind_text(stmt, 2, consumed_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, id.c_str(), -1, SQLITE_TRANSIENT);

    auto rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_ROW) {
        spdlog::info("ApprovalManager: consumed approval ticket {} by {}", redact_id(id), consumed_by);
        return {};
    }
    if (rc == SQLITE_DONE)
        return std::unexpected(
            ConsumeError{ConsumeFailure::kNotConsumable,
                         kNotConsumableMessage});
    return std::unexpected(ConsumeError{ConsumeFailure::kStoreError,
                                        std::string("consume failed: ") + sqlite3_errmsg(db_),
                                        sqlite3_extended_errcode(db_)});
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
        spdlog::info("ApprovalManager: {} approval {} by {}", status, redact_id(id), reviewer);
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
