#include "result_set_store.hpp"
#include "migration_runner.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <random>

namespace yuzu::server {

// ── Small helpers ────────────────────────────────────────────────────────────

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static int64_t now_epoch_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static const char* safe(const char* p) {
    return p ? p : "";
}

const char* to_string(ResultSetStatus s) {
    switch (s) {
    case ResultSetStatus::Pending:
        return "pending";
    case ResultSetStatus::Materialized:
        return "materialized";
    case ResultSetStatus::Failed:
        return "failed";
    }
    return "materialized";
}

ResultSetStatus result_set_status_from(std::string_view s) {
    if (s == "pending")
        return ResultSetStatus::Pending;
    if (s == "failed")
        return ResultSetStatus::Failed;
    return ResultSetStatus::Materialized;
}

const char* to_string(ResultSetError e) {
    switch (e) {
    case ResultSetError::NotFound:
        return "RESULT_SET_NOT_FOUND";
    case ResultSetError::NotOwner:
        return "RESULT_SET_NOT_OWNER";
    case ResultSetError::QuotaExceeded:
        return "RESULT_SET_QUOTA";
    case ResultSetError::PinLimit:
        return "PIN_LIMIT";
    case ResultSetError::Pinned:
        return "RESULT_SET_PINNED";
    case ResultSetError::DbError:
        return "RESULT_SET_DB_ERROR";
    }
    return "RESULT_SET_DB_ERROR";
}

// Cursor: keyset over (last_used_at, created_at, id) descending. Encoded as
// "<last_used_at>|<created_at>|<id>". Empty string means first page.
static std::string make_cursor(const ResultSet& r) {
    return std::to_string(r.last_used_at) + "|" + std::to_string(r.created_at) + "|" + r.id;
}

static bool parse_cursor(const std::string& c, int64_t& lu, int64_t& ca, std::string& id) {
    auto p1 = c.find('|');
    if (p1 == std::string::npos)
        return false;
    auto p2 = c.find('|', p1 + 1);
    if (p2 == std::string::npos)
        return false;
    try {
        lu = std::stoll(c.substr(0, p1));
        ca = std::stoll(c.substr(p1 + 1, p2 - p1 - 1));
    } catch (...) {
        return false;
    }
    id = c.substr(p2 + 1);
    return true;
}

// ── Construction / teardown ──────────────────────────────────────────────────

ResultSetStore::ResultSetStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("ResultSetStore: failed to open {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    create_tables();
    if (db_)
        spdlog::info("ResultSetStore: opened {}", db_path.string());
}

ResultSetStore::~ResultSetStore() {
    if (db_)
        sqlite3_close(db_);
}

bool ResultSetStore::is_open() const {
    return db_ != nullptr;
}

void ResultSetStore::create_tables() {
    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS result_sets (
                id                  TEXT PRIMARY KEY,
                name                TEXT,
                owner_principal     TEXT NOT NULL,
                created_at          INTEGER NOT NULL,
                ttl_at              INTEGER NOT NULL,
                last_used_at        INTEGER NOT NULL,
                pinned              INTEGER NOT NULL DEFAULT 0,
                parent_id           TEXT REFERENCES result_sets(id) ON DELETE SET NULL,
                source_kind         TEXT NOT NULL,
                source_payload      TEXT NOT NULL,
                status              TEXT NOT NULL DEFAULT 'materialized',
                source_execution_id TEXT NOT NULL DEFAULT '',
                matcher             TEXT NOT NULL DEFAULT '',
                device_count        INTEGER NOT NULL DEFAULT 0,
                CHECK (length(id) >= 5 AND substr(id,1,3) = 'rs_'),
                CHECK (ttl_at >= created_at)
            );
            CREATE TABLE IF NOT EXISTS result_set_members (
                result_set_id TEXT NOT NULL REFERENCES result_sets(id) ON DELETE CASCADE,
                device_id     TEXT NOT NULL,
                PRIMARY KEY (result_set_id, device_id)
            );
            CREATE INDEX IF NOT EXISTS idx_result_sets_owner_used
                ON result_sets(owner_principal, last_used_at);
            CREATE INDEX IF NOT EXISTS idx_result_sets_owner_name
                ON result_sets(owner_principal, name);
            CREATE INDEX IF NOT EXISTS idx_result_sets_parent ON result_sets(parent_id);
            CREATE INDEX IF NOT EXISTS idx_result_sets_status ON result_sets(status);
            CREATE INDEX IF NOT EXISTS idx_result_set_members_dev
                ON result_set_members(device_id);
        )"},
    };
    if (!MigrationRunner::run(db_, "result_set_store", kMigrations)) {
        spdlog::error("ResultSetStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ── ID generation ────────────────────────────────────────────────────────────

std::string ResultSetStore::generate_id() {
    // Time-prefixed, lexically sortable (ULID-like) without a new dependency:
    // "rs_" + 11 hex digits of epoch-ms (sortable to ~year 2527) + 16 hex
    // digits of randomness for collision resistance within the same ms.
    thread_local std::mt19937_64 rng{std::random_device{}()};
    std::array<char, 40> buf{};
    std::snprintf(buf.data(), buf.size(), "rs_%011llx%016llx",
                  static_cast<unsigned long long>(now_epoch_ms()),
                  static_cast<unsigned long long>(rng()));
    return std::string(buf.data());
}

// ── Row reader ───────────────────────────────────────────────────────────────

static ResultSet read_row(sqlite3_stmt* s) {
    ResultSet r;
    r.id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
    r.name = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
    r.owner_principal = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
    r.created_at = sqlite3_column_int64(s, 3);
    r.ttl_at = sqlite3_column_int64(s, 4);
    r.last_used_at = sqlite3_column_int64(s, 5);
    r.pinned = sqlite3_column_int64(s, 6) != 0;
    if (sqlite3_column_type(s, 7) != SQLITE_NULL)
        r.parent_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 7)));
    r.source_kind = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 8)));
    r.source_payload = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 9)));
    r.status = result_set_status_from(safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 10))));
    r.source_execution_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 11)));
    r.matcher = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 12)));
    r.device_count = sqlite3_column_int64(s, 13);
    return r;
}

static constexpr const char* kRowCols =
    "id, name, owner_principal, created_at, ttl_at, last_used_at, pinned, parent_id, "
    "source_kind, source_payload, status, source_execution_id, matcher, device_count";

std::optional<ResultSet> ResultSetStore::get_impl(const std::string& id) const {
    if (!db_)
        return std::nullopt;
    sqlite3_stmt* s = nullptr;
    std::string sql = std::string("SELECT ") + kRowCols + " FROM result_sets WHERE id = ? LIMIT 1;";
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<ResultSet> result;
    if (sqlite3_step(s) == SQLITE_ROW)
        result = read_row(s);
    sqlite3_finalize(s);
    return result;
}

std::optional<ResultSet> ResultSetStore::get(const std::string& id) const {
    std::shared_lock lock(mtx_);
    return get_impl(id);
}

// ── Create ───────────────────────────────────────────────────────────────────

std::expected<ResultSet, ResultSetError> ResultSetStore::insert_row_impl(
    const CreateRequest& req, ResultSetStatus status, const std::string& execution_id,
    const std::vector<std::string>& members, int64_t member_count) {
    // Caller holds the unique_lock; the store mutex serialises all writers, so
    // the quota count + insert below is atomic w.r.t. other store operations
    // (no reliance on sqlite3_changes()).
    if (!db_)
        return std::unexpected(ResultSetError::DbError);

    // Hard per-operator quota (design §3.3).
    {
        sqlite3_stmt* c = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "SELECT COUNT(*) FROM result_sets WHERE owner_principal = ?;", -1,
                               &c, nullptr) != SQLITE_OK)
            return std::unexpected(ResultSetError::DbError);
        sqlite3_bind_text(c, 1, req.owner_principal.c_str(), -1, SQLITE_TRANSIENT);
        int count = (sqlite3_step(c) == SQLITE_ROW) ? sqlite3_column_int(c, 0) : 0;
        sqlite3_finalize(c);
        if (count >= kMaxPerOwner)
            return std::unexpected(ResultSetError::QuotaExceeded);
    }

    ResultSet row;
    row.id = generate_id();
    row.name = req.name;
    row.owner_principal = req.owner_principal;
    row.created_at = now_epoch();
    row.ttl_at = row.created_at + kDefaultTtlSeconds;
    row.last_used_at = row.created_at;
    row.pinned = false;
    row.parent_id = req.parent_id;
    row.source_kind = req.source_kind;
    row.source_payload = req.source_payload;
    row.status = status;
    row.source_execution_id = execution_id;
    row.matcher = req.matcher;
    row.device_count = member_count;

    if (sqlite3_exec(db_, "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr) != SQLITE_OK)
        return std::unexpected(ResultSetError::DbError);

    auto rollback = [&]() { sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr); };

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "INSERT INTO result_sets (id, name, owner_principal, created_at, ttl_at, "
            "last_used_at, pinned, parent_id, source_kind, source_payload, status, "
            "source_execution_id, matcher, device_count) "
            "VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?);",
            -1, &s, nullptr) != SQLITE_OK) {
        rollback();
        return std::unexpected(ResultSetError::DbError);
    }
    sqlite3_bind_text(s, 1, row.id.c_str(), -1, SQLITE_TRANSIENT);
    if (row.name.empty())
        sqlite3_bind_null(s, 2);
    else
        sqlite3_bind_text(s, 2, row.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, row.owner_principal.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 4, row.created_at);
    sqlite3_bind_int64(s, 5, row.ttl_at);
    sqlite3_bind_int64(s, 6, row.last_used_at);
    if (row.parent_id)
        sqlite3_bind_text(s, 7, row.parent_id->c_str(), -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(s, 7);
    sqlite3_bind_text(s, 8, row.source_kind.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 9, row.source_payload.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 10, to_string(row.status), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 11, row.source_execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 12, row.matcher.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 13, row.device_count);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE) {
        rollback();
        return std::unexpected(ResultSetError::DbError);
    }

    if (!members.empty()) {
        sqlite3_stmt* m = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "INSERT OR IGNORE INTO result_set_members (result_set_id, device_id) "
                               "VALUES (?, ?);",
                               -1, &m, nullptr) != SQLITE_OK) {
            rollback();
            return std::unexpected(ResultSetError::DbError);
        }
        for (const auto& dev : members) {
            sqlite3_bind_text(m, 1, row.id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(m, 2, dev.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(m) != SQLITE_DONE) {
                sqlite3_finalize(m);
                rollback();
                return std::unexpected(ResultSetError::DbError);
            }
            sqlite3_reset(m);
        }
        sqlite3_finalize(m);
    }

    if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, nullptr) != SQLITE_OK) {
        rollback();
        return std::unexpected(ResultSetError::DbError);
    }
    return row;
}

std::expected<ResultSet, ResultSetError> ResultSetStore::create_materialized(
    const CreateRequest& req, const std::vector<std::string>& members) {
    std::unique_lock lock(mtx_);
    return insert_row_impl(req, ResultSetStatus::Materialized, /*execution_id=*/"", members,
                           static_cast<int64_t>(members.size()));
}

std::expected<ResultSet, ResultSetError> ResultSetStore::create_pending(
    const CreateRequest& req, const std::string& execution_id) {
    std::unique_lock lock(mtx_);
    return insert_row_impl(req, ResultSetStatus::Pending, execution_id, /*members=*/{},
                           /*member_count=*/0);
}

// ── Read ─────────────────────────────────────────────────────────────────────

std::vector<ResultSet> ResultSetStore::list_by_owner(const std::string& owner,
                                                     const std::string& cursor, int limit,
                                                     std::string& out_next_cursor) const {
    std::shared_lock lock(mtx_);
    out_next_cursor.clear();
    std::vector<ResultSet> result;
    if (!db_)
        return result;
    if (limit <= 0)
        limit = 50;

    int64_t cur_lu = 0, cur_ca = 0;
    std::string cur_id;
    bool has_cursor = !cursor.empty() && parse_cursor(cursor, cur_lu, cur_ca, cur_id);

    // Keyset pagination over (last_used_at, created_at, id) DESC.
    std::string sql = std::string("SELECT ") + kRowCols + " FROM result_sets WHERE owner_principal = ?";
    if (has_cursor) {
        sql +=
            " AND (last_used_at < ? OR (last_used_at = ? AND (created_at < ? OR "
            "(created_at = ? AND id < ?))))";
    }
    sql += " ORDER BY last_used_at DESC, created_at DESC, id DESC LIMIT ?;";

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
        return result;
    int idx = 1;
    sqlite3_bind_text(s, idx++, owner.c_str(), -1, SQLITE_TRANSIENT);
    if (has_cursor) {
        sqlite3_bind_int64(s, idx++, cur_lu);
        sqlite3_bind_int64(s, idx++, cur_lu);
        sqlite3_bind_int64(s, idx++, cur_ca);
        sqlite3_bind_int64(s, idx++, cur_ca);
        sqlite3_bind_text(s, idx++, cur_id.c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int(s, idx++, limit + 1); // fetch one extra to detect next page

    while (sqlite3_step(s) == SQLITE_ROW)
        result.push_back(read_row(s));
    sqlite3_finalize(s);

    if (static_cast<int>(result.size()) > limit) {
        result.resize(limit);
        out_next_cursor = make_cursor(result.back());
    }
    return result;
}

std::vector<std::string> ResultSetStore::members(const std::string& id, const std::string& cursor,
                                                 int limit, std::string& out_next_cursor) const {
    std::shared_lock lock(mtx_);
    out_next_cursor.clear();
    std::vector<std::string> result;
    if (!db_)
        return result;
    if (limit <= 0)
        limit = 1000;

    // Keyset over device_id ASC.
    std::string sql = "SELECT device_id FROM result_set_members WHERE result_set_id = ?";
    if (!cursor.empty())
        sql += " AND device_id > ?";
    sql += " ORDER BY device_id ASC LIMIT ?;";

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
        return result;
    int idx = 1;
    sqlite3_bind_text(s, idx++, id.c_str(), -1, SQLITE_TRANSIENT);
    if (!cursor.empty())
        sqlite3_bind_text(s, idx++, cursor.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, idx++, limit + 1);

    while (sqlite3_step(s) == SQLITE_ROW)
        result.push_back(safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0))));
    sqlite3_finalize(s);

    if (static_cast<int>(result.size()) > limit) {
        result.resize(limit);
        out_next_cursor = result.back();
    }
    return result;
}

std::vector<LineageNode> ResultSetStore::lineage(const std::string& id) const {
    std::shared_lock lock(mtx_);
    std::vector<LineageNode> chain;
    if (!db_)
        return chain;

    std::optional<std::string> cur = id;
    int depth = 0;
    while (cur && depth < kLineageDepthCap) {
        sqlite3_stmt* s = nullptr;
        if (sqlite3_prepare_v2(
                db_, "SELECT id, name, source_kind, device_count, parent_id FROM result_sets "
                     "WHERE id = ? LIMIT 1;",
                -1, &s, nullptr) != SQLITE_OK)
            break;
        sqlite3_bind_text(s, 1, cur->c_str(), -1, SQLITE_TRANSIENT);
        std::optional<std::string> next;
        if (sqlite3_step(s) == SQLITE_ROW) {
            LineageNode n;
            n.id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
            n.name = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
            n.source_kind = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
            n.device_count = sqlite3_column_int64(s, 3);
            chain.push_back(std::move(n));
            if (sqlite3_column_type(s, 4) != SQLITE_NULL)
                next = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 4)));
        }
        sqlite3_finalize(s);
        cur = next;
        ++depth;
    }
    // chain is leaf→root; reverse to root→leaf for breadcrumb display.
    std::reverse(chain.begin(), chain.end());
    return chain;
}

bool ResultSetStore::contains(const std::string& id, const std::string& device_id) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return false;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT 1 FROM result_set_members WHERE result_set_id = ? AND "
                           "device_id = ? LIMIT 1;",
                           -1, &s, nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, device_id.c_str(), -1, SQLITE_TRANSIENT);
    bool found = sqlite3_step(s) == SQLITE_ROW;
    sqlite3_finalize(s);
    return found;
}

std::optional<std::string> ResultSetStore::resolve_alias(const std::string& owner,
                                                         const std::string& name) const {
    std::shared_lock lock(mtx_);
    if (!db_ || name.empty())
        return std::nullopt;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT id FROM result_sets WHERE owner_principal = ? AND name = ? "
                           "ORDER BY created_at DESC LIMIT 1;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(s, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, name.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<std::string> id;
    if (sqlite3_step(s) == SQLITE_ROW)
        id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
    sqlite3_finalize(s);
    return id;
}

int ResultSetStore::count_for_owner(const std::string& owner) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return 0;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM result_sets WHERE owner_principal = ?;", -1,
                           &s, nullptr) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(s, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
    int n = (sqlite3_step(s) == SQLITE_ROW) ? sqlite3_column_int(s, 0) : 0;
    sqlite3_finalize(s);
    return n;
}

int ResultSetStore::count_pinned_for_owner_unlocked(const std::string& owner) const {
    if (!db_)
        return 0;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT COUNT(*) FROM result_sets WHERE owner_principal = ? AND "
                           "pinned = 1;",
                           -1, &s, nullptr) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(s, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
    int n = (sqlite3_step(s) == SQLITE_ROW) ? sqlite3_column_int(s, 0) : 0;
    sqlite3_finalize(s);
    return n;
}

int ResultSetStore::count_pinned_for_owner(const std::string& owner) const {
    std::shared_lock lock(mtx_);
    return count_pinned_for_owner_unlocked(owner);
}

ResultSetStore::Counts ResultSetStore::counts() const {
    std::shared_lock lock(mtx_);
    Counts c;
    if (!db_)
        return c;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT COUNT(*), "
                           "COALESCE(SUM(pinned), 0), "
                           "COALESCE(SUM(status = 'pending'), 0) FROM result_sets;",
                           -1, &s, nullptr) != SQLITE_OK)
        return c;
    if (sqlite3_step(s) == SQLITE_ROW) {
        c.total = sqlite3_column_int(s, 0);
        c.pinned = sqlite3_column_int(s, 1);
        c.pending = sqlite3_column_int(s, 2);
    }
    sqlite3_finalize(s);
    return c;
}

// ── Mutate ───────────────────────────────────────────────────────────────────

std::expected<ResultSet, ResultSetError> ResultSetStore::pin(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected(ResultSetError::DbError);
    auto row = get_impl(id);
    if (!row)
        return std::unexpected(ResultSetError::NotFound);
    if (row->pinned)
        return *row; // idempotent

    // Pin-storm guard (design §3.3): per-operator cap.
    if (count_pinned_for_owner_unlocked(row->owner_principal) >= kMaxPinsPerOwner)
        return std::unexpected(ResultSetError::PinLimit);

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "UPDATE result_sets SET pinned = 1, ttl_at = ? WHERE id = ? RETURNING 1;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(ResultSetError::DbError);
    sqlite3_bind_int64(s, 1, INT64_MAX);
    sqlite3_bind_text(s, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW)
        return std::unexpected(ResultSetError::NotFound);
    return get_impl(id).value();
}

std::expected<ResultSet, ResultSetError> ResultSetStore::unpin(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected(ResultSetError::DbError);
    // Restore ttl_at = max(now + default, original_ttl_at) but original was
    // INT64_MAX while pinned, so clamp to now + default (design §3.3).
    int64_t new_ttl = now_epoch() + kDefaultTtlSeconds;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "UPDATE result_sets SET pinned = 0, ttl_at = ? WHERE id = ? "
                           "RETURNING 1;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(ResultSetError::DbError);
    sqlite3_bind_int64(s, 1, new_ttl);
    sqlite3_bind_text(s, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW)
        return std::unexpected(ResultSetError::NotFound);
    return get_impl(id).value();
}

void ResultSetStore::touch(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;
    int64_t now = now_epoch();
    sqlite3_stmt* s = nullptr;
    // Do not shorten a pinned set's INT64_MAX ttl; only ever extend.
    if (sqlite3_prepare_v2(db_,
                           "UPDATE result_sets SET last_used_at = ?, "
                           "ttl_at = MAX(ttl_at, ?) WHERE id = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return;
    sqlite3_bind_int64(s, 1, now);
    sqlite3_bind_int64(s, 2, now + kDefaultTtlSeconds);
    sqlite3_bind_text(s, 3, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
}

std::expected<void, ResultSetError> ResultSetStore::delete_set(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected(ResultSetError::DbError);
    auto row = get_impl(id);
    if (!row)
        return std::unexpected(ResultSetError::NotFound);
    if (row->pinned)
        return std::unexpected(ResultSetError::Pinned); // must unpin first (design §6)

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM result_sets WHERE id = ? RETURNING 1;", -1, &s,
                           nullptr) != SQLITE_OK)
        return std::unexpected(ResultSetError::DbError);
    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW)
        return std::unexpected(ResultSetError::NotFound);
    return {};
}

// ── Async materialisation ────────────────────────────────────────────────────

std::vector<PendingSet> ResultSetStore::list_pending() const {
    std::shared_lock lock(mtx_);
    std::vector<PendingSet> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT id, owner_principal, source_kind, source_execution_id, "
                           "matcher, created_at FROM result_sets WHERE status = 'pending' "
                           "ORDER BY created_at ASC;",
                           -1, &s, nullptr) != SQLITE_OK)
        return result;
    while (sqlite3_step(s) == SQLITE_ROW) {
        PendingSet p;
        p.id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        p.owner_principal = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        p.source_kind = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        p.source_execution_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        p.matcher = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 4)));
        p.created_at = sqlite3_column_int64(s, 5);
        result.push_back(std::move(p));
    }
    sqlite3_finalize(s);
    return result;
}

std::expected<void, ResultSetError> ResultSetStore::materialize(
    const std::string& id, const std::vector<std::string>& members) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected(ResultSetError::DbError);
    if (sqlite3_exec(db_, "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr) != SQLITE_OK)
        return std::unexpected(ResultSetError::DbError);
    auto rollback = [&]() { sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr); };

    if (!members.empty()) {
        sqlite3_stmt* m = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "INSERT OR IGNORE INTO result_set_members (result_set_id, device_id) "
                               "VALUES (?, ?);",
                               -1, &m, nullptr) != SQLITE_OK) {
            rollback();
            return std::unexpected(ResultSetError::DbError);
        }
        for (const auto& dev : members) {
            sqlite3_bind_text(m, 1, id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(m, 2, dev.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(m) != SQLITE_DONE) {
                sqlite3_finalize(m);
                rollback();
                return std::unexpected(ResultSetError::DbError);
            }
            sqlite3_reset(m);
        }
        sqlite3_finalize(m);
    }

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "UPDATE result_sets SET status = 'materialized', device_count = ? "
                           "WHERE id = ? AND status = 'pending' RETURNING 1;",
                           -1, &s, nullptr) != SQLITE_OK) {
        rollback();
        return std::unexpected(ResultSetError::DbError);
    }
    sqlite3_bind_int64(s, 1, static_cast<int64_t>(members.size()));
    sqlite3_bind_text(s, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_ROW) {
        rollback();
        return std::unexpected(ResultSetError::NotFound);
    }
    if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, nullptr) != SQLITE_OK) {
        rollback();
        return std::unexpected(ResultSetError::DbError);
    }
    return {};
}

void ResultSetStore::mark_failed(const std::string& id, const std::string& reason) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "UPDATE result_sets SET status = 'failed', "
                           "source_payload = json_set(CASE WHEN json_valid(source_payload) "
                           "THEN source_payload ELSE '{}' END, '$.failure', ?) "
                           "WHERE id = ? AND status = 'pending';",
                           -1, &s, nullptr) != SQLITE_OK)
        return;
    sqlite3_bind_text(s, 1, reason.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
}

// ── GC ───────────────────────────────────────────────────────────────────────

int ResultSetStore::gc_sweep() {
    std::unique_lock lock(mtx_);
    if (!db_)
        return 0;
    // Count first (under the same lock, so no concurrent writer), then delete.
    int64_t now = now_epoch();
    int count = 0;
    {
        sqlite3_stmt* c = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "SELECT COUNT(*) FROM result_sets WHERE pinned = 0 AND ttl_at < ?;",
                               -1, &c, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(c, 1, now);
            if (sqlite3_step(c) == SQLITE_ROW)
                count = sqlite3_column_int(c, 0);
            sqlite3_finalize(c);
        }
    }
    if (count == 0)
        return 0;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM result_sets WHERE pinned = 0 AND ttl_at < ?;", -1, &s,
                           nullptr) != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(s, 1, now);
    sqlite3_step(s); // cascades to result_set_members via FK
    sqlite3_finalize(s);
    return count;
}

} // namespace yuzu::server
