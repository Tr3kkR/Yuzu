#include "baseline_store.hpp"

#include "migration_runner.hpp"
#include "store_errors.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <random>
#include <unordered_map>
#include <unordered_set>

namespace yuzu::server {

namespace {

const char* safe(const char* p) {
    return p ? p : "";
}

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Canonical kConflictPrefix-tagged error (mirrors guaranteed_state_store).
std::string format_conflict(std::string_view detail) {
    return std::string(kConflictPrefix) + " " + std::string(detail);
}

// A UNIQUE / PRIMARY KEY violation is a duplicate-resource conflict (HTTP 409).
bool is_uniqueness_violation(int extended) {
    return extended == SQLITE_CONSTRAINT_UNIQUE ||
           extended == SQLITE_CONSTRAINT_PRIMARYKEY;
}

// Read every column of a Baseline row off a stepped statement. Column order is
// fixed by kBaselineColumns; every SELECT below uses that exact list.
constexpr const char* kBaselineColumns =
    "baseline_id, name, description, lifecycle, deployed_snapshot, "
    "created_by, updated_by, deployed_by, created_at, updated_at, deployed_at";

Baseline read_baseline_row(sqlite3_stmt* s) {
    Baseline b;
    b.baseline_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
    b.name = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
    b.description = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
    b.lifecycle = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
    b.deployed_snapshot = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 4)));
    b.created_by = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 5)));
    b.updated_by = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 6)));
    b.deployed_by = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 7)));
    b.created_at = sqlite3_column_int64(s, 8);
    b.updated_at = sqlite3_column_int64(s, 9);
    b.deployed_at = sqlite3_column_int64(s, 10);
    return b;
}

} // namespace

// ── Construction / teardown ──────────────────────────────────────────────────

BaselineStore::BaselineStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("BaselineStore: failed to open {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    // Load-bearing: the join tables' ON DELETE CASCADE only fires when foreign
    // keys are enabled, and the FK is also what rejects an INSERT into a join
    // table for a non-existent baseline_id. SQLite defaults foreign_keys OFF.
    sqlite3_exec(db_, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    create_tables();
    if (db_)
        spdlog::info("BaselineStore: opened {}", db_path.string());
}

BaselineStore::~BaselineStore() {
    if (db_)
        sqlite3_close(db_);
}

bool BaselineStore::is_open() const {
    return db_ != nullptr;
}

// ── DDL ──────────────────────────────────────────────────────────────────────

void BaselineStore::create_tables() {
    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS guaranteed_state_baselines (
                baseline_id       TEXT PRIMARY KEY,
                name              TEXT NOT NULL UNIQUE,
                description       TEXT NOT NULL DEFAULT '',
                lifecycle         TEXT NOT NULL DEFAULT 'draft',
                -- RESERVED for the deploy slice (draft-vs-deployed diffing). The
                -- store never interprets it; see baseline_store.hpp.
                deployed_snapshot TEXT NOT NULL DEFAULT '',
                created_by        TEXT NOT NULL DEFAULT '',
                updated_by        TEXT NOT NULL DEFAULT '',
                deployed_by       TEXT NOT NULL DEFAULT '',
                created_at        INTEGER NOT NULL DEFAULT 0,
                updated_at        INTEGER NOT NULL DEFAULT 0,
                deployed_at       INTEGER NOT NULL DEFAULT 0
            );

            -- Member Guards (M:N). rule_id references a Guard in a DIFFERENT
            -- database (guaranteed-state.db) so there is no FK on it; a dangling
            -- member is harmless at deploy (the push builder skips it). The FK to
            -- guaranteed_state_baselines (same file) gives delete_baseline its
            -- cascade and rejects a member row for a non-existent baseline.
            CREATE TABLE IF NOT EXISTS guaranteed_state_baseline_rules (
                baseline_id TEXT NOT NULL
                    REFERENCES guaranteed_state_baselines(baseline_id) ON DELETE CASCADE,
                rule_id     TEXT NOT NULL,
                PRIMARY KEY (baseline_id, rule_id)
            );

            -- Assignment: included − excluded management groups. group_id also
            -- references a different database (the management group store), so no
            -- FK on it. PK on (baseline_id, group_id) makes a group's disposition
            -- unambiguous — it cannot be both included and excluded.
            CREATE TABLE IF NOT EXISTS guaranteed_state_baseline_groups (
                baseline_id TEXT NOT NULL
                    REFERENCES guaranteed_state_baselines(baseline_id) ON DELETE CASCADE,
                group_id    TEXT NOT NULL,
                disposition TEXT NOT NULL,   -- 'include' | 'exclude'
                PRIMARY KEY (baseline_id, group_id)
            );

            -- Reverse-lookup indexes: which baselines reference a given guard /
            -- group (deploy slice's affected-set recompute + cross-store cleanup).
            -- No index on lifecycle (cardinality 2): SQLite would skip it and the
            -- baselines table is bounded operator config anyway.
            CREATE INDEX IF NOT EXISTS idx_gsbr_rule
                ON guaranteed_state_baseline_rules(rule_id);
            CREATE INDEX IF NOT EXISTS idx_gsbg_group
                ON guaranteed_state_baseline_groups(group_id);
        )"},
    };
    if (!MigrationRunner::run(db_, "baseline_store", kMigrations)) {
        spdlog::error("BaselineStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

std::string BaselineStore::generate_id() const {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr char chars[] = "0123456789abcdef";
    std::string id;
    id.reserve(12);
    std::uniform_int_distribution<int> dist(0, 15);
    for (int i = 0; i < 12; ++i)
        id += chars[dist(rng)];
    return id;
}

// ── Baseline CRUD ──────────────────────────────────────────────────────────

std::expected<std::string, std::string> BaselineStore::create_baseline(const Baseline& b) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    if (b.name.empty())
        return std::unexpected("baseline name cannot be empty");

    const std::string id = b.baseline_id.empty() ? generate_id() : b.baseline_id;
    const int64_t now = now_epoch();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO guaranteed_state_baselines "
                           "(baseline_id, name, description, lifecycle, deployed_snapshot, "
                           "created_by, updated_by, deployed_by, created_at, updated_at, "
                           "deployed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    const std::string lifecycle = b.lifecycle.empty() ? kBaselineDraft : b.lifecycle;
    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, b.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, b.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, lifecycle.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 5, b.deployed_snapshot.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 6, b.created_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 7, b.updated_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 8, b.deployed_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 9, now);
    sqlite3_bind_int64(s, 10, now);
    sqlite3_bind_int64(s, 11, b.deployed_at);

    const int step = sqlite3_step(s);
    if (step != SQLITE_DONE) {
        const int ext = sqlite3_extended_errcode(db_);
        const std::string err = sqlite3_errmsg(db_);
        sqlite3_finalize(s);
        if (is_uniqueness_violation(ext)) {
            const bool name_collision = err.find(".name") != std::string::npos;
            return std::unexpected(format_conflict(
                name_collision ? ("baseline name '" + b.name + "' already exists")
                                : ("baseline_id '" + id + "' already exists")));
        }
        return std::unexpected("insert failed: " + err);
    }
    sqlite3_finalize(s);
    return id;
}

std::optional<Baseline> BaselineStore::get_baseline(const std::string& baseline_id) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return std::nullopt;
    sqlite3_stmt* s = nullptr;
    const std::string sql = std::string("SELECT ") + kBaselineColumns +
                            " FROM guaranteed_state_baselines WHERE baseline_id = ?;";
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(s, 1, baseline_id.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<Baseline> result;
    if (sqlite3_step(s) == SQLITE_ROW)
        result = read_baseline_row(s);
    sqlite3_finalize(s);
    return result;
}

std::vector<Baseline> BaselineStore::list_baselines() const {
    std::shared_lock lock(mtx_);
    std::vector<Baseline> out;
    if (!db_)
        return out;
    sqlite3_stmt* s = nullptr;
    const std::string sql = std::string("SELECT ") + kBaselineColumns +
                            " FROM guaranteed_state_baselines ORDER BY name;";
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
        return out;
    while (sqlite3_step(s) == SQLITE_ROW)
        out.push_back(read_baseline_row(s));
    sqlite3_finalize(s);
    return out;
}

std::expected<void, std::string> BaselineStore::update_baseline(const Baseline& b) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    if (b.name.empty())
        return std::unexpected("baseline name cannot be empty");

    const int64_t now = now_epoch();
    sqlite3_stmt* s = nullptr;
    // RETURNING (not sqlite3_changes()) so the affected-row test rides in the
    // step return code on this FULLMUTEX connection — see CLAUDE.md #1033.
    if (sqlite3_prepare_v2(db_,
                           "UPDATE guaranteed_state_baselines SET "
                           "name = ?, description = ?, lifecycle = ?, deployed_snapshot = ?, "
                           "updated_by = ?, deployed_by = ?, deployed_at = ?, updated_at = ? "
                           "WHERE baseline_id = ? RETURNING baseline_id;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    sqlite3_bind_text(s, 1, b.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, b.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, b.lifecycle.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, b.deployed_snapshot.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 5, b.updated_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 6, b.deployed_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 7, b.deployed_at);
    sqlite3_bind_int64(s, 8, now);
    sqlite3_bind_text(s, 9, b.baseline_id.c_str(), -1, SQLITE_TRANSIENT);

    bool found = false;
    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW)
        found = true;
    if (rc != SQLITE_DONE) {
        const int ext = sqlite3_extended_errcode(db_);
        const std::string err = sqlite3_errmsg(db_);
        sqlite3_finalize(s);
        if (is_uniqueness_violation(ext))
            return std::unexpected(format_conflict("baseline name '" + b.name + "' already exists"));
        return std::unexpected("update failed: " + err);
    }
    sqlite3_finalize(s);
    if (!found)
        return std::unexpected("not found: baseline_id '" + b.baseline_id + "'");
    return {};
}

std::expected<void, std::string> BaselineStore::delete_baseline(const std::string& baseline_id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");
    sqlite3_stmt* s = nullptr;
    // ON DELETE CASCADE clears the member + assignment rows. RETURNING reports
    // whether the baseline existed without a separate sqlite3_changes() read.
    if (sqlite3_prepare_v2(db_,
                           "DELETE FROM guaranteed_state_baselines WHERE baseline_id = ? "
                           "RETURNING baseline_id;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
    sqlite3_bind_text(s, 1, baseline_id.c_str(), -1, SQLITE_TRANSIENT);
    bool found = false;
    int rc;
    while ((rc = sqlite3_step(s)) == SQLITE_ROW)
        found = true;
    if (rc != SQLITE_DONE) {
        const std::string err = sqlite3_errmsg(db_);
        sqlite3_finalize(s);
        return std::unexpected("delete failed: " + err);
    }
    sqlite3_finalize(s);
    if (!found)
        return std::unexpected("not found: baseline_id '" + baseline_id + "'");
    return {};
}

// ── Member Guards (M:N) ──────────────────────────────────────────────────────

std::expected<void, std::string>
BaselineStore::set_members(const std::string& baseline_id,
                           const std::vector<std::string>& rule_ids) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    // Existence check up front: an INSERT enforces the FK, but an EMPTY member
    // set inserts nothing, so a clear() against a bogus baseline_id would
    // silently "succeed". Verify here for a crisp, consistent error either way.
    {
        sqlite3_stmt* chk = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "SELECT 1 FROM guaranteed_state_baselines WHERE baseline_id = ?;",
                               -1, &chk, nullptr) != SQLITE_OK)
            return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
        sqlite3_bind_text(chk, 1, baseline_id.c_str(), -1, SQLITE_TRANSIENT);
        const bool exists = sqlite3_step(chk) == SQLITE_ROW;
        sqlite3_finalize(chk);
        if (!exists)
            return std::unexpected("not found: baseline_id '" + baseline_id + "'");
    }

    if (sqlite3_exec(db_, "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("begin failed: ") + sqlite3_errmsg(db_));

    auto rollback = [&](const std::string& msg) -> std::expected<void, std::string> {
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        return std::unexpected(msg);
    };

    {
        sqlite3_stmt* del = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "DELETE FROM guaranteed_state_baseline_rules WHERE baseline_id = ?;",
                               -1, &del, nullptr) != SQLITE_OK)
            return rollback(std::string("prepare failed: ") + sqlite3_errmsg(db_));
        sqlite3_bind_text(del, 1, baseline_id.c_str(), -1, SQLITE_TRANSIENT);
        const int rc = sqlite3_step(del);
        sqlite3_finalize(del);
        if (rc != SQLITE_DONE)
            return rollback(std::string("delete failed: ") + sqlite3_errmsg(db_));
    }

    std::unordered_set<std::string> seen;
    sqlite3_stmt* ins = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO guaranteed_state_baseline_rules (baseline_id, rule_id) "
                           "VALUES (?, ?);",
                           -1, &ins, nullptr) != SQLITE_OK)
        return rollback(std::string("prepare failed: ") + sqlite3_errmsg(db_));
    for (const auto& rule_id : rule_ids) {
        if (rule_id.empty() || !seen.insert(rule_id).second)
            continue; // skip blanks + de-dup
        sqlite3_reset(ins);
        sqlite3_bind_text(ins, 1, baseline_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 2, rule_id.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(ins) != SQLITE_DONE) {
            const std::string err = sqlite3_errmsg(db_);
            sqlite3_finalize(ins);
            return rollback("insert member failed: " + err);
        }
    }
    sqlite3_finalize(ins);

    if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, nullptr) != SQLITE_OK)
        return rollback(std::string("commit failed: ") + sqlite3_errmsg(db_));
    return {};
}

std::vector<std::string> BaselineStore::get_members(const std::string& baseline_id) const {
    std::shared_lock lock(mtx_);
    std::vector<std::string> out;
    if (!db_)
        return out;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT rule_id FROM guaranteed_state_baseline_rules "
                           "WHERE baseline_id = ? ORDER BY rule_id;",
                           -1, &s, nullptr) != SQLITE_OK)
        return out;
    sqlite3_bind_text(s, 1, baseline_id.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW)
        out.emplace_back(safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0))));
    sqlite3_finalize(s);
    return out;
}

std::vector<std::string>
BaselineStore::baselines_containing_rule(const std::string& rule_id) const {
    std::shared_lock lock(mtx_);
    std::vector<std::string> out;
    if (!db_)
        return out;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT baseline_id FROM guaranteed_state_baseline_rules "
                           "WHERE rule_id = ? ORDER BY baseline_id;",
                           -1, &s, nullptr) != SQLITE_OK)
        return out;
    sqlite3_bind_text(s, 1, rule_id.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW)
        out.emplace_back(safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0))));
    sqlite3_finalize(s);
    return out;
}

std::size_t BaselineStore::remove_rule_everywhere(const std::string& rule_id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return 0;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "DELETE FROM guaranteed_state_baseline_rules WHERE rule_id = ? "
                           "RETURNING baseline_id;",
                           -1, &s, nullptr) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(s, 1, rule_id.c_str(), -1, SQLITE_TRANSIENT);
    std::size_t removed = 0;
    while (sqlite3_step(s) == SQLITE_ROW)
        ++removed;
    sqlite3_finalize(s);
    return removed;
}

// ── Assignment (included − excluded management groups) ───────────────────────

std::expected<void, std::string>
BaselineStore::set_assignment(const std::string& baseline_id,
                              const std::vector<BaselineGroupAssignment>& groups) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    // Validate + collapse duplicates (last disposition wins) BEFORE any write,
    // so an invalid disposition aborts with nothing persisted. Insertion order
    // is irrelevant — the PK is (baseline_id, group_id).
    std::unordered_map<std::string, std::string> resolved;
    for (const auto& g : groups) {
        if (g.group_id.empty())
            continue;
        if (g.disposition != kAssignInclude && g.disposition != kAssignExclude)
            return std::unexpected("invalid disposition '" + g.disposition +
                                   "' (expected 'include' or 'exclude')");
        resolved[g.group_id] = g.disposition;
    }

    {
        sqlite3_stmt* chk = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "SELECT 1 FROM guaranteed_state_baselines WHERE baseline_id = ?;",
                               -1, &chk, nullptr) != SQLITE_OK)
            return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
        sqlite3_bind_text(chk, 1, baseline_id.c_str(), -1, SQLITE_TRANSIENT);
        const bool exists = sqlite3_step(chk) == SQLITE_ROW;
        sqlite3_finalize(chk);
        if (!exists)
            return std::unexpected("not found: baseline_id '" + baseline_id + "'");
    }

    if (sqlite3_exec(db_, "BEGIN IMMEDIATE;", nullptr, nullptr, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("begin failed: ") + sqlite3_errmsg(db_));

    auto rollback = [&](const std::string& msg) -> std::expected<void, std::string> {
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        return std::unexpected(msg);
    };

    {
        sqlite3_stmt* del = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "DELETE FROM guaranteed_state_baseline_groups WHERE baseline_id = ?;",
                               -1, &del, nullptr) != SQLITE_OK)
            return rollback(std::string("prepare failed: ") + sqlite3_errmsg(db_));
        sqlite3_bind_text(del, 1, baseline_id.c_str(), -1, SQLITE_TRANSIENT);
        const int rc = sqlite3_step(del);
        sqlite3_finalize(del);
        if (rc != SQLITE_DONE)
            return rollback(std::string("delete failed: ") + sqlite3_errmsg(db_));
    }

    sqlite3_stmt* ins = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO guaranteed_state_baseline_groups "
                           "(baseline_id, group_id, disposition) VALUES (?, ?, ?);",
                           -1, &ins, nullptr) != SQLITE_OK)
        return rollback(std::string("prepare failed: ") + sqlite3_errmsg(db_));
    for (const auto& [group_id, disposition] : resolved) {
        sqlite3_reset(ins);
        sqlite3_bind_text(ins, 1, baseline_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 2, group_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 3, disposition.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(ins) != SQLITE_DONE) {
            const std::string err = sqlite3_errmsg(db_);
            sqlite3_finalize(ins);
            return rollback("insert assignment failed: " + err);
        }
    }
    sqlite3_finalize(ins);

    if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, nullptr) != SQLITE_OK)
        return rollback(std::string("commit failed: ") + sqlite3_errmsg(db_));
    return {};
}

std::vector<BaselineGroupAssignment>
BaselineStore::get_assignment(const std::string& baseline_id) const {
    std::shared_lock lock(mtx_);
    std::vector<BaselineGroupAssignment> out;
    if (!db_)
        return out;
    sqlite3_stmt* s = nullptr;
    // Sort include-before-exclude then by group_id for a stable UI order.
    if (sqlite3_prepare_v2(db_,
                           "SELECT group_id, disposition FROM guaranteed_state_baseline_groups "
                           "WHERE baseline_id = ? ORDER BY disposition, group_id;",
                           -1, &s, nullptr) != SQLITE_OK)
        return out;
    sqlite3_bind_text(s, 1, baseline_id.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW) {
        BaselineGroupAssignment a;
        a.group_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        a.disposition = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        out.push_back(std::move(a));
    }
    sqlite3_finalize(s);
    return out;
}

std::size_t BaselineStore::remove_group_everywhere(const std::string& group_id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return 0;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "DELETE FROM guaranteed_state_baseline_groups WHERE group_id = ? "
                           "RETURNING baseline_id;",
                           -1, &s, nullptr) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(s, 1, group_id.c_str(), -1, SQLITE_TRANSIENT);
    std::size_t removed = 0;
    while (sqlite3_step(s) == SQLITE_ROW)
        ++removed;
    sqlite3_finalize(s);
    return removed;
}

// ── Reverse lookups / counting ───────────────────────────────────────────────

std::vector<Baseline> BaselineStore::list_deployed_baselines() const {
    std::shared_lock lock(mtx_);
    std::vector<Baseline> out;
    if (!db_)
        return out;
    sqlite3_stmt* s = nullptr;
    const std::string sql = std::string("SELECT ") + kBaselineColumns +
                            " FROM guaranteed_state_baselines WHERE lifecycle = ? ORDER BY name;";
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
        return out;
    sqlite3_bind_text(s, 1, kBaselineDeployed, -1, SQLITE_STATIC);
    while (sqlite3_step(s) == SQLITE_ROW)
        out.push_back(read_baseline_row(s));
    sqlite3_finalize(s);
    return out;
}

std::size_t BaselineStore::baseline_count() const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return 0;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM guaranteed_state_baselines;", -1, &s,
                           nullptr) != SQLITE_OK)
        return 0;
    std::size_t n = 0;
    if (sqlite3_step(s) == SQLITE_ROW)
        n = static_cast<std::size_t>(sqlite3_column_int64(s, 0));
    sqlite3_finalize(s);
    return n;
}

std::size_t BaselineStore::member_count(const std::string& baseline_id) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return 0;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT COUNT(*) FROM guaranteed_state_baseline_rules "
                           "WHERE baseline_id = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(s, 1, baseline_id.c_str(), -1, SQLITE_TRANSIENT);
    std::size_t n = 0;
    if (sqlite3_step(s) == SQLITE_ROW)
        n = static_cast<std::size_t>(sqlite3_column_int64(s, 0));
    sqlite3_finalize(s);
    return n;
}

} // namespace yuzu::server
