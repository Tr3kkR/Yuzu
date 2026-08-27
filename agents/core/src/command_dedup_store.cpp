/**
 * command_dedup_store.cpp -- see command_dedup_store.hpp
 *
 * SQLite idioms (open flags, WAL, busy_timeout, StmtPtr RAII, the RETURNING
 * drain-to-DONE durability check) mirror kv_store.cpp deliberately — the two
 * stores share the agent's SQLite conventions.
 */

#include <yuzu/agent/command_dedup_store.hpp>

#include <sqlite3.h>

#include <spdlog/spdlog.h>

#include <chrono>
#include <format>

namespace yuzu::agent {

namespace {

int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct StmtDeleter {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

// Persisted state values. Stored as INTEGER, never the enum's ABI value.
constexpr int kStateInFlight = 0;
constexpr int kStateTerminal = 1;

} // namespace

CommandDedupStore::CommandDedupStore(sqlite3* db) : db_{db} {}

CommandDedupStore::~CommandDedupStore() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

CommandDedupStore::CommandDedupStore(CommandDedupStore&& other) noexcept : db_{other.db_} {
    other.db_ = nullptr;
}

CommandDedupStore& CommandDedupStore::operator=(CommandDedupStore&& other) noexcept {
    if (this != &other) {
        if (db_)
            sqlite3_close(db_);
        db_ = other.db_;
        other.db_ = nullptr;
    }
    return *this;
}

std::expected<CommandDedupStore, CommandDedupError>
CommandDedupStore::open(const std::filesystem::path& db_path) {
    std::error_code ec;
    auto parent = db_path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return std::unexpected(CommandDedupError{
                std::format("failed to create directory {}: {}", parent.string(), ec.message())});
        }
    }

    sqlite3* raw_db = nullptr;
    int rc = sqlite3_open_v2(db_path.string().c_str(), &raw_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        std::string err = raw_db ? sqlite3_errmsg(raw_db) : "unknown error";
        if (raw_db)
            sqlite3_close(raw_db);
        return std::unexpected(
            CommandDedupError{std::format("failed to open command_dedup.db: {}", err)});
    }

    char* err_msg = nullptr;
    rc = sqlite3_exec(raw_db, "PRAGMA journal_mode=WAL", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::warn("CommandDedupStore: WAL mode failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
    }
    sqlite3_busy_timeout(raw_db, 5000);

    // Schema. `command_id` is the PRIMARY KEY so claim() can lean on ON CONFLICT
    // DO NOTHING for its atomic first-writer-wins check. `response` is a BLOB —
    // it holds a serialized protobuf (embedded NULs must survive). `claimed_at`
    // is DIAGNOSTIC ONLY: retention is a clock-free rowid ring (prune_locked),
    // so this column must NEVER become a wall-clock retention cutoff (that would
    // reintroduce the clock-guarded-retention hazard on a user-controlled clock).
    // A `meta` table carries schema_version for a future migration ladder (the
    // agent has no shared MigrationRunner; this mirrors tar_db's config-row
    // precedent).
    const char* create_sql = R"(
        CREATE TABLE IF NOT EXISTS command_outcomes (
            command_id TEXT PRIMARY KEY,
            state      INTEGER NOT NULL,
            response   BLOB,
            claimed_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        INSERT INTO meta(key, value) VALUES('schema_version', '1')
            ON CONFLICT(key) DO NOTHING;
    )";
    err_msg = nullptr;
    rc = sqlite3_exec(raw_db, create_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        sqlite3_close(raw_db);
        return std::unexpected(
            CommandDedupError{std::format("failed to create command_dedup schema: {}", err)});
    }

    spdlog::info("CommandDedupStore opened: {}", db_path.string());
    return CommandDedupStore{raw_db};
}

ClaimResult CommandDedupStore::claim(std::string_view command_id) noexcept {
    if (command_id.empty())
        return ClaimResult{.status = ClaimStatus::Error};
    std::lock_guard lock(mu_);
    if (!db_)
        return ClaimResult{.status = ClaimStatus::Error};

    // Atomic first-writer-wins claim. A RETURNING row means WE inserted the
    // in-flight record; no row (DO NOTHING) means a prior claim already owns it.
    const char* insert_sql = R"(
        INSERT INTO command_outcomes (command_id, state, response, claimed_at)
        VALUES (?, ?, NULL, ?)
        ON CONFLICT(command_id) DO NOTHING
        RETURNING 1
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, insert_sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("CommandDedupStore::claim prepare failed: {}", sqlite3_errmsg(db_));
        return ClaimResult{.status = ClaimStatus::Error};
    }
    StmtPtr stmt(raw_stmt);
    sqlite3_bind_text(stmt.get(), 1, command_id.data(), static_cast<int>(command_id.size()),
                      SQLITE_STATIC);
    sqlite3_bind_int(stmt.get(), 2, kStateInFlight);
    sqlite3_bind_int64(stmt.get(), 3, now_epoch_seconds());

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        // RETURNING row: inserted. Drain to DONE so a commit/WAL-fsync failure
        // (SQLITE_FULL / SQLITE_IOERR) surfaces as Error rather than a false
        // Claimed that would let a not-yet-durable claim proceed — matching
        // KvStore::insert_if_absent's durability contract.
        rc = sqlite3_step(stmt.get());
        if (rc != SQLITE_DONE) {
            spdlog::error("CommandDedupStore::claim commit failed: {}", sqlite3_errmsg(db_));
            return ClaimResult{.status = ClaimStatus::Error};
        }
        if (++claims_since_prune_ >= kPruneInterval) {
            prune_locked();
            claims_since_prune_ = 0;
        }
        return ClaimResult{.status = ClaimStatus::Claimed};
    }
    if (rc != SQLITE_DONE) {
        spdlog::error("CommandDedupStore::claim step failed: {}", sqlite3_errmsg(db_));
        return ClaimResult{.status = ClaimStatus::Error};
    }

    // Conflict: the id is already known. Read the existing record's state (+ the
    // terminal response, if any) so the caller can replay or answer RUNNING.
    const char* select_sql = "SELECT state, response FROM command_outcomes WHERE command_id = ?";
    sqlite3_stmt* raw_sel = nullptr;
    rc = sqlite3_prepare_v2(db_, select_sql, -1, &raw_sel, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("CommandDedupStore::claim select prepare failed: {}", sqlite3_errmsg(db_));
        return ClaimResult{.status = ClaimStatus::Error};
    }
    StmtPtr sel(raw_sel);
    sqlite3_bind_text(sel.get(), 1, command_id.data(), static_cast<int>(command_id.size()),
                      SQLITE_STATIC);
    rc = sqlite3_step(sel.get());
    if (rc == SQLITE_ROW) {
        const int state = sqlite3_column_int(sel.get(), 0);
        if (state == kStateTerminal) {
            const auto* blob = static_cast<const char*>(sqlite3_column_blob(sel.get(), 1));
            const int bytes = sqlite3_column_bytes(sel.get(), 1);
            return ClaimResult{
                .status = ClaimStatus::Duplicate,
                .state = DedupState::Terminal,
                .response = blob ? std::string(blob, static_cast<std::size_t>(bytes))
                                 : std::string{},
            };
        }
        return ClaimResult{.status = ClaimStatus::Duplicate, .state = DedupState::InFlight};
    }
    if (rc == SQLITE_DONE) {
        // The row vanished between the failed insert and this select (a
        // concurrent prune of a just-evicted row is the only way, and it cannot
        // hit a row this claim would have inserted). Treat as "proceed without
        // dedup" rather than fabricate a state.
        spdlog::warn("CommandDedupStore::claim: conflicting row for {} not found on re-read",
                     command_id);
        return ClaimResult{.status = ClaimStatus::Error};
    }
    spdlog::error("CommandDedupStore::claim select step failed: {}", sqlite3_errmsg(db_));
    return ClaimResult{.status = ClaimStatus::Error};
}

void CommandDedupStore::record_terminal(std::string_view command_id,
                                        std::string_view serialized_response) noexcept {
    if (command_id.empty())
        return;
    std::lock_guard lock(mu_);
    if (!db_)
        return;

    // UPDATE-only: a terminal outcome is recorded against a row a prior claim()
    // already created (the newest rowid, so prune never evicts it first). If the
    // row is somehow gone, 0 rows change and durability degrades to at-least-once
    // for this one command — never wrong, and never a fabricated row.
    const char* sql =
        "UPDATE command_outcomes SET state = ?, response = ? WHERE command_id = ?";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("CommandDedupStore::record_terminal prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }
    StmtPtr stmt(raw_stmt);
    sqlite3_bind_int(stmt.get(), 1, kStateTerminal);
    sqlite3_bind_blob(stmt.get(), 2, serialized_response.data(),
                      static_cast<int>(serialized_response.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 3, command_id.data(), static_cast<int>(command_id.size()),
                      SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE)
        spdlog::error("CommandDedupStore::record_terminal step failed: {}", sqlite3_errmsg(db_));
}

void CommandDedupStore::release(std::string_view command_id) noexcept {
    if (command_id.empty())
        return;
    std::lock_guard lock(mu_);
    if (!db_)
        return;

    // Only an in-flight row is releasable — never delete a terminal outcome (a
    // concurrent worker may have just recorded one for a redelivery).
    const char* sql = "DELETE FROM command_outcomes WHERE command_id = ? AND state = ?";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("CommandDedupStore::release prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }
    StmtPtr stmt(raw_stmt);
    sqlite3_bind_text(stmt.get(), 1, command_id.data(), static_cast<int>(command_id.size()),
                      SQLITE_STATIC);
    sqlite3_bind_int(stmt.get(), 2, kStateInFlight);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE)
        spdlog::error("CommandDedupStore::release step failed: {}", sqlite3_errmsg(db_));
}

void CommandDedupStore::prune_locked() noexcept {
    // Clock-free ring: keep the newest kMaxDedupRows by rowid (monotonic with
    // insert order), evict the rest. No wall clock is consulted, so the
    // clock-guarded-retention hazard does not apply. A rare old in-flight row
    // (crashed mid-execution, never redelivered) can be evicted here — bounded,
    // and its only cost is that a later redelivery would re-execute.
    const char* sql = R"(
        DELETE FROM command_outcomes
        WHERE rowid NOT IN (
            SELECT rowid FROM command_outcomes ORDER BY rowid DESC LIMIT ?
        )
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("CommandDedupStore::prune prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }
    StmtPtr stmt(raw_stmt);
    sqlite3_bind_int64(stmt.get(), 1, kMaxDedupRows);
    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE)
        spdlog::error("CommandDedupStore::prune step failed: {}", sqlite3_errmsg(db_));
}

std::optional<std::int64_t> CommandDedupStore::count() const {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::nullopt;
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM command_outcomes", -1, &raw_stmt, nullptr) !=
        SQLITE_OK)
        return std::nullopt;
    StmtPtr stmt(raw_stmt);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW)
        return std::nullopt;
    return sqlite3_column_int64(stmt.get(), 0);
}

} // namespace yuzu::agent
