/**
 * tar_db.cpp -- SQLite-backed Timeline Activity Record database
 *
 * Tables:
 *   tar_events(id, timestamp, event_type, event_action, detail_json, snapshot_id)
 *   tar_state(collector PRIMARY KEY, state_json, updated_at)
 *   tar_config(key PRIMARY KEY, value)
 *
 * All queries use parameterized SQL to prevent injection.
 * A std::mutex guards all sqlite3* access for thread safety (Darwin pitfall).
 */

#include "tar_db.hpp"
#include "tar_schema_registry.hpp"

#include <sqlite3.h>
#include <spdlog/spdlog.h>

#include <cctype>
#include <chrono>
#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <string_view>

namespace yuzu::tar {

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

// Case-insensitive ASCII equality for a short, NUL-terminated SQL identifier
// (SQLite function/identifier names are case-insensitive).
bool ascii_iequals(const char* a, const char* b) noexcept {
    for (; *a && *b; ++a, ++b)
        if (std::tolower(static_cast<unsigned char>(*a)) !=
            std::tolower(static_cast<unsigned char>(*b)))
            return false;
    return *a == *b;
}

// SQLite authorizer for the read-only operator-SQL sandbox (#760). Permits only
// the overall SELECT, reads of registry-known warehouse tables, and scalar/
// aggregate function calls (the handle is read-only, so no function can mutate;
// load_extension is denied both by name here and via SQLITE_DBCONFIG). Everything
// else — INSERT/UPDATE/DELETE/DDL, ATTACH/DETACH, PRAGMA, transaction control,
// recursive CTEs — is denied at prepare time.
//
// noexcept + catch-all is load-bearing: SQLite invokes this from C frames during
// sqlite3_prepare_v2, so a C++ exception (e.g. std::bad_alloc from
// is_queryable_table's allocation) must never unwind through them — that would be
// UB. Any exception fails closed (SQLITE_DENY).
int tar_query_authorizer(void* /*ctx*/, int action, const char* arg1, const char* arg2,
                         const char* /*db_name*/, const char* /*inner_trigger_or_view*/) noexcept {
    try {
        switch (action) {
        case SQLITE_SELECT:
            return SQLITE_OK;
        case SQLITE_FUNCTION:
            // arg2 is the function name; deny load_extension by name (case-
            // insensitive, as SQLite names are) atop the SQLITE_DBCONFIG disable.
            if (arg2 && ascii_iequals(arg2, "load_extension"))
                return SQLITE_DENY;
            return SQLITE_OK;
        case SQLITE_READ:
            return (arg1 && is_queryable_table(arg1)) ? SQLITE_OK : SQLITE_DENY;
        default:
            return SQLITE_DENY;
        }
    } catch (...) {
        return SQLITE_DENY;
    }
}

/// Schema DDL for all TAR tables.
constexpr const char* kCreateSchema = R"(
    CREATE TABLE IF NOT EXISTS tar_events (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp    INTEGER NOT NULL,
        event_type   TEXT    NOT NULL,
        event_action TEXT    NOT NULL,
        detail_json  TEXT    NOT NULL DEFAULT '{}',
        snapshot_id  INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_tar_events_ts
        ON tar_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_tar_events_type_ts
        ON tar_events(event_type, timestamp);
    CREATE INDEX IF NOT EXISTS idx_tar_events_snapshot
        ON tar_events(snapshot_id);

    CREATE TABLE IF NOT EXISTS tar_state (
        collector   TEXT PRIMARY KEY,
        state_json  TEXT NOT NULL DEFAULT '{}',
        updated_at  INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS tar_config (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL DEFAULT ''
    );
)";

// #559 — self-test a freshly-opened tar.db with PRAGMA integrity_check. A
// corrupt file (filesystem damage, partial restore, mid-write crash) must NOT
// be silently trusted: get_config() returns the caller's default on a read
// failure, so a corrupt DB would read every `<source>_enabled` key as its
// "true" default and silently re-enable sources an operator deliberately paused
// for forensic preservation — defeating the #539 retention guard with no
// telemetry. Returns true only when the check reports the canonical "ok".
bool integrity_ok(sqlite3* db) noexcept {
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &raw, nullptr) != SQLITE_OK)
        return false; // can't even read the DB → treat as corrupt
    StmtPtr stmt(raw);
    bool ok = false;
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const auto* txt = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        ok = txt && std::string_view{txt} == "ok";
    }
    return ok;
}

// Move a corrupt tar.db (and its -wal/-shm sidecars) aside to a timestamped
// `.corrupt-<epoch>` path for forensic review, so open() can re-initialise a
// fresh, trustworthy database rather than refusing to load TAR entirely.
// Returns the quarantine path, or std::nullopt if the corrupt main file could
// NOT be moved aside (read-only mount, locked file on Windows, permissions) —
// in which case the caller MUST fail closed rather than re-open-and-trust the
// still-corrupt file (#559 / UP-1). A sidecar that can't be moved is removed
// instead, so the freshly-created DB can never adopt a stale -wal/-shm; the
// caller's post-reopen integrity re-check is the backstop if even that fails.
std::optional<std::filesystem::path>
quarantine_corrupt_db(const std::filesystem::path& path) {
    const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
    std::filesystem::path dest = path;
    dest += std::format(".corrupt-{}", epoch);
    std::error_code ec;
    std::filesystem::rename(path, dest, ec);
    if (ec)
        return std::nullopt; // could not move the corrupt DB aside — fail closed
    for (const char* suffix : {"-wal", "-shm"}) {
        std::filesystem::path side = path;
        side += suffix;
        std::error_code ec2;
        if (std::filesystem::exists(side, ec2)) {
            std::filesystem::path side_dest = dest;
            side_dest += suffix;
            std::filesystem::rename(side, side_dest, ec2);
            if (ec2) {
                // Couldn't preserve the sidecar — remove it so the fresh DB
                // can't replay a stale WAL belonging to the quarantined file.
                std::error_code ec3;
                std::filesystem::remove(side, ec3);
            }
        }
    }
    return dest;
}

} // namespace

// ── Construction / destruction ───────────────────────────────────────────────

TarDatabase::TarDatabase(sqlite3* db) : db_{db} {}

TarDatabase::~TarDatabase() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
    if (query_db_) {
        sqlite3_close(query_db_);
        query_db_ = nullptr;
    }
}

TarDatabase::TarDatabase(TarDatabase&& other) noexcept
    : db_{other.db_}, query_db_{other.query_db_} {
    other.db_ = nullptr;
    other.query_db_ = nullptr;
}

TarDatabase& TarDatabase::operator=(TarDatabase&& other) noexcept {
    if (this != &other) {
        if (db_)
            sqlite3_close(db_);
        if (query_db_)
            sqlite3_close(query_db_);
        db_ = other.db_;
        query_db_ = other.query_db_;
        other.db_ = nullptr;
        other.query_db_ = nullptr;
    }
    return *this;
}

std::expected<TarDatabase, std::string> TarDatabase::open(const std::filesystem::path& path) {
    // Ensure parent directory exists
    std::error_code ec;
    auto parent = path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return std::unexpected(
                std::format("failed to create directory {}: {}", parent.string(), ec.message()));
        }
    }

    sqlite3* raw_db = nullptr;
    int rc = sqlite3_open_v2(path.string().c_str(), &raw_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        std::string err = raw_db ? sqlite3_errmsg(raw_db) : "unknown error";
        if (raw_db)
            sqlite3_close(raw_db);
        return std::unexpected(std::format("failed to open tar.db: {}", err));
    }

    // #559 — corruption self-test BEFORE we trust the DB. A fresh/empty file
    // passes trivially; an existing corrupt one is quarantined aside and a clean
    // DB is re-opened in its place, so the agent never silently serves garbage
    // config (which would re-enable operator-paused sources, compounding #539).
    if (!integrity_ok(raw_db)) {
        sqlite3_close(raw_db);
        raw_db = nullptr;
        auto quarantined = quarantine_corrupt_db(path);
        if (!quarantined) {
            // FAIL CLOSED (UP-1): the corrupt DB could not be moved aside, so we
            // must NOT re-open and trust it — doing so would silently serve the
            // "true" get_config default for every `<source>_enabled` key and
            // re-enable sources an operator paused for forensic preservation,
            // the exact failure #559 guards against. Refuse to open; the
            // operator must clear the underlying fault (read-only mount, locked
            // file, permissions) and restart.
            return std::unexpected(std::format(
                "tar.db failed integrity_check and could not be quarantined "
                "(corrupt and unmovable): {}",
                path.string()));
        }
        spdlog::error("TAR: tar.db failed PRAGMA integrity_check (tar.db.corruption_detected) — "
                      "quarantined to {} and re-initialising a fresh database",
                      quarantined->string());
        rc = sqlite3_open_v2(path.string().c_str(), &raw_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
        if (rc != SQLITE_OK) {
            std::string err = raw_db ? sqlite3_errmsg(raw_db) : "unknown error";
            if (raw_db)
                sqlite3_close(raw_db);
            return std::unexpected(
                std::format("failed to re-open tar.db after quarantine: {}", err));
        }
        // Backstop (UP-2): the freshly-created DB must itself be clean — this
        // also catches the case where a -wal/-shm sidecar belonging to the
        // quarantined file could neither be moved nor removed and was adopted by
        // the new file. If even the fresh DB is corrupt, fail closed.
        if (!integrity_ok(raw_db)) {
            sqlite3_close(raw_db);
            return std::unexpected(std::format(
                "tar.db re-initialised after quarantine still fails integrity_check: {}",
                path.string()));
        }
    }

    // WAL mode for concurrent read performance -- required for correctness
    char* err_msg = nullptr;
    rc = sqlite3_exec(raw_db, "PRAGMA journal_mode=WAL", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown";
        sqlite3_free(err_msg);
        sqlite3_close(raw_db);
        return std::unexpected(std::format("failed to enable WAL mode: {}", err));
    }
    sqlite3_free(err_msg);

    // Busy timeout for concurrent access
    sqlite3_busy_timeout(raw_db, 5000);

    // Secure delete -- zeroes deleted content; required for security
    err_msg = nullptr;
    rc = sqlite3_exec(raw_db, "PRAGMA secure_delete=ON", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown";
        sqlite3_free(err_msg);
        sqlite3_close(raw_db);
        return std::unexpected(std::format("failed to enable secure_delete: {}", err));
    }
    sqlite3_free(err_msg);

    // Create schema
    err_msg = nullptr;
    rc = sqlite3_exec(raw_db, kCreateSchema, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        sqlite3_close(raw_db);
        return std::unexpected(std::format("failed to create TAR schema: {}", err));
    }

    // Set default retention if not already configured
    {
        const char* check_sql = "SELECT value FROM tar_config WHERE key = 'retention_days'";
        sqlite3_stmt* raw_stmt = nullptr;
        rc = sqlite3_prepare_v2(raw_db, check_sql, -1, &raw_stmt, nullptr);
        if (rc == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
                // No retention_days configured -- set default
                const char* insert_sql =
                    "INSERT INTO tar_config (key, value) VALUES ('retention_days', '7')";
                sqlite3_exec(raw_db, insert_sql, nullptr, nullptr, nullptr);
            }
        }
    }

    auto db = TarDatabase{raw_db};

    // Ensure every registry-declared warehouse table exists on EVERY open —
    // the DDL is IF-NOT-EXISTS-idempotent, and gating it on schema_version<2
    // left upgraded fleets without tables added by NEWER releases (the A1
    // perf tier never materialised on a pre-existing v3 tar.db, so
    // insert_perf_sample failed every 30 s; found during A2). The version
    // marker keeps its legacy meaning (>=2 = typed warehouse present).
    if (db.create_warehouse_tables()) {
        if (db.schema_version() < 2) {
            db.set_config("schema_version", "2");
            spdlog::info("TarDatabase: migrated to schema version 2 (typed warehouse tables)");
        }
    } else {
        spdlog::warn("TarDatabase: warehouse table creation failed{}",
                     db.schema_version() < 2 ? ", continuing in legacy mode" : "");
    }

    // Disable load_extension for defense-in-depth (H2)
    sqlite3_db_config(raw_db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, nullptr);

    // Version 3: retire legacy tar_events table (reclaim disk space)
    if (db.schema_version() == 2) {
        std::lock_guard lock(db.mu_);
        char* emsg = nullptr;
        // Use SAVEPOINT for atomicity
        sqlite3_exec(raw_db, "SAVEPOINT v3_migration", nullptr, nullptr, nullptr);
        int mrc = sqlite3_exec(raw_db, "DROP TABLE IF EXISTS tar_events", nullptr, nullptr, &emsg);
        if (mrc == SQLITE_OK) {
            sqlite3_free(emsg);
            sqlite3_exec(raw_db, "DROP INDEX IF EXISTS idx_tar_events_ts", nullptr, nullptr,
                         nullptr);
            sqlite3_exec(raw_db, "DROP INDEX IF EXISTS idx_tar_events_type_ts", nullptr, nullptr,
                         nullptr);
            sqlite3_exec(raw_db, "DROP INDEX IF EXISTS idx_tar_events_snapshot", nullptr, nullptr,
                         nullptr);
            // Only set version to 3 if DROP succeeded
            db.set_config_locked("schema_version", "3");
            sqlite3_exec(raw_db, "RELEASE v3_migration", nullptr, nullptr, nullptr);
            spdlog::info("TarDatabase: migrated to schema version 3 (legacy tar_events retired)");
        } else {
            spdlog::warn("TarDatabase: failed to drop tar_events: {}", emsg ? emsg : "unknown");
            sqlite3_free(emsg);
            sqlite3_exec(raw_db, "ROLLBACK TO v3_migration", nullptr, nullptr, nullptr);
            sqlite3_exec(raw_db, "RELEASE v3_migration", nullptr, nullptr, nullptr);
        }
    }

    // Open a dedicated read-only, authorizer-sandboxed connection for untrusted
    // operator SQL (the tar.sql action). On this handle writes are structurally
    // impossible and the authorizer restricts reads to registry-known warehouse
    // tables (#760). Internal trusted reads keep using db_. If this connection
    // can't be opened we continue without it; execute_user_query then fails
    // closed.
    {
        sqlite3* ro = nullptr;
        int rrc = sqlite3_open_v2(path.string().c_str(), &ro,
                                  SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nullptr);
        if (rrc == SQLITE_OK) {
            sqlite3_busy_timeout(ro, 5000);
            sqlite3_db_config(ro, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, nullptr);
            sqlite3_set_authorizer(ro, &tar_query_authorizer, nullptr);
            // Force the is_queryable_table allowlist's one-time static init now,
            // on a normal C++ stack — never lazily inside the authorizer callback
            // while it runs in SQLite's C prepare frames.
            (void)is_queryable_table("");
            db.query_db_ = ro;
        } else {
            spdlog::warn("TarDatabase: read-only query connection unavailable ({}); "
                         "tar.sql queries will be refused",
                         ro ? sqlite3_errmsg(ro) : "open failed");
            if (ro)
                sqlite3_close(ro);
        }
    }

    spdlog::info("TarDatabase opened: {} (schema v{})", path.string(), db.schema_version());
    return db;
}

// ── Statistics (queries typed warehouse tables) ─────────────────────────────

TarStats TarDatabase::stats() {
    std::lock_guard lock(mu_);
    TarStats s{};
    if (!db_)
        return s;

    // Aggregate record count across all live tables
    {
        const char* sql = "SELECT "
                          "(SELECT COUNT(*) FROM process_live) + "
                          "(SELECT COUNT(*) FROM tcp_live) + "
                          "(SELECT COUNT(*) FROM service_live) + "
                          "(SELECT COUNT(*) FROM user_live)";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.record_count = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // Oldest timestamp across all live tables
    {
        const char* sql = "SELECT MIN(m) FROM ("
                          "SELECT MIN(ts) AS m FROM process_live UNION ALL "
                          "SELECT MIN(ts) FROM tcp_live UNION ALL "
                          "SELECT MIN(ts) FROM service_live UNION ALL "
                          "SELECT MIN(ts) FROM user_live)";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.oldest_timestamp = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // Newest timestamp
    {
        const char* sql = "SELECT MAX(m) FROM ("
                          "SELECT MAX(ts) AS m FROM process_live UNION ALL "
                          "SELECT MAX(ts) FROM tcp_live UNION ALL "
                          "SELECT MAX(ts) FROM service_live UNION ALL "
                          "SELECT MAX(ts) FROM user_live)";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.newest_timestamp = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // DB size (page_count * page_size)
    {
        const char* sql =
            "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.db_size_bytes = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // Retention days from config
    {
        const char* sql = "SELECT value FROM tar_config WHERE key = 'retention_days'";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
                auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
                if (text) {
                    try {
                        s.retention_days = std::stoi(text);
                    } catch (...) {
                        s.retention_days = 7;
                    }
                }
            }
        }
    }

    return s;
}

// ── State management ─────────────────────────────────────────────────────────

std::string TarDatabase::get_state(const std::string& collector) {
    std::lock_guard lock(mu_);
    if (!db_)
        return {};

    const char* sql = "SELECT state_json FROM tar_state WHERE collector = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::get_state prepare failed: {}", sqlite3_errmsg(db_));
        return {};
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, collector.c_str(), static_cast<int>(collector.size()),
                      SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        return text ? text : "";
    }
    return {};
}

void TarDatabase::set_state(const std::string& collector, const std::string& json) {
    std::lock_guard lock(mu_);
    if (!db_)
        return;

    const char* sql = R"(
        INSERT INTO tar_state (collector, state_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(collector) DO UPDATE SET state_json = excluded.state_json,
                                             updated_at = excluded.updated_at
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::set_state prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, collector.c_str(), static_cast<int>(collector.size()),
                      SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, json.c_str(), static_cast<int>(json.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt.get(), 3, now_epoch_seconds());

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("TarDatabase::set_state step failed: {}", sqlite3_errmsg(db_));
    }
}

// ── Config management ────────────────────────────────────────────────────────

std::string TarDatabase::get_config(const std::string& key, const std::string& default_val) {
    std::lock_guard lock(mu_);
    if (!db_)
        return default_val;

    const char* sql = "SELECT value FROM tar_config WHERE key = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::get_config prepare failed: {}", sqlite3_errmsg(db_));
        return default_val;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, key.c_str(), static_cast<int>(key.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        return text ? text : default_val;
    }
    return default_val;
}

void TarDatabase::set_config(const std::string& key, const std::string& value) {
    std::lock_guard lock(mu_);
    set_config_locked(key, value);
}

void TarDatabase::set_config_locked(const std::string& key, const std::string& value) {
    if (!db_)
        return;

    const char* sql = R"(
        INSERT INTO tar_config (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::set_config prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, key.c_str(), static_cast<int>(key.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, value.c_str(), static_cast<int>(value.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("TarDatabase::set_config step failed: {}", sqlite3_errmsg(db_));
    }
}

// ── Warehouse schema management ─────────────────────────────────────────────

int TarDatabase::schema_version() {
    auto v = get_config("schema_version", "0");
    try {
        return std::stoi(v);
    } catch (...) {
        return 0;
    }
}

bool TarDatabase::create_warehouse_tables() {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    auto ddl = generate_warehouse_ddl();
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, ddl.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::create_warehouse_tables failed: {}",
                      err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);
    return true;
}

// ── Typed inserts ───────────────────────────────────────────────────────────

bool TarDatabase::insert_process_events(const std::vector<ProcessEvent>& events) {
    std::lock_guard lock(mu_);
    if (!db_ || events.empty())
        return events.empty();

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_process_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO process_live (ts, snapshot_id, action, pid, ppid, name, cmdline, user)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_process_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt.get(), 4, static_cast<int>(ev.pid));
        sqlite3_bind_int(stmt.get(), 5, static_cast<int>(ev.ppid));
        sqlite3_bind_text(stmt.get(), 6, ev.name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 7, ev.cmdline.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 8, ev.user.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_process_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_process_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

bool TarDatabase::insert_network_events(const std::vector<NetworkEvent>& events) {
    std::lock_guard lock(mu_);
    if (!db_ || events.empty())
        return events.empty();

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_network_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO tcp_live (ts, snapshot_id, action, proto, local_addr, local_port,
                              remote_addr, remote_host, remote_port, state, pid, process_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_network_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.proto.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, ev.local_addr.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt.get(), 6, ev.local_port);
        sqlite3_bind_text(stmt.get(), 7, ev.remote_addr.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 8, ev.remote_host.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt.get(), 9, ev.remote_port);
        sqlite3_bind_text(stmt.get(), 10, ev.state.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt.get(), 11, static_cast<int>(ev.pid));
        sqlite3_bind_text(stmt.get(), 12, ev.process_name.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_network_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_network_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

std::expected<std::vector<NetworkEvent>, std::string>
TarDatabase::query_recent_tcp_connections(int64_t since_ts) {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected{"database not open"};

    // Group by 5-tuple+pid; surface the most recent observation per group.
    // Filter to ESTABLISHED — LISTEN/TIME_WAIT/CLOSE_WAIT/etc. are not
    // "this box talks to that box" edges and would pollute the viz.
    // remote_host (reverse-DNS) is taken from the latest row in the group
    // via a correlated subquery; if two rows in the same group resolved
    // differently, we accept the newest.
    const char* sql = R"(
        SELECT proto, local_addr, local_port, remote_addr, remote_port, pid,
               MAX(process_name) AS process_name,
               MAX(remote_host)  AS remote_host,
               MAX(state)        AS state,
               MAX(ts)           AS ts
        FROM tcp_live
        WHERE ts >= ?
          AND state = 'ESTABLISHED'
        GROUP BY proto, local_addr, local_port, remote_addr, remote_port, pid
        ORDER BY ts DESC
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK)
        return std::unexpected{std::string{"prepare: "} + sqlite3_errmsg(db_)};
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_int64(stmt.get(), 1, since_ts);

    std::vector<NetworkEvent> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        NetworkEvent ev;
        auto col_text = [&](int i) -> std::string {
            const unsigned char* p = sqlite3_column_text(stmt.get(), i);
            return p ? std::string{reinterpret_cast<const char*>(p)} : std::string{};
        };
        ev.proto = col_text(0);
        ev.local_addr = col_text(1);
        ev.local_port = sqlite3_column_int(stmt.get(), 2);
        ev.remote_addr = col_text(3);
        ev.remote_port = sqlite3_column_int(stmt.get(), 4);
        ev.pid = static_cast<uint32_t>(sqlite3_column_int(stmt.get(), 5));
        ev.process_name = col_text(6);
        ev.remote_host = col_text(7);
        ev.state = col_text(8);
        ev.ts = sqlite3_column_int64(stmt.get(), 9);
        out.push_back(std::move(ev));
    }
    return out;
}

bool TarDatabase::insert_service_events(const std::vector<ServiceEvent>& events) {
    std::lock_guard lock(mu_);
    if (!db_ || events.empty())
        return events.empty();

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_service_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO service_live (ts, snapshot_id, action, name, display_name, status,
                                  prev_status, startup_type, prev_startup_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_service_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, ev.display_name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 6, ev.status.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 7, ev.prev_status.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 8, ev.startup_type.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 9, ev.prev_startup_type.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_service_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_service_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

bool TarDatabase::insert_user_events(const std::vector<UserEvent>& events) {
    std::lock_guard lock(mu_);
    if (!db_ || events.empty())
        return events.empty();

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_user_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO user_live (ts, snapshot_id, action, user, domain, logon_type, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_user_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.user.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, ev.domain.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 6, ev.logon_type.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 7, ev.session_id.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_user_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_user_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

bool TarDatabase::insert_perf_sample(const PerfRow& row) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    // Single row per sample interval — no transaction wrapper needed (one
    // statement is already atomic; one fsync per 30 s is the WAL cost).
    const char* sql = R"(
        INSERT INTO perf_live (ts, snapshot_id, cpu_pct, mem_used_pct, commit_pct,
                               disk_read_bps, disk_write_bps, disk_read_lat_us,
                               disk_write_lat_us, net_rx_bps, net_tx_bps)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("insert_perf_sample prepare: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_int64(stmt.get(), 1, row.ts);
    sqlite3_bind_int64(stmt.get(), 2, row.snapshot_id);
    sqlite3_bind_double(stmt.get(), 3, row.cpu_pct);
    sqlite3_bind_double(stmt.get(), 4, row.mem_used_pct);
    sqlite3_bind_double(stmt.get(), 5, row.commit_pct);
    sqlite3_bind_int64(stmt.get(), 6, row.disk_read_bps);
    sqlite3_bind_int64(stmt.get(), 7, row.disk_write_bps);
    sqlite3_bind_int64(stmt.get(), 8, row.disk_read_lat_us);
    sqlite3_bind_int64(stmt.get(), 9, row.disk_write_lat_us);
    sqlite3_bind_int64(stmt.get(), 10, row.net_rx_bps);
    sqlite3_bind_int64(stmt.get(), 11, row.net_tx_bps);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        spdlog::error("insert_perf_sample step: {}", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

bool TarDatabase::insert_proc_perf_samples(const std::vector<ProcPerfRow>& rows) {
    std::lock_guard lock(mu_);
    if (!db_ || rows.empty())
        return rows.empty();

    // <= 2*kProcTopN rows per tick — one transaction, one fsync per 30 s.
    char* err_msg = nullptr;
    if (sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("insert_proc_perf_samples BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO procperf_live (ts, snapshot_id, name, instances, cpu_pct, ws_bytes)
        VALUES (?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("insert_proc_perf_samples prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& r : rows) {
        sqlite3_bind_int64(stmt.get(), 1, r.ts);
        sqlite3_bind_int64(stmt.get(), 2, r.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, r.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt.get(), 4, r.instances);
        sqlite3_bind_double(stmt.get(), 5, r.cpu_pct);
        sqlite3_bind_int64(stmt.get(), 6, r.ws_bytes);
        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_proc_perf_samples step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
    }

    if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("insert_proc_perf_samples COMMIT: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    sqlite3_free(err_msg);
    return true;
}

bool TarDatabase::insert_netqual_samples(const std::vector<NetQualRow>& rows) {
    std::lock_guard lock(mu_);
    if (!db_ || rows.empty())
        return rows.empty();

    // <= top-N connections per tick (collector cap) — one transaction per tick.
    char* err_msg = nullptr;
    if (sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("insert_netqual_samples BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO netqual_live
            (ts, snapshot_id, proto, remote_bucket, process_name,
             rtt_us, rtt_var_us, lost, retrans, segs_out, ca_state)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("insert_netqual_samples prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& r : rows) {
        sqlite3_bind_int64(stmt.get(), 1, r.ts);
        sqlite3_bind_int64(stmt.get(), 2, r.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, r.proto.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 4, r.remote_bucket.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 5, r.process_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt.get(), 6, r.rtt_us);
        sqlite3_bind_int64(stmt.get(), 7, r.rtt_var_us);
        sqlite3_bind_int64(stmt.get(), 8, r.lost);
        sqlite3_bind_int64(stmt.get(), 9, r.retrans);
        sqlite3_bind_int64(stmt.get(), 10, r.segs_out);
        sqlite3_bind_int64(stmt.get(), 11, r.ca_state);
        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_netqual_samples step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
    }

    if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("insert_netqual_samples COMMIT: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    sqlite3_free(err_msg);
    return true;
}

// ── Generic SQL execution ───────────────────────────────────────────────────

std::expected<QueryResult, std::string> TarDatabase::execute_query(const std::string& sql,
                                                                   int max_rows) {
    std::lock_guard lock(mu_);
    QueryResult result;
    if (!db_)
        return std::unexpected("database not open");

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        auto err = std::string(sqlite3_errmsg(db_));
        spdlog::error("execute_query prepare: {}", err);
        return std::unexpected(std::format("query failed: {}", err));
    }
    StmtPtr stmt(raw_stmt);

    // Extract column names
    int col_count = sqlite3_column_count(stmt.get());
    result.columns.reserve(col_count);
    for (int i = 0; i < col_count; ++i) {
        auto name = sqlite3_column_name(stmt.get(), i);
        result.columns.emplace_back(name ? name : "");
    }

    // Step through rows with enforced row limit (H1: prevent DoS via cross-joins)
    int row_count = 0;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        if (++row_count > max_rows) {
            spdlog::warn("execute_query: row limit ({}) exceeded, truncating", max_rows);
            break;
        }
        QueryRow row;
        row.reserve(col_count);
        for (int i = 0; i < col_count; ++i) {
            auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), i));
            row.emplace_back(text ? text : "");
        }
        result.rows.push_back(std::move(row));
    }

    return result;
}

std::expected<QueryResult, std::string> TarDatabase::execute_user_query(const std::string& sql,
                                                                        int max_rows) {
    std::lock_guard lock(query_mu_);
    QueryResult result;
    if (!query_db_)
        return std::unexpected("query engine unavailable");

    sqlite3_stmt* raw_stmt = nullptr;
    const char* tail = nullptr;
    // Pass the explicit byte length (not -1): with -1 SQLite stops at the first
    // embedded NUL, which would let the executed query differ from the validated
    // one (the #631 class). An explicit length makes an embedded NUL a tokenizer
    // error instead.
    int rc = sqlite3_prepare_v2(query_db_, sql.c_str(), static_cast<int>(sql.size()), &raw_stmt,
                                &tail);
    if (rc != SQLITE_OK) {
        // Authorizer denials surface as SQLITE_AUTH; keep the reason generic so
        // a probe can't use the message to enumerate tables or columns.
        if (rc == SQLITE_AUTH)
            return std::unexpected("query rejected: operation or table not permitted");
        auto err = std::string(sqlite3_errmsg(query_db_));
        spdlog::warn("execute_user_query prepare failed: {}", err);
        return std::unexpected(std::format("query failed: {}", err));
    }
    StmtPtr stmt(raw_stmt);

    // Engine-level single-statement enforcement: prepare_v2 compiles only the
    // first statement and points `tail` at the remainder — reject any trailing
    // SQL (defence in depth alongside the validator's check).
    if (tail) {
        while (*tail && std::isspace(static_cast<unsigned char>(*tail)))
            ++tail;
        if (*tail)
            return std::unexpected("only single-statement queries are allowed");
    }

    int col_count = sqlite3_column_count(stmt.get());
    result.columns.reserve(col_count);
    for (int i = 0; i < col_count; ++i) {
        auto name = sqlite3_column_name(stmt.get(), i);
        result.columns.emplace_back(name ? name : "");
    }

    int row_count = 0;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        if (++row_count > max_rows) {
            spdlog::warn("execute_user_query: row limit ({}) exceeded, truncating", max_rows);
            break;
        }
        QueryRow row;
        row.reserve(col_count);
        for (int i = 0; i < col_count; ++i) {
            auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), i));
            row.emplace_back(text ? text : "");
        }
        result.rows.push_back(std::move(row));
    }

    return result;
}

bool TarDatabase::execute_sql(const std::string& sql) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("execute_sql failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);
    return true;
}

bool TarDatabase::execute_sql_range(const std::string& sql, int64_t from, int64_t to) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("execute_sql_range prepare: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    // Bind all ? placeholders as repeating (from, to) pairs.
    // CONTRACT: All rollup SQL must use ? in (from, to) pairs with identical semantics.
    int param_count = sqlite3_bind_parameter_count(stmt.get());
    if (param_count % 2 != 0) {
        spdlog::error("execute_sql_range: odd parameter count {} — expected (from,to) pairs",
                      param_count);
        return false;
    }
    for (int i = 1; i <= param_count; i += 2) {
        sqlite3_bind_int64(stmt.get(), i, from);
        sqlite3_bind_int64(stmt.get(), i + 1, to);
    }

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        spdlog::error("execute_sql_range step: {}", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

} // namespace yuzu::tar
