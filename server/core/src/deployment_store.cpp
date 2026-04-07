#include "deployment_store.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <mutex>
#include <random>

namespace yuzu::server {

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static const char* safe(const char* p) {
    return p ? p : "";
}

// ── ID generation ────────────────────────────────────────────────────────────

std::string DeploymentStore::generate_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<uint64_t> dist;
    uint64_t val = dist(rng);
    // Format as 16-char hex
    char buf[17]{};
    snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(val));
    return std::string{buf};
}

// ── Construction / teardown ──────────────────────────────────────────────────

DeploymentStore::DeploymentStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("DeploymentStore: failed to open {}: {}", db_path.string(),
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
    spdlog::info("DeploymentStore: opened {}", db_path.string());
}

DeploymentStore::~DeploymentStore() {
    if (db_)
        sqlite3_close(db_);
}

bool DeploymentStore::is_open() const {
    return db_ != nullptr;
}

void DeploymentStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS deployment_jobs (
            id              TEXT PRIMARY KEY,
            target_host     TEXT NOT NULL,
            os              TEXT NOT NULL DEFAULT 'linux',
            method          TEXT NOT NULL DEFAULT 'manual',
            status          TEXT NOT NULL DEFAULT 'pending',
            created_at      INTEGER NOT NULL DEFAULT 0,
            started_at      INTEGER NOT NULL DEFAULT 0,
            completed_at    INTEGER NOT NULL DEFAULT 0,
            error           TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_deployment_status ON deployment_jobs(status);
        CREATE INDEX IF NOT EXISTS idx_deployment_created ON deployment_jobs(created_at);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("DeploymentStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

// ── Operations ───────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
DeploymentStore::create_job(const std::string& target_host, const std::string& os,
                            const std::string& method) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    if (target_host.empty())
        return std::unexpected("target_host is required");

    // Validate hostname: must match DNS rules — [a-zA-Z0-9._-] only, max 253 chars.
    // Reject anything with shell metacharacters to prevent command injection.
    if (target_host.size() > 253)
        return std::unexpected("target_host exceeds DNS limit of 253 characters");

    auto is_valid_hostname_char = [](char c) -> bool {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    };
    if (!std::all_of(target_host.begin(), target_host.end(), is_valid_hostname_char))
        return std::unexpected("target_host contains invalid characters "
                               "(only [a-zA-Z0-9._-] allowed)");

    // Validate OS
    if (os != "windows" && os != "linux" && os != "darwin")
        return std::unexpected("os must be windows, linux, or darwin");

    // Validate method
    if (method != "ssh" && method != "group_policy" && method != "manual")
        return std::unexpected("method must be ssh, group_policy, or manual");

    auto id = generate_id();
    auto now = now_epoch();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO deployment_jobs "
                           "(id, target_host, os, method, status, created_at) "
                           "VALUES (?, ?, ?, ?, 'pending', ?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));

    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, target_host.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, os.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, method.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 5, now);

    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(sqlite3_errmsg(db_));

    spdlog::info("DeploymentStore: created job {} for {} ({})", id, target_host, method);
    return id;
}

std::vector<DeploymentJob> DeploymentStore::list_jobs() const {
    std::shared_lock lock(mtx_);
    std::vector<DeploymentJob> result;
    if (!db_)
        return result;

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT id, target_host, os, method, status, created_at, started_at, "
            "completed_at, error FROM deployment_jobs ORDER BY created_at DESC;",
            -1, &s, nullptr) != SQLITE_OK)
        return result;

    while (sqlite3_step(s) == SQLITE_ROW) {
        DeploymentJob j;
        j.id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        j.target_host = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        j.os = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        j.method = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        j.status = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 4)));
        j.created_at = sqlite3_column_int64(s, 5);
        j.started_at = sqlite3_column_int64(s, 6);
        j.completed_at = sqlite3_column_int64(s, 7);
        j.error = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 8)));
        result.push_back(std::move(j));
    }
    sqlite3_finalize(s);
    return result;
}

std::optional<DeploymentJob> DeploymentStore::get_job(const std::string& id) const {
    std::shared_lock lock(mtx_);
    return get_job_impl(id);
}

std::optional<DeploymentJob> DeploymentStore::get_job_impl(const std::string& id) const {
    if (!db_)
        return std::nullopt;

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT id, target_host, os, method, status, created_at, started_at, "
            "completed_at, error FROM deployment_jobs WHERE id = ? LIMIT 1;",
            -1, &s, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<DeploymentJob> result;
    if (sqlite3_step(s) == SQLITE_ROW) {
        DeploymentJob j;
        j.id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        j.target_host = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        j.os = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        j.method = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        j.status = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 4)));
        j.created_at = sqlite3_column_int64(s, 5);
        j.started_at = sqlite3_column_int64(s, 6);
        j.completed_at = sqlite3_column_int64(s, 7);
        j.error = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 8)));
        result = std::move(j);
    }
    sqlite3_finalize(s);
    return result;
}

std::expected<void, std::string>
DeploymentStore::update_status(const std::string& id, const std::string& status,
                               const std::string& error) {
    std::unique_lock lock(mtx_);
    return update_status_impl(id, status, error);
}

std::expected<void, std::string>
DeploymentStore::update_status_impl(const std::string& id, const std::string& status,
                                    const std::string& error) {
    if (!db_)
        return std::unexpected("database not open");

    // Validate status
    if (status != "pending" && status != "running" && status != "completed" &&
        status != "failed" && status != "cancelled")
        return std::unexpected("invalid status");

    auto now = now_epoch();

    sqlite3_stmt* s = nullptr;
    const char* sql = nullptr;

    if (status == "running") {
        sql = "UPDATE deployment_jobs SET status = ?, started_at = ?, error = ? WHERE id = ?;";
    } else if (status == "completed" || status == "failed") {
        sql = "UPDATE deployment_jobs SET status = ?, completed_at = ?, error = ? WHERE id = ?;";
    } else {
        sql = "UPDATE deployment_jobs SET status = ?, created_at = created_at, error = ? WHERE id = ?;";
    }

    if (status == "running" || status == "completed" || status == "failed") {
        if (sqlite3_prepare_v2(db_, sql, -1, &s, nullptr) != SQLITE_OK)
            return std::unexpected(sqlite3_errmsg(db_));
        sqlite3_bind_text(s, 1, status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(s, 2, now);
        sqlite3_bind_text(s, 3, error.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 4, id.c_str(), -1, SQLITE_TRANSIENT);
    } else {
        if (sqlite3_prepare_v2(db_, sql, -1, &s, nullptr) != SQLITE_OK)
            return std::unexpected(sqlite3_errmsg(db_));
        sqlite3_bind_text(s, 1, status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 2, error.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 3, id.c_str(), -1, SQLITE_TRANSIENT);
    }

    sqlite3_step(s);
    sqlite3_finalize(s);

    if (sqlite3_changes(db_) == 0)
        return std::unexpected("job not found");

    return {};
}

std::expected<void, std::string> DeploymentStore::cancel_job(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    // Only pending or running jobs can be cancelled — atomic check+update under lock
    auto job = get_job_impl(id);
    if (!job)
        return std::unexpected("job not found");
    if (job->status != "pending" && job->status != "running")
        return std::unexpected("only pending or running jobs can be cancelled");

    return update_status_impl(id, "cancelled", "cancelled by operator");
}

} // namespace yuzu::server
