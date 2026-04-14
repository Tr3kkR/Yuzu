#include "software_deployment_store.hpp"
#include "migration_runner.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <random>

namespace yuzu::server {

// ── Helpers ──────────────────────────────────────────────────────────────────

namespace {

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string col_text(sqlite3_stmt* stmt, int col) {
    auto p = sqlite3_column_text(stmt, col);
    return p ? std::string(reinterpret_cast<const char*>(p)) : std::string{};
}

std::string generate_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<uint64_t> dist;
    auto hi = dist(rng);
    auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx", static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

} // namespace

// ── Construction / teardown ──────────────────────────────────────────────────

SoftwareDeploymentStore::SoftwareDeploymentStore(const std::filesystem::path& db_path) {
    // Canonicalize parent path (Darwin /var -> /private/var symlink)
    auto canonical_path = db_path;
    {
        std::error_code ec;
        auto parent = db_path.parent_path();
        if (!parent.empty() && std::filesystem::exists(parent, ec)) {
            auto canon_parent = std::filesystem::canonical(parent, ec);
            if (!ec)
                canonical_path = canon_parent / db_path.filename();
        }
    }
    int rc = sqlite3_open_v2(canonical_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("SoftwareDeploymentStore: failed to open {}: {}", canonical_path.string(),
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
    if (db_)
        spdlog::info("SoftwareDeploymentStore: opened {}", canonical_path.string());
}

SoftwareDeploymentStore::~SoftwareDeploymentStore() {
    if (db_)
        sqlite3_close(db_);
}

bool SoftwareDeploymentStore::is_open() const {
    return db_ != nullptr;
}

void SoftwareDeploymentStore::create_tables() {
    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS software_packages (
                id               TEXT PRIMARY KEY,
                name             TEXT NOT NULL,
                version          TEXT NOT NULL DEFAULT '',
                platform         TEXT NOT NULL DEFAULT '',
                installer_type   TEXT NOT NULL DEFAULT '',
                content_hash     TEXT NOT NULL DEFAULT '',
                content_url      TEXT NOT NULL DEFAULT '',
                silent_args      TEXT NOT NULL DEFAULT '',
                verify_command   TEXT NOT NULL DEFAULT '',
                rollback_command TEXT NOT NULL DEFAULT '',
                size_bytes       INTEGER NOT NULL DEFAULT 0,
                created_at       INTEGER NOT NULL DEFAULT 0,
                created_by       TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_swpkg_name ON software_packages(name);
            CREATE INDEX IF NOT EXISTS idx_swpkg_platform ON software_packages(platform);

            CREATE TABLE IF NOT EXISTS software_deployments (
                id               TEXT PRIMARY KEY,
                package_id       TEXT NOT NULL,
                scope_expression TEXT NOT NULL DEFAULT '',
                status           TEXT NOT NULL DEFAULT 'staged',
                created_by       TEXT NOT NULL DEFAULT '',
                created_at       INTEGER NOT NULL DEFAULT 0,
                started_at       INTEGER NOT NULL DEFAULT 0,
                completed_at     INTEGER NOT NULL DEFAULT 0,
                agents_targeted  INTEGER NOT NULL DEFAULT 0,
                agents_success   INTEGER NOT NULL DEFAULT 0,
                agents_failure   INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (package_id) REFERENCES software_packages(id)
            );
            CREATE INDEX IF NOT EXISTS idx_swdep_status ON software_deployments(status);
            CREATE INDEX IF NOT EXISTS idx_swdep_package ON software_deployments(package_id);
            CREATE INDEX IF NOT EXISTS idx_swdep_created ON software_deployments(created_at);

            CREATE TABLE IF NOT EXISTS agent_software_status (
                deployment_id TEXT NOT NULL,
                agent_id      TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'pending',
                started_at    INTEGER NOT NULL DEFAULT 0,
                completed_at  INTEGER NOT NULL DEFAULT 0,
                error         TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (deployment_id, agent_id),
                FOREIGN KEY (deployment_id) REFERENCES software_deployments(id)
            );
            CREATE INDEX IF NOT EXISTS idx_agentstatus_dep ON agent_software_status(deployment_id);
            CREATE INDEX IF NOT EXISTS idx_agentstatus_agent ON agent_software_status(agent_id);
        )"},
    };
    if (!MigrationRunner::run(db_, "software_deployment_store", kMigrations)) {
        spdlog::error("SoftwareDeploymentStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ── Packages ─────────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
SoftwareDeploymentStore::create_package(const SoftwarePackage& pkg) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    if (pkg.name.empty())
        return std::unexpected("name is required");

    auto id = generate_id();
    auto now = now_epoch();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO software_packages "
                           "(id, name, version, platform, installer_type, content_hash, "
                           "content_url, silent_args, verify_command, rollback_command, "
                           "size_bytes, created_at, created_by) "
                           "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));

    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, pkg.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, pkg.version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, pkg.platform.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 5, pkg.installer_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 6, pkg.content_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 7, pkg.content_url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 8, pkg.silent_args.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 9, pkg.verify_command.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 10, pkg.rollback_command.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 11, pkg.size_bytes);
    sqlite3_bind_int64(s, 12, now);
    sqlite3_bind_text(s, 13, pkg.created_by.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(sqlite3_errmsg(db_));

    spdlog::info("SoftwareDeploymentStore: created package {} ({})", id, pkg.name);
    return id;
}

std::vector<SoftwarePackage> SoftwareDeploymentStore::list_packages() const {
    std::shared_lock lock(mtx_);
    std::vector<SoftwarePackage> result;
    if (!db_)
        return result;

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT id, name, version, platform, installer_type, content_hash, "
                           "content_url, silent_args, verify_command, rollback_command, "
                           "size_bytes, created_at, created_by "
                           "FROM software_packages ORDER BY created_at DESC;",
                           -1, &s, nullptr) != SQLITE_OK)
        return result;

    while (sqlite3_step(s) == SQLITE_ROW) {
        SoftwarePackage p;
        p.id = col_text(s, 0);
        p.name = col_text(s, 1);
        p.version = col_text(s, 2);
        p.platform = col_text(s, 3);
        p.installer_type = col_text(s, 4);
        p.content_hash = col_text(s, 5);
        p.content_url = col_text(s, 6);
        p.silent_args = col_text(s, 7);
        p.verify_command = col_text(s, 8);
        p.rollback_command = col_text(s, 9);
        p.size_bytes = sqlite3_column_int64(s, 10);
        p.created_at = sqlite3_column_int64(s, 11);
        p.created_by = col_text(s, 12);
        result.push_back(std::move(p));
    }
    sqlite3_finalize(s);
    return result;
}

std::optional<SoftwarePackage>
SoftwareDeploymentStore::get_package(const std::string& id) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return std::nullopt;

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT id, name, version, platform, installer_type, content_hash, "
                           "content_url, silent_args, verify_command, rollback_command, "
                           "size_bytes, created_at, created_by "
                           "FROM software_packages WHERE id = ? LIMIT 1;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<SoftwarePackage> result;
    if (sqlite3_step(s) == SQLITE_ROW) {
        SoftwarePackage p;
        p.id = col_text(s, 0);
        p.name = col_text(s, 1);
        p.version = col_text(s, 2);
        p.platform = col_text(s, 3);
        p.installer_type = col_text(s, 4);
        p.content_hash = col_text(s, 5);
        p.content_url = col_text(s, 6);
        p.silent_args = col_text(s, 7);
        p.verify_command = col_text(s, 8);
        p.rollback_command = col_text(s, 9);
        p.size_bytes = sqlite3_column_int64(s, 10);
        p.created_at = sqlite3_column_int64(s, 11);
        p.created_by = col_text(s, 12);
        result = std::move(p);
    }
    sqlite3_finalize(s);
    return result;
}

bool SoftwareDeploymentStore::delete_package(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM software_packages WHERE id = ?;", -1, &s,
                           nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return sqlite3_changes(db_) > 0;
}

// ── Deployments ──────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
SoftwareDeploymentStore::create_deployment(const SoftwareDeployment& dep) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    if (dep.package_id.empty())
        return std::unexpected("package_id is required");

    auto id = generate_id();
    auto now = now_epoch();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO software_deployments "
                           "(id, package_id, scope_expression, status, created_by, "
                           "created_at, agents_targeted) "
                           "VALUES (?,?,?,'staged',?,?,?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));

    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, dep.package_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, dep.scope_expression.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, dep.created_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 5, now);
    sqlite3_bind_int(s, 6, dep.agents_targeted);

    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(sqlite3_errmsg(db_));

    spdlog::info("SoftwareDeploymentStore: created deployment {} for package {}", id,
                 dep.package_id);
    return id;
}

std::vector<SoftwareDeployment>
SoftwareDeploymentStore::list_deployments(const std::string& status) const {
    std::shared_lock lock(mtx_);
    std::vector<SoftwareDeployment> result;
    if (!db_)
        return result;

    sqlite3_stmt* s = nullptr;
    if (status.empty()) {
        if (sqlite3_prepare_v2(db_,
                               "SELECT id, package_id, scope_expression, status, created_by, "
                               "created_at, started_at, completed_at, agents_targeted, "
                               "agents_success, agents_failure "
                               "FROM software_deployments ORDER BY created_at DESC;",
                               -1, &s, nullptr) != SQLITE_OK)
            return result;
    } else {
        if (sqlite3_prepare_v2(db_,
                               "SELECT id, package_id, scope_expression, status, created_by, "
                               "created_at, started_at, completed_at, agents_targeted, "
                               "agents_success, agents_failure "
                               "FROM software_deployments WHERE status = ? "
                               "ORDER BY created_at DESC;",
                               -1, &s, nullptr) != SQLITE_OK)
            return result;
        sqlite3_bind_text(s, 1, status.c_str(), -1, SQLITE_TRANSIENT);
    }

    while (sqlite3_step(s) == SQLITE_ROW) {
        SoftwareDeployment d;
        d.id = col_text(s, 0);
        d.package_id = col_text(s, 1);
        d.scope_expression = col_text(s, 2);
        d.status = col_text(s, 3);
        d.created_by = col_text(s, 4);
        d.created_at = sqlite3_column_int64(s, 5);
        d.started_at = sqlite3_column_int64(s, 6);
        d.completed_at = sqlite3_column_int64(s, 7);
        d.agents_targeted = sqlite3_column_int(s, 8);
        d.agents_success = sqlite3_column_int(s, 9);
        d.agents_failure = sqlite3_column_int(s, 10);
        result.push_back(std::move(d));
    }
    sqlite3_finalize(s);
    return result;
}

std::optional<SoftwareDeployment>
SoftwareDeploymentStore::get_deployment(const std::string& id) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return std::nullopt;

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT id, package_id, scope_expression, status, created_by, "
                           "created_at, started_at, completed_at, agents_targeted, "
                           "agents_success, agents_failure "
                           "FROM software_deployments WHERE id = ? LIMIT 1;",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<SoftwareDeployment> result;
    if (sqlite3_step(s) == SQLITE_ROW) {
        SoftwareDeployment d;
        d.id = col_text(s, 0);
        d.package_id = col_text(s, 1);
        d.scope_expression = col_text(s, 2);
        d.status = col_text(s, 3);
        d.created_by = col_text(s, 4);
        d.created_at = sqlite3_column_int64(s, 5);
        d.started_at = sqlite3_column_int64(s, 6);
        d.completed_at = sqlite3_column_int64(s, 7);
        d.agents_targeted = sqlite3_column_int(s, 8);
        d.agents_success = sqlite3_column_int(s, 9);
        d.agents_failure = sqlite3_column_int(s, 10);
        result = std::move(d);
    }
    sqlite3_finalize(s);
    return result;
}

bool SoftwareDeploymentStore::start_deployment(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    auto now = now_epoch();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "UPDATE software_deployments SET status = 'deploying', started_at = ? "
                           "WHERE id = ? AND status = 'staged';",
                           -1, &s, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_int64(s, 1, now);
    sqlite3_bind_text(s, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return sqlite3_changes(db_) > 0;
}

bool SoftwareDeploymentStore::cancel_deployment(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    auto now = now_epoch();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "UPDATE software_deployments SET status = 'cancelled', completed_at = ? "
            "WHERE id = ? AND status IN ('staged','deploying');",
            -1, &s, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_int64(s, 1, now);
    sqlite3_bind_text(s, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return sqlite3_changes(db_) > 0;
}

bool SoftwareDeploymentStore::rollback_deployment(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;

    auto now = now_epoch();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "UPDATE software_deployments SET status = 'rolled_back', completed_at = ? "
            "WHERE id = ? AND status IN ('deploying','verifying','completed');",
            -1, &s, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_int64(s, 1, now);
    sqlite3_bind_text(s, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return sqlite3_changes(db_) > 0;
}

void SoftwareDeploymentStore::update_agent_status(const std::string& deployment_id,
                                                   const AgentDeploymentStatus& status) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT OR REPLACE INTO agent_software_status "
                           "(deployment_id, agent_id, status, started_at, completed_at, error) "
                           "VALUES (?,?,?,?,?,?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(s, 1, deployment_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, status.agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, status.status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 4, status.started_at);
    sqlite3_bind_int64(s, 5, status.completed_at);
    sqlite3_bind_text(s, 6, status.error.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(s);
    sqlite3_finalize(s);
}

void SoftwareDeploymentStore::refresh_counts(const std::string& deployment_id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "UPDATE software_deployments SET "
            "agents_success = (SELECT COUNT(*) FROM agent_software_status "
            "  WHERE deployment_id = ? AND status = 'success'), "
            "agents_failure = (SELECT COUNT(*) FROM agent_software_status "
            "  WHERE deployment_id = ? AND status = 'failed') "
            "WHERE id = ?;",
            -1, &s, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(s, 1, deployment_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, deployment_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, deployment_id.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(s);
    sqlite3_finalize(s);
}

std::vector<AgentDeploymentStatus>
SoftwareDeploymentStore::get_agent_statuses(const std::string& deployment_id) const {
    std::shared_lock lock(mtx_);
    std::vector<AgentDeploymentStatus> result;
    if (!db_)
        return result;

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT deployment_id, agent_id, status, started_at, completed_at, "
                           "error FROM agent_software_status WHERE deployment_id = ? "
                           "ORDER BY agent_id;",
                           -1, &s, nullptr) != SQLITE_OK)
        return result;

    sqlite3_bind_text(s, 1, deployment_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(s) == SQLITE_ROW) {
        AgentDeploymentStatus a;
        a.deployment_id = col_text(s, 0);
        a.agent_id = col_text(s, 1);
        a.status = col_text(s, 2);
        a.started_at = sqlite3_column_int64(s, 3);
        a.completed_at = sqlite3_column_int64(s, 4);
        a.error = col_text(s, 5);
        result.push_back(std::move(a));
    }
    sqlite3_finalize(s);
    return result;
}

int SoftwareDeploymentStore::active_count() const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return 0;

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT COUNT(*) FROM software_deployments "
                           "WHERE status IN ('deploying','verifying');",
                           -1, &s, nullptr) != SQLITE_OK)
        return 0;

    int count = 0;
    if (sqlite3_step(s) == SQLITE_ROW)
        count = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return count;
}

} // namespace yuzu::server
