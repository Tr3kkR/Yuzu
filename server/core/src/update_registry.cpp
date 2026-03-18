#include "update_registry.hpp"

#include "nvd_db.hpp" // compare_versions()

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <functional>
#include <string_view>
#include <utility>

namespace yuzu::server {

// ── UpdateRegistry implementation ────────────────────────────────────────────

UpdateRegistry::UpdateRegistry(const std::filesystem::path& db_path,
                               const std::filesystem::path& update_dir)
    : update_dir_(update_dir) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("UpdateRegistry: failed to open {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }

    // Enable WAL mode for better concurrent read performance
    char* err_msg = nullptr;
    rc = sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::warn("UpdateRegistry: WAL mode failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
    }

    create_tables();
    spdlog::info("UpdateRegistry: opened {}", db_path.string());
}

UpdateRegistry::~UpdateRegistry() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool UpdateRegistry::is_open() const {
    return db_ != nullptr;
}

void UpdateRegistry::create_tables() {
    if (!db_)
        return;

    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS update_packages (
            platform    TEXT    NOT NULL,
            arch        TEXT    NOT NULL,
            version     TEXT    NOT NULL,
            sha256      TEXT    NOT NULL,
            filename    TEXT    NOT NULL,
            mandatory   INTEGER DEFAULT 0,
            rollout_pct INTEGER DEFAULT 100,
            uploaded_at TEXT,
            file_size   INTEGER DEFAULT 0,
            PRIMARY KEY (platform, arch, version)
        );
    )";

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("UpdateRegistry: create_tables failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
    }
}

void UpdateRegistry::upsert_package(const UpdatePackage& pkg) {
    if (!db_)
        return;

    const char* sql = R"(
        INSERT OR REPLACE INTO update_packages
            (platform, arch, version, sha256, filename, mandatory,
             rollout_pct, uploaded_at, file_size)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("UpdateRegistry: upsert_package prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }

    sqlite3_bind_text(stmt, 1, pkg.platform.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, pkg.arch.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, pkg.version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, pkg.sha256.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, pkg.filename.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, pkg.mandatory ? 1 : 0);
    sqlite3_bind_int(stmt, 7, pkg.rollout_pct);
    sqlite3_bind_text(stmt, 8, pkg.uploaded_at.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 9, pkg.file_size);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        spdlog::error("UpdateRegistry: upsert_package step failed for {}/{}/{}: {}", pkg.platform,
                      pkg.arch, pkg.version, sqlite3_errmsg(db_));
    } else {
        spdlog::info("UpdateRegistry: upserted package {}/{}/{} ({})", pkg.platform, pkg.arch,
                     pkg.version, pkg.filename);
    }

    sqlite3_finalize(stmt);
}

void UpdateRegistry::remove_package(const std::string& platform, const std::string& arch,
                                    const std::string& version) {
    if (!db_)
        return;

    const char* sql = "DELETE FROM update_packages WHERE platform = ? AND arch = ? AND version = ?";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("UpdateRegistry: remove_package prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }

    sqlite3_bind_text(stmt, 1, platform.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, arch.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, version.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        spdlog::error("UpdateRegistry: remove_package step failed for {}/{}/{}: {}", platform, arch,
                      version, sqlite3_errmsg(db_));
    } else {
        spdlog::info("UpdateRegistry: removed package {}/{}/{}", platform, arch, version);
    }

    sqlite3_finalize(stmt);
}

std::vector<UpdatePackage> UpdateRegistry::list_packages() const {
    std::vector<UpdatePackage> packages;
    if (!db_)
        return packages;

    const char* sql = "SELECT platform, arch, version, sha256, filename, mandatory, "
                      "rollout_pct, uploaded_at, file_size "
                      "FROM update_packages ORDER BY platform, arch, uploaded_at DESC";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("UpdateRegistry: list_packages prepare failed: {}", sqlite3_errmsg(db_));
        return packages;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        UpdatePackage pkg;

        auto col_text = [&](int col) -> std::string {
            const char* val = reinterpret_cast<const char*>(sqlite3_column_text(stmt, col));
            return val ? val : "";
        };

        pkg.platform = col_text(0);
        pkg.arch = col_text(1);
        pkg.version = col_text(2);
        pkg.sha256 = col_text(3);
        pkg.filename = col_text(4);
        pkg.mandatory = sqlite3_column_int(stmt, 5) != 0;
        pkg.rollout_pct = sqlite3_column_int(stmt, 6);
        pkg.uploaded_at = col_text(7);
        pkg.file_size = sqlite3_column_int64(stmt, 8);

        packages.push_back(std::move(pkg));
    }

    sqlite3_finalize(stmt);
    return packages;
}

std::optional<UpdatePackage> UpdateRegistry::latest_for(const std::string& platform,
                                                        const std::string& arch) const {
    if (!db_)
        return std::nullopt;

    const char* sql = "SELECT platform, arch, version, sha256, filename, mandatory, "
                      "rollout_pct, uploaded_at, file_size "
                      "FROM update_packages WHERE platform = ? AND arch = ?";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("UpdateRegistry: latest_for prepare failed: {}", sqlite3_errmsg(db_));
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, platform.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, arch.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<UpdatePackage> best;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        UpdatePackage pkg;

        auto col_text = [&](int col) -> std::string {
            const char* val = reinterpret_cast<const char*>(sqlite3_column_text(stmt, col));
            return val ? val : "";
        };

        pkg.platform = col_text(0);
        pkg.arch = col_text(1);
        pkg.version = col_text(2);
        pkg.sha256 = col_text(3);
        pkg.filename = col_text(4);
        pkg.mandatory = sqlite3_column_int(stmt, 5) != 0;
        pkg.rollout_pct = sqlite3_column_int(stmt, 6);
        pkg.uploaded_at = col_text(7);
        pkg.file_size = sqlite3_column_int64(stmt, 8);

        if (!best.has_value() || compare_versions(pkg.version, best->version) > 0) {
            best = std::move(pkg);
        }
    }

    sqlite3_finalize(stmt);
    return best;
}

bool UpdateRegistry::is_eligible(const std::string& agent_id, int rollout_pct) {
    return rollout_pct >= 100 ||
           (std::hash<std::string>{}(agent_id) % 100) < static_cast<unsigned>(rollout_pct);
}

std::filesystem::path UpdateRegistry::binary_path(const UpdatePackage& pkg) const {
    return update_dir_ / pkg.filename;
}

} // namespace yuzu::server
