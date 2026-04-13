#include "patch_manager.hpp"
#include "migration_runner.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <random>
#include <regex>
#include <shared_mutex>

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

std::string gen_id() {
    thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    auto hi = dist(rng);
    auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx",
                  static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

std::string deployment_status_to_string(DeploymentStatus s) {
    switch (s) {
    case DeploymentStatus::kPending:     return "pending";
    case DeploymentStatus::kScanning:    return "scanning";
    case DeploymentStatus::kDownloading: return "downloading";
    case DeploymentStatus::kInstalling:  return "installing";
    case DeploymentStatus::kVerifying:   return "verifying";
    case DeploymentStatus::kCompleted:   return "completed";
    case DeploymentStatus::kFailed:      return "failed";
    case DeploymentStatus::kCancelled:   return "cancelled";
    }
    return "unknown";
}

} // namespace

// ── Construction / teardown ──────────────────────────────────────────────────

PatchManager::PatchManager(const std::filesystem::path& db_path) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("PatchManager: failed to open {}: {}", db_path.string(),
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
        spdlog::info("PatchManager: opened {}", db_path.string());
}

PatchManager::~PatchManager() {
    if (db_)
        sqlite3_close(db_);
}

bool PatchManager::is_open() const {
    return db_ != nullptr;
}

// ── DDL ──────────────────────────────────────────────────────────────────────

void PatchManager::create_tables() {
    // Legacy compat: bring pre-v0.10 databases up to v1's schema before stamping.
    // v1's CREATE TABLE IF NOT EXISTS is a no-op on existing tables, so reboot
    // orchestration columns added historically must still be applied here.
    sqlite3_exec(db_,
        "ALTER TABLE patch_deployments ADD COLUMN reboot_delay_seconds INTEGER NOT NULL DEFAULT 300;",
        nullptr, nullptr, nullptr);
    sqlite3_exec(db_,
        "ALTER TABLE patch_deployments ADD COLUMN reboot_at INTEGER NOT NULL DEFAULT 0;",
        nullptr, nullptr, nullptr);

    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS patch_inventory (
                agent_id    TEXT NOT NULL,
                kb_id       TEXT NOT NULL,
                title       TEXT NOT NULL DEFAULT '',
                severity    TEXT NOT NULL DEFAULT 'Unspecified',
                status      TEXT NOT NULL DEFAULT 'missing',
                released_at INTEGER NOT NULL DEFAULT 0,
                scanned_at  INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (agent_id, kb_id)
            );

            CREATE TABLE IF NOT EXISTS patch_deployments (
                id                    TEXT PRIMARY KEY,
                kb_id                 TEXT NOT NULL,
                title                 TEXT NOT NULL DEFAULT '',
                status                TEXT NOT NULL DEFAULT 'pending',
                created_by            TEXT NOT NULL DEFAULT '',
                reboot_needed         INTEGER NOT NULL DEFAULT 0,
                reboot_delay_seconds  INTEGER NOT NULL DEFAULT 300,
                reboot_at             INTEGER NOT NULL DEFAULT 0,
                created_at            INTEGER NOT NULL DEFAULT 0,
                completed_at          INTEGER NOT NULL DEFAULT 0,
                total_targets         INTEGER NOT NULL DEFAULT 0,
                completed_targets     INTEGER NOT NULL DEFAULT 0,
                failed_targets        INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS patch_deployment_targets (
                deployment_id TEXT NOT NULL,
                agent_id      TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'pending',
                error         TEXT NOT NULL DEFAULT '',
                started_at    INTEGER NOT NULL DEFAULT 0,
                completed_at  INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (deployment_id, agent_id)
            );

            CREATE INDEX IF NOT EXISTS idx_patch_inv_kb ON patch_inventory(kb_id);
            CREATE INDEX IF NOT EXISTS idx_patch_inv_status ON patch_inventory(status);
            CREATE INDEX IF NOT EXISTS idx_patch_inv_agent ON patch_inventory(agent_id);
            CREATE INDEX IF NOT EXISTS idx_patch_depl_status ON patch_deployments(status);
            CREATE INDEX IF NOT EXISTS idx_patch_depl_targets ON patch_deployment_targets(deployment_id);
        )"},
    };
    if (!MigrationRunner::run(db_, "patch_manager", kMigrations)) {
        spdlog::error("PatchManager: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

std::string PatchManager::generate_id() const {
    return gen_id();
}

// ── Patch inventory ──────────────────────────────────────────────────────────

void PatchManager::record_patches(const std::string& agent_id,
                                  const std::vector<PatchInfo>& patches) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    auto now = now_epoch();

    const char* sql = R"(
        INSERT OR REPLACE INTO patch_inventory
            (agent_id, kb_id, title, severity, status, released_at, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_exec(db_, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        return;
    }

    for (const auto& p : patches) {
        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, p.kb_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, p.title.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, p.severity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, p.status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 6, p.released_at);
        sqlite3_bind_int64(stmt, 7, now);
        sqlite3_step(stmt);
    }

    sqlite3_finalize(stmt);
    sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, nullptr);

    spdlog::info("PatchManager: recorded {} patches for agent {}", patches.size(), agent_id);
}

std::vector<PatchInfo> PatchManager::query_patches(const PatchQuery& query,
                                                    const std::string& status_filter) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return {};

    // Build dynamic query
    std::string sql = R"(
        SELECT agent_id, kb_id, title, severity, status, released_at, scanned_at
        FROM patch_inventory WHERE 1=1
    )";

    if (!status_filter.empty())
        sql += " AND status = ?";
    if (!query.agent_id.empty())
        sql += " AND agent_id = ?";
    if (!query.severity.empty())
        sql += " AND severity = ?";

    sql += " ORDER BY scanned_at DESC LIMIT ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return {};

    int idx = 1;
    if (!status_filter.empty())
        sqlite3_bind_text(stmt, idx++, status_filter.c_str(), -1, SQLITE_TRANSIENT);
    if (!query.agent_id.empty())
        sqlite3_bind_text(stmt, idx++, query.agent_id.c_str(), -1, SQLITE_TRANSIENT);
    if (!query.severity.empty())
        sqlite3_bind_text(stmt, idx++, query.severity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, idx, query.limit);

    std::vector<PatchInfo> result;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        PatchInfo p;
        p.agent_id = col_text(stmt, 0);
        p.kb_id = col_text(stmt, 1);
        p.title = col_text(stmt, 2);
        p.severity = col_text(stmt, 3);
        p.status = col_text(stmt, 4);
        p.released_at = sqlite3_column_int64(stmt, 5);
        p.scanned_at = sqlite3_column_int64(stmt, 6);
        result.push_back(std::move(p));
    }

    sqlite3_finalize(stmt);
    return result;
}

std::vector<PatchInfo> PatchManager::get_missing_patches(const PatchQuery& query) const {
    auto q = query;
    return query_patches(q, "missing");
}

std::vector<PatchInfo> PatchManager::get_installed_patches(const PatchQuery& query) const {
    auto q = query;
    return query_patches(q, "installed");
}

std::vector<std::pair<std::string, int>> PatchManager::get_fleet_patch_summary(int limit) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return {};

    const char* sql = R"(
        SELECT kb_id, COUNT(DISTINCT agent_id) as agent_count
        FROM patch_inventory
        WHERE status = 'missing'
        GROUP BY kb_id
        ORDER BY agent_count DESC
        LIMIT ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return {};

    sqlite3_bind_int(stmt, 1, limit);

    std::vector<std::pair<std::string, int>> result;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        result.emplace_back(col_text(stmt, 0), sqlite3_column_int(stmt, 1));
    }

    sqlite3_finalize(stmt);
    return result;
}

// ── Deployment ───────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
PatchManager::deploy_patch(const std::string& kb_id,
                           const std::vector<std::string>& agent_ids,
                           bool reboot_if_needed,
                           const std::string& created_by,
                           int reboot_delay_seconds,
                           int64_t reboot_at) {
    return deploy_patch({kb_id, agent_ids, reboot_if_needed, created_by,
                         reboot_delay_seconds, reboot_at});
}

std::expected<std::string, std::string>
PatchManager::deploy_patch(const DeploymentRequest& req) {
    const auto& kb_id = req.kb_id;
    const auto& agent_ids = req.agent_ids;
    bool reboot_if_needed = req.reboot_if_needed;
    const auto& created_by = req.created_by;
    int reboot_delay_seconds = req.reboot_delay_seconds;
    int64_t reboot_at = req.reboot_at;

    if (kb_id.empty())
        return std::unexpected("kb_id is required");

    // KB IDs must be KBnnnnn format — reject anything else to prevent
    // PowerShell -match injection when the kb_id is interpolated into scripts
    std::regex kb_pattern("^KB\\d{4,10}$", std::regex::icase);
    if (!std::regex_match(kb_id, kb_pattern))
        return std::unexpected("invalid KB ID format (must be KBnnnnnnn)");

    if (agent_ids.empty())
        return std::unexpected("at least one agent_id is required");

    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("patch manager not available");

    auto id = generate_id();
    auto now = now_epoch();

    // Find title from inventory
    std::string title;
    {
        const char* sql = "SELECT title FROM patch_inventory WHERE kb_id = ? LIMIT 1";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, kb_id.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW)
                title = col_text(stmt, 0);
            sqlite3_finalize(stmt);
        }
    }

    // Create deployment record
    {
        const char* sql = R"(
            INSERT INTO patch_deployments
                (id, kb_id, title, status, created_by, reboot_needed,
                 reboot_delay_seconds, reboot_at, created_at, total_targets)
            VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)
        )";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return std::unexpected("failed to create deployment");

        // Clamp delay to [60, 86400]
        reboot_delay_seconds = std::clamp(reboot_delay_seconds, 60, 86400);

        sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, kb_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, title.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, created_by.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 5, reboot_if_needed ? 1 : 0);
        sqlite3_bind_int(stmt, 6, reboot_delay_seconds);
        sqlite3_bind_int64(stmt, 7, reboot_at);
        sqlite3_bind_int64(stmt, 8, now);
        sqlite3_bind_int(stmt, 9, static_cast<int>(agent_ids.size()));

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            return std::unexpected("failed to insert deployment");
        }
        sqlite3_finalize(stmt);
    }

    // Create target records
    {
        const char* sql = R"(
            INSERT INTO patch_deployment_targets (deployment_id, agent_id, status)
            VALUES (?, ?, 'pending')
        )";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return std::unexpected("failed to create target records");

        for (const auto& aid : agent_ids) {
            sqlite3_reset(stmt);
            sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, aid.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
        }
        sqlite3_finalize(stmt);
    }

    spdlog::info("PatchManager: created deployment {} for {} targeting {} agents",
                 id, kb_id, agent_ids.size());
    return id;
}

std::expected<void, std::string>
PatchManager::execute_deployment(const std::string& deployment_id,
                                 PatchDispatchFn dispatch_fn,
                                 AgentOsLookupFn os_lookup) {
    auto depl = get_deployment(deployment_id);
    if (!depl)
        return std::unexpected("deployment not found");

    if (depl->status == "completed" || depl->status == "cancelled")
        return std::unexpected("deployment already " + depl->status);

    if (!dispatch_fn)
        return std::unexpected("no dispatch function provided");

    // Defense-in-depth: validate kb_id format before constructing shell commands
    static const std::regex kb_re(R"(^KB\d{4,10}$)");
    if (!std::regex_match(depl->kb_id, kb_re)) {
        spdlog::error("PatchManager: deployment {} has invalid kb_id '{}'",
                       deployment_id, depl->kb_id);
        return std::unexpected("invalid kb_id format");
    }

    update_deployment_status(deployment_id, "scanning");

    // Workflow for each target:
    // Step 1: Scan for missing patches (windows_updates.missing)
    // Step 2: Install the patch (windows_updates.install or script_exec)
    // Step 3: Verify installation (windows_updates.installed)
    // Step 4: Reboot if needed (script_exec.run with reboot command)

    // TODO: Parallelize target dispatch (thread pool or std::async with
    // concurrency limit) before wiring to REST API. Sequential dispatch
    // does not scale beyond ~10 targets.
    for (const auto& target : depl->targets) {
        if (target.status == "completed" || target.status == "failed")
            continue;

        auto agent_id = target.agent_id;
        update_target_status(deployment_id, agent_id, "scanning");

        // Step 1: Check if patch is actually missing on this agent
        {
            nlohmann::json params = {{"kb_id", depl->kb_id}};
            auto result = dispatch_fn("device.windows_updates.missing",
                                      agent_id, params.dump());
            if (!result) {
                update_target_status(deployment_id, agent_id, "failed",
                                     "scan failed: " + result.error());
                continue;
            }

            // Parse scan result — check if the patch is listed as missing
            try {
                auto scan = nlohmann::json::parse(*result);
                bool found = false;
                if (scan.contains("rows") && scan["rows"].is_array()) {
                    for (const auto& row : scan["rows"]) {
                        auto title = row.value("title", "");
                        if (title.find(depl->kb_id) != std::string::npos) {
                            found = true;
                            break;
                        }
                    }
                }
                if (!found) {
                    // Patch is already installed or not applicable
                    update_target_status(deployment_id, agent_id, "completed");
                    spdlog::info("PatchManager: {} already has {} or not applicable",
                                 agent_id, depl->kb_id);
                    continue;
                }
            } catch (const std::exception&) {
                // If we can't parse, continue with installation anyway
            }
        }

        // Step 2: Install the patch
        update_target_status(deployment_id, agent_id, "installing");
        {
            nlohmann::json params = {
                {"kb_id", depl->kb_id},
                {"reboot", depl->reboot_if_needed}
            };

            // Use script_exec to run installation — select script by agent OS at
            // runtime (not server compile-time) so a Linux server can deploy
            // Windows patches to Windows agents.
            std::string agent_os = os_lookup ? os_lookup(agent_id) : "";
            nlohmann::json exec_params;
            if (agent_os == "windows") {
                std::string install_script =
                    "$criteria = 'IsInstalled=0 and Type=\\'Software\\'';"
                    "$searcher = (New-Object -ComObject Microsoft.Update.Searcher);"
                    "$results = $searcher.Search($criteria);"
                    "foreach ($update in $results.Updates) {"
                    "  if ($update.Title -match '" + depl->kb_id + "') {"
                    "    $collection = New-Object -ComObject Microsoft.Update.UpdateColl;"
                    "    $collection.Add($update);"
                    "    $installer = New-Object -ComObject Microsoft.Update.Installer;"
                    "    $installer.Updates = $collection;"
                    "    $result = $installer.Install();"
                    "    Write-Output \"Install result: $($result.ResultCode)\";"
                    "  }"
                    "}";
                exec_params = {
                    {"command", "powershell"},
                    {"args", "-NoProfile -ExecutionPolicy Bypass -Command \"" + install_script + "\""},
                    {"timeout", "600"}
                };
            } else {
                exec_params = {
                    {"command", "echo"},
                    {"args", "Windows Update installation not supported on this platform"},
                    {"timeout", "30"}
                };
            }

            auto result = dispatch_fn("device.script_exec.run",
                                      agent_id, exec_params.dump());
            if (!result) {
                update_target_status(deployment_id, agent_id, "failed",
                                     "install failed: " + result.error());
                continue;
            }
        }

        // Step 3: Verify installation
        update_target_status(deployment_id, agent_id, "verifying");
        {
            nlohmann::json params = {};
            auto result = dispatch_fn("device.windows_updates.installed",
                                      agent_id, params.dump());
            if (!result) {
                update_target_status(deployment_id, agent_id, "failed",
                                     "verification failed: " + result.error());
                continue;
            }

            // Check if the KB now appears in installed updates
            try {
                auto verify = nlohmann::json::parse(*result);
                bool found = false;
                if (verify.contains("rows") && verify["rows"].is_array()) {
                    for (const auto& row : verify["rows"]) {
                        auto identifier = row.value("identifier", "");
                        if (identifier.find(depl->kb_id) != std::string::npos) {
                            found = true;
                            break;
                        }
                    }
                }
                if (!found) {
                    update_target_status(deployment_id, agent_id, "failed",
                                         "patch not found after installation");
                    continue;
                }
            } catch (const std::exception&) {
                // Verification parse failure — mark as potentially successful
            }
        }

        // Step 4: Reboot orchestration — notify user, then cross-platform reboot
        if (depl->reboot_if_needed) {
            // Compute effective delay — clamp int64_t BEFORE static_cast<int>
            // to prevent overflow when reboot_at is far in the future.
            int delay_seconds = depl->reboot_delay_seconds;
            if (depl->reboot_at > 0) {
                auto now_ts = now_epoch();
                if (depl->reboot_at > now_ts) {
                    int64_t diff = depl->reboot_at - now_ts;
                    delay_seconds = static_cast<int>(
                        std::clamp(diff, int64_t{60}, int64_t{86400}));
                }
            }
            delay_seconds = std::clamp(delay_seconds, 60, 86400);

            update_target_status(deployment_id, agent_id, "rebooting");

            // 4a: Notify user (best-effort)
            int delay_minutes = delay_seconds / 60;
            if (delay_minutes < 1) delay_minutes = 1;
            nlohmann::json notify_params = {
                {"title", "System Reboot"},
                {"message", "Your computer will restart in " +
                            std::to_string(delay_minutes) +
                            " minutes for security updates (" +
                            depl->kb_id + ")."},
                {"type", "warning"}
            };
            auto notify_result = dispatch_fn("device.interaction.notify",
                                             agent_id, notify_params.dump());
            if (!notify_result) {
                spdlog::info("PatchManager: notification failed for {} (headless?): {}",
                             agent_id, notify_result.error());
            }
            // Audit: reboot notification dispatched
            // TODO: Wire AuditStore when execute_deployment is connected to routes
            spdlog::info("PatchManager: audit: deployment={} agent={} action=reboot.notify delay={}s notify_ok={}",
                         deployment_id, agent_id, delay_seconds, notify_result.has_value());

            // 4b: Cross-platform reboot command
            std::string os = os_lookup ? os_lookup(agent_id) : "";
            if (os.empty()) {
                spdlog::warn("PatchManager: os_lookup not provided for {}, skipping reboot", agent_id);
                update_target_status(deployment_id, agent_id, "completed",
                                     "reboot skipped: unknown OS");
                continue; // Skip reboot dispatch — target already marked completed
            }
            nlohmann::json reboot_params;
            if (os == "linux" || os == "darwin") {
                int delay_minutes_cmd = std::max(1, delay_seconds / 60);
                reboot_params = {
                    {"command", "shutdown"},
                    {"args", "-r +" + std::to_string(delay_minutes_cmd) +
                             " \"Yuzu: rebooting after " + depl->kb_id + "\""},
                    {"timeout", "30"}
                };
            } else if (os == "windows") {
                reboot_params = {
                    {"command", "shutdown"},
                    {"args", "/r /t " + std::to_string(delay_seconds) +
                             " /c \"Yuzu patch deployment: rebooting after " +
                             depl->kb_id + "\""},
                    {"timeout", "30"}
                };
            }
            // Only dispatch if we have a valid OS-specific command
            if (!reboot_params.empty()) {
                auto result = dispatch_fn("device.script_exec.run",
                                          agent_id, reboot_params.dump());
                spdlog::info("PatchManager: audit: deployment={} agent={} action=reboot.command os={} delay={}s success={}",
                             deployment_id, agent_id, os, delay_seconds, result.has_value());
                if (!result) {
                    spdlog::warn("PatchManager: reboot command failed for {}: {}",
                                 agent_id, result.error());
                    // Don't mark as failed — patch was installed successfully
                }
            }
        }

        update_target_status(deployment_id, agent_id, "completed");
    }

    // Recalculate overall deployment status
    recalculate_deployment_progress(deployment_id);
    return {};
}

std::optional<PatchDeployment> PatchManager::get_deployment(const std::string& id) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return std::nullopt;

    const char* sql = R"(
        SELECT id, kb_id, title, status, created_by, reboot_needed,
               created_at, completed_at, total_targets, completed_targets, failed_targets,
               reboot_delay_seconds, reboot_at
        FROM patch_deployments WHERE id = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    PatchDeployment d;
    d.id = col_text(stmt, 0);
    d.kb_id = col_text(stmt, 1);
    d.title = col_text(stmt, 2);
    d.status = col_text(stmt, 3);
    d.created_by = col_text(stmt, 4);
    d.reboot_if_needed = sqlite3_column_int(stmt, 5) != 0;
    d.created_at = sqlite3_column_int64(stmt, 6);
    d.completed_at = sqlite3_column_int64(stmt, 7);
    d.total_targets = sqlite3_column_int(stmt, 8);
    d.completed_targets = sqlite3_column_int(stmt, 9);
    d.failed_targets = sqlite3_column_int(stmt, 10);
    d.reboot_delay_seconds = sqlite3_column_int(stmt, 11);
    d.reboot_at = sqlite3_column_int64(stmt, 12);
    sqlite3_finalize(stmt);

    // Load targets
    const char* tsql = R"(
        SELECT agent_id, status, error, started_at, completed_at
        FROM patch_deployment_targets WHERE deployment_id = ?
    )";

    sqlite3_stmt* tstmt = nullptr;
    if (sqlite3_prepare_v2(db_, tsql, -1, &tstmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(tstmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(tstmt) == SQLITE_ROW) {
            PatchDeploymentTarget t;
            t.agent_id = col_text(tstmt, 0);
            t.status = col_text(tstmt, 1);
            t.error = col_text(tstmt, 2);
            t.started_at = sqlite3_column_int64(tstmt, 3);
            t.completed_at = sqlite3_column_int64(tstmt, 4);
            d.targets.push_back(std::move(t));
        }
        sqlite3_finalize(tstmt);
    }

    return d;
}

std::vector<PatchDeployment> PatchManager::list_deployments(int limit) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return {};

    const char* sql = R"(
        SELECT id, kb_id, title, status, created_by, reboot_needed,
               created_at, completed_at, total_targets, completed_targets, failed_targets,
               reboot_delay_seconds, reboot_at
        FROM patch_deployments
        ORDER BY created_at DESC
        LIMIT ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return {};

    sqlite3_bind_int(stmt, 1, limit);

    std::vector<PatchDeployment> result;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        PatchDeployment d;
        d.id = col_text(stmt, 0);
        d.kb_id = col_text(stmt, 1);
        d.title = col_text(stmt, 2);
        d.status = col_text(stmt, 3);
        d.created_by = col_text(stmt, 4);
        d.reboot_if_needed = sqlite3_column_int(stmt, 5) != 0;
        d.created_at = sqlite3_column_int64(stmt, 6);
        d.completed_at = sqlite3_column_int64(stmt, 7);
        d.total_targets = sqlite3_column_int(stmt, 8);
        d.completed_targets = sqlite3_column_int(stmt, 9);
        d.failed_targets = sqlite3_column_int(stmt, 10);
        d.reboot_delay_seconds = sqlite3_column_int(stmt, 11);
        d.reboot_at = sqlite3_column_int64(stmt, 12);
        result.push_back(std::move(d));
    }

    sqlite3_finalize(stmt);
    return result;
}

std::expected<void, std::string>
PatchManager::cancel_deployment(const std::string& id) {
    auto depl = get_deployment(id);
    if (!depl)
        return std::unexpected("deployment not found");

    if (depl->status == "completed" || depl->status == "cancelled")
        return std::unexpected("deployment already " + depl->status);

    update_deployment_status(id, "cancelled");

    // Mark all pending targets as cancelled
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not available");

    const char* sql = R"(
        UPDATE patch_deployment_targets
        SET status = 'cancelled', completed_at = ?
        WHERE deployment_id = ? AND status IN ('pending', 'scanning', 'downloading', 'installing', 'verifying', 'rebooting')
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected("failed to cancel targets");

    sqlite3_bind_int64(stmt, 1, now_epoch());
    sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    spdlog::info("PatchManager: cancelled deployment {}", id);
    return {};
}

void PatchManager::update_target_status(const std::string& deployment_id,
                                        const std::string& agent_id,
                                        const std::string& status,
                                        const std::string& error) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    auto now = now_epoch();

    const char* sql = R"(
        UPDATE patch_deployment_targets
        SET status = ?, error = ?, started_at = CASE WHEN started_at = 0 THEN ? ELSE started_at END,
            completed_at = CASE WHEN ? IN ('completed', 'failed', 'cancelled') THEN ? ELSE completed_at END
        WHERE deployment_id = ? AND agent_id = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, error.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, now);
    sqlite3_bind_text(stmt, 4, status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, now);
    sqlite3_bind_text(stmt, 6, deployment_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, agent_id.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ── Internal helpers ─────────────────────────────────────────────────────────

void PatchManager::update_deployment_status(const std::string& id,
                                            const std::string& status) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    auto now = now_epoch();
    bool is_terminal = (status == "completed" || status == "failed" || status == "cancelled");

    const char* sql = is_terminal
        ? "UPDATE patch_deployments SET status = ?, completed_at = ? WHERE id = ?"
        : "UPDATE patch_deployments SET status = ? WHERE id = ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_TRANSIENT);
    if (is_terminal) {
        sqlite3_bind_int64(stmt, 2, now);
        sqlite3_bind_text(stmt, 3, id.c_str(), -1, SQLITE_TRANSIENT);
    } else {
        sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    }

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void PatchManager::recalculate_deployment_progress(const std::string& id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    // Count completed and failed targets
    const char* sql = R"(
        SELECT
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
            COUNT(*) as total
        FROM patch_deployment_targets
        WHERE deployment_id = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int completed = sqlite3_column_int(stmt, 0);
        int failed = sqlite3_column_int(stmt, 1);
        int total = sqlite3_column_int(stmt, 2);
        sqlite3_finalize(stmt);

        // Update deployment counters
        const char* update_sql = R"(
            UPDATE patch_deployments
            SET completed_targets = ?, failed_targets = ?, total_targets = ?,
                status = CASE
                    WHEN ? + ? = ? THEN CASE WHEN ? > 0 THEN 'failed' ELSE 'completed' END
                    ELSE status
                END,
                completed_at = CASE WHEN ? + ? = ? THEN ? ELSE completed_at END
            WHERE id = ?
        )";

        sqlite3_stmt* ustmt = nullptr;
        if (sqlite3_prepare_v2(db_, update_sql, -1, &ustmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(ustmt, 1, completed);
            sqlite3_bind_int(ustmt, 2, failed);
            sqlite3_bind_int(ustmt, 3, total);
            sqlite3_bind_int(ustmt, 4, completed);
            sqlite3_bind_int(ustmt, 5, failed);
            sqlite3_bind_int(ustmt, 6, total);
            sqlite3_bind_int(ustmt, 7, failed);
            sqlite3_bind_int(ustmt, 8, completed);
            sqlite3_bind_int(ustmt, 9, failed);
            sqlite3_bind_int(ustmt, 10, total);
            sqlite3_bind_int64(ustmt, 11, now_epoch());
            sqlite3_bind_text(ustmt, 12, id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(ustmt);
            sqlite3_finalize(ustmt);
        }
    } else {
        sqlite3_finalize(stmt);
    }
}

} // namespace yuzu::server
