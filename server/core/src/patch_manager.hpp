#pragma once

#include <sqlite3.h>

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu::server {

// ── Data types ───────────────────────────────────────────────────────────────

struct PatchInfo {
    std::string kb_id;      // KB identifier (e.g., "KB5034441") or package name
    std::string title;      // Human-readable title
    std::string severity;   // "Critical", "Important", "Moderate", "Low", "Unspecified"
    std::string status;     // "missing", "installed", "pending", "failed"
    std::string agent_id;   // Agent that reported this patch
    int64_t released_at{0}; // Release timestamp (epoch seconds)
    int64_t scanned_at{0};  // When the agent last scanned
};

enum class DeploymentStatus {
    kPending,    // Deployment created, not yet started
    kScanning,   // Checking if patch is missing on targets
    kDownloading,// Downloading patch content
    kInstalling, // Installing patch on targets
    kVerifying,  // Verifying successful installation
    kCompleted,  // All targets patched successfully
    kFailed,     // One or more targets failed
    kCancelled   // Deployment cancelled by operator
};

struct PatchDeploymentTarget {
    std::string agent_id;
    std::string status;    // "pending", "scanning", "downloading", "installing",
                           // "verifying", "completed", "failed", "skipped"
    std::string error;     // Error message if failed
    int64_t started_at{0};
    int64_t completed_at{0};
};

struct PatchDeployment {
    std::string id;
    std::string kb_id;
    std::string title;
    std::string status;     // Overall status
    std::string created_by; // Principal who initiated the deployment
    bool reboot_if_needed{false};
    int64_t created_at{0};
    int64_t completed_at{0};
    int total_targets{0};
    int completed_targets{0};
    int failed_targets{0};

    // Populated by get_deployment()
    std::vector<PatchDeploymentTarget> targets;
};

struct PatchQuery {
    std::string agent_id;    // Filter by agent
    std::string severity;    // Filter by severity
    std::string status;      // Filter by status ("missing", "installed")
    int limit{100};
};

// ── Dispatch callback types ─────────────────────────────────────────────────
// The patch manager invokes these callbacks to dispatch instructions to agents.
// Returns a JSON result string on success, or an error string on failure.

using PatchDispatchFn = std::function<std::expected<std::string, std::string>(
    const std::string& instruction_id,
    const std::string& agent_id,
    const std::string& parameters_json)>;

// ── PatchManager ─────────────────────────────────────────────────────────────

class PatchManager {
public:
    explicit PatchManager(const std::filesystem::path& db_path);
    ~PatchManager();

    PatchManager(const PatchManager&) = delete;
    PatchManager& operator=(const PatchManager&) = delete;

    bool is_open() const;

    // ── Patch inventory ─────────────────────────────────────────────────

    /// Record patches reported by an agent (called when scan results come in).
    void record_patches(const std::string& agent_id,
                        const std::vector<PatchInfo>& patches);

    /// Query missing patches, optionally filtered by agent/severity.
    std::vector<PatchInfo> get_missing_patches(const PatchQuery& query = {}) const;

    /// Query installed patches, optionally filtered.
    std::vector<PatchInfo> get_installed_patches(const PatchQuery& query = {}) const;

    /// Get a fleet-wide summary: how many agents are missing each patch.
    std::vector<std::pair<std::string, int>> get_fleet_patch_summary(int limit = 50) const;

    // ── Deployment ──────────────────────────────────────────────────────

    /// Create a new patch deployment targeting specific agents.
    /// The deployment orchestrates: scan -> download -> install -> verify -> reboot.
    std::expected<std::string, std::string>
    deploy_patch(const std::string& kb_id,
                 const std::vector<std::string>& agent_ids,
                 bool reboot_if_needed,
                 const std::string& created_by);

    /// Execute the deployment workflow using the provided dispatch callback.
    /// This runs through the steps: check -> install -> verify for each target.
    std::expected<void, std::string>
    execute_deployment(const std::string& deployment_id,
                       PatchDispatchFn dispatch_fn);

    /// Get deployment details including per-target status.
    std::optional<PatchDeployment> get_deployment(const std::string& id) const;

    /// List recent deployments.
    std::vector<PatchDeployment> list_deployments(int limit = 50) const;

    /// Cancel a pending/running deployment.
    std::expected<void, std::string> cancel_deployment(const std::string& id);

    /// Update a target's status within a deployment (called as results come in).
    void update_target_status(const std::string& deployment_id,
                              const std::string& agent_id,
                              const std::string& status,
                              const std::string& error = {});

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;

    void create_tables();
    std::string generate_id() const;

    // Internal helpers
    void update_deployment_status(const std::string& id, const std::string& status);
    void recalculate_deployment_progress(const std::string& id);
    std::vector<PatchInfo> query_patches(const PatchQuery& query,
                                          const std::string& status_filter) const;
};

} // namespace yuzu::server
