#pragma once

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <atomic>
#include <chrono>
#include <expected>
#include <filesystem>
#include <string>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::agent {

struct UpdateError {
    std::string message;
};

struct UpdateConfig {
    bool enabled{true};
    std::chrono::seconds check_interval{6 * 3600}; // 6 hours
};

class YUZU_EXPORT Updater {
public:
    /// `metrics` is an optional pointer to the agent's MetricsRegistry so
    /// the updater can emit `yuzu_agent_ota_chunk_deadline_total{phase=...}`
    /// counters on per-frame write/read deadline expiry (#911 / SRE-2 /
    /// #924). Pass nullptr to disable; the counters are otherwise
    /// no-ops. Lifetime: the registry MUST outlive the Updater.
    Updater(UpdateConfig config, std::string agent_id, std::string current_version, std::string os,
            std::string arch, std::filesystem::path exe_path,
            ::yuzu::MetricsRegistry* metrics = nullptr);
    ~Updater() = default;

    Updater(const Updater&) = delete;
    Updater& operator=(const Updater&) = delete;
    Updater(Updater&&) = delete;
    Updater& operator=(Updater&&) = delete;

    /// Check for update (CheckForUpdate unary), download (DownloadUpdate
    /// server-streaming-via-bidi), verify, apply. Both RPCs travel via
    /// `yuzu::transport::Channel` after the #376 PR 1c-4 lift.
    /// Returns true if update applied and process should restart.
    /// The `channel` parameter is `yuzu::transport::Channel*`, typed as
    /// void* to keep transport headers out of this public surface.
    [[nodiscard]] std::expected<bool, UpdateError> check_and_apply(void* channel);

    /// On startup: delete .old files from successful prior updates.
    void cleanup_old_binary();

    /// On startup: if .old exists and current binary seems broken, roll back.
    [[nodiscard]] bool rollback_if_needed();

    void stop() noexcept;

private:
    UpdateConfig config_;
    std::string agent_id_;
    std::string current_version_;
    std::string os_;
    std::string arch_;
    std::filesystem::path exe_path_;
    std::atomic<bool> stop_requested_{false};
    ::yuzu::MetricsRegistry* metrics_ = nullptr;

    /// Platform-specific binary replacement with rollback on failure.
    [[nodiscard]] std::expected<bool, UpdateError>
    apply_update(const std::filesystem::path& temp_path);
};

/// Get the path to the currently running executable (cross-platform).
YUZU_EXPORT std::filesystem::path current_executable_path();

} // namespace yuzu::agent
