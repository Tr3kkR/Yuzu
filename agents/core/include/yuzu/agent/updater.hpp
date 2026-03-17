#pragma once

#include <yuzu/plugin.h>  // YUZU_EXPORT

#include <atomic>
#include <chrono>
#include <expected>
#include <filesystem>
#include <string>

namespace yuzu::agent {

struct UpdateError { std::string message; };

struct UpdateConfig {
    bool enabled{true};
    std::chrono::seconds check_interval{6 * 3600};  // 6 hours
};

class YUZU_EXPORT Updater {
public:
    Updater(UpdateConfig config, std::string agent_id,
            std::string current_version, std::string os,
            std::string arch, std::filesystem::path exe_path);
    ~Updater() = default;

    Updater(const Updater&) = delete;
    Updater& operator=(const Updater&) = delete;
    Updater(Updater&&) = delete;
    Updater& operator=(Updater&&) = delete;

    /// Check for update via gRPC stub, download, verify, apply.
    /// Returns true if update applied and process should restart.
    /// The stub parameter is AgentService::Stub* (void* to avoid proto header in public header).
    [[nodiscard]] std::expected<bool, UpdateError> check_and_apply(void* stub);

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

    /// Platform-specific binary replacement with rollback on failure.
    [[nodiscard]] std::expected<bool, UpdateError>
    apply_update(const std::filesystem::path& temp_path);
};

/// Get the path to the currently running executable (cross-platform).
YUZU_EXPORT std::filesystem::path current_executable_path();

}  // namespace yuzu::agent
