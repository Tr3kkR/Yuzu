#pragma once

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <atomic>
#include <chrono>
#include <expected>
#include <filesystem>
#include <string>

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
    Updater(UpdateConfig config, std::string agent_id, std::string current_version, std::string os,
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
    // In-flight OTA RPC context (a grpc::ClientContext*, held as void* so this
    // public header stays free of the proto/grpc include — same reason the stub
    // is passed as void*). Published by check_and_apply() around the blocking
    // CheckForUpdate / DownloadUpdate calls and TryCancel'd by stop(), so a
    // shutdown during a stalled OTA RPC unblocks the call rather than hanging
    // the update-thread join (#1434 UP-1). Mirrors AgentImpl::heartbeat_ctx_.
    std::atomic<void*> active_rpc_ctx_{nullptr};

#ifndef _WIN32
    /// POSIX-only binary replacement with rollback on failure.
    ///
    /// On Windows the apply is performed inline in check_and_apply via
    /// SetFileInformationByHandle on the held HANDLE (see W2.3 cross-
    /// platform-debt closure). A path-based fallback on Windows would
    /// re-introduce the close-then-rename race window — keep this
    /// declaration compile-time-absent on Windows.
    [[nodiscard]] std::expected<bool, UpdateError>
    apply_update(const std::filesystem::path& temp_path);
#endif
};

/// Get the path to the currently running executable (cross-platform).
YUZU_EXPORT std::filesystem::path current_executable_path();

} // namespace yuzu::agent
