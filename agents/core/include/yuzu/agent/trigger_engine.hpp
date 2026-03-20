#pragma once

#include <yuzu/plugin.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace yuzu::agent {

// ── Trigger types ────────────────────────────────────────────────────────────

enum class TriggerType {
    Interval,       // Fires on a time interval (e.g., every 300 seconds)
    FileChange,     // Fires when a file/directory mtime changes
    ServiceStatus,  // Fires when a service state matches expected_status
    AgentStartup,   // Fires once when the agent starts
    RegistryChange  // Fires when a Windows registry key changes (Windows-only)
};

/// Convert a TriggerType to its string representation.
[[nodiscard]] constexpr const char* trigger_type_to_string(TriggerType t) noexcept {
    switch (t) {
    case TriggerType::Interval:
        return "interval";
    case TriggerType::FileChange:
        return "filesystem";
    case TriggerType::ServiceStatus:
        return "service";
    case TriggerType::AgentStartup:
        return "agent-startup";
    case TriggerType::RegistryChange:
        return "registry";
    }
    return "unknown";
}

/// Parse a string to TriggerType. Returns Interval as the default if unknown.
[[nodiscard]] inline TriggerType trigger_type_from_string(std::string_view s) noexcept {
    if (s == "interval")
        return TriggerType::Interval;
    if (s == "filesystem" || s == "file_change")
        return TriggerType::FileChange;
    if (s == "service" || s == "service_status")
        return TriggerType::ServiceStatus;
    if (s == "agent-startup" || s == "agent_startup" || s == "startup")
        return TriggerType::AgentStartup;
    if (s == "registry" || s == "registry_change")
        return TriggerType::RegistryChange;
    return TriggerType::Interval;
}

// ── Trigger configuration ────────────────────────────────────────────────────

struct TriggerConfig {
    std::string id;    // unique trigger ID
    TriggerType type;
    std::string plugin;  // plugin to invoke when triggered
    std::string action;  // action to invoke when triggered
    std::map<std::string, std::string> parameters; // params passed to the plugin

    // Type-specific configuration
    int interval_seconds = 0;     // for Interval triggers (minimum 30)
    std::string watch_path;       // for FileChange triggers (file or directory)
    std::string service_name;     // for ServiceStatus triggers
    std::string expected_status;  // for ServiceStatus triggers (e.g. "stopped", "running")
    std::string registry_hive;    // for RegistryChange triggers (e.g. "HKLM", "HKCU")
    std::string registry_key;     // for RegistryChange triggers (key path to watch)

    // Debounce
    int debounce_seconds = 0; // suppress re-fires within this window (0 = no debounce)
};

// ── Trigger engine ───────────────────────────────────────────────────────────

/**
 * TriggerEngine evaluates registered triggers and dispatches plugin actions
 * when conditions are met. It runs background worker threads for each trigger
 * type (interval, file watch, service watch) and fires startup triggers
 * immediately on start().
 *
 * Thread safety: register/unregister are safe to call from any thread while
 * the engine is running. The dispatch callback is invoked from worker threads.
 */
class YUZU_EXPORT TriggerEngine {
public:
    /// Callback type for dispatching triggered actions.
    using DispatchFn = std::function<void(const std::string& plugin,
                                          const std::string& action,
                                          const std::map<std::string, std::string>& params)>;

    TriggerEngine();
    ~TriggerEngine();

    TriggerEngine(const TriggerEngine&) = delete;
    TriggerEngine& operator=(const TriggerEngine&) = delete;

    /// Register a trigger. Safe to call while running.
    void register_trigger(TriggerConfig config);

    /// Unregister a trigger by ID. Safe to call while running.
    void unregister_trigger(const std::string& id);

    /// Set the callback invoked when a trigger fires.
    void set_dispatch(DispatchFn fn);

    /// Start all monitoring loops. Fires AgentStartup triggers immediately.
    void start();

    /// Stop all monitoring loops and join worker threads.
    void stop();

    /// Returns the number of registered triggers.
    [[nodiscard]] size_t trigger_count() const;

    /// Returns true if the engine is currently running.
    [[nodiscard]] bool is_running() const noexcept;

    /// Validate service name (alphanumeric + ._@- only, blocks shell metacharacters).
    /// Public so callers can validate before creating triggers.
    [[nodiscard]] static bool is_valid_service_name(const std::string& name);

private:
    // Worker loops for each trigger type
    void interval_loop();
    void file_watch_loop();
    void service_watch_loop();
    void registry_watch_loop();
    void fire_startup_triggers();

    // Dispatch helper (applies debounce and calls dispatch_)
    void fire_trigger(const TriggerConfig& trigger);

    // Query service status (platform-specific)
    static std::string query_service_status(const std::string& service_name);

    // State
    std::vector<TriggerConfig> triggers_;
    mutable std::mutex mu_;
    std::atomic<bool> running_{false};
    std::vector<std::thread> workers_;
    DispatchFn dispatch_;

    // File watch state: trigger_id -> last known mtime
    std::map<std::string, std::filesystem::file_time_type> file_mtimes_;
    std::mutex file_mu_;

    // Service watch state: trigger_id -> last known status
    std::map<std::string, std::string> service_states_;
    std::mutex service_mu_;

    // Debounce state: trigger_id -> last fire time
    std::map<std::string, std::chrono::steady_clock::time_point> last_fire_times_;
    std::mutex debounce_mu_;
};

} // namespace yuzu::agent
