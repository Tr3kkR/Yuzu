#pragma once

/**
 * guard_registry.hpp — Windows Registry Spark for Yuzu Guardian (contract step 4).
 *
 * Watches a registry value via RegNotifyChangeKeyValue (pattern lifted from
 * trigger_engine.cpp's registry watch) and, on change, compares the live value
 * to the rule's expected value (`registry-value-equals`). On drift it reports a
 * RegistryDrift to its sink — the GuardianEngine turns that into a
 * GuaranteedStateEvent and ships it to the server.
 *
 * Deliberately proto-free: this keeps windows.h and protobuf out of the same
 * translation unit (windows.h's ERROR / min / max macros vs protobuf headers).
 * On non-Windows the class is a no-op (start() returns false) so the engine and
 * tests build everywhere; real enforcement is Windows-only for the MVP.
 */

#include <yuzu/plugin.h>  // YUZU_EXPORT

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace yuzu::agent {

/// What the guard observed when a watched value drifted from its expected state.
struct RegistryDrift {
    std::string rule_id;
    std::string rule_name;
    std::string detected_value;   ///< string-encoded live value, or "<absent>"
    std::string expected_value;   ///< string-encoded expected (registry-value-equals)
    std::uint64_t detection_latency_us{0};

    // Remediation (enforce mode only). When the guard is armed with
    // Config::enforce=true it writes `expected_value` back on drift, before
    // reporting, and records the outcome here. In audit mode all three stay at
    // their defaults (attempted=false) and the guard only observes.
    bool remediation_attempted{false};
    bool remediation_success{false};
    std::uint64_t remediation_latency_us{0};
    std::string remediation_action;   ///< "registry-write" when a write-back was attempted
};

/// One registry-value watch. start() opens the key, runs an initial compare, and
/// arms RegNotifyChangeKeyValue on a dedicated thread that re-reads + compares on
/// every change and re-arms. (The RegNotify re-arm gap is the reconciliation
/// guard's job — deferred to Slice A.2.)
class YUZU_EXPORT RegistryGuard {
public:
    struct Config {
        std::string rule_id;
        std::string rule_name;
        std::string hive;        ///< "HKLM" | "HKCU" | "HKCR" | "HKU"
        std::string key;         ///< subkey path, e.g. "SOFTWARE\\YuzuTest"
        std::string value_name;  ///< "" = the key's default value
        std::string value_type;  ///< "REG_DWORD" | "REG_SZ" | ... (load-bearing in enforce mode: selects the write-back encoding)
        std::string expected;    ///< string-encoded (G4): DWORD=decimal, SZ=literal
        bool enforce{false};     ///< true = write `expected` back on drift (registry-write remediation); false = observe/audit only
    };
    using Sink = std::function<void(const RegistryDrift&)>;

    RegistryGuard(Config cfg, Sink sink);
    ~RegistryGuard();
    RegistryGuard(const RegistryGuard&) = delete;
    RegistryGuard& operator=(const RegistryGuard&) = delete;

    /// Open the key, run an initial compare, arm the watch, and start the watch
    /// thread. Returns false if the guard could not be started (invalid hive, or
    /// non-Windows build).
    bool start();
    void stop();

    const std::string& rule_id() const { return cfg_.rule_id; }

private:
    void run();

    Config cfg_;
    Sink sink_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
    void* stop_event_{nullptr};  ///< HANDLE (void* keeps windows.h out of this header)
};

} // namespace yuzu::agent
