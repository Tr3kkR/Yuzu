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
#include <yuzu/agent/guard.hpp>                 // IGuard, GuardDrift, GuardSink
#include <yuzu/agent/resilience_strategy.hpp>  // ResilienceConfig (C3 retry policy)

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace yuzu::agent {

/// Registry drift report alias — the common GuardDrift, kept as a name for the
/// registry guard's call sites and tests. A registry guard leaves
/// `guard_type` at its "registry" default.
using RegistryDrift = GuardDrift;

/// One registry-value watch. start() opens the key, runs an initial compare, and
/// arms RegNotifyChangeKeyValue on a dedicated thread that re-reads + compares on
/// every change and re-arms (resilient, nearest-ancestor re-arm — C1/C2).
class YUZU_EXPORT RegistryGuard : public IGuard {
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
        /// C3: per-rule enforcement retry policy (Persist/Backoff/Bounded). Default
        /// Persist (immediate, never give up) = the pre-C3 behaviour, so existing
        /// rules are unchanged. Consulted in enforce mode only.
        ResilienceConfig resilience{};
        /// C3: event/sink debounce window (ms) — collapses rapid drift events into a
        /// count. 0 = emit every drift. Default 1000 (the prior hard-coded value).
        std::uint64_t event_debounce_ms{1000};
    };
    using Sink = GuardSink;

    RegistryGuard(Config cfg, Sink sink);
    ~RegistryGuard() override;
    RegistryGuard(const RegistryGuard&) = delete;
    RegistryGuard& operator=(const RegistryGuard&) = delete;

    /// Open the key, run an initial compare, arm the watch, and start the watch
    /// thread. Returns false if the guard could not be started (invalid hive, or
    /// non-Windows build).
    bool start() override;
    void stop() override;

    const std::string& rule_id() const override { return cfg_.rule_id; }

private:
    void run();

    Config cfg_;
    Sink sink_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
    void* stop_event_{nullptr};  ///< HANDLE (void* keeps windows.h out of this header)
};

} // namespace yuzu::agent
