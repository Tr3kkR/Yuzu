#pragma once

/**
 * guard_file.hpp — Windows file-change Spark for Yuzu Guardian (Change B).
 *
 * Watches a target file in REAL TIME via ReadDirectoryChangesW on its parent
 * directory (kernel-notified, NO polling — unlike the Trigger Engine's mtime
 * poll). Resilient like RegistryGuard (C1/C2): the watch is live from arm until
 * the rule is disabled, survives the parent directory being deleted and
 * recreated (a nearest-existing-ancestor watch catches the recreation), and
 * reconciles the target's state from scratch on every wake.
 *
 * B1 implements the `file-exists` assertion: drift when the file's presence
 * (exists / absent) differs from the rule's expected state — i.e. realtime
 * detection of a file being deleted (or created). `file-hash-equals`
 * (content-change detection) is B2.
 *
 * Detection-only: a FileGuard never writes. File-content remediation (restore a
 * known-good copy) needs the Content Distribution subsystem and is deferred.
 *
 * Deliberately proto-free and windows.h-free (stop_event_ is a void* HANDLE).
 * On non-Windows the guard is a no-op (start() returns false) so the engine and
 * tests build everywhere; the watch is Windows-only for the MVP (Linux inotify /
 * macOS FSEvents are later platform work).
 */

#include <yuzu/plugin.h>          // YUZU_EXPORT
#include <yuzu/agent/guard.hpp>   // IGuard, GuardDrift, GuardSink

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

namespace yuzu::agent {

/// One file-existence watch. start() canonicalises the path, arms the parent-dir
/// watch on a dedicated thread, runs an initial compare, and reports drift via
/// the sink. Detection-only.
class YUZU_EXPORT FileGuard : public IGuard {
public:
    struct Config {
        std::string rule_id;
        std::string rule_name;
        std::string path;          ///< target file (canonicalised at start)
        bool expect_present{true}; ///< file-exists: desired presence (drift when actual != this)
        /// Event/sink debounce window (ms) — collapses rapid drift events into a
        /// count (shared convention with RegistryGuard). 0 = emit every drift.
        std::uint64_t event_debounce_ms{1000};
    };

    FileGuard(Config cfg, GuardSink sink);
    ~FileGuard() override;
    FileGuard(const FileGuard&) = delete;
    FileGuard& operator=(const FileGuard&) = delete;

    /// Canonicalise the path, arm the watch, run an initial compare, and start the
    /// watch thread. Returns false if the guard could not be started (empty path,
    /// or non-Windows build).
    bool start() override;
    void stop() override;

    const std::string& rule_id() const override { return cfg_.rule_id; }

private:
    void run();

    Config cfg_;
    GuardSink sink_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
    void* stop_event_{nullptr}; ///< HANDLE (void* keeps windows.h out of this header)
};

} // namespace yuzu::agent
