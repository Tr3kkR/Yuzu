#pragma once

/**
 * guard_file.hpp — file-change Spark for Yuzu Guardian (Change B).
 *
 * Watches a target file in REAL TIME (kernel-notified, NO polling — unlike the
 * Trigger Engine's mtime poll): ReadDirectoryChangesW on the parent directory
 * on Windows, an FSEvents stream (guard_fsevents.hpp) on macOS. Resilient like
 * RegistryGuard (C1/C2) on both: the watch is live from arm until the rule is
 * disabled, survives the parent directory being deleted and recreated (Windows
 * re-arms via a nearest-existing-ancestor watch; FSEvents subscriptions are
 * path-string based and keep delivering across the recreation), and reconciles
 * the target's state from scratch on every wake.
 *
 * B1 implements the `file-exists` assertion: drift when the file's presence
 * (exists / absent) differs from the rule's expected state — i.e. realtime
 * detection of a file being deleted (or created). `file-hash-equals`
 * (content-change detection) is B2.
 *
 * Detection-only: a FileGuard never writes. File-content remediation (restore a
 * known-good copy) needs the Content Distribution subsystem and is deferred.
 *
 * Deliberately proto-free and OS-header-free (stop_event_ is an opaque void*:
 * a Windows event HANDLE / the macOS wake state). On Linux the guard is a
 * no-op (start() returns false) so the engine and tests build everywhere —
 * inotify is later platform work.
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
    /// Which desired-state check the guard evaluates on a change.
    enum class Assertion {
        Exists,    ///< file-exists (B1): presence vs expect_present
        HashEquals ///< file-hash-equals (B2): content (size + SHA-256) vs a baseline
    };

    struct Config {
        std::string rule_id;
        std::string rule_name;
        std::string path; ///< target file (canonicalised at start)
        Assertion assertion{Assertion::Exists};
        // file-exists:
        bool expect_present{true}; ///< desired presence (drift when actual != this)
        // file-hash-equals:
        std::string expected_hash;                       ///< lowercase hex SHA-256; empty = baseline-on-arm
        std::uint64_t max_hash_bytes{64ull * 1024 * 1024}; ///< hashing-DoS cap; over → "<oversize>" drift
        std::uint64_t settle_ms{750};                    ///< coalesce window before hashing (writes are not atomic)
        /// Upper bound on how long a continuous write storm may defer the hash. The
        /// settle window restarts on every notification, so without this cap a writer
        /// touching the file faster than settle_ms would starve the hash forever
        /// (drift invisible). Once this much has elapsed since the first un-hashed
        /// change, hash anyway. Default 5s.
        std::uint64_t max_settle_defer_ms{5000};
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
    /// or an unsupported-platform build — today that means Linux).
    bool start() override;
    void stop() override;

    const std::string& rule_id() const override { return cfg_.rule_id; }

private:
    void run();

    Config cfg_;
    GuardSink sink_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
    void* stop_event_{nullptr}; ///< Windows event HANDLE / macOS wake state (void* keeps OS headers out)
};

} // namespace yuzu::agent
