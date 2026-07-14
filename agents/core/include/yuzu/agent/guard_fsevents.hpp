#pragma once

/**
 * guard_fsevents.hpp — macOS FSEvents watch core for Yuzu Guardian.
 *
 * One multiplexed path-watch primitive: N FSEvents streams (one per watched
 * path, `kFSEventStreamCreateFlagFileEvents | NoDefer | WatchRoot`, latency 0)
 * delivering onto ONE private serial dispatch queue. Consumers register paths
 * by key and receive `FsWatchEvent`s naming the changed path; an event the
 * kernel could not attribute precisely (coalescing overflow, root
 * moved/deleted, mount churn) is flagged `must_reconcile` — the consumer must
 * re-read real state from disk rather than trust the event.
 *
 * FSEvents subscriptions are PATH-STRING based against the volume's global
 * event stream, so a stream keeps delivering after its watched directory is
 * deleted and recreated — the resilience the Windows FileGuard needs a
 * nearest-existing-ancestor watch for falls out of the API here.
 *
 * The surface (start(emit, fault) / watch / unwatch / stop) is deliberately
 * congruent with ISparkMechanism (spark_mechanism.hpp): when Spark Stage 2
 * rehomes Guardian detection onto mechanisms, this core becomes the darwin
 * file mechanism's engine with a thin adapter — do not let the two surfaces
 * drift apart.
 *
 * Threading contract:
 *  - `emit` runs on the core's private dispatch queue: keep it non-blocking
 *    (flip a flag, notify a CV) and NEVER call watch/unwatch/stop from inside
 *    it — teardown drains that queue and would deadlock.
 *  - watch/unwatch/stop are safe from any other thread; unwatch/stop return
 *    only after in-flight callbacks for the affected stream(s) have drained,
 *    so no callback touches a consumer after they return. unwatch of an
 *    unknown key and repeated stop() are no-ops.
 *
 * On non-macOS builds the class compiles as a stub (watch() reports
 * unsupported) so callers and tests build everywhere — the dex_macos
 * convention.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <expected>
#include <functional>
#include <memory>
#include <string>

namespace yuzu::agent {

/// One delivered filesystem event. `path` is the changed path as reported by
/// FSEvents (may be empty if unavailable); when `must_reconcile` is set the
/// change could not be attributed to a specific path — re-check state from
/// scratch instead of interpreting `path`.
struct FsWatchEvent {
    std::string key;  ///< the watch this event belongs to
    std::string path; ///< changed path (empty when unknown)
    bool must_reconcile{false};
};

using FsWatchEmitFn = std::function<void(const FsWatchEvent&)>;
/// Fault channel (key, description) — kept for ISparkMechanism congruence;
/// FSEvents has no asynchronous death signal today, so faults are rare
/// (internal errors only), but Stage-2 adapters rely on the seam existing.
using FsWatchFaultFn = std::function<void(const std::string&, const std::string&)>;

class YUZU_EXPORT FsEventsWatchCore {
public:
    FsEventsWatchCore();
    ~FsEventsWatchCore(); ///< calls stop()

    FsEventsWatchCore(const FsEventsWatchCore&) = delete;
    FsEventsWatchCore& operator=(const FsEventsWatchCore&) = delete;

    /// Create the delivery queue and retain the callbacks. Call exactly once,
    /// before any watch().
    void start(FsWatchEmitFn emit, FsWatchFaultFn fault);

    /// Begin watching one path under `key`. The path does not need to exist
    /// yet (FSEvents accepts not-yet-existing roots; WatchRoot reports the
    /// root's own creation/removal). Distinct watches need distinct keys — a
    /// duplicate key is an error. Returns an error string on setup failure or
    /// on a non-macOS build.
    [[nodiscard]] std::expected<void, std::string> watch(const std::string& key,
                                                         const std::string& path);

    /// Stop watching `key`. Unknown key → no-op. Returns only after in-flight
    /// callbacks for that stream have drained.
    void unwatch(const std::string& key);

    /// Tear down every stream and the delivery queue. Idempotent. Returns only
    /// after all in-flight callbacks have drained — no `emit` runs after this.
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace yuzu::agent
