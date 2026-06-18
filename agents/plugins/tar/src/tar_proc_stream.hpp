#pragma once

/**
 * tar_proc_stream.hpp — platform-agnostic process-stream primitives.
 *
 * The `ProcEvent` value type and the `ProcEventRing` producer/consumer bridge are
 * shared by every gap-free process collector: the Windows ETW collector
 * (`tar_proc_etw.hpp`) and the macOS Endpoint Security collector
 * (`tar_proc_es.hpp`). Both feed the same TAR `process_live` schema, so the event
 * shape and the backpressure idiom live here, once, with no platform headers.
 *
 * Keeping these out of the per-platform collector headers lets the macOS build
 * include them without dragging in ETW/TDH vocabulary (and vice versa), and lets
 * the ring's unit tests target one header regardless of host.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace yuzu::tar {

/// One process lifecycle event decoded from a streaming source. Fields mirror the
/// TAR `process_live` schema (ts/action/pid/ppid/name/user) plus exit_code — which
/// a streaming source carries on the stop event and a poll never can.
///
/// `image_name` is the executable basename only; the full command line is NOT
/// captured by default (usage-class / works-council posture — the A2
/// names-only-never-cmdlines precedent).
///
/// `sid` is the Windows raw SID captured in the ETW callback and resolved to
/// `user` at drain time (so the costly LookupAccountSid stays off the consumer
/// thread). It is empty on platforms that resolve the owning user directly (the
/// macOS Endpoint Security collector fills `user` from the audit token's uid at
/// drain and leaves `sid` empty).
struct ProcEvent {
    std::int64_t ts_unix{0};   ///< event time, unix seconds
    bool is_start{true};       ///< true = start (exec); false = stop (exit)
    std::uint32_t pid{0};
    std::uint32_t ppid{0};     ///< parent pid (start only; 0 on stop)
    std::string image_name;    ///< executable basename, never the full command line
    std::string sid;           ///< Windows raw SID (start: live process; stop: pid→sid cache);
                               ///< empty off-Windows. Resolved to `user` at drain time.
    std::string user;          ///< DOMAIN\\account (Windows) or username (POSIX), "" if unresolved
    std::uint32_t uid{0};      ///< POSIX real uid, carried from the ES handler so the costly
                               ///< getpwuid_r resolution happens at DRAIN (off the kernel ES
                               ///< queue), mirroring the ETW sid→user-at-drain idiom. 0 on Windows.
    std::int32_t exit_code{0}; ///< process exit status (stop only)
};

/// Bounded ring buffer bridging a push-based consumer thread/queue (producer) to
/// the pull-based drain tick (consumer). Overflow drops the incoming event and
/// bumps `dropped_` (the blast-radius / fan-out backpressure idiom) so a
/// process-spawn storm can neither grow memory without bound nor block the
/// producer. push() never blocks.
class ProcEventRing {
public:
    /// A capacity of 0 is meaningless (every push would drop); clamp to 1 so a
    /// mis-sized ring degrades to "holds one event" rather than "drops all".
    explicit ProcEventRing(std::size_t capacity) : cap_(capacity == 0 ? 1 : capacity) {
        // Pre-allocate the full capacity up front so a push() under the lock never
        // reallocates. A reallocation could throw std::bad_alloc inside the ETW /
        // Endpoint Security handler, which runs across a C (provider) frame where an
        // escaping C++ exception is undefined behaviour. cap_ is bounded (default
        // 100k events), so this is a single bounded reservation, not unbounded growth.
        buf_.reserve(cap_);
    }

    /// Append one event. Returns false (and increments dropped()) when full.
    bool push(ProcEvent ev);

    /// Move all buffered events out for batched persistence; leaves the ring empty.
    std::vector<ProcEvent> drain();

    /// Events discarded due to overflow since construction (NFR visibility).
    std::uint64_t dropped() const noexcept {
        return dropped_.load(std::memory_order_relaxed);
    }
    std::size_t capacity() const noexcept { return cap_; }

private:
    mutable std::mutex mu_;
    std::vector<ProcEvent> buf_;
    std::size_t cap_;
    std::atomic<std::uint64_t> dropped_{0};
};

/// Common interface for a gap-free process start/stop stream — ETW on Windows
/// (ProcEtwCollector), Endpoint Security on macOS (ProcEsCollector). The TAR
/// plugin holds ONE of these and drains it each fast tick, falling back to the
/// snapshot-diff poll whenever none is active. Exactly one concrete collector is
/// constructed per platform; on platforms (or SDKs) without a stream, start()
/// returns false and the poll covers the source — there is never silent loss.
class ProcStreamCollector {
public:
    virtual ~ProcStreamCollector() = default;

    /// Begin streaming. Returns false if unavailable (wrong platform, missing
    /// entitlement/privilege, session-open failure) — caller falls back to poll.
    virtual bool start() = 0;
    /// Stop streaming and release the underlying session/client. Safe if not started.
    virtual void stop() = 0;
    virtual bool running() const noexcept = 0;
    /// Move buffered events out for the batched tar.db write.
    virtual std::vector<ProcEvent> drain() = 0;
    /// Events dropped due to ring overflow since construction.
    virtual std::uint64_t dropped() const noexcept = 0;
    /// Events the source's kernel/provider dropped BEFORE they reached userspace
    /// (e.g. Endpoint Security `seq_num` gaps), distinct from dropped() which
    /// counts the userspace ring overflow. Default 0 for sources with no
    /// kernel-side sequence to inspect (ETW today).
    virtual std::uint64_t kernel_dropped() const noexcept { return 0; }
    /// True when the collector still reports running() but has gone silent long
    /// enough to be presumed dead — for a source with no liveness API (the macOS
    /// Endpoint Security client). The plugin re-arms the snapshot-diff poll when
    /// this trips. Default false for sources whose running() already flips on
    /// death (ETW: the ProcessTrace thread returns).
    virtual bool stalled() const noexcept { return false; }
    /// Stable token for the `process_capture_method` status field
    /// ("etw" / "endpoint_security").
    virtual const char* method_name() const noexcept = 0;
};

} // namespace yuzu::tar
