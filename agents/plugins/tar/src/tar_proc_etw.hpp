#pragma once

/**
 * tar_proc_etw.hpp — gap-free process start/stop capture via ETW.
 *
 * Thread 1(a) of the ETW process-events workstream. Subscribes to the
 * Microsoft-Windows-Kernel-Process provider on a real-time ETW session and
 * decodes process start (event id 1) / stop (event id 2) into a bounded ring
 * buffer that the TAR plugin drains and persists in batches. This is the
 * event-driven complement to the snapshot-diff poll (CreateToolhelp32Snapshot /
 * NtQuerySystemInformation): the poll misses anything that starts and exits
 * within an interval; ETW does not.
 *
 * Boot gap (known limitation, thread 1(b)): a real-time session only sees events
 * once it is open, so processes that start AND exit before the agent's session
 * starts are missed. The fix is an AutoLogger that buffers boot events to an
 * .etl the agent drains at startup — a separate slice.
 *
 * windows.h-free by design: all ETW / TDH / windows.h usage lives in the .cpp
 * (mirrors guard.hpp's discipline — keeps windows.h's ERROR/min/max macros out
 * of headers). Off-Windows the collector is a no-op: start() returns false, the
 * ring stays empty, drain() yields nothing — callers degrade cleanly.
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace yuzu::tar {

/// One process lifecycle event decoded from Microsoft-Windows-Kernel-Process.
/// Fields mirror the TAR `process_live` schema (ts/action/pid/ppid/name/user)
/// plus exit_code — which ETW carries on the stop event and a poll never can.
///
/// `image_name` is the executable basename only; the full command line is NOT
/// captured by default (usage-class / works-council posture — the A2
/// names-only-never-cmdlines precedent). `user` is resolved at drain time
/// (batched), never in the ETW callback, to keep the hot path cheap.
struct ProcEvent {
    std::int64_t ts_unix{0};   ///< event time, unix seconds
    bool is_start{true};       ///< true = start (event 1); false = stop (event 2)
    std::uint32_t pid{0};
    std::uint32_t ppid{0};     ///< parent pid (start only; 0 on stop)
    std::string image_name;    ///< executable basename, never the full command line
    std::string sid;           ///< raw SID string, captured in the callback (start: from the
                               ///< live process; stop: from the pid→sid cache). Resolved to
                               ///< `user` at drain time so the costly LookupAccountSid stays
                               ///< off the ETW consumer thread and is cached per distinct SID.
    std::string user;          ///< DOMAIN\\account, resolved from `sid` at drain ("" if unresolved)
    std::int32_t exit_code{0}; ///< process exit status (stop only)
};

/// Bounded ring buffer bridging the push-based ETW consumer thread (producer)
/// to the pull-based drain tick (consumer). Overflow drops the incoming event
/// and bumps `dropped_` (the blast-radius / fan-out backpressure idiom) so a
/// process-spawn storm can neither grow memory without bound nor block the ETW
/// callback. push() never blocks.
class ProcEventRing {
public:
    explicit ProcEventRing(std::size_t capacity) : cap_(capacity) {}

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

/// Owns a real-time ETW session on Microsoft-Windows-Kernel-Process and decodes
/// start/stop events into a ProcEventRing on a dedicated ProcessTrace thread.
/// Single-owner (non-copyable). Windows-only; every method is a no-op on other
/// platforms and start() returns false.
class ProcEtwCollector {
public:
    /// `ring_capacity` bounds buffered-but-not-yet-drained events. Sized for the
    /// drain cadence × peak spawn rate with headroom; overflow drops with a
    /// counter rather than growing.
    explicit ProcEtwCollector(std::size_t ring_capacity = 100000);
    ~ProcEtwCollector();

    ProcEtwCollector(const ProcEtwCollector&) = delete;
    ProcEtwCollector& operator=(const ProcEtwCollector&) = delete;

    /// Open the session, enable the provider, and start ProcessTrace on its own
    /// thread. Returns false off-Windows, on any session-open failure, or if
    /// already running. A false return leaves nothing started (no thread, no
    /// session) so callers can fall back to the poll cleanly.
    bool start();

    /// Close the session and join the consumer thread. Safe if not started.
    void stop();

    bool running() const noexcept;

    /// Move buffered events out for the batched tar.db write (the drain tick).
    /// Returns empty when not running / off-Windows.
    std::vector<ProcEvent> drain();

    /// Count of events dropped due to ring overflow since construction.
    std::uint64_t dropped() const noexcept;

private:
    struct Impl;                 ///< Windows ETW/TDH state; defined only in the .cpp
    std::unique_ptr<Impl> impl_; ///< null off-Windows / when not running
    ProcEventRing ring_;
};

/// Replay a file-mode ETW trace — the boot AutoLogger's `.etl` — and return the
/// process start/stop events with `ts < before_ts_unix`: the boot window before
/// the live session took over (which owns ts >= before, so this partition avoids
/// both gaps and duplicates). Names are recovered start→stop within the file;
/// there is NO user (the boot processes are dead by replay time).
///
/// Reads the file directly even while the AutoLogger is still writing it — that
/// works fine, PROVIDED the AutoLogger is configured with a FlushTimer so its
/// buffers actually reach the file (without one the file stays empty and this
/// replay sees nothing — verified on Win11). **No session stop, no elevation:**
/// the narrow agent account only needs read access to its own data dir. Caller
/// must dedup per-boot (the file persists, so an agent restart would otherwise
/// re-backfill the same boot events). Windows-only; empty off-Windows or on a
/// missing/empty file.
std::vector<ProcEvent> backfill_proc_events_from_etl(const std::string& etl_path,
                                                     std::int64_t before_ts_unix);

} // namespace yuzu::tar
