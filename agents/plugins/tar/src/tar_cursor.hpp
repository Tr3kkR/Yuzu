#pragma once

// tar_cursor.hpp -- the CURSOR-MODEL contract every subscription/cursor-backed
// TAR capture source (power, removable — wave 2) implements, plus the one new
// shared abstraction this seam introduces: a bounded, ack-after-commit pending
// queue for OS-callback-fed sources. This header is pure contract + a
// header-only template; it depends on nothing but tar_capture_status.hpp
// (IncompleteCaptureError) and the standard library, so it compiles standalone
// and is unit-testable without a live OS subscription (tests/unit/
// test_tar_cursor.cpp).
//
// WHY A SEPARATE MODEL FROM THE SNAPSHOT-DIFF SOURCES (service/mapdrive/arp) --
// those sources re-enumerate a full table every tick and diff it against the
// last COMPLETE snapshot (tar_capture_status.hpp's collect_or_retain). Power
// and removable-media events are OS-LOGGED TRANSITIONS (event-log records, a
// callback-fed subscription), not something to poll-and-diff: the source of
// truth is an append-only, possibly-wrapping log or a live callback stream,
// and what must be tracked between ticks is a POSITION in that log/stream
// (the "cursor"), not a snapshot of current state. Six load-bearing contract
// rules follow from that shape; every implementer (and this header's own
// driver code in tar_plugin.cpp) applies them identically:
//
//  1. TRANSIENT failure (the log/subscription could not be read this tick --
//     e.g. a locked/ACL-denied channel, a momentarily unreachable API) throws
//     IncompleteCaptureError (tar_capture_status.hpp:57), exactly like the
//     snapshot-diff sources. The driver (tar_plugin.cpp's collect_or_retain
//     usage) retains the cursor UNCHANGED and skips the persist for this tick
//     -- the same collect_or_retain policy documented at tar_capture_status.
//     hpp:187. This is a RETRY signal, not a data-loss signal: the next tick
//     re-reads from the same (unchanged) cursor.
//
//  2. A LOST/INVALID cursor -- the stored cursor references a log position
//     that no longer exists (the log WRAPPED past it, the subscription handle
//     is stale, the cursor JSON fails to parse) -- or a WRAPPED LOG detected
//     mid-read, is explicitly NOT an exception. It is a normal, expected
//     outcome: emit a `capture_gap` event recording the gap, RE-BASELINE the
//     cursor at the CURRENT log end (never replay-from-zero -- a full
//     from-zero replay of an OS event log/USB history is exactly the kind of
//     unbounded backfill this seam avoids), and return CursorOutcome::
//     CursorLost from collect(). The measured case this rule exists for:
//     runDir/fixtures shows a Kernel-PnP/Configuration channel observed going
//     1432 -> 1352 records mid-capture (the provider recycled/wrapped the
//     channel) -- a real, not hypothetical, log-wrap.
//
//  3. Replay idempotence comes from the UNIQUE `record_key` column + INSERT OR
//     IGNORE (tar_db.hpp/.cpp), never from cursor arithmetic. A cursor that is
//     re-read from a slightly earlier position than strictly necessary (e.g.
//     after rule 2's re-baseline, or a retry) must never double-insert -- the
//     database's unique index is the single source of truth for "have I
//     already stored this event", not any offset math a source might do.
//
//  4. Cursor state is PER-INPUT, carried inside one opaque, versioned JSON
//     blob (`{"v":1, ...}` -- the version lets a source evolve its internal
//     shape without a schema migration). A source with multiple independent
//     inputs (e.g. more than one event-log channel) packs all of them into
//     that single JSON document; tar_cursor stores exactly one row per source
//     name, never one row per input.
//
//  5. A RETROSPECTIVE source (one whose first read can reach into OS-retained
//     history from before the source was ever enabled) honours a
//     `<name>_lookback_seconds` config key -- default 604800 (7 days), and
//     0 = FORWARD-ONLY (no pre-enablement history is ever read). This is the
//     same operator-facing privacy control already shipped for netconn
//     (ADR-0020, netconn_lookback_seconds, tar_netconn.hpp) -- power and
//     removable follow the identical shape rather than inventing a second
//     one.
//
//  6. A subscription/callback-fed source must never DESTRUCTIVELY drain its
//     callback queue before the corresponding DB transaction commits (P-003).
//     BoundedPendingQueue below is the shared mechanism: push() is safe to
//     call from an OS callback thread, snapshot() copies out a batch without
//     removing it, and ack(n) removes exactly the acknowledged prefix -- and
//     must be called ONLY after the event+cursor transaction
//     (insert_power_events_and_cursor / insert_removable_events_and_cursor)
//     has actually committed. A batch that fails to persist stays in the
//     queue and is retried next tick. This mirrors the existing pending_
//     stream_evs_ / kPendingStreamCap retry-on-insert-failure posture
//     (tar_plugin.cpp:1209) -- the difference is that here the seam OWNS the
//     bounded queue as a reusable template rather than every source
//     reimplementing its own std::vector-plus-cap dance.
//
// LIFECYCLE (P-002) -- a CursorSource is a TarPlugin-owned member (constructed
// once by make_cursor_sources(), started once, stopped once), NEVER a
// function-local static: a static registry cannot be torn down deterministically
// relative to TarDatabase's own lifetime, and this seam's #1 ordering
// requirement is that every source is fully stopped BEFORE the database it
// was writing to is destroyed (see stop() below).
//
//  - name()               -- the source name ("power", "removable"); doubles
//                             as the tar_cursor primary key and the
//                             `<name>_enabled` / `<name>_lookback_seconds`
//                             config-key prefix.
//  - start(db)             -- arm whatever OS subscription this source needs
//                             (an event-log handle, a device-notification
//                             callback, ...). A no-op for a pure-replay source
//                             that only reads a log on collect(). Called once,
//                             at plugin init, for every source (enabled or
//                             not) -- so a later on_enabled_changed(true) has
//                             something live to resume, mirroring the ETW
//                             process stream's "keep the session warm across
//                             a disable" posture (tar_plugin.cpp:1157).
//  - collect(db, cursor)   -- do one tick's read: given the last-persisted
//                             cursor (nullopt if never persisted), produce a
//                             CursorCollectResult. Throws IncompleteCaptureError
//                             per rule 1; returns CursorLost per rule 2;
//                             otherwise Baseline (no prior cursor -- this is
//                             the FIRST successful read) or Advanced.
//  - stop() noexcept       -- bounded unregister/drain/join of EVERY callback,
//                             queue, thread and OS handle the source owns. A
//                             source owns NOTHING live after stop() returns --
//                             no callback can fire, no thread can touch the
//                             database, after this call. Must be safe to call
//                             from shutdown() while collect_mu_ is held (so it
//                             must not itself try to take collect_mu_), and
//                             must be called for every constructed source
//                             BEFORE the TarDatabase is destroyed (tar_plugin.
//                             cpp shutdown() orders this exactly like
//                             proc_stream_/module_stream_ at tar_plugin.cpp:
//                             926-960: stop() every cursor source under
//                             collect_mu_, THEN db_.reset()).
//  - on_enabled_changed(en) -- the operator flips `<name>_enabled` (P-002 /
//                             forensic-pause parity with tar_plugin.cpp:1157):
//                               disable (en=false)  -- unregister the live
//                                 callback/subscription, OR (if it must stay
//                                 warm) drain-and-DISCARD whatever it already
//                                 buffered, so NOTHING from the paused window
//                                 is ever stored -- exactly the ETW process-
//                                 stream contract at tar_plugin.cpp:1157-1160.
//                               re-enable (en=true) -- RE-BASELINE forward (as
//                                 if this were a fresh CursorLost recovery: new
//                                 cursor at current log end) and emit a
//                                 capture_gap event recording the disabled
//                                 window -- NEVER emit the disabled window's
//                                 own events; only the fact that a gap
//                                 exists.

#include "tar_capture_status.hpp" // IncompleteCaptureError

#include <algorithm> // std::min in BoundedPendingQueue::ack()
#include <cstddef>
#include <cstdint> // std::uint64_t -- BoundedPendingQueue's internal seq (R-005)
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility> // std::pair -- BoundedPendingQueue's seq-stamped storage (R-005)
#include <vector>

namespace yuzu::tar {

class TarDatabase;

/// Result of one collect() tick.
enum class CursorOutcome {
    Baseline,   // no prior cursor existed (first-ever successful read, OR a
                // rule-2 re-baseline after CursorLost/disable-window-close) --
                // the new cursor marks "now", no historical replay happened.
    Advanced,   // a valid prior cursor existed and moved forward normally.
    CursorLost, // the prior cursor was invalid/behind a wrapped log; the
                // source re-baselined at the current log end and emitted a
                // capture_gap event (rule 2). Never thrown as an exception --
                // this is a normal, expected outcome the driver persists like
                // any other successful collect().
};

/// One collect() tick's result.
///
/// The SOURCE persists, not the driver: from inside collect() it calls
/// insert_*_events_and_cursor (tar_db.hpp), which writes this tick's events
/// and the new cursor in ONE transaction, so the two can never disagree.
/// `new_cursor_json` REPORTS the value the source committed -- the driver does
/// not write it, and a caller comparing it against get_cursor() is asserting
/// that the source held up its end (which is exactly what the unit tests do).
/// An earlier revision of this comment said the driver persists; it does not,
/// and on a frozen contract that both consumers read, the distinction decides
/// where the atomicity guarantee actually lives.
struct CursorCollectResult {
    std::string new_cursor_json; // opaque, versioned ({"v":1,...}) -- rule 4
    std::size_t events_emitted{0};
    CursorOutcome outcome{CursorOutcome::Baseline};
    std::string detail; // free-form, logged only (never parsed)
};

/// The full lifecycle contract every cursor-model TAR source implements.
/// See the header comment above for the per-method contract; this class adds
/// no behaviour of its own -- it is a pure interface.
class CursorSource {
public:
    virtual ~CursorSource() = default;

    /// Stable source name ("power", "removable", ...). Also the tar_cursor
    /// primary key and the `<name>_enabled` / `<name>_lookback_seconds`
    /// config-key prefix.
    [[nodiscard]] virtual std::string name() const = 0;

    /// Arm whatever OS subscription this source needs. Called once at plugin
    /// init for every constructed source, regardless of its current
    /// `<name>_enabled` state (see on_enabled_changed doc above for why).
    /// A no-op for a pure-replay source.
    virtual void start(TarDatabase& db) = 0;

    /// One collect tick. `cursor_json` is the last-persisted cursor
    /// (std::nullopt if get_cursor() returned none yet). Throws
    /// IncompleteCaptureError on a transient read failure (rule 1); returns a
    /// CursorLost result rather than throwing when the cursor itself is
    /// invalid or the log has wrapped (rule 2).
    virtual CursorCollectResult collect(TarDatabase& db,
                                        const std::optional<std::string>& cursor_json) = 0;

    /// Bounded unregister/drain/join of every callback, queue, thread and OS
    /// handle this source owns. Must return with nothing left live -- no
    /// callback can fire and no thread can touch `db` after this returns.
    /// Called under collect_mu_ from tar_plugin.cpp's shutdown(), so this
    /// method must NOT itself attempt to take collect_mu_.
    virtual void stop() noexcept = 0;

    /// The operator flipped `<name>_enabled`. See the header comment above
    /// The operator flipped `<name>_enabled`. See the header comment above
    /// for the disable/re-enable contract (forensic-pause parity, P-002).
    ///
    /// Deliberately takes NO TarDatabase&. It is called UNDER `collect_mu_`, the
    /// same lock every collect tick holds, so it can never race one -- and for
    /// that same reason it must NOT itself take `collect_mu_`, exactly as stop()
    /// must not. A source therefore has no database to write to here, and A
    /// re-enable therefore records its intent (a flag) and the NEXT collect()
    /// emits the single capture_gap covering the disabled window and
    /// re-baselines forward -- and only clears that flag once the insert has
    /// committed, so a failed tick re-reports rather than losing the gap.
virtual void on_enabled_changed(bool enabled) = 0;
};

/// Wave-2 factories (defined in the wave-2 .cpp that implements each source).
/// Declared here so tar_cursor_sources.cpp's make_cursor_sources() -- and
/// this wave's caller in tar_plugin.cpp -- have a stable signature to build
/// against, even though this wave supplies no definition.
std::unique_ptr<CursorSource> make_power_cursor_source();
std::unique_ptr<CursorSource> make_removable_cursor_source();

/// Build every cursor-model source this agent ships. THIS WAVE returns an
/// empty vector (marker only) -- the wave-2 integrator adds the two
/// push_backs (make_power_cursor_source / make_removable_cursor_source).
/// Defined in tar_cursor_sources.cpp. Deliberately NOT a function-local
/// static: the sources it returns become TarPlugin-owned members (P-002),
/// constructed exactly once per plugin instance, not lazily via a shared
/// process-lifetime registry.
std::vector<std::unique_ptr<CursorSource>> make_cursor_sources();

/// Subscription-durability queue (P-003): a bounded, mutex-guarded queue an OS
/// callback pushes into and a collect() tick drains via snapshot_batch()/
/// ack_through(), so a callback-fed source never has to choose between
/// blocking the OS callback and losing events.
///
///  - push()            -- callback-thread-safe. On overflow (size already
///                          at cap) drops the OLDEST entry and increments
///                          the cumulative dropped counter -- mirrors
///                          pending_stream_evs_ / kPendingStreamCap's
///                          overflow posture (tar_plugin.cpp:1209-1215):
///                          newest data wins over oldest, and the loss is
///                          counted, never silent. Every pushed entry is
///                          stamped with an internal, queue-owned,
///                          monotonically increasing sequence number --
///                          unrelated to any caller-side `Event::seq`
///                          field; the template gains no requirements on
///                          `Event`.
///  - snapshot_batch()  -- copies out every currently-queued entry WITHOUT
///                          removing them (rule 6: never destructively
///                          drain before commit), plus the internal
///                          sequence number of the last entry copied
///                          (`Batch::last_seq`; 0 for an empty queue).
///  - ack_through(seq)  -- removes every entry whose internal sequence
///                          number is <= `seq` (pass the `last_seq` the
///                          matching snapshot_batch() returned). Call this
///                          ONLY after that batch has been durably
///                          committed (insert_*_events_and_cursor returned
///                          true) -- a failed insert must leave every entry
///                          in place so the next tick's snapshot_batch()
///                          retries the same batch. Identity-based, so an
///                          entry pushed after the snapshot has a larger
///                          seq and can NEVER be removed by acking an
///                          earlier batch, regardless of what overflow
///                          evicted in between -- fixes R-005, under which
///                          the old positional ack(n) could erase an
///                          uncommitted entry that overflow shifted into
///                          the acked prefix after the snapshot was taken.
///                          A no-op for seq == 0.
///  - dropped()         -- cumulative count of entries ever dropped by
///                          overflow. A source surfaces this as the
///                          `dropped` count on the next capture_gap event
///                          it emits (rule 6), then may reset its own
///                          last-reported baseline -- the queue's counter
///                          itself is monotonic and never resets on its
///                          own, exactly like proc_stream_->dropped().
///                          Accepted residual: an entry evicted by overflow
///                          AFTER being snapshotted still increments this
///                          counter even though its copy goes on to commit
///                          -- dropped() may therefore overcount, never
///                          undercount, actual loss, which is the
///                          conservative direction.
///
/// There is deliberately NO positional ack. An earlier revision kept a
/// snapshot()/ack(n) pair "so already-built callers keep compiling"; no such
/// caller existed, and this header is FROZEN for its two consumers, so the
/// only thing it could have done is let one of them reintroduce R-005. Ack is
/// by sequence, or not at all.
template <class Event>
class BoundedPendingQueue {
public:
    static constexpr std::size_t kCap = 4096;

    struct Batch {
        std::vector<Event> items; // oldest first
        std::uint64_t last_seq{0};
    };

    void push(Event ev) {
        std::lock_guard lock(mu_);
        if (q_.size() >= kCap) {
            q_.pop_front();
            ++dropped_;
        }
        q_.emplace_back(next_seq_++, std::move(ev));
    }

    /// Non-destructive copy of everything currently queued, oldest first,
    /// plus the internal sequence number of the last entry copied (0 if the
    /// queue was empty). Pass `Batch::last_seq` to ack_through() once the
    /// batch this call returned has committed.
    [[nodiscard]] Batch snapshot_batch() const {
        std::lock_guard lock(mu_);
        Batch batch;
        batch.items.reserve(q_.size());
        for (const auto& entry : q_)
            batch.items.push_back(entry.second);
        batch.last_seq = q_.empty() ? 0 : q_.back().first;
        return batch;
    }

    /// Remove every entry whose internal sequence number is <= `last_seq`.
    /// Call only after the batch snapshot_batch() returned it from has been
    /// durably committed. Identity-based (R-005): an entry pushed after the
    /// snapshot has a larger sequence number and is never removed by this
    /// call, regardless of intervening overflow. A no-op for last_seq == 0.
    void ack_through(std::uint64_t last_seq) {
        std::lock_guard lock(mu_);
        while (!q_.empty() && q_.front().first <= last_seq)
            q_.pop_front();
    }

    /// Discard everything queued right now WITHOUT counting it as an
    /// overflow drop -- used by on_enabled_changed(false)'s
    /// drain-and-DISCARD contract (rule/forensic-pause above), which is a
    /// deliberate policy discard, not a queue overflow.
    void discard_all() {
        std::lock_guard lock(mu_);
        q_.clear();
    }

    [[nodiscard]] std::size_t size() const {
        std::lock_guard lock(mu_);
        return q_.size();
    }

    [[nodiscard]] std::size_t dropped() const {
        std::lock_guard lock(mu_);
        return dropped_;
    }

private:
    mutable std::mutex mu_;
    std::deque<std::pair<std::uint64_t, Event>> q_;
    std::uint64_t next_seq_{1};
    std::size_t dropped_{0};
};

} // namespace yuzu::tar
