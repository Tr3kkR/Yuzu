#include "mcp_stream.hpp"

#include "mcp_jsonrpc.hpp"
#include "mcp_session.hpp"
#include "mcp_transport.hpp"
#include "rest_a4_envelope.hpp"
#include "auth_routes.hpp" // detail::sanitize_detail_value — audit-string sanitiser
#include "principal_quota_gate.hpp" // detail::adopt_quota_slot_into_stream (UP-1)
#include "rest_audit.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <random>
#include <functional>
#include <string_view>
#include <system_error>
#include <utility>

namespace yuzu::server::mcp {

// The ring's frame cap must never exceed the sink queue's cap: a full-ring replay is
// pushed through enqueue_capped, so a larger ring would silently drop the OLDEST
// replayed frames — gapping a resume that the ring could actually have served, which
// is precisely the failure the ring exists to prevent.
static_assert(kMcpRingCapDefault <= sse_bus::kPerConnectionQueueCapDefault,
              "replay ring must fit the sink queue or a full replay self-gaps");
static_assert(McpSessionRegistry::Config{}.ring_cap == kMcpRingCapDefault,
              "registry default and stream default must not drift");
// Same for the byte cap: the registry header cannot name the constant (it only
// forward-declares McpStreamState), so the two literals are pinned together here.
static_assert(McpSessionRegistry::Config{}.ring_bytes_cap == kMcpRingBytesCapDefault,
              "registry byte-cap default and stream byte-cap default must not drift");

namespace {

constexpr std::size_t kMaxWriteSlice = 8192;  // sibling parity (/api/v1/events)
constexpr std::size_t kMaxEventTypeBytes = 64;  // SSE event names are short by construction

// Metric names — the Decision 15(k) family, fixed at PR 0 so dashboards/alerts
// can be authored against them before the code lands.
constexpr const char* kMetricStreamsActive = "yuzu_mcp_streams_active";
constexpr const char* kMetricStreamsHandover = "yuzu_mcp_streams_handover_pending";
constexpr const char* kMetricRingEvictions = "yuzu_mcp_stream_replay_ring_evictions_total";
constexpr const char* kMetricStreamRejects = "yuzu_mcp_stream_rejects_total";
constexpr const char* kMetricStreamCloses = "yuzu_mcp_stream_closes_total";
constexpr const char* kMetricFramesDropped = "yuzu_mcp_stream_frames_dropped_total";
constexpr const char* kMetricFramesTruncated = "yuzu_mcp_stream_frames_too_large_total";

void count_reject(yuzu::MetricsRegistry* metrics, const char* reason) {
    if (metrics != nullptr) {
        metrics->counter(kMetricStreamRejects, {{"reason", reason}}).increment();
    }
}

// Closes are counted BY REASON. Without this an operator cannot alert on
// "auth_unavailable closes are spiking" (i.e. our auth store is sick and streams are
// dying of it) without trawling the audit store — and that is precisely the signal the
// tri-state re-validation exists to produce.
void count_stream_close(yuzu::MetricsRegistry* metrics, McpStreamClose reason) {
    if (metrics != nullptr) {
        metrics->counter(kMetricStreamCloses, {{"reason", to_string(reason)}}).increment();
    }
}

// SSE is a line protocol: a newline in `event_type` would terminate the field and
// let the rest of the string forge SSE lines. `data` is safe (format_sse re-prefixes
// every line), but the type is not — strip rather than trust. The producer seam
// (`publish`) is the only way a type reaches the wire.
std::string sanitize_event_type(std::string type) {
    for (char& c : type) {
        if (c == '\n' || c == '\r') {
            c = '_';
        }
    }
    return type;
}

// What a client should DO about each close reason. Part of the A4 shape on the final
// frame: "your stream ended" is only actionable if we say what ends it.
const char* close_remediation(McpStreamClose reason) {
    switch (reason) {
    case McpStreamClose::kCredentialRevoked:
        return "re-authenticate, then re-initialize and reconnect";
    case McpStreamClose::kAuthUnavailable:
        return "the auth store was unreachable; retry — durable results remain fetchable "
               "by execution_id";
    case McpStreamClose::kSessionTerminated:
        return "re-initialize to mint a new session";
    case McpStreamClose::kInternalError:
        return "a server-side fault ended this stream — reconnect; durable results remain "
               "fetchable by execution_id";
    case McpStreamClose::kClientGone:
    case McpStreamClose::kSuperseded:
    case McpStreamClose::kNone:
        break;
    }
    return "reconnect with Last-Event-ID to resume within the replay window";
}

// Strict, non-throwing cursor parse. std::stoull would be wrong twice over: it does
// not throw on "-1" (it WRAPS to UINT64_MAX, which lands past the ring window and so
// would terminate the client's session over a typo), it accepts trailing junk, and it
// throws on overflow — inside a content-provider callback that must never throw.
std::uint64_t parse_last_event_id(std::string_view raw) {
    if (raw.empty() || raw.front() == '-' || raw.front() == '+') {
        return 0;
    }
    std::uint64_t value = 0;
    const char* const end = raw.data() + raw.size();
    const auto [ptr, ec] = std::from_chars(raw.data(), end, value);
    if (ec != std::errc{} || ptr != end) {
        return 0; // unparseable cursor → replay what we still hold, never terminate
    }
    return value;
}

bool write_all(const McpStreamPump::WriteFn& write, std::string_view payload) {
    const char* p = payload.data();
    std::size_t rem = payload.size();
    while (rem > 0) {
        const std::size_t n = std::min(rem, kMaxWriteSlice);
        if (!write(p, n)) {
            return false;
        }
        p += n;
        rem -= n;
    }
    return true;
}

}  // namespace

const char* to_string(McpStreamClose reason) {
    switch (reason) {
    case McpStreamClose::kNone:
        return "none";
    case McpStreamClose::kClientGone:
        return "client_disconnect";
    case McpStreamClose::kSuperseded:
        return "superseded";
    case McpStreamClose::kSessionTerminated:
        return "session_terminated";
    case McpStreamClose::kCredentialRevoked:
        return "credential_revoked";
    case McpStreamClose::kAuthUnavailable:
        return "auth_unavailable";
    case McpStreamClose::kInternalError:
        return "internal_error";
    }
    return "unknown";
}

// ── McpStreamState ──────────────────────────────────────────────────────────

McpStreamState::McpStreamState(std::size_t ring_cap, yuzu::MetricsRegistry* metrics,
                               std::size_t ring_bytes_cap)
    : ring_cap_(ring_cap == 0 ? 1 : ring_cap),
      // Floored, not merely non-zero: below the size of the frame_too_large notice itself
      // every publish would be "oversized", collapsing the ring to a single frame and
      // making every resume a gap.
      ring_bytes_cap_(std::max<std::size_t>(ring_bytes_cap, kMinRingBytesCap)), metrics_(metrics) {
    if (metrics_ != nullptr) {
        // Pay the allocation and the global-registry lock HERE, once, on a path that is
        // allowed to throw — not inside attach/detach, where a throw would strand a sink
        // that is already live and already holds a budget lease.
        gauge_streams_active_ = &metrics_->gauge(kMetricStreamsActive);
        gauge_streams_handover_ = &metrics_->gauge(kMetricStreamsHandover);
    }
}

std::uint64_t McpStreamState::publish(std::string event_type, std::string data) {
    std::shared_ptr<McpStreamSink> live;
    std::uint64_t id = 0;
    std::uint64_t evicted = 0;
    bool oversized = false;
    {
        // A single frame must not exceed the ring's byte budget, or the "always keep the
        // newest frame" rule below would admit it whole and the byte cap would bound
        // nothing.
        //
        // Do NOT byte-truncate it: these payloads are JSON, so a cut at an arbitrary
        // offset yields a guaranteed-unparseable frame — which we would then hand to the
        // live sink AND store in the ring under an id, so every resume would faithfully
        // re-serve the same garbage. Substitute a well-formed frame that says what
        // happened and where the real answer is. The client gets something it can parse
        // and act on; the ring stays bounded.
        if (event_type.size() + data.size() > ring_bytes_cap_) {
            data = "{\"error\":\"frame_too_large\",\"bytes\":" + std::to_string(data.size()) +
                   ",\"remediation\":\"fetch the full result by execution_id\"}";
            // The frame is event_type + data, so a pathological type could still overshoot
            // the bound the notice was meant to restore. Types are server-chosen and short
            // ("message"); clamp anyway rather than trust that forever.
            if (event_type.size() > kMaxEventTypeBytes) {
                event_type.resize(kMaxEventTypeBytes);
            }
            oversized = true;
        }
        std::lock_guard<std::mutex> lk(mu_);
        id = next_id_++;
        ring_.push_back(sse_bus::SseEvent{sanitize_event_type(std::move(event_type)),
                                          std::move(data), id});
        while (ring_.size() > ring_cap_ ||
               (ring_bytes_ + frame_bytes(ring_.back()) > ring_bytes_cap_ && ring_.size() > 1)) {
            // Bounded on BOTH axes (Decision 15(d)). The frame count alone is not a memory
            // bound — 1024 sessions x 500 frames only bounds memory if you also know what a
            // frame weighs. Always keep at least the newest frame.
            ring_bytes_ -= frame_bytes(ring_.front());
            ring_.pop_front();
            ++evictions_;
            ++evicted;
        }
        ring_bytes_ += frame_bytes(ring_.back());

        // Enqueue to the live sink UNDER mu_, not after releasing it. Two concurrent
        // publishers (PR 3 will have concurrent tool calls on one session) would
        // otherwise be able to interleave between id-assignment and enqueue, putting
        // id 6 on the wire before id 5 — which silently breaks the monotonic
        // Last-Event-ID contract the whole resume mechanism rests on.
        // Safe: this is the DECLARED lock order (mu_ → sink mu), and enqueue_capped
        // never blocks on I/O or calls back into us.
        live = live_;
        if (live) {
            sse_bus::enqueue_capped(live->sse, ring_.back(), ring_cap_);
        }
    }
    if (live) {
        live->sse->cv.notify_one(); // outside mu_ — no need to hold it to wake a waiter
    }
    if (evicted > 0 && metrics_ != nullptr) {
        metrics_->counter(kMetricRingEvictions).increment(static_cast<double>(evicted));
    }
    if (oversized && metrics_ != nullptr) {
        // Counted, not just logged: an unbounded warn-per-publish is a log-flood vector,
        // and a new failure mode nobody can alert on is a failure mode nobody sees.
        metrics_->counter(kMetricFramesTruncated).increment();
    }
    return id;
}

McpStreamState::AttachResult McpStreamState::attach_and_replay(std::uint64_t last_event_id,
                                                               sse_bus::StreamBudget* budget,
                                                               const std::string& principal,
                                                               std::size_t per_principal_cap) {
    AttachResult out;
    std::shared_ptr<McpStreamSink> superseded;
    sse_bus::StreamBudget::Lease new_lease;
    {
        std::lock_guard<std::mutex> lk(mu_);

        // 1. Resumability. A cursor of 0 is "from the start of what we still have".
        //    Anything else must sit inside the ring window: at or after the frame
        //    before our oldest surviving id, and strictly before the next id we
        //    will assign. A cursor whose frames were evicted, and a bogus future
        //    cursor, take the SAME path — one client recovery (re-initialize), no
        //    silent gap and no oracle about which of the two it was.
        const std::uint64_t min_available = ring_.empty() ? next_id_ : ring_.front().id;
        const bool resumable =
            last_event_id == 0 || (last_event_id + 1 >= min_available && last_event_id < next_id_);
        if (!resumable) {
            out.status = AttachStatus::kGap;
            return out;
        }

        // 2. Admission.
        //
        // The scarce resource is not the session — it is the httplib WORKER each
        // held-open response pins for its whole life. So the accounting rule is:
        // one lease per SINK (per pinned worker), never one per session. An earlier
        // version kept the lease on the session and let a takeover inherit it, which
        // meant a superseded provider — still pinning its worker until it drains, and
        // a peer with a closed TCP window can stall that for the full write timeout —
        // was charged to nobody. A client could then hammer GET on ONE session and
        // pin the whole pool while the cap read 1. That defeats the entire point of
        // Decision 15(h).
        //
        // A takeover is admitted WITHOUT a cap check (a client reconnecting across a
        // zombie TCP must never be locked out by its own zombie), but it still takes
        // a lease, so the accounting stays truthful. The bound comes from structure
        // instead: a session holds at most ONE draining sink, so at most TWO
        // providers — hence `derive_stream_budget` reserves 2 workers per permitted
        // stream, and a second takeover while a handover is still pending is refused.
        if (live_ && draining_) {
            out.status = AttachStatus::kHandoverPending;
            return out; // one handover at a time — this is what bounds the pool
        }
        // Allocate BEFORE mutating live_/draining_. If make_shared threw after the
        // supersede, the session would be left with no live sink and a superseded provider
        // still on the wire receiving nothing — silent frame loss, and the next handover
        // blocked forever.
        auto sink = std::make_shared<McpStreamSink>();
        const bool is_takeover = live_ != nullptr; // decided BEFORE anything is mutated
        if (budget != nullptr) {
            // A takeover bypasses the CAPS but not the accounting.
            const auto mode = is_takeover ? sse_bus::StreamBudget::Admission::kTakeover
                                          : sse_bus::StreamBudget::Admission::kEnforceCaps;
            auto acquired = budget->try_acquire(sse_bus::SseSurface::kMcpGet, principal,
                                                per_principal_cap, mode);
            if (!acquired.lease) {
                // Only reachable on the first-attach path (a takeover always admits). The
                // session is untouched — nothing has been mutated yet.
                out.status = AttachStatus::kStreamCapHit;
                out.reject_reason = acquired.reject_reason;
                return out;
            }
            new_lease = std::move(acquired.lease);
        }

        // 3. Replay + attach, under the same lock a publisher would need — so no
        //    frame can slip into the window between the two. (The `/api/v1/events`
        //    sibling does replay and subscribe under SEPARATE locks and documents the
        //    resulting lost-frame window; here it cannot happen.)
        sink->lease = std::move(new_lease);
        for (const auto& ev : ring_) {
            if (ev.id > last_event_id) {
                sse_bus::enqueue_capped(sink->sse, ev, ring_cap_); // allocates — still safe:
                                                                   // live_/draining_ untouched
            }
        }
        // COMMIT. Everything above could throw and leave the session exactly as it was;
        // nothing below can.
        if (live_) {
            draining_ = std::move(live_);
            superseded = draining_;
        }
        live_ = sink;
        out.status = AttachStatus::kAttached;
        out.sink = sink;
        out.generation = ++generation_;

        // Gauges are published UNDER mu_, paired with the state change they describe: done
        // outside, a takeover whose superseded provider detaches before the attacher gets
        // to the increment drives `handover_pending` transiently negative — a sample an
        // alert would see. Safe to do here ONLY because the gauges were resolved at
        // construction: an increment through the cached pointer takes that gauge's own
        // mutex and allocates nothing, so it cannot throw while this sink is live and
        // holding a lease with no releaser armed yet.
        if (gauge_streams_active_ != nullptr) {
            gauge_streams_active_->increment();
            if (superseded) {
                gauge_streams_handover_->increment();
            }
        }
    }

    // Wake the superseded provider outside mu_ (lock order). `closed` MUST be set
    // while holding the sink mutex: the pump evaluates it as its wait predicate, and
    // a store+notify issued in the window between the pump's predicate check and its
    // atomic release-and-block is simply LOST — the provider would then sleep a full
    // tick before noticing, pinning a worker for 3 s per takeover.
    if (superseded) {
        close_sink(superseded, McpStreamClose::kSuperseded);
    }
    return out;
}

void McpStreamState::close_sink(const std::shared_ptr<McpStreamSink>& sink, McpStreamClose reason) {
    if (!sink) {
        return;
    }
    sink->set_close_reason(reason);
    {
        // `closed` is the pump's wait PREDICATE, so it must be modified while owning
        // the sink mutex. Storing it atomically without the lock and then notifying is
        // a classic lost wakeup: if the pump has already evaluated the predicate and is
        // about to release-and-block, the notify lands on an empty wait queue and the
        // provider sleeps the full tick. Being atomic does not save you — ownership of
        // the mutex during the modification is what orders it against the wait.
        std::lock_guard<std::mutex> lk(sink->sse->mu);
        sink->sse->closed.store(true);
    }
    sink->sse->cv.notify_all();
}

void McpStreamState::close(McpStreamClose reason) {
    std::shared_ptr<McpStreamSink> live;
    {
        std::lock_guard<std::mutex> lk(mu_);
        live = live_;
        // The live sink is intentionally NOT cleared: the provider is still running and
        // calls detach() on teardown, which is the single place its lease is returned.
    }
    close_sink(live, reason); // outside mu_ (lock order) — never blocks on I/O
}

void McpStreamState::detach(const std::shared_ptr<McpStreamSink>& sink) {
    if (!sink) {
        return;
    }
    bool was_live = false;
    bool was_draining = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (live_ == sink) {
            live_.reset();
            was_live = true;
        } else if (draining_ == sink) {
            draining_.reset(); // the handover completed — a new takeover may proceed
            was_draining = true;
        }
    }
    if (!was_live && !was_draining) {
        return; // already detached (idempotent — httplib runs the releaser exactly once,
                // but a caller must not be able to corrupt the accounting by re-running it)
    }
    // Release the lease outside mu_ on this path — not because the nesting would be unsafe
    // (attach already establishes mu_ → budget mu_, and StreamBudget never calls back), but
    // because there is no reason to hold a per-stream lock across a global one. Each sink
    // owns its own lease, so this returns exactly the worker THIS provider was pinning. The
    // lease goes home BEFORE the metrics touch — that ordering is what lets every caller
    // treat a throwing metric as ignorable.
    sink->lease.release();
    if (gauge_streams_active_ != nullptr) {
        gauge_streams_active_->decrement();
        if (was_draining) {
            gauge_streams_handover_->decrement();
        }
    }
}

std::uint64_t McpStreamState::current_generation() const {
    std::lock_guard<std::mutex> lk(mu_);
    return generation_;
}

std::uint64_t McpStreamState::next_event_id() const {
    std::lock_guard<std::mutex> lk(mu_);
    return next_id_;
}

std::uint64_t McpStreamState::evictions_total() const {
    std::lock_guard<std::mutex> lk(mu_);
    return evictions_;
}

bool McpStreamState::has_live_sink() const {
    std::lock_guard<std::mutex> lk(mu_);
    return live_ != nullptr;
}

bool McpStreamState::has_draining_sink() const {
    std::lock_guard<std::mutex> lk(mu_);
    return draining_ != nullptr;
}

std::size_t McpStreamState::frame_bytes(const McpStreamEvent& ev) {
    return ev.event_type.size() + ev.data.size();
}

// ── McpStreamPump ───────────────────────────────────────────────────────────

McpStreamPump::McpStreamPump(std::shared_ptr<McpStreamSink> sink,
                             std::shared_ptr<McpStreamState> stream, std::uint64_t generation,
                             std::function<StreamRevalidate()> revalidate,
                             std::function<bool()> session_alive)
    : McpStreamPump(std::move(sink), std::move(stream), generation, std::move(revalidate),
                    std::move(session_alive), Config{}, {}, nullptr) {}

McpStreamPump::McpStreamPump(std::shared_ptr<McpStreamSink> sink,
                             std::shared_ptr<McpStreamState> stream, std::uint64_t generation,
                             std::function<StreamRevalidate()> revalidate,
                             std::function<bool()> session_alive, Config cfg, ClockFn clock,
                             yuzu::MetricsRegistry* metrics)
    : sink_(std::move(sink)), stream_(std::move(stream)), generation_(generation),
      revalidate_(std::move(revalidate)), session_alive_(std::move(session_alive)), cfg_(cfg),
      clock_(std::move(clock)), metrics_(metrics) {}

std::chrono::steady_clock::time_point McpStreamPump::now() const {
    return clock_ ? clock_() : std::chrono::steady_clock::now();
}

bool McpStreamPump::finish(const WriteFn& write, McpStreamClose reason) {
    sink_->set_close_reason(reason);
    const McpStreamClose actual = sink_->close_reason.load();
    count_stream_close(metrics_, actual);

    // A SUPERSEDED stream gets no final frame — deliberately. The client already has a
    // newer stream on this session, so the only thing that can be waiting on the far
    // end of this socket is the stalled peer that caused the takeover in the first
    // place; writing to it would block this worker for the full write timeout (30 s)
    // while its lease is still charged. Every other reason gets the frame.
    if (actual != McpStreamClose::kSuperseded) {
        // Decision 15(f): a close is never indistinguishable from a clean completion,
        // and the reason is machine-parseable in the same A4 shape as every denial on
        // this route (so a client has ONE error contract, not two).
        const auto cid = yuzu::server::detail::make_correlation_id();
        std::string body = "{\"reason\":";
        body += detail::json_quoted(to_string(actual));
        body += ",\"correlation_id\":";
        body += detail::json_quoted(cid);
        body += ",\"retry_after_ms\":null,\"remediation\":";
        body += detail::json_quoted(close_remediation(actual));
        body += "}";
        (void)write_all(write, sse_bus::format_sse(sse_bus::SseEvent{"stream-closed", body}));
    }
    return false;
}

bool McpStreamPump::pump_once(const WriteFn& write) {
    // HARD exception boundary. httplib invokes a chunked content provider from a bare
    // ThreadPool task — `routing()` is inside its try/catch, this is NOT — so an
    // escaped exception here is std::terminate, not a 500 (the #2037 failure class).
    // Everything below can throw: revalidate_() reaches SQLite and the auth manager,
    // and every frame build allocates.
    try {
        return pump_once_impl(write);
    } catch (...) {
        // `set_close_reason` is the ONLY thing here that cannot throw (an atomic CAS on a
        // member that already exists) — and it is the one thing that must happen, so an
        // internal fault is not audited as a client disconnect and the operator does not
        // go looking at the client for our bug.
        sink_->set_close_reason(McpStreamClose::kInternalError);
        // EVERYTHING else in this handler allocates: MetricsRegistry::counter() inserts a
        // map node on first use, and spdlog's formatter builds a string. We are here
        // because something threw — quite possibly bad_alloc — and a throw from inside a
        // catch handler propagates straight out of pump_once into an unguarded httplib
        // ThreadPool task, i.e. std::terminate. That is the exact hole this boundary
        // exists to close, so the best-effort part gets its own net.
        try {
            count_stream_close(metrics_, McpStreamClose::kInternalError);
            spdlog::warn("MCP stream pump: aborting stream after an exception");
        } catch (...) {  // NOLINT(bugprone-empty-catch) — nothing left we could safely do
        }
        return false; // httplib still runs the releaser → detach() → the lease comes back
    }
}

bool McpStreamPump::pump_once_impl(const WriteFn& write) {
    std::deque<sse_bus::SseEvent> drained;
    std::uint64_t dropped = 0;
    std::optional<sse_bus::SseEvent> pre_emit;
    {
        std::unique_lock<std::mutex> lk(sink_->sse->mu);
        sink_->sse->cv.wait_for(lk, cfg_.tick, [this] {
            return !sink_->sse->queue.empty() || sink_->sse->closed.load() ||
                   sink_->sse->pre_emit.has_value();
        });
        if (sink_->sse->closed.load()) {
            lk.unlock();
            // Reason was set by whoever closed us (takeover, DELETE, GC); if the
            // sink was closed without one, the peer went away.
            return finish(write, McpStreamClose::kClientGone);
        }
        if (sink_->sse->pre_emit.has_value()) {
            pre_emit = std::move(*sink_->sse->pre_emit);
            sink_->sse->pre_emit.reset();
        }
        drained.swap(sink_->sse->queue);
        dropped = sink_->sse->dropped_total.exchange(0, std::memory_order_relaxed);
    }
    // Everything below runs WITHOUT the sink mutex: a stalled socket write must
    // never block a publisher (which would hold McpStreamState::mu_ and in turn
    // stall attach/close for this session).

    // Credential re-validation, once per tick (Decision 15(c)/(i), CH-4).
    if (revalidate_) {
        switch (revalidate_()) {
        case StreamRevalidate::kRevoked:
            stream_->close(McpStreamClose::kCredentialRevoked);
            return finish(write, McpStreamClose::kCredentialRevoked);
        case StreamRevalidate::kIndeterminate:
            // The auth backend is unreachable — that is NOT a revocation. Ride it
            // out for a bounded grace window rather than cutting every live stream
            // on the fleet at the same instant. The deadline carries a per-stream
            // jitter chosen ONCE here, so streams that all entered grace together do
            // not all die together (Config::revalidate_grace_jitter_max).
            if (!grace_deadline_.has_value()) {
                grace_start_ = now();
                std::chrono::milliseconds jitter{0};
                if (cfg_.revalidate_grace_jitter_max.count() > 0) {
                    // A per-stream offset in [0, jitter_max]. thread_local RNG seeded once
                    // per worker; non-cryptographic — this only decorrelates timers, it
                    // guards nothing.
                    static thread_local std::minstd_rand rng{static_cast<std::uint32_t>(
                        std::chrono::steady_clock::now().time_since_epoch().count())};
                    // The modulo is done in the int64 (chrono::rep) domain and the span is
                    // clamped to a sane ceiling FIRST. The knob is hardwired to grace/2
                    // today, but if it ever becomes operator-controlled, a raw
                    // `static_cast<uint32>(count()) + 1` could wrap to 0 (div-by-zero) on a
                    // 32-bit result_type, or silently truncate a > UINT32_MAX-ms value.
                    // Contain it at the source now, not when the wiring lands.
                    constexpr std::int64_t kMaxJitterMs = 3600 * 1000; // one hour is plenty
                    const std::int64_t span =
                        std::min<std::int64_t>(cfg_.revalidate_grace_jitter_max.count(),
                                               kMaxJitterMs);
                    jitter = std::chrono::milliseconds{
                        static_cast<std::int64_t>(rng()) % (span + 1)};
                }
                grace_deadline_ = *grace_start_ + cfg_.revalidate_grace + jitter;
            } else if (now() > *grace_deadline_) {
                stream_->close(McpStreamClose::kAuthUnavailable);
                return finish(write, McpStreamClose::kAuthUnavailable);
            }
            break;
        case StreamRevalidate::kValid:
            grace_start_.reset();
            grace_deadline_.reset();
            break;
        }
    }

    // Session liveness. This is also the TTL slide: a genuinely-live stream keeps
    // its session young, so the registry's idle GC needs no live-stream exemption
    // (and a zombie peer stops ticking, so the normal TTL reclaims it).
    if (session_alive_ && !session_alive_()) {
        return finish(write, McpStreamClose::kSessionTerminated);
    }

    // Takeover fence: a newer GET owns this session's stream now.
    if (generation_ != stream_->current_generation()) {
        return finish(write, McpStreamClose::kSuperseded);
    }

    if (pre_emit.has_value()) {
        if (!write_all(write, sse_bus::format_sse(*pre_emit))) {
            return finish(write, McpStreamClose::kClientGone);
        }
    }
    if (dropped > 0) {
        // The sink queue overflowed. Tell the client — a silent gap is the one thing
        // this channel must never produce. But do NOT promise a replay we may not be
        // able to honour: the ring and the sink share a cap, so a consumer slow enough
        // to overflow the queue has usually also fallen out of the replay window, and
        // its reconnect will be answered with a 404 + re-initialize rather than the
        // frames it lost. Say both.
        // Field names match the `/api/v1/events` sibling's synthetic (dropped_count +
        // reason) — one taxonomy, not a per-route format.
        const sse_bus::SseEvent ev{
            "events-dropped",
            "{\"dropped_count\":" + std::to_string(dropped) +
                ",\"reason\":\"slow consumer — the per-connection queue overflowed\""
                ",\"remediation\":\"reconnect with Last-Event-ID; if the replay window has "
                "also passed you will get a 404 — re-initialize, durable results remain "
                "fetchable by execution_id\"}"};
        if (metrics_ != nullptr) {
            metrics_->counter(kMetricFramesDropped).increment(static_cast<double>(dropped));
        }
        if (!write_all(write, sse_bus::format_sse(ev))) {
            return finish(write, McpStreamClose::kClientGone);
        }
    }
    for (const auto& ev : drained) {
        // The id rides on the frame (SseEvent::id) — it is NOT parsed back out of the
        // payload. Re-parsing put a throwing stoull inside this callback, which httplib
        // runs on an unguarded worker task.
        // Ring frames carry an `id:` (SseEvent::id, emitted by the shared formatter) so a
        // broken stream can resume; heartbeats and synthetics carry none — resuming onto
        // a heartbeat's id would skip real frames.
        if (!write_all(write, sse_bus::format_sse(ev))) {
            return finish(write, McpStreamClose::kClientGone);
        }
    }

    static constexpr std::string_view kHeartbeat = "event: heartbeat\ndata: \n\n";
    if (!write_all(write, kHeartbeat)) {
        return finish(write, McpStreamClose::kClientGone);
    }
    return true;
}

// ── GET tail ────────────────────────────────────────────────────────────────

void handle_get_tail(const httplib::Request& req, httplib::Response& res,
                     const std::string& principal, McpSessionRegistry& sessions,
                     sse_bus::StreamBudget* budget, const StreamRevalidateFn& revalidate,
                     yuzu::MetricsRegistry* metrics, const StreamAuditFn& audit_fn,
                     std::size_t per_principal_cap, StreamAuditPrincipal audit_principal,
                     const StreamPrincipalAuditFn& principal_audit_fn) {
    const auto cid = yuzu::server::detail::make_correlation_id();
    const auto audit = [&](const char* action, const char* result, const std::string& target_id,
                           const std::string& detail) {
        return yuzu::server::detail::try_persist_audit(audit_fn, req, action, result, "McpSession",
                                                       target_id, detail);
    };
    const auto deny = [&](int status, int code, std::string_view message, const char* reason,
                          std::string_view remediation, std::optional<std::int64_t> retry_after_ms,
                          const std::string& sid) {
        // Only a prefix of the session id reaches the audit row — enough to join a
        // reject to its stream, never enough to replay it. Sanitized because the id is
        // an attacker-controlled HEADER until it validates: raw bytes here could inject
        // `;`/`=` field separators or CR/LF into a "k=v;k=v" audit detail that SIEM
        // tooling parses (yuzu::server::detail::sanitize_detail_value, the convention
        // for every externally-controlled audit string).
        (void)audit("mcp.session.reject", "failure",
                    yuzu::server::detail::sanitize_detail_value(sid.substr(0, 8)),
                    std::string("reason=") + reason + " cid=" + cid);
        count_reject(metrics, reason);
        res.status = status;
        // Retry-After header alongside the A4 retry_after_ms — the platform 429 convention
        // is BOTH (whole seconds, rounded up), and the three sibling surfaces set it. MCP
        // was the one surface that carried only the body field.
        if (retry_after_ms.has_value() && *retry_after_ms > 0) {
            const auto secs = (*retry_after_ms + 999) / 1000;
            res.set_header("Retry-After", std::to_string(secs));
        }
        res.set_content(error_response_null_a4(code, message, cid, remediation, retry_after_ms),
                        "application/json");
    };

    const std::string sid = req.get_header_value("Mcp-Session-Id");
    if (sid.empty()) {
        deny(400, kInvalidRequest, "Mcp-Session-Id header required", "missing_session_header",
             "initialize first, then send the returned Mcp-Session-Id on GET", std::nullopt, sid);
        return;
    }
    if (sessions.validate_and_touch(sid, principal) != McpSessionRegistry::ValidateResult::kValid) {
        // Unknown / expired / bound to another principal — one answer for all three
        // (no cross-principal existence oracle, Decision 15(a) / CH-8).
        deny(404, kMcpUnknownSession, "Unknown or expired session", "unknown_session",
             "re-initialize to mint a new session", std::nullopt, sid);
        return;
    }
    if (!transport::accept_wants_sse(req.get_header_value("Accept"))) {
        // Fail closed: the GET channel is SSE-only, so an Accept that does not opt
        // in is a client bug, not a reason to guess.
        deny(406, kMcpNotAcceptable, "GET /mcp/v1/ requires Accept: text/event-stream",
             "not_acceptable", "send Accept: text/event-stream", std::nullopt, sid);
        return;
    }

    const std::uint64_t last_event_id =
        parse_last_event_id(req.get_header_value("Last-Event-ID"));

    auto stream = sessions.stream_for(sid, principal);
    if (!stream) {
        deny(404, kMcpUnknownSession, "Unknown or expired session", "unknown_session",
             "re-initialize to mint a new session", std::nullopt, sid);
        return;
    }

    auto attached = stream->attach_and_replay(last_event_id, budget, principal, per_principal_cap);
    if (attached.status == McpStreamState::AttachStatus::kGap) {
        // The cursor's frames are gone. Terminate the session so the client's next
        // POST 404s too — one coherent "re-initialize" signal, and no abandoned
        // session lingering against the session cap.
        (void)sessions.terminate(sid, principal);
        (void)audit("mcp.session.close", "success",
                    yuzu::server::detail::sanitize_detail_value(sid.substr(0, 8)),
                    "reason=replay_window_exceeded cid=" + cid);
        count_reject(metrics, "replay_window_exceeded");
        res.status = 404;
        res.set_content(
            error_response_null_a4(kMcpUnknownSession, "Replay window exceeded", cid,
                                   "re-initialize; durable results remain fetchable by "
                                   "execution_id"),
            "application/json");
        return;
    }
    if (attached.status == McpStreamState::AttachStatus::kStreamCapHit) {
        const char* const cap_reason =
            attached.reject_reason != nullptr ? attached.reject_reason : "global_stream_cap";
        // Name the flag that can ACTUALLY resolve THIS reject. Telling a per-principal
        // reject to raise --max-sse-streams is inert (that is the global cap) and actively
        // misleading — the per-principal knob is --mcp-max-streams-per-principal.
        const bool per_principal =
            std::string_view(cap_reason) == sse_bus::StreamBudget::kRejectPerPrincipal;
        deny(429, kMcpStreamCap, "Concurrent stream cap reached", cap_reason,
             per_principal
                 ? "close one of your own SSE streams, or raise --mcp-max-streams-per-principal"
                 : "close an existing SSE stream, or raise --max-sse-streams",
             kMcpStreamCapRetryAfterMs, sid);
        return;
    }
    if (attached.status == McpStreamState::AttachStatus::kHandoverPending) {
        // A previous stream on this session was superseded and its provider has not
        // torn down yet. Admitting a third would let one client pin providers without
        // bound (each one holds a worker until it drains). Retry shortly — the
        // handover completes as soon as the old provider wakes.
        deny(429, kMcpStreamCap, "A previous stream on this session is still closing",
             "stream_handover_pending", "retry shortly; the superseded stream is draining",
             kMcpHandoverRetryAfterMs, sid);
        return;
    }

    auto sink = attached.sink;
    const std::uint64_t generation = attached.generation;

    // From here to set_chunked_content_provider, the sink is attached and its budget
    // lease is HELD, but the releaser that returns it is not installed yet. Everything
    // in between allocates (the Request copy, the pump, the audit strings), so a
    // bad_alloc would unwind out of the handler with the lease held forever: 16 of
    // those and MCP streaming is dead until restart. httplib guarantees the releaser
    // runs once installed (~Response calls it unconditionally) — this guard covers the
    // window before that guarantee starts.
    //
    // The guard is a POD, NOT a std::function: this lambda's captures exceed
    // libstdc++'s 16-byte small-object buffer, so wrapping it would heap-allocate —
    // planting a throw site inside the very window the guard exists to protect.
    struct LeaseGuard {
        McpStreamState* stream;
        const std::shared_ptr<McpStreamSink>* sink;
        bool installed = false;
        ~LeaseGuard() noexcept {
            if (!installed) {
                try {
                    stream->detach(*sink); // returns the lease first, then touches metrics
                } catch (...) {            // NOLINT(bugprone-empty-catch)
                    // detach() allocates (metric name temporaries), and this destructor
                    // runs while UNWINDING — a throw escaping here is a double fault, i.e.
                    // terminate. The lease is already home by then: detach() releases it
                    // before it touches metrics, and Lease's own destructor would return it
                    // regardless.
                }
            }
        }
    };
    LeaseGuard lease_guard{stream.get(), &sink};

    // Audit BEFORE the provider: set_chunked_content_provider seals the headers, so
    // Sec-Audit-Failed can only be set here (the /api/v1/events posture — signal the
    // evidence gap, then proceed; a transient audit hiccup must not silently drop an
    // operator's stream).
    if (!audit("mcp.stream.attach", "success",
               yuzu::server::detail::sanitize_detail_value(sid.substr(0, 8)),
               "cid=" + cid + " last_event_id=" + std::to_string(last_event_id) +
                   " generation=" + std::to_string(attached.generation))) {
        res.set_header("Sec-Audit-Failed", "true");
    }
    res.set_header("X-Correlation-Id", cid);
    res.set_header("Cache-Control", "no-cache");
    res.set_header("X-Accel-Buffering", "no");  // defeat reverse-proxy response buffering
    res.set_header("X-Content-Type-Options", "nosniff");

    // The provider and releaser run inside this request's lifetime, but pinning the
    // headers we re-validate against by copy costs one allocation and removes any
    // question of aliasing httplib's per-connection object across ticks.
    // (Never read req_copy->matches: its smatch iterators alias the ORIGINAL path.)
    auto req_copy = std::make_shared<httplib::Request>(req);
    const std::string audit_sid = yuzu::server::detail::sanitize_detail_value(sid.substr(0, 8));

    auto revalidate_fn = [req_copy, principal, revalidate]() -> StreamRevalidate {
        if (!revalidate) {
            return StreamRevalidate::kValid;  // test seam; production always wires this
        }
        return revalidate(*req_copy, principal);
    };
    // `sessions` is a ServerImpl member; stop() joins the web workers before any member
    // destructs, so no provider can outlive it.
    auto* registry = &sessions;
    auto session_alive = [registry, sid, principal]() {
        return registry->validate_and_touch(sid, principal) ==
               McpSessionRegistry::ValidateResult::kValid;
    };
    // Production config: spread the indeterminate-grace deadline by up to half the grace
    // window per stream, so a PG brownout does not drive the whole fleet's streams to die
    // at the same instant (Config::revalidate_grace_jitter_max — the default is 0 for
    // deterministic unit tests). At the 60 s default this spreads deaths over [60 s, 90 s].
    McpStreamPump::Config pump_cfg{};
    pump_cfg.revalidate_grace_jitter_max = pump_cfg.revalidate_grace / 2;
    auto pump = std::make_shared<McpStreamPump>(sink, stream, generation, std::move(revalidate_fn),
                                                std::move(session_alive), pump_cfg,
                                                McpStreamPump::ClockFn{}, metrics);

    res.set_chunked_content_provider(
        "text/event-stream",
        [pump](std::size_t /*offset*/, httplib::DataSink& s) {
            return pump->pump_once(
                [&s](const char* p, std::size_t n) { return s.write(p, n); });
        },
        // UP-1: adopt any pending engine QuotaSlot into this stream's releaser so the
        // per-principal CONCURRENCY reservation lasts for the stream's real lifetime.
        // `/mcp/v1/` is in is_streaming_path (principal_quota_gate.hpp), so pre-routing
        // stashes a slot in the thread_local and post-routing resets it unconditionally —
        // which fires before the streamed body ever runs. Without this adoption an engine
        // principal's MCP streams are bounded only by StreamBudget's per-principal cap,
        // and the configurable PrincipalQuota concurrency cap is silently bypassed on the
        // one surface it most exists to protect.
        //
        // The composition is re-wrapped in a noexcept guard. Note precisely what that
        // guard does and does not do: it CANNOT catch a throw from `slot->reset()`, and an
        // earlier version of this comment wrongly claimed it could. ~QuotaSlot is
        // implicitly noexcept (every subobject has a non-throwing destructor), so a throw
        // out of PrincipalQuota::release would call std::terminate INSIDE that destructor,
        // two frames within this try — no caller-side handler can intercept it. That path
        // is contained where it must be, at the source: QuotaSlot::reset() and
        // PrincipalQuota::release() are now noexcept by construction. This outer guard is
        // belt-and-braces for the rest of the composition (a bad_function_call, or a throw
        // from adopt_quota_slot_into_stream's own body), which is still worth having
        // because httplib invokes releasers from ~Response (#2037's class).
        [inner = yuzu::server::detail::adopt_quota_slot_into_stream(
             [stream, sink, audit_fn, principal_audit_fn, audit_principal, req_copy, audit_sid,
              cid](bool /*success*/) noexcept {
                // Runs from ~Response — a DESTRUCTOR. An exception escaping here is
                // std::terminate no matter what httplib does, so the whole body is guarded
                // (try_persist_audit swallows its own, but the string building allocates).
                try {
                    stream->detach(sink); // returns this provider's worker to the budget
                    // A teardown that never re-entered the pump leaves close_reason at
                    // kNone — and that is the MODAL case, not an edge one: httplib tests
                    // is_peer_alive() BEFORE invoking the provider, so an ordinary client
                    // disconnect is nearly always observed while the pump sits in its 3 s
                    // condvar wait, not as a failed write inside finish(). Auditing "none"
                    // there would emit a value outside the closed set documented in
                    // observability-conventions.md and pre-seeded in server.cpp, and would
                    // mean the reason vocabulary said nothing about the commonest close.
                    const auto reason = sink->close_reason.load();
                    const auto detail =
                        std::string("reason=") +
                        to_string(reason == McpStreamClose::kNone ? McpStreamClose::kClientGone
                                                                  : reason) +
                        " cid=" + cid + " role_as_of=attach";
                    // STAMP the principal rather than letting the sink re-derive it. The
                    // generic sink resolves the actor from the request when the row is
                    // written, and this row is written at teardown against the ORIGINAL
                    // attach request — so on a `credential_revoked` close the credential no
                    // longer resolves by definition and the row would name nobody. The rows
                    // that prove the revocation control would be exactly the rows missing
                    // their actor (SOC 2 CC6.2/CC7.2). Both values were captured at attach,
                    // while the credential was still good.
                    if (principal_audit_fn) {
                        (void)yuzu::server::detail::try_persist_audit_for_principal(
                            principal_audit_fn, *req_copy, "mcp.stream.close", "success",
                            audit_principal, "McpSession", audit_sid, detail);
                    } else {
                        // Test seams only — production wires the explicit-principal sink.
                        (void)yuzu::server::detail::try_persist_audit(
                            audit_fn, *req_copy, "mcp.stream.close", "success", "McpSession",
                            audit_sid, detail);
                    }
                } catch (...) {
                    // The lease is still returned: detach() is the first call, and Lease's
                    // destructor would return it even if that somehow threw.
                }
             })](bool success) noexcept {
            try {
                inner(success);
            } catch (...) {
                // Nothing to do but contain it — this frame is a destructor's callee.
            }
        });
    // The releaser now owns the lease's return path; the guard stands down.
    lease_guard.installed = true;
}

}  // namespace yuzu::server::mcp
