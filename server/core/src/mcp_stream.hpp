#pragma once

/// @file mcp_stream.hpp
/// MCP Streamable HTTP GET SSE channel (ADR-1005 Decision 15, track 2f PR 2).
///
/// The `GET /mcp/v1/` channel a client attaches to a session it minted on
/// `initialize`. It carries the server→client half of that session: heartbeats,
/// a bounded per-session replay ring for `Last-Event-ID` resume, and (from
/// track 2f PR 3) the `notifications/progress` frames the streamed-POST bridge
/// publishes. In PR 2 nothing produces frames yet — `publish()` is the seam PR 3
/// and the tests write through.
///
/// Invariants this module owns (governance: security-guardian / cpp-safety):
///   * Event ids are PER-SESSION, monotonic from 1, never global (Decision
///     15(j) / CH-3). A restart or re-initialize gets a fresh namespace.
///   * The replay ring is BOUNDED (Decision 15(d)). A cursor whose frames have
///     been evicted is never silently gapped: the caller 404s and the client
///     re-initializes, refetching durable state by `execution_id`.
///   * A live stream re-validates its credential every heartbeat tick and dies
///     within one tick of a revocation (Decision 15(c)); an INDETERMINATE auth
///     backend (a blip, not a revocation) gets a bounded grace window instead of
///     a mass kill (Decision 15(i)).
///   * Concurrency is admission-controlled through the shared
///     `sse_bus::StreamBudget` — one budget across every held-open SSE response
///     on the shared httplib worker pool (Decision 15(h)).
///
/// LOCK ORDER (both classes): `McpStreamState::mu_` → `SseSinkState::mu`.
/// Never the reverse. The pump therefore releases the sink mutex before calling
/// back into `McpStreamState`, and no socket write ever happens under either
/// mutex (a stalled peer must not block a publisher).

#include "event_bus.hpp"
#include "stream_budget.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

#include <httplib.h>

namespace yuzu {
class MetricsRegistry;
class Gauge;
}

namespace yuzu::server::auth {
struct Session;
// Defined in <yuzu/server/auth.hpp>. Opaquely forward-declared (the underlying
// type is pinned there, so this is well-formed) to keep the MCP stream header off
// the auth header's include cost.
enum class CredentialCheck : int;
}  // namespace yuzu::server::auth

namespace yuzu::server::mcp {

// `yuzu::server::mcp::detail` already exists (mcp_jsonrpc.hpp), so an unqualified
// `detail::` inside this namespace resolves to THAT one and never finds the SSE
// primitives in `yuzu::server::detail`. Alias the outer namespace explicitly —
// and not as `sse`, which is already a member name on McpStreamSink.
namespace sse_bus = ::yuzu::server::detail;

class McpSessionRegistry;

/// Replay-ring capacity per session. Matches `sse_bus::kPerConnectionQueueCapDefault`
/// so a full-ring replay fits the sink queue exactly and cannot trip the sink's
/// own drop-oldest guard (which would gap a resume that the ring could satisfy).
inline constexpr std::size_t kMcpRingCapDefault = sse_bus::kPerConnectionQueueCapDefault;

/// Heartbeat / re-validation tick. Matches the `/api/v1/events` cadence — short
/// enough to keep intermediaries from idling the connection out, and it is the
/// bound on "a revoked stream dies within one tick" (CH-4).
inline constexpr std::chrono::milliseconds kMcpStreamTickDefault{3000};

/// Grace window for an INDETERMINATE re-validation (auth backend unreachable —
/// NOT a revocation). Equal to `ApiTokenStore::kTokenCacheTtl` (60 s): a blip
/// shorter than the token cache's own TTL can never kill a stream, because a
/// cached token would not have re-hit the backend within that window anyway
/// (Decision 15(i) — no mass kill on a blip).
inline constexpr std::chrono::milliseconds kMcpRevalidateGraceDefault{60000};

/// `retry_after_ms` on a stream-cap 429. Honest, not aspirational: a slot frees
/// only when a live stream ends, and a dead peer is detected within one tick
/// (3 s) plus its socket write failure — so a retry sooner than this cannot
/// succeed for a capacity reason.
inline constexpr std::int64_t kMcpStreamCapRetryAfterMs = 5000;

/// `retry_after_ms` when a session's previous stream is still draining.
///
/// The common case clears in microseconds: the superseded provider is woken under its
/// own mutex and returns without writing. But if it was caught mid-write to a peer that
/// has stopped reading — the exact case a takeover exists to rescue — it does not
/// re-enter until httplib's `wait_writable` gives up, bounded by the 30 s write timeout.
/// So this hint is deliberately the same as the capacity hint rather than an optimistic
/// half-second that would have a flaky client 429-storming us sixty times while it
/// dutifully obeyed our own advice.
inline constexpr std::int64_t kMcpHandoverRetryAfterMs = 5000;

/// Ring / sink frames are the shared `detail::SseEvent` (whose `id` field carries
/// the per-session event id). Deliberately NOT a bespoke type: the id used to be
/// packed into `data` as a `"<id>\n<payload>"` string and re-parsed in the provider,
/// which put a throwing `stoull` inside a content-provider callback — and httplib
/// runs those on an unguarded worker task, where an escaped exception is
/// `std::terminate`, not a 500.
using McpStreamEvent = sse_bus::SseEvent;

/// Byte cap on a session's replay ring, enforced alongside the frame cap. The frame
/// count alone is not a memory bound: 1024 sessions × 500 frames is only a bound if
/// you also know what a frame weighs. 64 KiB/session keeps the fleet-wide worst case
/// at ~64 MiB rather than the ~250 MiB an unbounded-size 500-frame ring would allow
/// at PR-3 progress-frame sizes (Decision 15(d): ALL in-memory state bounded).
inline constexpr std::size_t kMcpRingBytesCapDefault = 64 * 1024;

/// Why a stream ended. Wire-visible (the final `stream-closed` frame), audited
/// (`mcp.stream.close` `reason=`), and distinct per CH-4 — a client must be able
/// to tell "your credential was revoked" from "our auth backend is down".
enum class McpStreamClose {
    kNone,               ///< still open
    kClientGone,         ///< peer disconnected / write failed
    kSuperseded,         ///< a newer GET took the session's stream over
    kSessionTerminated,  ///< DELETE, idle GC, or replay-window termination
    kCredentialRevoked,  ///< re-validation said the credential is definitively gone
    kAuthUnavailable,    ///< re-validation was indeterminate past the grace window
    kInternalError,      ///< the pump caught an exception — OUR fault, not the client's
};
const char* to_string(McpStreamClose reason);

/// Tri-state credential re-validation (Decision 15(c)+(i)). The distinction is
/// load-bearing: kRevoked kills the stream NOW, kIndeterminate starts a bounded
/// grace window so an auth-backend blip does not cut every live stream at once.
///
/// This is an ALIAS of the auth layer's own type, not an MCP-specific one: the
/// answer is produced by auth and merely consumed here, and the next held-open
/// surface to want per-tick re-validation (`/api/v1/events`, #2056) must not have
/// to name an MCP type to get it.
using StreamRevalidate = auth::CredentialCheck;

/// Re-validate the credential that opened a stream, against the principal the
/// stream is bound to. Takes the ORIGINAL request (the handler keeps a copy —
/// the pump runs long after httplib's stack frame is gone).
using StreamRevalidateFn = std::function<StreamRevalidate(const httplib::Request& original_req,
                                                          const std::string& expected_principal)>;

/// Audit sink, shape-identical to `McpServer::AuditFn` (declared here so this
/// module does not depend on mcp_server.hpp — the dependency runs the other way).
using StreamAuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                         const std::string& result, const std::string& target_type,
                                         const std::string& target_id, const std::string& detail)>;

/// One live GET attachment: the reusable SSE sink, the close-reason channel the
/// generic sink lacks, and THE BUDGET LEASE FOR THE WORKER THIS ATTACHMENT PINS.
///
/// The lease lives here, not on the session: an httplib worker is pinned per
/// held-open RESPONSE, and a superseded response keeps pinning its worker until it
/// drains. Charging the lease to the session instead would leave those workers
/// uncounted — which is how a single client hammering GET on one session could
/// exhaust the pool while the cap still read 1.
///
/// Heap-owned; shared by the provider, the release callback, and (while live or
/// draining) the session's stream state.
struct McpStreamSink {
    std::shared_ptr<sse_bus::SseSinkState> sse = std::make_shared<sse_bus::SseSinkState>();
    std::atomic<McpStreamClose> close_reason{McpStreamClose::kNone};
    sse_bus::StreamBudget::Lease lease;  ///< released exactly once, in McpStreamState::detach

    /// First reason wins — a revocation already recorded must not be overwritten
    /// by the client-gone the teardown then observes.
    void set_close_reason(McpStreamClose reason) {
        McpStreamClose expected = McpStreamClose::kNone;
        close_reason.compare_exchange_strong(expected, reason);
    }
};

/// Per-session stream state: bounded replay ring + at-most-one live sink + the
/// budget lease held while a sink is live.
///
/// Owned by `shared_ptr` from BOTH the session registry entry and the provider
/// closures, so a DELETE/GC that erases the session never races the live
/// provider's teardown — the state outlives the registry entry until the last
/// closure drops it.
class McpStreamState {
public:
    explicit McpStreamState(std::size_t ring_cap = kMcpRingCapDefault,
                            yuzu::MetricsRegistry* metrics = nullptr,
                            std::size_t ring_bytes_cap = kMcpRingBytesCapDefault);

    McpStreamState(const McpStreamState&) = delete;
    McpStreamState& operator=(const McpStreamState&) = delete;
    // Holds a mutex, so it is already non-movable — say so, and a future member
    // reorder cannot silently make it movable while providers hold raw references.
    McpStreamState(McpStreamState&&) = delete;
    McpStreamState& operator=(McpStreamState&&) = delete;

    /// Append a frame to the ring and hand it to the live sink, if any. The
    /// producer seam for track 2f PR 3 (progress bridge) and for tests.
    /// Returns the assigned per-session event id.
    ///
    /// CONTRACT (Decision 15(b) — LOAD-BEARING): a published frame MUST be a message
    /// arising from THIS session's own requests. The GET channel is exempt from
    /// per-tool tier/RBAC gating precisely because it carries nothing else; a
    /// server-initiated or cross-session frame published here would reopen that
    /// question and the exemption would no longer hold.
    ///
    /// Drop-oldest at the frame AND byte caps; every eviction is counted (a client
    /// whose cursor falls behind the ring is 404'd on resume, never silently gapped).
    std::uint64_t publish(std::string event_type, std::string data);

    enum class AttachStatus {
        kAttached,
        kGap,              ///< cursor outside the ring window → caller 404s, client re-initializes
        kStreamCapHit,     ///< budget rejected → caller 429s
        kHandoverPending,  ///< a superseded provider has not drained yet → caller 429s
    };

    struct AttachResult {
        AttachStatus status = AttachStatus::kGap;
        std::shared_ptr<McpStreamSink> sink;  ///< engaged iff kAttached
        std::uint64_t generation = 0;         ///< this attachment's generation (takeover fence)
        const char* reject_reason = nullptr;  ///< static literal iff kStreamCapHit
    };

    /// Resume-check + admission + replay + attach, ATOMICALLY under one mutex.
    ///
    /// Doing all four under a single lock closes the replay→subscribe race the
    /// `/api/v1/events` sibling documents (a frame published between its replay
    /// and its subscribe is lost): here nothing can be published into the gap,
    /// because a publisher needs the same mutex.
    ///
    /// Takeover, not reject-second: if the session already has a live sink, the
    /// newcomer supersedes it (generation bumped, old sink closed kSuperseded) and is
    /// admitted WITHOUT a cap check — the common second GET is a client reconnecting
    /// across a zombie TCP the server has not noticed yet, and making it wait for its
    /// own zombie to time out would turn the cap into a self-inflicted lockout.
    ///
    /// It still takes its OWN lease (the superseded provider keeps pinning its worker
    /// until it drains, and an uncounted pinned worker is exactly the hole this budget
    /// exists to close). The pool is bounded structurally instead: a session holds at
    /// most one draining sink, so at most two providers — a second takeover while a
    /// handover is still pending returns kHandoverPending, and `derive_stream_budget`
    /// reserves `kMaxProvidersPerStream` workers for every permitted stream.
    ///
    /// `budget == nullptr` disables admission control (test seams only —
    /// production always wires the shared budget).
    AttachResult attach_and_replay(std::uint64_t last_event_id, sse_bus::StreamBudget* budget,
                                   const std::string& principal);

    /// Close the live sink, if any (idempotent). Wakes the provider, which writes the
    /// final `stream-closed` frame and returns false. Never blocks on socket I/O —
    /// safe to call from the registry under a DELETE/GC.
    void close(McpStreamClose reason);

    /// Provider-release path: clears the sink (live OR draining) and returns the lease
    /// for the worker THAT sink was pinning. Idempotent.
    void detach(const std::shared_ptr<McpStreamSink>& sink);

    std::uint64_t current_generation() const;
    std::uint64_t next_event_id() const;    ///< id the next publish will assign
    std::uint64_t evictions_total() const;  ///< frames dropped from the ring (observability/tests)
    bool has_live_sink() const;
    bool has_draining_sink() const;         ///< a superseded provider has not torn down yet

private:
    /// Close a sink, setting `closed` UNDER its mutex (it is the pump's wait
    /// predicate — an atomic store outside the lock races the pump's
    /// release-and-block and the wakeup is lost). Never blocks on I/O; never called
    /// while holding mu_.
    static void close_sink(const std::shared_ptr<McpStreamSink>& sink, McpStreamClose reason);
    static std::size_t frame_bytes(const McpStreamEvent& ev);

    mutable std::mutex mu_;
    std::deque<McpStreamEvent> ring_;
    std::size_t ring_cap_;
    std::size_t ring_bytes_cap_;
    std::size_t ring_bytes_ = 0;
    std::uint64_t next_id_ = 1;  ///< CH-3: per-session, starts at 1
    std::uint64_t evictions_ = 0;
    std::uint64_t generation_ = 0;
    std::shared_ptr<McpStreamSink> live_;
    std::shared_ptr<McpStreamSink> draining_;  ///< superseded, still pinning its worker
    yuzu::MetricsRegistry* metrics_ = nullptr;
    // Resolved ONCE at construction. MetricsRegistry::gauge(name) allocates (a string
    // temporary for the name, plus a map node on first use) and takes the process-global
    // registry lock — neither is acceptable on a path that runs under mu_, and a throw
    // there would strand a sink that already holds a lease. The families live in
    // node-based maps, so these references are stable for the registry's life; a
    // Gauge::increment through them takes only that gauge's own mutex.
    yuzu::Gauge* gauge_streams_active_ = nullptr;
    yuzu::Gauge* gauge_streams_handover_ = nullptr;
};

/// The content-provider body of one live GET stream.
///
/// `pump_once` is the test seam: it takes a `WriteFn` rather than an
/// `httplib::DataSink`, so the whole stream lifecycle (heartbeats, revocation,
/// grace window, replay drain, close frames) is unit-testable without standing
/// up an httplib server — which the server suite must not do (TSan acceptor
/// crash, #438).
class McpStreamPump {
public:
    struct Config {
        std::chrono::milliseconds tick = kMcpStreamTickDefault;
        std::chrono::milliseconds revalidate_grace = kMcpRevalidateGraceDefault;
    };

    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;
    using WriteFn = std::function<bool(const char*, std::size_t)>;

    // Two ctors rather than a `Config cfg = {}` default argument: Config's default
    // member initializers cannot be consumed by `= {}` while the enclosing class is
    // still incomplete (GCC rejects it — the same shape documented on
    // McpSessionRegistry). The short form delegates where Config is complete.
    McpStreamPump(std::shared_ptr<McpStreamSink> sink, std::shared_ptr<McpStreamState> stream,
                  std::uint64_t generation, std::function<StreamRevalidate()> revalidate,
                  std::function<bool()> session_alive);
    McpStreamPump(std::shared_ptr<McpStreamSink> sink, std::shared_ptr<McpStreamState> stream,
                  std::uint64_t generation, std::function<StreamRevalidate()> revalidate,
                  std::function<bool()> session_alive, Config cfg, ClockFn clock = {},
                  yuzu::MetricsRegistry* metrics = nullptr);

    /// One provider pass: wait up to a tick, re-validate, drain, heartbeat.
    /// Returns false when the stream is over (httplib then runs the release
    /// callback, which detaches the sink and audits the close reason).
    ///
    /// NEVER THROWS. httplib runs a chunked content provider from a bare ThreadPool
    /// task — outside the try/catch that wraps `routing()` — so an escaped exception
    /// here is `std::terminate`, not a 500 (the #2037 failure class). The body is
    /// wrapped; do not unwrap it. Re-validation alone reaches SQLite and the auth
    /// manager, both of which can throw.
    bool pump_once(const WriteFn& write);

private:
    bool pump_once_impl(const WriteFn& write); ///< the throwing body pump_once() guards
    bool finish(const WriteFn& write, McpStreamClose reason);
    std::chrono::steady_clock::time_point now() const;

    std::shared_ptr<McpStreamSink> sink_;
    std::shared_ptr<McpStreamState> stream_;
    std::uint64_t generation_;
    std::function<StreamRevalidate()> revalidate_;
    std::function<bool()> session_alive_;
    Config cfg_;
    ClockFn clock_;
    yuzu::MetricsRegistry* metrics_ = nullptr;
    std::optional<std::chrono::steady_clock::time_point> grace_start_;
};

/// The `GET /mcp/v1/` tail, called by `McpServer::build_get_handler` after its
/// PR-1 pre-checks (kill switch → streaming gate → Origin → auth). Owns every
/// denial (400/404/406/429), the attach audit, the response headers, and the
/// chunked provider wiring.
///
/// `budget` / `revalidate` may be null/empty in test seams; production wires
/// both (the registration path warns when they are missing).
void handle_get_tail(const httplib::Request& req, httplib::Response& res,
                     const std::string& principal, McpSessionRegistry& sessions,
                     sse_bus::StreamBudget* budget, const StreamRevalidateFn& revalidate,
                     yuzu::MetricsRegistry* metrics, const StreamAuditFn& audit_fn);

}  // namespace yuzu::server::mcp
