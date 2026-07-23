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

#include <array>
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
#include <string_view>

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

/// Floor for the ring byte cap. Below the size of the `frame_too_large` notice, every
/// publish would count as oversized and the ring would collapse to a single frame —
/// turning every resume into a gap.
inline constexpr std::size_t kMinRingBytesCap = 256;

/// Per-principal MCP stream allowance. A per-SURFACE policy, not a pool limit — the pool is
/// protected by the budget's global cap alone. This one exists to stop a single agentic
/// token monopolising the channel, not to ration capacity.
inline constexpr std::size_t kMcpStreamsPerPrincipalDefault = 4;

/// Max concurrent STREAMED-POST requests per session, and therefore the max eviction-exempt
/// (pinned) final-response frames the ring can hold at once (Decision 15(f): "one pending
/// response per streamed request"). The 2f progress bridge caps streamed records per session
/// at this number at ADMISSION, so publish_final never runs short of a pin slot; the
/// fixed-size pin array here is the ring-side enforcement of the same bound.
inline constexpr std::size_t kMaxStreamedPostsPerSession = 4;

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

/// Audit sink that STAMPS the principal explicitly instead of re-deriving it from the
/// request. Required for `mcp.stream.close`, and only for it.
///
/// The generic sink resolves the actor by calling `resolve_session(req)` when the row is
/// written. That is correct for a request-time audit, and wrong for a stream close: the
/// close audit runs at teardown against the ORIGINAL attach request, so on a
/// `credential_revoked` close the credential no longer resolves BY DEFINITION and the row
/// lands with an empty `principal`/`principal_role`. The rows that prove the revocation
/// control are exactly the rows that lose their actor (SOC 2 CC6.2/CC7.2).
///
/// The principal is known at attach time, so it is captured then and stamped here.
/// Empty = fall back to the generic sink (test seams; production wires it).
/// The actor, captured at attach. A struct rather than three more `const std::string&`
/// parameters on purpose: adjacent same-typed positional arguments can be transposed and
/// still compile, which no `is_invocable_r_v` static_assert can detect — it checks arity
/// and return type only. Named fields make a transposition a compile error.
struct StreamAuditPrincipal {
    std::string id;    ///< session->username — the stable authorization principal
    std::string role;  ///< role_to_string(effective_role(session)) AS OF ATTACH
    std::string cls;   ///< principal_class: "engine" for an engine principal, else by credential
};

using StreamPrincipalAuditFn = std::function<bool(
    const httplib::Request&, const std::string& action, const std::string& result,
    const StreamAuditPrincipal& principal, const std::string& target_type,
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
    ///
    /// HARD exception boundary (#2366). PR 3's progress bridge invokes this from an
    /// ExecutionEventBus listener running on a worker with no routing try/catch, so an
    /// escaped throw here is std::terminate (the #2037 class). `noexcept` is structural,
    /// not decorative (the stream_budget.hpp precedent): the boundary cannot be quietly
    /// dropped by a future edit without this signature failing loudly.
    ///
    /// Parameters are `string_view`, NOT `std::string` by value: a by-value parameter is
    /// copy-constructed in the CALLER's frame for an lvalue argument (the realistic PR 3
    /// call `publish(event.event_type, event.data)`), and a std::bad_alloc from that copy
    /// would escape to the unguarded listener BEFORE this function's body — bypassing the
    /// boundary entirely. `string_view` makes the caller-side conversion non-throwing; the
    /// owned copies happen inside publish_impl's try, where a bad_alloc is a clean
    /// pre-commit 0. The caller MUST keep the referenced storage alive across the call
    /// (publish copies synchronously before returning; it captures no view).
    ///
    /// Return contract:
    ///  - > 0: the frame is COMMITTED to the in-memory ring under this per-session id.
    ///    A post-commit failure (live-sink enqueue allocation, metrics) never un-commits:
    ///    the id is still returned, the frame stays replayable via Last-Event-ID, and a
    ///    sink-enqueue failure is made visible by bumping the sink's `dropped_total`
    ///    (the pump's existing `events-dropped` synthetic) — never a silent gap.
    ///  - == 0: pre-commit failure. Ring AND `next_id_` are untouched — no id hole, the
    ///    next publish assigns the id this call would have. 0 is never a valid frame id
    ///    (ids start at 1).
    ///
    /// CALLER OBLIGATION (asymmetric — a `0` is client-INVISIBLE): a pre-commit `0` bumps
    /// no `dropped_total`, so no `events-dropped` synthetic fires and no replay recovers
    /// the frame — it simply never existed. That is correct for a fire-and-forget progress
    /// delta. It is NOT sufficient for a TERMINAL/completion frame: a producer of one MUST
    /// NOT treat `publish()` as the delivery guarantee, because a `0` there leaves the
    /// client with no terminal and no gap signal. The durable `execution_id` fetch
    /// (Decision 15(f)) is the backstop, and track 2f PR 3 must wire it to a `0` return
    /// explicitly, not rely on general stream-death recovery.
    ///
    /// CONTRACT (Decision 15(b) — LOAD-BEARING): a published frame MUST be a message
    /// arising from THIS session's own requests. The GET channel is exempt from
    /// per-tool tier/RBAC gating precisely because it carries nothing else; a
    /// server-initiated or cross-session frame published here would reopen that
    /// question and the exemption would no longer hold.
    ///
    /// Drop-oldest at the frame AND byte caps; every eviction is counted (a client
    /// whose cursor falls behind the ring is 404'd on resume, never silently gapped).
    std::uint64_t publish(std::string_view event_type, std::string_view data) noexcept;

    /// Commit a frame to the ring for RESUME replay WITHOUT handing it to the live GET sink.
    ///
    /// Track 2f PR 3, Decision 15 + the MCP Streamable HTTP spec ("MUST NOT broadcast the
    /// same message across multiple streams"): a streamed POST delivers its frames on the
    /// POST stream, so publishing them onto a concurrently-live GET sink too would be a
    /// broadcast violation. The ring commit is purely so a GET resume (Last-Event-ID) can
    /// replay them — never a second live copy. Same return contract and boundary as publish().
    std::uint64_t publish_ring_only(std::string_view event_type, std::string_view data) noexcept;

    /// Commit a streamed request's FINAL response frame: ring-only (as publish_ring_only)
    /// AND eviction-EXEMPT (pinned) while the session lives, so a resume always recovers the
    /// terminal even after the ring wraps (Decision 15(f), bounded one pending per streamed
    /// request by kMaxStreamedPostsPerSession).
    ///
    /// The pin is written only AFTER the frame commits, so a pre-commit failure leaves no
    /// ghost pin and consumes no id. A committed final with no free pin slot (never expected —
    /// the bridge caps streamed records at the pin count) still commits, unpinned, rather
    /// than losing a real terminal. The pin is released by unpin() (final written on the POST
    /// wire), by attach_and_replay when a cursor proves consumption (Last-Event-ID >= its id),
    /// or with the whole object. Same return contract and boundary as publish().
    std::uint64_t publish_final(std::string_view event_type, std::string_view data) noexcept;

    /// Deterministic fault injection for publish() — TEST SEAM ONLY. The throw sites
    /// inside publish_impl are internal string/deque allocations with no callback to
    /// throw through (the repo's usual injection idiom), so the THREE failure phases the
    /// #2366 boundary distinguishes get explicit trip points instead. One-shot: the
    /// fault fires on the next publish and resets to kNone.
    enum class PublishFault {
        kNone,
        kPreCommit,    ///< models the ring push_back allocation failing (nothing committed)
        kSinkEnqueue,  ///< models the live-sink enqueue copy failing (frame already committed)
        /// Models the POST-COMMIT observability block (metric increment / WARN format)
        /// throwing after the frame is committed. Exercises publish_impl's innermost
        /// `catch(...)` — the guarantee that a metrics/log allocation fault never turns a
        /// committed publish into a 0 return. Fires inside that try, so it never reaches
        /// publish()'s outer boundary: publish returns the committed id.
        kPostCommitObservability,
    };
    /// `times` arms the same fault for the next N publishes (default 1 = the historical
    /// one-shot). Needed by the bridge's double-terminal-failure -> poison test: both the
    /// real-final and fallback-final publishes happen inside ONE projector pass, so the
    /// seam cannot be re-armed between them from the test thread.
    void inject_publish_fault_for_test(PublishFault fault, int times = 1);

    /// Set a short human-readable log prefix (e.g. the session id) included in publish()'s
    /// rare WARN lines so an operator can attribute a dropped/anomalous frame to a session.
    ///
    /// Threading: WRITE-ONCE, called at mint BEFORE the stream is shared with any other
    /// thread (McpSessionRegistry::mint, before the Entry is emplaced). Effectively
    /// immutable thereafter, so publish()'s reads need no lock — the registry mutex + the
    /// shared_ptr handoff at emplace are the happens-before edge to every later reader.
    /// Do NOT call it after the stream is live.
    void set_log_context(std::string context);

    enum class AttachStatus {
        kAttached,
        kGap,              ///< cursor outside the ring window → caller 404s, client re-initializes
        kStreamCapHit,     ///< budget rejected → caller 429s
        kHandoverPending,  ///< a superseded provider has not drained yet → caller 429s
        kPoisoned,         ///< terminal delivery failed twice → caller 410s, fetch by execution_id
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
                                   const std::string& principal,
                                   std::size_t per_principal_cap = kMcpStreamsPerPrincipalDefault);

    /// Close the live sink, if any (idempotent). Wakes the provider, which writes the
    /// final `stream-closed` frame and returns false. Never blocks on socket I/O —
    /// safe to call from the registry under a DELETE/GC.
    void close(McpStreamClose reason);

    /// Provider-release path: clears the sink (live OR draining) and returns the lease
    /// for the worker THAT sink was pinning. Idempotent.
    void detach(const std::shared_ptr<McpStreamSink>& sink);

    /// Release the eviction-exemption on a pinned final frame (unpin rule (a): the final was
    /// written on the POST wire). Idempotent — an unknown/already-cleared id is a no-op.
    void unpin(std::uint64_t id);

    /// True while `id` is a pinned (eviction-exempt) final frame. The 2f bridge sweep polls
    /// this: a parked (ring-only) record whose pin has gone — consumed via a GET resume that
    /// acked past it — can be torn down. Const, cheap (scans the fixed pin array under mu_).
    bool is_pinned(std::uint64_t id) const;

    /// Poison the session stream: no terminal frame could be delivered (publish_final failed
    /// twice) and the durable result must be fetched by execution_id instead. Sets a sticky
    /// flag so every FUTURE attach fast-fails (AttachStatus::kPoisoned → 410 + remediation)
    /// rather than a client re-attaching and heart-beating forever for a terminal that will
    /// never arrive, and closes any currently-live sink with kInternalError. Idempotent.
    void poison_terminal();

    std::size_t pinned_count() const;  ///< eviction-exempt frames currently held (observability/tests)

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

    /// The shared noexcept boundary for publish() / publish_ring_only() / publish_final().
    /// `deliver_live` hands the frame to the live GET sink (false = ring-only, for streamed
    /// POST frames); `pinned` marks a committed final eviction-exempt. One implementation of
    /// the #2366 hard boundary so the three public seams cannot drift.
    std::uint64_t publish_guarded(std::string_view event_type, std::string_view data,
                                  bool deliver_live, bool pinned) noexcept;

    /// The throwing body publish_guarded() guards. Owns the payload from the caller's views
    /// up front (those copies may throw — pre-commit, so a bad_alloc there is a clean 0).
    /// After the ring push + next_id_ advance, every step is either noexcept or locally
    /// contained, so a throw reaching the guard's catch proves nothing was committed and
    /// 0 is the honest return.
    std::uint64_t publish_impl(std::string_view event_type, std::string_view data,
                               bool deliver_live, bool pinned);

    /// True if `id` is a pinned final. Assumes mu_ is held (the eviction path and the public
    /// is_pinned() both funnel through it). Scans the fixed pin array — O(pin count).
    bool is_pinned_locked(std::uint64_t id) const;

    mutable std::mutex mu_;
    std::deque<McpStreamEvent> ring_;
    std::size_t ring_cap_;
    std::size_t ring_bytes_cap_;
    std::size_t ring_bytes_ = 0;
    std::uint64_t next_id_ = 1;  ///< CH-3: per-session, starts at 1
    std::uint64_t evictions_ = 0;
    std::uint64_t generation_ = 0;
    PublishFault publish_fault_ = PublishFault::kNone;  ///< test seam; guarded by mu_
    int publish_fault_remaining_ = 0;  ///< publishes left that consume publish_fault_; guarded by mu_
    // Write-once at mint before the stream is shared (set_log_context contract); read
    // unlocked in publish()'s WARN paths. Never mutated after the stream goes live.
    std::string log_context_;
    // Eviction-exempt (pinned) final-frame ids; 0 = empty slot. Fixed size = the per-session
    // streamed-request bound. All access under mu_. Decision 15(f).
    std::array<std::uint64_t, kMaxStreamedPostsPerSession> pinned_ids_{};
    bool terminal_poisoned_ = false;  ///< sticky; every future attach 410s (guarded by mu_)
    std::shared_ptr<McpStreamSink> live_;
    std::shared_ptr<McpStreamSink> draining_;  ///< superseded, still pinning its worker
    yuzu::MetricsRegistry* metrics_ = nullptr;
    // Resolved ONCE at construction. MetricsRegistry::gauge(name) allocates (a string
    // temporary for the name, plus a map node on first use) and takes the process-global
    // registry lock — neither is acceptable on a path that runs under mu_, and a throw
    // there would strand a sink that already holds a lease. The families live in
    // node-based maps, so these references are stable for the registry's life; a
    // Gauge::increment through them takes only that gauge's own mutex.
    /// Non-owning views into MetricsRegistry's node-based families: valid for the
    /// registry's life, and invalidated ONLY by `clear_gauge_family()` (which is never
    /// called on the `yuzu_mcp_streams_*` families — if that ever changes, these dangle).
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
        // Maximum extra grace ADDED per-stream, chosen once uniformly in
        // [0, revalidate_grace_jitter_max] when a stream first enters the indeterminate
        // grace window. Its whole purpose is to DE-SYNCHRONISE the mass kill: without it,
        // every stream's grace equals the token-cache TTL (60 s), so a PG brownout drives
        // every stream into grace within one tick of onset and they all die at onset+60 s
        // together — a simultaneous fleet-wide reconnect storm that re-floods the very
        // pool that is trying to recover (the substrate has NO SQLite fallback, ADR-0006).
        // Spreading the deadlines turns a cliff into a ramp. Grace only ever applies to
        // kIndeterminate (auth store unreachable), NEVER to a real revocation (which is an
        // immediate kill), so a longer grace can never keep a revoked credential alive —
        // this is a pure availability knob with no security cost.
        //
        // Defaults to 0 so the pump is DETERMINISTIC in unit tests; production wires a real
        // spread (half the grace). A stream picks its own offset once, so the spread is
        // stable for the life of that stream.
        std::chrono::milliseconds revalidate_grace_jitter_max{0};
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
    // The effective grace deadline for THIS stream's current indeterminate spell,
    // = grace_start_ + revalidate_grace + a per-stream jitter chosen once when
    // grace_start_ is set (see Config::revalidate_grace_jitter_max). Reset alongside
    // grace_start_ when the credential re-validates.
    std::optional<std::chrono::steady_clock::time_point> grace_deadline_;
};

/// The `GET /mcp/v1/` tail, called by `McpServer::build_get_handler` after its
/// PR-1 pre-checks (kill switch → streaming gate → Origin → auth). Owns every
/// denial (400/404/406/429), the attach audit, the response headers, and the
/// chunked provider wiring.
///
/// `budget` / `revalidate` may be null/empty in test seams; production wires
/// both (the registration path warns when they are missing).
///
/// `per_principal_cap` is the operator's `--mcp-max-streams-per-principal`. It is a
/// PARAMETER, not a constant read at the call site: threading it from Config is what
/// makes the flag do anything. It was previously hardcoded to the default here, so the
/// flag and its env var parsed, validated, logged and documented as a working control
/// while having no effect at all.
void handle_get_tail(const httplib::Request& req, httplib::Response& res,
                     const std::string& principal, McpSessionRegistry& sessions,
                     sse_bus::StreamBudget* budget, const StreamRevalidateFn& revalidate,
                     yuzu::MetricsRegistry* metrics, const StreamAuditFn& audit_fn,
                     std::size_t per_principal_cap = kMcpStreamsPerPrincipalDefault,
                     StreamAuditPrincipal audit_principal = {},
                     const StreamPrincipalAuditFn& principal_audit_fn = {});

}  // namespace yuzu::server::mcp
