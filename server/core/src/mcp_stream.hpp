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
}

namespace yuzu::server::auth {
struct Session;
}

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

/// One frame in a session's replay ring.
struct McpStreamEvent {
    std::uint64_t id = 0;    ///< per-session, monotonic from 1
    std::string event_type;  ///< SSE `event:` — "message" for JSON-RPC frames (PR 3)
    std::string data;        ///< SSE `data:` payload
};

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
};
const char* to_string(McpStreamClose reason);

/// Tri-state credential re-validation (Decision 15(c)+(i)). The distinction is
/// load-bearing: kRevoked kills the stream NOW, kIndeterminate starts a bounded
/// grace window so an auth-backend blip does not cut every live stream at once.
enum class StreamRevalidate {
    kValid,
    kRevoked,
    kIndeterminate,
};

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

/// One live GET attachment: the reusable SSE sink plus the close-reason channel
/// the generic sink lacks. Heap-owned; shared by the provider, the release
/// callback, and (while live) the session's stream state.
struct McpStreamSink {
    std::shared_ptr<sse_bus::SseSinkState> sse = std::make_shared<sse_bus::SseSinkState>();
    std::atomic<McpStreamClose> close_reason{McpStreamClose::kNone};

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
                            yuzu::MetricsRegistry* metrics = nullptr);

    McpStreamState(const McpStreamState&) = delete;
    McpStreamState& operator=(const McpStreamState&) = delete;

    /// Append a frame to the ring and hand it to the live sink, if any. The
    /// producer seam for track 2f PR 3 (progress bridge) and for tests.
    /// Returns the assigned per-session event id.
    ///
    /// Drop-oldest at the ring cap; every eviction is counted (a client whose
    /// cursor falls behind the ring is 404'd on resume, never silently gapped).
    std::uint64_t publish(std::string event_type, std::string data);

    enum class AttachStatus {
        kAttached,
        kGap,             ///< cursor outside the ring window → caller 404s, client re-initializes
        kStreamCapHit,    ///< budget rejected → caller 429s
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
    /// newcomer supersedes it (generation bumped, old sink closed kSuperseded)
    /// and INHERITS its budget lease. The common second GET is a client
    /// reconnecting across a zombie TCP the server has not noticed yet;
    /// rejecting it would lock that client out for a full write-timeout, and
    /// requiring fresh budget headroom for a reconnect would make the cap
    /// self-inflicting.
    ///
    /// `budget == nullptr` disables admission control (test seams only —
    /// production always wires the shared budget).
    AttachResult attach_and_replay(std::uint64_t last_event_id, sse_bus::StreamBudget* budget,
                                   const std::string& principal);

    /// Close the live sink, if any (idempotent). Wakes the provider, which
    /// writes the final `stream-closed` frame and returns false. Never blocks on
    /// socket I/O — safe to call from the registry under a DELETE/GC.
    void close(McpStreamClose reason);

    /// Provider-release path. Releases the budget lease and clears the live sink
    /// iff `sink` is still the live one — a SUPERSEDED sink detaches without
    /// releasing, because its lease moved to the sink that replaced it.
    void detach(const std::shared_ptr<McpStreamSink>& sink);

    std::uint64_t current_generation() const;
    std::uint64_t next_event_id() const;    ///< id the next publish will assign
    std::uint64_t evictions_total() const;  ///< frames dropped from the ring (observability/tests)
    bool has_live_sink() const;

private:
    void close_locked(McpStreamClose reason);  ///< caller holds mu_

    mutable std::mutex mu_;
    std::deque<McpStreamEvent> ring_;
    std::size_t ring_cap_;
    std::uint64_t next_id_ = 1;  ///< CH-3: per-session, starts at 1
    std::uint64_t evictions_ = 0;
    std::uint64_t generation_ = 0;
    std::shared_ptr<McpStreamSink> live_;
    sse_bus::StreamBudget::Lease lease_;  ///< held while live_ != nullptr
    yuzu::MetricsRegistry* metrics_ = nullptr;
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
                  std::function<bool()> session_alive, Config cfg, ClockFn clock = {});

    /// One provider pass: wait up to a tick, re-validate, drain, heartbeat.
    /// Returns false when the stream is over (httplib then runs the release
    /// callback, which detaches the sink and audits the close reason).
    bool pump_once(const WriteFn& write);

private:
    bool finish(const WriteFn& write, McpStreamClose reason);
    std::chrono::steady_clock::time_point now() const;

    std::shared_ptr<McpStreamSink> sink_;
    std::shared_ptr<McpStreamState> stream_;
    std::uint64_t generation_;
    std::function<StreamRevalidate()> revalidate_;
    std::function<bool()> session_alive_;
    Config cfg_;
    ClockFn clock_;
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
