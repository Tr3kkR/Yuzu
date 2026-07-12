#include "mcp_stream.hpp"

#include "mcp_jsonrpc.hpp"
#include "mcp_session.hpp"
#include "mcp_transport.hpp"
#include "rest_a4_envelope.hpp"
#include "rest_audit.hpp"

#include <yuzu/metrics.hpp>

#include <algorithm>
#include <string_view>
#include <utility>

namespace yuzu::server::mcp {

namespace {

constexpr std::size_t kMaxWriteSlice = 8192;  // sibling parity (/api/v1/events)

// Metric names — the Decision 15(k) family, fixed at PR 0 so dashboards/alerts
// can be authored against them before the code lands.
constexpr const char* kMetricStreamsActive = "yuzu_mcp_streams_active";
constexpr const char* kMetricRingEvictions = "yuzu_mcp_stream_replay_ring_evictions_total";
constexpr const char* kMetricStreamRejects = "yuzu_mcp_stream_rejects_total";

void count_reject(yuzu::MetricsRegistry* metrics, const char* reason) {
    if (metrics != nullptr) {
        metrics->counter(kMetricStreamRejects, {{"reason", reason}}).increment();
    }
}

// SSE framing. Ring frames carry an `id:` so a broken stream can resume with
// `Last-Event-ID`; heartbeats and the close frame deliberately do NOT (they are
// not replayable state — resuming onto a heartbeat id would skip real frames).
std::string format_frame(const McpStreamEvent& ev) {
    std::string out = "id: ";
    out += std::to_string(ev.id);
    out += '\n';
    out += sse_bus::format_sse(sse_bus::SseEvent{ev.event_type, ev.data});
    return out;
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
    }
    return "unknown";
}

// ── McpStreamState ──────────────────────────────────────────────────────────

McpStreamState::McpStreamState(std::size_t ring_cap, yuzu::MetricsRegistry* metrics)
    : ring_cap_(ring_cap == 0 ? 1 : ring_cap), metrics_(metrics) {}

std::uint64_t McpStreamState::publish(std::string event_type, std::string data) {
    std::shared_ptr<McpStreamSink> live;
    std::uint64_t id = 0;
    std::string queued;  // "<id>\n<data>" — the sink queue's framing (see pump drain)
    std::string type;
    std::uint64_t evicted = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        id = next_id_++;
        ring_.push_back(McpStreamEvent{id, std::move(event_type), std::move(data)});
        while (ring_.size() > ring_cap_) {
            ring_.pop_front();
            ++evictions_;
            ++evicted;
        }
        const auto& ev = ring_.back();
        type = ev.event_type;
        queued = std::to_string(ev.id) + '\n' + ev.data;
        live = live_;
    }
    // Hand off to the sink outside mu_ (lock order mu_ → sink mu still holds; the
    // shorter the critical section, the less a slow attach blocks a publisher).
    if (live) {
        sse_bus::enqueue_capped(live->sse, sse_bus::SseEvent{std::move(type), std::move(queued)},
                               ring_cap_);
        live->sse->cv.notify_one();
    }
    if (evicted > 0 && metrics_ != nullptr) {
        metrics_->counter(kMetricRingEvictions).increment(static_cast<double>(evicted));
    }
    return id;
}

McpStreamState::AttachResult McpStreamState::attach_and_replay(std::uint64_t last_event_id,
                                                               sse_bus::StreamBudget* budget,
                                                               const std::string& principal) {
    AttachResult out;
    std::shared_ptr<McpStreamSink> superseded;
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

        // 2. Admission. A takeover inherits the superseded stream's lease (see
        //    header rationale); a first attach must be admitted by the budget.
        if (live_) {
            superseded = std::move(live_);
            live_.reset();
            superseded->set_close_reason(McpStreamClose::kSuperseded);
        } else if (budget != nullptr) {
            auto acquired = budget->try_acquire(principal);
            if (!acquired.lease) {
                out.status = AttachStatus::kStreamCapHit;
                out.reject_reason = acquired.reject_reason;
                return out;
            }
            lease_ = std::move(acquired.lease);
        }

        // 3. Replay + attach, under the same lock a publisher would need — so no
        //    frame can slip into the window between the two.
        auto sink = std::make_shared<McpStreamSink>();
        for (const auto& ev : ring_) {
            if (ev.id > last_event_id) {
                sse_bus::enqueue_capped(sink->sse,
                                       sse_bus::SseEvent{ev.event_type,
                                                        std::to_string(ev.id) + '\n' + ev.data},
                                       ring_cap_);
            }
        }
        live_ = sink;
        out.status = AttachStatus::kAttached;
        out.sink = sink;
        out.generation = ++generation_;
    }

    // Wake the superseded provider outside mu_ (lock order; it will write its
    // final frame and return false, releasing its worker).
    if (superseded) {
        superseded->sse->closed.store(true);
        superseded->sse->cv.notify_all();
    } else if (metrics_ != nullptr) {
        // Gauge counts LIVE streams: a takeover replaces one, it does not add one.
        metrics_->gauge(kMetricStreamsActive).increment();
    }
    return out;
}

void McpStreamState::close_locked(McpStreamClose reason) {
    if (!live_) {
        return;
    }
    live_->set_close_reason(reason);
    live_->sse->closed.store(true);
    live_->sse->cv.notify_all();
}

void McpStreamState::close(McpStreamClose reason) {
    std::lock_guard<std::mutex> lk(mu_);
    close_locked(reason);
    // The live sink is intentionally NOT cleared here: the provider is still
    // running and will call detach() on teardown, which is the single place the
    // budget lease is returned. Clearing it here would leak the lease.
}

void McpStreamState::detach(const std::shared_ptr<McpStreamSink>& sink) {
    bool released = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (live_ != sink) {
            return;  // superseded sink: its lease moved to the sink that replaced it
        }
        live_.reset();
        lease_.release();
        released = true;
    }
    if (released && metrics_ != nullptr) {
        metrics_->gauge(kMetricStreamsActive).decrement();
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

// ── McpStreamPump ───────────────────────────────────────────────────────────

McpStreamPump::McpStreamPump(std::shared_ptr<McpStreamSink> sink,
                             std::shared_ptr<McpStreamState> stream, std::uint64_t generation,
                             std::function<StreamRevalidate()> revalidate,
                             std::function<bool()> session_alive)
    : McpStreamPump(std::move(sink), std::move(stream), generation, std::move(revalidate),
                    std::move(session_alive), Config{}, {}) {}

McpStreamPump::McpStreamPump(std::shared_ptr<McpStreamSink> sink,
                             std::shared_ptr<McpStreamState> stream, std::uint64_t generation,
                             std::function<StreamRevalidate()> revalidate,
                             std::function<bool()> session_alive, Config cfg, ClockFn clock)
    : sink_(std::move(sink)), stream_(std::move(stream)), generation_(generation),
      revalidate_(std::move(revalidate)), session_alive_(std::move(session_alive)), cfg_(cfg),
      clock_(std::move(clock)) {}

std::chrono::steady_clock::time_point McpStreamPump::now() const {
    return clock_ ? clock_() : std::chrono::steady_clock::now();
}

bool McpStreamPump::finish(const WriteFn& write, McpStreamClose reason) {
    sink_->set_close_reason(reason);
    // Best-effort final frame: a client that is still readable learns WHY its
    // stream ended (Decision 15(f) — a close is never indistinguishable from a
    // clean completion). A dead peer simply fails the write; nothing to do.
    const std::string frame =
        sse_bus::format_sse(sse_bus::SseEvent{"stream-closed",
                                            std::string("{\"reason\":\"") +
                                                to_string(sink_->close_reason.load()) + "\"}"});
    (void)write_all(write, frame);
    return false;
}

bool McpStreamPump::pump_once(const WriteFn& write) {
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
            // on the fleet at the same instant.
            if (!grace_start_.has_value()) {
                grace_start_ = now();
            } else if (now() - *grace_start_ > cfg_.revalidate_grace) {
                stream_->close(McpStreamClose::kAuthUnavailable);
                return finish(write, McpStreamClose::kAuthUnavailable);
            }
            break;
        case StreamRevalidate::kValid:
            grace_start_.reset();
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
        // The sink queue overflowed, but the RING still holds those frames — tell
        // the client to reconnect with Last-Event-ID rather than pretend the gap
        // does not exist.
        const sse_bus::SseEvent ev{
            "events-dropped",
            "{\"dropped\":" + std::to_string(dropped) +
                ",\"remediation\":\"reconnect with Last-Event-ID to replay missed frames\"}"};
        if (!write_all(write, sse_bus::format_sse(ev))) {
            return finish(write, McpStreamClose::kClientGone);
        }
    }
    for (const auto& ev : drained) {
        // Queue payloads are framed "<id>\n<data>" by publish/replay.
        const std::size_t nl = ev.data.find('\n');
        McpStreamEvent frame;
        if (nl == std::string::npos) {
            frame = McpStreamEvent{0, ev.event_type, ev.data};
        } else {
            frame = McpStreamEvent{std::stoull(ev.data.substr(0, nl)), ev.event_type,
                                   ev.data.substr(nl + 1)};
        }
        if (!write_all(write, format_frame(frame))) {
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
                     yuzu::MetricsRegistry* metrics, const StreamAuditFn& audit_fn) {
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
        // reject to its stream, never enough to replay it (PR 1 convention).
        (void)audit("mcp.session.reject", "failure", sid.substr(0, 8),
                    std::string("reason=") + reason + " cid=" + cid);
        count_reject(metrics, reason);
        res.status = status;
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

    std::uint64_t last_event_id = 0;
    if (const std::string lei = req.get_header_value("Last-Event-ID"); !lei.empty()) {
        try {
            last_event_id = std::stoull(lei);
        } catch (const std::exception&) {
            last_event_id = 0;  // unparseable cursor → replay what we still hold
        }
    }

    auto stream = sessions.stream_for(sid, principal);
    if (!stream) {
        deny(404, kMcpUnknownSession, "Unknown or expired session", "unknown_session",
             "re-initialize to mint a new session", std::nullopt, sid);
        return;
    }

    auto attached = stream->attach_and_replay(last_event_id, budget, principal);
    if (attached.status == McpStreamState::AttachStatus::kGap) {
        // The cursor's frames are gone. Terminate the session so the client's next
        // POST 404s too — one coherent "re-initialize" signal, and no abandoned
        // session lingering against the session cap.
        (void)sessions.terminate(sid, principal);
        (void)audit("mcp.session.close", "success", sid.substr(0, 8),
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
        deny(429, kMcpStreamCap, "Concurrent stream cap reached",
             attached.reject_reason != nullptr ? attached.reject_reason : "global_stream_cap",
             "close an existing SSE stream, or raise --mcp-max-streams", kMcpStreamCapRetryAfterMs,
             sid);
        return;
    }

    // Audit BEFORE the provider: set_chunked_content_provider seals the headers,
    // so Sec-Audit-Failed can only be set here (the /api/v1/events posture —
    // signal the evidence gap, then proceed; a transient audit hiccup must not
    // silently drop an operator's stream).
    if (!audit("mcp.stream.attach", "success", sid.substr(0, 8),
               "correlation_id=" + cid + " last_event_id=" + std::to_string(last_event_id) +
                   " generation=" + std::to_string(attached.generation))) {
        res.set_header("Sec-Audit-Failed", "true");
    }
    res.set_header("X-Correlation-Id", cid);
    res.set_header("Cache-Control", "no-cache");
    res.set_header("X-Accel-Buffering", "no");  // defeat reverse-proxy response buffering
    res.set_header("X-Content-Type-Options", "nosniff");

    // The pump outlives this stack frame — copy what it needs. `req` is httplib's
    // per-connection object; the re-validation closure must not bet on it.
    auto req_copy = std::make_shared<httplib::Request>(req);
    auto sink = attached.sink;
    const std::uint64_t generation = attached.generation;

    auto revalidate_fn = [req_copy, principal, revalidate]() -> StreamRevalidate {
        if (!revalidate) {
            return StreamRevalidate::kValid;  // test seam; production always wires this
        }
        return revalidate(*req_copy, principal);
    };
    auto session_alive = [&sessions, sid, principal]() {
        return sessions.validate_and_touch(sid, principal) ==
               McpSessionRegistry::ValidateResult::kValid;
    };
    auto pump = std::make_shared<McpStreamPump>(sink, stream, generation, std::move(revalidate_fn),
                                                std::move(session_alive));

    res.set_chunked_content_provider(
        "text/event-stream",
        [pump](std::size_t /*offset*/, httplib::DataSink& s) {
            return pump->pump_once(
                [&s](const char* p, std::size_t n) { return s.write(p, n); });
        },
        [stream, sink, audit_fn, req_copy, sid, cid](bool /*success*/) {
            stream->detach(sink);
            (void)yuzu::server::detail::try_persist_audit(
                audit_fn, *req_copy, "mcp.stream.close", "success", "McpSession", sid.substr(0, 8),
                std::string("reason=") + to_string(sink->close_reason.load()) +
                    " correlation_id=" + cid);
        });
}

}  // namespace yuzu::server::mcp
