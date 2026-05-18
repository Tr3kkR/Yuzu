#pragma once

/// @file event_bus.hpp
/// SSE event pub/sub bus for server-side events.
/// Header-only — small enough that a separate TU adds no value.

#include <cstddef>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <atomic>
#include <cstring>

#include <httplib.h>

namespace yuzu::server::detail {

// -- SSE Event ----------------------------------------------------------------

struct SseEvent {
    std::string event_type;
    std::string data;
};

// -- SSE Event Bus ------------------------------------------------------------

class EventBus {
public:
    using Listener = std::function<void(const SseEvent&)>;

    std::size_t subscribe(Listener fn) {
        std::lock_guard<std::mutex> lock(mu_);
        auto id = next_id_++;
        listeners_[id] = std::move(fn);
        return id;
    }

    void unsubscribe(std::size_t id) {
        std::lock_guard<std::mutex> lock(mu_);
        listeners_.erase(id);
    }

    void publish(const std::string& event_type, const std::string& data) {
        SseEvent ev{event_type, data};
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& [id, fn] : listeners_) {
            fn(ev);
        }
    }

    std::size_t listener_count() const {
        std::lock_guard<std::mutex> lock(mu_);
        return listeners_.size();
    }

private:
    mutable std::mutex mu_;
    std::size_t next_id_ = 0;
    std::unordered_map<std::size_t, Listener> listeners_;
};

// -- SSE sink state (per-connection, shared with content provider) -------------

/// Default per-connection queue cap, used by routes that opt into slow-
/// consumer protection. A slow / blackholed TCP consumer can otherwise
/// grow `SseSinkState::queue` without bound (publisher runs synchronously
/// under the bus channel mutex, listener enqueues, content provider may
/// not drain for 3 s+ during `wait_for` waits). With ~hundreds of
/// agentic clients per server, an unbounded queue is the primary memory
/// growth risk on this path. 500 events is roughly half of
/// `ExecutionEventBus::kBufferCap` — large enough to absorb a normal
/// burst, small enough that a stalled consumer is dropped before any
/// realistic OOM. governance round unhappy-R3 / sre-OBS-MED.
inline constexpr std::size_t kPerConnectionQueueCapDefault = 500;

struct SseSinkState {
    std::mutex mu;
    std::condition_variable cv;
    std::deque<SseEvent> queue;
    std::atomic<bool> closed = false;
    std::size_t sub_id = 0;
    /// Total events dropped from the per-connection queue (drop-oldest
    /// on cap overflow). Routes that enforce a cap use this counter to
    /// emit a synthetic `events-dropped` envelope on the next provider
    /// invocation so the client knows a gap exists. Routes that do NOT
    /// enforce a cap leave this at 0. Atomic so the listener
    /// (publisher thread) and provider (httplib worker thread) can both
    /// touch it without taking `mu`.
    std::atomic<std::uint64_t> dropped_total{0};
};

/// Enqueue with drop-oldest cap. Routes that opt into slow-consumer
/// protection call this from their bus listener instead of a raw
/// `queue.push_back`. Lives next to `SseSinkState` so it's directly
/// unit-testable; the `/api/v1/events` handler calls it via a capturing
/// lambda. Holds the per-connection mutex, no condition_variable notify
/// (the caller controls that — replay shouldn't wake the provider).
inline void enqueue_capped(const std::shared_ptr<SseSinkState>& state, SseEvent ev,
                           std::size_t cap = kPerConnectionQueueCapDefault) {
    std::lock_guard<std::mutex> lk(state->mu);
    while (state->queue.size() >= cap) {
        state->queue.pop_front();
        state->dropped_total.fetch_add(1, std::memory_order_relaxed);
    }
    state->queue.push_back(std::move(ev));
}

// -- SSE helpers --------------------------------------------------------------

// Format an SSE message.  The SSE spec requires every line of a multi-line
// data field to carry its own "data: " prefix; the browser's EventSource
// parser re-joins them with '\n'.  Without this, embedded newlines in agent
// output cause silent truncation — only the first line reaches the browser.
inline std::string format_sse(const SseEvent& ev) {
    std::string out;
    out += "event: ";
    out += ev.event_type;
    out += '\n';
    std::string_view d{ev.data};
    if (d.empty()) {
        out += "data: \n";
    } else {
        std::size_t pos = 0;
        while (pos < d.size()) {
            auto nl = d.find('\n', pos);
            out += "data: ";
            out.append(d.substr(pos, (nl == std::string_view::npos ? d.size() : nl) - pos));
            out += '\n';
            if (nl == std::string_view::npos)
                break;
            pos = nl + 1;
        }
    }
    out += '\n'; // blank line terminates the event
    return out;
}

// -- SSE content provider callback --------------------------------------------

inline bool sse_content_provider(const std::shared_ptr<SseSinkState>& state, size_t /*offset*/,
                                 httplib::DataSink& sink) {
    std::unique_lock<std::mutex> lk(state->mu);
    // Keep the interval well under httplib's Keep-Alive timeout (5s)
    // to prevent the browser from closing the SSE connection due to
    // inactivity.
    state->cv.wait_for(lk, std::chrono::seconds(3),
                       [&state] { return !state->queue.empty() || state->closed.load(); });

    if (state->closed.load()) {
        return false;
    }

    while (!state->queue.empty()) {
        auto& ev = state->queue.front();
        std::string sse = format_sse(ev);
        // httplib's chunked provider assembles each sink.write() into a
        // single HTTP chunk frame (hex-size + CRLF + data + CRLF) and
        // flushes it in one send() call — the browser processes each chunk
        // eagerly.  Write in <=8 KB slices to stay within typical TCP send
        // buffer limits and avoid partial-write failures.
        const char* p = sse.data();
        size_t rem = sse.size();
        constexpr size_t kMaxSlice = 8192;
        while (rem > 0) {
            auto n = std::min(rem, kMaxSlice);
            if (!sink.write(p, n))
                return false;
            p += n;
            rem -= n;
        }
        state->queue.pop_front();
    }

    const char* keepalive = "event: heartbeat\ndata: \n\n";
    if (!sink.write(keepalive, std::strlen(keepalive))) {
        return false;
    }
    return true;
}

inline void sse_resource_release(const std::shared_ptr<SseSinkState>& state, EventBus& bus,
                                 bool /*success*/) {
    state->closed.store(true);
    state->cv.notify_all();
    bus.unsubscribe(state->sub_id);
}

} // namespace yuzu::server::detail
