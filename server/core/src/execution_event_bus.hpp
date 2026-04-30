#pragma once

/// @file execution_event_bus.hpp
///
/// PR 3 — per-execution SSE event bus for live drawer updates.
///
/// Distinct from `detail::EventBus` (global pub/sub keyed only by event_type):
/// `ExecutionEventBus` partitions subscribers by `execution_id` so that one
/// running execution's transitions never spray onto another execution's SSE
/// connections. Each per-execution channel carries its own ring buffer
/// (default 1000 events, ~30 s) so a client that disconnects and reconnects
/// inside the replay window resumes without missing transitions.
///
/// Threading model:
///   - `publish` is called from `ExecutionTracker::update_agent_status`
///     (status writer) and `mark_cancelled` — both synchronous w.r.t. the
///     mutating gRPC writer threads. `publish` therefore must not block.
///   - `subscribe` / `unsubscribe` are called from the SSE handler running
///     on the httplib request thread.
///   - All listeners run under the per-execution mutex; the listener body
///     should be short — typically queue-and-notify on a per-connection
///     `SseSinkState`.
///
/// Bounded memory: per execution, the ring buffer caps at `kBufferCap`
/// entries; old entries are dropped FIFO. When an execution reaches a
/// terminal state, the channel is held for `kRetentionAfterTerminalSec`
/// so a late client can still replay the final transitions, then dropped.
/// `gc_terminal_channels` performs the cleanup; the server calls it on
/// a periodic tick (or on every `publish`, opportunistically).

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

struct ExecutionEvent {
    /// Monotonic id within the per-execution channel — used by
    /// `Last-Event-ID` replay. Stable across reconnects.
    std::uint64_t id{0};
    /// Wall-clock timestamp (epoch ms). Cheap to compute, useful for
    /// the buffer-retention TTL check.
    std::int64_t timestamp_ms{0};
    /// SSE `event:` field. Examples: `agent-transition`,
    /// `execution-progress`, `execution-completed`.
    std::string event_type;
    /// SSE `data:` payload — typically a one-line JSON object.
    std::string data;
};

class ExecutionEventBus {
public:
    using Listener = std::function<void(const ExecutionEvent&)>;

    static constexpr std::size_t kBufferCap = 1000;
    static constexpr std::int64_t kRetentionAfterTerminalSec = 60;

    ExecutionEventBus() = default;
    ~ExecutionEventBus() = default;

    ExecutionEventBus(const ExecutionEventBus&) = delete;
    ExecutionEventBus& operator=(const ExecutionEventBus&) = delete;

    /// Subscribe to a per-execution channel. Returns a subscription token
    /// scoped to `execution_id` — tokens from different channels are not
    /// comparable. Listener is invoked synchronously from `publish`.
    std::size_t subscribe(const std::string& execution_id, Listener listener);

    /// Unsubscribe a token previously returned by `subscribe`. Idempotent;
    /// silently no-ops if the channel or sub_id no longer exists.
    void unsubscribe(const std::string& execution_id, std::size_t sub_id);

    /// Publish an event onto a per-execution channel. Assigns a monotonic
    /// id, appends to the ring buffer (evicting the oldest if at cap),
    /// then fans out to listeners under the channel mutex.
    ///
    /// `is_terminal` marks the execution as having reached completion;
    /// the channel keeps the buffer for `kRetentionAfterTerminalSec` so
    /// late reconnects can replay, then is GC'd on next sweep.
    void publish(const std::string& execution_id, const std::string& event_type,
                 const std::string& data, bool is_terminal = false);

    /// Replay buffered events with `id > since_id` in arrival order.
    /// Used by the SSE handler on connect when the client supplied a
    /// `Last-Event-ID` header. The walk runs under the channel mutex
    /// to keep the replay consistent with concurrent publishers.
    void replay_since(const std::string& execution_id, std::uint64_t since_id,
                      const Listener& listener) const;

    /// Snapshot of ring-buffer contents — used by tests to assert
    /// retention/eviction behaviour. Cheap O(N) copy.
    std::vector<ExecutionEvent> snapshot(const std::string& execution_id) const;

    /// Number of active subscribers on a given channel. Returns 0 for
    /// unknown executions. Safe to call concurrently with publish.
    std::size_t subscriber_count(const std::string& execution_id) const;

    /// Number of distinct execution channels currently held in memory.
    std::size_t channel_count() const;

    /// Drop channels that reached terminal state more than
    /// `kRetentionAfterTerminalSec` ago AND have no live subscribers.
    /// Returns the number of channels collected. Called opportunistically
    /// from `publish` so callers don't need to wire a periodic timer.
    std::size_t gc_terminal_channels();

private:
    struct Channel {
        mutable std::mutex mu;
        std::uint64_t next_id{1};
        std::deque<ExecutionEvent> buffer;
        std::unordered_map<std::size_t, Listener> listeners;
        std::size_t next_sub_id{0};
        bool terminal{false};
        std::int64_t terminal_at_ms{0};
    };

    /// Returns the channel pointer, allocating it if missing. The shared
    /// channel map mutex is held only briefly; callers then take the
    /// per-channel `mu` for the actual work.
    std::shared_ptr<Channel> get_or_create(const std::string& execution_id);

    /// Lookup-only — returns nullptr if the channel is absent.
    std::shared_ptr<Channel> find(const std::string& execution_id) const;

    static std::int64_t now_ms() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::system_clock::now().time_since_epoch())
            .count();
    }

    mutable std::shared_mutex map_mu_;
    std::unordered_map<std::string, std::shared_ptr<Channel>> channels_;
};

} // namespace yuzu::server
