#include "execution_event_bus.hpp"

#include <algorithm>

namespace yuzu::server {

std::shared_ptr<ExecutionEventBus::Channel>
ExecutionEventBus::get_or_create(const std::string& execution_id) {
    {
        std::shared_lock<std::shared_mutex> rl(map_mu_);
        auto it = channels_.find(execution_id);
        if (it != channels_.end()) return it->second;
    }
    std::unique_lock<std::shared_mutex> wl(map_mu_);
    // Re-check after upgrading — another thread may have inserted while
    // we were waiting for the unique lock.
    auto it = channels_.find(execution_id);
    if (it != channels_.end()) return it->second;
    auto ch = std::make_shared<Channel>();
    channels_.emplace(execution_id, ch);
    return ch;
}

std::shared_ptr<ExecutionEventBus::Channel>
ExecutionEventBus::find(const std::string& execution_id) const {
    std::shared_lock<std::shared_mutex> rl(map_mu_);
    auto it = channels_.find(execution_id);
    return it == channels_.end() ? nullptr : it->second;
}

std::size_t ExecutionEventBus::subscribe(const std::string& execution_id, Listener listener) {
    auto ch = get_or_create(execution_id);
    std::lock_guard<std::mutex> g(ch->mu);
    auto id = ++ch->next_sub_id;
    ch->listeners.emplace(id, std::move(listener));
    return id;
}

void ExecutionEventBus::unsubscribe(const std::string& execution_id, std::size_t sub_id) {
    auto ch = find(execution_id);
    if (!ch) return;
    std::lock_guard<std::mutex> g(ch->mu);
    ch->listeners.erase(sub_id);
}

void ExecutionEventBus::publish(const std::string& execution_id, const std::string& event_type,
                                const std::string& data, bool is_terminal) {
    auto ch = get_or_create(execution_id);

    ExecutionEvent ev;
    ev.event_type = event_type;
    ev.data = data;
    ev.timestamp_ms = now_ms();

    {
        std::lock_guard<std::mutex> g(ch->mu);
        ev.id = ch->next_id++;
        ch->buffer.push_back(ev);
        while (ch->buffer.size() > kBufferCap) {
            ch->buffer.pop_front();
            // OBS-3: per-channel ring overflow counter, aggregated bus-wide.
            // Operators tune kBufferCap (or upgrade to per-execution sizing
            // — see Deferred-1 / issue #696) when this counter starts moving.
            events_dropped_.fetch_add(1, std::memory_order_relaxed);
        }
        if (is_terminal && !ch->terminal) {
            ch->terminal = true;
            ch->terminal_at_ms = ev.timestamp_ms;
        }
        // Fan out under the channel mutex — listeners must not block.
        // The intended pattern is queue-and-notify on a per-connection
        // SseSinkState, which is non-blocking.
        for (auto& [_, fn] : ch->listeners) {
            fn(ev);
        }
    }

    // Opportunistic GC. Throttled to at most once per kMinGcIntervalMs
    // (perf-B2) — the previous comment claimed amortised O(1) but no
    // throttle existed; every publish walked the entire channels_ map.
    gc_terminal_channels();
}

void ExecutionEventBus::replay_since(const std::string& execution_id, std::uint64_t since_id,
                                     const Listener& listener) const {
    auto ch = find(execution_id);
    if (!ch) return;
    std::lock_guard<std::mutex> g(ch->mu);
    for (const auto& ev : ch->buffer) {
        if (ev.id > since_id) listener(ev);
    }
}

std::vector<ExecutionEvent>
ExecutionEventBus::snapshot(const std::string& execution_id) const {
    auto ch = find(execution_id);
    if (!ch) return {};
    std::lock_guard<std::mutex> g(ch->mu);
    return std::vector<ExecutionEvent>(ch->buffer.begin(), ch->buffer.end());
}

std::size_t ExecutionEventBus::subscriber_count(const std::string& execution_id) const {
    auto ch = find(execution_id);
    if (!ch) return 0;
    std::lock_guard<std::mutex> g(ch->mu);
    return ch->listeners.size();
}

std::size_t ExecutionEventBus::channel_count() const {
    std::shared_lock<std::shared_mutex> rl(map_mu_);
    return channels_.size();
}

std::size_t ExecutionEventBus::gc_terminal_channels() {
    auto now = now_ms();

    // perf-B2 throttle. The previous comment claimed amortised O(1) but
    // no throttle existed — every publish walked all channels_, took
    // each per-channel lock, and dropped under contention. Now the full
    // sweep runs at most once per kMinGcIntervalMs; the early-return
    // path is a single relaxed atomic load + compare.
    auto last_gc = last_gc_at_ms_.load(std::memory_order_relaxed);
    if (now - last_gc < kMinGcIntervalMs) {
        return 0;
    }

    auto deadline = now - kRetentionAfterTerminalSec * 1000;

    // First pass: collect candidates under the read lock so we never
    // hold the write lock while inspecting per-channel state.
    std::vector<std::string> victims;
    {
        std::shared_lock<std::shared_mutex> rl(map_mu_);
        victims.reserve(channels_.size());
        for (const auto& [id, ch] : channels_) {
            std::lock_guard<std::mutex> g(ch->mu);
            if (ch->terminal && ch->terminal_at_ms <= deadline && ch->listeners.empty()) {
                victims.push_back(id);
            }
        }
    }

    // Stamp the sweep timestamp regardless of whether anything was
    // actually collected — we paid the O(channels) inspection cost,
    // throttle should reflect that. OBS-3: increment sweeps counter.
    last_gc_at_ms_.store(now, std::memory_order_relaxed);
    gc_sweeps_.fetch_add(1, std::memory_order_relaxed);

    if (victims.empty()) return 0;

    std::size_t removed = 0;
    std::unique_lock<std::shared_mutex> wl(map_mu_);
    for (const auto& id : victims) {
        auto it = channels_.find(id);
        if (it == channels_.end()) continue;
        // Re-check terminal+empty under the per-channel mutex — a late
        // subscriber may have joined between the two passes.
        std::lock_guard<std::mutex> g(it->second->mu);
        if (it->second->terminal && it->second->terminal_at_ms <= deadline &&
            it->second->listeners.empty()) {
            channels_.erase(it);
            ++removed;
        }
    }
    if (removed > 0) {
        gc_channels_.fetch_add(removed, std::memory_order_relaxed);
    }
    return removed;
}

std::size_t ExecutionEventBus::subscribers_total() const {
    std::size_t total = 0;
    std::shared_lock<std::shared_mutex> rl(map_mu_);
    for (const auto& [_, ch] : channels_) {
        std::lock_guard<std::mutex> g(ch->mu);
        total += ch->listeners.size();
    }
    return total;
}

} // namespace yuzu::server
