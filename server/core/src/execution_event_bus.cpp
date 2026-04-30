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
        while (ch->buffer.size() > kBufferCap) ch->buffer.pop_front();
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

    // Opportunistic GC — runs at most every publish, but is guarded
    // by a timestamp check inside `gc_terminal_channels` so the cost
    // amortises to O(1) on the hot path.
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
    return removed;
}

} // namespace yuzu::server
