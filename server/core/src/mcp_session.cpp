#include "mcp_session.hpp"

#include <yuzu/server/auth.hpp>

#include <utility>

namespace yuzu::server::mcp {

McpSessionRegistry::McpSessionRegistry() : McpSessionRegistry(Config{}, {}) {}

McpSessionRegistry::McpSessionRegistry(Config cfg, ClockFn clock)
    : cfg_(cfg), clock_(std::move(clock)) {}

std::chrono::steady_clock::time_point McpSessionRegistry::now() const {
    return clock_ ? clock_() : std::chrono::steady_clock::now();
}

std::size_t McpSessionRegistry::principal_count_locked(const std::string& p) const {
    std::size_t n = 0;
    for (const auto& [id, e] : sessions_) {
        if (e.principal == p) {
            ++n;
        }
    }
    return n;
}

void McpSessionRegistry::gc_locked() {
    const auto cutoff = now();
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (cutoff - it->second.last_seen > cfg_.idle_ttl) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

void McpSessionRegistry::gc() {
    std::lock_guard<std::mutex> lk(mu_);
    gc_locked();
}

McpSessionRegistry::MintResult McpSessionRegistry::mint(const std::string& principal) {
    std::lock_guard<std::mutex> lk(mu_);
    gc_locked();  // reclaim idle sessions before enforcing caps

    if (sessions_.size() >= cfg_.global_cap) {
        return {false, {}, "global_cap"};
    }
    if (principal_count_locked(principal) >= cfg_.per_principal_cap) {
        return {false, {}, "per_principal_cap"};
    }

    // 16 CSPRNG bytes → 32 lowercase hex chars = 128-bit id. Regenerate on the
    // (astronomically unlikely) collision rather than overwrite a live session.
    std::string id;
    bool free_slot = false;
    for (int attempt = 0; attempt < 4; ++attempt) {
        id = auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(16));
        if (sessions_.find(id) == sessions_.end()) {
            free_slot = true;
            break;
        }
    }
    if (!free_slot) {
        // Four consecutive 128-bit CSPRNG collisions is impossible with a healthy
        // RNG; a degenerate/constant RNG is the only way here. Reject rather than
        // emplace onto an existing key (which would no-op yet report success,
        // binding the caller to a foreign entry) — keeps mint total (governance
        // CPP-I1 / UP-7).
        return {false, {}, "id_generation"};
    }
    const auto t = now();
    sessions_.emplace(id, Entry{principal, t, t});
    return {true, id, {}};
}

McpSessionRegistry::ValidateResult
McpSessionRegistry::validate_and_touch(const std::string& id, const std::string& principal) {
    std::lock_guard<std::mutex> lk(mu_);
    gc_locked();
    auto it = sessions_.find(id);
    if (it == sessions_.end()) {
        return ValidateResult::kUnknown;
    }
    // Wrong principal is indistinguishable from unknown (no existence oracle,
    // CH-8). The extra string compare vs. a straight miss is negligible against
    // network latency — "no gross timing divergence" per Decision 15(a).
    if (it->second.principal != principal) {
        return ValidateResult::kUnknown;
    }
    it->second.last_seen = now();
    return ValidateResult::kValid;
}

bool McpSessionRegistry::terminate(const std::string& id, const std::string& principal) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = sessions_.find(id);
    if (it == sessions_.end() || it->second.principal != principal) {
        return false;
    }
    sessions_.erase(it);
    return true;
}

std::size_t McpSessionRegistry::active_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return sessions_.size();
}

}  // namespace yuzu::server::mcp
