#include "mcp_session.hpp"

#include "mcp_stream.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <utility>

namespace yuzu::server::mcp {

namespace {
constexpr const char* kMetricSessionsActive = "yuzu_mcp_sessions_active";
constexpr const char* kMetricSessionsOpened = "yuzu_mcp_sessions_opened_total";
}  // namespace

McpSessionRegistry::McpSessionRegistry() : McpSessionRegistry(Config{}, {}, nullptr) {}

McpSessionRegistry::McpSessionRegistry(Config cfg, ClockFn clock, yuzu::MetricsRegistry* metrics)
    : cfg_(cfg), clock_(std::move(clock)), metrics_(metrics) {}

// Out-of-line: Entry holds a shared_ptr<McpStreamState>, an incomplete type at
// the header's point of definition.
McpSessionRegistry::~McpSessionRegistry() = default;

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

void McpSessionRegistry::refresh_active_gauge_locked() const {
    if (metrics_ != nullptr) {
        metrics_->gauge(kMetricSessionsActive).set(static_cast<double>(sessions_.size()));
    }
}

std::vector<std::shared_ptr<McpStreamState>> McpSessionRegistry::gc_locked() {
    std::vector<std::shared_ptr<McpStreamState>> reaped;
    const auto cutoff = now();
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (cutoff - it->second.last_seen > cfg_.idle_ttl) {
            // Collect, don't close: closing takes the stream's mutex, and a
            // publisher takes that mutex before touching a sink — so calling into a
            // stream while we hold mu_ would nest the two locks in the forbidden
            // order. The caller closes these after releasing mu_.
            reaped.push_back(std::move(it->second.stream));
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
    return reaped;
}

void McpSessionRegistry::gc() {
    std::vector<std::shared_ptr<McpStreamState>> reaped;
    {
        std::lock_guard<std::mutex> lk(mu_);
        reaped = gc_locked();
        refresh_active_gauge_locked();
    }
    for (const auto& s : reaped) {
        if (s) {
            s->close(McpStreamClose::kSessionTerminated);
        }
    }
}

McpSessionRegistry::MintResult McpSessionRegistry::mint(const std::string& principal) {
    std::vector<std::shared_ptr<McpStreamState>> reaped;
    MintResult result;
    {
        std::lock_guard<std::mutex> lk(mu_);
        reaped = gc_locked();  // reclaim idle sessions before enforcing caps

        if (sessions_.size() >= cfg_.global_cap) {
            result = {false, {}, "global_cap"};
        } else if (principal_count_locked(principal) >= cfg_.per_principal_cap) {
            result = {false, {}, "per_principal_cap"};
        } else {
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
                result = {false, {}, "id_generation"};
            } else {
                const auto t = now();
                sessions_.emplace(id, Entry{principal, t, t,
                                            std::make_shared<McpStreamState>(cfg_.ring_cap,
                                                                             metrics_)});
                if (metrics_ != nullptr) {
                    metrics_->counter(kMetricSessionsOpened).increment();
                }
                result = {true, id, {}};
            }
        }
        refresh_active_gauge_locked();
    }
    for (const auto& s : reaped) {
        if (s) {
            s->close(McpStreamClose::kSessionTerminated);
        }
    }
    return result;
}

McpSessionRegistry::ValidateResult
McpSessionRegistry::validate_and_touch(const std::string& id, const std::string& principal) {
    std::vector<std::shared_ptr<McpStreamState>> reaped;
    ValidateResult result = ValidateResult::kUnknown;
    {
        std::lock_guard<std::mutex> lk(mu_);
        reaped = gc_locked();
        auto it = sessions_.find(id);
        // Wrong principal is indistinguishable from unknown (no existence oracle,
        // CH-8). The extra string compare vs. a straight miss is negligible against
        // network latency — "no gross timing divergence" per Decision 15(a).
        if (it != sessions_.end() && it->second.principal == principal) {
            it->second.last_seen = now();
            result = ValidateResult::kValid;
        }
        refresh_active_gauge_locked();
    }
    for (const auto& s : reaped) {
        if (s) {
            s->close(McpStreamClose::kSessionTerminated);
        }
    }
    return result;
}

std::shared_ptr<McpStreamState> McpSessionRegistry::stream_for(const std::string& id,
                                                               const std::string& principal) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = sessions_.find(id);
    if (it == sessions_.end() || it->second.principal != principal) {
        return nullptr;  // same no-oracle answer as validate_and_touch
    }
    it->second.last_seen = now();
    return it->second.stream;
}

bool McpSessionRegistry::terminate(const std::string& id, const std::string& principal) {
    std::shared_ptr<McpStreamState> stream;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = sessions_.find(id);
        if (it == sessions_.end() || it->second.principal != principal) {
            return false;
        }
        stream = std::move(it->second.stream);
        sessions_.erase(it);
        refresh_active_gauge_locked();
    }
    // Outside mu_ (lock order, as in gc_locked). The stream state itself survives
    // until the live provider's release callback drops the last reference — the
    // erase above only removes the registry's.
    if (stream) {
        stream->close(McpStreamClose::kSessionTerminated);
    }
    return true;
}

std::size_t McpSessionRegistry::active_count() const {
    std::lock_guard<std::mutex> lk(mu_);
    return sessions_.size();
}

}  // namespace yuzu::server::mcp
