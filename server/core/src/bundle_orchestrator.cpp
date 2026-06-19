#include "bundle_orchestrator.hpp"

#include "response_store.hpp" // ResponseStore, ResponseQuery, StoredResponse

#include <algorithm>
#include <chrono>
#include <utility>

namespace yuzu::server {

namespace {
std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
} // namespace

BundleOrchestrator::BundleOrchestrator(DispatchFn dispatch, ResponseStore* response_store,
                                       IdMinter mint)
    : dispatch_(std::move(dispatch)), response_store_(response_store), mint_(std::move(mint)) {}

void BundleOrchestrator::evict_expired_locked(std::int64_t now) {
    for (auto it = manifests_.begin(); it != manifests_.end();) {
        if (now - it->second.created_at_ms > kManifestTtlMs)
            it = manifests_.erase(it);
        else
            ++it;
    }
}

BundleOrchestrator::DispatchResult
BundleOrchestrator::dispatch(const std::string& agent_id, const std::vector<BundleStepSpec>& steps,
                             const std::string& principal, const AuditSink& audit) {
    const std::string correlation = std::string(kCorrelationPrefix) + mint_();

    std::vector<DispatchedStep> dispatched;
    dispatched.reserve(steps.size());
    for (const auto& s : steps) {
        std::unordered_map<std::string, std::string> params;
        params.reserve(s.params.size());
        for (const auto& [k, v] : s.params)
            params[k] = v;

        // Fan out as an ORDINARY command under the shared correlation id (the
        // agent never sees a "bundle" — just a normal plugin/action).
        auto [command_id, sent] =
            dispatch_(s.plugin, s.action, {agent_id}, /*scope=*/"", params, correlation);
        const bool ok = sent > 0 && !command_id.empty();

        dispatched.push_back(DispatchedStep{ok ? command_id : std::string{}, s.plugin, s.action});

        // Per-step audit under its own verb (transport-agnostic; works-council
        // countability). plugin/action are validated [a-z0-9_] upstream so the
        // verb cannot be forged. target_type="Agent" so device-access audit
        // queries see bundle rows (governance compliance F1). "dispatched"
        // records access-intent, not outcome.
        if (audit) {
            audit("bundle." + s.plugin + "." + s.action, ok ? "dispatched" : "no_agents", "Agent",
                  agent_id, "correlation_id=" + correlation);
        }
    }

    {
        const std::int64_t now = now_ms();
        std::lock_guard lock(mu_);
        evict_expired_locked(now);
        // Bound the in-memory footprint: if still at the cap after expiry
        // eviction, drop the oldest manifest (most likely already collected /
        // abandoned) rather than reject a command set we have already sent.
        if (manifests_.size() >= kMaxManifests) {
            auto oldest = std::min_element(
                manifests_.begin(), manifests_.end(),
                [](const auto& a, const auto& b) { return a.second.created_at_ms < b.second.created_at_ms; });
            if (oldest != manifests_.end())
                manifests_.erase(oldest);
        }
        manifests_[correlation] = Manifest{std::move(dispatched), principal, agent_id, now};
    }

    return DispatchResult{correlation, steps.size()};
}

std::optional<BundleAggregate>
BundleOrchestrator::collate(const std::string& correlation_id, const std::string& principal,
                            bool is_admin) {
    std::vector<DispatchedStep> steps;
    {
        std::lock_guard lock(mu_);
        evict_expired_locked(now_ms());
        auto it = manifests_.find(correlation_id);
        if (it == manifests_.end())
            return std::nullopt; // unknown / expired
        // Ownership: only the dispatcher (or an admin) may collate. nullopt is
        // indistinguishable from not-found so existence isn't an enumeration
        // oracle (the wrapper audits the real reason).
        if (it->second.dispatched_by != principal && !is_admin)
            return std::nullopt;
        steps = it->second.steps; // copy so we release mu_ before the DB read
    }

    if (!response_store_)
        return std::nullopt;

    ResponseQuery rq;
    rq.limit = 1000; // bundle <= kMaxBundleSteps; well under the cap
    rq.status = -1;  // any status (step results may ride RUNNING or terminal rows)
    auto rows = response_store_->query_by_execution(correlation_id, rq);

    std::vector<BundleResponseRow> brows;
    brows.reserve(rows.size());
    for (const auto& r : rows)
        brows.push_back(BundleResponseRow{r.instruction_id, r.status, r.output});

    return aggregate_bundle(steps, brows);
}

} // namespace yuzu::server
