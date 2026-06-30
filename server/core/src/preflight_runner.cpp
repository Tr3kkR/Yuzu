#include "preflight_runner.hpp"

#include "preflight_eval.hpp"
#include "preflight_parse.hpp"
#include "preflight_run_store.hpp"

#include <chrono>

namespace yuzu::server {

PreflightRunner::PreflightRunner(Deps deps) : d_(std::move(deps)) {
    if (!d_.now_ms_fn) {
        d_.now_ms_fn = [] {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        };
    }
    if (d_.retention_days < 1)
        d_.retention_days = 14;
}

std::int64_t PreflightRunner::now_ms() const { return d_.now_ms_fn(); }

void PreflightRunner::tick() {
    if (!d_.run_store || !d_.run_store->is_open())
        return;
    const std::int64_t t = now_ms();

    // Retention prune (best-effort; cascades run_device).
    const std::int64_t cutoff = t - static_cast<std::int64_t>(d_.retention_days) * 86400000LL;
    d_.run_store->prune_older_than(cutoff);

    for (auto& run : d_.run_store->list_running()) {
        const auto cfg = preflight::config_from_json(run.config_json);
        auto targets = d_.run_store->get_targets(run.run_id);
        if (targets.empty()) {
            // A persisted run ALWAYS has ≥1 frozen target (create_run rejects an
            // empty cohort), so empty here means a transient read failure — skip
            // and retry next tick, NEVER complete (completing would lock in a
            // zero-device run). Recovery is the normal tick: once the store reads
            // again, an overdue run is processed + completed via the path below.
            continue;
        }

        const auto applicable = preflight::applicable_checks(cfg);
        std::vector<preflight::PreflightCheckResponses> checks;
        if (d_.response_store)
            checks = preflight::collect_check_responses(*d_.response_store, run.run_id, applicable);

        bool any_pending = false;
        auto grid = preflight::compute_device_results(targets, checks, cfg, &any_pending);

        const bool past_deadline = t >= run.deadline_at_ms;

        // Re-dispatch each applicable check to the not-yet-fully-answered targets
        // while inside the window. send_to drops offline agents silently.
        // LOAD-BEARING INVARIANT (#governance security): this re-dispatch reaches a
        // cohort FROZEN at creation, in the background, for up to the window, with
        // NO re-authorization — it is safe ONLY because every check is a READ-ONLY
        // plugin (idempotent). Any future check that MUTATES endpoint state must
        // NOT reuse this frozen cohort; it must re-resolve devices_fn(creator)∩group
        // authorization at each dispatch, or an operator who has since lost scope to
        // a device would still command it.
        if (!past_deadline && d_.dispatch_fn) {
            std::vector<std::string> pending;
            for (const auto& dr : grid)
                if (dr.bucket == preflight::Bucket::kIncomplete)
                    pending.push_back(dr.agent_id);
            if (!pending.empty()) {
                for (const auto& c : preflight::kPreflightChecks) {
                    if (!preflight::check_applicable(c.key, cfg))
                        continue;
                    d_.dispatch_fn(c.plugin, c.action, pending, "",
                                   preflight::dispatch_params(c.key, cfg),
                                   preflight::check_execution_id(run.run_id, c.key));
                }
            }
        }

        // Persist the grid + complete-when-settled. Shared with the live result
        // route (preflight::persist_and_maybe_complete) so a run completes the
        // moment its cohort settles on WHICHEVER path notices first — the route's
        // self-poll or this tick — and both build the grid identically.
        preflight::persist_and_maybe_complete(*d_.run_store, run.run_id, grid, t, past_deadline,
                                              any_pending);
    }
}

} // namespace yuzu::server
