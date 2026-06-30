#include "deployment_engine.hpp"

#include "deployment_run_store.hpp"

#include <chrono>

namespace yuzu::server::deployment {

namespace {

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

void advance(const EngineDeps& deps, const std::string& deployment_id, const DeploymentConfig& cfg,
             const std::unordered_set<std::string>& authorized) {
    if (deps.store == nullptr || deployment_id.empty())
        return;

    auto grid = deps.store->get_devices(deployment_id);

    // ── 1. Poll the stage + execute responses (no store lease held) ──────────
    std::unordered_map<std::string, AgentResponse> stage_resp, exec_resp;
    if (deps.poll_fn) {
        stage_resp = deps.poll_fn(stage_execution_id(deployment_id));
        exec_resp = deps.poll_fn(exec_execution_id(deployment_id));
    }

    // ── 2. Response-derived transitions, GUARDED on the source step ──────────
    // A device only moves out of 'staging'/'executing' when ITS phase response is
    // terminal; the store UPDATE re-checks the source step, so a concurrent advance
    // that already moved it is a no-op.
    std::vector<DeviceTransition> transitions;
    for (const auto& d : grid) {
        const Step s = step_from_token(d.step);
        if (s == Step::kStaging) {
            auto it = stage_resp.find(d.agent_id);
            if (it == stage_resp.end())
                continue;
            const StageResult r = parse_stage(it->second.status, it->second.output);
            if (r.outcome == PhaseOutcome::kOk)
                transitions.push_back({d.agent_id, "staging", "staged", 0, ""});
            else if (r.outcome == PhaseOutcome::kFailed)
                transitions.push_back({d.agent_id, "staging", "failed", 0, r.error});
        } else if (s == Step::kExecuting) {
            auto it = exec_resp.find(d.agent_id);
            if (it == exec_resp.end())
                continue;
            const ExecResult r = parse_exec(it->second.status, it->second.output);
            if (r.outcome == PhaseOutcome::kOk)
                transitions.push_back({d.agent_id, "executing", "succeeded", r.exit_code, ""});
            else if (r.outcome == PhaseOutcome::kFailed)
                transitions.push_back({d.agent_id, "executing", "failed", r.exit_code, r.error});
        }
    }
    if (!transitions.empty())
        deps.store->apply_results(deployment_id, transitions);

    // ── 3. Re-read on fresh state for the dispatch decisions ─────────────────
    grid = deps.store->get_devices(deployment_id);

    // ── 4. Skip out-of-scope devices (pending/staged, never executed) ────────
    std::vector<std::string> skip;
    for (const auto& d : grid) {
        const Step s = step_from_token(d.step);
        if ((s == Step::kPending || s == Step::kStaged) && authorized.find(d.agent_id) == authorized.end())
            skip.push_back(d.agent_id);
    }
    if (!skip.empty())
        deps.store->mark_skipped(deployment_id, skip);

    // ── 5. CAS-claim + dispatch STAGE to authorized 'pending' devices ────────
    if (deps.dispatch_fn) {
        std::vector<std::string> cand;
        for (const auto& d : grid)
            if (step_from_token(d.step) == Step::kPending &&
                authorized.find(d.agent_id) != authorized.end())
                cand.push_back(d.agent_id);
        auto claimed = deps.store->claim_for_stage(deployment_id, cand);
        if (!claimed.empty())
            deps.dispatch_fn("content_dist", "stage", claimed, "",
                             {{"url", cfg.url}, {"filename", cfg.filename}, {"sha256", cfg.sha256}},
                             stage_execution_id(deployment_id));
    }

    // ── 6. CAS-claim + dispatch EXECUTE to authorized 'staged' devices ───────
    // claim_for_exec is the execute-once guard: only rows still 'staged' are
    // claimed + dispatched, exactly once across concurrent advances / restart.
    if (deps.dispatch_fn) {
        std::vector<std::string> cand;
        for (const auto& d : grid)
            if (step_from_token(d.step) == Step::kStaged &&
                authorized.find(d.agent_id) != authorized.end())
                cand.push_back(d.agent_id);
        auto claimed = deps.store->claim_for_exec(deployment_id, cand);
        if (!claimed.empty()) {
            std::unordered_map<std::string, std::string> params{{"filename", cfg.filename},
                                                                {"expected_hash", cfg.sha256}};
            if (!cfg.args.empty())
                params["args"] = cfg.args;
            deps.dispatch_fn("content_dist", "execute_staged", claimed, "", params,
                             exec_execution_id(deployment_id));
        }
    }

    // ── 7. Recompute summary + complete if every device is settled ───────────
    deps.store->refresh_counts(deployment_id);
    deps.store->complete_deployment(deployment_id, now_ms());
}

} // namespace yuzu::server::deployment
