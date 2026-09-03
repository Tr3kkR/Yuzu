#include "deployment_engine.hpp"

#include "deployment_run_store.hpp"
#include "response_store.hpp" // StoredResponse (best_response_per_agent)

#include <chrono>
#include <cstdint>

namespace yuzu::server::deployment {

namespace {

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

int response_score(const StoredResponse& r) {
    int s = 0;
    if (r.status != 0) // 0 = RUNNING; terminal beats running
        s += 2;
    if (!r.output.empty())
        s += 1;
    return s;
}

} // namespace

std::unordered_map<std::string, AgentResponse>
best_response_per_agent(const std::vector<StoredResponse>& rows) {
    // Pick the best row per agent without copying every row: addresses into `rows`
    // (a stable local vector — not mutated here) feed `best`, which is consumed
    // into the value-typed result before returning.
    std::unordered_map<std::string, const StoredResponse*> best;
    for (const auto& r : rows) {
        auto it = best.find(r.agent_id);
        if (it == best.end()) {
            best.emplace(r.agent_id, &r);
            continue;
        }
        const StoredResponse& cur = *it->second;
        if (response_score(r) > response_score(cur) ||
            (response_score(r) == response_score(cur) && r.received_at_ms > cur.received_at_ms))
            it->second = &r;
    }
    std::unordered_map<std::string, AgentResponse> out;
    out.reserve(best.size());
    for (const auto& [agent, rp] : best)
        out.emplace(agent, AgentResponse{rp->status, rp->output});
    return out;
}

void advance(const EngineDeps& deps, const std::string& deployment_id, const DeploymentConfig& cfg,
             const std::unordered_set<std::string>& authorized,
             const yuzu::server::DispatchCaller& caller) {
    if (deps.store == nullptr || deployment_id.empty())
        return;

    // #1398: content_dist.{stage,execute_staged} are role-gated content —
    // ExecuteGate::AdminOrApproval at the dispatch chokepoint. The `/auto`
    // Deploy pipeline (this function: creator-authority go-cohort computed
    // upstream, guarded one-way transitions, execute-once CAS via
    // claim_for_stage/claim_for_exec below, full audit) is accepted as the
    // governing control in place of a per-dispatch ApprovalManager ticket
    // (#1398 design doc, Decision 5) — a SEPARATE, explicitly-typed
    // provenance value from a real consumed ticket, never conflated with
    // one. Per-dispatch attribution comes from `execution_id`
    // ("deployment-<id>-stage"/"...-exec", stage_execution_id/
    // exec_execution_id below) rather than a new audit call: it is already
    // the canonical per-dispatch correlation id this codebase threads
    // through the whole dispatch chain (matching the preflight-/polchk-/
    // bundle- id-prefix siblings), so an incident review can already trace
    // any dispatch back to the exact deployment run that authorized it.
    yuzu::server::DispatchCaller pipeline_caller = caller;
    pipeline_caller.approval_provenance = yuzu::server::ApprovalProvenance::GovernedPipeline;

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
        if (!claimed.empty()) {
            const auto outcome = deps.dispatch_fn(
                "content_dist", "stage", claimed, "",
                {{"url", cfg.url}, {"filename", cfg.filename}, {"sha256", cfg.sha256}},
                stage_execution_id(deployment_id), pipeline_caller);
            const auto& cmd = outcome.command_id;
            const auto sent = outcome.sent;
            // #3133 round-2 review MEDIUM: the claim used to be uncondition-
            // ally left in 'staging' with the dispatch result discarded — a
            // chokepoint-denied dispatch (caller lacks the classified
            // permission for content_dist.stage) or a zero-reach dispatch
            // left every claimed row stuck in an active step forever, with
            // no dispatched command and no transition to move it. Settle
            // them to the terminal 'failed' with an honest error instead —
            // via the same source-step-GUARDED transitions as every other
            // mutation here, so a row a concurrent advance already moved is
            // untouched. NOT 'pending': that would re-claim and re-deny on
            // every tick forever. The authorization outcome itself is
            // unchanged — the chokepoint already refused the dispatch; this
            // only stops the state machine wedging on the refusal.
            if (sent == 0) {
                std::vector<DeviceTransition> rollback;
                rollback.reserve(claimed.size());
                for (const auto& aid : claimed)
                    rollback.push_back({.agent_id = aid,
                                        .from_step = step_token(Step::kStaging),
                                        .to_step = step_token(Step::kFailed),
                                        .error = "stage dispatch refused or reached no agents "
                                                 "(command " +
                                                 cmd + ", 0 sent)"});
                deps.store->apply_results(deployment_id, rollback);
            }
        }
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
            const auto outcome =
                deps.dispatch_fn("content_dist", "execute_staged", claimed, "", params,
                                 exec_execution_id(deployment_id), pipeline_caller);
            const auto& cmd = outcome.command_id;
            const auto sent = outcome.sent;
            // Same settle-on-refusal as the stage claim above. The execute-once
            // property is PRESERVED, not weakened: claim_for_exec still claims
            // each row exactly once, and a row settled to 'failed' here was
            // never dispatched anywhere — there is no second execution to
            // guard against, only a wedge to release.
            if (sent == 0) {
                std::vector<DeviceTransition> rollback;
                rollback.reserve(claimed.size());
                for (const auto& aid : claimed)
                    rollback.push_back({.agent_id = aid,
                                        .from_step = step_token(Step::kExecuting),
                                        .to_step = step_token(Step::kFailed),
                                        .error = "execute dispatch refused or reached no agents "
                                                 "(command " +
                                                 cmd + ", 0 sent)"});
                deps.store->apply_results(deployment_id, rollback);
            }
        }
    }

    // ── 7. Recompute summary + complete if every device is settled ───────────
    deps.store->refresh_counts(deployment_id);
    deps.store->complete_deployment(deployment_id, now_ms());
}

} // namespace yuzu::server::deployment
