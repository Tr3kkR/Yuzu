#include "deployment_engine.hpp"

#include "deployment_run_store.hpp"
#include "response_store.hpp" // StoredResponse (best_response_per_agent)

#include <chrono>
#include <cstdint>
#include <string_view>
#include <unordered_set>

namespace yuzu::server::deployment {

namespace {

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// #3424/#3511 fix round (PR #3939 review, finding 2): the ORIGINAL version of
// this function (pre-review) only ever checked `outcome.sent == 0` for the
// WHOLE claimed batch, which had two confirmed bugs. (1) A transient
// `containment_unreadable` (the gate itself failing closed, typically
// recovering within seconds) was indistinguishable from a permanent refusal
// and settled every claimed row straight to 'failed' — unrecoverable, when
// the correct behaviour is to retry once the gate recovers. (2) In a MIXED
// batch — some devices reached, others withheld individually for a named
// permanent reason (quarantined, plugin absent) — `sent > 0` skipped the
// rollback branch entirely, so the withheld devices' rows stayed claimed in
// 'staging'/'executing' with NO transition ever able to move them out
// (a withheld device never gets an agent response, so the response-derived
// transitions at the top of `advance()` never fire for it either) —
// `complete_deployment` blocks forever on that row: an unconditional,
// state-machine-wedging hang on an entirely ordinary path (any deploy cohort
// with mixed device inventory).
//
// `revert_step` is where a CLAIMED-but-not-individually-evaluated row goes
// back to so a LATER tick's own candidate scan reclaims it — 'pending' for
// the stage claim, 'staged' for the exec claim — never 'failed': the gate
// degradation says nothing about these specific devices.
void settle_claimed_batch(const EngineDeps& deps, const std::string& deployment_id,
                          std::string_view phase_label, const std::vector<std::string>& claimed,
                          const yuzu::server::ConfinedDispatchOutcome& outcome,
                          const std::string& claimed_step, const std::string& revert_step,
                          const std::string& failed_step) {
    if (claimed.empty())
        return;

    if (outcome.containment_unreadable) {
        // The gate itself failed closed — nothing in `claimed` was
        // individually evaluated against quarantine/plugin-presence, so
        // there is no per-device fact to act on, only a systemic one. Undo
        // the claim entirely rather than fail it: a fail-closed gate
        // typically recovers within seconds (matching the retry_after_ms:
        // 5000 every other zero-reach cascade in this PR already promises).
        std::vector<DeviceTransition> revert;
        revert.reserve(claimed.size());
        for (const auto& aid : claimed)
            revert.push_back({.agent_id = aid,
                              .from_step = claimed_step,
                              .to_step = revert_step,
                              .error = ""});
        deps.store->apply_results(deployment_id, revert);
        return;
    }

    // Named ids withheld for a PERMANENT reason — settled to 'failed'
    // regardless of `outcome.sent`, so a mixed batch's withheld devices are
    // never left stranded just because other devices in the same batch were
    // reached.
    std::unordered_set<std::string> permanent_ids;
    std::vector<DeviceTransition> failed;
    const std::string phase(phase_label);
    for (const auto& aid : outcome.denied_quarantined) {
        if (permanent_ids.insert(aid).second)
            failed.push_back({.agent_id = aid,
                              .from_step = claimed_step,
                              .to_step = failed_step,
                              .error = phase + " dispatch withheld: device is quarantined"});
    }
    for (const auto& aid : outcome.unknown_plugin) {
        if (permanent_ids.insert(aid).second)
            failed.push_back(
                {.agent_id = aid,
                 .from_step = claimed_step,
                 .to_step = failed_step,
                 .error = phase + " dispatch withheld: content_dist plugin not found on "
                                  "this device's reported inventory"});
    }

    // Existing (pre-fix) behaviour, preserved exactly: when NOTHING in the
    // batch was sent and nothing was named-withheld either (a plain
    // zero-reach cause — offline devices, or a residual approval-required
    // race — `ConfinedDispatchOutcome` carries no per-id identification for
    // this class), fail the remainder of the batch too, matching what this
    // function always did for the `sent == 0` case. When `sent > 0` and a
    // remainder beyond the named-permanent ids was not reached, this is the
    // SAME pre-existing limitation (no way to tell which of the remainder
    // failed) — those rows are left claimed, exactly as every OTHER
    // dispatch surface in this codebase already leaves an in-flight row
    // for the next response poll to resolve.
    if (outcome.sent == 0 && claimed.size() > permanent_ids.size()) {
        const std::string reason = phase +
                                   " dispatch refused or reached no agents (command " +
                                   outcome.command_id + ", 0 sent)";
        for (const auto& aid : claimed) {
            if (permanent_ids.count(aid))
                continue;
            failed.push_back(
                {.agent_id = aid, .from_step = claimed_step, .to_step = failed_step, .error = reason});
        }
    }

    if (!failed.empty())
        deps.store->apply_results(deployment_id, failed);
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
            settle_claimed_batch(deps, deployment_id, "stage", claimed, outcome,
                                 step_token(Step::kStaging), step_token(Step::kPending),
                                 step_token(Step::kFailed));
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
            // The execute-once property is PRESERVED, not weakened, by
            // settle_claimed_batch's revert path below: claim_for_exec still
            // claims each row exactly once per call, and a revert only
            // returns a row to 'staged' so a LATER tick's claim_for_exec can
            // claim it again — that is a second CLAIM, not a second
            // EXECUTION of a command that was never actually dispatched.
            settle_claimed_batch(deps, deployment_id, "execute", claimed, outcome,
                                 step_token(Step::kExecuting), step_token(Step::kStaged),
                                 step_token(Step::kFailed));
        }
    }

    // ── 7. Recompute summary + complete if every device is settled ───────────
    deps.store->refresh_counts(deployment_id);
    deps.store->complete_deployment(deployment_id, now_ms());
}

} // namespace yuzu::server::deployment
