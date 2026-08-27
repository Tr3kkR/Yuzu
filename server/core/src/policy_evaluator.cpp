#include "policy_evaluator.hpp"

#include "agent_registry.hpp"
#include "compliance_eval.hpp"
#include "custom_properties_store.hpp"
#include "instruction_store.hpp"
#include "management_group_store.hpp"
#include "policy_store.hpp"
#include "response_store.hpp"
#include "result_envelope.hpp"
#include "scope_engine.hpp"
#include "tag_store.hpp"

#include <yuzu/server/auth.hpp>

#include <yuzu/metrics.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>

#include <chrono>
#include <format>
#include <set>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {

// CommandResponse::Status enum values (proto/yuzu/agent/v1/agent.proto).
constexpr int kStatusRunning = 0;
constexpr int kStatusSuccess = 1;
constexpr int kStatusFailure = 2;
constexpr int kStatusTimeout = 3;
constexpr int kStatusRejected = 4;

bool is_terminal_failure(int status) {
    return status == kStatusFailure || status == kStatusTimeout || status == kStatusRejected;
}

/// Substitute every `{{inputs.NAME}}` placeholder in `s` with the matching
/// policy input value (empty if absent). This mirrors the fragment-parameter
/// templating convention used in the policy YAML (the store keeps the raw
/// `{{inputs.X}}` text; interpolation happens at dispatch time).
std::string interpolate_inputs(std::string s,
                               const std::unordered_map<std::string, std::string>& inmap) {
    const std::string pre = "{{inputs.";
    size_t pos = 0;
    while ((pos = s.find(pre, pos)) != std::string::npos) {
        auto end = s.find("}}", pos);
        if (end == std::string::npos)
            break;
        auto name = s.substr(pos + pre.size(), end - (pos + pre.size()));
        // trim surrounding whitespace in the name
        auto b = name.find_first_not_of(" \t");
        auto e = name.find_last_not_of(" \t");
        if (b != std::string::npos)
            name = name.substr(b, e - b + 1);
        auto it = inmap.find(name);
        std::string val = (it != inmap.end()) ? it->second : "";
        s.replace(pos, end + 2 - pos, val);
        pos += val.size();
    }
    return s;
}

/// Build a dispatch parameter map from a fragment's `*_parameters` JSON object
/// plus the policy inputs, interpolating `{{inputs.NAME}}` placeholders.
std::unordered_map<std::string, std::string>
build_params(const std::string& params_json, const std::vector<PolicyInput>& inputs) {
    std::unordered_map<std::string, std::string> inmap;
    for (const auto& i : inputs)
        inmap[i.key] = i.value;

    std::unordered_map<std::string, std::string> out;
    if (params_json.empty())
        return out;
    auto j = nlohmann::json::parse(params_json, nullptr, false);
    if (j.is_discarded() || !j.is_object())
        return out;
    for (const auto& [k, v] : j.items()) {
        std::string sval = v.is_string() ? v.get<std::string>() : v.dump();
        out[k] = interpolate_inputs(std::move(sval), inmap);
    }
    return out;
}

std::string map_to_json_obj(const std::unordered_map<std::string, std::string>& m) {
    nlohmann::json o = nlohmann::json::object();
    for (const auto& [k, v] : m)
        o[k] = v;
    return o.dump();
}

std::unordered_map<std::string, std::string> params_from_json_obj(const std::string& s) {
    std::unordered_map<std::string, std::string> out;
    if (s.empty())
        return out;
    auto j = nlohmann::json::parse(s, nullptr, false);
    if (j.is_discarded() || !j.is_object())
        return out;
    for (const auto& [k, v] : j.items())
        out[k] = v.is_string() ? v.get<std::string>() : v.dump();
    return out;
}

/// Pick, per agent, the most informative response for an execution: prefer a
/// terminal status over RUNNING, then non-empty output, then the later one.
std::unordered_map<std::string, StoredResponse>
latest_per_agent(const std::vector<StoredResponse>& rows) {
    auto score = [](const StoredResponse& r) {
        int s = 0;
        if (r.status != kStatusRunning)
            s += 2;
        if (!r.output.empty())
            s += 1;
        return s;
    };
    std::unordered_map<std::string, StoredResponse> best;
    for (const auto& r : rows) {
        auto it = best.find(r.agent_id);
        if (it == best.end()) {
            best.emplace(r.agent_id, r);
            continue;
        }
        if (score(r) > score(it->second) ||
            (score(r) == score(it->second) && r.timestamp >= it->second.timestamp))
            it->second = r;
    }
    return best;
}

/// Evaluate one agent's check response into a status string.
std::string verdict_for(const StoredResponse& r, const std::string& instruction_id,
                        const std::string& cel, InstructionStore* istore) {
    if (is_terminal_failure(r.status))
        return "error"; // the check plugin itself failed/timed out/was rejected

    // Integrity guard (gov COMP-1 / UP-8): an empty compliance expression makes
    // evaluate_compliance() return `compliant` unconditionally (empty == always
    // true). A policy that checks nothing must NOT be reported as compliant —
    // that is false assurance. Treat a misconfigured (empty-CEL) check as an
    // error so it surfaces distinctly instead of inflating the posture number.
    if (cel.empty())
        return "error";

    std::string schema;
    if (istore) {
        // ADR-0058: get_definition now returns std::expected<optional<...>, string>. A
        // not-found id leaves schema empty, matching pre-migration behaviour (parse_result
        // tolerates an empty schema) — the check already dispatched successfully against a
        // known instruction, so a since-deleted definition is a narrow edge case, not a
        // reason to error the verdict. A genuine DB error is NOT the same: proceeding with
        // an empty schema on a type-blind parse could silently produce a WRONG
        // compliant/non_compliant verdict instead of surfacing the infrastructure failure
        // (gov Gate 3 architect finding) — persisted straight into SOC2-relevant compliance
        // posture data via update_agent_status.
        auto def_result = istore->get_definition(instruction_id);
        if (!def_result)
            return "error";
        if (*def_result)
            schema = (*def_result)->result_schema;
    }
    InstructionResult ir = parse_result(r.output, schema);
    // CEL resolves `result.<field>` by stripping the `result.` prefix and
    // looking up the BARE field name (cel_eval.cpp resolve_variable), so the
    // fields map must use bare keys — NOT a `result.`-prefixed key.
    std::map<std::string, std::string> fields;
    if (!ir.rows.empty()) {
        for (const auto& [k, v] : ir.rows.front().values)
            fields[k] = v;
    }
    switch (evaluate_compliance(cel, fields)) {
    case ComplianceResult::compliant:
        return "compliant";
    case ComplianceResult::non_compliant:
        return "non_compliant";
    default:
        return "error";
    }
}

std::string make_check_result(const StoredResponse& r) {
    nlohmann::json j;
    j["status"] = r.status;
    j["output"] = r.output.size() > 1000 ? r.output.substr(0, 1000) : r.output;
    return j.dump();
}

} // namespace

PolicyEvaluator::PolicyEvaluator(Deps deps) : d_(std::move(deps)) {
    if (!d_.now_fn) {
        d_.now_fn = [] {
            return std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        };
    }

    // ADR-0056: the boot-time stranded-'fixing' reset that used to live here
    // is gone — under N replicas, resetting EVERY 'fixing' row on EVERY
    // process restart (a routine rolling-deploy event, not just a crash)
    // would stomp another replica's still-live remediation. Superseded by
    // PolicyStore::claim_due_policies' per-tick, age-gated staleness sweep
    // (last_fix_at older than Deps::fixing_stale_seconds), which runs
    // continuously rather than only at boot.
}

int64_t PolicyEvaluator::now() const { return d_.now_fn(); }

std::string PolicyEvaluator::gen_execution_id() {
    return "polchk-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));
}

std::vector<std::string> PolicyEvaluator::resolve_targets(const Policy& p) const {
    std::vector<std::string> out;
    std::set<std::string> seen;
    if (!p.management_groups.empty() && d_.mgmt_group_store) {
        for (const auto& g : p.management_groups)
            for (const auto& m : d_.mgmt_group_store->get_members(g))
                if (seen.insert(m.agent_id).second)
                    out.push_back(m.agent_id);
    } else if (!p.scope_expression.empty() && d_.registry) {
        auto parsed = yuzu::scope::parse(p.scope_expression);
        if (parsed) {
            // No rs_store/principal passed. A from_result_set: atom in a
            // policy scope now ABORTS to nullopt (H1, 2026-07-29) and
            // value_or({}) collapses that to zero targets — evaluate nothing,
            // the safe direction. Unreachable today (create_policy rejects
            // fromResultSet:, PR-E2 pending) but the comment must not claim
            // "cannot degrade" on an authz-adjacent branch.
            auto matched = d_.registry
                              ->evaluate_scope(*parsed, d_.tag_store, d_.custom_properties_store)
                              .value_or(std::vector<std::string>{});
            for (const auto& a : matched)
                if (seen.insert(a).second)
                    out.push_back(a);
        }
    }
    return out;
}

std::expected<std::string, std::string>
PolicyEvaluator::dispatch_instruction(const std::string& instruction_id,
                                      const std::unordered_map<std::string, std::string>& parameters,
                                      const std::vector<std::string>& targets) {
    if (targets.empty() || !d_.dispatch_fn)
        return "";
    // db_error, not a legitimate no-op (gov Gate 3 architect finding): a null
    // instruction_store is a genuine unavailability, not "no targets"/"unknown
    // instruction" — collapsing it into the same "" those return would silently
    // skip dispatch instead of surfacing degraded. Currently unreachable (this
    // Deps struct is only ever constructed with a live instruction_store — same
    // boot-latch shape as workflow_routes.cpp's uninstall_fn), kept correct as
    // defense-in-depth against that invariant changing.
    if (!d_.instruction_store)
        return std::unexpected(std::string(kInstructionStoreDbErrorPrefix) +
                               "instruction store unavailable");
    // ADR-0058: get_definition now returns std::expected<optional<...>, string>.
    // A genuine DB error must surface as `unexpected` — never collapse into the
    // same "" a not-found id legitimately returns (that fail-open is exactly
    // what ADR-0036 exists to close on an authorization/dispatch-adjacent
    // read). Every caller already propagates a std::expected error the same
    // way it propagates its own other degrade paths.
    auto def_result = d_.instruction_store->get_definition(instruction_id);
    if (!def_result) {
        spdlog::warn("policy_evaluator: instruction store unavailable resolving '{}': {}",
                     instruction_id, def_result.error());
        return std::unexpected(def_result.error());
    }
    if (!*def_result) {
        spdlog::warn("policy_evaluator: unknown check/fix instruction '{}'", instruction_id);
        return "";
    }
    const auto& def = **def_result;
    auto execid = gen_execution_id();
    d_.dispatch_fn(def.plugin, def.action, targets, /*scope_expr=*/"", parameters, execid);
    return execid;
}

std::expected<std::string, std::string> PolicyEvaluator::kickoff_check(const Policy& p) {
    if (!d_.policy_store)
        return std::unexpected("policy store not wired");
    auto frag_res = d_.policy_store->get_fragment(p.fragment_id);
    if (!frag_res) {
        // ADR-0036: a degraded read must not be treated as "no fragment" —
        // and must not collapse into the same "" a legitimate no-op returns
        // either (adversarial review / governance, 2026-08-24): a bare ""
        // here was indistinguishable from "no check instruction" / "no
        // targets" / "check already in flight" one level up, so evaluate_now()
        // surfaced this as a false REST 409 instead of a 503.
        spdlog::warn("policy_evaluator: kickoff_check: degraded fragment read for policy {}",
                     p.id);
        return std::unexpected("degraded fragment read for policy " + p.id);
    }
    if (!*frag_res || (*frag_res)->check_instruction.empty())
        return "";
    const PolicyFragment& frag = **frag_res;
    auto targets = resolve_targets(p);
    if (targets.empty())
        return "";

    // Dedupe (gov UP-5 / UP-13): if a Check for this policy is already in flight,
    // do not dispatch another — otherwise rapid /evaluate calls or a tick landing
    // on a still-maturing check pile up duplicate in-flights (unbounded growth)
    // and a stale collect can overwrite a fresher verdict.
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (const auto& f : in_flight_)
            if (f.phase == Phase::Check && f.policy_id == p.id)
                return "";
    }

    auto params = build_params(frag.check_parameters, p.inputs);
    // dispatch_instruction invokes the blocking dispatch_fn — call it WITHOUT mu_.
    // ADR-0058: a genuine InstructionStore error propagates as `unexpected` here
    // too, the same way the degraded-fragment-read path above does.
    auto execid_result = dispatch_instruction(frag.check_instruction, params, targets);
    if (!execid_result)
        return std::unexpected(execid_result.error());
    if (execid_result->empty())
        return "";
    const std::string& execid = *execid_result;

    {
        std::lock_guard<std::mutex> lk(mu_);
        in_flight_.push_back(InFlight{.phase = Phase::Check,
                                      .policy_id = p.id,
                                      .execution_id = execid,
                                      .instruction_id = frag.check_instruction,
                                      .compliance_expr = frag.check_compliance,
                                      .targets = std::move(targets),
                                      .dispatched_at = now(),
                                      .verify_instruction = "",
                                      .verify_compliance = "",
                                      .verify_parameters_json = ""});
    }
    return execid;
}

void PolicyEvaluator::dispatch_due() {
    if (!d_.policy_store)
        return;
    // ADR-0056: due-ness is now a durable, fleet-wide single-sweeper claim —
    // exactly one replica claims (and sweeps stranded 'fixing' rows) per
    // tick. Lock-not-acquired returns an empty, non-error result (another
    // replica claimed this tick); a genuine DB error is `unexpected` and
    // MUST be treated as "skip this tick", never silently as "nothing due".
    // This durable claim also structurally closes the ABA hazard the earlier
    // in-memory last_eval_/EvalClaim generation-counter CAS (gov Gate 8) was
    // patching — that mechanism no longer exists here; see ADR-0058's
    // Consequences.
    auto claimed =
        d_.policy_store->claim_due_policies(now(), d_.default_interval_seconds,
                                            d_.fixing_stale_seconds);
    if (!claimed) {
        // sre (governance, 2026-08-24): this is the ADR's own stated worst
        // case for this store — a persistently failing claim means
        // compliance checks silently stop running fleet-wide. A warn-only
        // log with no counter left that failure mode with no alerting
        // surface at all.
        spdlog::error("policy_evaluator: claim_due_policies degraded, skipping tick: {}",
                     claimed.error());
        if (d_.metrics)
            d_.metrics->counter("yuzu_server_policy_eval_errors_total", {{"phase", "claim"}})
                .increment();
        return;
    }
    for (const auto& p : *claimed) {
        auto k = kickoff_check(p); // does its own brief locking; dispatch runs without mu_
        if (!k) {
            // Governance UP-2 (2026-08-24): this policy's durable dispatch
            // claim already committed as part of `claimed`'s single
            // transaction — a degraded kickoff_check here leaves it claimed
            // but never actually dispatched, silently skipping this policy
            // for the rest of its interval. Same consequence class as the
            // claim-failure counter above; give it the same visibility. This
            // also covers a genuine InstructionStore error (ADR-0058) —
            // kickoff_check propagates it as `unexpected` the same way it
            // propagates a degraded fragment read.
            spdlog::warn("policy_evaluator: dispatch_due: kickoff_check degraded for policy {}: {}",
                        p.id, k.error());
            if (d_.metrics)
                d_.metrics->counter("yuzu_server_policy_eval_errors_total", {{"phase", "dispatch"}})
                    .increment();
        }
    }
}

std::expected<std::string, std::string>
PolicyEvaluator::evaluate_now(const std::string& policy_id) {
    if (!d_.policy_store)
        return std::unexpected("policy store not wired");
    auto p_res = d_.policy_store->get_policy(policy_id);
    if (!p_res) {
        spdlog::warn("policy_evaluator: evaluate_now: degraded policy read for {}", policy_id);
        return std::unexpected("degraded policy read for " + policy_id);
    }
    if (!*p_res)
        return "";
    // Manual, operator-triggered — bypasses the interval claim entirely (an
    // explicit "check now" request), matching the pre-ADR-0056 behavior.
    // Runs on whichever replica received the REST call; if that replica
    // dies before its own collect_ready() matures this check, it strands —
    // an accepted, narrow residual (ADR-0056 Follow-ups): the operator has
    // a natural retry action.
    //
    // Stamp the durable claim record BEFORE dispatch (claim-before-dispatch,
    // matching claim_due_policies' own claim-then-dispatch order and the
    // pre-ADR-0056 last_eval_ ordering) — kickoff_check's dispatch_fn is
    // blocking gRPC/gateway I/O; stamping after it leaves a real window
    // where a concurrent tick (this replica's background thread, or a
    // sibling replica) sees no row yet and re-dispatches before this
    // manual check's network call even returns. Stamping unconditionally,
    // even if dispatch below ends up failing, matches the original in
    // WHO consumes the interval slot: a failed manual check still consumed
    // it. It does NOT match the original in BLAST RADIUS (governance UP-1,
    // 2026-08-24): the old last_eval_ was per-replica in-memory, so a
    // failed dispatch only cost that one replica's view of the interval —
    // a sibling replica's own last_eval_ was untouched. This stamp is
    // durable and fleet-wide, so the same failure now costs every replica
    // the interval, not just one. Self-heals after one interval; tracked,
    // not fixed, in ADR-0056's Follow-ups (same class as UP-2's
    // dispatch_due() equivalent, just above).
    // If the stamp itself fails, do NOT dispatch (adversarial review,
    // 2026-08-24): the correction above only closed "dispatch succeeded but
    // the stamp was never attempted" — a failed record_dispatch call is the
    // same durable-claim-blind outcome by a different path (the operator's
    // check would still run, still return 202, and the very next automatic
    // tick would see no row and re-claim/re-dispatch it immediately). This
    // is a plain runtime store error on an authoritative write (ADR-0012
    // §1) — surface it as "did not dispatch," never as silent success.
    auto r = d_.policy_store->record_dispatch(policy_id, now());
    if (!r) {
        spdlog::warn("policy_evaluator: evaluate_now: record_dispatch failed for {}: {} — "
                    "not dispatching (would leave the durable claim blind)",
                    policy_id, r.error());
        return std::unexpected("dispatch claim failed for " + policy_id + ": " + r.error());
    }
    auto k = kickoff_check(**p_res); // dispatch runs without mu_ held
    if (!k)
        return std::unexpected("kickoff_check degraded for " + policy_id + ": " + k.error());
    return *k;
}

PolicyEvaluator::RemediateResult
PolicyEvaluator::remediate(const std::string& policy_id,
                           const std::vector<std::string>& agent_ids) {
    RemediateResult out;
    if (!d_.policy_store) {
        out.error = "policy store unavailable";
        out.degraded = true;
        return out;
    }
    auto p_res = d_.policy_store->get_policy(policy_id);
    if (!p_res) {
        out.error = "policy store degraded — try again";
        out.degraded = true;
        return out;
    }
    if (!*p_res) {
        out.error = "policy not found";
        return out;
    }
    const Policy& p_ref = **p_res;
    auto frag_res = d_.policy_store->get_fragment(p_ref.fragment_id);
    if (!frag_res) {
        out.error = "policy store degraded — try again";
        out.degraded = true;
        return out;
    }
    if (!*frag_res || (*frag_res)->fix_instruction.empty()) {
        out.error = "policy has no remediation pathway (fragment defines no fix_instruction)";
        return out;
    }
    const PolicyFragment& frag_ref = **frag_res;
    // p/frag below keep the original body's pointer-like access working
    // (arrow syntax) without renaming every subsequent use.
    const Policy* p = &p_ref;
    const PolicyFragment* frag = &frag_ref;

    std::vector<std::string> targets;
    if (agent_ids.empty()) {
        auto statuses = d_.policy_store->get_policy_agent_statuses(policy_id);
        if (!statuses) {
            // ADR-0036: a degraded read must not resolve to "0 non-compliant
            // agents" — that would silently remediate nobody when the
            // operator asked to fix everyone non-compliant.
            out.error = "policy store degraded — could not determine remediation targets";
            out.degraded = true;
            return out;
        }
        for (const auto& s : *statuses)
            if (s.status == "non_compliant")
                targets.push_back(s.agent_id);
    } else {
        // Confused-deputy guard (gov sec-MEDIUM): a caller-supplied agent list
        // must be intersected with the policy's own scope. Otherwise a
        // Policy:Execute holder could dispatch the fragment's fix instruction to
        // arbitrary fleet agents the policy never targets.
        auto scoped = resolve_targets(*p);
        std::set<std::string> allowed(scoped.begin(), scoped.end());
        for (const auto& a : agent_ids)
            if (allowed.count(a))
                targets.push_back(a);
        if (targets.empty()) {
            out.error = "no in-scope agents to remediate (requested agents are outside the "
                        "policy's scope)";
            return out;
        }
    }
    if (targets.empty()) {
        out.error = "no non_compliant agents to remediate";
        return out;
    }

    // Governance UP-3 (2026-08-24): reserve this policy_id BEFORE dispatch,
    // not after — unlike kickoff_check's Check-phase dedupe (which only
    // needs to avoid a duplicate DISPATCH), a second concurrent remediate()
    // call reaching the blocking dispatch below would burn the retry-attempt
    // cap twice (update_agent_status's "fixing" write increments it) on a
    // fix instruction that may not be idempotent — a real double-run, not
    // just a duplicate in-flight record. The comment on update_agent_status's
    // UPSERT calling itself "naturally idempotent against a racing manual
    // remediate() on another replica" is true for the STATUS ROW but was
    // never true for the ATTEMPT COUNTER; this reservation only covers same
    // process concurrency (two REST calls landing on this replica), not a
    // cross-replica race — that residual is unchanged and tracked in
    // ADR-0056's Follow-ups, same as kickoff_check's cross-replica gap.
    {
        std::lock_guard<std::mutex> lk(mu_);
        bool already = remediating_.count(policy_id) > 0;
        if (!already)
            for (const auto& f : in_flight_)
                if (f.phase == Phase::FixWait && f.policy_id == policy_id)
                    already = true;
        if (already) {
            out.error = "remediation already in flight for this policy";
            return out;
        }
        remediating_.insert(policy_id);
    }
    // RAII: erase the reservation on every exit from here down. Once the
    // FixWait entry lands in in_flight_ on the success path, that entry
    // itself is what a later concurrent call's scan above sees — the
    // reservation only needs to cover THIS call's own window.
    struct ReservationGuard {
        PolicyEvaluator* self;
        std::string id;
        ~ReservationGuard() {
            std::lock_guard<std::mutex> lk(self->mu_);
            self->remediating_.erase(id);
        }
    } reservation_guard{this, policy_id};

    auto fix_params = build_params(frag->fix_parameters, p->inputs);
    std::string verify_instr = !frag->post_check_instruction.empty() ? frag->post_check_instruction
                                                                     : frag->check_instruction;
    std::string verify_cel =
        !frag->post_check_compliance.empty() ? frag->post_check_compliance : frag->check_compliance;
    auto verify_params = build_params(
        !frag->post_check_parameters.empty() ? frag->post_check_parameters : frag->check_parameters,
        p->inputs);

    // Dispatch the fix BEFORE marking 'fixing' (gov UP-7): marking first would
    // burn an attempt against the retry cap even when the dispatch fails (unknown
    // instruction / all targets offline), eventually locking the agent to 'error'
    // with no fix ever sent. dispatch_instruction must run without mu_ held.
    auto dispatch_result = dispatch_instruction(frag->fix_instruction, fix_params, targets);
    if (!dispatch_result) {
        out.degraded = true;
        // Gate 3 ARCH-1: dispatch_result.error() carries raw PQerrorMessage() text on a
        // genuine DB failure — genericized here at the source so both consumers
        // (compliance_routes.cpp's audit row AND its POST /api/policies/:id/remediate
        // response body, both of which echo `out.error` verbatim) get the fix for free.
        out.error = yuzu::server::genericize_db_error("PolicyEvaluator::remediate dispatch",
                                                       dispatch_result.error());
        return out;
    }
    if (dispatch_result->empty()) {
        out.error = "fix dispatch failed (unknown instruction or no agents)";
        return out;
    }
    const auto& execid = *dispatch_result;

    // Now mark fixing (increments the attempt counter; >3 auto-transitions to error).
    for (const auto& tgt : targets) {
        auto r = d_.policy_store->update_agent_status(policy_id, tgt, "fixing");
        if (!r)
            spdlog::warn("policy_evaluator: remediate: failed to mark {} fixing for policy {}: {}",
                        tgt, policy_id, r.error());
    }

    {
        std::lock_guard<std::mutex> lk(mu_);
        in_flight_.push_back(InFlight{.phase = Phase::FixWait,
                                      .policy_id = policy_id,
                                      .execution_id = execid,
                                      .instruction_id = frag->fix_instruction,
                                      .compliance_expr = "",
                                      .targets = targets,
                                      .dispatched_at = now(),
                                      .verify_instruction = std::move(verify_instr),
                                      .verify_compliance = std::move(verify_cel),
                                      .verify_parameters_json = map_to_json_obj(verify_params)});
    }
    out.ok = true;
    out.execution_id = execid;
    out.agents = static_cast<int>(targets.size());
    return out;
}

void PolicyEvaluator::collect_ready() {
    int64_t t = now();
    std::vector<InFlight> ready;
    {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<InFlight> keep;
        for (auto& f : in_flight_) {
            if (t - f.dispatched_at >= d_.grace_seconds)
                ready.push_back(std::move(f));
            else
                keep.push_back(std::move(f));
        }
        in_flight_.swap(keep);
    }

    for (auto& f : ready) {
        // Degrade → empty (ADR-0039 deny-or-benign): a transient read failure
        // reads as "no terminal response yet", the same as a genuinely slow
        // agent — verdict_for() below already treats an unmatched target as
        // "unknown", never a fabricated compliant/drifted verdict.
        auto rows = d_.response_store
                        ? d_.response_store->query_by_execution(f.execution_id)
                              .value_or(std::vector<StoredResponse>{})
                        : std::vector<StoredResponse>{};
        auto best = latest_per_agent(rows);

        if (f.phase == Phase::Check) {
            for (const auto& tgt : f.targets) {
                auto it = best.find(tgt);
                std::string status, cr;
                if (it == best.end() || it->second.status == kStatusRunning) {
                    status = "unknown"; // no terminal response within the grace window
                } else {
                    status = verdict_for(it->second, f.instruction_id, f.compliance_expr,
                                         d_.instruction_store);
                    cr = make_check_result(it->second);
                }
                if (d_.policy_store) {
                    auto r = d_.policy_store->update_agent_status(f.policy_id, tgt, status, cr);
                    if (!r)
                        spdlog::warn("policy_evaluator: update_agent_status failed: {}", r.error());
                }
                if (d_.metrics)
                    d_.metrics->counter("yuzu_server_policy_verdicts_total", {{"status", status}})
                        .increment();
            }
        } else { // Phase::FixWait — fix dispatched; failures error out, the rest go to verify.
            std::vector<std::string> verify_targets;
            for (const auto& tgt : f.targets) {
                auto it = best.find(tgt);
                if (it != best.end() && is_terminal_failure(it->second.status)) {
                    if (d_.policy_store) {
                        auto r = d_.policy_store->update_agent_status(
                            f.policy_id, tgt, "error", R"({"phase":"fix","result":"failed"})");
                        if (!r)
                            spdlog::warn("policy_evaluator: fix-failure status write failed for "
                                        "{}/{}: {}",
                                        f.policy_id, tgt, r.error());
                    }
                    if (d_.metrics)
                        d_.metrics
                            ->counter("yuzu_server_policy_eval_errors_total", {{"phase", "fix"}})
                            .increment();
                } else {
                    verify_targets.push_back(tgt);
                }
            }
            if (!verify_targets.empty()) {
                auto vparams = params_from_json_obj(f.verify_parameters_json);
                auto result = dispatch_instruction(f.verify_instruction, vparams, verify_targets);
                if (result && !result->empty()) {
                    std::lock_guard<std::mutex> lk(mu_);
                    in_flight_.push_back(InFlight{.phase = Phase::Check,
                                                  .policy_id = f.policy_id,
                                                  .execution_id = *result,
                                                  .instruction_id = f.verify_instruction,
                                                  .compliance_expr = f.verify_compliance,
                                                  .targets = verify_targets,
                                                  .dispatched_at = now(),
                                                  .verify_instruction = "",
                                                  .verify_compliance = "",
                                                  .verify_parameters_json = ""});
                } else if (d_.policy_store) {
                    // A store-unavailable verify dispatch is a transient infra failure, not
                    // a genuine post-fix verification failure — the result JSON records which
                    // it was rather than collapsing both into the same "dispatch_failed".
                    const char* result_tag = !result ? "store_unavailable" : "dispatch_failed";
                    for (const auto& tgt : verify_targets) {
                        auto r = d_.policy_store->update_agent_status(
                            f.policy_id, tgt, "error",
                            std::format(R"({{"phase":"verify","result":"{}"}})", result_tag));
                        if (!r)
                            spdlog::warn("policy_evaluator: verify-dispatch-failed status write "
                                        "failed for {}/{}: {}",
                                        f.policy_id, tgt, r.error());
                        if (d_.metrics)
                            d_.metrics
                                ->counter("yuzu_server_policy_eval_errors_total",
                                          {{"phase", "verify"}})
                                .increment();
                    }
                }
            }
        }
    }
}

void PolicyEvaluator::tick() {
    collect_ready();
    dispatch_due();
}

} // namespace yuzu::server
