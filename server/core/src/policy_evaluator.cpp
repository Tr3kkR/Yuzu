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

/// The check interval in seconds: the first `interval` trigger's
/// `interval_seconds`, else the supplied default.
int64_t interval_for(const Policy& p, int64_t default_seconds) {
    for (const auto& t : p.triggers) {
        if (t.trigger_type != "interval")
            continue;
        auto cfg = nlohmann::json::parse(t.config_json, nullptr, false);
        if (!cfg.is_discarded() && cfg.is_object() && cfg.contains("interval_seconds")) {
            const auto& v = cfg["interval_seconds"];
            if (v.is_number())
                return v.get<int64_t>();
            if (v.is_string()) {
                try {
                    return std::stoll(v.get<std::string>());
                } catch (...) {
                }
            }
        }
    }
    return default_seconds;
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
        if (auto def = istore->get_definition(instruction_id))
            schema = def->result_schema;
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

    // Boot reconciliation (gov REC-1 / UP-4): in_flight_ is in-memory only, so a
    // remediation that left agents in 'fixing' before a restart can never have
    // its verify step dispatched — those agents would be stranded forever. Reset
    // any persisted 'fixing' rows to 'unknown' so the next evaluation re-scores
    // them. (fix_attempt_count is intentionally preserved — the prior attempts
    // still count against the retry cap.)
    if (d_.policy_store) {
        PolicyQuery q;
        q.limit = 10000;
        for (const auto& p : d_.policy_store->query_policies(q)) {
            for (const auto& s : d_.policy_store->get_policy_agent_statuses(p.id)) {
                if (s.status == "fixing") {
                    (void)d_.policy_store->update_agent_status(p.id, s.agent_id, "unknown");
                    spdlog::info("policy_evaluator: reset stranded 'fixing' -> 'unknown' "
                                 "(policy={} agent={}) after restart",
                                 p.id, s.agent_id);
                }
            }
        }
    }
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
            auto matched =
                d_.registry->evaluate_scope(*parsed, d_.tag_store, d_.custom_properties_store);
            for (const auto& a : matched)
                if (seen.insert(a).second)
                    out.push_back(a);
        }
    }
    return out;
}

std::string
PolicyEvaluator::dispatch_instruction(const std::string& instruction_id,
                                      const std::unordered_map<std::string, std::string>& parameters,
                                      const std::vector<std::string>& targets) {
    if (targets.empty() || !d_.instruction_store || !d_.dispatch_fn)
        return "";
    auto def = d_.instruction_store->get_definition(instruction_id);
    if (!def) {
        spdlog::warn("policy_evaluator: unknown check/fix instruction '{}'", instruction_id);
        return "";
    }
    auto execid = gen_execution_id();
    d_.dispatch_fn(def->plugin, def->action, targets, /*scope_expr=*/"", parameters, execid);
    return execid;
}

std::string PolicyEvaluator::kickoff_check(const Policy& p) {
    if (!d_.policy_store)
        return "";
    auto frag = d_.policy_store->get_fragment(p.fragment_id);
    if (!frag || frag->check_instruction.empty())
        return "";
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

    auto params = build_params(frag->check_parameters, p.inputs);
    // dispatch_instruction invokes the blocking dispatch_fn — call it WITHOUT mu_.
    auto execid = dispatch_instruction(frag->check_instruction, params, targets);
    if (execid.empty())
        return "";

    {
        std::lock_guard<std::mutex> lk(mu_);
        in_flight_.push_back(InFlight{.phase = Phase::Check,
                                      .policy_id = p.id,
                                      .execution_id = execid,
                                      .instruction_id = frag->check_instruction,
                                      .compliance_expr = frag->check_compliance,
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
    PolicyQuery q;
    q.enabled_only = true;
    q.limit = 1000;
    auto policies = d_.policy_store->query_policies(q);
    int64_t t = now();
    for (const auto& p : policies) {
        // Clamp the interval to a sane floor (gov sec-LOW): an operator-supplied
        // interval of 0/negative would otherwise re-dispatch to the whole fleet
        // every tick — a self-inflicted dispatch amplifier.
        int64_t interval = std::max<int64_t>(interval_for(p, d_.default_interval_seconds), 60);
        // Claim the due slot under a short lock, then dispatch lock-free.
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto it = last_eval_.find(p.id);
            int64_t last = (it != last_eval_.end()) ? it->second : 0;
            if (t - last < interval)
                continue;
            last_eval_[p.id] = t; // claim before dispatch (throttle)
        }
        kickoff_check(p); // does its own brief locking; dispatch runs without mu_
    }
}

std::string PolicyEvaluator::evaluate_now(const std::string& policy_id) {
    if (!d_.policy_store)
        return "";
    auto p = d_.policy_store->get_policy(policy_id);
    if (!p)
        return "";
    {
        std::lock_guard<std::mutex> lk(mu_);
        last_eval_[policy_id] = now();
    }
    return kickoff_check(*p); // dispatch runs without mu_ held
}

PolicyEvaluator::RemediateResult
PolicyEvaluator::remediate(const std::string& policy_id,
                           const std::vector<std::string>& agent_ids) {
    RemediateResult out;
    if (!d_.policy_store) {
        out.error = "policy store unavailable";
        return out;
    }
    auto p = d_.policy_store->get_policy(policy_id);
    if (!p) {
        out.error = "policy not found";
        return out;
    }
    auto frag = d_.policy_store->get_fragment(p->fragment_id);
    if (!frag || frag->fix_instruction.empty()) {
        out.error = "policy has no remediation pathway (fragment defines no fix_instruction)";
        return out;
    }

    std::vector<std::string> targets;
    if (agent_ids.empty()) {
        for (const auto& s : d_.policy_store->get_policy_agent_statuses(policy_id))
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
    auto execid = dispatch_instruction(frag->fix_instruction, fix_params, targets);
    if (execid.empty()) {
        out.error = "fix dispatch failed (unknown instruction or no agents)";
        return out;
    }

    // Now mark fixing (increments the attempt counter; >3 auto-transitions to error).
    for (const auto& tgt : targets)
        (void)d_.policy_store->update_agent_status(policy_id, tgt, "fixing");

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
        auto rows = d_.response_store ? d_.response_store->query_by_execution(f.execution_id)
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
                    if (d_.policy_store)
                        (void)d_.policy_store->update_agent_status(
                            f.policy_id, tgt, "error", R"({"phase":"fix","result":"failed"})");
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
                auto execid = dispatch_instruction(f.verify_instruction, vparams, verify_targets);
                if (!execid.empty()) {
                    std::lock_guard<std::mutex> lk(mu_);
                    in_flight_.push_back(InFlight{.phase = Phase::Check,
                                                  .policy_id = f.policy_id,
                                                  .execution_id = execid,
                                                  .instruction_id = f.verify_instruction,
                                                  .compliance_expr = f.verify_compliance,
                                                  .targets = verify_targets,
                                                  .dispatched_at = now(),
                                                  .verify_instruction = "",
                                                  .verify_compliance = "",
                                                  .verify_parameters_json = ""});
                } else if (d_.policy_store) {
                    for (const auto& tgt : verify_targets) {
                        (void)d_.policy_store->update_agent_status(
                            f.policy_id, tgt, "error",
                            R"({"phase":"verify","result":"dispatch_failed"})");
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
