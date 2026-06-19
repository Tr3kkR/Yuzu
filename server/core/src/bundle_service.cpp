#include "bundle_service.hpp"

#include <nlohmann/json.hpp>

#include <set>
#include <string>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {

std::string to_lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

// Identifier rule for an already-lower-cased plugin/action: non-empty, <= 64
// bytes, [a-z0-9_]. Written out by hand (not std::isalnum) — locale-independent
// and safe on high-bit char values. These identifiers are used to build per-step
// audit verbs (mcp.bundle.<plugin>.<action>), so the charset is also the
// injection guard.
constexpr std::size_t kMaxIdentLen = 64;
bool is_ident(std::string_view s) {
    if (s.empty() || s.size() > kMaxIdentLen)
        return false;
    for (char c : s) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok)
            return false;
    }
    return true;
}

const char* state_token(BundleStepState st) {
    switch (st) {
    case BundleStepState::Responded:
        return "responded";
    case BundleStepState::DispatchFailed:
        return "dispatch_failed";
    case BundleStepState::Pending:
        break;
    }
    return "pending";
}

} // namespace

std::expected<std::vector<BundleStepSpec>, std::string>
validate_bundle_steps(std::string_view steps_json, std::size_t max_steps) {
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(steps_json.begin(), steps_json.end());
    } catch (const nlohmann::json::exception& e) {
        return std::unexpected(std::string("invalid JSON: ") + e.what());
    }

    if (!doc.is_array())
        return std::unexpected("steps must be a JSON array");
    if (doc.empty())
        return std::unexpected("steps array is empty");
    if (doc.size() > max_steps)
        return std::unexpected("too many steps (max " + std::to_string(max_steps) + ")");

    std::vector<BundleStepSpec> specs;
    specs.reserve(doc.size());
    std::set<std::pair<std::string, std::string>> seen;

    std::size_t idx = 0;
    for (const auto& elem : doc) {
        const std::string where = "step " + std::to_string(idx++);
        if (!elem.is_object())
            return std::unexpected(where + ": must be an object");
        if (!elem.contains("plugin") || !elem["plugin"].is_string())
            return std::unexpected(where + ": missing string 'plugin'");
        if (!elem.contains("action") || !elem["action"].is_string())
            return std::unexpected(where + ": missing string 'action'");

        BundleStepSpec s;
        s.plugin = to_lower(elem["plugin"].get<std::string>());
        s.action = to_lower(elem["action"].get<std::string>());
        if (!is_ident(s.plugin))
            return std::unexpected(where + ": invalid plugin name");
        if (!is_ident(s.action))
            return std::unexpected(where + ": invalid action name");
        if (!seen.insert({s.plugin, s.action}).second)
            return std::unexpected(where + ": duplicate (plugin, action) — each must be unique");

        if (elem.contains("params")) {
            const auto& p = elem["params"];
            if (!p.is_object())
                return std::unexpected(where + ": 'params' must be an object");
            s.params.reserve(p.size());
            for (const auto& [k, v] : p.items()) {
                // Coerce to string: strings pass through, other JSON types are
                // dumped to their textual form (matches execute_instruction).
                s.params.emplace_back(k, v.is_string() ? v.get<std::string>() : v.dump());
            }
        }

        specs.push_back(std::move(s));
    }

    return specs;
}

BundleAggregate aggregate_bundle(const std::vector<DispatchedStep>& steps,
                                 const std::vector<BundleResponseRow>& rows) {
    // Index rows by command_id (last write wins — a command can emit a RUNNING
    // data frame then a terminal; the terminal-or-latest is what we want).
    std::unordered_map<std::string, const BundleResponseRow*> by_cmd;
    by_cmd.reserve(rows.size());
    for (const auto& r : rows)
        by_cmd[r.command_id] = &r;

    BundleAggregate agg;
    agg.expected = steps.size();
    agg.steps.reserve(steps.size());

    for (const auto& step : steps) {
        BundleStepResult res;
        res.plugin = step.plugin;
        res.action = step.action;

        if (step.command_id.empty()) {
            res.state = BundleStepState::DispatchFailed;
        } else if (auto it = by_cmd.find(step.command_id); it != by_cmd.end()) {
            res.state = BundleStepState::Responded;
            res.status = it->second->status;
            res.output = it->second->output;
            ++agg.received;
        } else {
            res.state = BundleStepState::Pending;
        }
        agg.steps.push_back(std::move(res));
    }

    // Complete once nothing is still pending (responded or dispatch-failed). A
    // dispatch-failed step is terminal — it will never produce a response — so it
    // must not hold the bundle "incomplete" forever.
    agg.complete = true;
    for (const auto& s : agg.steps) {
        if (s.state == BundleStepState::Pending) {
            agg.complete = false;
            break;
        }
    }
    return agg;
}

std::string aggregate_to_json(const BundleAggregate& agg) {
    nlohmann::json j;
    j["complete"] = agg.complete;
    j["received"] = agg.received;
    j["expected"] = agg.expected;
    auto steps = nlohmann::json::array();
    for (const auto& s : agg.steps) {
        steps.push_back({
            {"plugin", s.plugin},
            {"action", s.action},
            {"state", state_token(s.state)},
            {"status", s.status},
            {"output", s.output},
        });
    }
    j["steps"] = std::move(steps);
    return j.dump();
}

} // namespace yuzu::server
