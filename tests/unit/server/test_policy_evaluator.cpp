/**
 * test_policy_evaluator.cpp — Unit tests for the compliance check -> verdict
 * pipeline (PolicyEvaluator).
 *
 * Strategy: real PolicyStore / InstructionStore / ResponseStore /
 * ManagementGroupStore on :memory:-style temp DBs, target resolution via a
 * static management group (so no AgentRegistry is needed), a FAKE dispatch_fn
 * that synchronously seeds canned ResponseStore rows under the execution_id it
 * is handed (keyed by agent + plugin), and an injectable clock to drive the
 * grace window deterministically.
 */

#include "instruction_store.hpp"
#include "management_group_store.hpp"
#include "policy_evaluator.hpp"
#include "policy_store.hpp"
#include "response_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

// A result envelope parse_result understands: columns + rows arrays.
std::string out_json(const std::string& col, const std::string& val) {
    return R"({"columns":[{"name":")" + col + R"(","type":"string"}],"rows":[{")" + col +
           R"(":")" + val + R"("}]})";
}

// Two-column variant for expressions that reference two fields.
std::string out_json2(const std::string& c1, const std::string& v1, const std::string& c2,
                      const std::string& v2) {
    return R"({"columns":[{"name":")" + c1 + R"(","type":"string"},{"name":")" + c2 +
           R"(","type":"string"}],"rows":[{")" + c1 + R"(":")" + v1 + R"(",")" + c2 + R"(":")" +
           v2 + R"("}]})";
}

struct Harness {
    yuzu::test::TempDbFile poldb{std::string_view("pol-")}, insdb{std::string_view("ins-")},
        resdb{std::string_view("res-")}, mgdb{std::string_view("mg-")};
    PolicyStore ps{poldb.path};
    InstructionStore is{insdb.path};
    ResponseStore rs{resdb.path};
    ManagementGroupStore mg{mgdb.path};

    int64_t fake_now{1000};
    int dispatch_calls{0};
    std::vector<std::string> dispatched_plugins;
    // canned[agent + "|" + plugin] -> (status, output)
    std::map<std::string, std::pair<int, std::string>> canned;

    std::string group_id;

    Harness() {
        auto def = [&](const std::string& id, const std::string& plugin) {
            InstructionDefinition d;
            d.id = id;
            d.name = id;
            d.version = "1.0.0";
            d.type = "question";
            d.plugin = plugin;
            d.action = "run";
            d.enabled = true;
            REQUIRE(is.create_definition(d).has_value());
        };
        def("test.check", "checkp");
        def("test.fix", "fixp");
        def("test.verify", "verifyp");

        ManagementGroup g;
        g.name = "grp";
        g.membership_type = "static";
        auto gid = mg.create_group(g);
        REQUIRE(gid.has_value());
        group_id = *gid;
        REQUIRE(mg.add_member(group_id, "agentA").has_value());
        REQUIRE(mg.add_member(group_id, "agentB").has_value());
    }

    PolicyEvaluator::Deps deps() {
        PolicyEvaluator::Deps d;
        d.policy_store = &ps;
        d.instruction_store = &is;
        d.response_store = &rs;
        d.registry = nullptr;
        d.tag_store = nullptr;
        d.custom_properties_store = nullptr;
        d.mgmt_group_store = &mg;
        d.grace_seconds = 15;
        d.default_interval_seconds = 3600;
        d.now_fn = [this] { return fake_now; };
        d.dispatch_fn = [this](const std::string& plugin, const std::string&,
                               const std::vector<std::string>& agents, const std::string&,
                               const std::unordered_map<std::string, std::string>&,
                               const std::string& execid) -> std::pair<std::string, int> {
            ++dispatch_calls;
            dispatched_plugins.push_back(plugin);
            int sent = 0;
            for (const auto& a : agents) {
                auto it = canned.find(a + "|" + plugin);
                if (it == canned.end())
                    continue; // non-responder
                StoredResponse r;
                r.instruction_id = "test";
                r.agent_id = a;
                r.status = it->second.first;
                r.output = it->second.second;
                r.plugin = plugin;
                r.execution_id = execid;
                r.timestamp = fake_now;
                rs.store(r);
                ++sent;
            }
            return {"cmd-" + execid, sent};
        };
        return d;
    }

    // Author a fragment + policy bound to the static group. Returns policy id.
    std::string author(const std::string& check_cel, bool with_fix = false) {
        std::string frag = std::string("apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\n") +
                           "spec:\n  check:\n    instruction: test.check\n    compliance: \"" +
                           check_cel + "\"\n";
        if (with_fix) {
            frag += "  fix:\n    instruction: test.fix\n";
            frag += "  postCheck:\n    instruction: test.verify\n    compliance: \"result.fixed "
                    "== 'yes'\"\n";
        }
        auto fid = ps.create_fragment(frag);
        REQUIRE(fid.has_value());

        std::string pol = std::string("apiVersion: yuzu.io/v1alpha1\nkind: Policy\n") + "spec:\n  fragment: " +
                          *fid + "\n  managementGroups:\n    - " + group_id + "\n";
        auto pid = ps.create_policy(pol);
        REQUIRE(pid.has_value());
        return *pid;
    }

    std::string status_of(const std::string& pid, const std::string& agent) {
        auto s = ps.get_agent_status(pid, agent);
        return s ? s->status : std::string("<none>");
    }
};

} // namespace

TEST_CASE("policy evaluator: compliant + non_compliant verdicts (multi-agent fan-out)",
          "[policy][evaluator]") {
    Harness h;
    h.canned["agentA|checkp"] = {1, out_json("hostname", "yuzu-a")};
    h.canned["agentB|checkp"] = {1, out_json("hostname", "")};
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).empty());
    h.fake_now += 20; // past grace
    ev.tick();

    CHECK(h.status_of(pid, "agentA") == "compliant");
    CHECK(h.status_of(pid, "agentB") == "non_compliant");
}

TEST_CASE("policy evaluator: non-responder -> unknown, plugin failure -> error",
          "[policy][evaluator]") {
    Harness h;
    h.canned["agentA|checkp"] = {2, ""}; // FAILURE status -> error
    // agentB intentionally absent -> non-responder -> unknown
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).empty());
    h.fake_now += 20;
    ev.tick();

    CHECK(h.status_of(pid, "agentA") == "error");
    CHECK(h.status_of(pid, "agentB") == "unknown");
}

TEST_CASE("policy evaluator: missing CEL field resolves empty -> non_compliant",
          "[policy][evaluator]") {
    Harness h;
    // Success status, but the result has no 'hostname' column the CEL references.
    // CEL resolves a missing result field to "" (not an error), so
    // `result.hostname != ''` is `'' != ''` -> false -> non_compliant. Missing
    // data is treated as non-compliant, NOT as an evaluation error.
    h.canned["agentA|checkp"] = {1, out_json("other", "x")};
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).empty());
    h.fake_now += 20;
    ev.tick();

    CHECK(h.status_of(pid, "agentA") == "non_compliant");
}

TEST_CASE("policy evaluator: CEL evaluation error -> error", "[policy][evaluator]") {
    Harness h;
    // Division by zero yields a top-level CEL evaluation error (monostate ->
    // eval_error), which the evaluator must surface as status "error", distinct
    // from a non-compliant verdict. (A comparison like `... > 1` would coerce
    // the monostate to the string "null" and mask the error, so the bare
    // arithmetic expression is the deterministic eval_error trigger.)
    h.canned["agentA|checkp"] = {1, out_json2("num", "10", "den", "0")};
    auto pid = h.author("result.num / result.den");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).empty());
    h.fake_now += 20;
    ev.tick();

    CHECK(h.status_of(pid, "agentA") == "error");
}

TEST_CASE("policy evaluator: interval throttles re-dispatch", "[policy][evaluator]") {
    Harness h;
    h.canned["agentA|checkp"] = {1, out_json("hostname", "a")};
    h.canned["agentB|checkp"] = {1, out_json("hostname", "b")};
    auto pid = h.author("result.hostname != ''");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).empty()); // dispatch #1
    CHECK(h.dispatch_calls == 1);

    h.fake_now += 20;
    ev.tick(); // collect only; interval (3600s) not elapsed -> no new dispatch
    CHECK(h.dispatch_calls == 1);

    h.fake_now += 4000;
    ev.tick(); // interval elapsed -> dispatch #2
    CHECK(h.dispatch_calls == 2);
}

TEST_CASE("policy evaluator: empty compliance CEL -> error (no false compliant)",
          "[policy][evaluator]") {
    Harness h;
    // A successful check whose fragment defines an EMPTY check_compliance. The CEL
    // layer treats empty as always-compliant; the evaluator must NOT report this
    // as compliant (it would be false assurance) — it surfaces as error instead.
    h.canned["agentA|checkp"] = {1, out_json("hostname", "yuzu-a")};
    auto pid = h.author(/*check_cel=*/"");

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).empty());
    h.fake_now += 20;
    ev.tick();

    CHECK(h.status_of(pid, "agentA") == "error");
}

TEST_CASE("policy evaluator: remediation attempt cap -> error after 3 fixing transitions",
          "[policy][evaluator]") {
    Harness h;
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);
    h.canned["agentA|fixp"] = {1, "ok"};

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).empty());
    h.fake_now += 20;
    ev.tick();
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    // Drive remediation with an explicit (in-scope) agent list. Each call marks
    // the agent 'fixing'; PolicyStore caps fix attempts at 3 and forces 'error'
    // on the transition that would exceed it. Verify the cap is reached.
    for (int i = 0; i < 4; ++i) {
        auto rr = ev.remediate(pid, {"agentA"});
        // The first three dispatch the fix; the 4th still dispatches but the
        // status write trips the cap. remediate reports dispatch success either way.
        REQUIRE(rr.ok);
    }
    CHECK(h.status_of(pid, "agentA") == "error");
}

TEST_CASE("policy evaluator: verify dispatch failure -> error", "[policy][evaluator]") {
    Harness h;
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant
    h.canned["agentA|fixp"] = {1, "ok"};
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).empty());
    h.fake_now += 20;
    ev.tick();
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    auto rr = ev.remediate(pid, {});
    REQUIRE(rr.ok);

    // Remove the verify instruction definition before the FixWait matures, so the
    // post-check dispatch resolves to an unknown instruction and returns "".
    REQUIRE(h.is.delete_definition("test.verify"));

    h.fake_now += 20;
    ev.tick(); // collect FixWait -> verify dispatch fails -> error

    CHECK(h.status_of(pid, "agentA") == "error");
}

TEST_CASE("policy evaluator: manual remediation fix -> verify -> compliant",
          "[policy][evaluator]") {
    Harness h;
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")}; // non_compliant first
    auto pid = h.author("result.hostname != ''", /*with_fix=*/true);

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).empty());
    h.fake_now += 20;
    ev.tick();
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    // Wire up the fix + verify responses, then remediate.
    h.canned["agentA|fixp"] = {1, "ok"};
    h.canned["agentA|verifyp"] = {1, out_json("fixed", "yes")};

    auto rr = ev.remediate(pid, {});
    REQUIRE(rr.ok);
    CHECK(rr.agents == 1);

    h.fake_now += 20;
    ev.tick(); // collect FixWait -> dispatch verify
    h.fake_now += 20;
    ev.tick(); // collect verify -> final verdict

    CHECK(h.status_of(pid, "agentA") == "compliant");
}

TEST_CASE("policy evaluator: remediation rejected when no fix_instruction",
          "[policy][evaluator]") {
    Harness h;
    h.canned["agentA|checkp"] = {1, out_json("hostname", "")};
    auto pid = h.author("result.hostname != ''", /*with_fix=*/false);

    PolicyEvaluator ev(h.deps());
    REQUIRE_FALSE(ev.evaluate_now(pid).empty());
    h.fake_now += 20;
    ev.tick();
    REQUIRE(h.status_of(pid, "agentA") == "non_compliant");

    auto rr = ev.remediate(pid, {});
    CHECK_FALSE(rr.ok);
    CHECK(rr.error.find("remediation pathway") != std::string::npos);
}
