/**
 * test_bundle_orchestrator.cpp — server-side bundle dispatch/collate orchestration
 * (ADR-0011). Exercises the transport-agnostic core with an injected fake
 * DispatchFn + a :memory: ResponseStore + a fixed IdMinter, so no live agent or
 * server is needed. The REST/MCP wrappers are thin over this object.
 */

#include "bundle_orchestrator.hpp"
#include "bundle_service.hpp"
#include "response_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

// Fake per-command dispatcher: records calls, returns a deterministic
// command_id per (plugin,action) and a configurable agents_reached.
struct FakeDispatch {
    struct Call {
        std::string plugin, action, correlation;
        std::vector<std::string> agent_ids;
    };
    std::vector<Call> calls;
    int sent = 1; // agents_reached returned for every step

    BundleOrchestrator::DispatchFn fn() {
        return [this](const std::string& plugin, const std::string& action,
                      const std::vector<std::string>& agent_ids, const std::string& /*scope*/,
                      const std::unordered_map<std::string, std::string>& /*params*/,
                      const std::string& correlation) -> std::pair<std::string, int> {
            calls.push_back(Call{plugin, action, correlation, agent_ids});
            return {"cmd-" + plugin + "-" + action, sent};
        };
    }
};

BundleOrchestrator::IdMinter fixed_id(std::string id) {
    return [id = std::move(id)]() { return id; };
}

// no-op audit
BundleOrchestrator::AuditSink null_audit() {
    return [](const std::string&, const std::string&, const std::string&, const std::string&,
              const std::string&) {};
}

void put_response(ResponseStore& store, const std::string& correlation,
                  const std::string& command_id, int status, const std::string& output) {
    StoredResponse r;
    r.execution_id = correlation;  // stamped with the bundle correlation id
    r.instruction_id = command_id; // == the dispatched command_id
    r.agent_id = "agent-1";
    r.status = status;
    r.output = output;
    r.timestamp = 100;
    store.store(r);
}

std::vector<BundleStepSpec> two_steps() {
    auto v = validate_bundle_steps(
        R"([{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"os_name"}])");
    REQUIRE(v.has_value());
    return *v;
}

} // namespace

TEST_CASE("orchestrator dispatch fans each step under one bundle- correlation id",
          "[bundle][orchestrator]") {
    FakeDispatch fd;
    ResponseStore store(":memory:");
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"));

    int audited = 0;
    auto audit = [&](const std::string& verb, const std::string& result, const std::string& type,
                     const std::string& id, const std::string&) {
        ++audited;
        CHECK(verb.rfind("bundle.os_info.", 0) == 0); // per-step verb, transport-agnostic
        CHECK(result == "dispatched");
        CHECK(type == "Agent"); // device-access audit lens (governance F1)
        CHECK(id == "agent-1");
    };

    auto res = orch.dispatch("agent-1", two_steps(), "alice", audit);
    CHECK(res.correlation_id == "bundle-abc"); // bundle- prefix → notify_exec_tracker skips it
    CHECK(res.expected == 2);
    REQUIRE(fd.calls.size() == 2);
    CHECK(fd.calls[0].correlation == "bundle-abc");
    CHECK(fd.calls[0].agent_ids == std::vector<std::string>{"agent-1"});
    CHECK(audited == 2);
}

TEST_CASE("orchestrator collate groups responses in request order", "[bundle][orchestrator]") {
    FakeDispatch fd;
    ResponseStore store(":memory:");
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"));

    auto res = orch.dispatch("agent-1", two_steps(), "alice", null_audit());

    // Before any response: not complete.
    auto a0 = orch.collate(res.correlation_id, "alice", /*is_admin=*/false);
    REQUIRE(a0.has_value());
    CHECK_FALSE(a0->complete);
    CHECK(a0->received == 0);

    // Responses land (out of order) under the correlation id.
    put_response(store, "bundle-abc", "cmd-os_info-os_name", 1, "os_name|Win");
    put_response(store, "bundle-abc", "cmd-os_info-uptime", 1, "up 3d");

    auto a1 = orch.collate(res.correlation_id, "alice", false);
    REQUIRE(a1.has_value());
    CHECK(a1->complete);
    CHECK(a1->received == 2);
    REQUIRE(a1->steps.size() == 2);
    CHECK(a1->steps[0].action == "uptime"); // request order, not arrival
    CHECK(a1->steps[0].output == "up 3d");
    CHECK(a1->steps[1].action == "os_name");
}

TEST_CASE("orchestrator: a step that reached no agent is dispatch-failed (terminal)",
          "[bundle][orchestrator]") {
    FakeDispatch fd;
    fd.sent = 0; // every step reaches 0 agents
    ResponseStore store(":memory:");
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"));

    auto res = orch.dispatch("agent-1", two_steps(), "alice", null_audit());
    auto a = orch.collate(res.correlation_id, "alice", false);
    REQUIRE(a.has_value());
    CHECK(a->complete); // dispatch-failed steps are terminal, don't hold it open
    CHECK(a->received == 0);
    for (const auto& s : a->steps)
        CHECK(s.state == BundleStepState::DispatchFailed);
}

TEST_CASE("orchestrator collate enforces ownership (IDOR guard)", "[bundle][orchestrator]") {
    FakeDispatch fd;
    ResponseStore store(":memory:");
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"));

    auto res = orch.dispatch("agent-1", two_steps(), "alice", null_audit());

    // Wrong principal, not admin → nullopt (indistinguishable from not-found).
    CHECK_FALSE(orch.collate(res.correlation_id, "mallory", /*is_admin=*/false).has_value());
    // Admin override is allowed.
    CHECK(orch.collate(res.correlation_id, "mallory", /*is_admin=*/true).has_value());
    // Owner is allowed.
    CHECK(orch.collate(res.correlation_id, "alice", false).has_value());
}

TEST_CASE("orchestrator collate of an unknown correlation id is nullopt", "[bundle][orchestrator]") {
    FakeDispatch fd;
    ResponseStore store(":memory:");
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"));
    CHECK_FALSE(orch.collate("bundle-nope", "alice", false).has_value());
}
