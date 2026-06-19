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

#include <cstdint>
#include <stdexcept>
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

// ── Gate-7 governance hardening regressions ─────────────────────────────────

TEST_CASE("orchestrator: a throwing dispatch step is isolated, manifest still stored (UP-1)",
          "[bundle][orchestrator]") {
    // A throw from dispatch_ on step 2 must NOT propagate and must NOT orphan the
    // already-sent commands: the manifest is stored regardless, so collate finds
    // it; the throwing step reads dispatch-failed.
    ResponseStore store(":memory:");
    REQUIRE(store.is_open());
    int n = 0;
    BundleOrchestrator::DispatchFn throwing =
        [&n](const std::string& plugin, const std::string& action, const std::vector<std::string>&,
             const std::string&, const std::unordered_map<std::string, std::string>&,
             const std::string&) -> std::pair<std::string, int> {
        if (++n == 2)
            throw std::runtime_error("gRPC write failed");
        return {"cmd-" + plugin + "-" + action, 1};
    };
    BundleOrchestrator orch(throwing, &store, fixed_id("abc"));
    auto specs = validate_bundle_steps(
        R"([{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"os_name"},{"plugin":"os_info","action":"os_arch"}])");
    REQUIRE(specs.has_value());

    BundleOrchestrator::DispatchResult res;
    REQUIRE_NOTHROW(res = orch.dispatch("agent-1", *specs, "alice", null_audit()));

    auto agg = orch.collate(res.correlation_id, "alice", /*is_admin=*/false);
    REQUIRE(agg.has_value()); // not orphaned
    REQUIRE(agg->steps.size() == 3);
    CHECK(agg->steps[1].state == BundleStepState::DispatchFailed); // the throwing step
    CHECK(agg->steps[0].state == BundleStepState::Pending);        // dispatched, awaiting response
    CHECK(agg->steps[2].state == BundleStepState::Pending);
}

TEST_CASE("orchestrator: a single boundary poll does not self-evict; polling slides the TTL",
          "[bundle][orchestrator]") {
    // governance UP-3/UP-4 / CH-3/CH-4.
    FakeDispatch fd;
    ResponseStore store(":memory:");
    REQUIRE(store.is_open());
    std::int64_t clock = 1000;
    BundleOrchestrator::ClockFn now = [&clock]() { return clock; };
    const std::int64_t ttl = 10000;
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"), /*metrics=*/nullptr,
                            /*surface=*/"test", now, ttl, /*max_manifests=*/4096);
    auto res = orch.dispatch("agent-1", two_steps(), "alice", null_audit());

    // CH-3: first/only poll exactly at created_at + ttl + 1 still serves it
    // (collate finds BEFORE sweeping).
    clock = 1000 + ttl + 1;
    CHECK(orch.collate(res.correlation_id, "alice", false).has_value());

    // CH-4: that poll slid the window — a poll within ttl of the LAST poll works,
    // even though it is far past the original created_at.
    clock += ttl;
    CHECK(orch.collate(res.correlation_id, "alice", false).has_value());
}

TEST_CASE("orchestrator: an abandoned (un-polled) bundle is eventually swept",
          "[bundle][orchestrator]") {
    FakeDispatch fd;
    ResponseStore store(":memory:");
    REQUIRE(store.is_open());
    std::int64_t clock = 0;
    int idctr = 0;
    BundleOrchestrator::ClockFn now = [&clock]() { return clock; };
    BundleOrchestrator::IdMinter mint = [&idctr]() { return std::to_string(idctr++); };
    const std::int64_t ttl = 10000;
    BundleOrchestrator orch(fd.fn(), &store, mint, nullptr, "test", now, ttl, 4096);

    clock = 1000;
    auto abandoned = orch.dispatch("agent-1", two_steps(), "alice", null_audit());
    // Never poll `abandoned`. Jump past ttl AND past the 30s sweep interval, then
    // a fresh dispatch triggers the sweep that drops it.
    clock = 1000 + ttl + 31000;
    orch.dispatch("agent-1", two_steps(), "alice", null_audit());
    CHECK_FALSE(orch.collate(abandoned.correlation_id, "alice", false).has_value());
}

TEST_CASE("orchestrator: an empty principal can never collate (sec-M2/CH-7)",
          "[bundle][orchestrator]") {
    FakeDispatch fd;
    ResponseStore store(":memory:");
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"));
    auto res = orch.dispatch("agent-1", two_steps(), /*principal=*/"", null_audit());
    // Even the (empty) dispatcher cannot collate — empty principal never owns.
    CHECK_FALSE(orch.collate(res.correlation_id, "", /*is_admin=*/false).has_value());
    // Admin break-glass still works.
    CHECK(orch.collate(res.correlation_id, "", /*is_admin=*/true).has_value());
}

TEST_CASE("orchestrator: cap eviction drops the oldest manifest (QE-S3)",
          "[bundle][orchestrator]") {
    FakeDispatch fd;
    ResponseStore store(":memory:");
    REQUIRE(store.is_open());
    std::int64_t clock = 0;
    int idctr = 0;
    BundleOrchestrator::ClockFn now = [&clock]() { return ++clock; }; // distinct, monotonic
    BundleOrchestrator::IdMinter mint = [&idctr]() { return std::to_string(idctr++); };
    // High TTL so only the CAP evicts; max=2.
    BundleOrchestrator orch(fd.fn(), &store, mint, nullptr, "test", now, /*ttl=*/1'000'000'000,
                            /*max_manifests=*/2);
    auto a = orch.dispatch("agent-1", two_steps(), "alice", null_audit());
    auto b = orch.dispatch("agent-1", two_steps(), "alice", null_audit());
    auto c = orch.dispatch("agent-1", two_steps(), "alice", null_audit()); // cap → evict oldest (a)
    CHECK_FALSE(orch.collate(a.correlation_id, "alice", false).has_value());
    CHECK(orch.collate(b.correlation_id, "alice", false).has_value());
    CHECK(orch.collate(c.correlation_id, "alice", false).has_value());
}
