/**
 * test_bundle_service.cpp — server-side live-query bundle core (ADR-0011).
 *
 * Pure pieces only: step-list validation and the collate/aggregate that matches
 * response rows to the dispatched-step map by command_id. No DB. The dispatch
 * fan-out + persistence + REST/MCP wiring are exercised at the integration/UAT
 * layer.
 */

#include "bundle_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

// ── validate_bundle_steps ────────────────────────────────────────────────────

TEST_CASE("validate_bundle_steps accepts valid steps and lower-cases", "[bundle][validate]") {
    auto r = validate_bundle_steps(
        R"([{"plugin":"OS_Info","action":"UpTime"},{"plugin":"hardware","action":"memory","params":{"k":"v"}}])");
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 2);
    CHECK((*r)[0].plugin == "os_info");
    CHECK((*r)[0].action == "uptime");
    CHECK((*r)[1].plugin == "hardware");
    REQUIRE((*r)[1].params.size() == 1);
    CHECK((*r)[1].params[0].first == "k");
    CHECK((*r)[1].params[0].second == "v");
}

TEST_CASE("validate_bundle_steps coerces non-string param values", "[bundle][validate]") {
    auto r = validate_bundle_steps(R"([{"plugin":"p","action":"a","params":{"n":42,"b":true}}])");
    REQUIRE(r.has_value());
    REQUIRE((*r)[0].params.size() == 2);
    auto find = [&](const std::string& k) {
        for (const auto& [pk, pv] : (*r)[0].params)
            if (pk == k) return pv;
        return std::string("<missing>");
    };
    CHECK(find("n") == "42");
    CHECK(find("b") == "true");
}

TEST_CASE("validate_bundle_steps rejects malformed / unsafe steps", "[bundle][validate][unhappy]") {
    CHECK_FALSE(validate_bundle_steps("not json").has_value());
    CHECK_FALSE(validate_bundle_steps(R"({"plugin":"p","action":"a"})").has_value()); // object
    CHECK_FALSE(validate_bundle_steps("[]").has_value());                              // empty
    CHECK_FALSE(validate_bundle_steps(R"([{"action":"a"}])").has_value());             // no plugin
    CHECK_FALSE(validate_bundle_steps(R"([{"plugin":"p"}])").has_value());             // no action
    CHECK_FALSE(validate_bundle_steps(R"([{"plugin":2,"action":"a"}])").has_value());  // plugin !str
    // identifier safety (audit-verb injection attempts)
    CHECK_FALSE(validate_bundle_steps(R"([{"plugin":"p p","action":"a"}])").has_value());
    CHECK_FALSE(validate_bundle_steps(R"([{"plugin":"p","action":"a\nx"}])").has_value());
    CHECK_FALSE(validate_bundle_steps(R"([{"plugin":"p","action":"a","params":[]}])").has_value());
}

TEST_CASE("validate_bundle_steps rejects duplicate (plugin,action) but allows same plugin diff action",
          "[bundle][validate]") {
    CHECK_FALSE(validate_bundle_steps(
                    R"([{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"uptime"}])")
                    .has_value());
    // same plugin, different action is fine (ServiceNow does several os_info actions)
    auto ok = validate_bundle_steps(
        R"([{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"os_name"}])");
    REQUIRE(ok.has_value());
    CHECK(ok->size() == 2);
}

TEST_CASE("validate_bundle_steps enforces the step cap", "[bundle][validate][unhappy]") {
    std::string over = "[";
    for (std::size_t i = 0; i < kMaxBundleSteps + 1; ++i) {
        if (i) over += ',';
        over += R"({"plugin":"p","action":"a)" + std::to_string(i) + R"("})"; // distinct actions
    }
    over += "]";
    CHECK_FALSE(validate_bundle_steps(over).has_value());
}

// ── aggregate_bundle ─────────────────────────────────────────────────────────

namespace {
DispatchedStep step(std::string cmd, std::string plugin, std::string action) {
    return DispatchedStep{std::move(cmd), std::move(plugin), std::move(action)};
}
BundleResponseRow row(std::string cmd, int status, std::string out) {
    return BundleResponseRow{std::move(cmd), status, std::move(out)};
}
} // namespace

TEST_CASE("aggregate_bundle: all responded → complete, request order preserved", "[bundle][collate]") {
    std::vector<DispatchedStep> steps{step("c1", "os_info", "uptime"),
                                      step("c2", "os_info", "os_name")};
    std::vector<BundleResponseRow> rows{row("c2", 1, "os_name|Win"), row("c1", 1, "up 3d")};
    auto agg = aggregate_bundle(steps, rows);
    CHECK(agg.complete);
    CHECK(agg.received == 2);
    CHECK(agg.expected == 2);
    REQUIRE(agg.steps.size() == 2);
    // request order, not row arrival order
    CHECK(agg.steps[0].action == "uptime");
    CHECK(agg.steps[0].output == "up 3d");
    CHECK(agg.steps[1].action == "os_name");
    CHECK(agg.steps[1].output == "os_name|Win");
}

TEST_CASE("aggregate_bundle: a missing response is Pending → not complete", "[bundle][collate]") {
    std::vector<DispatchedStep> steps{step("c1", "a", "x"), step("c2", "b", "y")};
    std::vector<BundleResponseRow> rows{row("c1", 1, "o1")};
    auto agg = aggregate_bundle(steps, rows);
    CHECK_FALSE(agg.complete);
    CHECK(agg.received == 1);
    CHECK(agg.steps[0].state == BundleStepState::Responded);
    CHECK(agg.steps[1].state == BundleStepState::Pending);
}

TEST_CASE("aggregate_bundle: dispatch-failed step is terminal, not pending-forever", "[bundle][collate]") {
    // c2 never dispatched (empty command_id) → DispatchFailed; with c1 responded
    // and nothing Pending, the bundle is complete.
    std::vector<DispatchedStep> steps{step("c1", "a", "x"), step("", "b", "y")};
    std::vector<BundleResponseRow> rows{row("c1", 1, "o1")};
    auto agg = aggregate_bundle(steps, rows);
    CHECK(agg.steps[1].state == BundleStepState::DispatchFailed);
    CHECK(agg.received == 1);
    CHECK(agg.complete); // dispatch-failed doesn't hold it open
}

TEST_CASE("aggregate_to_json carries flags + per-step state tokens", "[bundle][collate]") {
    std::vector<DispatchedStep> steps{step("c1", "os_info", "uptime"), step("c2", "proc", "list"),
                                      step("", "rdp_control", "status")};
    std::vector<BundleResponseRow> rows{row("c1", 1, "up")};
    auto agg = aggregate_bundle(steps, rows);
    auto j = nlohmann::json::parse(aggregate_to_json(agg));
    CHECK(j.at("complete") == false); // c2 pending
    CHECK(j.at("received") == 1);
    CHECK(j.at("expected") == 3);
    REQUIRE(j.at("steps").size() == 3);
    CHECK(j["steps"][0].at("state") == "responded");
    CHECK(j["steps"][0].at("output") == "up");
    CHECK(j["steps"][1].at("state") == "pending");
    CHECK(j["steps"][2].at("state") == "dispatch_failed");
    CHECK(j["steps"][2].at("plugin") == "rdp_control");
}
