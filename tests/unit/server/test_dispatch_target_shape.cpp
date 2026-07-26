/**
 * test_dispatch_target_shape.cpp — the pure targeting rule shared by MCP
 * `execute_instruction` (#2492) and the two REST twins (#2500).
 *
 * THE RULE: an OMITTED targeting argument means "the whole fleet"; a SUPPLIED
 * one that resolves to nothing is an ERROR. Collapsing the two is the defect
 * both issues describe — `{"agent_ids":[1,2,3]}` from a client emitting numeric
 * device ids, and `{"agent_ids":[]}` from a device filter that matched nothing,
 * each became a fleet-wide dispatch that returned success.
 *
 * This file pins the rule at the level it is DECIDED, so a route that forgets
 * to call it fails its own route test rather than quietly disagreeing with the
 * other surfaces about what a target is. The reason labels are asserted, not
 * just the reject/accept verdict, because they are the closed metric label set
 * — `server.cpp` pre-seeds `yuzu_server_dispatch_target_rejected_total` by
 * iterating `kTargetingShapeReasons`, so a reason renamed here and not there is
 * emitted-but-unseeded and silently breaks `absent()` alerting.
 */

#include "dispatch_target_shape.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>

using yuzu::server::check_targeting_shape;
using yuzu::server::kTargetingShapeReasons;
using yuzu::server::targeting_supplied;

namespace {

/// The violated reason for `body`, or "" when the shape is accepted.
std::string reason_for(const std::string& body) {
    auto bv = check_targeting_shape(nlohmann::json::parse(body));
    return bv ? std::string(bv->reason) : std::string{};
}

} // namespace

TEST_CASE("#2500 — every widening shape from the issue is refused, with its own reason",
          "[targeting][security][dispatch]") {
    // Row for row, the table in issue #2500. Each of these dispatched to the
    // entire fleet on at least one of the two REST routes before the fix.
    CHECK(reason_for(R"({"agent_ids":[1,2,3]})") == "agent_id_type");
    CHECK(reason_for(R"({"agent_ids":[]})") == "agent_ids_empty");
    CHECK(reason_for(R"({"agent_ids":"dev-01"})") == "agent_ids_type");
    CHECK(reason_for(R"({"agent_ids":null})") == "agent_ids_type");
    CHECK(reason_for(R"({"scope":5})") == "scope_type");
    CHECK(reason_for(R"({"scope":""})") == "scope_empty");

    // A mixed array — one good id, one number — is refused whole rather than
    // silently reduced to the ids that happened to parse. Dropping the bad
    // entry would dispatch to a NARROWER set than the caller asked for, which
    // is the same class of surprise pointing the other way.
    CHECK(reason_for(R"({"agent_ids":["agent-1",2]})") == "agent_id_type");
}

TEST_CASE("#2500 — a genuinely omitted target is accepted (the over-broadness guard)",
          "[targeting][dispatch]") {
    // The half of the rule that is not a refusal. A fix that rejected
    // everything would satisfy every assertion in the case above.
    CHECK(reason_for(R"({})").empty());
    CHECK(reason_for(R"({"plugin":"service","action":"restart"})").empty());
    CHECK(reason_for(R"({"agent_ids":["agent-1"]})").empty());
    CHECK(reason_for(R"({"scope":"tag:prod"})").empty());
    CHECK(reason_for(R"({"agent_ids":["a","b"],"scope":"tag:prod"})").empty());

    // `params` and unrelated keys are none of this function's business — it
    // decides targeting only. The size bounds live with the surface that
    // publishes them (mcp_input_bounds.hpp), deliberately not here.
    CHECK(reason_for(R"({"params":{"k":"v"},"agent_ids":["a"]})").empty());
}

TEST_CASE("#2500 — targeting_supplied distinguishes omitted from resolved-to-nothing",
          "[targeting][dispatch]") {
    // This is the fact a SINK cannot recover on its own: by the time targeting
    // has been extracted into a vector and a string, "" and {} mean both
    // "omitted" and "supplied and thrown away". That erasure is why the guard
    // has to see the parsed body.
    CHECK_FALSE(targeting_supplied(nlohmann::json::parse(R"({})")));
    CHECK_FALSE(targeting_supplied(nlohmann::json::parse(R"({"plugin":"p","action":"a"})")));
    CHECK(targeting_supplied(nlohmann::json::parse(R"({"agent_ids":[]})")));
    CHECK(targeting_supplied(nlohmann::json::parse(R"({"scope":""})")));
    CHECK(targeting_supplied(nlohmann::json::parse(R"({"agent_ids":["a"]})")));
}

TEST_CASE("#2500 — agent_ids is decided before scope, so a denial is reproducible",
          "[targeting][dispatch]") {
    // The function documents a deterministic first-violation order. A body
    // violating both must always name the same one, or the same request logs a
    // different reason label on different builds and the metric becomes noise.
    CHECK(reason_for(R"({"agent_ids":[],"scope":""})") == "agent_ids_empty");
    CHECK(reason_for(R"({"agent_ids":"x","scope":5})") == "agent_ids_type");
}

TEST_CASE("#2500 — every emitted reason is a member of the closed label set",
          "[targeting][dispatch][metrics]") {
    // The boot pre-seed iterates kTargetingShapeReasons. A reason emitted from
    // this function but absent from that array creates its series on first use,
    // which passes the emitting test while the dashboard reads zero until the
    // first refusal — exactly the absent()-alerting break the single-array
    // discipline exists to prevent.
    const std::string bodies[] = {
        R"({"agent_ids":[1]})",  R"({"agent_ids":[]})",   R"({"agent_ids":"x"})",
        R"({"scope":5})",        R"({"scope":""})",
    };
    for (const auto& b : bodies) {
        const auto r = reason_for(b);
        REQUIRE_FALSE(r.empty());
        CHECK(std::find(kTargetingShapeReasons.begin(), kTargetingShapeReasons.end(), r) !=
              kTargetingShapeReasons.end());
    }
    // And the set is exactly the five this function can produce — a sixth added
    // to the array without an emit site would leave a permanently-zero series
    // that reads as "this can never happen".
    CHECK(kTargetingShapeReasons.size() == 5);
}
