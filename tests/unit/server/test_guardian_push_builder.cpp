/**
 * test_guardian_push_builder.cpp — Unit tests for the per-agent Guardian push
 * builder (M4 + M7 / #1209).
 *
 * The push fan-out lambda in server.cpp had zero unit coverage; its rule
 * filtering (OS target + per-agent scope) and the spec_json → proto marshal were
 * exercised only by manual Windows UAT. This pins both via the pure helper the
 * lambda now delegates to, with no live AgentRegistry or gRPC stream.
 */

#include "guardian_push_builder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <functional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

GuaranteedStateRuleRow row(std::string id, std::string os, std::string scope,
                           bool enabled = true) {
    GuaranteedStateRuleRow r;
    r.rule_id = id;
    r.name = std::move(id);
    r.enabled = enabled;
    r.enforcement_mode = "enforce";
    r.os_target = std::move(os);
    r.scope_expr = std::move(scope);
    r.spec_json =
        R"({"spark":{"type":"registry-change","params":{"hive":"HKLM"}},)"
        R"("assertion":{"type":"registry-value-equals","params":{"value_name":"Start","expected":"4"}},)"
        R"("remediation":{"type":"alert-only"}})";
    return r;
}

std::vector<std::string> rule_ids(const ::yuzu::guardian::v1::GuaranteedStatePush& push) {
    std::vector<std::string> ids;
    for (const auto& r : push.rules())
        ids.push_back(r.rule_id());
    return ids;
}

const auto always_in_scope = [](const std::string&) { return true; };
const auto never_in_scope = [](const std::string&) { return false; };

} // namespace

TEST_CASE("guardian::os_target_matches", "[guardian_push_builder]") {
    CHECK(guardian::os_target_matches("", "windows"));        // empty target = all OSes
    CHECK(guardian::os_target_matches("windows", "windows"));
    CHECK(guardian::os_target_matches("WINDOWS", "windows"));  // case-insensitive
    CHECK_FALSE(guardian::os_target_matches("windows", "linux"));
    // The agent reports kAgentOs "darwin"; rule os_target authors "macos" — they
    // normalize to the same token so a macOS rule reaches a Darwin agent (#1209).
    CHECK(guardian::os_target_matches("macos", "darwin"));
    // Exact-token, NOT substring: a short/ambiguous target must not cross-match
    // (the old substring match made "win" hit "darwin"). #1209 regression guard.
    CHECK_FALSE(guardian::os_target_matches("win", "darwin"));
    CHECK_FALSE(guardian::os_target_matches("linux", "linuxmint"));
    // Unknown agent OS fails OPEN (send it, agent decides) — never silently drop a
    // guard for an agent whose session has no os. Regression guard for #1209/H1-M4.
    CHECK(guardian::os_target_matches("linux", ""));
}

TEST_CASE("build_agent_push: filters by enabled / OS / scope", "[guardian_push_builder]") {
    std::vector<GuaranteedStateRuleRow> rules = {
        row("win-on", "windows", "tag:a"),
        row("lin-on", "linux", "tag:a"),                 // wrong OS for a windows agent
        row("win-off", "windows", "tag:a", /*enabled=*/false),
        row("all-os", "", "tag:a"),                      // os_target "" = all
    };

    auto push = guardian::build_agent_push(rules, "windows", always_in_scope,
                                           /*full_sync=*/true, /*generation=*/7);

    CHECK(push.full_sync());
    CHECK(push.policy_generation() == 7);
    // Only the enabled rules that target this agent's OS survive.
    CHECK(rule_ids(push) == std::vector<std::string>{"win-on", "all-os"});
}

TEST_CASE("build_agent_push: empty scope_expr is fleet-wide, never consults the oracle",
          "[guardian_push_builder]") {
    std::vector<GuaranteedStateRuleRow> rules = {
        row("scoped", "windows", "tag:a"),  // oracle says no
        row("fleet", "windows", ""),        // empty scope → always included
    };
    // never_in_scope rejects every scope_expr; only the empty-scope rule passes.
    auto push = guardian::build_agent_push(rules, "windows", never_in_scope,
                                           /*full_sync=*/false, /*generation=*/1);
    CHECK_FALSE(push.full_sync());
    CHECK(rule_ids(push) == std::vector<std::string>{"fleet"});
}

TEST_CASE("build_agent_push: spec_json round-trips into typed proto blocks",
          "[guardian_push_builder]") {
    auto push = guardian::build_agent_push({row("r", "windows", "tag:a")}, "windows",
                                           always_in_scope, true, 1);
    REQUIRE(push.rules_size() == 1);
    const auto& pr = push.rules(0);
    CHECK(pr.rule_id() == "r");
    CHECK(pr.enabled());
    CHECK(pr.enforcement_mode() == "enforce");
    CHECK(pr.spark().type() == "registry-change");
    REQUIRE(pr.spark().params().contains("hive"));
    CHECK(pr.spark().params().at("hive") == "HKLM");
    CHECK(pr.assertion().type() == "registry-value-equals");
    CHECK(pr.assertion().params().at("expected") == "4");
    CHECK(pr.remediation().type() == "alert-only");
}

TEST_CASE("build_agent_push: legacy rule with empty spec_json is header-only",
          "[guardian_push_builder]") {
    GuaranteedStateRuleRow legacy;
    legacy.rule_id = "leg";
    legacy.name = "leg";
    legacy.enabled = true;
    legacy.enforcement_mode = "audit";
    legacy.os_target = "";
    legacy.scope_expr = "";
    legacy.spec_json = "";  // pre-migration row — not agent-enforceable

    auto push = guardian::build_agent_push({legacy}, "windows", always_in_scope, true, 1);
    REQUIRE(push.rules_size() == 1);
    CHECK(push.rules(0).rule_id() == "leg");
    CHECK(push.rules(0).enforcement_mode() == "audit");
    CHECK(push.rules(0).spark().type().empty());        // no spec blocks filled
    CHECK(push.rules(0).assertion().type().empty());
}
