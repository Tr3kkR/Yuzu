/**
 * test_policy_store.cpp -- Unit tests for PolicyStore
 *
 * Covers: Fragment CRUD, Policy CRUD, compliance tracking, cache invalidation,
 * YAML parsing edge cases, cascading deletes.
 */

#include "policy_store.hpp"
#include "store_errors.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;

// ---- YAML helpers ----------------------------------------------------------

static const std::string kCheckOnlyFragment = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
displayName: Check Service Running
description: Verify a Windows service is running
spec:
  check:
    instruction: get_service_status
    compliance: "result.status == 'running'"
    parameters:
      service_name: "{{inputs.service}}"
)";

static const std::string kFullFragment = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
id: frag-full-001
displayName: Full Fragment
description: Fragment with check, fix, and postCheck
spec:
  check:
    instruction: get_service_status
    compliance: "result.status == 'running'"
    parameters:
      service_name: "{{inputs.service}}"
  fix:
    instruction: start_service
    parameters:
      service_name: "{{inputs.service}}"
  postCheck:
    instruction: get_service_status
    compliance: "result.status == 'running'"
    parameters:
      service_name: "{{inputs.service}}"
)";

static const std::string kCheckOnlyNoFix = R"(
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
id: frag-check-only
displayName: Check Only Fragment
description: A fragment with only a check section
spec:
  check:
    instruction: check_disk_space
    compliance: "result.free_gb > 10"
    parameters:
      drive: C
)";

// Returns a Policy YAML that references the given fragment ID
static std::string make_policy_yaml(const std::string& fragment_id,
                                     const std::string& name = "Test Policy") {
    return R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: )" +
           name + R"(
description: A test policy
fragment: )" +
           fragment_id + R"(
scope: "tags.env == 'production'"
inputs:
  service: WinRM
triggers:
  - type: interval
    interval_seconds: 300
  - type: file_change
    path: "C:\\config.yaml"
managementGroups:
  - "all-devices"
  - "windows-servers"
)";
}

// ============================================================================
// Fragment CRUD
// ============================================================================

TEST_CASE("PolicyStore: open in-memory", "[policy_store][db]") {
    PolicyStore store(":memory:");
    REQUIRE(store.is_open());
}

TEST_CASE("PolicyStore: create fragment from YAML", "[policy_store][fragment]") {
    PolicyStore store(":memory:");

    auto result = store.create_fragment(kCheckOnlyFragment);
    REQUIRE(result.has_value());
    CHECK(!result.value().empty());

    // Retrieve it
    auto frag = store.get_fragment(result.value());
    REQUIRE(frag.has_value());
    CHECK(frag->name == "Check Service Running");
    CHECK(frag->description == "Verify a Windows service is running");
    CHECK(frag->check_instruction == "get_service_status");
    CHECK(frag->check_compliance == "result.status == 'running'");
    CHECK(frag->created_at > 0);
    CHECK(frag->updated_at > 0);
}

TEST_CASE("PolicyStore: create fragment with explicit ID", "[policy_store][fragment]") {
    PolicyStore store(":memory:");

    auto result = store.create_fragment(kFullFragment);
    REQUIRE(result.has_value());
    CHECK(result.value() == "frag-full-001");

    auto frag = store.get_fragment("frag-full-001");
    REQUIRE(frag.has_value());
    CHECK(frag->name == "Full Fragment");
}

TEST_CASE("PolicyStore: query fragments", "[policy_store][fragment]") {
    PolicyStore store(":memory:");

    store.create_fragment(kCheckOnlyFragment);
    store.create_fragment(kFullFragment);
    store.create_fragment(kCheckOnlyNoFix);

    // Unfiltered
    auto all = store.query_fragments();
    REQUIRE(all.size() == 3);

    // Name filter
    FragmentQuery q;
    q.name_filter = "Check";
    auto filtered = store.query_fragments(q);
    REQUIRE(filtered.size() == 2); // "Check Service Running" and "Check Only Fragment"

    // Limit
    FragmentQuery q2;
    q2.limit = 1;
    auto limited = store.query_fragments(q2);
    REQUIRE(limited.size() == 1);
}

TEST_CASE("PolicyStore: delete fragment", "[policy_store][fragment]") {
    PolicyStore store(":memory:");

    auto result = store.create_fragment(kCheckOnlyFragment);
    REQUIRE(result.has_value());

    CHECK(store.delete_fragment(result.value()) == true);
    CHECK(store.get_fragment(result.value()) == std::nullopt);

    // Second delete returns false
    CHECK(store.delete_fragment(result.value()) == false);
}

TEST_CASE("PolicyStore: create fragment with duplicate ID", "[policy_store][fragment]") {
    PolicyStore store(":memory:");

    auto r1 = store.create_fragment(kFullFragment);
    REQUIRE(r1.has_value());
    CHECK(r1.value() == "frag-full-001");

    // Attempt duplicate — fragment has both duplicate id and duplicate
    // displayName. The #396 name guard fires first (and is more informative
    // than the SQLite PK constraint message), so the error carries the
    // "conflict:" prefix routes use to map to HTTP 409.
    auto r2 = store.create_fragment(kFullFragment);
    REQUIRE(!r2.has_value());
    CHECK(is_conflict_error(r2.error()));
}

TEST_CASE("PolicyStore: create fragment with empty YAML", "[policy_store][fragment]") {
    PolicyStore store(":memory:");

    auto result = store.create_fragment("");
    REQUIRE(!result.has_value());
    CHECK(result.error() == "yaml_source is required");
}

TEST_CASE("PolicyStore: create fragment with wrong kind", "[policy_store][fragment]") {
    PolicyStore store(":memory:");

    auto result = store.create_fragment("kind: Policy\nname: oops\n");
    REQUIRE(!result.has_value());
    CHECK(result.error().find("kind must be 'PolicyFragment'") != std::string::npos);
    // Issue #621: error must include a worked example so operators sending
    // partial YAML (or sending `kind` as a request param) get unstuck without
    // having to find the docs separately. The prefix above stays stable so
    // existing scripts that grep on it keep working.
    CHECK(result.error().find("apiVersion: yuzu.io/v1alpha1") != std::string::npos);
    CHECK(result.error().find("docs/user-manual/policy-engine.md") != std::string::npos);
}

TEST_CASE("PolicyStore: create fragment with missing kind", "[policy_store][fragment]") {
    PolicyStore store(":memory:");

    auto result = store.create_fragment("name: no-kind\ndescription: missing kind field\n");
    REQUIRE(!result.has_value());
    CHECK(result.error().find("kind must be 'PolicyFragment'") != std::string::npos);
    CHECK(result.error().find("apiVersion: yuzu.io/v1alpha1") != std::string::npos);
    // Governance Gate 7 (consistency S2 / QA SHOULD): docs link must be
    // pinned on this branch too — not just the wrong-kind branch — so the
    // operator-facing UX is symmetric across both `kind`-failure modes.
    CHECK(result.error().find("docs/user-manual/policy-engine.md") != std::string::npos);
}

TEST_CASE("PolicyStore: fragment with check only (no fix, no postCheck)",
          "[policy_store][fragment][yaml]") {
    PolicyStore store(":memory:");

    auto result = store.create_fragment(kCheckOnlyNoFix);
    REQUIRE(result.has_value());

    auto frag = store.get_fragment(result.value());
    REQUIRE(frag.has_value());
    CHECK(frag->check_instruction == "check_disk_space");
    CHECK(frag->check_compliance == "result.free_gb > 10");
    CHECK(frag->fix_instruction.empty());
    CHECK(frag->fix_parameters == "{}");
    CHECK(frag->post_check_instruction.empty());
    CHECK(frag->post_check_parameters == "{}");
}

TEST_CASE("PolicyStore: fragment with all three sections", "[policy_store][fragment][yaml]") {
    PolicyStore store(":memory:");

    auto result = store.create_fragment(kFullFragment);
    REQUIRE(result.has_value());

    auto frag = store.get_fragment("frag-full-001");
    REQUIRE(frag.has_value());
    CHECK(frag->check_instruction == "get_service_status");
    CHECK(frag->check_compliance == "result.status == 'running'");
    CHECK(frag->fix_instruction == "start_service");
    CHECK(frag->post_check_instruction == "get_service_status");
    CHECK(frag->post_check_compliance == "result.status == 'running'");
}

TEST_CASE("PolicyStore: cannot delete fragment referenced by a policy",
          "[policy_store][fragment]") {
    PolicyStore store(":memory:");

    auto frag_result = store.create_fragment(kFullFragment);
    REQUIRE(frag_result.has_value());

    // Create a policy referencing the fragment
    auto yaml = make_policy_yaml(frag_result.value());
    auto pol_result = store.create_policy(yaml);
    REQUIRE(pol_result.has_value());

    // Delete should fail
    CHECK(store.delete_fragment(frag_result.value()) == false);

    // Fragment should still exist
    CHECK(store.get_fragment(frag_result.value()).has_value());
}

// ============================================================================
// Policy CRUD
// ============================================================================

TEST_CASE("PolicyStore: create policy from YAML", "[policy_store][policy]") {
    PolicyStore store(":memory:");

    // Create prerequisite fragment
    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    auto yaml = make_policy_yaml(frag.value(), "My Service Policy");
    auto result = store.create_policy(yaml);
    REQUIRE(result.has_value());
    CHECK(!result.value().empty());

    // Verify
    auto pol = store.get_policy(result.value());
    REQUIRE(pol.has_value());
    CHECK(pol->name == "My Service Policy");
    CHECK(pol->description == "A test policy");
    CHECK(pol->fragment_id == frag.value());
    CHECK(pol->enabled == true);
    CHECK(pol->created_at > 0);

    // Inputs
    REQUIRE(pol->inputs.size() == 1);
    CHECK(pol->inputs[0].key == "service");
    CHECK(pol->inputs[0].value == "WinRM");

    // Triggers
    REQUIRE(pol->triggers.size() == 2);
    bool has_interval = false, has_file_change = false;
    for (const auto& t : pol->triggers) {
        if (t.trigger_type == "interval")
            has_interval = true;
        if (t.trigger_type == "file_change")
            has_file_change = true;
    }
    CHECK(has_interval);
    CHECK(has_file_change);

    // Management groups
    REQUIRE(pol->management_groups.size() == 2);
    CHECK(pol->management_groups[0] == "all-devices");
    CHECK(pol->management_groups[1] == "windows-servers");
}

TEST_CASE("PolicyStore: query policies with filters", "[policy_store][policy]") {
    PolicyStore store(":memory:");

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    store.create_policy(make_policy_yaml(frag.value(), "Alpha Policy"));
    store.create_policy(make_policy_yaml(frag.value(), "Beta Policy"));
    store.create_policy(make_policy_yaml(frag.value(), "Gamma Policy"));

    // Unfiltered
    auto all = store.query_policies();
    REQUIRE(all.size() == 3);

    // Name filter
    PolicyQuery q;
    q.name_filter = "Alpha";
    auto filtered = store.query_policies(q);
    REQUIRE(filtered.size() == 1);
    CHECK(filtered[0].name == "Alpha Policy");

    // Fragment filter
    PolicyQuery q2;
    q2.fragment_filter = frag.value();
    auto by_frag = store.query_policies(q2);
    CHECK(by_frag.size() == 3);

    // Limit
    PolicyQuery q3;
    q3.limit = 2;
    auto limited = store.query_policies(q3);
    CHECK(limited.size() == 2);
}

TEST_CASE("PolicyStore: enable and disable policy", "[policy_store][policy]") {
    PolicyStore store(":memory:");

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    auto pol_result = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol_result.has_value());

    // Initially enabled
    auto pol = store.get_policy(pol_result.value());
    REQUIRE(pol.has_value());
    CHECK(pol->enabled == true);

    // Disable
    auto disable_r = store.disable_policy(pol_result.value());
    REQUIRE(disable_r.has_value());

    pol = store.get_policy(pol_result.value());
    REQUIRE(pol.has_value());
    CHECK(pol->enabled == false);

    // enabled_only filter should exclude it
    PolicyQuery q;
    q.enabled_only = true;
    auto enabled = store.query_policies(q);
    CHECK(enabled.empty());

    // Re-enable
    auto enable_r = store.enable_policy(pol_result.value());
    REQUIRE(enable_r.has_value());

    pol = store.get_policy(pol_result.value());
    REQUIRE(pol.has_value());
    CHECK(pol->enabled == true);
}

TEST_CASE("PolicyStore: enable/disable nonexistent policy", "[policy_store][policy]") {
    PolicyStore store(":memory:");

    auto r = store.enable_policy("does-not-exist");
    REQUIRE(!r.has_value());
    CHECK(r.error() == "policy not found");

    auto r2 = store.disable_policy("does-not-exist");
    REQUIRE(!r2.has_value());
    CHECK(r2.error() == "policy not found");
}

TEST_CASE("PolicyStore: delete policy cascades", "[policy_store][policy]") {
    PolicyStore store(":memory:");

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    auto pol_result = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol_result.has_value());

    // Add some compliance status
    store.update_agent_status(pol_result.value(), "agent-1", "compliant");
    store.update_agent_status(pol_result.value(), "agent-2", "non_compliant");

    // Delete the policy
    CHECK(store.delete_policy(pol_result.value()) == true);

    // Verify policy is gone
    CHECK(store.get_policy(pol_result.value()) == std::nullopt);

    // Verify compliance status is gone
    CHECK(store.get_agent_status(pol_result.value(), "agent-1") == std::nullopt);
    CHECK(store.get_agent_status(pol_result.value(), "agent-2") == std::nullopt);

    // Verify compliance summary is empty
    auto cs = store.get_compliance_summary(pol_result.value());
    CHECK(cs.total == 0);

    // Second delete returns false
    CHECK(store.delete_policy(pol_result.value()) == false);
}

TEST_CASE("PolicyStore: create policy with empty YAML", "[policy_store][policy]") {
    PolicyStore store(":memory:");

    auto r = store.create_policy("");
    REQUIRE(!r.has_value());
    CHECK(r.error() == "yaml_source is required");
}

TEST_CASE("PolicyStore: create policy with wrong kind", "[policy_store][policy]") {
    PolicyStore store(":memory:");

    auto r = store.create_policy("kind: PolicyFragment\nname: wrong\n");
    REQUIRE(!r.has_value());
    CHECK(r.error().find("kind must be 'Policy'") != std::string::npos);
    // Issue #621: same UX expectation as create_fragment — operators must
    // see a worked example in the error body, not just the prefix.
    CHECK(r.error().find("apiVersion: yuzu.io/v1alpha1") != std::string::npos);
    CHECK(r.error().find("docs/user-manual/policy-engine.md") != std::string::npos);
}

TEST_CASE("PolicyStore: create policy with missing kind", "[policy_store][policy]") {
    PolicyStore store(":memory:");

    // Governance Gate 7 (consistency S2 / QA SHOULD): symmetric coverage
    // with the create_fragment "missing kind" case above. Without this
    // test the asymmetry would let a future regression that drops the
    // worked-example body from create_policy alone slip through CI.
    auto r = store.create_policy("name: no-kind\ndescription: missing kind field\n");
    REQUIRE(!r.has_value());
    CHECK(r.error().find("kind must be 'Policy'") != std::string::npos);
    CHECK(r.error().find("apiVersion: yuzu.io/v1alpha1") != std::string::npos);
    CHECK(r.error().find("docs/user-manual/policy-engine.md") != std::string::npos);
}

TEST_CASE("PolicyStore: create policy with missing fragment", "[policy_store][policy]") {
    PolicyStore store(":memory:");

    auto yaml = make_policy_yaml("nonexistent-fragment-id");
    auto r = store.create_policy(yaml);
    REQUIRE(!r.has_value());
    CHECK(r.error().find("not found") != std::string::npos);
}

TEST_CASE("PolicyStore: create policy without fragment field", "[policy_store][policy]") {
    PolicyStore store(":memory:");

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: No Fragment
description: missing fragment field
)";
    auto r = store.create_policy(yaml);
    REQUIRE(!r.has_value());
    CHECK(r.error().find("fragment") != std::string::npos);
}

// ============================================================================
// Compliance tracking
// ============================================================================

TEST_CASE("PolicyStore: update and get agent status", "[policy_store][compliance]") {
    PolicyStore store(":memory:");

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    // Set status
    auto r = store.update_agent_status(pol.value(), "agent-1", "compliant", "{\"status\":\"ok\"}");
    REQUIRE(r.has_value());

    // Retrieve
    auto status = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(status.has_value());
    CHECK(status->policy_id == pol.value());
    CHECK(status->agent_id == "agent-1");
    CHECK(status->status == "compliant");
    CHECK(status->check_result == "{\"status\":\"ok\"}");
    CHECK(status->last_check_at > 0);
}

TEST_CASE("PolicyStore: update agent status overwrites", "[policy_store][compliance]") {
    PolicyStore store(":memory:");

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    store.update_agent_status(pol.value(), "agent-1", "unknown");
    store.update_agent_status(pol.value(), "agent-1", "compliant");

    auto status = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(status.has_value());
    CHECK(status->status == "compliant");
}

TEST_CASE("PolicyStore: update agent status with invalid status", "[policy_store][compliance]") {
    PolicyStore store(":memory:");

    auto r = store.update_agent_status("pol-1", "agent-1", "garbage");
    REQUIRE(!r.has_value());
    CHECK(r.error().find("invalid status") != std::string::npos);
}

TEST_CASE("PolicyStore: update agent status with empty IDs", "[policy_store][compliance]") {
    PolicyStore store(":memory:");

    auto r1 = store.update_agent_status("", "agent-1", "compliant");
    REQUIRE(!r1.has_value());

    auto r2 = store.update_agent_status("pol-1", "", "compliant");
    REQUIRE(!r2.has_value());
}

TEST_CASE("PolicyStore: get compliance summary", "[policy_store][compliance]") {
    PolicyStore store(":memory:");

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    store.update_agent_status(pol.value(), "agent-1", "compliant");
    store.update_agent_status(pol.value(), "agent-2", "compliant");
    store.update_agent_status(pol.value(), "agent-3", "non_compliant");
    store.update_agent_status(pol.value(), "agent-4", "unknown");
    store.update_agent_status(pol.value(), "agent-5", "fixing");
    store.update_agent_status(pol.value(), "agent-6", "error");

    auto cs = store.get_compliance_summary(pol.value());
    CHECK(cs.policy_id == pol.value());
    CHECK(cs.compliant == 2);
    CHECK(cs.non_compliant == 1);
    CHECK(cs.unknown == 1);
    CHECK(cs.fixing == 1);
    CHECK(cs.error == 1);
    CHECK(cs.total == 6);
}

TEST_CASE("PolicyStore: get compliance summary for empty policy",
          "[policy_store][compliance]") {
    PolicyStore store(":memory:");

    auto cs = store.get_compliance_summary("nonexistent");
    CHECK(cs.policy_id == "nonexistent");
    CHECK(cs.total == 0);
    CHECK(cs.compliant == 0);
}

TEST_CASE("PolicyStore: get fleet compliance", "[policy_store][compliance]") {
    PolicyStore store(":memory:");

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    store.update_agent_status(pol.value(), "agent-1", "compliant");
    store.update_agent_status(pol.value(), "agent-2", "compliant");
    store.update_agent_status(pol.value(), "agent-3", "non_compliant");
    store.update_agent_status(pol.value(), "agent-4", "compliant");

    auto fc = store.get_fleet_compliance();
    CHECK(fc.total_checks == 4);
    CHECK(fc.compliant == 3);
    CHECK(fc.non_compliant == 1);
    // 3/4 = 75%
    CHECK(fc.compliance_pct > 74.9);
    CHECK(fc.compliance_pct < 75.1);
}

TEST_CASE("PolicyStore: get fleet compliance with no data", "[policy_store][compliance]") {
    PolicyStore store(":memory:");

    auto fc = store.get_fleet_compliance();
    CHECK(fc.total_checks == 0);
    CHECK(fc.compliance_pct == 0.0);
}

TEST_CASE("PolicyStore: get policy agent statuses", "[policy_store][compliance]") {
    PolicyStore store(":memory:");

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    store.update_agent_status(pol.value(), "agent-1", "compliant");
    store.update_agent_status(pol.value(), "agent-2", "non_compliant");

    auto statuses = store.get_policy_agent_statuses(pol.value());
    REQUIRE(statuses.size() == 2);
    // Ordered by agent_id
    CHECK(statuses[0].agent_id == "agent-1");
    CHECK(statuses[0].status == "compliant");
    CHECK(statuses[1].agent_id == "agent-2");
    CHECK(statuses[1].status == "non_compliant");
}

TEST_CASE("PolicyStore: fixing status updates last_fix_at", "[policy_store][compliance]") {
    PolicyStore store(":memory:");

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    // First check, not fixing
    store.update_agent_status(pol.value(), "agent-1", "non_compliant");
    auto s1 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s1.has_value());
    CHECK(s1->last_fix_at == 0);

    // Now fixing
    store.update_agent_status(pol.value(), "agent-1", "fixing");
    auto s2 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s2.has_value());
    CHECK(s2->last_fix_at > 0);
}

// ============================================================================
// Cache invalidation
// ============================================================================

TEST_CASE("PolicyStore: invalidate policy resets statuses", "[policy_store][invalidation]") {
    PolicyStore store(":memory:");

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());
    auto pol = store.create_policy(make_policy_yaml(frag.value()));
    REQUIRE(pol.has_value());

    store.update_agent_status(pol.value(), "agent-1", "compliant");
    store.update_agent_status(pol.value(), "agent-2", "non_compliant");
    store.update_agent_status(pol.value(), "agent-3", "error");

    auto r = store.invalidate_policy(pol.value());
    REQUIRE(r.has_value());
    CHECK(r.value() == 3);

    // All should be 'unknown' now (invalidation resets to unknown)
    auto s1 = store.get_agent_status(pol.value(), "agent-1");
    REQUIRE(s1.has_value());
    CHECK(s1->status == "unknown");

    auto s2 = store.get_agent_status(pol.value(), "agent-2");
    REQUIRE(s2.has_value());
    CHECK(s2->status == "unknown");

    auto s3 = store.get_agent_status(pol.value(), "agent-3");
    REQUIRE(s3.has_value());
    CHECK(s3->status == "unknown");
}

TEST_CASE("PolicyStore: invalidate nonexistent policy returns 0",
          "[policy_store][invalidation]") {
    PolicyStore store(":memory:");

    auto r = store.invalidate_policy("does-not-exist");
    REQUIRE(r.has_value());
    CHECK(r.value() == 0);
}

TEST_CASE("PolicyStore: invalidate empty policy ID", "[policy_store][invalidation]") {
    PolicyStore store(":memory:");

    auto r = store.invalidate_policy("");
    REQUIRE(!r.has_value());
    CHECK(r.error().find("required") != std::string::npos);
}

TEST_CASE("PolicyStore: invalidate all policies", "[policy_store][invalidation]") {
    PolicyStore store(":memory:");

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    auto pol1 = store.create_policy(make_policy_yaml(frag.value(), "Policy A"));
    auto pol2 = store.create_policy(make_policy_yaml(frag.value(), "Policy B"));
    REQUIRE(pol1.has_value());
    REQUIRE(pol2.has_value());

    store.update_agent_status(pol1.value(), "agent-1", "compliant");
    store.update_agent_status(pol1.value(), "agent-2", "non_compliant");
    store.update_agent_status(pol2.value(), "agent-3", "compliant");

    auto r = store.invalidate_all_policies();
    REQUIRE(r.has_value());
    CHECK(r.value() == 3);

    // Verify all unknown (invalidation resets to unknown)
    auto s1 = store.get_agent_status(pol1.value(), "agent-1");
    REQUIRE(s1.has_value());
    CHECK(s1->status == "unknown");

    auto s3 = store.get_agent_status(pol2.value(), "agent-3");
    REQUIRE(s3.has_value());
    CHECK(s3->status == "unknown");
}

TEST_CASE("PolicyStore: invalidate all with no data returns 0",
          "[policy_store][invalidation]") {
    PolicyStore store(":memory:");

    auto r = store.invalidate_all_policies();
    REQUIRE(r.has_value());
    CHECK(r.value() == 0);
}

// ============================================================================
// Policy YAML parsing edge cases
// ============================================================================

TEST_CASE("PolicyStore: policy with multiple triggers and groups",
          "[policy_store][policy][yaml]") {
    PolicyStore store(":memory:");

    auto frag = store.create_fragment(kFullFragment);
    REQUIRE(frag.has_value());

    std::string yaml = R"(
apiVersion: yuzu.io/v1alpha1
kind: Policy
displayName: Multi Trigger Policy
description: Policy with many triggers and groups
fragment: )" + frag.value() + R"(
scope: "tags.env == 'prod'"
inputs:
  service: Spooler
  timeout: "60"
triggers:
  - type: interval
    interval_seconds: 600
  - type: file_change
    path: "C:\\config.yaml"
  - type: event_log
    event_source: System
    event_id: "7036"
managementGroups:
  - "all-devices"
  - "windows-servers"
  - "us-east-region"
)";

    auto result = store.create_policy(yaml);
    REQUIRE(result.has_value());

    auto pol = store.get_policy(result.value());
    REQUIRE(pol.has_value());

    REQUIRE(pol->inputs.size() == 2);
    REQUIRE(pol->triggers.size() == 3);
    REQUIRE(pol->management_groups.size() == 3);
}

TEST_CASE("PolicyStore: get nonexistent fragment returns nullopt",
          "[policy_store][fragment]") {
    PolicyStore store(":memory:");
    CHECK(store.get_fragment("does-not-exist") == std::nullopt);
}

TEST_CASE("PolicyStore: get nonexistent policy returns nullopt", "[policy_store][policy]") {
    PolicyStore store(":memory:");
    CHECK(store.get_policy("does-not-exist") == std::nullopt);
}

TEST_CASE("PolicyStore: get nonexistent agent status returns nullopt",
          "[policy_store][compliance]") {
    PolicyStore store(":memory:");
    CHECK(store.get_agent_status("pol", "agent") == std::nullopt);
}

// ── Duplicate-name guard (#396) ──────────────────────────────────────────

TEST_CASE("PolicyStore: duplicate fragment name rejected with conflict prefix",
          "[policy_store][fragment][duplicate]") {
    PolicyStore store(":memory:");

    // First create succeeds.
    auto first = store.create_fragment(kCheckOnlyNoFix);
    REQUIRE(first.has_value());

    // Same YAML again (same displayName -> same name) must surface as
    // "conflict:" so the route layer can return HTTP 409 instead of 400.
    auto second = store.create_fragment(kCheckOnlyNoFix);
    REQUIRE_FALSE(second.has_value());
    CHECK(is_conflict_error(second.error()));

    // First fragment is intact — no silent duplicate row.
    auto fragments = store.query_fragments({});
    int matches = 0;
    for (const auto& f : fragments)
        if (f.name == "Check Only Fragment")
            ++matches;
    CHECK(matches == 1);
}
