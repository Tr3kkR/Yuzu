/**
 * test_authz_model.cpp — the registry-independent authz MODEL (ADR-0033 §2)
 * and the shared #1788 per-device-visibility primitive.
 *
 * Two independent halves, per `authz_model.hpp`'s own split:
 *
 *   1. `CapabilityDeclaration` / `kSeedCatalogue` / `is_valid()` — a stub
 *      consumer exercising the PR1.9-facing declaration schema.
 *   2. `VisibleSet` / `in_scope` / `filter_to_scope` — composition tests
 *      against `RbacStore`'s PUBLIC resolver-backed API (never the private
 *      `resolve_perm_groups`), asserting the documented #1715/INV-7 lattice
 *      semantics for `Execution:Execute` specifically, PLUS negative tests
 *      for each of the four `/api/command` dispatch-arm shapes.
 *
 * The four dispatch arms themselves live inside `Server::start()`'s raw
 * `httplib::Server` registration and are not independently reachable by a
 * test harness — the same limitation `dispatch_target_shape.hpp` documents
 * for `classify_dispatch_arm` (#2557). These tests cover the shared
 * `in_scope`/`filter_to_scope` primitive every arm calls before `send_to`,
 * against each arm's characteristic already-resolved target-set shape.
 */

#include "authz_model.hpp"
#include "management_group_store.hpp"
#include "rbac_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server::authz;

namespace {

bool contains(const std::vector<std::string>& v, const std::string& x) {
    return std::find(v.begin(), v.end(), x) != v.end();
}

} // namespace

// ── 1. CapabilityDeclaration / kSeedCatalogue ────────────────────────────

TEST_CASE("authz_model: every seed catalogue row materializes to a valid declaration",
          "[authz_model][seed]") {
    for (const auto& seed : kSeedCatalogue) {
        auto decl = from_seed(seed);
        INFO("securable=" << decl.securable << " operation=" << to_string(decl.operation));
        CHECK(decl.is_valid());
        CHECK(decl.securable == std::string(seed.securable));
        CHECK(decl.operation == seed.operation);
        CHECK(decl.risk_tier == seed.risk_tier);
        CHECK(decl.mcp_tier_class == default_mcp_tier_class(seed.operation));
    }
}

TEST_CASE("authz_model: seed catalogue includes AccessReview:Attest (SOC 2 CC6.2)",
          "[authz_model][seed]") {
    bool found = false;
    for (const auto& seed : kSeedCatalogue) {
        if (seed.securable == "AccessReview" && seed.operation == Operation::Attest) {
            found = true;
            // Attest is a narrow op, outside every CRUD loop — floors at Medium,
            // not Low (it is not an ordinary read).
            CHECK(static_cast<uint8_t>(seed.risk_tier) >=
                  static_cast<uint8_t>(min_risk_tier_for(Operation::Attest)));
        }
    }
    CHECK(found);
}

TEST_CASE("authz_model: seed catalogue includes Execution:Execute", "[authz_model][seed]") {
    bool found = false;
    for (const auto& seed : kSeedCatalogue)
        if (seed.securable == "Execution" && seed.operation == Operation::Execute)
            found = true;
    CHECK(found);
}

TEST_CASE("authz_model: default_mcp_tier_class matches mcp_policy.hpp's Execution:Execute "
          "special-case",
          "[authz_model][mcp_tier_class]") {
    // mcp_policy.hpp's operator tier auto-approves Execution:Execute without
    // allowing arbitrary writes — the ONE non-Read operation that maps to the
    // execute tier class rather than write.
    CHECK(default_mcp_tier_class(Operation::Execute) == McpTierClass::Execute);
    CHECK(default_mcp_tier_class(Operation::Read) == McpTierClass::Read);
    CHECK(default_mcp_tier_class(Operation::Write) == McpTierClass::Write);
    CHECK(default_mcp_tier_class(Operation::Delete) == McpTierClass::Write);
    CHECK(default_mcp_tier_class(Operation::Approve) == McpTierClass::Write);
    CHECK(default_mcp_tier_class(Operation::Push) == McpTierClass::Write);
    CHECK(default_mcp_tier_class(Operation::Attest) == McpTierClass::Write);
}

// ── is_valid(): "undeclared means the capability does not exist" ────────

TEST_CASE("authz_model: CapabilityDeclaration::is_valid rejects a missing required field",
          "[authz_model][validate]") {
    CapabilityDeclaration base = from_seed(kSeedCatalogue[0]);
    REQUIRE(base.is_valid());

    auto no_securable = base;
    no_securable.securable.clear();
    CHECK(!no_securable.is_valid());

    auto no_discovery = base;
    no_discovery.discovery_entry.clear();
    CHECK(!no_discovery.is_valid());

    auto no_data_class = base;
    no_data_class.data_class.clear();
    CHECK(!no_data_class.is_valid());

    auto no_audit_verb = base;
    no_audit_verb.audit_verb.clear();
    CHECK(!no_audit_verb.is_valid());
}

TEST_CASE("authz_model: CapabilityDeclaration::is_valid rejects a risk_tier below its floor",
          "[authz_model][validate]") {
    CapabilityDeclaration decl = from_seed(kSeedCatalogue[0]); // Response:Read
    decl.operation = Operation::Delete; // floor: High
    decl.risk_tier = RiskTier::Low;     // under-declared
    CHECK(!decl.is_valid());
    decl.risk_tier = RiskTier::High; // at the floor
    CHECK(decl.is_valid());
}

TEST_CASE("authz_model: CapabilityDeclaration::is_valid rejects both twins absent with no "
          "recorded exception",
          "[authz_model][validate]") {
    CapabilityDeclaration decl = from_seed(kSeedCatalogue[0]);
    decl.has_rest_twin = false;
    decl.has_mcp_twin = false;
    CHECK(!decl.is_valid());

    decl.twin_exception_ref = "ADR-1005-ledger#42";
    CHECK(decl.is_valid()); // a recorded exception makes an absent twin valid
}

TEST_CASE("authz_model: min_risk_tier_for never floors below Low, never above High",
          "[authz_model][validate]") {
    CHECK(min_risk_tier_for(Operation::Read) == RiskTier::Low);
    CHECK(min_risk_tier_for(Operation::Write) == RiskTier::Medium);
    CHECK(min_risk_tier_for(Operation::Execute) == RiskTier::Medium);
    CHECK(min_risk_tier_for(Operation::Attest) == RiskTier::Medium);
    CHECK(min_risk_tier_for(Operation::Delete) == RiskTier::High);
    CHECK(min_risk_tier_for(Operation::Approve) == RiskTier::High);
    CHECK(min_risk_tier_for(Operation::Push) == RiskTier::High);
}

// ── 2. Composition with RbacStore's public resolver-backed API ──────────
// Mirrors test_list_read_confinement.cpp's fixture pattern, for
// Execution:Execute specifically (the #1788 fix's securable/operation).

namespace {

/// A two-store rig with a small management-group tree, custom allow/deny
/// Execution:Execute roles, and RBAC enforcement ON.
///
///   P ─┬─ C1        S   (P and S are roots; C1,C2 are children of P)
///      └─ C2
///
/// Members: a_p∈P, a_c1∈C1, a_c2∈C2, a_s∈S.
struct Rig {
    yuzu::server::RbacStore rbac{":memory:"};
    yuzu::test::TempDbFile mgmt_db{"yuzu_test_authzmodel_mgmt-"};
    yuzu::server::ManagementGroupStore mgmt{mgmt_db.path};
    std::string gP, gC1, gC2, gS;

    Rig() {
        rbac.set_rbac_enabled(true);

        REQUIRE(rbac.create_role({"ExecReader", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"ExecReader", "Execution", "Execute", "allow"}).has_value());
        REQUIRE(rbac.create_role({"ExecDenier", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"ExecDenier", "Execution", "Execute", "deny"}).has_value());

        gP = make_group("P", "");
        gC1 = make_group("C1", gP);
        gC2 = make_group("C2", gP);
        gS = make_group("S", "");

        REQUIRE(mgmt.add_member(gP, "a_p").has_value());
        REQUIRE(mgmt.add_member(gC1, "a_c1").has_value());
        REQUIRE(mgmt.add_member(gC2, "a_c2").has_value());
        REQUIRE(mgmt.add_member(gS, "a_s").has_value());
    }

    std::string make_group(const std::string& name, const std::string& parent) {
        yuzu::server::ManagementGroup g;
        g.name = name;
        g.membership_type = "static";
        g.parent_id = parent;
        auto id = mgmt.create_group(g);
        REQUIRE(id.has_value());
        return *id;
    }

    void group_assign(const std::string& group, const std::string& user, const std::string& role) {
        REQUIRE(mgmt.assign_role({group, "user", user, role}).has_value());
    }
};

/// Compose a `VisibleSet` the SAME way the #1788 `/api/command` fix does:
/// global `check_permission` first (unfiltered on a hit, #1715(b)), else the
/// ADR-0017 `visible_agents_for_permission` scoped set, fail-closed to
/// "nothing visible" on any store error. This is the exact composition
/// `server.cpp` performs — duplicated here (rather than exported from
/// `authz_model.hpp`) because it needs an `RbacStore&`, which the
/// registry-independent header deliberately does not depend on.
VisibleSet compose_exec_visible(const yuzu::server::RbacStore& rbac, const std::string& user,
                                yuzu::server::ManagementGroupStore* mgmt) {
    if (rbac.check_permission(user, "Execution", "Execute"))
        return std::nullopt;
    std::unordered_set<std::string> visible;
    if (auto v = rbac.visible_agents_for_permission(user, "Execution", "Execute", mgmt))
        visible.insert(v->begin(), v->end());
    return visible;
}

} // namespace

TEST_CASE("authz_model composition: global allow ⇒ unfiltered (#1715(b))",
          "[authz_model][compose][1715]") {
    Rig r;
    REQUIRE(r.rbac.assign_role({"user", "bob", "ExecReader"}).has_value()); // GLOBAL allow
    r.group_assign(r.gC2, "bob", "ExecDenier"); // a group deny must NOT carve out

    auto visible = compose_exec_visible(r.rbac, "bob", &r.mgmt);
    CHECK(!visible.has_value()); // nullopt == unfiltered
    CHECK(in_scope(visible, "a_s")); // outside every group, still admitted
}

TEST_CASE("authz_model composition: global deny + group allow ⇒ scoped (additive, #1715(a))",
          "[authz_model][compose][1715]") {
    Rig r;
    REQUIRE(r.rbac.assign_role({"user", "carol", "ExecDenier"}).has_value()); // GLOBAL deny
    r.group_assign(r.gP, "carol", "ExecReader");                              // group allow

    auto visible = compose_exec_visible(r.rbac, "carol", &r.mgmt);
    REQUIRE(visible.has_value());
    CHECK(visible->contains("a_p"));
    CHECK(visible->contains("a_c1")); // descendant of P
    CHECK(!visible->contains("a_s")); // outside P's subtree
}

TEST_CASE("authz_model composition: no grant anywhere ⇒ empty visible set (fail-closed)",
          "[authz_model][compose]") {
    Rig r;
    auto visible = compose_exec_visible(r.rbac, "nobody", &r.mgmt);
    REQUIRE(visible.has_value());
    CHECK(visible->empty());
}

TEST_CASE("authz_model composition: null mgmt store ⇒ empty visible set, never unfiltered",
          "[authz_model][compose][fail-closed]") {
    yuzu::server::RbacStore rbac{":memory:"};
    rbac.set_rbac_enabled(true);
    REQUIRE(rbac.create_role({"ExecReader2", "", false, 0}).has_value());
    REQUIRE(rbac.set_permission({"ExecReader2", "Execution", "Execute", "allow"}).has_value());
    // "alice" has no GLOBAL grant; her only route to a visible set is the
    // (here, unavailable) scoped resolver — a store error must narrow to
    // nothing, never fall through to unfiltered.
    auto visible = compose_exec_visible(rbac, "alice", nullptr);
    REQUIRE(visible.has_value());
    CHECK(visible->empty());
}

// ── Negative tests: each of the four dispatch-arm shapes ─────────────────
// `in_scope`/`filter_to_scope` is the ONE primitive `server.cpp` calls for
// all four /api/command arms; these exercise it against each arm's
// characteristic already-resolved target-set shape.

TEST_CASE("authz_model #1788: Ids arm — an explicit agent_ids list drops a hidden device",
          "[authz_model][1788][ids]") {
    Rig r;
    r.group_assign(r.gP, "scoped_op", "ExecReader"); // visible: a_p, a_c1, a_c2 (not a_s)
    auto visible = compose_exec_visible(r.rbac, "scoped_op", &r.mgmt);
    REQUIRE(visible.has_value());

    const std::vector<std::string> requested{"a_p", "a_s"}; // a_s is OUTSIDE the group
    auto filtered = filter_to_scope(requested, visible);
    CHECK(contains(filtered, "a_p"));
    CHECK(!contains(filtered, "a_s")); // #1788: hidden device never reached
}

TEST_CASE("authz_model #1788: Group arm — resolved members outside scope are dropped",
          "[authz_model][1788][group]") {
    Rig r;
    r.group_assign(r.gC1, "scoped_op", "ExecReader"); // visible: only a_c1
    auto visible = compose_exec_visible(r.rbac, "scoped_op", &r.mgmt);
    REQUIRE(visible.has_value());

    // Simulates a Group-arm dispatch to a DIFFERENT group (C2) than the one
    // the operator is scoped to — every resolved member is out of scope.
    const std::vector<std::string> group_members{"a_c2"};
    auto filtered = filter_to_scope(group_members, visible);
    CHECK(filtered.empty());
}

TEST_CASE("authz_model #1788: Scope arm — evaluate_scope's matched ids are narrowed",
          "[authz_model][1788][scope]") {
    Rig r;
    r.group_assign(r.gP, "scoped_op", "ExecReader"); // visible: a_p, a_c1, a_c2
    auto visible = compose_exec_visible(r.rbac, "scoped_op", &r.mgmt);
    REQUIRE(visible.has_value());

    // Simulates a scope expression (e.g. a broad tag match) that resolved
    // to devices both inside AND outside the operator's confinement.
    const std::vector<std::string> matched_ids{"a_p", "a_c2", "a_s"};
    auto filtered = filter_to_scope(matched_ids, visible);
    CHECK(contains(filtered, "a_p"));
    CHECK(contains(filtered, "a_c2"));
    CHECK(!contains(filtered, "a_s")); // #1788: outside confinement, dropped
}

TEST_CASE("authz_model #1788: Broadcast arm — __all__ narrows to the visible set, never widens",
          "[authz_model][1788][broadcast]") {
    Rig r;
    r.group_assign(r.gP, "scoped_op", "ExecReader"); // visible: a_p, a_c1, a_c2
    auto visible = compose_exec_visible(r.rbac, "scoped_op", &r.mgmt);
    REQUIRE(visible.has_value());

    // Simulates the full known-agent-id list a broadcast would otherwise
    // reach unfiltered.
    const std::vector<std::string> all_known_ids{"a_p", "a_c1", "a_c2", "a_s"};
    auto filtered = filter_to_scope(all_known_ids, visible);
    CHECK(contains(filtered, "a_p"));
    CHECK(contains(filtered, "a_c1"));
    CHECK(contains(filtered, "a_c2"));
    CHECK(!contains(filtered, "a_s")); // #1788: broadcast no longer reaches everyone
    CHECK(filtered.size() == 3);
}

TEST_CASE("authz_model #1788: Broadcast arm — a global grant stays truly unfiltered",
          "[authz_model][1788][broadcast]") {
    Rig r;
    REQUIRE(r.rbac.assign_role({"user", "admin_op", "ExecReader"}).has_value()); // GLOBAL
    auto visible = compose_exec_visible(r.rbac, "admin_op", &r.mgmt);
    CHECK(!visible.has_value());

    const std::vector<std::string> all_known_ids{"a_p", "a_c1", "a_c2", "a_s"};
    auto filtered = filter_to_scope(all_known_ids, visible);
    CHECK(filtered == all_known_ids); // unchanged — no regression for a global admin
}

TEST_CASE("authz_model #1788: in_scope agrees with filter_to_scope per id",
          "[authz_model][1788]") {
    Rig r;
    r.group_assign(r.gP, "scoped_op", "ExecReader");
    auto visible = compose_exec_visible(r.rbac, "scoped_op", &r.mgmt);
    REQUIRE(visible.has_value());

    const std::vector<std::string> all_ids{"a_p", "a_c1", "a_c2", "a_s"};
    auto filtered = filter_to_scope(all_ids, visible);
    for (const auto& id : all_ids) {
        INFO("id=" << id);
        CHECK(in_scope(visible, id) == contains(filtered, id));
    }
}
