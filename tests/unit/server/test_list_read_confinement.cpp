/**
 * test_list_read_confinement.cpp — ADR-0017 admit-then-filter list gate.
 *
 * Foundation tests for RbacStore::authorize_list_read + the shared resolver
 * (holds_permission_via_any_group / visible_agents_for_permission) and the
 * refactored check_scoped_permission. Covers the frozen #1715 combining
 * lattice (cross-boundary additive/OR; deny-overrides intra-group only) and
 * the design invariants:
 *   INV-1  fail-closed is total (corrupt/unavailable store → DenyAll, not AdmitAll)
 *   INV-2  empty visible set ⇒ AdmitScoped({}) (200 empty), not DenyAll (403)
 *   INV-4  descendant-ward expansion (a grant on a group covers its subtree)
 *   INV-5  partial failure denies, never includes
 *   INV-7  ONE resolver — visible set == { a : check_scoped_permission(...) }
 */

#include "management_group_store.hpp"
#include "rbac_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <fstream>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace {

bool contains(const std::vector<std::string>& v, const std::string& x) {
    return std::find(v.begin(), v.end(), x) != v.end();
}

/// A two-store rig with a small management-group tree, custom allow/deny
/// Response:Read roles, and RBAC enforcement ON so authorize_list_read runs
/// the real admit-then-filter path (a fresh store is loaded-and-disabled →
/// legacy-open, which we test separately).
///
///   P ─┬─ C1        S   (P and S are roots; C1,C2 are children of P)
///      └─ C2
///
/// Members: a_p∈P, a_c1∈C1, a_c2∈C2, a_s∈S.
struct Rig {
    RbacStore rbac{":memory:"};
    yuzu::test::TempDbFile mgmt_db{"yuzu_test_lrc_mgmt-"};
    ManagementGroupStore mgmt{mgmt_db.path};
    std::string gP, gC1, gC2, gS;

    Rig() {
        rbac.set_rbac_enabled(true); // enforcement in effect

        REQUIRE(rbac.create_role({"RespReader", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"RespReader", "Response", "Read", "allow"}).has_value());
        REQUIRE(rbac.create_role({"RespDenier", "", false, 0}).has_value());
        REQUIRE(rbac.set_permission({"RespDenier", "Response", "Read", "deny"}).has_value());

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
        ManagementGroup g;
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

} // namespace

// ── #1715(b): a global ALLOW overrides any group deny → AdmitAll ──────────────

TEST_CASE("authorize_list_read: global allow ⇒ AdmitAll", "[list_read][rbac][1715]") {
    Rig r;
    REQUIRE(r.rbac.assign_role({"user", "bob", "RespReader"}).has_value()); // GLOBAL allow
    r.group_assign(r.gC2, "bob", "RespDenier"); // a group deny must NOT carve out

    auto d = r.rbac.authorize_list_read("bob", "Response", "Read", &r.mgmt);
    CHECK(d.decision == ListReadDecision::AdmitAll);
}

// ── #1715(a): a global DENY does NOT override a group allow (additive) ────────

TEST_CASE("authorize_list_read: global deny + group allow ⇒ AdmitScoped (additive)",
          "[list_read][rbac][1715]") {
    Rig r;
    REQUIRE(r.rbac.assign_role({"user", "carol", "RespDenier"}).has_value()); // GLOBAL deny
    r.group_assign(r.gP, "carol", "RespReader");                              // group allow

    // Global deny makes check_permission false, but the group allow still admits.
    auto d = r.rbac.authorize_list_read("carol", "Response", "Read", &r.mgmt);
    CHECK(d.decision == ListReadDecision::AdmitScoped);
    CHECK(contains(d.visible_agents, "a_p"));
}

// ── DenyAll: no grant anywhere ────────────────────────────────────────────────

TEST_CASE("authorize_list_read: no grant ⇒ DenyAll", "[list_read][rbac]") {
    Rig r;
    auto d = r.rbac.authorize_list_read("nobody", "Response", "Read", &r.mgmt);
    CHECK(d.decision == ListReadDecision::DenyAll);
    CHECK(d.visible_agents.empty());
}

// ── INV-2: holds via a group but sees nothing ⇒ AdmitScoped({}), not DenyAll ──

TEST_CASE("authorize_list_read: allow on an empty group ⇒ AdmitScoped empty (INV-2)",
          "[list_read][rbac][inv2]") {
    Rig r;
    auto empty = r.make_group("Empty", ""); // no members
    r.group_assign(empty, "dave", "RespReader");

    auto d = r.rbac.authorize_list_read("dave", "Response", "Read", &r.mgmt);
    CHECK(d.decision == ListReadDecision::AdmitScoped); // 200 empty, NOT a 403
    CHECK(d.visible_agents.empty());
    CHECK(r.rbac.holds_permission_via_any_group("dave", "Response", "Read", &r.mgmt));
}

// ── INV-4: descendant-ward expansion + deny-override subtraction ──────────────

TEST_CASE("authorize_list_read: descendant-ward visible set with a deny branch (INV-4)",
          "[list_read][rbac][inv4]") {
    Rig r;
    r.group_assign(r.gP, "alice", "RespReader");  // allow on P (covers P,C1,C2)
    r.group_assign(r.gC2, "alice", "RespDenier"); // deny on the C2 branch

    auto d = r.rbac.authorize_list_read("alice", "Response", "Read", &r.mgmt);
    REQUIRE(d.decision == ListReadDecision::AdmitScoped);
    CHECK(contains(d.visible_agents, "a_p"));   // P member
    CHECK(contains(d.visible_agents, "a_c1"));  // descendant of P, not denied
    CHECK(!contains(d.visible_agents, "a_c2")); // descendant of P but denied
    CHECK(!contains(d.visible_agents, "a_s"));  // outside P's subtree
    CHECK(d.visible_agents.size() == 2);
}

// ── INV-7: the set-equivalence property + one-resolver cross-check ────────────

TEST_CASE("authorize_list_read: visible set == {a : check_scoped_permission} (INV-7)",
          "[list_read][rbac][inv7]") {
    Rig r;
    r.group_assign(r.gP, "alice", "RespReader");
    r.group_assign(r.gC2, "alice", "RespDenier");

    // The property, over every agent in the fixture tree.
    const std::vector<std::string> all_agents{"a_p", "a_c1", "a_c2", "a_s"};

    auto visible = r.rbac.visible_agents_for_permission("alice", "Response", "Read", &r.mgmt);
    REQUIRE(visible.has_value());

    for (const auto& a : all_agents) {
        bool per_row = r.rbac.check_scoped_permission("alice", "Response", "Read", a, &r.mgmt);
        bool in_set = contains(*visible, a);
        INFO("agent=" << a);
        CHECK(in_set == per_row); // one resolver: the set and the per-row gate agree
    }

    // Cross-check: authorize_list_read's AdmitScoped set == visible_agents_for_permission.
    auto d = r.rbac.authorize_list_read("alice", "Response", "Read", &r.mgmt);
    REQUIRE(d.decision == ListReadDecision::AdmitScoped);
    auto lhs = d.visible_agents;
    auto rhs = *visible;
    std::sort(lhs.begin(), lhs.end());
    std::sort(rhs.begin(), rhs.end());
    CHECK(lhs == rhs);
}

// ── Legacy-open: RBAC loaded-and-disabled ⇒ AdmitAll (behaviour-neutral) ──────

TEST_CASE("authorize_list_read: RBAC disabled ⇒ AdmitAll (legacy-open)", "[list_read][rbac]") {
    RbacStore rbac{":memory:"}; // is_open() && !is_rbac_enabled() → legacy-open
    yuzu::test::TempDbFile mgmt_db{"yuzu_test_lrc_legacy-"};
    ManagementGroupStore mgmt{mgmt_db.path};

    auto d = rbac.authorize_list_read("anyone", "Response", "Read", &mgmt);
    CHECK(d.decision == ListReadDecision::AdmitAll);
}

// ── INV-1/INV-5: fail-closed is total ────────────────────────────────────────

TEST_CASE("authorize_list_read: null mgmt store under enforcement ⇒ DenyAll (INV-1)",
          "[list_read][rbac][inv1]") {
    RbacStore rbac{":memory:"};
    rbac.set_rbac_enabled(true); // enforcement in effect, but no global grant
    auto d = rbac.authorize_list_read("alice", "Response", "Read", /*mgmt=*/nullptr);
    CHECK(d.decision == ListReadDecision::DenyAll); // never AdmitAll
}

TEST_CASE("authorize_list_read: corrupt rbac.db ⇒ DenyAll, never AdmitAll (INV-1)",
          "[list_read][rbac][inv1]") {
    yuzu::test::TempDbFile bad_db{"yuzu_test_lrc_corrupt-"};
    {
        std::ofstream f(bad_db.path, std::ios::binary);
        f << "this is not a sqlite database at all, migrations will fail\n";
    }
    RbacStore bad{bad_db.path};
    REQUIRE(!bad.is_open()); // precondition: migrations failed → store not open

    yuzu::test::TempDbFile mgmt_db{"yuzu_test_lrc_corrupt_mgmt-"};
    ManagementGroupStore mgmt{mgmt_db.path};

    // rbac_enforcement_in_effect(!is_open()) == true (enforce), so this must NOT
    // take the legacy-open AdmitAll branch — a corrupt store fails CLOSED.
    auto d = bad.authorize_list_read("alice", "Response", "Read", &mgmt);
    CHECK(d.decision == ListReadDecision::DenyAll);
}

// ── check_scoped_permission behaviour preserved by the INV-7 refactor ─────────

TEST_CASE("check_scoped_permission: preserved through the shared-resolver refactor",
          "[list_read][rbac][refactor]") {
    Rig r;
    r.group_assign(r.gP, "alice", "RespReader");
    r.group_assign(r.gC2, "alice", "RespDenier");

    // allow on P covers P + descendants (ancestor-ward admit); deny on C2 wins there.
    CHECK(r.rbac.check_scoped_permission("alice", "Response", "Read", "a_p", &r.mgmt));
    CHECK(r.rbac.check_scoped_permission("alice", "Response", "Read", "a_c1", &r.mgmt));
    CHECK(!r.rbac.check_scoped_permission("alice", "Response", "Read", "a_c2", &r.mgmt)); // deny
    CHECK(!r.rbac.check_scoped_permission("alice", "Response", "Read", "a_s", &r.mgmt));  // no grant

    // Global allow still short-circuits (matches #1715(b)).
    REQUIRE(r.rbac.assign_role({"user", "gadmin", "RespReader"}).has_value());
    CHECK(r.rbac.check_scoped_permission("gadmin", "Response", "Read", "a_s", &r.mgmt));
}

// ── INV-7 set-equivalence over a DEEP tree (≥3 levels) with a mid-tree deny ───
// Exercises the ancestor-ward ⟷ descendant-ward duality past one level:
// a grandchild inherits a root allow AND a mid-tree deny; a sibling branch is
// isolated from the deny (architect + consistency-auditor SHOULD).
//
//   R(allow) ── DP ──┬── DC1(deny) ── DGC          members: a_R,a_dp,a_dc1,a_dgc,a_dc2
//                    └── DC2
TEST_CASE("authorize_list_read: INV-7 holds over a 4-level tree with a mid-tree deny",
          "[list_read][rbac][inv7]") {
    Rig r; // reuses RespReader/RespDenier roles + RBAC-enabled store
    auto R = r.make_group("R", "");
    auto DP = r.make_group("DP", R);
    auto DC1 = r.make_group("DC1", DP);
    auto DGC = r.make_group("DGC", DC1); // depth 3 — within create_group's cap of 5
    auto DC2 = r.make_group("DC2", DP);
    REQUIRE(r.mgmt.add_member(R, "a_R").has_value());
    REQUIRE(r.mgmt.add_member(DP, "a_dp").has_value());
    REQUIRE(r.mgmt.add_member(DC1, "a_dc1").has_value());
    REQUIRE(r.mgmt.add_member(DGC, "a_dgc").has_value());
    REQUIRE(r.mgmt.add_member(DC2, "a_dc2").has_value());

    r.group_assign(R, "deep", "RespReader");   // allow on the root (covers whole tree)
    r.group_assign(DC1, "deep", "RespDenier");  // deny mid-tree (covers DC1 + DGC)

    const std::vector<std::string> all_agents{"a_R", "a_dp", "a_dc1", "a_dgc", "a_dc2"};

    auto visible = r.rbac.visible_agents_for_permission("deep", "Response", "Read", &r.mgmt);
    REQUIRE(visible.has_value());
    // Expected: allow(R-subtree) minus deny(DC1-subtree) = {a_R,a_dp,a_dc2}.
    CHECK(contains(*visible, "a_R"));
    CHECK(contains(*visible, "a_dp"));
    CHECK(contains(*visible, "a_dc2"));  // sibling of the denied branch — survives
    CHECK(!contains(*visible, "a_dc1")); // denied directly
    CHECK(!contains(*visible, "a_dgc")); // grandchild inherits the mid-tree deny
    CHECK(visible->size() == 3);

    // The set-equivalence property AND the INV-7 cross-check, past one level.
    for (const auto& a : all_agents) {
        bool per_row = r.rbac.check_scoped_permission("deep", "Response", "Read", a, &r.mgmt);
        INFO("agent=" << a);
        CHECK(contains(*visible, a) == per_row);
    }
    auto d = r.rbac.authorize_list_read("deep", "Response", "Read", &r.mgmt);
    REQUIRE(d.decision == ListReadDecision::AdmitScoped);
    auto lhs = d.visible_agents, rhs = *visible;
    std::sort(lhs.begin(), lhs.end());
    std::sort(rhs.begin(), rhs.end());
    CHECK(lhs == rhs);
}
