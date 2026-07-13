/**
 * test_rbac_store.cpp — Unit tests for RbacStore
 *
 * Covers: lifecycle, seed data, role CRUD, permission CRUD, principal-role
 * assignments, group membership, check_permission, deny-overrides-allow,
 * RBAC toggle, check_scoped_permission.
 */

#include "management_group_store.hpp"
#include "migration_runner.hpp"
#include "rbac_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <algorithm>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

// ── Lifecycle ────────────────────────────────────────────────────────────────

TEST_CASE("RbacStore: open in-memory", "[rbac_store][db]") {
    RbacStore store(":memory:");
    REQUIRE(store.is_open());
}

TEST_CASE("RbacStore: seed data — system roles exist", "[rbac_store]") {
    RbacStore store(":memory:");
    auto roles = store.list_roles();

    auto find = [&](const std::string& name) {
        return std::find_if(roles.begin(), roles.end(),
                            [&](const RbacRole& r) { return r.name == name; });
    };

    REQUIRE(find("Administrator") != roles.end());
    REQUIRE(find("Operator") != roles.end());
    REQUIRE(find("ITServiceOwner") != roles.end());
    REQUIRE(find("Viewer") != roles.end());
    CHECK(find("Administrator")->is_system);
    CHECK(find("Operator")->is_system);
    CHECK(find("ITServiceOwner")->is_system);
    CHECK(find("Viewer")->is_system);
}

TEST_CASE("RbacStore: seed data — securable types", "[rbac_store]") {
    RbacStore store(":memory:");
    auto types = store.list_securable_types();
    REQUIRE(types.size() == 21); // +SoftwareLicensing (ADR-0024)

    auto has = [&](const std::string& t) {
        return std::find(types.begin(), types.end(), t) != types.end();
    };
    CHECK(has("Infrastructure"));
    CHECK(has("Execution"));
    CHECK(has("AuditLog"));
    CHECK(has("Response"));
    CHECK(has("ManagementGroup"));
    CHECK(has("ApiToken"));
    CHECK(has("Security"));
    CHECK(has("Policy"));
    CHECK(has("DeviceToken"));
    CHECK(has("SoftwareDeployment"));
    CHECK(has("License")); // Yuzu's OWN product licence (§22.3) — DISTINCT from SLE
    CHECK(has("FileRetrieval"));
    CHECK(has("GuaranteedState"));
    CHECK(has("Inventory"));
    CHECK(has("SoftwareLicensing")); // SLE securable (ADR-0024 Decision 9) — NOT `License`
}

TEST_CASE("RbacStore: seed data — operations", "[rbac_store]") {
    RbacStore store(":memory:");
    auto ops = store.list_operations();
    // Read, Write, Execute, Delete, Approve, Push (Push added for Guardian
    // distribute-rules-to-fleet operation; design v1.1 §9.2).
    REQUIRE(ops.size() == 6);
}

TEST_CASE("RbacStore: seed data — Administrator has all permissions", "[rbac_store]") {
    RbacStore store(":memory:");
    auto perms = store.get_role_permissions("Administrator");
    // 21 types * 5 CRUD ops = 105 permissions, plus a single targeted Push
    // grant on GuaranteedState = 106 permissions total. Push is deliberately
    // NOT cross-seeded on non-Guardian securables — see the rationale in
    // rbac_store.cpp seed_defaults(). (21st type: SoftwareLicensing, ADR-0024.)
    CHECK(perms.size() == 106);
    for (auto& p : perms)
        CHECK(p.effect == "allow");

    // Confirm the Push grant exists exactly once, and only on GuaranteedState.
    size_t push_count = 0;
    for (const auto& p : perms) {
        if (p.operation == "Push") {
            ++push_count;
            CHECK(p.securable_type == "GuaranteedState");
        }
    }
    CHECK(push_count == 1);
}

TEST_CASE("RbacStore: seed data — Viewer has read-only", "[rbac_store]") {
    RbacStore store(":memory:");
    auto perms = store.get_role_permissions("Viewer");
    // 20 types * Read only (everything except Infrastructure; incl. Inventory +
    // SoftwareLicensing, ADR-0024)
    CHECK(perms.size() == 20);
    for (auto& p : perms) {
        CHECK(p.operation == "Read");
        CHECK(p.effect == "allow");
        CHECK(p.securable_type != "Infrastructure");
    }
}

// ── RBAC toggle ──────────────────────────────────────────────────────────────

TEST_CASE("RbacStore: RBAC disabled by default", "[rbac_store]") {
    RbacStore store(":memory:");
    CHECK_FALSE(store.is_rbac_enabled());
}

TEST_CASE("RbacStore: enable and disable RBAC", "[rbac_store]") {
    RbacStore store(":memory:");
    store.set_rbac_enabled(true);
    CHECK(store.is_rbac_enabled());
    store.set_rbac_enabled(false);
    CHECK_FALSE(store.is_rbac_enabled());
}

// #1498 — the device-visibility fallback must distinguish a store that is
// loaded-and-explicitly-disabled (full-fleet fallback OK) from one that is
// missing or failed to load (fail CLOSED). The probe wired into
// ManagementGroupStore is exactly rbac_enforcement_in_effect(rbac_store_.get()),
// so this exercises the real predicate, not a stand-in lambda.
TEST_CASE("rbac_enforcement_in_effect fails closed on null / load-failed store",
          "[rbac_store][visibility]") {
    SECTION("null store → enforcement in effect (fail closed)") {
        CHECK(rbac_enforcement_in_effect(nullptr));
    }

    SECTION("load-failed store (is_open()==false) → fail closed, not full-fleet") {
        // A db path whose PARENT directory does not exist: sqlite3_open_v2 with
        // SQLITE_OPEN_CREATE creates the file but never the parent, so the open
        // fails and db_ is left null — the same state an open/migration failure
        // produces, and indistinguishable by the enabled flag alone.
        const auto bogus = yuzu::test::unique_temp_path("rbac-loadfail-") / "rbac.db";
        RbacStore broken(bogus);
        REQUIRE_FALSE(broken.is_open());
        CHECK(rbac_enforcement_in_effect(&broken)); // must fail closed
    }

    SECTION("loaded + explicitly disabled → full-fleet fallback permitted") {
        RbacStore store(":memory:");
        REQUIRE(store.is_open());
        REQUIRE_FALSE(store.is_rbac_enabled()); // disabled by default
        CHECK_FALSE(rbac_enforcement_in_effect(&store));
    }

    SECTION("loaded + enabled → enforcement in effect (role-scoped path)") {
        RbacStore store(":memory:");
        store.set_rbac_enabled(true);
        REQUIRE(store.is_rbac_enabled());
        CHECK(rbac_enforcement_in_effect(&store));
    }
}

// ── Role CRUD ────────────────────────────────────────────────────────────────

TEST_CASE("RbacStore: create custom role", "[rbac_store]") {
    RbacStore store(":memory:");
    auto result = store.create_role({"SOC Analyst", "Security operations read access", false, 0});
    REQUIRE(result.has_value());

    auto role = store.get_role("SOC Analyst");
    REQUIRE(role.has_value());
    CHECK(role->name == "SOC Analyst");
    CHECK(role->description == "Security operations read access");
    CHECK_FALSE(role->is_system);
    CHECK(role->created_at > 0);
}

TEST_CASE("RbacStore: create duplicate role fails", "[rbac_store]") {
    RbacStore store(":memory:");
    store.create_role({"MyRole", "", false, 0});
    auto result = store.create_role({"MyRole", "", false, 0});
    CHECK_FALSE(result.has_value());
}

TEST_CASE("RbacStore: create role with empty name fails", "[rbac_store]") {
    RbacStore store(":memory:");
    auto result = store.create_role({"", "desc", false, 0});
    CHECK_FALSE(result.has_value());
}

TEST_CASE("RbacStore: delete custom role succeeds", "[rbac_store]") {
    RbacStore store(":memory:");
    store.create_role({"Temp", "temporary", false, 0});
    auto result = store.delete_role("Temp");
    REQUIRE(result.has_value());
    CHECK_FALSE(store.get_role("Temp").has_value());
}

TEST_CASE("RbacStore: delete system role fails", "[rbac_store]") {
    RbacStore store(":memory:");
    auto result = store.delete_role("Administrator");
    CHECK_FALSE(result.has_value());
    CHECK(store.get_role("Administrator").has_value());
}

TEST_CASE("RbacStore: update role description", "[rbac_store]") {
    RbacStore store(":memory:");
    store.create_role({"MyRole", "old desc", false, 0});
    auto result = store.update_role("MyRole", "new desc");
    REQUIRE(result.has_value());
    CHECK(store.get_role("MyRole")->description == "new desc");
}

// ── Permission CRUD ──────────────────────────────────────────────────────────

TEST_CASE("RbacStore: set and get permission", "[rbac_store]") {
    RbacStore store(":memory:");
    store.create_role({"TestRole", "", false, 0});

    auto result = store.set_permission({"TestRole", "Execution", "Execute", "allow"});
    REQUIRE(result.has_value());

    auto perms = store.get_role_permissions("TestRole");
    REQUIRE(perms.size() == 1);
    CHECK(perms[0].securable_type == "Execution");
    CHECK(perms[0].operation == "Execute");
    CHECK(perms[0].effect == "allow");
}

TEST_CASE("RbacStore: remove permission", "[rbac_store]") {
    RbacStore store(":memory:");
    store.create_role({"TestRole", "", false, 0});
    store.set_permission({"TestRole", "Tag", "Read", "allow"});
    store.set_permission({"TestRole", "Tag", "Write", "allow"});

    store.remove_permission("TestRole", "Tag", "Write");
    auto perms = store.get_role_permissions("TestRole");
    REQUIRE(perms.size() == 1);
    CHECK(perms[0].operation == "Read");
}

TEST_CASE("RbacStore: deleting role cascades permissions", "[rbac_store]") {
    RbacStore store(":memory:");
    store.create_role({"Cascade", "", false, 0});
    store.set_permission({"Cascade", "Tag", "Read", "allow"});
    store.delete_role("Cascade");

    auto perms = store.get_role_permissions("Cascade");
    CHECK(perms.empty());
}

// ── Principal-role assignments ───────────────────────────────────────────────

TEST_CASE("RbacStore: assign and list principal roles", "[rbac_store]") {
    RbacStore store(":memory:");
    store.assign_role({"user", "alice", "Administrator"});
    store.assign_role({"user", "alice", "Viewer"});

    auto roles = store.get_principal_roles("user", "alice");
    REQUIRE(roles.size() == 2);
}

TEST_CASE("RbacStore: duplicate assignment is idempotent", "[rbac_store]") {
    RbacStore store(":memory:");
    store.assign_role({"user", "bob", "Viewer"});
    store.assign_role({"user", "bob", "Viewer"});

    auto roles = store.get_principal_roles("user", "bob");
    CHECK(roles.size() == 1);
}

TEST_CASE("RbacStore: unassign role", "[rbac_store]") {
    RbacStore store(":memory:");
    store.assign_role({"user", "carol", "Operator"});
    store.unassign_role("user", "carol", "Operator");

    auto roles = store.get_principal_roles("user", "carol");
    CHECK(roles.empty());
}

TEST_CASE("RbacStore: get role members", "[rbac_store]") {
    RbacStore store(":memory:");
    store.assign_role({"user", "alice", "Operator"});
    store.assign_role({"user", "bob", "Operator"});

    auto members = store.get_role_members("Operator");
    REQUIRE(members.size() == 2);
}

TEST_CASE("RbacStore: deleting role cascades assignments", "[rbac_store]") {
    RbacStore store(":memory:");
    store.create_role({"Temp", "", false, 0});
    store.assign_role({"user", "alice", "Temp"});
    store.delete_role("Temp");

    auto roles = store.get_principal_roles("user", "alice");
    CHECK(roles.empty());
}

// ── check_permission ─────────────────────────────────────────────────────────

TEST_CASE("RbacStore: check_permission with direct role", "[rbac_store]") {
    RbacStore store(":memory:");
    store.assign_role({"user", "alice", "Administrator"});

    CHECK(store.check_permission("alice", "Infrastructure", "Write"));
    CHECK(store.check_permission("alice", "Execution", "Execute"));
    CHECK(store.check_permission("alice", "AuditLog", "Read"));
}

TEST_CASE("RbacStore: check_permission denied when no role", "[rbac_store]") {
    RbacStore store(":memory:");
    CHECK_FALSE(store.check_permission("nobody", "Execution", "Execute"));
}

TEST_CASE("RbacStore: Viewer cannot write", "[rbac_store]") {
    RbacStore store(":memory:");
    store.assign_role({"user", "bob", "Viewer"});

    CHECK(store.check_permission("bob", "Execution", "Read"));
    CHECK_FALSE(store.check_permission("bob", "Execution", "Execute"));
    CHECK_FALSE(store.check_permission("bob", "Tag", "Write"));
    CHECK_FALSE(store.check_permission("bob", "Infrastructure", "Read"));
}

TEST_CASE("RbacStore: check_permission via group membership", "[rbac_store]") {
    RbacStore store(":memory:");
    store.create_group({"soc-team", "Security Operations", "local", "", 0});
    store.add_group_member("soc-team", "carol");
    store.assign_role({"group", "soc-team", "Operator"});

    CHECK(store.check_permission("carol", "Execution", "Execute"));
    CHECK(store.check_permission("carol", "Tag", "Write"));
    CHECK_FALSE(store.check_permission("carol", "Infrastructure", "Write"));
}

TEST_CASE("RbacStore: deny overrides allow", "[rbac_store]") {
    RbacStore store(":memory:");
    store.create_role({"NoPatch", "No patching allowed", false, 0});
    store.set_permission({"NoPatch", "Execution", "Execute", "deny"});

    // alice has Operator (allow Execute) AND NoPatch (deny Execute)
    store.assign_role({"user", "alice", "Operator"});
    store.assign_role({"user", "alice", "NoPatch"});

    CHECK_FALSE(store.check_permission("alice", "Execution", "Execute"));
    // But read still works
    CHECK(store.check_permission("alice", "Execution", "Read"));
}

TEST_CASE("RbacStore: multiple roles combine permissions", "[rbac_store]") {
    RbacStore store(":memory:");
    store.create_role({"AuditReader", "Read audit logs", false, 0});
    store.set_permission({"AuditReader", "AuditLog", "Read", "allow"});

    store.assign_role({"user", "dave", "Viewer"});
    store.assign_role({"user", "dave", "AuditReader"});

    // Viewer gives Read on most types; AuditReader adds AuditLog Read
    CHECK(store.check_permission("dave", "AuditLog", "Read"));
    CHECK(store.check_permission("dave", "Execution", "Read"));
    CHECK_FALSE(store.check_permission("dave", "Execution", "Execute"));
}

// ── Effective permissions ────────────────────────────────────────────────────

TEST_CASE("RbacStore: get_effective_permissions", "[rbac_store]") {
    RbacStore store(":memory:");
    store.assign_role({"user", "alice", "Viewer"});

    auto perms = store.get_effective_permissions("alice");
    CHECK_FALSE(perms.empty());
    for (auto& p : perms)
        CHECK(p.effect == "allow");
}

TEST_CASE("RbacStore: effective permissions empty for unassigned user", "[rbac_store]") {
    RbacStore store(":memory:");
    auto perms = store.get_effective_permissions("nobody");
    CHECK(perms.empty());
}

// ── Group CRUD ───────────────────────────────────────────────────────────────

TEST_CASE("RbacStore: create and list groups", "[rbac_store]") {
    RbacStore store(":memory:");
    store.create_group({"dev-team", "Development", "local", "", 0});
    store.create_group({"ops-team", "Operations", "local", "", 0});

    auto groups = store.list_groups();
    REQUIRE(groups.size() == 2);
}

TEST_CASE("RbacStore: group membership", "[rbac_store]") {
    RbacStore store(":memory:");
    store.create_group({"team", "Test team", "local", "", 0});
    store.add_group_member("team", "alice");
    store.add_group_member("team", "bob");

    auto members = store.get_group_members("team");
    REQUIRE(members.size() == 2);

    store.remove_group_member("team", "bob");
    members = store.get_group_members("team");
    CHECK(members.size() == 1);
    CHECK(members[0] == "alice");
}

TEST_CASE("RbacStore: deleting group cascades members", "[rbac_store]") {
    RbacStore store(":memory:");
    store.create_group({"temp", "", "local", "", 0});
    store.add_group_member("temp", "alice");
    store.delete_group("temp");

    auto members = store.get_group_members("temp");
    CHECK(members.empty());
}

// ── IdP membership reconciliation (#1832) ───────────────────────────────────

TEST_CASE("RbacStore: namespaced_group_name", "[rbac_store]") {
    CHECK(namespaced_group_name("entra", "abc-123") == "entra:abc-123");
    CHECK(namespaced_group_name("saml", "g1") == "saml:g1");
    // 'local' is NOT namespaced.
    CHECK(namespaced_group_name("local", "raw-name") == "raw-name");
}

TEST_CASE("RbacStore: reconcile_idp_memberships namespacing prevents confused deputy",
         "[rbac_store]") {
    RbacStore store(":memory:");

    // A LOCAL group named "admins" already carries a role.
    store.create_group({"admins", "Local admins", "local", "", 0});
    REQUIRE(store.assign_role({"group", "admins", "Operator"}).has_value());

    // The IdP asserts a group with the SAME raw id "admins" for carol.
    auto reconciled = store.reconcile_idp_memberships("carol", "entra", {{"admins", "Admins"}});
    REQUIRE(reconciled.has_value());

    // carol must NOT inherit the local group's role via the same-named IdP
    // group — she landed in "entra:admins", a distinct row with no role
    // assignment of its own yet.
    CHECK_FALSE(store.check_permission("carol", "Execution", "Execute"));

    // The local group's membership is never touched by reconcile.
    auto local_members = store.get_group_members("admins");
    CHECK(local_members.empty());

    // Assigning the role to the NAMESPACED group (the correct, explicit
    // grant an operator would make) is what it takes for carol to get it —
    // proving namespacing, not raw-name collision, decides the outcome.
    REQUIRE(store.assign_role({"group", "entra:admins", "Operator"}).has_value());
    CHECK(store.check_permission("carol", "Execution", "Execute"));
}

TEST_CASE("RbacStore: reconcile_idp_memberships add/remove diff", "[rbac_store]") {
    RbacStore store(":memory:");

    REQUIRE(store.reconcile_idp_memberships("dave", "entra", {{"A", "A"}, {"B", "B"}})
                .has_value());
    CHECK(store.get_group_members("entra:A") == std::vector<std::string>{"dave"});
    CHECK(store.get_group_members("entra:B") == std::vector<std::string>{"dave"});

    // A separately-added LOCAL membership must survive every reconcile.
    store.create_group({"crew", "", "local", "", 0});
    store.add_group_member("crew", "dave");

    // Re-login only asserts A now — B must be dropped.
    REQUIRE(store.reconcile_idp_memberships("dave", "entra", {{"A", "A"}}).has_value());
    CHECK(store.get_group_members("entra:A") == std::vector<std::string>{"dave"});
    CHECK(store.get_group_members("entra:B").empty());
    CHECK(store.get_group_members("crew") == std::vector<std::string>{"dave"});
}

TEST_CASE("RbacStore: reconcile_idp_memberships empty asserted removes only that source",
         "[rbac_store]") {
    RbacStore store(":memory:");

    REQUIRE(store.reconcile_idp_memberships("erin", "entra", {{"A", "A"}}).has_value());
    REQUIRE(store.reconcile_idp_memberships("erin", "saml", {{"S1", "S1"}}).has_value());
    store.create_group({"local-crew", "", "local", "", 0});
    store.add_group_member("local-crew", "erin");

    // Next SSO login asserts NO groups at all — full deprovisioning.
    REQUIRE(store.reconcile_idp_memberships("erin", "entra", {}).has_value());

    CHECK(store.get_group_members("entra:A").empty());
    // Untouched: a different source, and a local group.
    CHECK(store.get_group_members("saml:S1") == std::vector<std::string>{"erin"});
    CHECK(store.get_group_members("local-crew") == std::vector<std::string>{"erin"});
}

// qa-S1: the row-presence assertions above prove the DELETE didn't touch the
// local group's *membership table row*, but the invariant that actually
// matters is the permission it grants. Attach a role to the LOCAL group and
// prove check_permission is bit-for-bit unchanged before and after an
// empty-asserted (full-deprovisioning) reconcile — this is what would catch
// a future regression that widens the stale-membership DELETE's scoping
// (e.g. a refactor that drops the `group_name IN (SELECT name FROM groups
// WHERE source = ?)` clause) even if row-presence checks were accidentally
// preserved.
TEST_CASE("RbacStore: empty-asserted reconcile cannot strip a local role grant",
         "[rbac_store]") {
    RbacStore store(":memory:");

    store.create_group({"local-crew", "", "local", "", 0});
    store.add_group_member("local-crew", "erin");
    REQUIRE(store.assign_role({"group", "local-crew", "Operator"}).has_value());

    REQUIRE(store.reconcile_idp_memberships("erin", "entra", {{"A", "A"}}).has_value());

    // Baseline: erin holds Operator permissions via the local group.
    REQUIRE(store.check_permission("erin", "Execution", "Execute"));
    REQUIRE(store.check_permission("erin", "Tag", "Write"));
    REQUIRE_FALSE(store.check_permission("erin", "Infrastructure", "Write"));

    // Full deprovisioning of the 'entra' source — asserts NO groups at all.
    REQUIRE(store.reconcile_idp_memberships("erin", "entra", {}).has_value());

    // The local role grant must be bit-for-bit unchanged.
    CHECK(store.check_permission("erin", "Execution", "Execute"));
    CHECK(store.check_permission("erin", "Tag", "Write"));
    CHECK_FALSE(store.check_permission("erin", "Infrastructure", "Write"));
}

TEST_CASE("RbacStore: reconcile_idp_memberships enforces the group-count cap", "[rbac_store]") {
    RbacStore store(":memory:");

    std::vector<std::pair<std::string, std::string>> asserted;
    asserted.reserve(RbacStore::kMaxIdpGroupsPerLogin + 1);
    for (size_t i = 0; i <= RbacStore::kMaxIdpGroupsPerLogin; ++i)
        asserted.emplace_back("g" + std::to_string(i), "g" + std::to_string(i));

    auto result = store.reconcile_idp_memberships("frank", "entra", asserted);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == "group_count_exceeded");

    // No mutation on rejection.
    CHECK(store.list_groups().empty());
    CHECK(store.get_group_members("entra:g0").empty());
}

// qa-S3: exactly the cap boundary succeeds — only `> kMaxIdpGroupsPerLogin`
// is rejected, not `==`.
TEST_CASE("RbacStore: reconcile_idp_memberships accepts exactly the group-count cap",
         "[rbac_store]") {
    RbacStore store(":memory:");

    std::vector<std::pair<std::string, std::string>> asserted;
    asserted.reserve(RbacStore::kMaxIdpGroupsPerLogin);
    for (size_t i = 0; i < RbacStore::kMaxIdpGroupsPerLogin; ++i)
        asserted.emplace_back("g" + std::to_string(i), "g" + std::to_string(i));

    auto result = store.reconcile_idp_memberships("frank2", "entra", asserted);
    REQUIRE(result.has_value());
    CHECK(result->added == RbacStore::kMaxIdpGroupsPerLogin);
    CHECK(store.get_group_members("entra:g0") == std::vector<std::string>{"frank2"});
}

TEST_CASE("RbacStore: reconcile_idp_memberships is idempotent", "[rbac_store]") {
    RbacStore store(":memory:");

    std::vector<std::pair<std::string, std::string>> asserted = {{"A", "A"}, {"B", "B"}};
    REQUIRE(store.reconcile_idp_memberships("gina", "entra", asserted).has_value());
    REQUIRE(store.reconcile_idp_memberships("gina", "entra", asserted).has_value());

    CHECK(store.get_group_members("entra:A") == std::vector<std::string>{"gina"});
    CHECK(store.get_group_members("entra:B") == std::vector<std::string>{"gina"});
    CHECK(store.list_groups().size() == 2);
}

// comp-S2/cons-S3: the {added, removed} counts a caller uses to decide
// whether to write a provisioning audit row.
TEST_CASE("RbacStore: reconcile_idp_memberships reports added/removed counts",
         "[rbac_store]") {
    RbacStore store(":memory:");

    auto first = store.reconcile_idp_memberships("hank", "entra", {{"A", "A"}, {"B", "B"}});
    REQUIRE(first.has_value());
    CHECK(first->added == 2);
    CHECK(first->removed == 0);

    // No-op re-login: same asserted set, nothing added or removed.
    auto noop = store.reconcile_idp_memberships("hank", "entra", {{"A", "A"}, {"B", "B"}});
    REQUIRE(noop.has_value());
    CHECK(noop->added == 0);
    CHECK(noop->removed == 0);

    // Drop B, add C: one added, one removed.
    auto diff = store.reconcile_idp_memberships("hank", "entra", {{"A", "A"}, {"C", "C"}});
    REQUIRE(diff.has_value());
    CHECK(diff->added == 1);
    CHECK(diff->removed == 1);
}

// UP-6: reconcile_idp_memberships must never accept "local" (or an empty
// string) as `source` — the stale-membership DELETE it runs is scoped to
// `groups.source = ?` and is only safe for an IdP source. A miswired call
// with "local" would mass-delete local group memberships fleet-wide.
TEST_CASE("RbacStore: reconcile_idp_memberships rejects source=='local'", "[rbac_store]") {
    RbacStore store(":memory:");

    store.create_group({"crew", "", "local", "", 0});
    store.add_group_member("crew", "ivan");
    REQUIRE(store.assign_role({"group", "crew", "Operator"}).has_value());

    auto result = store.reconcile_idp_memberships("ivan", "local", {{"crew", "crew"}});
    REQUIRE_FALSE(result.has_value());
    CHECK_FALSE(result.error().empty());

    // No mutation: the local membership and its role grant survive.
    CHECK(store.get_group_members("crew") == std::vector<std::string>{"ivan"});
    CHECK(store.check_permission("ivan", "Execution", "Execute"));
}

TEST_CASE("RbacStore: reconcile_idp_memberships rejects an empty source", "[rbac_store]") {
    RbacStore store(":memory:");
    auto result = store.reconcile_idp_memberships("ivan", "", {{"g", "g"}});
    REQUIRE_FALSE(result.has_value());
}

// sec-L1: a group row that pre-exists with a DIFFERENT source than this
// reconcile call (e.g. a local group literally named `entra:x`, created
// before the create_group reserved-prefix guard existed, or by direct DB
// manipulation) must never be joined — that would leak whatever roles are
// granted to the pre-existing group to the IdP-authenticated user.
TEST_CASE("RbacStore: reconcile_idp_memberships does not join a pre-existing "
         "differently-sourced group",
         "[rbac_store]") {
    // The `create_group` reserved-prefix guard means a source='local' create
    // named "entra:x" can no longer be made through the public API — which
    // is exactly the point of this scenario: a row like this can only exist
    // as a LEGACY artifact from before the guard shipped (or direct DB
    // manipulation). Seed it by bypassing the app layer, the same way a real
    // pre-upgrade deployment's data would.
    const auto path = yuzu::test::unique_temp_path("rbac-secl1-");
    {
        RbacStore seed(path); // creates schema + seed_defaults
        REQUIRE(seed.is_open());
    }
    {
        sqlite3* db = nullptr;
        REQUIRE(sqlite3_open_v2(path.string().c_str(), &db, SQLITE_OPEN_READWRITE, nullptr) ==
                SQLITE_OK);
        REQUIRE(sqlite3_exec(db,
                             "INSERT INTO groups (name, description, source, external_id, "
                             "created_at) VALUES ('entra:x', 'Local admins', 'local', '', 100);",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(db);
    }

    {
        RbacStore store(path);
        REQUIRE(store.is_open());
        REQUIRE(store.assign_role({"group", "entra:x", "Administrator"}).has_value());

        auto reconciled = store.reconcile_idp_memberships("judy", "entra", {{"x", "x"}});
        REQUIRE(reconciled.has_value());
        CHECK(reconciled->added == 0); // the join was skipped, not counted as added

        // judy must NOT be a member of the pre-existing local group, and must
        // NOT inherit its Administrator role.
        CHECK(store.get_group_members("entra:x").empty());
        CHECK_FALSE(store.check_permission("judy", "Infrastructure", "Write"));
    } // close `store` before deleting the file — Windows cannot remove an open
      // file (Linux unlinks it lazily), and the throwing remove() overload would
      // otherwise fail this test on MSVC. Use the non-throwing overload for cleanup.
    std::error_code ec;
    std::filesystem::remove(path, ec);
    std::filesystem::remove(std::filesystem::path(path.string() + "-wal"), ec);
    std::filesystem::remove(std::filesystem::path(path.string() + "-shm"), ec);
}

// UP-9: an asserted entry with a blank/whitespace-only external_id must be
// skipped, never turned into a garbage `entra:` / `entra:   ` group.
TEST_CASE("RbacStore: reconcile_idp_memberships skips blank external_id", "[rbac_store]") {
    RbacStore store(":memory:");

    auto reconciled =
        store.reconcile_idp_memberships("karen", "entra", {{"", "Empty"}, {"   ", "Blank"},
                                                            {"real-id", "Real"}});
    REQUIRE(reconciled.has_value());
    CHECK(reconciled->added == 1);

    CHECK(store.get_group_members("entra:real-id") == std::vector<std::string>{"karen"});
    CHECK(store.get_group_members("entra:").empty());
    // No group was created for the blank/whitespace entries.
    auto groups = store.list_groups();
    CHECK(groups.size() == 1);
    CHECK(groups[0].name == "entra:real-id");
}

TEST_CASE("RbacStore: create_group rejects a local group with a reserved IdP prefix",
         "[rbac_store]") {
    RbacStore store(":memory:");

    auto local_collision = store.create_group({"entra:x", "", "local", "", 0});
    REQUIRE_FALSE(local_collision.has_value());

    // Every reserved prefix is covered.
    CHECK_FALSE(store.create_group({"saml:x", "", "local", "", 0}).has_value());
    CHECK_FALSE(store.create_group({"ad:x", "", "local", "", 0}).has_value());
    CHECK_FALSE(store.create_group({"local:x", "", "local", "", 0}).has_value());

    // An IdP-sourced create of the SAME name is exempt from the guard.
    auto idp_create = store.create_group({"entra:x", "", "entra", "x", 0});
    CHECK(idp_create.has_value());

    // A local group whose name merely CONTAINS (not starts with) a reserved
    // token is fine — only the leading `prefix:` is reserved.
    CHECK(store.create_group({"my-entra:team", "", "local", "", 0}).has_value());
}

// qa-S2: a store on disk at schema v1 (pre-#1832) migrates cleanly to v2 —
// idx_groups_source + idx_group_members_username get created and existing
// rows survive. Mirrors the `test_migration_runner.cpp` adoption-scenario
// pattern: seed a v1-only schema directly with the runner, insert data,
// close, then reopen through the real RbacStore constructor (which always
// runs the FULL migration list) and check both the schema and the data.
namespace {
bool index_exists(sqlite3* db, const char* name) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?;", -1,
                           &stmt, nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    bool found = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return found;
}
} // namespace

TEST_CASE("RbacStore: v1 -> v2 migration adds indices without data loss",
         "[rbac_store][migration]") {
    const auto path = yuzu::test::unique_temp_path("rbac-migration-");

    // v1-only migration list — exactly rbac_store's historical v1 schema,
    // duplicated here (not `#include`d from rbac_store.cpp) so this test
    // fails loudly if a future edit changes v1's shape without updating
    // this fixture, rather than silently drifting.
    static const std::vector<yuzu::server::Migration> kV1Only = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS securable_types (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS operations (
                id          TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS roles (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   INTEGER NOT NULL DEFAULT 0,
                created_at  INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS role_permissions (
                role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                securable_type  TEXT NOT NULL REFERENCES securable_types(name),
                operation       TEXT NOT NULL REFERENCES operations(id),
                effect          TEXT NOT NULL DEFAULT 'allow',
                PRIMARY KEY (role_name, securable_type, operation)
            );
            CREATE TABLE IF NOT EXISTS principal_roles (
                principal_type  TEXT NOT NULL,
                principal_id    TEXT NOT NULL,
                role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                PRIMARY KEY (principal_type, principal_id, role_name)
            );
            CREATE INDEX IF NOT EXISTS idx_principal_roles_lookup
                ON principal_roles(principal_type, principal_id);
            CREATE TABLE IF NOT EXISTS groups (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                source      TEXT NOT NULL DEFAULT 'local',
                external_id TEXT,
                created_at  INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS group_members (
                group_name  TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
                username    TEXT NOT NULL,
                PRIMARY KEY (group_name, username)
            );
            CREATE TABLE IF NOT EXISTS rbac_config (
                key     TEXT PRIMARY KEY,
                value   TEXT NOT NULL
            );
        )"},
    };

    {
        sqlite3* db = nullptr;
        REQUIRE(sqlite3_open_v2(path.string().c_str(), &db,
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                                nullptr) == SQLITE_OK);
        REQUIRE(yuzu::server::MigrationRunner::run(db, "rbac_store", kV1Only));
        REQUIRE(yuzu::server::MigrationRunner::current_version(db, "rbac_store") == 1);
        REQUIRE_FALSE(index_exists(db, "idx_groups_source"));
        REQUIRE_FALSE(index_exists(db, "idx_group_members_username"));

        // Seed data that must survive the upgrade. Deliberately a LOCAL
        // group/membership, not an IdP-sourced one (#1837 v3 legitimately
        // purges IdP-sourced group_members — that behavior is covered by
        // its own dedicated migration test in test_oidc_principal_key.cpp;
        // this test's purpose is unrelated generic data survival across the
        // rest of the migration ladder).
        sqlite3_exec(db,
                    "INSERT INTO groups (name, description, source, external_id, created_at) "
                    "VALUES ('seed-team', 'seed', 'local', '', 100);"
                    "INSERT INTO group_members (group_name, username) VALUES ('seed-team', 'leo');"
                    "INSERT INTO roles (name, description, is_system, created_at) "
                    "VALUES ('Custom', 'seed role', 0, 100);",
                    nullptr, nullptr, nullptr);
        sqlite3_close(db);
    }

    // Reopen through the production constructor — runs the FULL migration
    // list (v1 adoption no-op + v2 index creation + v3 no-op for local
    // groups) and seed_defaults().
    {
        RbacStore store(path);
        REQUIRE(store.is_open());

        // Pre-existing data preserved.
        auto groups = store.list_groups();
        auto found = std::find_if(groups.begin(), groups.end(),
                                  [](const RbacGroup& g) { return g.name == "seed-team"; });
        REQUIRE(found != groups.end());
        CHECK(found->source == "local");
        CHECK(store.get_group_members("seed-team") == std::vector<std::string>{"leo"});
        CHECK(store.get_role("Custom").has_value());

        // v2 index creation — the store's own connection isn't reachable
        // from the test, so open a second raw connection on the same file
        // to inspect sqlite_master (WAL-mode readers see committed schema
        // changes from another connection on the same file).
        sqlite3* verify_db = nullptr;
        REQUIRE(sqlite3_open_v2(path.string().c_str(), &verify_db, SQLITE_OPEN_READONLY,
                                nullptr) == SQLITE_OK);
        CHECK(index_exists(verify_db, "idx_groups_source"));
        CHECK(index_exists(verify_db, "idx_group_members_username"));
        sqlite3_close(verify_db);
    }

    std::filesystem::remove(path);
    std::filesystem::remove(std::filesystem::path(path.string() + "-wal"));
    std::filesystem::remove(std::filesystem::path(path.string() + "-shm"));
}

// ── ITServiceOwner role ──────────────────────────────────────────────────────

TEST_CASE("RbacStore: ITServiceOwner role seeded with correct permissions", "[rbac_store]") {
    RbacStore store(":memory:");
    auto role = store.get_role("ITServiceOwner");
    REQUIRE(role.has_value());
    CHECK(role->is_system);
    CHECK(role->description.find("IT Service") != std::string::npos);

    auto perms = store.get_role_permissions("ITServiceOwner");
    // 18 types * 5 CRUD ops = 90 permissions, plus the targeted Push grant on
    // GuaranteedState = 91 permissions total. Push is deliberately NOT
    // cross-seeded on non-Guardian securables — see the rationale in
    // rbac_store.cpp seed_defaults(). (18th type: SoftwareLicensing, ADR-0024 —
    // ITServiceOwner full CRUD per the D-9 matrix.)
    CHECK(perms.size() == 91);
    size_t push_count = 0;
    for (auto& p : perms) {
        CHECK(p.effect == "allow");
        // Should not include UserManagement, Security, ApiToken
        CHECK(p.securable_type != "UserManagement");
        CHECK(p.securable_type != "Security");
        CHECK(p.securable_type != "ApiToken");
        if (p.operation == "Push") {
            ++push_count;
            CHECK(p.securable_type == "GuaranteedState");
        }
    }
    CHECK(push_count == 1);
}

// ── check_scoped_permission ──────────────────────────────────────────────────

namespace {
// Per-test SQLite temp file for the on-disk ManagementGroupStore — the fixed
// "test_scoped_rbac.db" name was a cross-JOB shared resource on the
// shared-identity CI pools (#1883); TempDbFile also picks up the -wal/-shm
// cleanup the old fixture missed.
struct ScopedTestDb : yuzu::test::TempDbFile {
    ScopedTestDb() : TempDbFile("yuzu_test_scoped_rbac-") {}
};
} // namespace

TEST_CASE("RbacStore: check_scoped_permission global allow bypasses scoping", "[rbac_store]") {
    RbacStore rbac(":memory:");
    ScopedTestDb tmp;
    ManagementGroupStore mgmt(tmp.path);

    rbac.assign_role({"user", "admin_user", "Administrator"});
    CHECK(rbac.check_scoped_permission("admin_user", "Tag", "Write", "agent-1", &mgmt));
}

TEST_CASE("RbacStore: check_scoped_permission group-scoped allow", "[rbac_store]") {
    RbacStore rbac(":memory:");
    ScopedTestDb tmp;
    ManagementGroupStore mgmt(tmp.path);

    // Create a management group and add agent to it
    ManagementGroup g;
    g.name = "Service: CRM";
    g.membership_type = "static";
    auto group_id = mgmt.create_group(g);
    REQUIRE(group_id.has_value());
    mgmt.add_member(*group_id, "agent-crm-1");

    // Assign ITServiceOwner to alice on this group
    GroupRoleAssignment a;
    a.group_id = *group_id;
    a.principal_type = "user";
    a.principal_id = "alice";
    a.role_name = "ITServiceOwner";
    mgmt.assign_role(a);

    // alice has NO global role, but should have scoped access
    CHECK(rbac.check_scoped_permission("alice", "Tag", "Write", "agent-crm-1", &mgmt));
    CHECK(rbac.check_scoped_permission("alice", "Execution", "Execute", "agent-crm-1", &mgmt));
}

TEST_CASE("RbacStore: check_scoped_permission denied without scope", "[rbac_store]") {
    RbacStore rbac(":memory:");
    ScopedTestDb tmp;
    ManagementGroupStore mgmt(tmp.path);

    // alice has ITServiceOwner on CRM group, but agent-other is not in it
    ManagementGroup g;
    g.name = "Service: CRM";
    g.membership_type = "static";
    auto group_id = mgmt.create_group(g);
    REQUIRE(group_id.has_value());
    mgmt.add_member(*group_id, "agent-crm-1");

    GroupRoleAssignment a;
    a.group_id = *group_id;
    a.principal_type = "user";
    a.principal_id = "alice";
    a.role_name = "ITServiceOwner";
    mgmt.assign_role(a);

    // agent-other is NOT in the CRM group
    CHECK_FALSE(rbac.check_scoped_permission("alice", "Tag", "Write", "agent-other", &mgmt));
}
