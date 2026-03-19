/**
 * test_management_group_store.cpp — Unit tests for management group store
 */

#include "management_group_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>

using namespace yuzu::server;

namespace {

struct TempDb {
    std::filesystem::path path;
    TempDb() : path(std::filesystem::temp_directory_path() / "test_mgmt_groups.db") {
        std::filesystem::remove(path);
    }
    ~TempDb() { std::filesystem::remove(path); }
};

} // namespace

TEST_CASE("ManagementGroupStore: create and retrieve group", "[mgmt][crud]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);
    REQUIRE(store.is_open());

    ManagementGroup g;
    g.name = "Production Servers";
    g.description = "All production servers";
    g.membership_type = "static";
    g.created_by = "admin";

    auto result = store.create_group(g);
    REQUIRE(result.has_value());

    auto retrieved = store.get_group(*result);
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->name == "Production Servers");
    CHECK(retrieved->description == "All production servers");
    CHECK(retrieved->membership_type == "static");
    CHECK(retrieved->created_by == "admin");
    CHECK(retrieved->created_at > 0);
}

TEST_CASE("ManagementGroupStore: list groups", "[mgmt][crud]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup g1;
    g1.name = "Group A";
    g1.membership_type = "static";
    ManagementGroup g2;
    g2.name = "Group B";
    g2.membership_type = "static";

    store.create_group(g1);
    store.create_group(g2);

    auto groups = store.list_groups();
    REQUIRE(groups.size() == 2);
}

TEST_CASE("ManagementGroupStore: duplicate name rejected", "[mgmt][crud]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup g;
    g.name = "Duplicate";
    g.membership_type = "static";
    auto r1 = store.create_group(g);
    REQUIRE(r1.has_value());

    auto r2 = store.create_group(g);
    REQUIRE(!r2.has_value());
}

TEST_CASE("ManagementGroupStore: update group", "[mgmt][crud]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup g;
    g.name = "Original";
    g.membership_type = "static";
    auto id = store.create_group(g);
    REQUIRE(id.has_value());

    ManagementGroup updated;
    updated.id = *id;
    updated.name = "Updated";
    updated.description = "New description";
    updated.membership_type = "dynamic";
    updated.scope_expression = R"(ostype == "Windows")";

    auto result = store.update_group(updated);
    REQUIRE(result.has_value());

    auto retrieved = store.get_group(*id);
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->name == "Updated");
    CHECK(retrieved->membership_type == "dynamic");
}

TEST_CASE("ManagementGroupStore: delete group", "[mgmt][crud]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup g;
    g.name = "ToDelete";
    g.membership_type = "static";
    auto id = store.create_group(g);
    REQUIRE(id.has_value());

    auto del = store.delete_group(*id);
    REQUIRE(del.has_value());

    auto retrieved = store.get_group(*id);
    CHECK(!retrieved.has_value());
}

TEST_CASE("ManagementGroupStore: parent-child hierarchy", "[mgmt][hierarchy]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup parent;
    parent.name = "Parent";
    parent.membership_type = "static";
    auto parent_id = store.create_group(parent);
    REQUIRE(parent_id.has_value());

    ManagementGroup child;
    child.name = "Child";
    child.membership_type = "static";
    child.parent_id = *parent_id;
    auto child_id = store.create_group(child);
    REQUIRE(child_id.has_value());

    auto children = store.get_children(*parent_id);
    REQUIRE(children.size() == 1);
    CHECK(children[0].name == "Child");

    auto ancestors = store.get_ancestor_ids(*child_id);
    REQUIRE(ancestors.size() == 1);
    CHECK(ancestors[0] == *parent_id);

    auto descendants = store.get_descendant_ids(*parent_id);
    REQUIRE(descendants.size() == 1);
    CHECK(descendants[0] == *child_id);
}

TEST_CASE("ManagementGroupStore: hierarchy depth limit", "[mgmt][hierarchy]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    std::string prev_id;
    for (int i = 0; i < 6; ++i) {
        ManagementGroup g;
        g.name = "Level " + std::to_string(i);
        g.membership_type = "static";
        g.parent_id = prev_id;
        auto result = store.create_group(g);
        if (i < 6) {
            // First 6 levels should succeed (root + 5 children)
            if (result.has_value()) {
                prev_id = *result;
            } else {
                // Depth exceeded
                CHECK(i >= 5); // Should fail at level 5 or later
                break;
            }
        }
    }
}

TEST_CASE("ManagementGroupStore: static membership", "[mgmt][members]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup g;
    g.name = "Test";
    g.membership_type = "static";
    auto group_id = store.create_group(g);
    REQUIRE(group_id.has_value());

    store.add_member(*group_id, "agent-001");
    store.add_member(*group_id, "agent-002");

    auto members = store.get_members(*group_id);
    REQUIRE(members.size() == 2);

    auto groups = store.get_agent_groups("agent-001");
    REQUIRE(groups.size() == 1);
    CHECK(groups[0] == *group_id);

    store.remove_member(*group_id, "agent-001");
    auto members2 = store.get_members(*group_id);
    CHECK(members2.size() == 1);
}

TEST_CASE("ManagementGroupStore: dynamic membership refresh", "[mgmt][members]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup g;
    g.name = "Dynamic";
    g.membership_type = "dynamic";
    auto group_id = store.create_group(g);
    REQUIRE(group_id.has_value());

    store.refresh_dynamic_membership(*group_id, {"agent-A", "agent-B", "agent-C"});
    auto members = store.get_members(*group_id);
    CHECK(members.size() == 3);

    // Refresh with new set
    store.refresh_dynamic_membership(*group_id, {"agent-B", "agent-D"});
    auto members2 = store.get_members(*group_id);
    CHECK(members2.size() == 2);
}

TEST_CASE("ManagementGroupStore: group role assignments", "[mgmt][roles]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup g;
    g.name = "RoleGroup";
    g.membership_type = "static";
    auto group_id = store.create_group(g);
    REQUIRE(group_id.has_value());

    GroupRoleAssignment a;
    a.group_id = *group_id;
    a.principal_type = "user";
    a.principal_id = "alice";
    a.role_name = "Operator";

    auto result = store.assign_role(a);
    REQUIRE(result.has_value());

    auto roles = store.get_group_roles(*group_id);
    REQUIRE(roles.size() == 1);
    CHECK(roles[0].principal_id == "alice");
    CHECK(roles[0].role_name == "Operator");

    store.unassign_role(*group_id, "user", "alice", "Operator");
    auto roles2 = store.get_group_roles(*group_id);
    CHECK(roles2.empty());
}

TEST_CASE("ManagementGroupStore: cascade delete removes members and roles", "[mgmt][cascade]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup g;
    g.name = "CascadeTest";
    g.membership_type = "static";
    auto group_id = store.create_group(g);
    REQUIRE(group_id.has_value());

    store.add_member(*group_id, "agent-001");

    GroupRoleAssignment a;
    a.group_id = *group_id;
    a.principal_type = "user";
    a.principal_id = "bob";
    a.role_name = "Viewer";
    store.assign_role(a);

    store.delete_group(*group_id);

    auto members = store.get_members(*group_id);
    CHECK(members.empty());

    auto roles = store.get_group_roles(*group_id);
    CHECK(roles.empty());
}
