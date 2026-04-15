/**
 * test_management_group_store.cpp — Unit tests for management group store
 */

#include "management_group_store.hpp"

#include <sqlite3.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

using namespace yuzu::server;

namespace {

// Per-instance unique path so tests are safe to run under parallel
// meson test --num-processes N. The prior hardcoded path collided
// between concurrent test cases and between the outer constructor and
// destructor in the injected-cycle test below.
struct TempDb {
    std::filesystem::path path;
    TempDb()
        : path(std::filesystem::temp_directory_path() /
               ("test_mgmt_groups-" +
                std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()) ^
                               static_cast<size_t>(std::chrono::steady_clock::now()
                                                       .time_since_epoch()
                                                       .count())) +
                ".db")) {
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

TEST_CASE("ManagementGroupStore: find_group_by_name", "[mgmt][crud]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup g;
    g.name = "Service: CRM";
    g.membership_type = "dynamic";
    g.scope_expression = R"(tag:service == "CRM")";
    auto id = store.create_group(g);
    REQUIRE(id.has_value());

    auto found = store.find_group_by_name("Service: CRM");
    REQUIRE(found.has_value());
    CHECK(found->id == *id);
    CHECK(found->name == "Service: CRM");
    CHECK(found->membership_type == "dynamic");

    auto not_found = store.find_group_by_name("Service: ERP");
    CHECK(!not_found.has_value());
}

TEST_CASE("ManagementGroupStore: update_group rejects self-parent", "[mgmt][hierarchy][cycle]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup g;
    g.name = "Self";
    g.membership_type = "static";
    auto id = store.create_group(g);
    REQUIRE(id.has_value());

    ManagementGroup updated;
    updated.id = *id;
    updated.name = "Self";
    updated.membership_type = "static";
    updated.parent_id = *id; // attempt to become its own parent

    auto result = store.update_group(updated);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("own parent") != std::string::npos);
}

TEST_CASE("ManagementGroupStore: update_group rejects re-parenting cycle",
          "[mgmt][hierarchy][cycle]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup a;
    a.name = "A";
    a.membership_type = "static";
    auto a_id = store.create_group(a);
    REQUIRE(a_id.has_value());

    ManagementGroup b;
    b.name = "B";
    b.membership_type = "static";
    b.parent_id = *a_id;
    auto b_id = store.create_group(b);
    REQUIRE(b_id.has_value());

    // Attempt to set A.parent = B, which would form the cycle A->B->A.
    ManagementGroup a_update;
    a_update.id = *a_id;
    a_update.name = "A";
    a_update.membership_type = "static";
    a_update.parent_id = *b_id;

    auto result = store.update_group(a_update);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("cycle") != std::string::npos);
}

TEST_CASE("ManagementGroupStore: update_group rejects depth overflow",
          "[mgmt][hierarchy][cycle]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    // Build a 5-deep chain: root -> L1 -> L2 -> L3 -> L4.
    std::string prev;
    std::vector<std::string> chain;
    for (int i = 0; i < 5; ++i) {
        ManagementGroup g;
        g.name = "L" + std::to_string(i);
        g.membership_type = "static";
        g.parent_id = prev;
        auto result = store.create_group(g);
        REQUIRE(result.has_value());
        chain.push_back(*result);
        prev = *result;
    }

    // Create an orphan and try to attach it under L4 — that would make it
    // the 6th level, exceeding the depth limit of 5.
    ManagementGroup orphan;
    orphan.name = "Orphan";
    orphan.membership_type = "static";
    auto orphan_id = store.create_group(orphan);
    REQUIRE(orphan_id.has_value());

    ManagementGroup reparent;
    reparent.id = *orphan_id;
    reparent.name = "Orphan";
    reparent.membership_type = "static";
    reparent.parent_id = chain.back();

    auto result = store.update_group(reparent);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("depth") != std::string::npos);
}

TEST_CASE("ManagementGroupStore: get_descendant_ids terminates on injected cycle",
          "[mgmt][hierarchy][cycle]") {
    TempDb tmp;

    std::string a_id;
    std::string b_id;
    {
        ManagementGroupStore store(tmp.path);

        ManagementGroup a;
        a.name = "Cycle-A";
        a.membership_type = "static";
        auto r1 = store.create_group(a);
        REQUIRE(r1.has_value());
        a_id = *r1;

        ManagementGroup b;
        b.name = "Cycle-B";
        b.membership_type = "static";
        b.parent_id = a_id;
        auto r2 = store.create_group(b);
        REQUIRE(r2.has_value());
        b_id = *r2;
    } // store closed — release locks before we reach around with raw sqlite3.

    // NOTE: test-only raw SQL. The `a_id`/`b_id` values come from the store's
    // `generate_id()` (hex-only) so there's no actual injection vector, but
    // production code must never use string concatenation to build SQL —
    // use sqlite3_prepare_v2 + sqlite3_bind_text.
    {
        sqlite3* raw = nullptr;
        const auto path_str = tmp.path.string();
        REQUIRE(sqlite3_open(path_str.c_str(), &raw) == SQLITE_OK);
        std::string sql = "UPDATE management_groups SET parent_id = '" + b_id +
                          "' WHERE id = '" + a_id + "';";
        REQUIRE(sqlite3_exec(raw, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    // Re-open the store and walk descendants from A. The BFS must terminate
    // (not hang) and must include B without repeating it.
    ManagementGroupStore store(tmp.path);
    auto descendants = store.get_descendant_ids(a_id);
    CHECK(std::find(descendants.begin(), descendants.end(), b_id) != descendants.end());
    // Every entry should be unique — the visited set guarantees no repeats.
    std::vector<std::string> sorted = descendants;
    std::sort(sorted.begin(), sorted.end());
    CHECK(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end());
}

TEST_CASE("ManagementGroupStore: get_descendant_ids terminates on 3-node cycle",
          "[mgmt][hierarchy][cycle]") {
    TempDb tmp;
    std::string a_id, b_id, c_id;
    {
        ManagementGroupStore store(tmp.path);
        ManagementGroup a;
        a.name = "Three-A";
        a.membership_type = "static";
        auto r1 = store.create_group(a);
        REQUIRE(r1.has_value());
        a_id = *r1;
        ManagementGroup b;
        b.name = "Three-B";
        b.membership_type = "static";
        b.parent_id = a_id;
        auto r2 = store.create_group(b);
        REQUIRE(r2.has_value());
        b_id = *r2;
        ManagementGroup c;
        c.name = "Three-C";
        c.membership_type = "static";
        c.parent_id = b_id;
        auto r3 = store.create_group(c);
        REQUIRE(r3.has_value());
        c_id = *r3;
    }

    // Inject A.parent = C to form A->B->C->A.
    {
        sqlite3* raw = nullptr;
        const auto path_str = tmp.path.string();
        REQUIRE(sqlite3_open(path_str.c_str(), &raw) == SQLITE_OK);
        std::string sql = "UPDATE management_groups SET parent_id = '" + c_id +
                          "' WHERE id = '" + a_id + "';";
        REQUIRE(sqlite3_exec(raw, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    ManagementGroupStore store(tmp.path);
    auto descendants = store.get_descendant_ids(a_id);
    CHECK(std::find(descendants.begin(), descendants.end(), b_id) != descendants.end());
    CHECK(std::find(descendants.begin(), descendants.end(), c_id) != descendants.end());
    // Each node visited at most once, so the result vector is small.
    CHECK(descendants.size() <= 3);
    // No duplicates.
    std::vector<std::string> sorted = descendants;
    std::sort(sorted.begin(), sorted.end());
    CHECK(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end());

    // Ancestor walk from C must also terminate and return at most 3 unique IDs.
    auto ancestors = store.get_ancestor_ids(c_id);
    CHECK(ancestors.size() <= 3);
    std::vector<std::string> asorted = ancestors;
    std::sort(asorted.begin(), asorted.end());
    CHECK(std::adjacent_find(asorted.begin(), asorted.end()) == asorted.end());
}

TEST_CASE("ManagementGroupStore: get_descendant_ids terminates on self-loop row",
          "[mgmt][hierarchy][cycle]") {
    TempDb tmp;
    std::string a_id;
    {
        ManagementGroupStore store(tmp.path);
        ManagementGroup a;
        a.name = "SelfLoop";
        a.membership_type = "static";
        auto r = store.create_group(a);
        REQUIRE(r.has_value());
        a_id = *r;
    }

    // parent_id = id — the degenerate 1-row cycle.
    {
        sqlite3* raw = nullptr;
        const auto path_str = tmp.path.string();
        REQUIRE(sqlite3_open(path_str.c_str(), &raw) == SQLITE_OK);
        std::string sql = "UPDATE management_groups SET parent_id = '" + a_id +
                          "' WHERE id = '" + a_id + "';";
        REQUIRE(sqlite3_exec(raw, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    ManagementGroupStore store(tmp.path);
    auto descendants = store.get_descendant_ids(a_id);
    // A is its own child but visited already contains it, so it is skipped.
    CHECK(descendants.empty());
    auto ancestors = store.get_ancestor_ids(a_id);
    CHECK(ancestors.empty());
}

TEST_CASE("ManagementGroupStore: update_group accepts reparent-to-root",
          "[mgmt][hierarchy]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup root;
    root.name = "RootParent";
    root.membership_type = "static";
    auto root_id = store.create_group(root);
    REQUIRE(root_id.has_value());

    ManagementGroup child;
    child.name = "MovableChild";
    child.membership_type = "static";
    child.parent_id = *root_id;
    auto child_id = store.create_group(child);
    REQUIRE(child_id.has_value());

    // Reparent the child up to root-level (empty parent_id). Must succeed:
    // all cycle/depth validation is gated on non-empty parent_id, but a
    // future refactor could accidentally break the null-bind path.
    ManagementGroup moved;
    moved.id = *child_id;
    moved.name = "MovableChild";
    moved.membership_type = "static";
    moved.parent_id = "";
    auto result = store.update_group(moved);
    REQUIRE(result.has_value());

    auto retrieved = store.get_group(*child_id);
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->parent_id.empty());
}

TEST_CASE("ManagementGroupStore: create_group rejects caller-supplied self-parent",
          "[mgmt][hierarchy][cycle]") {
    TempDb tmp;
    ManagementGroupStore store(tmp.path);

    ManagementGroup g;
    g.id = "abcdef012345"; // caller-supplied id
    g.parent_id = g.id;    // self-parent
    g.name = "SelfCreate";
    g.membership_type = "static";

    auto result = store.create_group(g);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("own parent") != std::string::npos);
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
