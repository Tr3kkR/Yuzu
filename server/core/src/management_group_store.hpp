#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

struct ManagementGroup {
    std::string id;
    std::string name;
    std::string description;
    std::string parent_id;        // empty for root groups
    std::string membership_type;  // "static" or "dynamic"
    std::string scope_expression; // for dynamic groups (evaluated by scope engine)
    std::string created_by;
    int64_t created_at{0};
    int64_t updated_at{0};
};

struct ManagementGroupMember {
    std::string group_id;
    std::string agent_id;
    std::string source; // "static" or "dynamic"
    int64_t added_at{0};
};

struct GroupRoleAssignment {
    std::string group_id;
    std::string principal_type; // "user" or "group"
    std::string principal_id;
    std::string role_name;
};

class ManagementGroupStore {
public:
    explicit ManagementGroupStore(const std::filesystem::path& db_path);
    ~ManagementGroupStore();

    ManagementGroupStore(const ManagementGroupStore&) = delete;
    ManagementGroupStore& operator=(const ManagementGroupStore&) = delete;

    bool is_open() const;

    // ── Group CRUD ───────────────────────────────────────────────────────
    std::expected<std::string, std::string> create_group(const ManagementGroup& group);
    std::optional<ManagementGroup> get_group(const std::string& id) const;
    std::optional<ManagementGroup> find_group_by_name(const std::string& name) const;
    std::vector<ManagementGroup> list_groups() const;
    std::vector<ManagementGroup> get_children(const std::string& parent_id) const;
    std::expected<void, std::string> update_group(const ManagementGroup& group);
    std::expected<void, std::string> delete_group(const std::string& id);

    // ── Membership ───────────────────────────────────────────────────────
    std::expected<void, std::string> add_member(const std::string& group_id,
                                                const std::string& agent_id);
    std::expected<void, std::string> remove_member(const std::string& group_id,
                                                   const std::string& agent_id);
    std::vector<ManagementGroupMember> get_members(const std::string& group_id) const;
    std::vector<std::string> get_agent_groups(const std::string& agent_id) const;

    /// Replace dynamic membership for a group (used after scope expression evaluation).
    void refresh_dynamic_membership(const std::string& group_id,
                                    const std::vector<std::string>& matching_agent_ids);

    // ── Hierarchy ────────────────────────────────────────────────────────
    std::vector<std::string> get_ancestor_ids(const std::string& group_id) const;
    std::vector<std::string> get_descendant_ids(const std::string& group_id) const;

    // ── Group-scoped role assignments ────────────────────────────────────
    std::expected<void, std::string> assign_role(const GroupRoleAssignment& assignment);
    std::expected<void, std::string> unassign_role(const std::string& group_id,
                                                   const std::string& principal_type,
                                                   const std::string& principal_id,
                                                   const std::string& role_name);
    std::vector<GroupRoleAssignment> get_group_roles(const std::string& group_id) const;

    /// Which agents can a user see based on group-scoped role assignments?
    std::vector<std::string> get_visible_agents(const std::string& username) const;

    // ── Counting (for metrics / UI) ───────────────────────────────────────
    size_t count_groups() const;
    size_t count_all_members() const;
    size_t count_members(const std::string& group_id) const;

    /// Well-known root group ID.
    static constexpr const char* kRootGroupId = "000000000000";

private:
    sqlite3* db_{nullptr};

    void create_tables();
    std::string generate_id() const;
};

} // namespace yuzu::server
