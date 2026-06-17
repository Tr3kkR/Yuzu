#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <shared_mutex>
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
    ///
    /// PRECONDITION: the caller must have already authenticated the session.
    /// This method performs NO authentication and, when RBAC is not actively
    /// enforced (below), returns the full enrolled set for ANY username — the
    /// route-layer session/permission check is the access boundary.
    ///
    /// When RBAC enforcement is globally DISABLED (the default posture, and the
    /// UAT rig), no per-user `management_group_roles` rows exist, so the
    /// role-scoped inner join would return an empty set and hide every agent
    /// from the legacy-admin superuser — even though it has full effective
    /// access everywhere else (#1453). In that case this returns the full
    /// enrolled set instead (every agent is auto-added to the root "All
    /// Devices" group at enrollment). The branch is gated on the injected
    /// `rbac_enabled_probe_`: when the probe reports RBAC ENABLED the exact
    /// role-scoped semantics are preserved unchanged, so the fallback can never
    /// widen visibility WHILE RBAC IS ON. When the probe is UNSET it also fails
    /// CLOSED (role-scoped join only). The widened set is returned only when the
    /// probe affirmatively reports RBAC off — which, consistent with the rest of
    /// the dashboard (`check_permission`, `/api/me`), is the same posture under
    /// which every authenticated user is a legacy superuser. (How a *failed*
    /// RbacStore load should be treated — legacy-open vs fail-closed — is a
    /// system-wide question tracked separately, not specific to visibility.)
    std::vector<std::string> get_visible_agents(const std::string& username) const;

    /// Inject a predicate reporting whether RBAC enforcement is globally
    /// enabled, wired once at startup from `RbacStore::is_rbac_enabled()`
    /// (before the web server accepts requests). If never set,
    /// `get_visible_agents` fails CLOSED — role-scoped inner join only.
    void set_rbac_enabled_probe(std::function<bool()> probe);

    // ── Counting (for metrics / UI) ───────────────────────────────────────
    size_t count_groups() const;
    size_t count_all_members() const;
    size_t count_members(const std::string& group_id) const;

    /// Well-known root group ID.
    static constexpr const char* kRootGroupId = "000000000000";

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_; // protects db_ access (G3-ARCH-003)
    // Reports whether RBAC enforcement is globally enabled (see
    // set_rbac_enabled_probe). Read by get_visible_agents to choose between the
    // role-scoped inner join (RBAC on / probe unset) and the full enrolled set
    // (RBAC off). Set once at startup before any request, so the unsynchronised
    // read in get_visible_agents races nothing.
    std::function<bool()> rbac_enabled_probe_;

    void create_tables();
    std::string generate_id() const;
    // Full enrolled set: every agent that is a member of any management group.
    // Every agent is auto-added to the root group at enrollment, so this is the
    // RBAC-disabled "visible to the legacy-admin superuser" set (#1453).
    std::vector<std::string> all_member_agents() const;
};

} // namespace yuzu::server
