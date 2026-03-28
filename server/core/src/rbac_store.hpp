#pragma once

#include <sqlite3.h>

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

class ManagementGroupStore; // forward declaration

struct RbacRole {
    std::string name;
    std::string description;
    bool is_system{false};
    int64_t created_at{0};
};

struct Permission {
    std::string role_name;
    std::string securable_type;
    std::string operation;
    std::string effect; // "allow" or "deny"
};

struct PrincipalRole {
    std::string principal_type; // "user" or "group"
    std::string principal_id;
    std::string role_name;
};

struct RbacGroup {
    std::string name;
    std::string description;
    std::string source; // "local", "ad", "entra"
    std::string external_id;
    int64_t created_at{0};
};

class RbacStore {
public:
    explicit RbacStore(const std::filesystem::path& db_path);
    ~RbacStore();

    RbacStore(const RbacStore&) = delete;
    RbacStore& operator=(const RbacStore&) = delete;

    bool is_open() const;

    // ── Global toggle ────────────────────────────────────────────────────
    bool is_rbac_enabled() const;
    void set_rbac_enabled(bool enabled);

    // ── Roles CRUD ───────────────────────────────────────────────────────
    std::vector<RbacRole> list_roles() const;
    std::optional<RbacRole> get_role(const std::string& name) const;
    std::expected<void, std::string> create_role(const RbacRole& role);
    std::expected<void, std::string> update_role(const std::string& name,
                                                 const std::string& description);
    std::expected<void, std::string> delete_role(const std::string& name);

    // ── Permissions CRUD ─────────────────────────────────────────────────
    std::vector<Permission> get_role_permissions(const std::string& role_name) const;
    std::expected<void, std::string> set_permission(const Permission& perm);
    std::expected<void, std::string> remove_permission(const std::string& role_name,
                                                       const std::string& securable_type,
                                                       const std::string& operation);

    // ── Principal-role assignments ────────────────────────────────────────
    std::vector<PrincipalRole> get_principal_roles(const std::string& principal_type,
                                                   const std::string& principal_id) const;
    std::vector<PrincipalRole> get_role_members(const std::string& role_name) const;
    std::expected<void, std::string> assign_role(const PrincipalRole& pr);
    std::expected<void, std::string> unassign_role(const std::string& principal_type,
                                                   const std::string& principal_id,
                                                   const std::string& role_name);

    // ── Groups CRUD (minimal — for future AD/Entra) ──────────────────────
    std::vector<RbacGroup> list_groups() const;
    std::expected<void, std::string> create_group(const RbacGroup& group);
    std::expected<void, std::string> delete_group(const std::string& name);
    std::vector<std::string> get_group_members(const std::string& group_name) const;
    std::expected<void, std::string> add_group_member(const std::string& group_name,
                                                      const std::string& username);
    std::expected<void, std::string> remove_group_member(const std::string& group_name,
                                                         const std::string& username);

    // ── Authorization check ──────────────────────────────────────────────
    bool check_permission(const std::string& username, const std::string& securable_type,
                          const std::string& operation) const;

    /// Scoped permission check: first tries global, then checks group-scoped roles.
    bool check_scoped_permission(const std::string& username, const std::string& securable_type,
                                 const std::string& operation, const std::string& agent_id,
                                 const ManagementGroupStore* mgmt_store) const;

    /// Check if a specific role grants a permission (for service-scoped token validation).
    bool check_role_has_permission(const std::string& role_name, const std::string& securable_type,
                                   const std::string& operation) const;

    /// All effective permissions for a user (for UI display).
    std::vector<Permission> get_effective_permissions(const std::string& username) const;

    // ── Reference data ───────────────────────────────────────────────────
    std::vector<std::string> list_securable_types() const;
    std::vector<std::string> list_operations() const;

private:
    sqlite3* db_{nullptr};
    mutable std::atomic<bool> rbac_enabled_{false};
    mutable std::shared_mutex mtx_;

    void create_tables();
    void seed_defaults();
    void load_enabled_flag();

    /// Collect all role names for a user (direct + via group membership).
    /// Caller must hold at least a shared lock on mtx_.
    std::vector<std::string> collect_roles_locked(const std::string& username) const;

    // Permission cache (G3-PERF-004): avoids 2+ SQL queries per REST request.
    // Invalidated by incrementing cache_generation_ on any permission/role mutation.
    mutable std::mutex cache_mtx_;
    mutable std::unordered_map<std::string, bool> perm_cache_; // "user:type:op" -> allow/deny
    mutable uint64_t cache_generation_{0};
    uint64_t write_generation_{0}; // bumped on mutations; cache cleared when mismatch

    void invalidate_perm_cache();
    std::string perm_cache_key(const std::string& user, const std::string& type,
                               const std::string& op) const;
};

} // namespace yuzu::server
