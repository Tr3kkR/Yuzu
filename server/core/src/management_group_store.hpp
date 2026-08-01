#pragma once

/// @file management_group_store.hpp
/// Management-group CONFINEMENT hierarchy — group definitions (static +
/// dynamic scope-expression), the parent/child tree, group membership
/// (agents), and group→role assignments. Born on SQLite
/// (`management-groups.db`), migrated to PostgreSQL (ADR-0006/0007/0008/0009/
/// 0012, schema `management_group_store`; migration ADR-0042).
///
/// This is the CONFINEMENT SUBSTRATE — RbacStore's `authorize_list_read`
/// (ADR-0017 World A) and `resolve_perm_groups`/`check_scoped_permission`
/// resolve an operator's visible agent set through this store. A migration
/// defect here is a cross-management-group disclosure (a confinement bypass),
/// so the confinement-feeding reads are DEGRADE-DISTINGUISHABLE (ADR-0042):
/// they return `std::optional`/`std::expected` and yield `nullopt`/`unexpected`
/// on store-not-open / pool-acquire timeout / query error — NEVER a silent
/// empty. RbacStore consumes a degrade as `DenyAll` (fail-closed). The reason a
/// silent empty is unacceptable: a DENY-set read (`get_member_agents_in_subtrees`
/// on the deny groups) degrading to empty denies nothing, so the operator sees
/// MORE than their confinement allows — a fail-OPEN over-disclosure. Reporting
/// the degrade lets the caller fail closed instead.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement
/// (`management_group_store.management_groups`). No `sqlite3_changes()` (#1033)
/// — mutators use `RETURNING` / `PQcmdTuples`.

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

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
    std::string principal_type; // "user", "group", or "engine" (PR 4.2, design §4.1)
    std::string principal_id;
    std::string role_name;
};

class ManagementGroupStore {
public:
    /// Borrows the shared pool and runs the `management_group_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was empty
    /// or the migration failed — construction FAIL-CLOSED (ADR-0007/0012 §1):
    /// the server sets `startup_failed_` and refuses to boot rather than serve
    /// a confinement substrate that cannot answer.
    explicit ManagementGroupStore(pg::PgPool& pool);
    ~ManagementGroupStore();

    ManagementGroupStore(const ManagementGroupStore&) = delete;
    ManagementGroupStore& operator=(const ManagementGroupStore&) = delete;
    // Non-movable: borrows PgPool& and owns atomics/probe. Already immovable
    // (deleted copy suppresses implicit moves); explicit to document intent.
    ManagementGroupStore(ManagementGroupStore&&) = delete;
    ManagementGroupStore& operator=(ManagementGroupStore&&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire the Prometheus registry for the read-degrade + backfill counters.
    /// Optional; a null registry makes the counters no-ops.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// MANDATORY one-time backfill (ADR-0009/0042) from the legacy
    /// `management-groups.db`: groups + members + role assignments. Idempotent
    /// (durable marker), resumable, row-count reconciled, fail-CLOSED; the
    /// legacy file is moved aside after a verified backfill. Management-group
    /// config is irreducible operator intent (confinement scope) that cannot be
    /// re-derived — a silent drop is a fail-open. Returns false on any failure
    /// (the server then refuses to boot).
    [[nodiscard]] bool migrate_from_sqlite(const std::filesystem::path& legacy_db_path);

    // ── Group CRUD (deny-or-benign display class — may stay plain) ───────────
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

    /// CONFINEMENT read (ADR-0042): the management groups an agent belongs to.
    /// Feeds `RbacStore::check_scoped_permission`'s reachable-set build. Returns
    /// `nullopt` on store-not-open / pool-acquire timeout / query error so the
    /// caller fails closed (a silent empty would drop the agent's reachable
    /// groups and mis-decide the scoped check).
    [[nodiscard]] std::optional<std::vector<std::string>> get_agent_groups(const std::string& agent_id) const;

    /// Replace dynamic membership for a group (used after scope expression evaluation).
    void refresh_dynamic_membership(const std::string& group_id,
                                    const std::vector<std::string>& matching_agent_ids);

    // ── Hierarchy (CONFINEMENT reads, ADR-0042) ──────────────────────────
    /// Ancestor-ward walk (parent, grandparent, …), bounded recursive CTE with
    /// a depth cap so a corrupt parent cycle TERMINATES (does not spin) and the
    /// outer `DISTINCT` drops phantom cycle IDs. `nullopt` on degrade →
    /// fail-closed at the caller.
    [[nodiscard]] std::optional<std::vector<std::string>> get_ancestor_ids(const std::string& group_id) const;
    /// Descendant-ward walk, same bounded/cycle-safe recursive CTE. `nullopt`
    /// on degrade.
    [[nodiscard]] std::optional<std::vector<std::string>> get_descendant_ids(const std::string& group_id) const;

    // ── Group-scoped role assignments ────────────────────────────────────
    std::expected<void, std::string> assign_role(const GroupRoleAssignment& assignment);
    std::expected<void, std::string> unassign_role(const std::string& group_id,
                                                   const std::string& principal_type,
                                                   const std::string& principal_id,
                                                   const std::string& role_name);
    std::vector<GroupRoleAssignment> get_group_roles(const std::string& group_id) const;

    /// Batched (ADR-0017 INV-10) role assignments applicable to a principal:
    /// every `GroupRoleAssignment` whose principal is the user directly
    /// (`principal_type='user' AND principal_id=user`) OR one of the user's
    /// RBAC groups (`principal_type='group' AND principal_id IN rbac_groups`).
    /// Fail-closed (ADR-0017 INV-1/INV-5): `unexpected(msg)` on a closed store,
    /// pool-acquire timeout, or a query error, so a read failure denies rather
    /// than silently narrowing to nothing — which, for a principal carrying a
    /// DENY assignment, would fail OPEN (an unseen deny → an un-suppressed
    /// agent). A value (possibly empty) is a genuine, fully-read result.
    [[nodiscard]] std::expected<std::vector<GroupRoleAssignment>, std::string>
    get_assignments_for_principal(const std::string& user,
                                  const std::vector<std::string>& rbac_groups) const;

    /// Distinct member agent_ids of `seed_groups` AND every descendant group,
    /// resolved in ONE recursive-CTE query (ADR-0017 INV-4 descendant-ward,
    /// INV-10 batched). A role grant on a group applies downward to its
    /// descendants, so the visible/denied agent set for a set of perm-holding
    /// groups is the union of their subtrees' members. Fail-closed
    /// (INV-1/INV-5): `unexpected(msg)` on any failure, so a partial walk can
    /// never under-compute a DENY set (which would over-disclose). Empty
    /// `seed_groups` yields an empty result without a query.
    [[nodiscard]] std::expected<std::vector<std::string>, std::string>
    get_member_agents_in_subtrees(const std::vector<std::string>& seed_groups) const;

    /// Which agents can a user see based on group-scoped role assignments?
    /// CONFINEMENT read (ADR-0042): `nullopt` on degrade → the caller shows no
    /// agents (fail-closed).
    ///
    /// PRECONDITION: the caller must have already authenticated the session.
    /// When RBAC enforcement is globally DISABLED (probe reports off), returns
    /// the full enrolled set for ANY username (#1453 — the legacy-admin
    /// superuser posture). When the probe is UNSET or reports RBAC ENABLED, the
    /// exact role-scoped semantics are preserved (the fallback can never widen
    /// visibility while RBAC is on).
    [[nodiscard]] std::optional<std::vector<std::string>> get_visible_agents(const std::string& username) const;

    /// Inject a predicate reporting whether RBAC enforcement is globally
    /// enabled, wired once at startup. If never set, `get_visible_agents` fails
    /// CLOSED — role-scoped inner join only.
    void set_rbac_enabled_probe(std::function<bool()> probe);

    // ── Counting (for metrics / UI — benign display class) ────────────────
    size_t count_groups() const;
    size_t count_all_members() const;
    size_t count_members(const std::string& group_id) const;

    /// Well-known root group ID.
    static constexpr const char* kRootGroupId = "000000000000";

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
    // Reports whether RBAC enforcement is globally enabled (see
    // set_rbac_enabled_probe). Set once at startup before any request.
    std::function<bool()> rbac_enabled_probe_;

    std::string generate_id() const;
    // Full enrolled set: every agent that is a member of any management group.
    // CONFINEMENT read — `nullopt` on degrade (propagated by get_visible_agents).
    std::optional<std::vector<std::string>> all_member_agents() const;
};

} // namespace yuzu::server
