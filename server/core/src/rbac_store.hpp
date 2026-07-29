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
    std::string principal_type; // "user", "group", or "engine" (PR 4.2, design §4.1)
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

/// Membership counts changed by a `reconcile_idp_memberships` call — how many
/// asserted memberships were newly ADDED and how many stale memberships were
/// REMOVED. Both are 0 for a no-op reconcile (the asserted set exactly
/// matched what was already on record), which callers use to skip writing a
/// provisioning audit row for a login that changed nothing. #1832 hardening.
struct ReconcileResult {
    size_t added{0};
    size_t removed{0};
};

/// Discriminated result of `RbacStore::authorize_list_read` — the ADR-0017
/// admit-then-filter list gate for per-agent list/fan-out reads.
enum class ListReadDecision {
    DenyAll,     ///< no grant anywhere — 403 (REST) / empty (dashboard)
    AdmitAll,    ///< global grant, or RBAC loaded-and-disabled → unfiltered read
    AdmitScoped, ///< management-group-confined — read ONLY `visible_agents`
};

struct ListReadAuthorization {
    ListReadDecision decision{ListReadDecision::DenyAll}; ///< fail-closed default (INV-1)
    /// Populated ONLY for `AdmitScoped`; the management-group-visible agent set
    /// (possibly empty ⇒ zero rows, INV-2). Left empty for Deny/AdmitAll.
    std::vector<std::string> visible_agents;
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

    /// Authoritative variant of `get_role_permissions` (ADR-0012 read
    /// posture) for bulk-read consumers — e.g. the periodic-access-review
    /// export (`access_review_model.cpp`) — that must distinguish "this role
    /// genuinely grants no permissions" from "the query failed". A bare
    /// vector conflates the two; `unexpected(msg)` here is a closed store,
    /// prepare failure, or a step that terminated on anything other than
    /// `SQLITE_DONE`. A value (possibly empty) is a genuine, fully-read
    /// result.
    std::expected<std::vector<Permission>, std::string>
    get_role_permissions_checked(const std::string& role_name) const;

    /// Bulk variant of `get_role_permissions_checked` — every row in
    /// `role_permissions`, for every role, in ONE query. Added for the
    /// grant-table-driven periodic-access-review export
    /// (`access_review_model.cpp`, governance UP-1): the export memoizes this
    /// single read into a `role_name -> permission set` map once, rather than
    /// re-querying per role per principal (the N×M fan-out the prior
    /// per-principal-type walk incurred). Same fail-closed posture as the
    /// other `_checked` accessors: `unexpected(msg)` on a closed store,
    /// prepare failure, or a step that terminated on anything other than
    /// `SQLITE_DONE`; a value (possibly empty) is a genuine, fully-read
    /// result.
    std::expected<std::vector<Permission>, std::string>
    list_all_role_permissions_checked() const;

    std::expected<void, std::string> set_permission(const Permission& perm);
    std::expected<void, std::string> remove_permission(const std::string& role_name,
                                                       const std::string& securable_type,
                                                       const std::string& operation);

    // ── Principal-role assignments ────────────────────────────────────────
    std::vector<PrincipalRole> get_principal_roles(const std::string& principal_type,
                                                   const std::string& principal_id) const;

    /// Authoritative variant of `get_principal_roles` — same posture as
    /// `get_role_permissions_checked` above. `unexpected(msg)` is a closed
    /// store or a mid-scan SQLite error; a value (possibly empty) is a
    /// genuine, fully-read result (the principal really has no role grants).
    std::expected<std::vector<PrincipalRole>, std::string>
    get_principal_roles_checked(const std::string& principal_type,
                                const std::string& principal_id) const;

    /// Bulk variant of `get_principal_roles_checked` — EVERY `(principal_type,
    /// principal_id, role_name)` grant row on record, across all three
    /// principal types, in ONE query. This is the authoritative set: the
    /// grant table, not any roster (`users`/`groups`/engine-principal list),
    /// is the source of truth for "who currently holds a role" — a roster
    /// walk can silently miss a since-deleted user, a stale IdP-provisioned
    /// row, or an OIDC/SSO principal (`oidc:<iss>#<sub>`) that was never
    /// materialized into a roster. Added for the grant-table-driven
    /// periodic-access-review export (`access_review_model.cpp`, governance
    /// UP-1), which pivots to this call as its spine instead of walking the
    /// rosters and asking RBAC per member. Same fail-closed posture as the
    /// other `_checked` accessors: `unexpected(msg)` on a closed store,
    /// prepare failure, or a step that terminated on anything other than
    /// `SQLITE_DONE`; a value (possibly empty) is a genuine, fully-read
    /// result (no grants exist at all).
    std::expected<std::vector<PrincipalRole>, std::string>
    list_all_principal_roles_checked() const;

    std::vector<PrincipalRole> get_role_members(const std::string& role_name) const;

    /// Shared assignment guard called by BOTH `RbacStore::assign_role` AND
    /// `ManagementGroupStore::assign_role` (which includes this header to
    /// reach it) — a single chokepoint per design §4.2 "no admin, ever" so a
    /// future assignment call site can never re-derive its own, possibly
    /// looser, copy. Deliberately static/DB-independent (name-based, not an
    /// `is_system` lookup): `ManagementGroupStore` has no RbacStore
    /// connection to query the `roles` table against.
    ///
    /// - Any `principal_type` other than `"engine"` is a no-op pass —
    ///   existing user/group assignment behavior is completely unchanged.
    /// - `principal_type == "engine"` REQUIRES `principal_id` to carry the
    ///   reserved `"engine:<slug>"` namespace (§3.3); anything else is
    ///   rejected as a malformed engine assignment.
    /// - `principal_type == "engine"` REJECTS `role_name` naming a built-in
    ///   full-access role ("Administrator" — RBAC's legacy-admin-equivalent
    ///   system role — or the literal "admin"). See the `.cpp`
    ///   `kEngineDisallowedRoles` doc for the full rationale, including why
    ///   elevation eligibility needs no entry here.
    static std::expected<void, std::string> validate_assignment(const std::string& principal_type,
                                                                 const std::string& principal_id,
                                                                 const std::string& role_name);

    std::expected<void, std::string> assign_role(const PrincipalRole& pr);
    std::expected<void, std::string> unassign_role(const std::string& principal_type,
                                                   const std::string& principal_id,
                                                   const std::string& role_name);

    // ── Groups CRUD (minimal — for future AD/Entra) ──────────────────────
    std::vector<RbacGroup> list_groups() const;

    /// Authoritative variant of `list_groups` — same posture as
    /// `get_role_permissions_checked` above. `unexpected(msg)` is a closed
    /// store, prepare failure, or a step that terminated on anything other
    /// than `SQLITE_DONE`; a value (possibly empty) is a genuine, fully-read
    /// result (no groups exist yet). Added for the periodic-access-review
    /// export (`access_review_model.cpp`), which must never export a
    /// partial grant set as if it were complete.
    std::expected<std::vector<RbacGroup>, std::string> list_groups_checked() const;

    /// Rejects a `source=="local"` create whose `name` collides with a reserved
    /// IdP or engine-principal namespace prefix (`local:`/`entra:`/`saml:`/
    /// `ad:`/`engine:`) — see `namespaced_group_name` below. An IdP-sourced
    /// create (any other `source`) is exempt: `reconcile_idp_memberships`
    /// writes IdP groups directly (not via this method) and always passes a
    /// namespaced name, but the exemption also covers any future caller that
    /// legitimately creates an IdP-sourced group through this API. #1832;
    /// `engine:` reservation is design §3.3 / PR 4.2.
    std::expected<void, std::string> create_group(const RbacGroup& group);
    std::expected<void, std::string> delete_group(const std::string& name);

    /// Read-only prefix scan over LOCALLY-sourced group names — backs the T8
    /// startup collision-scan preflight (decision log #3: "The PR 4.2
    /// migration itself scans for pre-existing colliding names rather than
    /// allowing silent coexistence"). `prefix` must be a code-controlled
    /// literal (e.g. `"engine:"`) — see the `.cpp` for the LIKE-metacharacter
    /// fail-closed guard.
    ///
    /// G3 (governance hardening, UP-2): returns `std::nullopt` on a scan
    /// error (statement prepare failure, or `sqlite3_step` terminating on
    /// anything other than `SQLITE_DONE`) so a mid-scan SQLite error can
    /// never be misread as "no collisions found" by the boot preflight — an
    /// empty-but-`has_value()` result means the scan genuinely completed and
    /// found nothing. Callers MUST treat `nullopt` as fail-closed.
    std::optional<std::vector<std::string>>
    find_local_groups_with_prefix(const std::string& prefix) const;
    std::vector<std::string> get_group_members(const std::string& group_name) const;
    std::expected<void, std::string> add_group_member(const std::string& group_name,
                                                      const std::string& username);
    std::expected<void, std::string> remove_group_member(const std::string& group_name,
                                                         const std::string& username);

    /// Upper bound on the number of IdP-asserted groups reconciled for a single
    /// login. Defends `reconcile_idp_memberships` against a malicious/compromised
    /// IdP response (or claims-inflation bug) turning one login into an
    /// unbounded write storm. #1832.
    static constexpr size_t kMaxIdpGroupsPerLogin = 200;

    /// Reconcile the IdP-asserted group memberships for `username` under
    /// `source` ("entra"/"saml"/"ad" — never "local"/empty, rejected below)
    /// against what `group_members` currently records for that (user,
    /// source) pair.
    ///
    /// In one transaction:
    ///   1. Skips any asserted entry whose `external_id` is empty/whitespace-
    ///      only or longer than 512 bytes (defends against a malformed/hostile
    ///      assertion seeding a garbage group; #1832 hardening UP-9).
    ///   2. For each remaining `{external_id, display}`: upserts a namespaced
    ///      group (`namespaced_group_name(source, id)`, `INSERT OR IGNORE` so
    ///      a pre-existing row's `source`/description is never overwritten),
    ///      then — ONLY if that group row's `source` matches this call's
    ///      `source` — upserts the membership row. A namespaced name that
    ///      collides with a PRE-EXISTING row of a DIFFERENT source (e.g. a
    ///      local group literally named `entra:<gid>`, created before the
    ///      `create_group` reserved-prefix guard existed) is never joined —
    ///      that would leak the local group's already-granted roles to the
    ///      IdP-authenticated user (#1832 hardening sec-L1).
    ///   3. Deletes any of the user's memberships in a `source`-owned group
    ///      that was NOT in the (filtered) asserted set — this is what makes
    ///      IdP-group removal (deprovisioning) take effect on next login
    ///      instead of accumulating stale grants forever.
    /// Local memberships (`groups.source == 'local'`) are never touched: the
    /// stale-membership DELETE is scoped to `groups.source = ?` (the caller's
    /// `source`), so a user's local group memberships survive every IdP login.
    ///
    /// Returns `unexpected("group_count_exceeded")` WITHOUT mutating anything
    /// if `asserted.size() > kMaxIdpGroupsPerLogin`, and
    /// `unexpected("invalid source: ...")` WITHOUT mutating anything if
    /// `source` is empty or `"local"` — the source-scoped stale-membership
    /// DELETE is only safe for IdP sources; a miswired caller passing
    /// `"local"` would mass-delete every local group membership fleet-wide
    /// (#1832 hardening UP-6). Callers (the OIDC/SAML callback handlers) MUST
    /// treat any `unexpected` result as fail-closed: deny the login rather
    /// than mint a session with unreconciled/stale roles. On success, returns
    /// the `{added, removed}` membership counts so a no-op login (nothing
    /// added or removed) can skip writing a provisioning audit row. #1832.
    std::expected<ReconcileResult, std::string>
    reconcile_idp_memberships(const std::string& username, const std::string& source,
                              const std::vector<std::pair<std::string, std::string>>& asserted);

    // ── Authorization check ──────────────────────────────────────────────
    bool check_permission(const std::string& username, const std::string& securable_type,
                          const std::string& operation) const;

    /// Scoped permission check: first tries global, then checks group-scoped roles.
    bool check_scoped_permission(const std::string& username, const std::string& securable_type,
                                 const std::string& operation, const std::string& agent_id,
                                 const ManagementGroupStore* mgmt_store) const;

    // ── ADR-0017 admit-then-filter list gate ─────────────────────────────
    /// The single chokepoint for list/fan-out reads of per-agent data under
    /// management-group confinement (ADR-0017; resolves #1714 World A). Returns
    /// a discriminated decision the transport wrappers (`require_list_read` and
    /// its MCP/dashboard twins) render into 403 / unfiltered read / scoped read:
    ///   * `AdmitAll`  — the caller holds `<securable>:<op>` globally, OR RBAC
    ///     enforcement is loaded-and-explicitly-disabled (legacy-open); read the
    ///     whole fleet, no per-agent filter.
    ///   * `AdmitScoped(visible_agents)` — a management-group-confined caller;
    ///     read ONLY `visible_agents` (empty set ⇒ zero rows, INV-2).
    ///   * `DenyAll` — no grant anywhere; 403 (REST) / empty (dashboard).
    /// FAIL-CLOSED (INV-1/INV-5): any `rbac.db`/mgmt-store error, `!is_open()`,
    /// or unresolvable scope yields `DenyAll`, never `AdmitAll`. Keys on
    /// `rbac_enforcement_in_effect()`. #1715 combining lattice: a global ALLOW
    /// overrides a group deny (→ `AdmitAll`); a global DENY does NOT override a
    /// group allow (additive) — deny-overrides applies only within a group's own
    /// assignments. This is the ONE resolver that `check_scoped_permission`,
    /// `holds_permission_via_any_group`, and `visible_agents_for_permission` all
    /// share (INV-7), pinned by a cross-check test.
    ListReadAuthorization authorize_list_read(const std::string& username,
                                              const std::string& securable_type,
                                              const std::string& operation,
                                              const ManagementGroupStore* mgmt_store) const;

    /// "Does this user hold `<securable>:<op>` via ANY management group?" — the
    /// list-admit computation (ADR-0017), for a gate with no single `agent_id`
    /// to pass to `check_scoped_permission`. True iff the user has at least one
    /// group ALLOW assignment for the permission (a global grant is handled
    /// separately by `authorize_list_read`'s `AdmitAll`). Fail-closed: false on
    /// any store error.
    bool holds_permission_via_any_group(const std::string& username,
                                        const std::string& securable_type,
                                        const std::string& operation,
                                        const ManagementGroupStore* mgmt_store) const;

    /// The permission-specific visible set (ADR-0017 INV-4, descendant-ward):
    /// every agent the confined `username` may see for `<securable>:<op>`. The
    /// INV-7 set-equivalence invariant (pinned by a property test):
    ///   `visible_agents_for_permission(u,s,o) == { a : check_scoped_permission(u,s,o,a) }`
    /// for a non-global caller. Computed batched as
    /// `members(allow-groups ∪ descendants) \ members(deny-groups ∪ descendants)`.
    /// Fail-closed (INV-1/INV-5): `unexpected(msg)` on any store error, so a
    /// partial read never over-discloses (an unseen deny would).
    std::expected<std::vector<std::string>, std::string>
    visible_agents_for_permission(const std::string& username, const std::string& securable_type,
                                  const std::string& operation,
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

    /// Collect all role names for a principal (direct user grant + via group
    /// membership + PR 4.2 direct engine-principal grant, §4.1). `username`
    /// is also the identity key for an `engine:`-prefixed caller — the
    /// namespace reservation (§3.3) is what keeps the three UNION arms from
    /// ever colliding. Caller must hold at least a shared lock on mtx_.
    std::vector<std::string> collect_roles_locked(const std::string& username) const;

    // ── ADR-0017 shared list-gate resolver (INV-7) ───────────────────────
    /// {groups where the user holds an ALLOW for (sec,op)} and {groups where a
    /// DENY}. The ONE shared classification behind `check_scoped_permission`,
    /// `holds_permission_via_any_group`, `visible_agents_for_permission`, and
    /// `authorize_list_read` (INV-7). Fail-closed: `unexpected(msg)` on any
    /// store error, so a read failure denies rather than silently dropping a
    /// deny (→ over-disclosure).
    struct PermGroups {
        std::vector<std::string> allow_groups;
        std::vector<std::string> deny_groups;
    };
    std::expected<PermGroups, std::string> resolve_perm_groups(
        const std::string& username, const std::string& securable_type,
        const std::string& operation, const ManagementGroupStore* mgmt_store) const;

    /// `members(allow ∪ descendants) \ members(deny ∪ descendants)`, sorted +
    /// deduped. Fail-closed: propagates any subtree-read error.
    std::expected<std::vector<std::string>, std::string>
    expand_visible_set(const PermGroups& pg, const ManagementGroupStore* mgmt_store) const;

    /// The user's RBAC group names (`group_members`), error-propagating so a
    /// read failure fails the whole resolution closed (INV-5).
    std::expected<std::vector<std::string>, std::string>
    user_rbac_group_names(const std::string& username) const;

    /// Deny-wins (sec,op) verdict per role, from ONE targeted query
    /// (`WHERE securable_type=? AND operation=?`) rather than materializing the
    /// whole `role_permissions` table client-side — the ADR-0017 perf-F5 hot-path
    /// fix (resolve_perm_groups runs per-agent in fleet-list loops). Map values:
    /// -1 deny (wins), 1 allow, 0 none. Fail-closed: unexpected on store error.
    std::expected<std::unordered_map<std::string, int>, std::string>
    role_effects_for(const std::string& securable_type, const std::string& operation) const;

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

/// Visibility policy for device-listing call sites (e.g. the TAR fleet scan via
/// ManagementGroupStore::get_visible_agents) that fall back to the full enrolled
/// fleet when RBAC enforcement is OFF.
///
/// Returns true when RBAC enforcement is IN EFFECT — the caller must use its
/// role-scoped path, which fails closed (an unroled caller sees nothing).
/// Returns false only to PERMIT the full-fleet fallback, and only for a store
/// that is loaded AND explicitly disabled (`is_open() && !is_rbac_enabled()`).
///
/// #1498 — a null `store`, or one that failed to load (open/migration failure
/// leaves `db_` null, so `is_open()` is false while the default-false enabled
/// flag would otherwise be indistinguishable from an intentional disable),
/// returns true and so fails CLOSED. A corrupt rbac.db can never widen
/// fleet-scan visibility to the whole fleet.
[[nodiscard]] bool rbac_enforcement_in_effect(const RbacStore* store) noexcept;

/// Build the `groups.name` used for an IdP-sourced group: `source:external_id`
/// (e.g. `entra:8f3c...`). `source == "local"` groups are NOT namespaced —
/// this returns `external_id` unchanged in that case (matches how local
/// groups are created directly by name, with no `external_id` concept).
///
/// This is the confused-deputy fix for #1832: an operator-created local group
/// named e.g. "admins" and an IdP group asserting the same raw id "admins" are
/// two DIFFERENT rows (`admins` vs `entra:admins`) once every IdP membership
/// write goes through this helper, so a same-named IdP group can never assume
/// a local group's already-granted roles (or vice versa).
[[nodiscard]] std::string namespaced_group_name(const std::string& source,
                                                const std::string& external_id);

} // namespace yuzu::server
