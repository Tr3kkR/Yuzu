#pragma once

/// @file rbac_store.hpp
/// Authorization substrate — role definitions, role→permission grants,
/// principal→role assignments, RBAC groups + membership, and the global
/// `rbac_enabled` flag. Born on SQLite (`rbac.db`), migrated to PostgreSQL
/// (ADR-0006/0007/0008/0009/0012, schema `rbac_store`; migration ADR-0041).
/// The LARGEST and highest-blast-radius store on the ladder: a migration
/// defect here is a FLEET-WIDE authorization failure.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement
/// (`rbac_store.roles`). No `sqlite3_changes()` (#1033) — mutators use
/// `RETURNING` / `PQcmdTuples`.
///
/// Failure posture (ADR-0041), the load-bearing invariant:
///  - **Authz reads FAIL CLOSED.** `check_permission` /
///    `check_scoped_permission` / `holds_permission_via_any_group` /
///    `check_role_has_permission` keep their `bool`/DENY-on-error contract: a
///    store-not-open, pool-acquire timeout, or query error returns `false`
///    (deny), NEVER `true`. The list/scope reads return the empty /
///    most-restrictive result on degrade. Callers that must distinguish
///    "denied" from "store degraded" (403 vs 503) use the `_checked`
///    (`std::expected`) accessors — the plain `bool`/vector paths stay
///    deny-on-error so no chokepoint can regress to fail-open.
///  - **Permission cache → shared durable generation token.** The
///    process-local `write_generation_` becomes a durable
///    `rbac_meta.write_generation` counter bumped IN THE SAME TXN as every
///    mutation. Each replica keeps its in-process `perm_cache_` but validates
///    it against the durable generation, refreshed at most once per
///    `kRbacGenerationRefreshMs`; on a generation change (a mutation on ANY
///    replica) or on ANY generation-read error it clears the cache (fail
///    toward "assume changed", never extend trust). Bounds cross-replica
///    stale-allow to the refresh interval.
///  - **Backfill: MANDATORY (ADR-0009/0041).** RBAC state is irreducible
///    operator intent (custom roles, every grant, groups, membership) that
///    cannot be re-derived — `migrate_from_sqlite` seeds defaults then
///    backfills operator rows (`ON CONFLICT DO NOTHING`), idempotent /
///    resumable / row-count reconciled, and boot FAILS CLOSED on failure. The
///    `rbac_enabled` flag is migrated FIRST and read-back-verified — losing it
///    silently reverts the fleet to RBAC-off (catastrophic fail-open).

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

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
    /// Borrows the shared pool and runs the `rbac_store` schema migration on a
    /// pinned lease, then seeds defaults + loads the durable enabled flag.
    /// `is_open()` is false if the lease was empty or the migration failed
    /// (fail-closed — every authz read then DENIES, the right posture for the
    /// authorization substrate).
    explicit RbacStore(pg::PgPool& pool);
    ~RbacStore();

    RbacStore(const RbacStore&) = delete;
    RbacStore& operator=(const RbacStore&) = delete;
    RbacStore(RbacStore&&) = delete;
    RbacStore& operator=(RbacStore&&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for `yuzu_server_rbac_read_degrade_total{reason}`
    /// and the backfill counter. Set ONCE during single-threaded startup before
    /// serving; read without synchronisation on serving threads. Null (the
    /// default, e.g. unit tests) disables emission; every emit site is guarded.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// MANDATORY backfill (ADR-0009/0041). On first boot against an empty
    /// `rbac_store` with a legacy `rbac.db` present, migrates the `rbac_enabled`
    /// flag FIRST (read-back-verified — losing it is catastrophic fail-open),
    /// then backfills custom roles / role_permissions / principal_roles /
    /// groups / group_members via `ON CONFLICT DO NOTHING`, reconciles row
    /// counts, and stamps a one-time marker. Returns TRUE on success or when
    /// already complete; FALSE on any failure — the caller MUST refuse boot
    /// (fail-closed). The verified-migrated legacy file is moved aside.
    [[nodiscard]] bool migrate_from_sqlite(const std::filesystem::path& legacy_db_path);

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
    /// genuinely grants no permissions" from "the store degraded". A bare
    /// vector conflates the two; `unexpected(msg)` here is a closed store,
    /// pool-acquire timeout, or a query error. A value (possibly empty) is a
    /// genuine, fully-read result.
    std::expected<std::vector<Permission>, std::string>
    get_role_permissions_checked(const std::string& role_name) const;

    /// Bulk variant of `get_role_permissions_checked` — every row in
    /// `role_permissions`, for every role, in ONE query. Same fail-closed
    /// posture as the other `_checked` accessors.
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
    /// `get_role_permissions_checked`.
    std::expected<std::vector<PrincipalRole>, std::string>
    get_principal_roles_checked(const std::string& principal_type,
                                const std::string& principal_id) const;

    /// Bulk variant of `get_principal_roles_checked` — EVERY `(principal_type,
    /// principal_id, role_name)` grant row on record, across all three
    /// principal types, in ONE query. This is the authoritative set: the grant
    /// table, not any roster, is the source of truth for "who currently holds
    /// a role". Same fail-closed posture as the other `_checked` accessors.
    std::expected<std::vector<PrincipalRole>, std::string>
    list_all_principal_roles_checked() const;

    std::vector<PrincipalRole> get_role_members(const std::string& role_name) const;

    /// Shared assignment guard called by BOTH `RbacStore::assign_role` AND
    /// `ManagementGroupStore::assign_role` — a single chokepoint per design
    /// §4.2 "no admin, ever" so a future assignment call site can never
    /// re-derive its own, possibly looser, copy. Deliberately static/
    /// DB-independent (name-based, not an `is_system` lookup).
    ///
    /// - Any `principal_type` other than `"engine"` is a no-op pass.
    /// - `principal_type == "engine"` REQUIRES `principal_id` to carry the
    ///   reserved `"engine:<slug>"` namespace (§3.3).
    /// - `principal_type == "engine"` REJECTS `role_name` naming a built-in
    ///   full-access role ("Administrator" or the literal "admin").
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
    /// `get_role_permissions_checked`. Added for the periodic-access-review
    /// export, which must never export a partial grant set as if complete.
    std::expected<std::vector<RbacGroup>, std::string> list_groups_checked() const;

    /// Rejects a `source=="local"` create whose `name` collides with a reserved
    /// IdP or engine-principal namespace prefix (`local:`/`entra:`/`saml:`/
    /// `ad:`/`engine:`). An IdP-sourced create (any other `source`) is exempt.
    std::expected<void, std::string> create_group(const RbacGroup& group);
    std::expected<void, std::string> delete_group(const std::string& name);

    /// Read-only prefix scan over LOCALLY-sourced group names — backs the T8
    /// startup collision-scan preflight. `prefix` must be a code-controlled
    /// literal (e.g. `"engine:"`).
    ///
    /// G3 (governance hardening, UP-2): returns `std::nullopt` on a scan error
    /// (store not open, pool-acquire timeout, or query error) so a scan failure
    /// can never be misread as "no collisions found" by the boot preflight — an
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
    /// IdP response turning one login into an unbounded write storm. #1832.
    static constexpr size_t kMaxIdpGroupsPerLogin = 200;

    /// Reconcile the IdP-asserted group memberships for `username` under
    /// `source` ("entra"/"saml"/"ad" — never "local"/empty) against what
    /// `group_members` currently records. See the .cpp for the full contract
    /// (#1832). Returns `unexpected` WITHOUT mutating on an over-cap or
    /// invalid-source call; callers MUST treat any `unexpected` as fail-closed.
    std::expected<ReconcileResult, std::string>
    reconcile_idp_memberships(const std::string& username, const std::string& source,
                              const std::vector<std::pair<std::string, std::string>>& asserted);

    // ── Authorization check ──────────────────────────────────────────────
    /// FAIL-CLOSED: false (deny) on store-not-open / pool timeout / query error.
    bool check_permission(const std::string& username, const std::string& securable_type,
                          const std::string& operation) const;

    /// Scoped permission check: first tries global, then checks group-scoped
    /// roles. FAIL-CLOSED: false on any store error.
    bool check_scoped_permission(const std::string& username, const std::string& securable_type,
                                 const std::string& operation, const std::string& agent_id,
                                 const ManagementGroupStore* mgmt_store) const;

    // ── ADR-0017 admit-then-filter list gate ─────────────────────────────
    /// The single chokepoint for list/fan-out reads of per-agent data under
    /// management-group confinement (ADR-0017). FAIL-CLOSED (INV-1/INV-5): any
    /// store/mgmt-store error, `!is_open()`, or unresolvable scope yields
    /// `DenyAll`, never `AdmitAll`.
    ListReadAuthorization authorize_list_read(const std::string& username,
                                              const std::string& securable_type,
                                              const std::string& operation,
                                              const ManagementGroupStore* mgmt_store) const;

    /// "Does this user hold `<securable>:<op>` via ANY management group?"
    /// FAIL-CLOSED: false on any store error.
    bool holds_permission_via_any_group(const std::string& username,
                                        const std::string& securable_type,
                                        const std::string& operation,
                                        const ManagementGroupStore* mgmt_store) const;

    /// The permission-specific visible set (ADR-0017 INV-4). FAIL-CLOSED
    /// (INV-1/INV-5): `unexpected(msg)` on any store error, so a partial read
    /// never over-discloses.
    std::expected<std::vector<std::string>, std::string>
    visible_agents_for_permission(const std::string& username, const std::string& securable_type,
                                  const std::string& operation,
                                  const ManagementGroupStore* mgmt_store) const;

    /// Check if a specific role grants a permission (for service-scoped token
    /// validation). FAIL-CLOSED: false on any store error.
    bool check_role_has_permission(const std::string& role_name, const std::string& securable_type,
                                   const std::string& operation) const;

    /// All effective permissions for a user (for UI display).
    std::vector<Permission> get_effective_permissions(const std::string& username) const;

    // ── Reference data ───────────────────────────────────────────────────
    std::vector<std::string> list_securable_types() const;
    std::vector<std::string> list_operations() const;

private:
    pg::PgPool& pool_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};

    // Durable-generation-validated view of the global enabled flag. The atomic
    // is the hot-path answer; `maybe_refresh_generation()` re-reads the durable
    // `rbac_meta.rbac_enabled` at most once per refresh interval and updates it
    // (never flips it to disabled on a read error — that would be fail-open).
    mutable std::atomic<bool> rbac_enabled_{false};

    void seed_defaults();     // idempotent (ON CONFLICT DO NOTHING)
    void load_enabled_flag(); // seed rbac_enabled_ from the durable row

    /// Collect all role names for a principal (direct user grant + via group
    /// membership + direct engine-principal grant, §4.1) using `conn`. Returns
    /// empty on a query error (fail-closed: an empty role set denies).
    std::vector<std::string> collect_roles(void* conn, const std::string& username) const;

    // ── ADR-0017 shared list-gate resolver (INV-7) ───────────────────────
    struct PermGroups {
        std::vector<std::string> allow_groups;
        std::vector<std::string> deny_groups;
    };
    std::expected<PermGroups, std::string> resolve_perm_groups(
        const std::string& username, const std::string& securable_type,
        const std::string& operation, const ManagementGroupStore* mgmt_store) const;

    std::expected<std::vector<std::string>, std::string>
    expand_visible_set(const PermGroups& pg, const ManagementGroupStore* mgmt_store) const;

    std::expected<std::vector<std::string>, std::string>
    user_rbac_group_names(const std::string& username) const;

    std::expected<std::unordered_map<std::string, int>, std::string>
    role_effects_for(const std::string& securable_type, const std::string& operation) const;

    // ── Permission cache — durable generation token (ADR-0041) ───────────
    mutable std::mutex cache_mtx_;
    mutable std::unordered_map<std::string, bool> perm_cache_; // "user:type:op" -> allow/deny
    mutable uint64_t cached_generation_{0};   // durable generation perm_cache_ is valid for
    mutable bool generation_valid_{false};    // false ⇒ assume-changed, do not trust cache
    mutable int64_t last_generation_refresh_ms_{0};

    /// At most once per `kRbacGenerationRefreshMs`, re-read the durable
    /// `write_generation` + `rbac_enabled` in ONE query; on a generation change
    /// clear `perm_cache_`; on ANY error clear the cache and mark it invalid
    /// (assume-changed — never extend trust). Leaves `rbac_enabled_` unchanged
    /// on a read error (never flips to disabled/fail-open).
    void maybe_refresh_generation() const;

    /// Apply a locally-committed durable generation: clear `perm_cache_`, set
    /// `cached_generation_`, mark valid, and re-anchor the refresh clock (the
    /// writing replica is immediately coherent with itself).
    void apply_local_generation(uint64_t new_gen) const;

    std::string perm_cache_key(const std::string& user, const std::string& type,
                               const std::string& op) const;
};

/// Visibility policy for device-listing call sites that fall back to the full
/// enrolled fleet when RBAC enforcement is OFF. Returns true when RBAC
/// enforcement is IN EFFECT (caller must use its role-scoped, fail-closed
/// path); false only for a store that is loaded AND explicitly disabled
/// (`is_open() && !is_rbac_enabled()`). A null / load-failed store returns true
/// and so fails CLOSED (#1498).
[[nodiscard]] bool rbac_enforcement_in_effect(const RbacStore* store) noexcept;

/// Build the `groups.name` used for an IdP-sourced group: `source:external_id`.
/// `source == "local"` groups are NOT namespaced — returns `external_id`
/// unchanged. The confused-deputy fix for #1832.
[[nodiscard]] std::string namespaced_group_name(const std::string& source,
                                                const std::string& external_id);

} // namespace yuzu::server
