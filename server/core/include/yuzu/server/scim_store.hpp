#pragma once

/**
 * scim_store.hpp — storage layer for SCIM v2 provisioning (slice 1),
 * born-on-Postgres (ADR-0006, schema `scim_store`).
 *
 * Maps the IdP-facing SCIM `id` / `externalId` to a Yuzu username, and holds
 * the SCIM bearer credential(s) as sha256 hashes only — mirrors
 * `ApiTokenStore`'s token-hashing pattern (server/core/src/api_token_store.cpp).
 * SCIM tokens stay verify-only hashes (no `SecretCodec` — there is no
 * plaintext to envelope-encrypt; a hash cannot be decrypted back to a raw
 * bearer value the way a `SecretCodec` blob can).
 *
 * Posture (ADR-0012 §1): FRESH START, no `migrate_from_sqlite()` — this is a
 * greenfield born-on-PG store (no prior release shipped a Postgres SCIM
 * store to backfill from); any pre-existing `auth.db`-resident SCIM mappings
 * are not carried forward. Construction is fail-CLOSED: `is_open()` is false
 * if the pool lease or schema migration fails, and server.cpp treats that as
 * a fatal startup error (same pattern as every other born-on-PG store).
 * Runtime reads/mutations degrade to the empty/false/nullopt value the
 * existing (SQLite-era) callers already treat as "operation did not
 * succeed" — `scim_routes.cpp` (a separate, un-touched slice) already
 * handles that outcome as a 5xx, so this store keeps the same signatures
 * rather than introducing a parallel `std::expected` surface here.
 *
 * Substrate contract (ADR-0008/0012): holds a `pg::PgPool&` (not a
 * `sqlite3*`), runs its migration at construction on a pinned lease,
 * schema-qualifies every runtime statement (`scim_store.scim_resources`,
 * `scim_store.scim_tokens`, `scim_store.scim_groups`,
 * `scim_store.scim_group_members`), and uses `RETURNING` for
 * mutate-and-return (never `sqlite3_changes()`/row-count polling, #1033).
 * Bounded `try_acquire_for` leases on every runtime path.
 *
 * NO per-connection `db_mtx_` anymore (the SQLite single-handle serialization
 * this store used to rely on) — a `PgPool` hands out independent connections
 * per lease, same as every other born-on-PG store. `scim_routes.cpp`'s
 * `recompute_scim_user_role` doc comment references a "LOCK ORDER ...
 * ScimStore::db_mtx_" that predates this port; that comment is stale as of
 * this port (member removed) and is out of this store's scope to fix
 * (routes layer, not touched here) — flagged for the routes owner.
 *
 * This class does NOT implement any HTTP/REST route or JSON codec — it is
 * the data + token layer only (slice 1 of 3; a sibling junior owns the JSON
 * codec, another owns the routes).
 *
 * SCIM v2 Groups (#2021, slice 2): schema version 2 adds `scim_groups` +
 * the `scim_group_members` join table, and this class exposes group CRUD +
 * membership management + the `list_group_display_names_for_user` reverse
 * lookup a later, separate task consumes to map SCIM groups to Yuzu roles.
 * Still no HTTP/REST route, JSON codec, or role-application logic here.
 */

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// A single SCIM resource mapping: the IdP-facing `id`/`externalId` bound to
/// a Yuzu username.
struct ScimResource {
    std::string scim_id;     ///< IdP-facing SCIM `id` (server-generated, opaque hex).
    std::string external_id; ///< IdP's `externalId` claim. Empty if the IdP never sent one.
    std::string username;    ///< The Yuzu username this resource maps to.
    bool active{true};
    std::string created_at; ///< ISO-8601 UTC text (`YYYY-MM-DDTHH:MM:SSZ`).
    std::string updated_at;
    int64_t etag_version{1}; ///< Bumped on every mutation; usable as a SCIM ETag.
};

/// A single SCIM Group resource (slice 2, #2021): the IdP-facing group `id`/
/// `externalId`/`displayName` — membership itself lives in the separate
/// `scim_group_members` join table, not on this struct.
struct ScimGroup {
    std::string scim_id;     ///< IdP-facing SCIM `id` (server-generated, opaque hex).
    std::string external_id; ///< IdP's `externalId` claim. Empty if the IdP never sent one.
    std::string display_name; ///< The Group's SCIM `displayName`.
    bool active{true};
    std::string created_at; ///< ISO-8601 UTC text (`YYYY-MM-DDTHH:MM:SSZ`).
    std::string updated_at;
    int64_t etag_version{1}; ///< Bumped on every mutation; usable as a SCIM ETag.
};

class ScimStore {
public:
    /// Borrows the shared pool and runs the `scim_store` schema migration on
    /// a pinned lease. `is_open()` is false if the lease was empty or the
    /// migration failed — the server fails closed (startup_failed_) before
    /// reaching here in production.
    explicit ScimStore(pg::PgPool& pool);
    ~ScimStore() = default;

    ScimStore(const ScimStore&) = delete;
    ScimStore& operator=(const ScimStore&) = delete;

    bool is_open() const noexcept;

    // ── Bearer token (SCIM credential) ───────────────────────────────────

    /// Hash and store the SCIM bearer token under `label`. Any existing
    /// non-revoked token sharing the same label is revoked first (upsert by
    /// label) — used at boot from a config flag, not exposed over any route
    /// in this slice. Returns false on CSPRNG/db failure or an empty `raw`.
    bool set_token(const std::string& raw, const std::string& label);

    /// True if at least one non-revoked token row exists.
    bool has_token() const;

    /// Constant-time validate a raw Bearer token against every non-revoked
    /// token hash (via `CRYPTO_memcmp`). Empty input always rejects.
    bool validate_token(const std::string& raw) const;

    // ── SCIM resources ────────────────────────────────────────────────────

    /// Create a new resource mapping, generating a fresh `scim_id`. Returns
    /// `nullopt` if `username` already has a mapping (UNIQUE constraint) or
    /// on CSPRNG/db failure.
    std::optional<ScimResource> create_resource(const std::string& username,
                                                const std::string& external_id = {});

    std::optional<ScimResource> get_by_scim_id(const std::string& scim_id) const;

    /// Tri-state existence check: `true` = a resource with this `scim_id`
    /// exists, `false` = it definitively does not, `nullopt` = the store
    /// could not answer (closed, lease timeout, failed statement).
    ///
    /// ★ SECURITY (2026-07-25 Hermes pass, MEDIUM): `get_by_scim_id` collapses
    /// "no such resource" and "read failed" into the same `nullopt`, which is
    /// harmless for a plain lookup but NOT for group-membership resolution:
    /// `resolve_member_values` treats an unresolvable id as validate-and-skip,
    /// so on a transient blip a genuinely-provisioned member is dropped and
    /// the PUT/PATCH handler then persists the SMALLER set — a partial version
    /// of the durable membership loss the tri-state membership reads fix. Use
    /// this (not `get_by_scim_id().has_value()`) anywhere a negative answer
    /// feeds a write. Deliberately additive: `get_by_scim_id`'s many read-only
    /// call sites keep their existing contract.
    std::optional<bool> resource_exists(const std::string& scim_id) const;
    std::optional<ScimResource> get_by_username(const std::string& username) const;

    /// Empty `external_id` always returns `nullopt` (an empty externalId is
    /// not a meaningful lookup key).
    std::optional<ScimResource> find_by_external_id(const std::string& external_id) const;

    /// 1-based `start_index` per the SCIM list-response convention (RFC 7644
    /// §3.4.2 `startIndex`). `total_out` receives the total resource count
    /// (independent of the pagination window) so a caller can build
    /// `totalResults`. Stable creation-order pagination.
    std::vector<ScimResource> list(int start_index, int count, int& total_out) const;

    /// Toggle active/inactive (SCIM PATCH `active`). Bumps `etag_version` and
    /// `updated_at`. Returns false if no row matched `scim_id`.
    bool set_active(const std::string& scim_id, bool active);

    /// Update the mutable identity fields (username/external_id). Bumps
    /// `etag_version` and `updated_at`. Returns false if no row matched
    /// `scim_id`.
    bool update_resource(const std::string& scim_id, const std::string& username,
                         const std::string& external_id);

    /// Delete the resource mapping. Tri-state return so a caller can treat
    /// "the row is already gone" as idempotent success rather than a
    /// failure (UP-N4): `nullopt` on a genuine DB error (no connection,
    /// lease timeout, or a query-time error — the caller should fail
    /// closed/retry, never treat it as "already gone"); `true` if a row
    /// existed and was deleted; `false` if no row matched `scim_id` (e.g. a
    /// concurrent/duplicate DELETE already removed it).
    std::optional<bool> delete_by_scim_id(const std::string& scim_id);

    // ── SCIM groups (slice 2, #2021) ─────────────────────────────────────
    //
    // Storage + membership only — no HTTP route, no JSON codec, no role-
    // application logic. `list_group_display_names_for_user` is the reverse
    // lookup the (separate) role-application task consumes.

    /// Create a new group, generating a fresh `scim_id`. Returns `nullopt` if
    /// `display_name` is empty, on CSPRNG/db failure, or if `display_name`
    /// already has a mapping (see `get_group_by_display_name` for the
    /// idempotent-create check a caller should do first).
    std::optional<ScimGroup> create_group(const std::string& display_name,
                                          const std::string& external_id = {});

    std::optional<ScimGroup> get_group_by_id(const std::string& scim_id) const;

    /// Exact-match lookup by `displayName` — used for idempotent create /
    /// uniqueness checks by the routes layer (no DB-level UNIQUE constraint
    /// on this column; SCIM `displayName` collisions are a caller-level 409,
    /// not a storage-level rejection).
    std::optional<ScimGroup> get_group_by_display_name(const std::string& display_name) const;

    /// 1-based `start_index` per the SCIM list-response convention (RFC 7644
    /// §3.4.2 `startIndex`), mirroring `list()`. `total_out` receives the
    /// total group count.
    std::vector<ScimGroup> list_groups(int start_index, int count, int& total_out) const;

    /// Total number of groups (no pagination window).
    int count_groups() const;

    /// Update the mutable identity fields (display_name/external_id). Bumps
    /// `etag_version` and `updated_at`. Returns false if no row matched
    /// `scim_id`.
    bool update_group(const std::string& scim_id, const std::string& display_name,
                      const std::string& external_id);

    /// Delete the group (its `scim_group_members` rows are deleted alongside
    /// it, in the same transaction, so the reverse lookup never dangles).
    /// Tri-state return mirrors `delete_by_scim_id` (UP-N4): `nullopt` on a
    /// genuine DB error, `true` if a row existed and was deleted, `false` if
    /// no row matched `scim_id` (idempotent no-op).
    std::optional<bool> delete_group(const std::string& scim_id);

    /// Replace-all semantics: the group's membership becomes exactly
    /// `user_scim_ids` (existing rows deleted, then the new set inserted, in
    /// one transaction). Returns false on a db error; a group with zero
    /// members is expressed by passing an empty vector (not by omission).
    bool set_group_members(const std::string& group_scim_id,
                           const std::vector<std::string>& user_scim_ids);

    /// Atomically (single transaction) update the group's display_name/
    /// external_id AND replace its entire membership set — the durable fix
    /// for PUT/PATCH committing the rename and the membership change as
    /// separate transactions (#2127 review), which could leave a committed
    /// rename with a stale/partial membership set on a mid-write failure.
    /// Tri-state return mirrors `delete_group`: `nullopt` on a genuine DB
    /// error (rolled back — neither the rename nor the membership change
    /// persists), `false` if no row matched `scim_id` (no side effects),
    /// `true` if the group was updated.
    std::optional<bool> replace_group_and_members(
        const std::string& scim_id, const std::string& display_name,
        const std::string& external_id, const std::vector<std::string>& member_user_scim_ids);

    /// Add a single member (SCIM PATCH `add`). Idempotent: adding an
    /// already-present member returns true (no-op), not an error.
    bool add_group_member(const std::string& group_scim_id, const std::string& user_scim_id);

    /// Remove a single member (SCIM PATCH `remove`). Idempotent: removing an
    /// absent member returns true (no-op), not an error.
    bool remove_group_member(const std::string& group_scim_id, const std::string& user_scim_id);

    /// All `user_scim_id`s currently a member of `group_scim_id`.
    ///
    /// ★ SECURITY (2026-07-25 review, HIGH #3): returns `nullopt` when the
    /// store could not answer (pool-lease timeout, failed statement) —
    /// DISTINCT from an engaged-but-empty vector, which means the group
    /// genuinely has no members. These were fused into a bare empty vector,
    /// and because this read feeds a read-modify-write membership replace,
    /// a momentary blip read as "no current members" and the subsequent
    /// write then DURABLY DELETED the real membership. Callers MUST fail
    /// closed on `nullopt` and never treat it as an empty set. Existence of
    /// the group itself is still not distinguished — check `get_group_by_id`
    /// first if you need that.
    std::optional<std::vector<std::string>>
    list_group_member_user_scim_ids(const std::string& group_scim_id) const;

    /// Reverse lookup: every group `displayName` that `user_scim_id` is
    /// currently a member of (join scim_group_members -> scim_groups). This
    /// is the primary read the role-application task consumes to decide
    /// SCIM-group-to-Yuzu-role mapping.
    ///
    /// ★ SECURITY (same finding): `nullopt` on store failure. An empty vector
    /// here resolves the user to `role=user`, so a blip that read as "member
    /// of no groups" would silently demote a SCIM-provisioned admin — the
    /// authoritative-read-fails-open anti-pattern `docs/postgres-store-playbook.md`
    /// rejects, and the same argument this PR makes for MFA.
    std::optional<std::vector<std::string>>
    list_group_display_names_for_user(const std::string& user_scim_id) const;

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
