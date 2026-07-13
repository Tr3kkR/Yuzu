#pragma once

/**
 * scim_store.hpp — storage layer for SCIM v2 provisioning (slice 1).
 *
 * Maps the IdP-facing SCIM `id` / `externalId` to a Yuzu username, and holds
 * the SCIM bearer credential(s) as sha256 hashes only — mirrors
 * `ApiTokenStore`'s token-hashing pattern (server/core/src/api_token_store.cpp).
 *
 * Opens its OWN sqlite3 connection to the SAME auth.db file `AuthDB` manages
 * (constructor takes the full db path, not a directory) so SCIM's tables ride
 * auth.db's substrate — and its eventual Postgres migration, ADR-0006 —
 * without a second .db file. Schema is tracked under `MigrationRunner`
 * component "scim"; `schema_meta` is keyed by that component string
 * (verified against migration_runner.cpp/.hpp), so this track is independent
 * of AuthDB's own "auth_db" migration track on the same underlying file.
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
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace yuzu::server {

/// A single SCIM resource mapping: the IdP-facing `id`/`externalId` bound to
/// a Yuzu username.
struct ScimResource {
    std::string scim_id;     ///< IdP-facing SCIM `id` (server-generated, opaque hex).
    std::string external_id; ///< IdP's `externalId` claim. Empty if the IdP never sent one.
    std::string username;    ///< The Yuzu username this resource maps to.
    bool active{true};
    std::string created_at; ///< SQLite `CURRENT_TIMESTAMP` text, UTC.
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
    std::string created_at; ///< SQLite `CURRENT_TIMESTAMP` text, UTC.
    std::string updated_at;
    int64_t etag_version{1}; ///< Bumped on every mutation; usable as a SCIM ETag.
};

class ScimStore {
public:
    /// `db_path` is the full path to the auth.db file (the SAME file AuthDB
    /// manages) — not a directory and not a distinct database file.
    explicit ScimStore(const std::filesystem::path& db_path);
    ~ScimStore();

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
    /// prepare failure, or a step-time error such as SQLITE_BUSY/LOCKED/
    /// IOERR/CORRUPT — the caller should fail closed/retry, never treat it
    /// as "already gone"); `true` if a row existed and was deleted; `false`
    /// if no row matched `scim_id` (e.g. a concurrent/duplicate DELETE
    /// already removed it).
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

    /// Add a single member (SCIM PATCH `add`). Idempotent: adding an
    /// already-present member returns true (no-op), not an error.
    bool add_group_member(const std::string& group_scim_id, const std::string& user_scim_id);

    /// Remove a single member (SCIM PATCH `remove`). Idempotent: removing an
    /// absent member returns true (no-op), not an error.
    bool remove_group_member(const std::string& group_scim_id, const std::string& user_scim_id);

    /// All `user_scim_id`s currently a member of `group_scim_id`. Empty
    /// vector on no members or an unknown/absent group (not distinguished —
    /// callers that need existence should check `get_group_by_id` first).
    std::vector<std::string> list_group_member_user_scim_ids(const std::string& group_scim_id) const;

    /// Reverse lookup: every group `displayName` that `user_scim_id` is
    /// currently a member of (join scim_group_members -> scim_groups). This
    /// is the primary read the role-application task (a later, separate
    /// task) consumes to decide SCIM-group-to-Yuzu-role mapping.
    std::vector<std::string>
    list_group_display_names_for_user(const std::string& user_scim_id) const;

private:
    sqlite3* db_{nullptr};
    mutable std::mutex db_mtx_; // Serializes access to this connection.

    void create_tables();
};

} // namespace yuzu::server
