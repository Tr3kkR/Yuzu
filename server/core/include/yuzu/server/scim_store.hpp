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

private:
    sqlite3* db_{nullptr};
    mutable std::mutex db_mtx_; // Serializes access to this connection.

    void create_tables();
};

} // namespace yuzu::server
