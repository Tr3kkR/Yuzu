#pragma once

/**
 * session_store.hpp -- Durable operator sessions in Postgres (HA WS-1/1a, ADR-2002 §4)
 *
 * Moves operator sessions from `AuthManager`'s process-local `sessions_` map
 * (steady_clock, in-memory) to durable Postgres rows, so a session survives a
 * core-replica restart/failover and validates identically on any replica.
 *
 * This store is AUTHORITATIVE (ADR-0012 / postgres-store-playbook "Authoritative
 * reads"): a database error is type-distinguishable from "no such session" —
 * reads return `std::expected<std::optional<SessionRow>, Error>` where `nullopt`
 * means "definitively absent" and `unexpected` means "cannot tell" (a caller in
 * the auth path must NEVER treat a degraded read as "not a valid session" in a
 * way that silently grants; it fails the request rather than guessing).
 *
 * WALL-CLOCK (ADR-2002 §4, the reversal). Sessions were in-memory on a MONOTONIC
 * (steady_clock) clock specifically for NTP-step resistance. Durability forces
 * wall-clock: rows store absolute `system_clock` epoch-millis, and validation
 * compares against wall time. A backward clock step on the DB primary would
 * un-expire sessions and extend live JIT-elevation / MFA windows, so two
 * defences are layered (the store carries the data; AuthManager enforces):
 *   (1) elevation/MFA carry an `*_issued_ms` anchor and are additionally bounded
 *       by `now <= issued_ms + <authored max>` — a hard wall-clock ceiling that a
 *       steppable `elevated_until_ms` cannot exceed;
 *   (2) DB-primary clock integrity is a monitored security dependency (WS-11).
 *
 * SECRET-AT-REST. The row key is a verify-only SHA-256 of the bearer session
 * token, never the raw token (a DB read must not yield a usable session cookie).
 * The caller hashes the token; this store only ever sees the hash.
 *
 * VALIDATE-CACHE (the rbac_store pattern). Per-request session validation must
 * not hit Postgres every call. AuthManager keeps a process-local cache validated
 * against a durable generation counter (`session_meta.write_generation`) that is
 * bumped IN THE SAME TXN as every membership/authz-affecting mutation (create,
 * invalidate, elevate, revoke-elevation, mfa-verify). `touch_activity` is a
 * sliding idle update and deliberately does NOT bump the generation. This store
 * owns the durable side (mutations bump; `read_generation()` reads); the cache
 * itself lives in AuthManager.
 *
 * RETENTION. `reap_expired()` is a wall-clock bulk delete, so once sessions are
 * durable it joins the clock-guarded-retention set (routed concern #2360/#2361 —
 * previously the in-memory monotonic sweep was exempt "by construction"). It is
 * single-writer-safe across replicas via a `pg_advisory_xact_lock` taken as its
 * own statement before the check-and-delete, and it is capped + guarded.
 */

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// A durable session row, in wall-clock epoch-milliseconds. Mirrors the
/// authz-relevant fields of `struct Session` (auth.hpp); presentation-only
/// fields the map held but auth never keys on are carried verbatim.
struct SessionRow {
    std::string token_hash; ///< SHA-256 (hex) of the bearer token — the primary key
    std::string username;   ///< stable auth principal
    std::string display_name;
    std::string role; ///< serialized Role (auth::role_to_string)
    std::string auth_source{"local"};
    std::string oidc_sub;
    std::string token_scope_service;
    std::string mcp_tier;
    std::string principal_kind{"human"};
    std::int64_t created_at_ms{0};       ///< wall-clock session creation (the session issue anchor)
    std::int64_t expires_at_ms{0};       ///< absolute wall-clock lifetime ceiling
    std::int64_t last_activity_ms{0};    ///< sliding idle anchor (wall-clock)
    std::int64_t mfa_verified_ms{0};     ///< 0 = no MFA proof
    std::int64_t elevated_until_ms{0};   ///< 0 = not elevated
    std::int64_t elevation_issued_ms{0}; ///< wall-clock at elevation grant — the max-delta anchor
};

class SessionStore {
public:
    struct Error {
        std::string message;
    };

    /// Borrows the shared pool and runs the schema migration on a pinned lease.
    /// is_open() is false if the lease was empty or the migration failed —
    /// fail-closed, no fallback (ADR-0007).
    explicit SessionStore(pg::PgPool& pool);

    SessionStore(const SessionStore&) = delete;
    SessionStore& operator=(const SessionStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    // ── Mutations (each bumps the durable generation in the same txn) ──────────

    /// Insert (or replace) a session. Overwrites any prior row for the same
    /// token_hash (a token collision cannot legitimately occur; last-write-wins
    /// is safe and matches the map's `operator[]`).
    [[nodiscard]] std::expected<void, Error> create(const SessionRow& row);

    /// Delete one session. Returns whether a row was removed.
    [[nodiscard]] std::expected<bool, Error> invalidate(const std::string& token_hash);

    /// Delete every session for a username (logout-all / user removal / role
    /// change). Returns the number removed.
    [[nodiscard]] std::expected<int, Error> invalidate_user(const std::string& username);

    /// Grant/extend elevation. `elevated_until_ms` is the (already caller-clamped)
    /// absolute ceiling; `elevation_issued_ms` is the wall-clock grant time (the
    /// max-delta anchor). Returns whether the session existed.
    [[nodiscard]] std::expected<bool, Error> set_elevation(const std::string& token_hash,
                                                           std::int64_t elevated_until_ms,
                                                           std::int64_t elevation_issued_ms);

    /// Clear elevation on one session. Returns whether it existed.
    [[nodiscard]] std::expected<bool, Error> clear_elevation(const std::string& token_hash);

    /// Clear elevation on every session for a username. Returns the count cleared.
    [[nodiscard]] std::expected<int, Error> clear_user_elevations(const std::string& username);

    /// Stamp an MFA step-up proof time. Returns whether the session existed.
    [[nodiscard]] std::expected<bool, Error> mark_mfa(const std::string& token_hash,
                                                      std::int64_t mfa_verified_ms);

    // ── Sliding activity update (NO generation bump — not an authz change) ─────

    /// Advance the idle anchor. Deliberately does not bump the generation (a
    /// slide is not a membership/authz change), so it does not invalidate other
    /// replicas' caches. Returns whether the session existed.
    [[nodiscard]] std::expected<bool, Error> touch_activity(const std::string& token_hash,
                                                            std::int64_t last_activity_ms);

    // ── Reads ──────────────────────────────────────────────────────────────────

    /// Fetch one session by token hash. nullopt = definitively absent; unexpected
    /// = DB degraded (the caller must NOT treat this as "invalid session").
    [[nodiscard]] std::expected<std::optional<SessionRow>, Error>
    find(const std::string& token_hash) const;

    /// The durable write-generation the validate-cache validates against.
    [[nodiscard]] std::expected<std::uint64_t, Error> read_generation() const;

    // ── Retention (clock-guarded, single-writer across replicas) ───────────────

    /// Delete sessions whose absolute lifetime has passed. Guarded per the
    /// clock-guarded-retention rule and serialized cluster-wide by an advisory
    /// lock. `now_ms` is the caller's wall clock; the guard sanitises it against
    /// the durable anchor. Returns the number deleted (0 on a declined pass).
    [[nodiscard]] std::expected<int, Error> reap_expired(std::int64_t now_ms);

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
