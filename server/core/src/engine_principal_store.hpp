#pragma once

/// @file engine_principal_store.hpp
/// Born-on-Postgres store (ADR-0006, schema `engine_principal_store`) for
/// ENGINE PRINCIPALS — the durable identity behind an autonomous use-case
/// engine module (design doc `docs/auth-engine-principals-design.md` §3.1).
/// A dedicated store, not columns bolted onto `ApiTokenStore`: the identity
/// (owner, justification, classification, lifecycle) outlives any one
/// credential. No secret material lives here (credentials stay hash-only in
/// `ApiTokenStore`) — no ADR-0010 SecretCodec involvement.
///
/// Posture per ADR-0012 §1: **authoritative / fail-hard**, both at
/// construction AND at runtime. Construction is fail-CLOSED — a reachable
/// database whose schema can't migrate leaves the store `!is_open()`, which
/// server.cpp wires to `startup_failed_` (a later task; this store's
/// `is_open()` is the signal). At runtime, `get_for_auth` — the auth-lookup
/// chokepoint every consumer of this store must use — returns a **three-state**
/// result:
///
///   - `Active`      — a live row; the request may proceed.
///   - `MissingOrRevoked` — no row, or a row whose `lifecycle_state` is not
///     'active'. Terminal, 401-class: the credential is dead, stop and alert.
///   - `StoreUnreachable` — the store is closed, or a lease/query failed.
///     Retryable, 503-class: back off and retry, this is not a credential
///     problem.
///
/// **Both non-Active outcomes DENY the request.** The distinction changes
/// retry behavior ONLY, never the authorization outcome — there is no
/// downgrade path from "unreachable" to "admitted". Conflating the two risks
/// a transient PG blip reading as "credential revoked", which could make an
/// autonomous module abandon a healthy credential; conflating them the other
/// way (treating unreachable as admitted) would be a fail-open bypass, which
/// this design forbids outright. See design doc §3.1 / §12 decision 1.
///
/// Revoke is TERMINAL (never un-revoked — a false-positive compromise
/// response mints a successor principal instead, recorded via
/// `superseded_by`) and SOFT-RETAINED (a revoked row is never hard-deleted,
/// so audit attribution survives). `get()`/`revoke()`/`transfer_owner()` are
/// likewise authoritative (ADR-0012 §1): each returns a typed
/// `std::expected<..., std::string>` — mirroring `ApiTokenStore::get_token`/
/// `revoke_token` — so a genuine lease/query failure surfaces as
/// `unexpected(msg)` and is never conflated with the legitimate not-found /
/// no-op case (`nullopt` / `false`). A lease/query failure is NEVER a silent
/// success and NEVER reads as "no such row".
///
/// Substrate contract (ADR-0008/0012): holds a `PgPool&`, runs its migration
/// at construction on a pinned lease, schema-qualifies every runtime
/// statement, `RETURNING` is the mutate-and-return idiom. Bounded acquires
/// everywhere.
///
/// Operator-facing REST/MCP/console CRUD wrapping this store's API is PR
/// 4.3 scope — this header adds no routes.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// One persisted engine-principal identity row.
struct EnginePrincipalRow {
    std::string principal_id;     ///< "engine:<slug>" — reserved namespace, §3.3.
    std::string display_name;     ///< UI/audit label.
    std::string owner_username;   ///< Named responsible human (must reference an existing user).
    std::string justification;    ///< Grant justification captured at creation.
    std::string classification;   ///< "internal" | "external" — required at creation, no default.
    std::string lifecycle_state;  ///< "active" | "revoked" — terminal, not reversible.
    std::string superseded_by;    ///< Predecessor→successor link on revoke-and-replace; "" if none.
    std::int64_t created_at = 0;  ///< Epoch seconds.
    std::int64_t revoked_at = 0;  ///< Epoch seconds; 0 while active.
    std::string created_by;       ///< Audit anchor — who minted this principal.
};

/// Outcome of the authoritative auth-lookup chokepoint (`get_for_auth`).
/// See the file doc comment — the StoreUnreachable/MissingOrRevoked split
/// changes retry behavior ONLY, never the authorization outcome.
// G8 (governance hardening, cpp-expert N1): explicit `: int` underlying type
// — self-documenting, and keeps the forward-declaration in api_token_store.hpp
// and this definition ODR-compatible (a forward-declared scoped enum with no
// fixed underlying type is ill-formed to use before its definition is visible;
// pinning the type here removes any ambiguity for either TU).
enum class EngineLookupStatus : int {
    Active,            ///< A live row exists; the request may proceed.
    MissingOrRevoked,  ///< No row, or lifecycle_state != 'active'. Terminal (401-class), deny+stop.
    StoreUnreachable,  ///< Store closed or a lease/query failed. Retryable (503-class), deny+retry.
};

/// Result of `get_for_auth`. `row` is set if and only if `status == Active`.
struct EngineLookup {
    EngineLookupStatus status = EngineLookupStatus::StoreUnreachable;
    std::optional<EnginePrincipalRow> row;
};

class EnginePrincipalStore {
public:
    explicit EnginePrincipalStore(pg::PgPool& pool);

    EnginePrincipalStore(const EnginePrincipalStore&) = delete;
    EnginePrincipalStore& operator=(const EnginePrincipalStore&) = delete;
    EnginePrincipalStore(EnginePrincipalStore&&) = delete;
    EnginePrincipalStore& operator=(EnginePrincipalStore&&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// THE central auth-lookup chokepoint — see the file doc comment for the
    /// three-state contract. Every session-synthesis / delegation-redemption
    /// caller MUST route through this, never a plain `get()` (which returns
    /// any lifecycle_state and does not distinguish store-unreachable from
    /// not-found — it is for admin/test reads only).
    [[nodiscard]] EngineLookup get_for_auth(const std::string& principal_id) const;

    /// Mint a new engine principal. Validates BEFORE inserting:
    ///  - `classification` must be exactly "internal" or "external" (empty or
    ///    any other value is rejected — §3.1: required at creation, no
    ///    silent fallback on this write path).
    ///  - `principal_id` must start with "engine:" and carry a non-empty slug
    ///    (reserved namespace, §3.3).
    [[nodiscard]] std::expected<EnginePrincipalRow, std::string>
    create(const std::string& display_name, const std::string& owner_username,
          const std::string& justification, const std::string& classification,
          const std::string& created_by, const std::string& principal_id);

    /// Plain read by id, ANY lifecycle_state (admin/test surface — not the
    /// auth chokepoint; use `get_for_auth` for authorization decisions).
    /// Authoritative (ADR-0012 §1), mirrors `ApiTokenStore::get_token`'s typed
    /// result — a bare `optional` conflated "no such row" with "the store
    /// couldn't be asked":
    ///   * value `nullopt`   — genuine not-found; caller may 404.
    ///   * value (has row)   — the row, any lifecycle_state.
    ///   * `unexpected(msg)` — the store is closed, or a lease/query failed;
    ///     caller MUST surface this (503 / retry), never read it as
    ///     not-found.
    [[nodiscard]] std::expected<std::optional<EnginePrincipalRow>, std::string>
    get(const std::string& principal_id) const;

    /// Terminal revoke: active → revoked, `revoked_at` stamped,
    /// `superseded_by` recorded if given. Never un-revocable, never a
    /// hard-delete (soft-retain — audit attribution survives). Authoritative
    /// (ADR-0012 §1), mirrors `ApiTokenStore::revoke_token`'s typed result —
    /// a bare `bool` conflated "the write didn't land" with "there was
    /// nothing to revoke":
    ///   * value `true`      — the row existed (active) and is now revoked.
    ///   * value `false`     — the DB write ran fine but was a no-op — the
    ///     row is absent or already revoked. Not an error.
    ///   * `unexpected(msg)` — the write did NOT persist (store closed /
    ///     lease timeout / query error). The caller MUST surface this
    ///     (503 / retry), never audit or report success.
    [[nodiscard]] std::expected<bool, std::string>
    revoke(const std::string& principal_id, const std::string& superseded_by = "");

    /// Reassign ownership of an active principal (admin-forced — the design
    /// deliberately does not gate this on the outgoing owner's cooperation;
    /// that policy decision lives in the PR 4.3 route, this is the store
    /// primitive). Authoritative (ADR-0012 §1), same typed-result posture as
    /// `revoke`:
    ///   * value `true`      — the row existed (active) and is now
    ///     reassigned.
    ///   * value `false`     — the DB write ran fine but was a no-op — the
    ///     row is absent or not active. Not an error.
    ///   * `unexpected(msg)` — the write did NOT persist (store closed /
    ///     lease timeout / query error). The caller MUST surface this
    ///     (503 / retry), never a silent success.
    [[nodiscard]] std::expected<bool, std::string>
    transfer_owner(const std::string& principal_id, const std::string& new_owner);

    /// Admin/auditor list surface — every engine principal, ANY lifecycle_state
    /// by default, ordered by created_at. Pass `include_revoked=false` to
    /// filter to `lifecycle_state='active'` only. Bounded (few engine
    /// principals exist), parameterised, read-only. Best-effort: a lease/query
    /// failure is logged at warn and returns an empty vector rather than
    /// propagating the error — callers (admin list, auditor query) treat this
    /// as a best-effort read, not an authorization chokepoint (unlike
    /// `get_for_auth`, which fails closed with a distinct StoreUnreachable
    /// state).
    [[nodiscard]] std::vector<EnginePrincipalRow> list_all(bool include_revoked = true) const;

    /// Authoritative variant of `list_all` (ADR-0012 §1 read posture) for
    /// consumers that must NOT treat a lease/query failure as "zero engine
    /// principals exist" — e.g. the periodic-access-review export
    /// (`access_review_model.cpp`), where exporting a partial principal
    /// population as if it were complete is a SOC 2 evidence bug.
    /// `unexpected(msg)` on a closed store or a lease/query failure; a value
    /// (possibly empty) is a genuine, fully-read result.
    [[nodiscard]] std::expected<std::vector<EnginePrincipalRow>, std::string>
    list_all_checked(bool include_revoked = true) const;

    /// Count of ACTIVE engine principals owned by `owner_username` (uses
    /// `engine_principals_owner_idx`). Backs the owner-delete guard: a user
    /// cannot be deleted while owning an active engine principal. Returns
    /// `std::nullopt` on a lease/query failure — NOT `0` — so the caller's
    /// guard can fail CLOSED (treat "cannot verify" as "block the delete"),
    /// mirroring the authoritative posture elsewhere in this store. A `0`
    /// return is a verified count of zero, not "unknown".
    [[nodiscard]] std::optional<std::size_t>
    count_active_owned_by(const std::string& owner_username) const;

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
