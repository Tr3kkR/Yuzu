#pragma once

/// @file api_token_store.hpp
/// Born-on-Postgres store (ADR-0006, schema `api_token_store`) for API
/// Bearer tokens (human PATs, service-scoped change-window tokens, MCP
/// tier tokens, and — per `docs/auth-engine-principals-design.md` §6 — the
/// `principal_kind` seam for future engine-principal-issued tokens). FRESH
/// START (no `migrate_from_sqlite()`): the legacy `<db_dir>/api-tokens.db`
/// is no longer opened; existing tokens are invalidated on upgrade (see the
/// PR 4.1 rollout note in the design doc / changelog fragment).
///
/// Posture (ADR-0012 §1): CONSTRUCTION is fail-CLOSED — a reachable
/// database whose schema can't migrate/open sets `startup_failed_` in
/// server.cpp (same pattern as every other born-on-PG store). RUNTIME is
/// authoritative for revocation/deletion: a lease timeout or query error on
/// `revoke_token`/`revoke_for_principal`/`delete_token` MUST return
/// false/0, never a silent success — those calls back "Sign out
/// everywhere" and the stolen-laptop response path (ADR-0012 §1
/// authoritative posture; do not soften to fail-open). Reads
/// (`validate_token`/`get_token`/`list_tokens`) degrade to
/// empty/not-found on a DB error, same as before the port.
///
/// Substrate contract (ADR-0008/0012): holds a `PgPool&`, runs its
/// migration at construction on a pinned lease, schema-qualifies every
/// runtime statement (`api_token_store.api_tokens`), `RETURNING` is the
/// mutate-and-return idiom (never `sqlite3_changes()`, issue #1033).
/// Bounded acquires everywhere at runtime; unbounded `acquire()` is
/// construction-only.
///
/// Substrate-independent state (in-memory `token_cache_`, the
/// `revoke_generation_` TOCTOU guard, hit/miss counters) survives the port
/// unchanged — see the .cpp for why the generation counter narrowly guards a
/// cache-write racing a concurrent revoke (cache-poisoning only, NOT full
/// validate/revoke serialization — the pool has no
/// single connection-wide mutex serializing SELECT + cache-write the way
/// the old `db_mtx_` did).

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

// Forward-declared rather than pulling in engine_principal_store.hpp here —
// a scoped enum's underlying type defaults to `int`, so an opaque
// enum-class-declaration is a valid, self-consistent forward reference. The
// full definition (and the `.cpp`'s actual use of the enum values) lives in
// engine_principal_store.hpp, included only by api_token_store.cpp.
//
// G8 (governance hardening, cpp-expert N1): the underlying type is pinned
// `: int` explicitly (rather than relying on the implicit default) on BOTH
// this forward-declaration and the definition in engine_principal_store.hpp
// — self-documenting, and removes any ambiguity for either translation unit
// (a mismatched underlying type between a forward-declaration and its
// definition is ill-formed, no diagnostic required).
enum class EngineLookupStatus : int;

struct ApiToken {
    std::string token_id;      // Short display ID (prefix of hash)
    std::string token_hash;    // SHA-256 hash of raw token (stored, never the raw token)
    std::string name;          // Human-readable label
    std::string principal_id;  // Username (or engine principal id) who created it
    std::string scope_service; // Non-empty = scoped to this IT service (change window token)
    std::string mcp_tier;      // "readonly", "operator", "supervised", or "" (not MCP)
    int64_t created_at{0};
    int64_t expires_at{0}; // 0 = never
    int64_t last_used_at{0};
    bool revoked{false};
    // "human" | "engine" — set at creation, immutable thereafter (design doc
    // §6). Appended last so existing aggregate-initializer callers are
    // unaffected. Legacy/human-issued tokens are "human".
    std::string principal_kind{"human"};
};

class ApiTokenStore {
public:
    explicit ApiTokenStore(pg::PgPool& pool);

    ApiTokenStore(const ApiTokenStore&) = delete;
    ApiTokenStore& operator=(const ApiTokenStore&) = delete;

    bool is_open() const;

    /// Create a new API token. Returns the raw token string (shown to user once).
    /// If scope_service is non-empty, the token is scoped to that IT service.
    /// If mcp_tier is non-empty, the token is an MCP token with the given tier.
    /// `principal_kind` defaults to `"human"`; passing `"engine"` mints an
    /// engine-principal credential and triggers the engine block (design doc
    /// §§6-8): the mcp_tier must be `"readonly"`, the token must expire within
    /// the 90-day ceiling, and the injected referent check
    /// (`set_engine_referent_check`) must report the principal Active — else the
    /// mint fails closed. A C++-side allowlist rejects any other kind ahead of
    /// the DB `CHECK (principal_kind IN ('human','engine'))`.
    std::expected<std::string, std::string>
    create_token(const std::string& name, const std::string& principal_id, int64_t expires_at = 0,
                 const std::string& scope_service = {}, const std::string& mcp_tier = {},
                 std::string principal_kind = "human");

    /// Validate a raw Bearer token. Returns the ApiToken if valid and not expired/revoked.
    std::optional<ApiToken> validate_token(const std::string& raw_token);

    /// List all tokens (for admin UI). Raw token values are never returned.
    /// Authoritative read (ADR-0012 §1): `unexpected` on a runtime DB error, a
    /// value (possibly empty) on success — never an empty vector papering over
    /// an outage.
    std::expected<std::vector<ApiToken>, std::string>
    list_tokens(const std::string& principal_id = {}) const;

    /// Look up a single token by its short display ID. The raw token and
    /// `token_hash` are NOT populated — only metadata. Used by the REST API
    /// to verify ownership before revoke so a caller with `ApiToken:Delete`
    /// cannot revoke another user's token by guessing its ID. Authoritative
    /// read (ADR-0012 §1): `unexpected` on a runtime DB error (caller 503s),
    /// value `nullopt` on a genuine no-such-row (caller 404s).
    std::expected<std::optional<ApiToken>, std::string>
    get_token(const std::string& token_id) const;

    /// Revoke a token by ID. Returns a typed result that distinguishes the
    /// two outcomes a bare `bool` conflated (ADR-0030 §Posture — a revoke
    /// that did not land must never read as success):
    ///   * value `true`  — the token existed and is now revoked.
    ///   * value `false` — the DB write succeeded but no such token existed
    ///                     (already gone / unknown id) — a genuine 404.
    ///   * `unexpected(msg)` — the write did NOT persist (lease timeout /
    ///                     query error). The caller MUST surface this
    ///                     (503 / "retry"), never audit or toast success.
    std::expected<bool, std::string> revoke_token(const std::string& token_id);

    /// Revoke every non-revoked token belonging to a principal. Used by the
    /// session-revocation REST surface so "Sign out everywhere" actually
    /// revokes everywhere (cookie sessions + API tokens), not just browser
    /// cookies — a stolen-laptop incident otherwise leaves the on-laptop API
    /// token fully functional while the operator UX silently lies.
    ///   * value — the number of tokens marked revoked (0 = the principal had
    ///             none; the DB write still succeeded).
    ///   * `unexpected(msg)` — the write did NOT persist; the caller MUST
    ///             record a partial/failed revoke, never a clean success
    ///             (ADR-0030 §Posture).
    std::expected<std::size_t, std::string> revoke_for_principal(const std::string& principal_id);

    /// Delete a token permanently. Same authoritative typed result as
    /// `revoke_token` (ADR-0030 §Posture names delete_token in the
    /// error-is-surfaced list): `unexpected` on a DB write failure, value
    /// `false` on no-such-token, `true` on delete.
    std::expected<bool, std::string> delete_token(const std::string& token_id);

    /// Cumulative count of validate_token calls served from the in-memory cache.
    /// Exposed for Prometheus scraping; set via gauge in server.cpp's periodic loop.
    uint64_t cache_hits() const noexcept { return cache_hits_.load(std::memory_order_relaxed); }

    /// Cumulative count of validate_token calls that fell through to Postgres.
    uint64_t cache_misses() const noexcept { return cache_misses_.load(std::memory_order_relaxed); }

    /// Current number of distinct tokens cached in memory.
    std::size_t cache_size() const;

    // Test-only seams (#2179) for the revoke/validate TOCTOU regression test.
    // Null in production (zero overhead). Let a test deterministically
    // interleave a concurrent revoke at the exact cache-poisoning point.
    std::function<void()> test_hook_after_first_revoke_bump_;   // fired in revoke_token, right after the FIRST generation bump, before the lease/UPDATE
    std::function<void()> test_hook_after_validate_select_;     // fired in validate_token, right after the SELECT (+last_used update), before the generation re-check block

    /// Injects the engine-principal referential-integrity check used by
    /// `create_token`'s engine block (design doc §6). Unset by default —
    /// `create_token` fails closed (rejects every `principal_kind=="engine"`
    /// mint) until this is wired. server.cpp wires the real resolver
    /// (`EnginePrincipalStore::get_for_auth`) after both stores open; this
    /// setter exists so `ApiTokenStore` never constructs an
    /// `EnginePrincipalStore` itself (would couple two independently-owned
    /// stores at construction time).
    void set_engine_referent_check(std::function<EngineLookupStatus(const std::string&)> fn);

private:
    pg::PgPool& pool_;
    bool open_{false};

    // LRU cache for validated tokens: token_hash -> (ApiToken, expiry_time)
    struct CachedToken {
        ApiToken token;
        std::chrono::steady_clock::time_point cached_at;
    };
    mutable std::mutex cache_mtx_;
    mutable std::unordered_map<std::string, CachedToken> token_cache_;
    static constexpr auto kTokenCacheTtl = std::chrono::seconds(60);

    // Cache hit/miss counters (atomic, lock-free read for Prometheus scraping).
    mutable std::atomic<uint64_t> cache_hits_{0};
    mutable std::atomic<uint64_t> cache_misses_{0};

    // Defense-in-depth against a cache TOCTOU on revocation. Incremented
    // bumped TWICE per revoke in `revoke_token`, `revoke_for_principal`, and
    // `delete_token`: once BEFORE the UPDATE/DELETE and once AFTER it commits
    // (before `invalidate_cache`). `validate_token` snapshots the value before
    // its DB SELECT and re-reads it UNDER `cache_mtx_`, in the same critical
    // section as the cache write — if it moved, a revoke raced with us and we
    // MUST NOT populate the cache with a stale (revoked=false) view that would
    // survive for `kTokenCacheTtl` (60 s) and silently lie about "Sign out
    // everywhere". The re-check being under the lock is load-bearing:
    // `invalidate_cache` takes the same mutex and the generation bump precedes
    // it, so a check-BEFORE-lock ordering left a window in which a revoke's
    // erase ran between the check and the insert and the token re-authenticated
    // for the full TTL (fixed 2026-07; the re-check + insert are now one locked
    // step).
    //
    // Why TWO bumps (PR #2188 round-3 review). The pre-UPDATE bump only catches
    // a validate that snapshotted the generation BEFORE it. A validate that
    // starts AFTER the pre-bump captures the already-incremented value as its
    // baseline, and under Postgres READ COMMITTED its SELECT can still read the
    // row's pre-commit revoked=false; with only one bump its post-SELECT
    // re-check would match its own snapshot and cache the stale row for the full
    // TTL. The post-commit bump moves the generation past that snapshot too, so
    // BOTH classes of racing validate skip the stale cache write. The cache is
    // therefore never poisoned past the TTL.
    //
    // Under the pool there is no single connection-wide mutex serializing a
    // caller's SELECT against another caller's UPDATE the way the old sqlite
    // `db_mtx_` did — a Postgres pool hands out independent connections per
    // lease. The generation counter's job is NARROW: it stops a racing validate
    // from CACHING a stale entry. It does NOT restore the validate<->revoke
    // serialization db_mtx_ gave, so two bounded SINGLE-in-flight-request
    // windows remain (see validate_token in the .cpp): (A) a cache-MISS validate
    // may still RETURN (once, uncached) a token whose revoke committed during
    // its own execution, and (B) the cache-HIT path may return a validly-cached
    // value during the revoke's UPDATE->invalidate_cache gap. Neither permits a
    // NEW authentication after the revoke's invalidate runs, and neither leaves
    // a stale cache entry. A full close of (A)/(B) (SELECT ... FOR UPDATE in the
    // revoke txn, or a per-token version column) is tracked in #2173.
    // Keep every fetch_add (both per call) and every snapshot/re-check.
    std::atomic<uint64_t> revoke_generation_{0};

    // Engine-principal referential-integrity resolver (design doc §6),
    // injected via `set_engine_referent_check`. Null until server.cpp wires
    // it post-construction — `create_token` treats null as fail-closed
    // (never mints an engine token without this check available).
    std::function<EngineLookupStatus(const std::string&)> engine_referent_check_;

    /// Generate a fresh `yuzu_` Bearer token from the platform CSPRNG.
    /// Returns the raw token on success; std::unexpected when the system
    /// entropy source is unavailable (caller must surface as 503, never
    /// fall back to weak entropy). See `secure_random.hpp` for details.
    std::expected<std::string, std::string> generate_raw_token() const;
    std::string sha256_hex(const std::string& input) const;
    void invalidate_cache(const std::string& token_hash);
};

} // namespace yuzu::server
