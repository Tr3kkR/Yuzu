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
    /// `principal_kind` defaults to "human" — existing callers mint human
    /// tokens unchanged. Write-once: there is no update path for it.
    std::expected<std::string, std::string>
    create_token(const std::string& name, const std::string& principal_id, int64_t expires_at = 0,
                 const std::string& scope_service = {}, const std::string& mcp_tier = {},
                 std::string principal_kind = "human");

    /// Validate a raw Bearer token. Returns the ApiToken if valid and not expired/revoked.
    std::optional<ApiToken> validate_token(const std::string& raw_token);

    /// List all tokens (for admin UI). Raw token values are never returned.
    std::vector<ApiToken> list_tokens(const std::string& principal_id = {}) const;

    /// Look up a single token by its short display ID. The raw token and
    /// `token_hash` are NOT populated — only metadata. Used by the REST API
    /// to verify ownership before revoke so a caller with `ApiToken:Delete`
    /// cannot revoke another user's token by guessing its ID.
    std::optional<ApiToken> get_token(const std::string& token_id) const;

    /// Revoke a token by ID.
    bool revoke_token(const std::string& token_id);

    /// Revoke every non-revoked token belonging to a principal. Returns
    /// the number of tokens marked revoked. Used by the session-revocation
    /// REST surface so "Sign out everywhere" actually revokes everywhere
    /// (cookie sessions + API tokens), not just browser cookies. Without
    /// this, a stolen-laptop incident leaves the on-laptop API token
    /// fully functional and the operator UX silently lies.
    std::size_t revoke_for_principal(const std::string& principal_id);

    /// Delete a token permanently.
    bool delete_token(const std::string& token_id);

    /// Cumulative count of validate_token calls served from the in-memory cache.
    /// Exposed for Prometheus scraping; set via gauge in server.cpp's periodic loop.
    uint64_t cache_hits() const noexcept { return cache_hits_.load(std::memory_order_relaxed); }

    /// Cumulative count of validate_token calls that fell through to Postgres.
    uint64_t cache_misses() const noexcept { return cache_misses_.load(std::memory_order_relaxed); }

    /// Current number of distinct tokens cached in memory.
    std::size_t cache_size() const;

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
    // before every UPDATE/DELETE in `revoke_token`, `revoke_for_principal`,
    // and `delete_token`. `validate_token` snapshots the value before its DB
    // SELECT and re-reads before the cache write — if it moved, a revoke
    // raced with us and we MUST NOT populate the cache with a stale
    // (revoked=false) view that would survive for `kTokenCacheTtl` (60 s)
    // and silently lie about "Sign out everywhere" success.
    //
    // Under the pool there is no single connection-wide mutex serializing a
    // caller's SELECT against another caller's UPDATE the way the old sqlite
    // `db_mtx_` did — a Postgres pool hands out independent connections per
    // lease. The generation counter's job is therefore NARROW: it stops a
    // validate that raced a revoke from CACHING a stale revoked=false entry
    // (which would otherwise survive the full cache TTL). It does NOT restore
    // the validate<->revoke serialization db_mtx_ gave, so two bounded windows
    // remain (see validate_token in the .cpp): (A) a cache-MISS validate may
    // still return a token whose revoke committed during its own execution,
    // and (B) the cache-HIT path returns the cached value during the revoke's
    // UPDATE->invalidate_cache window. Both are single-in-flight-request
    // windows — neither permits a NEW authentication after revoke_token()
    // returns (the next uncached validate SELECTs revoked=true, and the cache
    // is never poisoned past the TTL). A proper close (SELECT ... FOR UPDATE
    // in the revoke txn, or a per-token version column) is tracked in #2173.
    // Keep every fetch_add and every snapshot/re-check.
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
