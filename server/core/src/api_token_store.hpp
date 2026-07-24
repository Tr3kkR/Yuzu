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
/// authoritative posture; do not soften to fail-open). Reads split by
/// role: `validate_token` is the auth hot path and degrades to `nullopt`
/// on a DB error (the per-request status label already carries the 401);
/// `get_token`/`list_tokens` are authoritative (ADR-0012 §1) and surface
/// a runtime DB error as `std::unexpected` rather than an empty/not-found
/// that would paper over an outage — see their per-method contracts below.
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

    // Overlap-pair rotation (design doc §7, schema v2, plan PR 4.3). Empty /
    // 0 for every token that has never participated in a rotation.
    std::string rotation_group;      // Links a predecessor/successor pair; shared by both.
    std::string supersedes_token_id; // Successor -> predecessor token_id; empty on the predecessor.
    int64_t overlap_expires_at{0};   // Predecessor's scheduled auto-revoke instant; 0 = not rotating.
    int64_t confirmed_at{0};         // Set when an operator confirms cutover; 0 = unconfirmed.
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

    /// Outcome of `validate_token_checked` — the tri-state `validate_token`
    /// deliberately collapses. A held-open SSE stream must be able to tell
    /// "this credential is definitively gone" (kill the stream NOW) from "we
    /// cannot reach the store to find out" (ride out a bounded grace window
    /// rather than cut every live stream on the fleet at once) — ADR-1005
    /// Decision 15(i) / chaos CH-4. Ordinary request auth has no such need:
    /// there, "cannot tell" and "no" both mean 401, which is why
    /// `validate_token` folds them together.
    enum class TokenCheck {
        kValid,        ///< token exists, unrevoked, unexpired
        kInvalid,      ///< DEFINITIVELY absent / revoked / expired
        kUnavailable,  ///< store unreachable — indeterminate, NOT a revocation
    };

    struct CheckedToken {
        TokenCheck status = TokenCheck::kInvalid;
        std::optional<ApiToken> token;  ///< engaged iff kValid
    };

    /// `validate_token` with the failure mode preserved. The extra store probe
    /// runs ONLY on the negative path (a valid token — the steady state for a
    /// live stream — is served from the same 60 s cache as `validate_token`, so
    /// re-validation stays O(cache-refresh), not O(streams × tick)).
    CheckedToken validate_token_checked(const std::string& raw_token);

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

    /// Active credentials for one principal: not revoked AND (expires_at==0
    /// OR expires_at>now). `token_hash` is masked ('') same as `list_tokens`.
    /// Used to enforce the design doc §7 "at most two active credentials"
    /// ceiling and to drive `rotate_engine_credential`'s state machine, and
    /// by the admin console to show live credential counts.
    [[nodiscard]] std::vector<ApiToken>
    list_active_for_principal(const std::string& principal_id) const;

    /// Overlap-pair credential rotation for an engine principal (design doc
    /// §7). `now` is caller-supplied epoch seconds (not read from the wall
    /// clock internally) so callers control the instant every window/floor
    /// check is evaluated against. `requesting_user` is the human operator
    /// driving this call (route layer's authenticated session) — it is
    /// stamped on a fresh mint's grace-cache entry and enforced on a
    /// same-window re-serve (Hermes F4): a DIFFERENT operator may never
    /// re-serve another admin's in-flight successor secret.
    ///
    /// Hermes F1: the ENTIRE check -> mint -> stamp sequence below runs
    /// inside ONE `pg::PgPool::with_txn_for` transaction that opens with
    /// `SELECT pg_advisory_xact_lock(hashtext($principal_id))` — this
    /// serializes concurrent `rotate_engine_credential`/`confirm_rotation`
    /// calls for the SAME principal (across server instances, since it's a
    /// Postgres-side lock, not an in-process mutex) so the active-credential
    /// count this function branches on is re-read fresh, under the lock,
    /// never the caller's own pre-lock snapshot. The ≤2 ceiling holds even
    /// under concurrent rotate calls for the same principal.
    ///
    /// Hermes F2: the successor's INSERT and the predecessor's pair-stamp
    /// UPDATE commit inside that SAME locked transaction — never two
    /// separate transactions — so a crash between mint and stamp is
    /// impossible; a successful rotate always leaves both rows linked. The
    /// engine-referential-integrity check (`engine_referent_check_`) and raw
    /// secret generation (CSPRNG) run BEFORE the transaction opens (as a
    /// speculative "candidate successor"), never inside it: both call back
    /// into shared infrastructure (`engine_referent_check_` acquires its own
    /// lease from this store's same `pg::PgPool`) that would nest a second
    /// connection acquire under the txn's already-held connection —
    /// documented in `pg_pool.hpp` as self-starving a small/size-1 pool
    /// (the standard shape this store's own unit tests use). The candidate
    /// is used only if the lock-held re-read below actually finds the
    /// 1-active mint case; otherwise it's silently discarded, so a
    /// transient referent-check hiccup never blocks a re-serve or a
    /// ceiling rejection that never needed it.
    ///
    /// State machine, keyed on the principal's current active-credential
    /// count, re-read fresh under the advisory lock (see the .cpp for the
    /// full commentary):
    ///   0 active  -> rejected; caller must mint the first credential via
    ///                `create_token` directly.
    ///   1 active  -> mints a successor (§6/§7/§8 validation + the
    ///                referential check all run), stamps both rows into one
    ///                rotation pair atomically (F1/F2 above), caches the
    ///                successor's raw secret + `requesting_user` for the
    ///                grace window, and returns the raw secret (one-time-
    ///                reveal contract).
    ///   2 active  -> a rotation is already in flight. Within
    ///                `kRotationGraceSecs` of the successor's mint AND while
    ///                its raw secret is still cached, re-serves the SAME raw
    ///                value (idempotent retry, design doc §7 bullet 1) — but
    ///                ONLY to the SAME `requesting_user` who initiated it
    ///                (F4); a different operator is rejected with
    ///                "rotation in progress by a different operator"
    ///                regardless of the grace window's remaining time. The
    ///                per-reveal audit + step-up re-validation that gates a
    ///                replay happen at the ROUTE layer, not here. Once the
    ///                grace window lapses (or the cache entry is gone),
    ///                rejected — the caller falls back to the compromise
    ///                runbook (principal-level revoke) or an explicit
    ///                re-mint, never an indefinite retry.
    ///   >2 active -> defensive rejection; this function's own 1-active arm
    ///                is the only mint path it drives, so this state means a
    ///                credential was minted outside `rotate_engine_credential`
    ///                (e.g. a direct `create_token` call) and must be
    ///                resolved manually, not silently arbitrated.
    ///
    /// The overlap window itself is rejected outright — never silently
    /// truncated — if `overlap_secs` is below the 24h floor, or if
    /// `now + overlap_secs` would exceed either credential's own expiry.
    [[nodiscard]] std::expected<std::string, std::string>
    rotate_engine_credential(const std::string& principal_id, int64_t overlap_secs, int64_t now,
                             const std::string& requesting_user);

    /// Operator-confirmed cutover (design doc §7 bullet 3, Hermes F5): while
    /// a rotation pair is in flight, sets the successor's `confirmed_at =
    /// now`, immediately revokes the predecessor (rather than waiting for
    /// the overlap window to elapse), clears the successor's rotation state
    /// (`rotation_group`/`supersedes_token_id`/`overlap_expires_at` ->
    /// defaults, `confirmed_at` retained as a historical marker), and evicts
    /// the grace-cache entry. Advisory-locked exactly like
    /// `rotate_engine_credential` (same `pg_advisory_xact_lock` on
    /// `principal_id`, same single-transaction commit for the confirm +
    /// revoke + clear triple) so it can't race a concurrent rotate/confirm/
    /// sweep for the same principal.
    ///
    /// Only the `requesting_user` who initiated the rotation (the operator
    /// bound into the grace-cache entry at mint time, F4) may confirm it —
    /// a different operator's call is rejected with "rotation in progress
    /// by a different operator", the same message F4 uses, never a silent
    /// no-op. Unlike the raw-secret re-serve, this identity check is NOT
    /// time-bounded to `kRotationGraceSecs` — the overlap window (default 7
    /// days) vastly outlives the short raw-reveal grace window, so the
    /// grace-cache entry's `requesting_user` is retained (not pruned by
    /// elapsed time, only evicted explicitly — see `grace_entry_owner`'s
    /// doc comment) for as long as the rotation stays unresolved. A process
    /// restart forfeits this binding along with the raw-secret re-serve
    /// capability (same documented limitation as the grace cache generally)
    /// — a confirm attempted after a restart is rejected with "rotation
    /// confirmation unavailable", not silently allowed for any caller.
    ///
    /// Rejected (no DB mutation) when there is no in-flight, recognizable
    /// rotation pair for `principal_id`. Since #2404 the rejection is
    /// state-discriminated (classifier: `rotation_confirm_state.hpp`) so a
    /// replay after the rotation already resolved gets a TERMINAL conflict the
    /// caller maps to 409/kInvalidParams, NOT the old blanket retryable error:
    ///   - 0 active, or 2 active that aren't a linked pair -> "no in-flight
    ///     rotation to confirm" (RETRYABLE/Transient: 0-active is ambiguous
    ///     with a swallowed read failure, and a malformed pair is kept
    ///     conservative);
    ///   - >2 active -> "more than two active credentials ..." (terminal,
    ///     manual resolution) — mirrors `rotate_engine_credential`;
    ///   - 1 active with UNCLEARED rotation linkage -> "... unresolved
    ///     rotation metadata ... do not rotate ..." (terminal; rotating would
    ///     strand a malformed pair, #2404 F1);
    ///   - 1 active, linkage clear, pin matches -> "rotation already
    ///     confirmed ..." (`confirmed_at != 0`) or "no rotation in flight ...
    ///     already the sole active credential ..." (`confirmed_at == 0`,
    ///     resolved by never-rotated / sweep / revoke) — both terminal;
    ///   - 1 active, linkage clear, pin does NOT match -> "... the rotation
    ///     was resolved ..." (terminal).
    /// `confirmed_at` is a sound discriminator ONLY on the pin-MATCH arm: it
    /// is written solely by confirm, solely on a successor row, and a row is a
    /// successor exactly once — so `row.confirmed_at != 0` means precisely
    /// "the rotation in which THIS row was successor was confirmed". It is a
    /// historical marker retained across later rotations, so it is NEVER used
    /// to attribute a non-matching pin's resolution cause.
    ///
    /// `token_id` pins the exact rotation being confirmed (#2384): it must
    /// equal the pending pair's SUCCESSOR `token_id` — the value the rotate
    /// call returned to the caller — or the confirm is rejected (no DB
    /// mutation) with "token_id does not match the pending rotation
    /// successor". Without the pin, a blind same-operator retry of an old
    /// confirm could land after a SECOND rotation started and revoke that
    /// later rotation's still-live predecessor early. With it, a replay can
    /// only ever target the pair it was issued for: while that pair is
    /// pending it confirms it (once); after cutover — or once a later
    /// rotation is in flight — the stale id mismatches and nothing is
    /// written.
    [[nodiscard]] std::expected<void, std::string>
    confirm_rotation(const std::string& principal_id, const std::string& token_id,
                     const std::string& requesting_user);

    /// One rotation pair currently in flight, as read by the T12 maintenance
    /// sweep (design doc §7). `predecessor.supersedes_token_id` is always
    /// empty; `successor.supersedes_token_id == predecessor.token_id`.
    struct RotationPair {
        ApiToken predecessor;
        ApiToken successor;
    };

    /// T12 sweep, half 1 — auto-revoke (design doc §7 bullet 3): revokes
    /// every predecessor whose overlap window has elapsed
    /// (`overlap_expires_at > 0 AND overlap_expires_at <= now`, not yet
    /// revoked) and clears the SURVIVING successor's rotation state
    /// (`rotation_group`/`supersedes_token_id`/`overlap_expires_at` ->
    /// defaults — "revocation during overlap ... resolves the rotation
    /// state", §7) so a fresh rotation may begin. `now` is caller-supplied,
    /// same contract as `rotate_engine_credential`.
    ///
    /// Idempotent: re-running finds nothing to revoke once every eligible
    /// predecessor is already revoked (the per-row UPDATE is itself
    /// `WHERE revoked = FALSE`, so a race with a concurrent manual revoke
    /// degrades to a no-op, never a double-revoke or an error). Each
    /// predecessor's revoke + its successor's rotation-state clear commit
    /// atomically together — Hermes F3: the clear UPDATE's own result is
    /// checked; a genuine execution failure on it (not merely "matched zero
    /// rows", which is the expected idempotent case when the successor is
    /// already gone/resolved) rolls back the WHOLE transaction, including
    /// the predecessor's revoke, so "revocation ... resolves the rotation
    /// state, or neither" (§7) is a real guarantee, not just a comment.
    /// Each per-row transaction also opens with the same principal-scoped
    /// `pg_advisory_xact_lock` `rotate_engine_credential`/`confirm_rotation`
    /// take, so this sweep can't race a concurrent manual rotate/confirm
    /// for the same principal (never a revoked predecessor left with a
    /// successor still mid-rotation). Returns the predecessors actually
    /// revoked this call (`principal_id`/`token_id` populated,
    /// `token_hash` masked same as every other read here) — design doc §7
    /// "every step audits", so the caller can emit one audit row per
    /// revoked credential rather than a single aggregate line. Empty on an
    /// unreachable store (fail-closed: a missed tick simply delays the
    /// revoke to the next tick, it never extends the window itself, which
    /// is stamped in the row and evaluated fresh every call).
    /// `tick_failed` (optional out-param): set to `true` when the tick could
    /// not run to completion — the pool lease timed out, or the predecessor
    /// scan query failed — so the caller can bump
    /// `yuzu_engine_principal_rotation_sweep_failures_total`. Since this sweep
    /// is the SOLE enforcement of predecessor auto-revoke (`validate_token`
    /// never checks `overlap_expires_at`), a silently-swallowed failed tick
    /// would let rotated-out credentials outlive their window with the alert at
    /// zero. Left `false` on a clean tick (including one that revoked nothing).
    std::vector<ApiToken> sweep_expired_rotations(int64_t now, bool* tick_failed = nullptr);

    /// T12 sweep, half 2 (operational-health signal, design doc §7 bullet 2)
    /// — read-only. Returns every in-flight rotation pair whose predecessor
    /// overlap window ends within `warn_within_secs` of `now` (but has not
    /// yet elapsed — an already-elapsed window is `sweep_expired_rotations`'s
    /// job, not a warning) AND whose successor has never been presented
    /// (`last_used_at == 0`). The caller (server.cpp's maintenance loop)
    /// turns each returned pair into an `engine_principal.rotation.
    /// successor_unused` audit row plus a bounded `reason="successor_unused"`
    /// Prometheus counter — deliberately NOT `event="security"` (this is an
    /// operational health signal, not a theft signal, per the design doc).
    /// Best-effort, mirrors `list_all`: a lease/query failure logs at warn
    /// and returns an empty vector rather than propagating — this is a
    /// maintenance-loop read, not an authorization chokepoint.
    std::vector<RotationPair> list_rotations_nearing_expiry_unused(int64_t now,
                                                                    int64_t warn_within_secs) const;

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

    // ── Overlap-pair rotation (design doc §7) ───────────────────────────
    //
    // Floor below which an overlap window is rejected outright rather than
    // silently truncated — a module that never gets a chance to pick up the
    // successor within the window is a worse failure than a rejected
    // `rotate` call.
    static constexpr int64_t kOverlapFloorSecs = 24 * 3600;

    // Ceiling above which an overlap window is rejected outright — without
    // this, an unfloored-but-unbounded caller value fed into
    // `now + overlap_secs` is an unchecked signed int64 add (UB on
    // overflow, and a wrapped-negative `window_end` would slip past the
    // expiry guards it's meant to enforce). 10 years is generously above
    // any legitimate overlap (the credential itself is capped to 90 days,
    // §7), so this never constrains a real caller.
    static constexpr int64_t kOverlapCeilSecs = 3650LL * 24 * 3600;

    // Grace window shape reused from §5's redemption-retry bound
    // (minutes-scale, single-digit default): how long a `rotate` retry may
    // re-serve the same successor secret, and how long its raw value stays
    // in the in-memory cache below. Deliberately NOT "until the module
    // presents the successor" — that condition is attacker-influenceable.
    static constexpr std::chrono::seconds kRotationGraceSecs{120};

    // Raw secret cache for the rotation grace window, keyed by
    // `rotation_group`. RAM-only, process-local — the raw value is NEVER
    // persisted (same one-time-reveal contract as `create_token`), and a
    // process restart forfeits re-serve (acceptable per §7: the caller falls
    // back to an explicit re-mint or the compromise runbook). `raw` reveal
    // is refused (by `try_reserve`, on lookup) once older than
    // `kRotationGraceSecs`, and the plaintext itself is actively scrubbed
    // (`yuzu::secure_zero`, not just left unreachable) by
    // `scrub_elapsed_grace_secrets` — called from `sweep_expired_rotations`'s
    // maintenance tick — the moment it crosses that same age, rather than
    // sitting resident in RAM for the rest of the (much longer) overlap
    // window. The entry itself, notably `requesting_user` (Hermes F4), is
    // NOT erased by either the staleness check or the scrub: `confirm_rotation`
    // (F5) needs the initiator binding to stay resolvable for the whole
    // overlap window (default 7 days), far outliving the short raw-reveal
    // grace window. The entry is only removed by an explicit
    // `evict_rotation_raw` call (confirm_rotation on success, or the sweep's
    // auto-revoke resolving the pair) — never a background timer.
    struct RotationGraceEntry {
        std::string raw;
        // Hermes F4/F5: the operator (route-layer authenticated session)
        // who initiated this rotation via `rotate_engine_credential`'s
        // 1-active mint arm. Binds both the grace-window re-serve (F4) and
        // `confirm_rotation` (F5) to that SAME caller — never served to,
        // or confirmable by, a different operator.
        std::string requesting_user;
        std::chrono::steady_clock::time_point minted;
    };
    mutable std::mutex rotation_cache_mtx_;
    mutable std::unordered_map<std::string, RotationGraceEntry> rotation_grace_cache_;

    /// Grace-cache accessor: true + `out_raw`/`out_requesting_user` set when
    /// `rotation_group` has an entry AND it is still within
    /// `kRotationGraceSecs` of its mint. Past the grace window (but the
    /// entry still present) returns false with `out_requesting_user` still
    /// populated (so a caller that wants identity-only, not the raw reveal,
    /// can still resolve it — see `grace_entry_owner` below for that use).
    /// Used internally by `rotate_engine_credential`'s 2-active re-serve
    /// arm. Never erases the entry — see the `RotationGraceEntry` doc
    /// comment for why.
    bool try_reserve(const std::string& rotation_group, std::string& out_raw,
                     std::string& out_requesting_user) const;

    /// Identity-only grace-cache accessor, NOT time-bounded to
    /// `kRotationGraceSecs` (unlike `try_reserve`'s raw reveal) — used by
    /// `confirm_rotation` (Hermes F5) to bind the confirm to the same
    /// operator who initiated the rotation, for as long as the entry
    /// remains (until explicitly evicted). False if no entry exists for
    /// `rotation_group` (e.g. a process restart since the mint, or the
    /// rotation already resolved).
    bool grace_entry_owner(const std::string& rotation_group,
                           std::string& out_requesting_user) const;

    /// Removes a grace-cache entry outright. Called once a rotation
    /// resolves (`confirm_rotation` on success; the T12 sweep's auto-revoke
    /// on the predecessor's window elapsing) so the entry doesn't linger in
    /// RAM after it can no longer be looked up by any live rotation state
    /// (rotation_group values are derived from a fresh token hash each
    /// mint, so a stale unevicted entry is otherwise inert, not a
    /// correctness risk — this is hygiene, not a security fix).
    void evict_rotation_raw(const std::string& rotation_group);

    /// Design §7 ("revocation during overlap ... resolves the rotation
    /// state"): when `revoke_token`/`delete_token` removes ONE credential of an
    /// in-flight rotation pair, the surviving partner must not be left mid-
    /// rotation. Clears the partner's rotation columns
    /// (`rotation_group`/`supersedes_token_id`/`overlap_expires_at` -> defaults)
    /// so (a) a revoked-predecessor's successor becomes a standalone active
    /// credential, and (b) a revoked-successor's predecessor is no longer a
    /// sweep target (its `overlap_expires_at` is cleared) — without which the
    /// T12 sweep would later auto-revoke the principal's ONLY remaining
    /// credential as routine `overlap_window_elapsed`. Advisory-locked on
    /// `principal_id` (serializes with rotate/confirm/sweep) and evicts the
    /// grace-cache entry. No-op when `rotation_group` is empty (the common
    /// non-rotation revoke). Best-effort: a failure here does not un-revoke the
    /// token the caller already committed.
    void resolve_rotation_pair_after_revoke(const std::string& principal_id,
                                            const std::string& rotation_group,
                                            const std::string& revoked_token_id);

    /// Caches a freshly-minted successor's raw secret + initiating operator
    /// for the grace window (Hermes F4).
    void store_rotation_raw(const std::string& rotation_group, const std::string& raw,
                            const std::string& requesting_user);

    /// Secret-hygiene sweep, distinct from `sweep_expired_rotations`'s
    /// DB-side auto-revoke half: scrubs (`yuzu::secure_zero`) every
    /// grace-cache entry's `raw` once it is past `kRotationGraceSecs`,
    /// WITHOUT erasing the entry itself — `requesting_user` (Hermes F4/F5)
    /// must stay resolvable for the whole overlap window. Without this, the
    /// plaintext successor secret would otherwise sit resident in RAM for
    /// up to the full overlap window (default days), long after
    /// `try_reserve` stops re-serving it. Called from
    /// `sweep_expired_rotations`'s maintenance tick; safe to call more
    /// often (idempotent — an already-empty `raw` is a no-op).
    void scrub_elapsed_grace_secrets();

    /// §6/§7/§8 engine-mint validation shared by `create_token`'s engine
    /// block and `rotate_engine_credential`'s candidate-successor prep
    /// (Hermes F2 — see the .cpp for why this runs OUTSIDE the locked
    /// transaction rather than being folded into it). Pure/cheap checks
    /// (scope/tier/TTL) plus the one external call, `engine_referent_check_`
    /// (referential integrity against `EnginePrincipalStore`, §6).
    [[nodiscard]] std::expected<void, std::string>
    validate_engine_mint(const std::string& principal_id, const std::string& scope_service,
                        const std::string& mcp_tier, int64_t expires_at, int64_t now) const;

    /// Generate a fresh `yuzu_` Bearer token from the platform CSPRNG.
    /// Returns the raw token on success; std::unexpected when the system
    /// entropy source is unavailable (caller must surface as 503, never
    /// fall back to weak entropy). See `secure_random.hpp` for details.
    std::expected<std::string, std::string> generate_raw_token() const;
    std::string sha256_hex(const std::string& input) const;
    void invalidate_cache(const std::string& token_hash);
};

} // namespace yuzu::server
