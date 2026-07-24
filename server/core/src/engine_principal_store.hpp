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
///
/// ## The revalidation cache (#2367) — deliberately NOT on the auth chokepoint
///
/// Every live MCP/SSE stream re-validates its credential on each ~3 s pump
/// tick. The token row itself is served from `ApiTokenStore`'s 60 s cache, so
/// for an ENGINE principal the extra `get_for_auth` hop was the only uncached
/// read on that path: one Postgres round-trip per engine stream per tick,
/// each a bounded `try_acquire_for` on a pool of ~16 connections. That is
/// absorbable in steady state and self-amplifying under a pool brownout —
/// `StoreUnreachable` -> `kIndeterminate` -> every engine stream stays in its
/// grace window and KEEPS retrying, N waiters starving ordinary
/// `validate_token` and the fleet data plane with it.
///
/// So `get_for_auth_revalidate()` adds a short-TTL positive cache — and ONLY
/// that method. `get_for_auth()` stays uncached and authoritative. Which
/// question is being asked decides whether a cached answer is admissible:
///
///   - A LIVENESS RE-CHECK asks "may this already-authenticated stream keep
///     running?". The stream was authenticated authoritatively at attach, and
///     the pump grants it a bounded grace window when the store cannot be
///     reached at all — so a recent answer is proportionate here.
///   - A FRESH AUTHORIZATION DECISION tolerates no staleness. Session
///     synthesis (`synthesize_token_session`) and the MCP/REST on-behalf-of
///     target checks keep reading through to Postgres every time, so revoking
///     a principal still stops new sessions and new delegations instantly.
///
/// A cached answer is NOT reported as a re-confirmation. `EngineRevalidate`
/// carries `from_cache`, the caller turns that into
/// `auth::CredentialCheck::kValidStale`, and the pump measures its grace
/// budget from the last AUTHORITATIVE confirmation. Without that, cache
/// residency and the grace window would ADD: a stream would ride the cache and
/// then collect a full fresh grace window once it expired. With it, total
/// survival past a real confirmation stays bounded by the grace window, and
/// `kAuthCacheTtl` is sized well under that window so an aged entry still
/// leaves useful grace (see the constant).
///
/// Only `Active` is cached. `MissingOrRevoked` is not (terminal and rare — the
/// alerting path — and negative-caching it would need `create()` invalidation
/// to avoid masking a fresh principal). `StoreUnreachable` is not cached
/// either, but it IS rate-limited: a short jittered backoff repeats that
/// answer without taking a lease, because otherwise the positive cache fixes
/// only the warm steady state and the per-tick amplifier returns intact the
/// moment entries age out during a sustained brownout.
///
/// Revocation latency on the cached path: the writing replica invalidates
/// synchronously in `revoke()`/`transfer_owner()`, so a single-server
/// deployment (the shipped posture) cuts the stream on the next tick. Across
/// replicas the window is bounded by `kAuthCacheTtl` — the same residual
/// property `ApiTokenStore`'s token cache already carries.

#include <atomic>
#include <chrono>
#include <cstddef>
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

/// Result of `get_for_auth_revalidate` (#2367) — liveness only, no row.
///
/// `from_cache` is not a diagnostic: it is the difference between "the store
/// confirmed this principal just now" and "the store confirmed it up to
/// `kAuthCacheTtl` ago". The caller must propagate that distinction (as
/// `auth::CredentialCheck::kValidStale`) so a held-open stream keeps measuring
/// its grace budget from the last AUTHORITATIVE confirmation. Collapsing it
/// into a plain "valid" makes cache residency and the grace window additive.
/// It is only ever true alongside `Active` — a miss reads through, so
/// `MissingOrRevoked` and `StoreUnreachable` are always authoritative.
struct EngineRevalidate {
    EngineLookupStatus status = EngineLookupStatus::StoreUnreachable;
    bool from_cache = false;
};

class EnginePrincipalStore {
public:
    /// Clock used for revalidation-cache TTL, jitter, and failure backoff.
    /// Injectable for tests only — see `set_clock_for_test`.
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;

    /// How long a positive liveness answer may be reused (#2367). PUBLIC
    /// because it is not an implementation detail: it is the staleness bound
    /// a consumer needs in order to keep its own freshness arithmetic honest,
    /// and it is COUPLED to `McpStreamPump`'s revalidate grace window — the
    /// TTL must stay well under it, or an aged entry leaves no usable grace
    /// and an outage cuts engine streams instantly. `auth_routes.cpp` carries
    /// a static_assert pinning that relationship so a future edit to either
    /// constant fails the build instead of silently degrading availability.
    static constexpr auto kAuthCacheTtl = std::chrono::seconds(15);

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
    /// not-found — it is for admin/test reads only). Always reads through to
    /// Postgres: a fresh authorization decision is never served from cache.
    [[nodiscard]] EngineLookup get_for_auth(const std::string& principal_id) const;

    /// LIVENESS RE-CHECK ONLY — the per-tick "is this already-authenticated
    /// stream's backing principal still alive?" question, served from a
    /// `kAuthCacheTtl` positive cache (#2367; rationale in the file doc
    /// comment). Same three-state status contract as `get_for_auth`.
    ///
    /// NEVER use this to make a FRESH authorization decision — not for
    /// session synthesis, not for an on-behalf-of target check, not for a
    /// route's admission gate. Those must call `get_for_auth`. A cached
    /// `Active` is evidence that the principal was live within the TTL; that
    /// is enough to let an EXISTING stream keep running, and not enough to
    /// admit anything new.
    ///
    /// Returns NO row, deliberately. The only consumer branches on status, and
    /// withholding the row means a cached answer can never be mistaken for
    /// authoritative metadata (a cached `owner_username` is exactly the kind of
    /// thing a future caller would read without noticing it may be a minute
    /// old). It also keeps a cache hit allocation-free.
    [[nodiscard]] EngineRevalidate
    get_for_auth_revalidate(const std::string& principal_id) const;

    /// Drop `principal_id` from the revalidation cache (empty string = clear
    /// all). Called synchronously by this store's own lifecycle writers; also
    /// public so a future replication/notify hook can invalidate on a peer's
    /// write without reaching into internals.
    void invalidate_revalidate_cache(const std::string& principal_id = {});

    /// Revalidation-cache counters (observability parity with
    /// `ApiTokenStore::cache_hits`/`cache_misses`). A miss is any lookup that
    /// had to read Postgres — absent, expired, or non-Active.
    [[nodiscard]] std::uint64_t revalidate_cache_hits() const noexcept {
        return revalidate_cache_hits_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t revalidate_cache_misses() const noexcept {
        return revalidate_cache_misses_.load(std::memory_order_relaxed);
    }
    /// Lookups answered `StoreUnreachable` from the failure backoff without
    /// taking a pool lease. This is the brownout-damping counter: a climbing
    /// value means the store is down AND the amplifier is being held off.
    [[nodiscard]] std::uint64_t revalidate_backoff_suppressed() const noexcept {
        return revalidate_backoff_suppressed_.load(std::memory_order_relaxed);
    }

    /// Number of principals with a LIVE (unexpired) cache entry. Expired but
    /// not-yet-swept entries are not counted — "resident" and "currently
    /// cached" are different facts, and reporting the former as the latter
    /// would overstate what the cache is actually serving.
    [[nodiscard]] std::size_t revalidate_cache_size() const;

    /// Test seam: override the clock used for TTL, jitter, and backoff. Call
    /// before any concurrent use. Passing an empty function restores the
    /// default `steady_clock::now`.
    void set_clock_for_test(ClockFn fn);

    /// Test seams for the RESIDENCY bound. `revalidate_cache_size()` reports
    /// what the cache is currently SERVING (unexpired only), which is the
    /// right operator-facing number but cannot observe the ceiling — an
    /// expired-but-unswept entry still occupies a slot. These report physical
    /// occupancy, so a test can prove the sweep and the decline-to-insert
    /// actually run rather than inferring it from a filtered count.
    [[nodiscard]] std::size_t revalidate_cache_resident_for_test() const;
    [[nodiscard]] std::size_t revalidate_backoff_resident_for_test() const;

    /// Test seam: shrink the entry ceiling so the full-after-sweep path is
    /// reachable without materialising `kAuthCacheMaxEntries` principals.
    /// 0 restores the default.
    void set_max_entries_for_test(std::size_t n);

    // Test-only seam (#2367), mirroring ApiTokenStore's
    // `test_hook_after_validate_select_`. Null in production (zero overhead).
    // Fires in get_for_auth_revalidate AFTER the read-through and BEFORE the
    // generation re-check + cache-write, letting a test deterministically
    // interleave a revoke at the exact poisoning point.
    std::function<void()> test_hook_after_revalidate_read_;

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
    /// One cached Active lookup. The liveness fact and when it stops counting —
    /// no row: the consumer branches on status only, and not retaining the row
    /// removes any chance of a stale `owner_username` being read as current.
    /// `expires_at` carries its jitter baked in (see the insert path).
    struct CachedAuth {
        std::chrono::steady_clock::time_point expires_at;
    };

    pg::PgPool& pool_;
    bool open_{false};

    /// Revalidation cache (#2367) — positive entries only, see the file doc
    /// comment for why this is not on `get_for_auth`.
    ///
    /// The TTL is deliberately WELL BELOW the pump's revalidate grace window
    /// (60 s), not equal to it. Total survival past the last authoritative
    /// confirmation is `cache residency + remaining grace`, and the consumer
    /// backdates its grace deadline to that last authoritative confirmation
    /// (`CredentialCheck::kValidStale`), so the sum is bounded by the grace
    /// window itself. Sizing the TTL at the full 60 s would make that bound
    /// technically hold while leaving a fully-aged entry with ZERO remaining
    /// grace — an outage would then cut engine streams instantly, strictly
    /// worse than the uncached behaviour this replaced. At 15 s the worst case
    /// still leaves 45 s of grace, while collapsing a 3 s tick 5x (and, with
    /// misses coalesced, further still).

    /// Up to `kAuthCacheTtlJitter` is subtracted per entry at insert, so entries
    /// warmed together (every stream revalidating after one outage recovers, or
    /// after a boot) do not all expire on the same tick and re-stampede the
    /// pool. Subtracted, never added — jitter must not push an entry past the
    /// TTL bound the grace arithmetic above depends on.
    /// NOTE the integer-duration arithmetic: seconds(15)/4 truncates to
    /// seconds(3), not 3.75 s. Spelled in milliseconds so the value is what it
    /// says it is.
    static constexpr auto kAuthCacheTtlJitter = std::chrono::milliseconds{3750};

    /// After a read-through that could not reach the store, further reads for
    /// that principal are suppressed and answered `StoreUnreachable` without
    /// touching the pool. Jitter is ADDITIVE here (unlike the TTL's, which is
    /// subtractive), so the real window is `kAuthFailureBackoff` to twice it —
    /// 5 s to 10 s. Extending a backoff is safe; shortening a positive TTL is
    /// the direction that must never overshoot, hence the opposite signs.
    ///
    /// This is a RATE LIMITER, not a negative cache. The distinction matters:
    /// it repeats an answer we obtained moments ago from the authoritative
    /// store, for a window far shorter than the positive TTL, and it re-probes
    /// promptly so recovery is detected fast. Without it the positive cache
    /// fixes only the warm steady state: once entries expire during a sustained
    /// brownout, every stream reads through on every ~3 s tick, each blocking
    /// up to the 1500 ms lease timeout — which is precisely the amplifier
    /// #2367 exists to remove, merely postponed by one TTL.
    static constexpr auto kAuthFailureBackoff = std::chrono::seconds(5);

    /// Hard ceiling on resident entries. Engine principals are created through
    /// a live REST/MCP surface with no store-level count limit, and an entry is
    /// otherwise only removed when that same principal is looked up again — so
    /// a principal whose streams all ended would sit resident for the process
    /// lifetime. On a full map the insert path first sweeps expired entries and
    /// then, if still full, simply declines to cache: degrading to read-through
    /// is slower, never wrong.
    static constexpr std::size_t kAuthCacheMaxEntries = 1024;
    /// Effective ceiling; `kAuthCacheMaxEntries` unless a test shrinks it.
    /// Applies to BOTH maps — the backoff map is filled precisely when the
    /// positive map is not, so bounding only one of them bounds neither.
    std::size_t max_entries_{kAuthCacheMaxEntries};

    mutable std::mutex revalidate_cache_mu_;
    mutable std::unordered_map<std::string, CachedAuth> revalidate_cache_;
    /// principal_id -> "do not touch the pool for this key before". Swept and
    /// ceiling-checked on ITS OWN insert path: an outage is the only thing
    /// that fills this map, and the positive-insert path (the other sweep
    /// site) by definition does not run during one.
    mutable std::unordered_map<std::string, std::chrono::steady_clock::time_point>
        revalidate_backoff_;

    /// Clock seam. Production leaves this as `steady_clock::now`; tests inject a
    /// controllable clock so TTL expiry, jitter bounds, and backoff windows are
    /// testable without sleeping through them. Set once before any concurrent
    /// use (there is no lock around the function object itself).
    ClockFn clock_{[] { return std::chrono::steady_clock::now(); }};
    mutable std::atomic<std::uint64_t> revalidate_cache_hits_{0};
    mutable std::atomic<std::uint64_t> revalidate_cache_misses_{0};
    mutable std::atomic<std::uint64_t> revalidate_backoff_suppressed_{0};

    /// Drop expired positive entries and elapsed backoffs. Caller holds
    /// `revalidate_cache_mu_`.
    void sweep_expired_locked(std::chrono::steady_clock::time_point now) const;

    /// TOCTOU guard against cache POISONING, copied from
    /// `ApiTokenStore::revoke_generation_` including its hard-won ordering
    /// rule: a writer bumps this BEFORE it takes `revalidate_cache_mu_`, and
    /// a reader re-checks it UNDER that mutex, in the same critical section as
    /// the insert. A check-then-lock ordering leaves a real window — the
    /// writer's erase runs between the reader's check and its insert (erasing
    /// nothing, because nothing is inserted yet), after which the reader
    /// installs a stale `Active` that survives the full TTL. Holding the lock
    /// across re-check AND insert serializes the pair against the erase:
    /// either the reader observes the bump and skips, or the erase lands
    /// strictly after the insert and removes it.
    ///
    /// This guards the CACHE only. It does not serialize an in-flight
    /// revalidate against a concurrent revoke: a principal revoked during a
    /// revalidate's own execution may be reported Active once. Bounded (the
    /// next tick reads through) and inside the pump's grace window by
    /// construction.
    std::atomic<std::uint64_t> revoke_generation_{0};
};

} // namespace yuzu::server
