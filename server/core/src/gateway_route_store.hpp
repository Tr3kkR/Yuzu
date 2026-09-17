#pragma once

/// @file gateway_route_store.hpp
/// HA WS-4 slice 4.1: the fenced agent→cluster **routing directory**. Records
/// which gateway cluster/node currently holds each agent's live gRPC stream,
/// so a future dispatch surface (NOT this slice — see below) can route a
/// command to the gateway actually holding the connection instead of relying
/// on the single-process `AgentRegistry` that active-active replicas cannot
/// share.
///
/// INERT IN 4.1: this store is written on connect/disconnect but nothing
/// reads it for dispatch decisions yet — that wiring is a later WS-4 slice.
/// Getting the writer path (and its anti-replay fence) right FIRST, before any
/// reader depends on it, is deliberate.
///
/// THE FENCE (why `connection_epoch` exists) — and what it does NOT do.
/// `register_fresh` mints a fresh epoch (`gateway_route_store.connection_epoch_seq`)
/// at ProxyRegister PROCESSING time and the guarded UPSERT only accepts an epoch
/// numerically GREATER than the row's current one (`WHERE EXCLUDED.connection_epoch
/// > agent_routes.connection_epoch`). Its job is to order CONCURRENT fresh
/// registrations for one agent: when two race, the later committer wins and the
/// earlier one is told `won=false` — mirroring the `LeaderElector`/
/// `CommandOutboxStore` epoch-fence shape (per-agent, not per-lock). It does NOT
/// fence a STALE/delayed replay: because the epoch is minted at processing time,
/// a replay handled later mints a HIGHER epoch and WINS the fresh branch (see the
/// 4.2 OBLIGATIONS note below). Stale-connection protection comes entirely from
/// the re-announce branch (reusing a still-known session) + the SESSION GUARDS
/// below — NOT from the epoch.
///
/// SESSION GUARDS (`announce_connected` / `deregister`). Once a connection has
/// won the epoch race and is recorded, its FOLLOW-UP notifications
/// (`announce_connected` filling in cluster/node once the gateway has fully
/// established the session, and the eventual `deregister` on disconnect) are
/// guarded by `session_id`, not by epoch — they only touch the row if it still
/// belongs to THIS session. A stale CONNECTED/DISCONNECTED from a DIFFERENT,
/// already-superseded session therefore cannot overwrite or tear down a
/// newer re-home: `announce_connected` no-ops (falls through to an
/// `ON CONFLICT DO NOTHING` insert) if the session doesn't match, and
/// `deregister` tombstones zero rows.
/// LIMIT (as of 4.2a) — a SAME-session late notification was NOT fenced by
/// `session_id` alone: the re-announce path deliberately REUSES the session
/// id, so `session_id` equality cannot distinguish an old home's teardown
/// from a newer re-home under the same id. This was unreachable under the
/// shipped gateway (at most one `CONNECTED(S)` and one `DISCONNECTED(S)` per
/// session — see the #4246 #4 bullet in ADR-2002 §7). SLICE #4324 below adds
/// the per-home generation (`stream_home_id`) that closes this gap
/// end-to-end (store predicate below AND the RPC-handler wiring in
/// `gateway_service_impl.cpp` — CLOSED, both halves, as of #4324 task 3/3).
/// Invariant to preserve: `session_id` ≡ exactly one gateway stream
/// placement.
///
/// SLICE #4324 (HA WS-4, store layer) — `stream_home_id` is an opaque,
/// per-connection-instance id (minted once per gateway process instance,
/// task 1 of #4324) stamped on both the CONNECTED and DISCONNECTED
/// notification a given stream instance ever sends. `announce_connected`
/// writes it into the row on every winning placement write, exactly like
/// `cluster_id`/`gateway_node` (it IS placement, not a session property —
/// `announce_connected` stays the sole writer of it); `register_fresh` NULLs
/// it on a winning re-register for the same reason it NULLs `cluster_id`/
/// `gateway_node` (4.2b Task A). `deregister`'s tombstone predicate is
/// `stream_home_id IS NULL OR stream_home_id = $3` — an EMPTY/NULL stored
/// home ADMITS ANY incoming `$3` (stamped or not); a STAMPED stored home
/// requires an EXACT match. This closes the SESSION GUARDS LIMIT above for a
/// rolling gateway upgrade (mixed-version cluster is the NORMAL state of
/// one): an old-build gateway node's late DISCONNECTED — unstamped — must
/// not tombstone a new-build node's stamped re-home reusing the same session
/// id (a stamped `$3` never satisfies `stream_home_id IS NULL` against a
/// stamped stored value, and `stream_home_id = $3` needs an exact match), but
/// a genuinely-matching stamped DISCONNECTED must still tear down its own
/// stamped row, and a legacy DISCONNECTED against a legacy (never-stamped,
/// stored-NULL) row must still behave exactly as before. The naive symmetric
/// predicate (`$3 = '' OR stream_home_id = $3`) would let ANY unstamped
/// DISCONNECTED tear down ANY row regardless of its stamped home id,
/// re-opening exactly this race — do not "fix" this predicate back to that
/// shape. `reap_stale_routes`'s tombstone sweep NULLs `stream_home_id`
/// alongside `session_id`/`lease_until`/`cluster_id`/`gateway_node` for the
/// same reason: a tombstoned row must have a fully cleared placement. CLOSED
/// under today's shipped-gateway producer invariant (#4324 task 3/3): the
/// RPC handler (`gateway_service_impl.cpp`'s `NotifyStreamStatus`) threads
/// the caller's REAL `stream_home_id` into both `announce_connected` and
/// `deregister`, AND resolves an identical fence against `AgentRegistry`'s
/// in-memory `gateway_stream_home_id` — resolved ONCE, at the top of the
/// DISCONNECTED branch, before ANY of the registry-clear/store-deregister/
/// session-map-erase effects run (all-or-nothing; see that handler's own
/// comment for why splitting them is a correctness bug, not a style choice).
/// A gateway build predating #4324 (empty `stream_home_id` on every call) is
/// unaffected — a stored-NULL row always admits an empty incoming value too.
///
/// PREDICATE FIX (PR #4492 review, HIGH, fixed pre-merge): the ORIGINAL form
/// of this predicate was `stream_home_id = $3 OR (stream_home_id IS NULL AND
/// $3 = '')` — requiring the INCOMING value to ALSO be empty before a
/// stored-NULL row would admit it. That was wrong: a stored-NULL home does
/// NOT only mean "legacy, never stamped" — under the single-producer
/// invariant it can equally mean "this session's own `announce_connected`
/// (called from the CONNECTED branch) simply hasn't run yet." The gateway
/// dispatches CONNECTED and DISCONNECTED as two independently
/// `spawn_monitor`'d RPC workers with NO ordering guarantee between them
/// (`yuzu_gw_upstream.erl`), so an ORDINARY connect/disconnect — no re-home,
/// no second CONNECTED/DISCONNECTED pair, just the FIRST and ONLY one for a
/// brand-new session — can have its DISCONNECTED reach this server before
/// its own paired CONNECTED. The original predicate rejected that stamped,
/// entirely legitimate DISCONNECTED (stored NULL, incoming non-empty), so
/// the deregister/fence silently no-opped, and the delayed CONNECTED then
/// published a route for an already-dead stream — a regression vs. the
/// pre-#4324 unfenced behavior, where the same reordering self-corrected.
/// This is DIFFERENT FROM, and reachable WITHOUT, the FORWARD NOTE gaps
/// below (which all require a producer of a SECOND CONNECTED/DISCONNECTED
/// pair for the same session — live re-home, not shipped until 4.3/4.4); it
/// needed only the ordinary FIRST pair, reordered, which is reachable today
/// under ordinary operational churn. The identical gap existed in the
/// in-memory fence (`gateway_service_impl.cpp`'s `home_matches`) and is
/// fixed there the same way — the two predicates must never diverge.
///
/// SCOPE OF "CLOSED" (adversarial review, 2026-09-17): the fence is a
/// check-then-act, not a single atomic operation — `gateway_stream_home_id()`
/// reads and releases `stream_mu` before the three DISCONNECTED effects run
/// under their own separate lock acquisitions. Under the CURRENT shipped
/// gateway this remains safe with the predicate fix above, because at most
/// one `CONNECTED(S)` and one `DISCONNECTED(S)` are ever emitted per session
/// id (see the SESSION GUARDS LIMIT above) — there is no producer of a
/// second, genuinely concurrent `CONNECTED(S, home2)` for the fence's
/// read-then-act window to race against. "CLOSED end-to-end" means closed
/// against every interleaving that invariant permits (which, after the
/// predicate fix, now correctly includes an out-of-order first pair), NOT
/// atomic against arbitrary concurrent RPC execution for a SECOND pair. See
/// the FORWARD NOTE immediately below for what 4.3/4.4 must add before
/// same-session re-home makes that second-pair producer real.
///
/// FORWARD NOTE for #4324's 4.3/4.4 (none of the three directions below are
/// reachable today — all three require a producer of a SECOND
/// CONNECTED/DISCONNECTED pair for the SAME session id, which does not exist
/// until live re-home ships; this is distinct from the PREDICATE FIX above,
/// which was reachable with only the first, ordinary pair and is already
/// fixed):
///
/// (a) STORE-SIDE ordering gap: if a stale `DISCONNECTED(home1)` lands
/// BEFORE the new `CONNECTED(home2)` arrives (two independent RPCs with no
/// ordering guarantee between them), the tombstone wins and
/// `announce_connected`'s `ON CONFLICT DO NOTHING` fallback cannot re-arm an
/// existing tombstoned row — the re-home is silently unroutable in the
/// directory until the next full ProxyRegister.
///
/// (b) IN-MEMORY check-then-act gap (adversarial review, 2026-09-17): even
/// with (a) resolved, a stale `DISCONNECTED(home1)` that reads
/// `stored_home == home1` and PASSES the fence, followed by a genuine
/// `CONNECTED(home2)` publishing home2 for the same session BEFORE the
/// DISCONNECTED's teardown effects run, causes the (correctly-admitted-at-
/// the-time-of-its-check) stale DISCONNECTED to tear down home2's live
/// registry session and session-map entry. The durable directory row
/// survives (its `UPDATE ... WHERE` predicate is a single atomic
/// statement), but in-memory dispatch for that agent breaks until
/// reconnect/lease-TTL self-heal. This is the SAME class of gap as (a) —
/// documented, currently unreachable, 4.3/4.4-scoped — one interleaving
/// direction later.
///
/// (c) CONNECTED-reorder gap: `set_gateway_route`'s in-memory publish is an
/// unconditional REPLACE and `announce_connected`'s UPDATE is session-guarded
/// only (no home/epoch ordering) — a late/reordered `CONNECTED(home1)`
/// arriving AFTER `CONNECTED(home2)` for the same session silently re-points
/// both stores back to a dead home until the next DISCONNECTED or the 90s
/// lease TTL/reaper self-heals it.
///
/// 4.3/4.4 must either route every re-home through `register_fresh` (which
/// mints a fresh, strictly-ordered epoch — resolving (a) and (c)) and add a
/// single home-CAS registry primitive gating the DISCONNECTED-branch
/// teardown as one atomic conditional operation keyed on
/// `(agent_id, session_id, stream_home_id)` (resolving (b)), or define
/// equivalent ordering/re-arm guarantees; do not assume the equality fence
/// alone makes live re-home safe in any of the three directions above.
///
/// `renew_leases` is a single batched statement, correlated on BOTH
/// `agent_id` AND `session_id` (a parallel-array unnest() join — #4246 #10) —
/// at fleet scale a per-row renew would be one write per agent every lease
/// interval; batching keeps the steady-state write rate flat regardless of
/// fleet size. The agent_id correlation is a defense-in-depth hardening: a
/// caller that knows only a session token can no longer renew a route
/// belonging to a DIFFERENT agent.
///
/// Posture (ADR-0012 §1): as of 4.2b this store is read for dispatch as a
/// FALLBACK (only on a local-registry miss; it changes no routing outcome on a
/// single-replica deployment, where every agent is locally known). Integrity
/// lives at the reader's `routable` trust predicate, so most writes stay
/// fail-open (a degraded write is logged and returned to the caller, never
/// silently dropped); register_fresh — the row-CREATING write whose loss has no
/// other writer to repair it — is the one fail-CLOSED exception (4.2b Task B,
/// returns UNAVAILABLE).
///
/// 4.2 OBLIGATIONS (latent while INERT, load-bearing once a dispatch reader
/// exists — full list in ADR-2002 §7 "4.2 design obligations"): the "cannot
/// overwrite a newer re-home" property above is precise only for OVERWRITE, and
/// only intra-replica with a live session. The epoch orders by server PROCESSING
/// time, so a stale replay whose session has left `gateway_sessions_` takes the
/// fresh branch and wins; the re-announce reuses the session id (a late
/// DISCONNECTED would otherwise tombstone — logically tear down — the
/// re-homed route, #4/#4324 — CLOSED under today's single-producer
/// invariant by SLICE #4324 below: both the store's asymmetric predicate AND
/// the RPC-handler's `stream_home_id` wiring + `AgentRegistry` in-memory
/// fence — see the SCOPE OF "CLOSED" note above for the check-then-act
/// residual 4.3/4.4 must still close) and its known-session check is
/// per-replica in-memory; re-announce refreshes the lease, not cluster/node; and
/// a stale-lease reaper plus the fail-open->fail-closed flip must land before 4.2
/// trusts this directory for routing.
///
/// SLICE 4.2a — `deregister` TOMBSTONES instead of deleting. This closes the
/// late-CONNECTED RESURRECTION direction (#5 in the 4.2 design doc): a late
/// CONNECTED for a now-gone session no-ops against the tombstone instead of
/// reviving a dead route. It did NOT close #4 (a same-session late
/// DISCONNECTED tombstoning a newer re-home) on its own — that needed the
/// per-home generation fence SLICE #4324 below adds, now closed under
/// today's single-producer invariant (see the SESSION GUARDS LIMIT above,
/// its SCOPE OF "CLOSED" note, and ADR-2002 §7 #4246 #4). A
/// tombstone is `session_id IS NULL
/// AND lease_until IS NULL`; `connection_epoch` is retained. Rationale: a bare
/// DELETE lets `announce_connected`'s fallback `ON CONFLICT DO NOTHING`
/// INSERT resurrect a dead route if a late/reordered CONNECTED notification
/// for the just-torn-down session arrives after the DISCONNECTED that
/// deleted it — the INSERT sees no row and recreates one carrying a session
/// nobody holds. With a tombstone, that late CONNECTED's session-guarded
/// UPDATE still misses (no row has that `session_id` — NULL never equals a
/// bound parameter) and its fallback INSERT is now an `ON CONFLICT DO
/// NOTHING` against an EXISTING row (the tombstone), so it no-ops instead of
/// resurrecting. A genuine later `register_fresh` still reuses the row: its
/// freshly-minted epoch is always higher than whatever the tombstoned row
/// retained, so the guarded UPSERT wins unconditionally.
///
/// `reap_stale_routes()` is the durable-directory-hygiene reaper (#7 in the
/// 4.2 design doc) for two row shapes this store accumulates over time: (a)
/// a route whose lease has been expired for longer than a grace window (a
/// gateway that stopped renewing — crashed, network-partitioned, or the
/// agent disconnected without a clean DISCONNECTED notification), and (b) a
/// tombstoned/never-announced row (`lease_until IS NULL`) old enough that it
/// is definitely not mid-handshake. See the header comment on
/// `reap_stale_routes` for the clock-guarded-retention adoption record.
///
/// SLICE 4.2b — TASK A: `announce_connected` is the SOLE writer of
/// placement. `register_fresh`'s guarded UPSERT used to COALESCE-preserve a
/// winning row's existing `cluster_id`/`gateway_node` across a fresh
/// registration; it now NULLs both unconditionally. Without this, a
/// `register_fresh(S2)` immediately followed by a bare `renew_leases`
/// (no intervening CONNECTED) left the row reading `{session=S2, live
/// lease, cluster=S1's old placement}` — a stale-placement trap for a
/// dispatch reader that must never route to a placement its own session
/// never confirmed. `lookup_routes` (also 4.2b Task A) exposes a
/// `routable` bit computed from exactly this shape (`session_id IS NOT
/// NULL AND lease_until >= now() AND cluster_id IS NOT NULL`), so a
/// dispatch reader built against it never needs to reason about the trap
/// directly.
///
/// Born-on-Postgres (ADR-0009 fresh-start): no legacy SQLite file, no
/// backfill — this store never existed before WS-4.

#include "pg/pg_migration_runner.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// The lease TTL agents/gateways renew against — DUPLICATED from (never
/// included from) `gateway_service_impl.cpp::kGatewayRouteLeaseTtlSecs`; see
/// `gateway_route_store.cpp`'s `reap_stale_routes()` constants comment for
/// why the duplication is deliberate. Declared here, rather than staying an
/// anonymous-namespace literal in the .cpp, so `gateway_service_impl.cpp`
/// (which already transitively includes this header) can `static_assert`
/// the two constants stay equal — see that file's `static_assert` next to
/// its own `kGatewayRouteLeaseTtlSecs` (PR #4299 review, MINOR).
inline constexpr int kKnownLeaseTtlSecs = 90;

/// Grace before an expired lease is treated as truly dead by `reap_stale_routes`
/// (sweep (a)): 2x the lease TTL tolerates a FULL missed renewal cycle, not just
/// the last heartbeat's worth of jitter. HOISTED into the header (PR #4299 round
/// 4) from `gateway_route_store.cpp`'s anonymous namespace so the reap recovery
/// FLOOR below can be computed from it here; the reap-sweep cutoff in the .cpp
/// still reads this same constant.
inline constexpr int kStaleLeaseGraceSecs = 2 * kKnownLeaseTtlSecs; // 180s

/// Reap-recovery persistence window (PR #4299 round 4). A skew anomaly's
/// decline-once/drain-on-repeat recovery fires only when the SAME (anchor,
/// direction) anomaly has PERSISTED for `delta = now_ms - first_now_ms` within
/// `[kMinReapRecoveryGapMs, kMaxReapRecoveryGapMs]` (see decide_reap).
///
/// FLOOR = the liveness horizon `(grace + lease TTL) * 1000` = 270'000ms: below
/// this, a spurious forward jump's exposed routes (those whose last renewal
/// predates the jump) are not yet reap-eligible, so recovering can't tombstone a
/// still-live route. It is load-bearing for the multi-replica future — an
/// ε-later second-replica pass must NOT recover with no persistence evidence.
/// CEILING = 1h (cadence-derived with slack): past it, the anomaly is a NEW,
/// discontinuous jump rather than the same one persisting.
inline constexpr std::int64_t kMinReapRecoveryGapMs =
    static_cast<std::int64_t>(kStaleLeaseGraceSecs + kKnownLeaseTtlSecs) * 1000; // 270'000
inline constexpr std::int64_t kMaxReapRecoveryGapMs = 3'600'000; // 1h

/// Typed store failure.
enum class GatewayRouteStoreError {
    store_unavailable, ///< not open / lease timeout — the store cannot answer
    db_error,          ///< a query against an open store failed
};

/// Outcome of `register_fresh`.
struct RegisterFreshResult {
    std::int64_t epoch{0}; ///< the freshly-minted epoch for this connection attempt
    bool won{false};       ///< true iff this epoch's row is the one now stored
};

/// Outcome of `announce_connected`.
struct AnnounceResult {
    bool matched{false}; ///< true iff the UPDATE hit a row owned by this session
};

/// Outcome of `deregister`.
struct DeregisterResult {
    bool removed{false}; ///< true iff a row owned by this session was tombstoned
};

/// Outcome of `reap_stale_routes`. `clock_anomaly` mirrors
/// `SessionStore::ReapOutcome` (session_store.hpp): true iff the pass was
/// DECLINED because a clock-guard-critical reading (DB `now()` or the
/// persisted `route_meta` anchor) was unusable — implausibly ahead of, or
/// behind, the anchor, or unparseable/negative. A declined pass always reaps
/// nothing. A skew (implausibly-ahead/-behind) decline leaves the anchor
/// UNCHANGED; an unparseable/negative PERSISTED anchor instead SELF-HEALS —
/// this method is the anchor's sole writer, so a bad reading there can only
/// be corruption/tampering, and the anchor is rewritten to this pass's own
/// now_ms (never drained) so the next pass proceeds normally rather than
/// wedging forever (PR #4299 round-3 review; see
/// gateway_route_store.cpp's persisted-anchor guard and
/// docs/clock-guarded-retention.md).
///
/// MARKER OBLIGATION (PR #4299 round-3, the defect class the decide/apply
/// split in gateway_route_reap_rules.hpp closes): every lock-holding pass that
/// COMMITS writes `reap_declined_anchor_ms` exactly once — ARM or CLEAR.
/// LEAVE exists ONLY for passes that never read `now()` (the advisory-lock
/// skip) or that roll back. Any DISTINCT anomaly — a skew/direction mismatch,
/// a bad `now()` reading, OR a corrupt persisted anchor — CLEARs or re-ARMs
/// the marker; none of them LEAVES a stale recovery identity a later
/// same-direction skew could free-ride on. The bad-`now()` path in particular
/// CLEARs (it used to LEAVE — that was the round-3 defect). Because
/// `ReapDecision::marker` has no default-constructible `MarkerAction`, a
/// future reap branch that forgets this decision is a COMPILE error, not a
/// silent fourth round of the same bug. `recovered` is true iff this
/// pass was NOT declined but DID run via the decline-once/drain-on-repeat
/// recovery branch (an anomaly persisted across a full decline pass — see
/// the reap_stale_routes() header below and docs/clock-guarded-retention.md)
/// — distinct from an ordinary accepted pass, since a recovery can drain a
/// large backlog in one go and is worth its own metric outcome
/// (`yuzu_server_gateway_route_reap_total{outcome="recovered"}`, PR #4299
/// round-2 review). `clock_anomaly` and `recovered` are mutually exclusive.
/// `skipped` (PR #4299 round-2 external review) is true iff another replica
/// already holds the `gateway_route_store:reap` advisory lock this tick — the
/// ReplicaSafe contract (background_jobs.hpp) is "all but the holder skip",
/// matching every sibling single-sweeper store's `pg_try_advisory_xact_lock`
/// idiom; `skipped` implies every other field stays at its default (the
/// lambda returns before reading now()/the anchor).
///
/// `cap_bound` (PR #4299 round 4, observability-only — NOT acceleration) is true
/// iff an accepted pass hit `kReapCap` on a sweep AND a same-txn `EXISTS` probe
/// (audit_store.cpp shape) confirmed a matching remainder still exists — i.e. a
/// real backlog outlives this pass. It surfaces as a distinct
/// `yuzu_server_gateway_route_reap_total{outcome="ok_capped"}` so a chronically
/// cap-bound reaper is visible WITHOUT changing cadence. Deliberately NOT wired
/// to a faster re-arm: see docs/clock-guarded-retention.md's GatewayRouteStore
/// adoption register for why acceleration is declined here.
struct ReapRoutesResult {
    int expired_leases_reaped{0}; ///< predicate (a): lease_until past the grace window
    int tombstones_reaped{0};     ///< predicate (b): NULL-lease rows past the purge age
    bool clock_anomaly{false};
    bool recovered{false};
    bool skipped{false};
    bool cap_bound{false}; ///< an accepted sweep hit kReapCap and a remainder still exists
};

/// A durable agent→cluster route, as read by `lookup_route`. Timestamps are
/// epoch-milliseconds authored by Postgres `now()` — never the process clock.
struct RouteRow {
    std::string agent_id;
    std::optional<std::string> cluster_id;
    std::optional<std::string> gateway_node;
    std::int64_t connection_epoch{0};
    std::optional<std::string> session_id;
    std::optional<std::int64_t> lease_until_ms; ///< epoch-ms, or nullopt if unset
    bool is_stale{false}; ///< computed IN-SQL: lease_until IS NOT NULL AND lease_until < now()
};

/// A route paired with the `routable` verdict computed by `lookup_routes`.
/// `routable` is IN-SQL, DB-clock-authoritative (never a replica clock, per
/// the #3715 rule): `session_id IS NOT NULL AND lease_until >= now() AND
/// cluster_id IS NOT NULL`. A tombstone (`session_id IS NULL AND lease_until
/// IS NULL`), an expired lease, or a null-placement row (a winning
/// `register_fresh` not yet followed by `announce_connected` — see the file
/// header "SLICE 4.2b") are all `routable == false`.
struct RoutableRoute {
    RouteRow route;
    bool routable{false};
};

class GatewayRouteStore {
public:
    /// Borrows the shared pool; runs the `gateway_route_store` schema
    /// migration on a pinned construction lease. `is_open()` is false if the
    /// lease was empty or the migration failed (ADR-0012 fail-closed —
    /// the caller/wiring site decides what "not open" means for boot).
    explicit GatewayRouteStore(pg::PgPool& pool);

    GatewayRouteStore(const GatewayRouteStore&) = delete;
    GatewayRouteStore& operator=(const GatewayRouteStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Mint a fresh epoch for a new connection attempt and guarded-upsert the
    /// agent's route row. `won` is true iff this epoch beat whatever epoch was
    /// previously stored (the CAS in the file header) — a caller whose
    /// `register_fresh` reports `won == false` lost to a newer connection
    /// and MUST NOT proceed to `announce_connected` with this epoch/session.
    /// `cluster_id`/`gateway_node`/`stream_home_id` are NULLed (4.2b; #4324
    /// for the last) on a winning re-register — `announce_connected` is the
    /// SOLE writer of placement, so a fresh registration never carries
    /// forward a superseded connection's cluster/node/home-id until its own
    /// CONNECTED confirms them.
    [[nodiscard]] std::expected<RegisterFreshResult, GatewayRouteStoreError>
    register_fresh(std::string_view agent_id, std::string_view session_id);

    /// Record that `session_id`'s connection is fully established on
    /// `cluster_id`/`gateway_node`, with a lease valid for `lease_ttl_secs`.
    /// Session-guarded (see file header): a no-op against a row now held by a
    /// DIFFERENT session. If no row exists yet for `agent_id` at all, inserts
    /// one (`ON CONFLICT DO NOTHING`) rather than overwriting a differently-
    /// sessioned row. `stream_home_id` (SLICE #4324, file header) is this
    /// connection instance's opaque per-home generation id — written into the
    /// row exactly like `cluster_id`/`gateway_node`, since it IS placement;
    /// an empty string (the default — a gateway build predating #4324, or a
    /// caller not yet threading it through) means "unknown", same convention
    /// as `cluster_id`.
    [[nodiscard]] std::expected<AnnounceResult, GatewayRouteStoreError>
    announce_connected(std::string_view agent_id, std::string_view session_id,
                       std::string_view cluster_id, std::string_view gateway_node,
                       int lease_ttl_secs, std::string_view stream_home_id = {});

    /// TOMBSTONE the agent's route row (session_id/lease_until/cluster_id/
    /// gateway_node/stream_home_id -> NULL; `connection_epoch` retained), but
    /// ONLY if the row still belongs to `session_id` AND the incoming
    /// `stream_home_id` clears the ASYMMETRIC fence (file header SLICE
    /// #4324): `stream_home_id = $3 OR (stream_home_id IS NULL AND $3 = '')`
    /// — an unstamped (empty, the default) incoming DISCONNECTED may only
    /// tombstone a row whose stored home id is ALSO unstamped; it can never
    /// tear down a row a stamped CONNECTED has since re-homed. See the file
    /// header "SLICE 4.2a" note for why this is an UPDATE, not a DELETE.
    [[nodiscard]] std::expected<DeregisterResult, GatewayRouteStoreError>
    deregister(std::string_view agent_id, std::string_view session_id,
              std::string_view stream_home_id = {});

    /// Batched lease renewal: bumps `lease_until` for every row whose
    /// `(agent_id, session_id)` matches a pair in the two PARALLEL arrays
    /// `agent_ids`/`session_ids` (index i is one pair), in ONE statement.
    /// #4246 #10 — correlating on BOTH columns (not `session_id` alone) closes
    /// a defense-in-depth gap: a caller that only ever knows a session token
    /// can no longer renew a DIFFERENT agent's route by presenting that token
    /// against the wrong `agent_id`; such a call matches zero rows. A length
    /// mismatch between the two arrays is refused (`db_error`) rather than
    /// guessed at. Returns the number of rows renewed.
    [[nodiscard]] std::expected<int, GatewayRouteStoreError>
    renew_leases(std::span<const std::string> agent_ids, std::span<const std::string> session_ids,
                int lease_ttl_secs);

    /// The current route for `agent_id`, or `nullopt` if no row exists.
    /// `RouteRow::is_stale` is computed in-SQL from `lease_until` vs. `now()`.
    [[nodiscard]] std::expected<std::optional<RouteRow>, GatewayRouteStoreError>
    lookup_route(std::string_view agent_id);

    /// Batched routable-aware read (4.2b Task A): the current route for every
    /// agent in `agent_ids` that has a row, in ONE query (`WHERE agent_id =
    /// ANY($1)`, mirroring `renew_leases`' array-param idiom) bounded by a
    /// SINGLE `kReadTimeout` — never N times that. An agent with no row is
    /// simply absent from the result (no error, no placeholder entry). See
    /// `RoutableRoute` for the `routable` computation.
    [[nodiscard]] std::expected<std::vector<RoutableRoute>, GatewayRouteStoreError>
    lookup_routes(std::span<const std::string> agent_ids);

    /// Directory-hygiene reaper (4.2a, #7 in the ADR-2002 §7 "4.2 design
    /// obligations" list). CLOCK-GUARDED-RETENTION ADOPTION RECORD (routed
    /// concern, CLAUDE.md; the full seven parts are in
    /// docs/clock-guarded-retention.md) — mirrors `SessionStore::reap_expired`
    /// (session_store.cpp):
    ///  - Part 2/3 (persisted, sanitised clock reading): a `route_meta`
    ///    anchor (migration v2) + Postgres `now()` read ONCE in-SQL under a
    ///    dedicated advisory lock (`gateway_route_store:reap`) — the SAME
    ///    clock domain that authors `lease_until`/`updated_at`.
    ///  - Part 5 (unconditional cap): every accepted pass caps each of the
    ///    two sweeps independently.
    ///  - Part 6 (missing-anchor decision): **PROCEED** on the first pass —
    ///    `ResultSetStore`'s answer. A route is regenerable by the agent's
    ///    next heartbeat/`ProxyRegister`, so a from-boot skewed clock
    ///    reaping a batch of already-stale rows on the very first pass is an
    ///    acceptable worst case, never non-reproducible evidence loss.
    ///  - Part 1 (would-wipe probe) is DELIBERATELY CARVED OUT, the
    ///    `api_token_store`/`SessionStore` precedent: this table drains
    ///    toward "everything reapable" as ROUTINE behaviour (a fleet going
    ///    offline overnight legitimately expires every lease), so a
    ///    would-wipe verdict cannot separate a true positive from that
    ///    routine case.
    ///  - Part 4 (fact-set anomaly dedup) is ADOPTED, keyed on the TRIPLE
    ///    (declined `route_meta.reap_anchor_ms` value, anomaly DIRECTION,
    ///    `first_now_ms` — the reading the anomaly was first observed at)
    ///    (PR #4299 review, BLOCKER 1; direction-keyed since round-2 external
    ///    review; the `first_now_ms` reading-continuity window added round 4).
    ///    A forward- or backward-skew anomaly declines ONCE (persisting
    ///    `reap_declined_anchor_ms = "<reap_anchor_ms>:<direction>:<first_now_ms>"`)
    ///    and RECOVERS only when the SAME (anchor, direction) anomaly has
    ///    PERSISTED a real-time-plausible interval — `delta = now_ms -
    ///    first_now_ms` in `[kMinReapRecoveryGapMs, kMaxReapRecoveryGapMs]`
    ///    (270s..1h). Below the floor it re-declines PRESERVING the original
    ///    `first_now_ms` (an ε-later repeat, e.g. a second replica ticking a
    ///    few seconds offset, must NOT recover with no persistence evidence —
    ///    the FLOOR is load-bearing for the multi-replica future). Above the
    ///    ceiling, or on a negative delta (a further-backward step), it is a
    ///    NEW distinct anomaly — re-declined once against the CURRENT reading,
    ///    never a free recovery on a stale marker. A DIFFERENT-direction
    ///    anomaly at the SAME frozen anchor is likewise not the same anomaly
    ///    repeating — it re-declines and re-arms against the new direction,
    ///    since recovering it would run the sweeps against a mis-classified
    ///    `now_ms`. Without the decline-once/drain-on-repeat mechanism at all,
    ///    a routine >24h gap (weekend shutdown, DR failover, extended
    ///    maintenance) wedged the guard PERMANENTLY — `now - anchor` only grows
    ///    while declined, so every later pass declined forever with no recovery
    ///    path. Note the floor/ceiling correction to the old "oscillates every
    ///    other pass" narrative: a clock stepping backward every pass, or
    ///    forward by more than the ceiling every pass, now DECLINES every pass
    ///    and never recovers until it stops — stricter and correct, observable
    ///    via `outcome="declined"`. An OPERATOR can force recovery early by
    ///    resetting `route_meta.reap_anchor_ms` (see the operator re-anchor
    ///    comment at the anomaly-detection site in `gateway_route_store.cpp`).
    ///    Every decline is `spdlog::warn`'d AND counted —
    ///    `yuzu_server_gateway_route_reap_total{outcome="declined"}`
    ///    (incremented at the server.cpp reap call site). A failed pass
    ///    (store/query error, distinct from a declined one) is counted the
    ///    same way under `outcome="error"`; a clean, ordinary accepted pass
    ///    is `outcome="ok"` (or `outcome="ok_capped"` when it hit `kReapCap`
    ///    and a same-txn `EXISTS` probe confirmed a remaining backlog —
    ///    `ReapRoutesResult::cap_bound`, PR #4299 round 4, observability-only,
    ///    NOT acceleration); a pass that ran via this recovery branch (this
    ///    method's `ReapRoutesResult::recovered`) is its own
    ///    `outcome="recovered"` (PR #4299 round-2 review) — worth
    ///    distinguishing since a recovery pass can drain a large backlog in
    ///    one go, unlike a routine `ok` pass.
    /// SINGLE-WRITER today (advisory lock scoped to one dedicated key); becomes
    /// PG-shared-state under the same ADR-0012 lock when a 2nd replica lands
    /// (matches every other reaper in the register).
    [[nodiscard]] std::expected<ReapRoutesResult, GatewayRouteStoreError>
    reap_stale_routes();

    /// The schema migrations for this store (version 3: v1 the `agent_routes`
    /// table, v2 the `route_meta` reaper-anchor table, v3 the nullable
    /// `stream_home_id` column — SLICE #4324). Exposed for tests and the
    /// migration ladder.
    static const std::vector<pg::PgMigration>& migrations();

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
