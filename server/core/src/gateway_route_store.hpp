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
/// belongs to THIS session. A stale CONNECTED/DISCONNECTED from an
/// already-superseded session therefore cannot overwrite or tear down a
/// newer re-home: `announce_connected` no-ops (falls through to an
/// `ON CONFLICT DO NOTHING` insert) if the session doesn't match, and
/// `deregister` deletes zero rows.
///
/// `renew_leases` is a single batched statement over `session_id = ANY($1)` —
/// at fleet scale a per-row renew would be one write per agent every lease
/// interval; batching keeps the steady-state write rate flat regardless of
/// fleet size.
///
/// Posture (ADR-0012 §1): this store is a coordination/liveness aid, not yet
/// an authority anything depends on for correctness (nothing reads it). A
/// degraded write here is logged and returned to the caller (never silently
/// dropped), but has no fail-closed obligation beyond that until a reader
/// exists.
///
/// 4.2 OBLIGATIONS (latent while INERT, load-bearing once a dispatch reader
/// exists — full list in ADR-2002 §7 "4.2 design obligations"): the "cannot
/// overwrite a newer re-home" property above is precise only for OVERWRITE, and
/// only intra-replica with a live session. The epoch orders by server PROCESSING
/// time, so a stale replay whose session has left `gateway_sessions_` takes the
/// fresh branch and wins; the re-announce reuses the session id (a late
/// DISCONNECTED then deletes the re-homed route) and its known-session check is
/// per-replica in-memory; re-announce refreshes the lease, not cluster/node; and
/// a stale-lease reaper plus the fail-open->fail-closed flip must land before 4.2
/// trusts this directory for routing.
///
/// SLICE 4.2a — `deregister` TOMBSTONES instead of deleting (closes the
/// "a late DISCONNECTED then deletes the re-homed route" obligation above,
/// #4/#5 in the 4.2 design doc). A tombstone is `session_id IS NULL AND
/// lease_until IS NULL`; `connection_epoch` is retained. Rationale: a bare
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
/// behind, the anchor, or unparseable/negative. A declined pass reaps
/// nothing and leaves the anchor unchanged.
struct ReapRoutesResult {
    int expired_leases_reaped{0}; ///< predicate (a): lease_until past the grace window
    int tombstones_reaped{0};     ///< predicate (b): NULL-lease rows past the purge age
    bool clock_anomaly{false};
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
    /// Existing `cluster_id`/`gateway_node` are preserved (COALESCE) across a
    /// winning re-register — they are filled in later by `announce_connected`.
    [[nodiscard]] std::expected<RegisterFreshResult, GatewayRouteStoreError>
    register_fresh(std::string_view agent_id, std::string_view session_id);

    /// Record that `session_id`'s connection is fully established on
    /// `cluster_id`/`gateway_node`, with a lease valid for `lease_ttl_secs`.
    /// Session-guarded (see file header): a no-op against a row now held by a
    /// DIFFERENT session. If no row exists yet for `agent_id` at all, inserts
    /// one (`ON CONFLICT DO NOTHING`) rather than overwriting a differently-
    /// sessioned row.
    [[nodiscard]] std::expected<AnnounceResult, GatewayRouteStoreError>
    announce_connected(std::string_view agent_id, std::string_view session_id,
                       std::string_view cluster_id, std::string_view gateway_node,
                       int lease_ttl_secs);

    /// TOMBSTONE the agent's route row (session_id/lease_until/cluster_id/
    /// gateway_node -> NULL; `connection_epoch` retained), but ONLY if the row
    /// still belongs to `session_id` (a stale DISCONNECTED from a superseded
    /// session must not tear down a newer re-home). See the file header
    /// "SLICE 4.2a" note for why this is an UPDATE, not a DELETE.
    [[nodiscard]] std::expected<DeregisterResult, GatewayRouteStoreError>
    deregister(std::string_view agent_id, std::string_view session_id);

    /// Batched lease renewal: bumps `lease_until` for every row whose
    /// `session_id` is in `session_ids`, in ONE statement. Returns the number
    /// of rows renewed.
    [[nodiscard]] std::expected<int, GatewayRouteStoreError>
    renew_leases(std::span<const std::string> session_ids, int lease_ttl_secs);

    /// The current route for `agent_id`, or `nullopt` if no row exists.
    /// `RouteRow::is_stale` is computed in-SQL from `lease_until` vs. `now()`.
    [[nodiscard]] std::expected<std::optional<RouteRow>, GatewayRouteStoreError>
    lookup_route(std::string_view agent_id);

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
    ///  - Part 4 (fact-set anomaly dedup) is ADOPTED, in a simplified form
    ///    keyed on the declined `route_meta.reap_anchor_ms` value rather than
    ///    the full multi-field `Facts` struct (PR #4299 review, BLOCKER 1) —
    ///    a forward- or backward-skew anomaly declines ONCE (persisting
    ///    `reap_declined_anchor_ms = reap_anchor_ms`) and an IDENTICAL
    ///    repeat (the anchor still unmoved) RECOVERS and drains, capped,
    ///    treating the persisted gap as genuine elapsed downtime rather than
    ///    a transient glitch. Without this, a routine >24h gap (weekend
    ///    shutdown, DR failover, extended maintenance) wedged the guard
    ///    PERMANENTLY — `now - anchor` only grows while declined, so every
    ///    later pass declined forever with no recovery path. An OPERATOR can
    ///    force recovery early by resetting `route_meta.reap_anchor_ms` (see
    ///    the operator re-anchor comment at the anomaly-detection site in
    ///    `gateway_route_store.cpp`). Every decline (first or, before this
    ///    fix, permanent) is `spdlog::warn`'d AND counted —
    ///    `yuzu_server_gateway_route_reap_total{outcome="declined"}`
    ///    (incremented at the server.cpp reap call site). A failed pass
    ///    (store/query error, distinct from a declined one) is counted the
    ///    same way under `outcome="error"`; a clean accepted OR recovered
    ///    pass is `outcome="ok"`.
    /// SINGLE-WRITER today (advisory lock scoped to one dedicated key); becomes
    /// PG-shared-state under the same ADR-0012 lock when a 2nd replica lands
    /// (matches every other reaper in the register).
    [[nodiscard]] std::expected<ReapRoutesResult, GatewayRouteStoreError>
    reap_stale_routes();

    /// The schema migrations for this store (version 2: v1 the `agent_routes`
    /// table, v2 the `route_meta` reaper-anchor table). Exposed for tests and
    /// the migration ladder.
    static const std::vector<pg::PgMigration>& migrations();

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
