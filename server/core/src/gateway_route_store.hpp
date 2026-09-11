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
    bool removed{false}; ///< true iff a row owned by this session was deleted
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

    /// Remove the agent's route row, but ONLY if it still belongs to
    /// `session_id` (a stale DISCONNECTED from a superseded session must not
    /// tear down a newer re-home).
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

    /// The schema migrations for this store (version 1). Exposed for tests and
    /// the migration ladder.
    static const std::vector<pg::PgMigration>& migrations();

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
