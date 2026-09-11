#include "gateway_route_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <spdlog/spdlog.h>

#include <algorithm> // std::max (reap anchor) — not transitively guaranteed on libc++
#include <cerrno> // errno — checked parse of the clock-guard-critical readings (session_store.cpp #3785 idiom)
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib> // std::strtoll — parse_reap_i64
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace {

// Schema == snake_case(ClassName) with the Store suffix (ADR-0008 Update):
// GatewayRouteStore -> gateway_route_store. One schema, one table
// (`agent_routes`).
constexpr const char* kStoreName = "gateway_route_store";

// Lease-acquire deadlines (ADR-0012 §2). This store is written from the
// connect/disconnect notification path, not a synchronous operator request,
// so modest deadlines are fine; the caller has its own retry on the next
// notification.
//
// #9 (4.2a): kWriteTimeout deliberately DIFFERS from the 2s codebase norm
// (session_store.cpp:34, command_outbox_store.cpp:32) at 500ms. Every writer
// here (register_fresh/announce_connected/deregister/renew_leases) runs
// SYNCHRONOUSLY on a gRPC handler thread on the agent heartbeat/connect hot
// path (agent_service_impl.cpp's BatchHeartbeat, gateway_service_impl.cpp's
// ProxyRegister/ProxyStreamStatus) — a 2s stall under pool pressure pins that
// thread for 2s per call, and these calls are already fail-open (a degraded
// write here never fails the RPC — see record_route_store_failure in
// gateway_service_impl.cpp). A short bound fails fast back to "log and
// proceed" instead of holding the handler thread hostage; the expected
// consequence is that yuzu_server_gateway_route_write_failed_total rises
// under real pool pressure rather than every heartbeat blocking for 2s each.
// reap_stale_routes() is a background pass, not a handler-thread call, so it
// deliberately keeps the 2s norm (kReapWriteTimeout below) rather than this
// shortened one.
constexpr std::chrono::milliseconds kWriteTimeout{500};
constexpr std::chrono::milliseconds kReadTimeout{2000};

// reap_stale_routes() runs off a background timer (Task B's job wiring), not
// a gRPC handler thread, so it keeps the 2s codebase norm rather than the
// hot-path-motivated kWriteTimeout above.
constexpr std::chrono::milliseconds kReapWriteTimeout{2000};

// ---------------------------------------------------------------------------
// reap_stale_routes() constants (clock-guarded-retention, see this store's
// header + docs/clock-guarded-retention.md). Copy the SHAPE from
// SessionStore::reap_expired, never the numbers — every constant here is
// substrate/store-specific.
//
// The lease TTL agents/gateways renew against is
// gateway_service_impl.cpp::kGatewayRouteLeaseTtlSecs = 90s. That file is out
// of this task's scope (owned by Task C) and this store has no dependency on
// the gateway wiring layer, so the value is DELIBERATELY DUPLICATED — but as
// yuzu::server::kKnownLeaseTtlSecs, a plain namespace-scope constant declared
// in this store's OWN header (gateway_route_store.hpp), not a local literal —
// so gateway_service_impl.cpp (which already includes that header
// transitively via gateway_service_impl.hpp) can `static_assert` the two
// stay equal without either .cpp depending on the other (PR #4299 review;
// see that static_assert for the enforcement). A future TTL bump there must
// still be mirrored here (kStaleLeaseGraceSecs must stay >= 1x that TTL) or a
// merely-late heartbeat mid-renew starts getting reaped — the static_assert
// only catches the two constants disagreeing, not either one being wrong.

// Grace >= 1 lease TTL (task spec): 2x tolerates a FULL missed renewal cycle
// (not just the last heartbeat's worth of jitter) before treating a lease as
// truly dead, mirroring the "tolerate a couple of missed heartbeats" margin
// already chosen for the TTL itself.
constexpr int kStaleLeaseGraceSecs = 2 * kKnownLeaseTtlSecs; // 180s

// Tombstone/never-announced purge age: deliberately SHORT (task spec) — a
// tombstone or a stuck mid-handshake row carries no state worth preserving
// beyond letting a genuine register_fresh find and reuse the primary-keyed
// row, which works whether the row exists or not (its higher minted epoch
// always wins). ~3.3x the TTL is comfortably longer than the lease-grace
// window (so this predicate never races predicate (a) over the same row)
// and short enough that dead rows do not linger in the directory.
constexpr int kTombstonePurgeAgeSecs = 300; // 5 minutes

// Unconditional per-predicate cap (part 5) — follows session_store.cpp's
// kReapCap shape (a hard ceiling that always applies, regardless of what the
// clock/anomaly guards decide).
constexpr int kReapCap = 5000;

// Part 1's implausibility bound, PER THIS STORE (never copied from another
// store's constant — docs/clock-guarded-retention.md part 1). This store's
// entire liveness horizon is under ten minutes (grace 180s + purge-age 300s
// == 480s); a `now()` reading more than a day ahead of the last accepted
// pass is already ~180x that horizon and cannot be legitimate operation,
// while staying far below SessionStore's 366-day bound (sized to a human
// session's plausible lifetime, not this store's sub-10-minute signal).
constexpr std::int64_t kMaxPlausibleSkewMs = 24LL * 3600 * 1000; // 1 day

std::optional<std::int64_t> parse_ms(const char* v) {
    if (v == nullptr || *v == '\0')
        return std::nullopt;
    // Postgres epoch-ms extraction below always yields an integral text value.
    std::int64_t n = 0;
    auto [ptr, ec] = std::from_chars(v, v + std::char_traits<char>::length(v), n);
    if (ec != std::errc{})
        return std::nullopt;
    return n;
}

std::optional<std::string> col_opt(PGresult* r, int row, int col) {
    if (PQgetisnull(r, row, col))
        return std::nullopt;
    return std::string(PQgetvalue(r, row, col));
}

// Checked parse for the two clock-guard-critical readings in
// reap_stale_routes (the DB now() column and the persisted route_meta
// anchor) — mirrors session_store.cpp's parse_reap_i64 (#3785): unparseable,
// empty, or negative is an ANOMALY, never a quiet reset. A second hand-rolled
// copy is the accepted drift for a three-line function (see that file's
// comment) rather than a shared-utility header.
std::optional<std::int64_t> parse_reap_i64(const std::string& val) {
    errno = 0;
    char* end = nullptr;
    const long long v = std::strtoll(val.c_str(), &end, 10);
    if (val.empty() || errno != 0 || end == val.c_str() || *end != '\0')
        return std::nullopt;
    return static_cast<std::int64_t>(v);
}

} // namespace

const std::vector<pg::PgMigration>& GatewayRouteStore::migrations() {
    // DDL is UNQUALIFIED — the runner sets search_path to this store's schema
    // for the migration transaction (playbook §2). `agent_id` is the PRIMARY
    // KEY: one live route per agent. `connection_epoch` is the anti-replay
    // fence (file header); `session_id`/`lease_until` guard the follow-up
    // announce/deregister/renew calls. cluster_id/gateway_node/session_id/
    // lease_until are nullable — unknown at register-time, filled in later by
    // announce_connected.
    //
    // The `session_id` index is load-bearing, not cosmetic: renew_leases() is
    // the highest-frequency op (once per BatchHeartbeat batch) and filters
    // `WHERE session_id = ANY($1)`, and deregister() filters on session_id too;
    // without the index those are a seq scan of agent_routes per heartbeat tick,
    // which grows with fleet size (governance perf/sre, WS-4 4.1). It ships in
    // migration v1 because adding it later costs a second migration version.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         R"(
CREATE SEQUENCE IF NOT EXISTS connection_epoch_seq AS bigint;
CREATE TABLE agent_routes (
    agent_id         TEXT        PRIMARY KEY,
    cluster_id       TEXT,
    gateway_node     TEXT,
    connection_epoch BIGINT      NOT NULL,
    session_id       TEXT,
    lease_until      TIMESTAMPTZ,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX agent_routes_session_id_idx ON agent_routes (session_id);
)"},
        // v2 (4.2a): reap_stale_routes()'s persisted, sanitised clock anchor
        // (clock-guarded-retention parts 2/3), mirroring session_store's
        // session_meta / execution_tracker's reap_meta anchor tables. Plain
        // key/value, additive, no backfill (ADR-0009 — this store is
        // born-on-Postgres and route_meta never existed before this slice).
        {2, R"(
CREATE TABLE IF NOT EXISTS route_meta(key TEXT PRIMARY KEY, value TEXT);
)"},
    };
    return kMigrations;
}

GatewayRouteStore::GatewayRouteStore(pg::PgPool& pool) : pool_(pool) {
    // Construction-only unbounded acquire (ADR-0012 §2); every runtime acquire
    // below is bounded.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("GatewayRouteStore: no database connection at construction ({}) — "
                      "gateway route directory disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("GatewayRouteStore: schema migration failed — gateway route directory "
                      "disabled");
        return;
    }
    open_ = true;
    // ADR-0009 fresh-start-by-default: born on Postgres, no legacy SQLite
    // file, no backfill (this store never existed before WS-4).
    spdlog::info("GatewayRouteStore initialized (schema {}) — born on Postgres, no legacy "
                 "backfill",
                 kStoreName);
}

std::expected<RegisterFreshResult, GatewayRouteStoreError>
GatewayRouteStore::register_fresh(std::string_view agent_id, std::string_view session_id) {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("GatewayRouteStore::register_fresh: lease timeout — degraded");
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    }
    // The fresh epoch is minted INSIDE the same statement as the guarded
    // upsert (mirrors leader_elector.cpp's nextval-in-INSERT idiom) so the
    // mint and the CAS attempt are atomic — no window where a concurrent
    // caller could mint a higher epoch and win the row between this call's
    // mint and its own write.
    //
    // The `WHERE EXCLUDED.connection_epoch > agent_routes.connection_epoch`
    // guard is the anti-replay fence (file header): a delayed/out-of-order
    // register whose freshly-minted epoch happens to be LOWER than the
    // row's current epoch (impossible for THIS caller's own mint since the
    // sequence is monotonic, but the whole point is that a DIFFERENT,
    // concurrently-racing register may have already advanced the row to a
    // higher epoch by the time this statement runs) loses: zero rows
    // returned, existing row untouched. cluster_id/gateway_node are
    // preserved via COALESCE across a winning re-register.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO gateway_route_store.agent_routes "
        "  (agent_id, connection_epoch, session_id, updated_at) "
        "VALUES ($1, nextval('gateway_route_store.connection_epoch_seq'), $2, now()) "
        "ON CONFLICT (agent_id) DO UPDATE SET "
        "  connection_epoch = EXCLUDED.connection_epoch, "
        "  session_id = EXCLUDED.session_id, "
        "  cluster_id = COALESCE(agent_routes.cluster_id, EXCLUDED.cluster_id), "
        "  gateway_node = COALESCE(agent_routes.gateway_node, EXCLUDED.gateway_node), "
        // A winning re-register is a NEW connection — it must NOT inherit the
        // superseded session's lease. Reset to NULL here; the connection's own
        // announce_connected / first heartbeat renew establishes a fresh lease.
        // (cluster_id/gateway_node ARE preserved via COALESCE above — they are
        // connection-agnostic placement and are refreshed by announce_connected;
        // the lease is connection-specific liveness and is not.)
        "  lease_until = NULL, "
        "  updated_at = now() "
        "WHERE EXCLUDED.connection_epoch > agent_routes.connection_epoch "
        "RETURNING connection_epoch",
        std::vector<std::optional<std::string>>{std::string(agent_id), std::string(session_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("GatewayRouteStore::register_fresh: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    if (PQntuples(res.get()) == 1) {
        RegisterFreshResult out;
        const char* v = PQgetvalue(res.get(), 0, 0);
        std::from_chars(v, v + std::char_traits<char>::length(v), out.epoch);
        out.won = true;
        return out;
    }
    // Zero rows: EITHER a brand-new INSERT with no conflict was somehow not
    // returned (impossible — a plain INSERT always returns its row) OR — the
    // real case — the ON CONFLICT branch's WHERE guard rejected the update
    // because a higher epoch already won. Either way the CAS did not apply;
    // the caller lost the race and must not proceed with this epoch. The
    // minted-but-discarded epoch value is not recoverable from the statement
    // (RETURNING produced no row), so report a zero epoch alongside won=false
    // — callers must check `won` before consulting `epoch`.
    return RegisterFreshResult{.epoch = 0, .won = false};
}

std::expected<AnnounceResult, GatewayRouteStoreError>
GatewayRouteStore::announce_connected(std::string_view agent_id, std::string_view session_id,
                                      std::string_view cluster_id, std::string_view gateway_node,
                                      int lease_ttl_secs) {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("GatewayRouteStore::announce_connected: lease timeout — degraded");
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    }
    // Session-guarded (file header): only touches a row that still belongs to
    // THIS session, so a stale CONNECTED from an already-superseded session
    // cannot overwrite a newer re-home's cluster/node.
    //
    // An EMPTY cluster_id is stored as NULL ("unknown"), never as ''. A gateway
    // build predating WS-4's field 7 sends no cluster_id (proto3 yields ""); a
    // future reader distinguishes "unknown" via IS NULL, and '' would be a third
    // state it would misclassify during a mixed-version rollout.
    std::optional<std::string> cluster_arg =
        cluster_id.empty() ? std::nullopt : std::optional<std::string>{std::string(cluster_id)};
    pg::PgResult upd = pg::exec_params(
        lease.get(),
        "UPDATE gateway_route_store.agent_routes SET "
        "  cluster_id=$3, gateway_node=$4, "
        "  lease_until = now() + ($5 || ' seconds')::interval, updated_at = now() "
        "WHERE agent_id=$1 AND session_id=$2 RETURNING agent_id",
        std::vector<std::optional<std::string>>{
            std::string(agent_id), std::string(session_id), std::move(cluster_arg),
            std::string(gateway_node), std::to_string(lease_ttl_secs)});
    if (upd.status() != PGRES_TUPLES_OK) {
        spdlog::error("GatewayRouteStore::announce_connected: update failed: {}",
                      PQresultErrorMessage(upd.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    if (PQntuples(upd.get()) > 0)
        return AnnounceResult{.matched = true};

    // No existing row for this (agent_id, session_id) pair — insert one, but
    // NEVER overwrite a row a different session already holds (ON CONFLICT DO
    // NOTHING, not DO UPDATE): a stale/duplicate CONNECTED for a session that
    // lost the register_fresh race must not clobber the winner's row.
    pg::PgResult ins = pg::exec_params(
        lease.get(),
        "INSERT INTO gateway_route_store.agent_routes "
        "  (agent_id, cluster_id, gateway_node, connection_epoch, session_id, lease_until, "
        "   updated_at) "
        "VALUES ($1, $2, $3, 0, $4, now() + ($5 || ' seconds')::interval, now()) "
        "ON CONFLICT (agent_id) DO NOTHING",
        std::vector<std::optional<std::string>>{
            std::string(agent_id),
            cluster_id.empty() ? std::nullopt : std::optional<std::string>{std::string(cluster_id)},
            std::string(gateway_node), std::string(session_id), std::to_string(lease_ttl_secs)});
    if (ins.status() != PGRES_COMMAND_OK) {
        spdlog::error("GatewayRouteStore::announce_connected: fallback insert failed: {}",
                      PQresultErrorMessage(ins.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    return AnnounceResult{.matched = false};
}

std::expected<DeregisterResult, GatewayRouteStoreError>
GatewayRouteStore::deregister(std::string_view agent_id, std::string_view session_id) {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("GatewayRouteStore::deregister: lease timeout — degraded");
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    }
    // Session-guarded: a stale DISCONNECTED from a superseded session must not
    // tear down a newer re-home's row.
    //
    // TOMBSTONE, not DELETE (file header "SLICE 4.2a", closes 4.2 design-doc
    // obligations #4/#5). A DELETE lets a late/reordered CONNECTED for this
    // same (now-gone) session resurrect the route via announce_connected's
    // fallback `ON CONFLICT DO NOTHING` INSERT, because that fallback only
    // refuses to clobber a row that EXISTS — against no row at all it just
    // recreates one. Tombstoning leaves the row in place with
    // `session_id IS NULL AND lease_until IS NULL` (the tombstone
    // definition): the late CONNECTED's session-guarded UPDATE still misses
    // (NULL never equals a bound `session_id` parameter) and its fallback
    // INSERT now hits `ON CONFLICT (agent_id) DO NOTHING` against the
    // EXISTING tombstoned row, so it no-ops instead of reviving a dead
    // route. `connection_epoch` is retained (NOT reset) — it is the
    // anti-replay fence's ratchet; a genuine later register_fresh mints a
    // strictly higher epoch and always wins the guarded UPSERT regardless of
    // what the tombstoned row's epoch is, so retaining it costs nothing and
    // avoids re-litigating fence state on every deregister/reconnect cycle.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE gateway_route_store.agent_routes SET "
        "  session_id=NULL, lease_until=NULL, cluster_id=NULL, gateway_node=NULL, "
        "  updated_at=now() "
        "WHERE agent_id=$1 AND session_id=$2 RETURNING agent_id",
        std::vector<std::optional<std::string>>{std::string(agent_id), std::string(session_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("GatewayRouteStore::deregister: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    return DeregisterResult{.removed = PQntuples(res.get()) > 0};
}

std::expected<int, GatewayRouteStoreError>
GatewayRouteStore::renew_leases(std::span<const std::string> session_ids, int lease_ttl_secs) {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    if (session_ids.empty())
        return 0;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("GatewayRouteStore::renew_leases: lease timeout — degraded");
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    }
    // ONE batched statement over session_id = ANY($1) — a per-row renew would
    // be one write per agent every lease interval at fleet scale (file
    // header). Session ids go through the shared pg::to_text_array helper
    // (pg/pg_array.hpp) rather than a hand-rolled literal, matching the
    // established idiom (app_perf_group_reader.cpp, deployment_run_store.cpp).
    std::vector<std::string_view> views;
    views.reserve(session_ids.size());
    for (const std::string& s : session_ids)
        views.emplace_back(s);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE gateway_route_store.agent_routes SET "
        "  lease_until = now() + ($2 || ' seconds')::interval, updated_at = now() "
        "WHERE session_id = ANY($1::text[]) RETURNING agent_id",
        std::vector<std::string>{pg::to_text_array(views), std::to_string(lease_ttl_secs)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("GatewayRouteStore::renew_leases: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    return PQntuples(res.get());
}

std::expected<std::optional<RouteRow>, GatewayRouteStoreError>
GatewayRouteStore::lookup_route(std::string_view agent_id) {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::warn("GatewayRouteStore::lookup_route: lease timeout — degraded");
        return std::unexpected(GatewayRouteStoreError::store_unavailable);
    }
    // is_stale computed IN-SQL against Postgres now() (DB-clock authority,
    // #3715 precedent) — never the process system_clock.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, cluster_id, gateway_node, connection_epoch, session_id, "
        "       (extract(epoch FROM lease_until) * 1000)::bigint AS lease_until_ms, "
        "       (lease_until IS NOT NULL AND lease_until < now()) AS is_stale "
        "FROM gateway_route_store.agent_routes WHERE agent_id=$1",
        std::vector<std::optional<std::string>>{std::string(agent_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("GatewayRouteStore::lookup_route: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<RouteRow>(std::nullopt);

    RouteRow row;
    row.agent_id = PQgetvalue(res.get(), 0, 0);
    row.cluster_id = col_opt(res.get(), 0, 1);
    row.gateway_node = col_opt(res.get(), 0, 2);
    {
        const char* v = PQgetvalue(res.get(), 0, 3);
        std::from_chars(v, v + std::char_traits<char>::length(v), row.connection_epoch);
    }
    row.session_id = col_opt(res.get(), 0, 4);
    row.lease_until_ms = PQgetisnull(res.get(), 0, 5)
                              ? std::nullopt
                              : parse_ms(PQgetvalue(res.get(), 0, 5));
    row.is_stale = std::string_view(PQgetvalue(res.get(), 0, 6)) == "t";
    return std::optional<RouteRow>(std::move(row));
}

std::expected<ReapRoutesResult, GatewayRouteStoreError> GatewayRouteStore::reap_stale_routes() {
    if (!open_)
        return std::unexpected(GatewayRouteStoreError::store_unavailable);

    // Clock-guarded, single-writer across replicas (SessionStore::reap_expired
    // shape — see the header comment on this method and
    // docs/clock-guarded-retention.md). The advisory lock is its OWN
    // statement, first, inside the txn (a CTE-embedded lock has the same
    // fixed-snapshot hazard session_store.cpp's comment describes). now_ms is
    // the DB clock (Postgres now(), read once in-SQL under the lock — the
    // SAME clock that authors lease_until/updated_at), sanitised against a
    // persisted route_meta anchor so a forward- or backward-skewed reading is
    // DECLINED, not acted on. Every accepted pass is unconditionally capped
    // per predicate.
    int expired_leases_reaped = 0;
    int tombstones_reaped = 0;
    bool clock_anomaly = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kReapWriteTimeout, [&](PGconn* c) -> bool {
        // Fixed key, deliberately NOT salted per-instance/per-test: Postgres advisory
        // locks are scoped per-DATABASE, and every [pg] test gets its own ephemeral
        // database, so a fixed key here cannot collide across tests. Across real
        // replicas sharing ONE production database, the fixed key IS the point — it is
        // the single-writer rendezvous every replica's reap tick must serialize
        // against (SINGLE-WRITER-today note above; becomes the PG-shared-state lock
        // when a 2nd replica lands).
        if (pg::exec_params(c, "SELECT pg_advisory_xact_lock(hashtext('gateway_route_store:reap'))",
                            std::vector<std::string>{})
                .status() != PGRES_TUPLES_OK) {
            err = "reap advisory lock failed";
            return false;
        }
        std::int64_t now_ms = 0;
        {
            pg::PgResult nr = pg::exec_params(
                c, "SELECT (extract(epoch FROM now()) * 1000)::bigint", std::vector<std::string>{});
            if (nr.status() != PGRES_TUPLES_OK || PQntuples(nr.get()) == 0) {
                err = "reap now() read failed";
                return false;
            }
            // SANITISE (clock-guarded-retention part 3): unparseable or
            // negative is an ANOMALY, never a quiet fallback.
            const std::string now_raw = PQgetvalue(nr.get(), 0, 0);
            auto parsed_now = parse_reap_i64(now_raw);
            if (!parsed_now || *parsed_now < 0) {
                spdlog::warn("GatewayRouteStore::reap_stale_routes declined: unparseable or "
                             "negative now() reading '{}'",
                             now_raw);
                clock_anomaly = true;
                return true; // decline (commit the no-op lock release), anchor unchanged
            }
            now_ms = *parsed_now;
        }
        // Persisted anchor = the max now_ms any prior pass accepted. A
        // reading implausibly far ahead of, or behind, it is an anomaly:
        // decline this pass, do not advance the anchor.
        pg::PgResult ar = pg::exec_params(
            c, "SELECT value FROM gateway_route_store.route_meta WHERE key='reap_anchor_ms'",
            std::vector<std::string>{});
        if (ar.status() != PGRES_TUPLES_OK) {
            err = "reap anchor read failed";
            return false;
        }
        const bool has_anchor = PQntuples(ar.get()) > 0;
        std::int64_t anchor = 0;
        if (has_anchor) {
            const std::string anchor_raw = PQgetvalue(ar.get(), 0, 0);
            auto parsed_anchor = parse_reap_i64(anchor_raw);
            if (!parsed_anchor || *parsed_anchor < 0) {
                spdlog::warn("GatewayRouteStore::reap_stale_routes declined: unparseable or "
                             "negative persisted anchor '{}'",
                             anchor_raw);
                clock_anomaly = true;
                return true; // decline, anchor unchanged
            }
            anchor = *parsed_anchor;
        }
        // Overflow-safe forward-skew comparison (mirrors session_store.cpp's
        // #3785 round-2 fix): subtracting (not adding) two already-sanitised
        // non-negative int64_t values cannot overflow.
        const bool forward_skew =
            has_anchor && now_ms >= anchor && now_ms - anchor > kMaxPlausibleSkewMs;
        // BACKWARD-anomaly guard: now_ms below the highest accepted reading
        // means the wall clock moved backward, or an earlier forward-skewed
        // pass poisoned the anchor.
        const bool backward_skew = has_anchor && now_ms < anchor;

        // DECLINE-ONCE / DRAIN-ON-REPEAT (PR #4299 review, BLOCKER 1).
        // Mirrors audit_retention_rules.hpp::classify + AuditStore::
        // cleanup_once's "decline ONCE on the fact set, then DRAIN an
        // identical repeat, capped" shape (docs/clock-guarded-retention.md
        // part 4) — a bare "always decline on skew" (the pre-fix behaviour)
        // wedges PERMANENTLY after any routine >24h gap (weekend shutdown, DR
        // failover, extended maintenance): now-anchor only grows while
        // declined, so every later pass declines forever with no recovery.
        //
        // Keyed on the DECLINED anchor value, not on the anomaly's direction:
        // `reap_anchor_ms` does not move while a decline is outstanding, so a
        // genuine multi-day gap presents the IDENTICAL anchor to pass 2 — the
        // signal that distinguishes "real elapsed downtime, decline once then
        // recover" from a single glitched reading (whose corrected successor
        // reads normally against the unmoved anchor and is an ordinary
        // accepted pass, not a recovery).
        //
        // OPERATOR RE-ANCHOR PROCEDURE: a pass that is genuinely stuck (the
        // clock itself is still wrong on pass 2, so the SAME anomaly keeps
        // reporting against an ever-different anchor and never lines up with
        // the declined marker) never recovers on its own — by design, since
        // recovery must not fire on an ongoing skew. An operator can force
        // recovery by resetting `route_meta.reap_anchor_ms` (and, for
        // cleanliness, deleting `route_meta.reap_declined_anchor_ms`) to the
        // corrected current epoch-ms once the underlying clock problem is
        // fixed — the next pass then has a fresh, correct anchor and proceeds
        // normally. See docs/clock-guarded-retention.md's GatewayRouteStore
        // entry for the full record.
        bool recovered_from_prior_decline = false;
        if (forward_skew || backward_skew) {
            pg::PgResult dr = pg::exec_params(
                c,
                "SELECT value FROM gateway_route_store.route_meta WHERE "
                "key='reap_declined_anchor_ms'",
                std::vector<std::string>{});
            if (dr.status() != PGRES_TUPLES_OK) {
                err = "reap declined-anchor read failed";
                return false;
            }
            std::optional<std::int64_t> declined_anchor;
            if (PQntuples(dr.get()) > 0) {
                const std::string raw = PQgetvalue(dr.get(), 0, 0);
                auto parsed = parse_reap_i64(raw);
                // This method is the sole writer of this marker, so an
                // unparseable value can only be external tampering. Treat it
                // as absent rather than erroring the whole pass — the safe
                // direction is to decline again below (re-arming the marker
                // with a clean value), never to grant a recovery this pass
                // never actually earned.
                if (parsed && *parsed >= 0)
                    declined_anchor = *parsed;
            }
            if (declined_anchor.has_value() && *declined_anchor == anchor) {
                recovered_from_prior_decline = true;
                spdlog::warn(
                    "GatewayRouteStore::reap_stale_routes recovering: the clock anomaly at "
                    "anchor {} persisted across a full decline pass (now_ms {}) — treating as "
                    "genuine elapsed downtime and running the sweeps now",
                    anchor, now_ms);
            } else {
                spdlog::warn(
                    "GatewayRouteStore::reap_stale_routes declined: now_ms {} vs anchor {} "
                    "({}) — declining this pass; an identical repeat (same anchor) recovers "
                    "and drains, capped",
                    now_ms, anchor, forward_skew ? "implausibly ahead" : "behind");
                pg::PgResult set_declined = pg::exec_params(
                    c,
                    "INSERT INTO gateway_route_store.route_meta (key, value) VALUES "
                    "('reap_declined_anchor_ms', $1) ON CONFLICT (key) DO UPDATE SET "
                    "value=EXCLUDED.value",
                    std::vector<std::string>{std::to_string(anchor)});
                if (set_declined.status() != PGRES_COMMAND_OK) {
                    err = "reap declined-anchor persist failed";
                    return false;
                }
                clock_anomaly = true;
                return true; // decline, anchor unchanged, declined-anchor marker set
            }
        }

        // Accepted (or recovered) pass: TWO capped sweeps in the same transaction, both
        // comparing epoch-ms cutoffs derived from the ONE sanitised now_ms
        // read above (never a fresh in-SQL now() per statement — the cutoff,
        // the anchor comparison, and the anchor update below all stay in the
        // ONE clock domain read once under the lock).

        // (a) Expired-lease routes: lease_until past the grace window. Grace
        // (>= 1 lease TTL, task spec) means a merely-late heartbeat mid-renew
        // is never reaped here. ACTION is the same TOMBSTONE `deregister`
        // performs (retain connection_epoch, NULL the rest) rather than a
        // hard delete: the associated session may still be alive and simply
        // stopped renewing (network partition), and a late DISCONNECTED for
        // it arriving after this pass must still land as a no-op against a
        // tombstoned row rather than an error against a vanished one.
        //
        // The outer UPDATE's WHERE re-asserts the SAME expired predicate the
        // subquery already applied (governance fix #4, cpp-safety/UP-4): under
        // READ COMMITTED, the inner SELECT snapshots agent_id candidates, and
        // by the time the outer UPDATE takes each row's lock a concurrent
        // renew_leases()/announce_connected() could have pushed lease_until
        // back into the future for one of those rows. Without the re-check the
        // outer UPDATE only re-verifies `agent_id IN (...)` and would tombstone
        // an agent that renewed in that window anyway. Re-checking against
        // `$1` (the same cutoff the subquery used) closes that window: a
        // concurrently-renewed row now fails the outer predicate and drops
        // out, at the cost of nothing — a row that is still genuinely expired
        // passes both checks identically.
        {
            const std::int64_t cutoff_a_ms = now_ms - static_cast<std::int64_t>(kStaleLeaseGraceSecs) * 1000;
            pg::PgResult dr = pg::exec_params(
                c,
                "UPDATE gateway_route_store.agent_routes SET "
                "  session_id=NULL, lease_until=NULL, cluster_id=NULL, gateway_node=NULL, "
                "  updated_at=now() "
                "WHERE agent_id IN (SELECT agent_id FROM gateway_route_store.agent_routes "
                "  WHERE lease_until IS NOT NULL "
                "    AND (extract(epoch FROM lease_until) * 1000)::bigint < $1::bigint "
                "  LIMIT $2::bigint) "
                "  AND lease_until IS NOT NULL "
                "  AND (extract(epoch FROM lease_until) * 1000)::bigint < $1::bigint "
                "RETURNING agent_id",
                std::vector<std::string>{std::to_string(cutoff_a_ms), std::to_string(kReapCap)});
            if (dr.status() != PGRES_TUPLES_OK) {
                err = std::string("reap expired-lease sweep failed: ") + PQerrorMessage(c);
                return false;
            }
            expired_leases_reaped = PQntuples(dr.get());
        }

        // (b) Tombstoned / never-announced rows (lease_until IS NULL) whose
        // `updated_at` is older than the SHORT purge age (task spec) — this
        // catches both a real tombstone (session_id also NULL, left by
        // deregister or by sweep (a) above) and a row stuck since
        // register_fresh that never got an announce_connected. ACTION is a
        // hard DELETE, not a re-tombstone: by the purge age (well past any
        // plausible network-reordering window for a CONNECTED/DISCONNECTED
        // pair) a resurrection from a late notification is not a realistic
        // risk, and a genuine later register_fresh works identically whether
        // the row exists or not (INSERT with no conflict, always wins).
        //
        // The outer DELETE's WHERE re-asserts the SAME predicate the subquery
        // already applied (PR #4299 review, BLOCKER 2 — the same
        // EvalPlanQual hazard sweep (a) closed above, missed here on the
        // first pass): under READ COMMITTED the inner SELECT snapshots
        // agent_id candidates, and by the time the outer DELETE takes each
        // row's lock a concurrent `register_fresh`/`announce_connected` could
        // have revived that exact row (a fresh session_id/lease_until) in the
        // window between the snapshot and the lock. Without the re-check the
        // outer DELETE only re-verifies `agent_id IN (...)` and deletes the
        // just-revived row anyway — dropping a route a caller just believes
        // it (re-)established. Re-checking `lease_until IS NULL` and the SAME
        // `$1` cutoff the subquery used closes that window: a concurrently
        // revived row now fails the outer predicate and drops out, at the
        // cost of nothing — a row that is still genuinely a stale
        // tombstone/never-announced row passes both checks identically.
        {
            const std::int64_t cutoff_b_ms =
                now_ms - static_cast<std::int64_t>(kTombstonePurgeAgeSecs) * 1000;
            pg::PgResult dr = pg::exec_params(
                c,
                "DELETE FROM gateway_route_store.agent_routes WHERE agent_id IN "
                "  (SELECT agent_id FROM gateway_route_store.agent_routes "
                "     WHERE lease_until IS NULL "
                "       AND (extract(epoch FROM updated_at) * 1000)::bigint < $1::bigint "
                "     LIMIT $2::bigint) "
                "  AND lease_until IS NULL "
                "  AND (extract(epoch FROM updated_at) * 1000)::bigint < $1::bigint "
                "RETURNING agent_id",
                std::vector<std::string>{std::to_string(cutoff_b_ms), std::to_string(kReapCap)});
            if (dr.status() != PGRES_TUPLES_OK) {
                err = std::string("reap tombstone-purge sweep failed: ") + PQerrorMessage(c);
                return false;
            }
            tombstones_reaped = PQntuples(dr.get());
        }

        // Advance the persisted anchor. A RECOVERY pass sets it to now_ms
        // UNCONDITIONALLY (never max(anchor, now_ms)) — the whole point of
        // recovery is to move the anchor off the stale/poisoned value that
        // wedged the guard; std::max would leave a forward-skew-poisoned
        // anchor unchanged forever (it always picks the already-too-far-
        // ahead anchor over a normal now_ms). A NORMAL accepted pass keeps
        // the pre-existing max(anchor, now_ms) shape (session_store.cpp
        // idiom, parenthesised to dodge the <windows.h> `max` function-like
        // macro, MSVC).
        const std::int64_t new_anchor =
            recovered_from_prior_decline ? now_ms
                                          : (has_anchor ? (std::max)(anchor, now_ms) : now_ms);
        pg::PgResult ur = pg::exec_params(
            c,
            "INSERT INTO gateway_route_store.route_meta (key, value) VALUES "
            "('reap_anchor_ms', $1) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
            std::vector<std::string>{std::to_string(new_anchor)});
        if (ur.status() != PGRES_COMMAND_OK) {
            err = "reap anchor update failed";
            return false;
        }
        // Clear the declined-anchor marker on EVERY accepted/recovered pass
        // (decline-once/drain-on-repeat, BLOCKER 1 above) — a later transient
        // glitch must be judged fresh against the NEW anchor rather than
        // silently recovering on its very first pass. A no-op DELETE when no
        // marker is set (the common case) costs one statement per pass.
        pg::PgResult clr_declined = pg::exec_params(
            c, "DELETE FROM gateway_route_store.route_meta WHERE key='reap_declined_anchor_ms'",
            std::vector<std::string>{});
        if (clr_declined.status() != PGRES_COMMAND_OK) {
            err = "reap declined-anchor clear failed";
            return false;
        }
        return true;
    });
    if (!ok) {
        // `err` stays empty when with_txn_for itself failed before the lambda
        // ran a single statement (a try_acquire_for lease timeout, or BEGIN
        // failing on a broken connection) — that is the same "degraded, not a
        // query bug" case every other method here reports as
        // store_unavailable. `err` non-empty means the lambda's own guard set
        // it on a specific statement failure: a real db_error.
        if (err.empty()) {
            spdlog::warn("GatewayRouteStore::reap_stale_routes: lease timeout or txn-begin "
                         "failure — degraded");
            return std::unexpected(GatewayRouteStoreError::store_unavailable);
        }
        spdlog::error("GatewayRouteStore::reap_stale_routes: {}", err);
        return std::unexpected(GatewayRouteStoreError::db_error);
    }
    return ReapRoutesResult{.expired_leases_reaped = expired_leases_reaped,
                            .tombstones_reaped = tombstones_reaped,
                            .clock_anomaly = clock_anomaly};
}

} // namespace yuzu::server
