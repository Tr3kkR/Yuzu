#include "gateway_route_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <spdlog/spdlog.h>

#include <charconv>
#include <chrono>
#include <cstdint>
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
constexpr std::chrono::milliseconds kWriteTimeout{2000};
constexpr std::chrono::milliseconds kReadTimeout{2000};

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
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM gateway_route_store.agent_routes WHERE agent_id=$1 AND session_id=$2 "
        "RETURNING agent_id",
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

} // namespace yuzu::server
