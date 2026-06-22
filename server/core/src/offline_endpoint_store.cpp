#include "offline_endpoint_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "endpoint_state";

// Bounded acquires (gov UP-1): the upsert is on the gRPC heartbeat thread, so
// it must NEVER block on a saturated pool — a short deadline makes it truly
// best-effort (skip the persist, the live in-memory stores stay authoritative).
// The read is a user-facing /viz request and can wait a little longer.
constexpr std::chrono::milliseconds kUpsertAcquireTimeout{250};
constexpr std::chrono::milliseconds kQueryAcquireTimeout{2000};
// Hard cap on rows materialised by query_stale_within (gov sec-LOW / UP-5): the
// viz machines_max ceiling, so the store can never allocate more than the page
// could ever serve even if the table has grown large.
constexpr int kQueryRowCap = 100000;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so `endpoints` lands in `endpoint_state`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE endpoints ("
         "  agent_id          TEXT PRIMARY KEY,"
         "  hostname          TEXT NOT NULL DEFAULT '',"
         "  os                TEXT NOT NULL DEFAULT '',"
         "  last_heartbeat_ms BIGINT NOT NULL,"
         "  agent_ts          BIGINT NOT NULL DEFAULT 0);"
         "CREATE INDEX endpoints_last_heartbeat_idx ON endpoints (last_heartbeat_ms);"},
    };
    return kMigrations;
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

} // namespace

OfflineEndpointStore::OfflineEndpointStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("OfflineEndpointStore: no database connection at construction ({}) — "
                      "endpoint persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("OfflineEndpointStore: schema migration failed — endpoint persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

bool OfflineEndpointStore::upsert(std::string_view agent_id, std::string_view hostname,
                                  std::string_view os, std::int64_t last_heartbeat_ms,
                                  std::int64_t agent_ts) {
    if (!open_ || agent_id.empty())
        return false;
    // Bounded acquire (gov UP-1): on a saturated pool, give up fast rather than
    // block the gRPC heartbeat thread. Best-effort persistence — the live
    // in-memory stores remain authoritative.
    auto lease = pool_.try_acquire_for(kUpsertAcquireTimeout);
    if (!lease) {
        spdlog::debug("OfflineEndpointStore: upsert skipped, no connection in time ({})",
                      pool_.last_error());
        return false;
    }
    // Single-statement autocommit upsert; RETURNING carries the result in the
    // step status (no sqlite3_changes()-style mutate-and-count race, #1033).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO endpoint_state.endpoints "
        "(agent_id, hostname, os, last_heartbeat_ms, agent_ts) "
        "VALUES ($1, $2, $3, $4::bigint, $5::bigint) "
        "ON CONFLICT (agent_id) DO UPDATE SET "
        "  hostname = EXCLUDED.hostname, os = EXCLUDED.os, "
        "  last_heartbeat_ms = EXCLUDED.last_heartbeat_ms, agent_ts = EXCLUDED.agent_ts "
        "RETURNING agent_id",
        std::vector<std::string>{std::string(agent_id), std::string(hostname), std::string(os),
                                 std::to_string(last_heartbeat_ms), std::to_string(agent_ts)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("OfflineEndpointStore: upsert failed for agent={}: {}", agent_id,
                      PQerrorMessage(lease.get()));
        return false;
    }
    return true;
}

std::vector<OfflineEndpoint> OfflineEndpointStore::query_stale_within(std::chrono::seconds window) {
    std::vector<OfflineEndpoint> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::debug("OfflineEndpointStore: query skipped, no connection in time ({})",
                      pool_.last_error());
        return out;
    }
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    const std::int64_t window_ms = static_cast<std::int64_t>(window.count()) * 1000;
    const std::int64_t since = now_ms - window_ms;

    // LIMIT caps the materialised set (gov sec-LOW / UP-5) so the store never
    // allocates more rows than the viz page could serve, regardless of table
    // growth. Newest-first, so the cap keeps the most recently-seen hosts.
    pg::PgResult res = pg::exec_params(lease.get(),
                                   "SELECT agent_id, hostname, os, last_heartbeat_ms, agent_ts "
                                   "FROM endpoint_state.endpoints "
                                   "WHERE last_heartbeat_ms >= $1::bigint "
                                   "ORDER BY last_heartbeat_ms DESC "
                                   "LIMIT $2::bigint",
                                   std::vector<std::string>{std::to_string(since),
                                                            std::to_string(kQueryRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("OfflineEndpointStore: query failed: {}", PQerrorMessage(lease.get()));
        return out;
    }
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        OfflineEndpoint ep;
        ep.agent_id = PQgetvalue(res.get(), i, 0);
        ep.hostname = PQgetvalue(res.get(), i, 1);
        ep.os = PQgetvalue(res.get(), i, 2);
        ep.last_heartbeat_ms = to_i64(PQgetvalue(res.get(), i, 3));
        ep.agent_ts = to_i64(PQgetvalue(res.get(), i, 4));
        out.push_back(std::move(ep));
    }
    return out;
}

} // namespace yuzu::server
