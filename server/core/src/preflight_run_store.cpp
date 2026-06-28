#include "preflight_run_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdlib>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "preflight_run_store";

// Bounded acquires — a /auto run click is user-facing; the runner's writes are
// background but still bounded (ADR-0012, never block on a saturated pool).
constexpr std::chrono::milliseconds kWriteTimeout{3000};
constexpr std::chrono::milliseconds kReadTimeout{2000};
// Hard cap on rows materialised by a grid/target read (a cohort the page renders).
constexpr int kRowCap = 20000;
constexpr int kRunListCap = 200;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for the
    // migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE runs ("
         "  run_id          TEXT PRIMARY KEY,"
         "  execution_id    TEXT NOT NULL,"
         "  created_by      TEXT NOT NULL DEFAULT '',"
         "  name            TEXT NOT NULL DEFAULT '',"
         "  scope_label     TEXT NOT NULL DEFAULT '',"
         "  group_id        TEXT NOT NULL DEFAULT '',"
         "  os_filter       TEXT NOT NULL DEFAULT '',"
         "  config_json     TEXT NOT NULL DEFAULT '',"
         "  window_seconds  INT  NOT NULL DEFAULT 0,"
         "  created_at_ms   BIGINT NOT NULL,"
         "  deadline_at_ms  BIGINT NOT NULL,"
         "  status          TEXT NOT NULL DEFAULT 'running',"
         "  completed_at_ms BIGINT NOT NULL DEFAULT 0,"
         "  total           INT NOT NULL DEFAULT 0,"
         "  go              INT NOT NULL DEFAULT 0,"
         "  warn            INT NOT NULL DEFAULT 0,"
         "  nogo            INT NOT NULL DEFAULT 0,"
         "  incomplete      INT NOT NULL DEFAULT 0);"
         "CREATE INDEX runs_owner_idx  ON runs (created_by, created_at_ms DESC);"
         "CREATE INDEX runs_status_idx ON runs (status);"
         "CREATE TABLE run_device ("
         "  run_id        TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,"
         "  agent_id      TEXT NOT NULL,"
         "  hostname      TEXT NOT NULL DEFAULT '',"
         "  os            TEXT NOT NULL DEFAULT '',"
         "  bucket        TEXT NOT NULL DEFAULT 'inc',"
         "  checks_json   TEXT NOT NULL DEFAULT '',"
         "  updated_at_ms BIGINT NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (run_id, agent_id));"},
    };
    return kMigrations;
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
int to_int(const char* s) { return static_cast<int>(to_i64(s)); }

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

PreflightRunRow read_run(PGresult* res, int i) {
    PreflightRunRow r;
    int c = 0;
    r.run_id = PQgetvalue(res, i, c++);
    r.execution_id = PQgetvalue(res, i, c++);
    r.created_by = PQgetvalue(res, i, c++);
    r.name = PQgetvalue(res, i, c++);
    r.scope_label = PQgetvalue(res, i, c++);
    r.group_id = PQgetvalue(res, i, c++);
    r.os_filter = PQgetvalue(res, i, c++);
    r.config_json = PQgetvalue(res, i, c++);
    r.window_seconds = to_int(PQgetvalue(res, i, c++));
    r.created_at_ms = to_i64(PQgetvalue(res, i, c++));
    r.deadline_at_ms = to_i64(PQgetvalue(res, i, c++));
    r.status = PQgetvalue(res, i, c++);
    r.completed_at_ms = to_i64(PQgetvalue(res, i, c++));
    r.total = to_int(PQgetvalue(res, i, c++));
    r.go = to_int(PQgetvalue(res, i, c++));
    r.warn = to_int(PQgetvalue(res, i, c++));
    r.nogo = to_int(PQgetvalue(res, i, c++));
    r.incomplete = to_int(PQgetvalue(res, i, c++));
    return r;
}

constexpr const char* kRunCols =
    "run_id, execution_id, created_by, name, scope_label, group_id, os_filter, config_json, "
    "window_seconds, created_at_ms, deadline_at_ms, status, completed_at_ms, total, go, warn, "
    "nogo, incomplete";

} // namespace

PreflightRunStore::PreflightRunStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("PreflightRunStore: no database connection at construction ({}) — pre-flight "
                      "run persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("PreflightRunStore: schema migration failed — pre-flight run persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

bool PreflightRunStore::create_run(const PreflightRunRow& run,
                                   const std::vector<preflight::PreflightTarget>& targets) {
    if (!open_ || run.run_id.empty())
        return false;
    // Frozen cohort columns for the unnest batch insert (string_views into the
    // caller's `targets`, which outlives the synchronous with_txn_for call below).
    std::vector<std::string_view> agent_ids, hostnames, oses;
    agent_ids.reserve(targets.size());
    hostnames.reserve(targets.size());
    oses.reserve(targets.size());
    for (const auto& t : targets) {
        agent_ids.emplace_back(t.agent_id);
        hostnames.emplace_back(t.hostname);
        oses.emplace_back(t.os);
    }
    const std::string ts = std::to_string(now_ms());
    return pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult r1 = pg::exec_params(
            conn,
            "INSERT INTO preflight_run_store.runs "
            "(run_id, execution_id, created_by, name, scope_label, group_id, os_filter, "
            " config_json, window_seconds, created_at_ms, deadline_at_ms, status, total) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::int,$10::bigint,$11::bigint,'running',$12::int) "
            "RETURNING run_id",
            std::vector<std::string>{run.run_id, run.execution_id, run.created_by, run.name,
                                     run.scope_label, run.group_id, run.os_filter, run.config_json,
                                     std::to_string(run.window_seconds),
                                     std::to_string(run.created_at_ms),
                                     std::to_string(run.deadline_at_ms),
                                     std::to_string(static_cast<int>(targets.size()))});
        if (r1.status() != PGRES_TUPLES_OK) {
            spdlog::warn("PreflightRunStore: run insert failed: {}", PQerrorMessage(conn));
            return false;
        }
        if (targets.empty())
            return true;
        pg::PgResult r2 = pg::exec_params(
            conn,
            "INSERT INTO preflight_run_store.run_device "
            "(run_id, agent_id, hostname, os, bucket, updated_at_ms) "
            "SELECT $1, a, h, o, 'inc', $5::bigint "
            "FROM unnest($2::text[], $3::text[], $4::text[]) AS t(a, h, o)",
            std::vector<std::string>{run.run_id, pg::to_text_array(agent_ids),
                                     pg::to_text_array(hostnames), pg::to_text_array(oses), ts});
        if (r2.status() != PGRES_COMMAND_OK && r2.status() != PGRES_TUPLES_OK) {
            spdlog::warn("PreflightRunStore: target seed insert failed: {}", PQerrorMessage(conn));
            return false;
        }
        return true;
    });
}

std::optional<PreflightRunRow> PreflightRunStore::get_run(const std::string& run_id,
                                                         const std::string& created_by) {
    if (!open_ || run_id.empty())
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    std::string sql =
        std::string("SELECT ") + kRunCols + " FROM preflight_run_store.runs WHERE run_id = $1";
    std::vector<std::string> params{run_id};
    if (!created_by.empty()) {
        sql += " AND created_by = $2"; // owner-scope at the seam
        params.push_back(created_by);
    }
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return read_run(res.get(), 0);
}

std::vector<PreflightRunRow> PreflightRunStore::list_runs(const std::string& viewer, bool is_admin,
                                                          int limit) {
    std::vector<PreflightRunRow> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    const int cap = (limit > 0 && limit < kRunListCap) ? limit : kRunListCap;
    const std::string sql_admin =
        std::string("SELECT ") + kRunCols +
        " FROM preflight_run_store.runs ORDER BY created_at_ms DESC LIMIT $1::bigint";
    const std::string sql_owner =
        std::string("SELECT ") + kRunCols +
        " FROM preflight_run_store.runs WHERE created_by = $1 ORDER BY created_at_ms DESC "
        "LIMIT $2::bigint";
    pg::PgResult res =
        is_admin ? pg::exec_params(lease.get(), sql_admin.c_str(),
                                   std::vector<std::string>{std::to_string(cap)})
                 : pg::exec_params(lease.get(), sql_owner.c_str(),
                                   std::vector<std::string>{viewer, std::to_string(cap)});
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_run(res.get(), i));
    return out;
}

std::vector<PreflightRunRow> PreflightRunStore::list_running() {
    std::vector<PreflightRunRow> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    const std::string sql =
        std::string("SELECT ") + kRunCols +
        " FROM preflight_run_store.runs WHERE status = 'running' ORDER BY created_at_ms ASC "
        "LIMIT $1::bigint";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(),
                        std::vector<std::string>{std::to_string(kRunListCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_run(res.get(), i));
    return out;
}

std::vector<preflight::PreflightTarget> PreflightRunStore::get_targets(const std::string& run_id) {
    std::vector<preflight::PreflightTarget> out;
    if (!open_ || run_id.empty())
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, hostname, os FROM preflight_run_store.run_device "
        "WHERE run_id = $1 ORDER BY hostname LIMIT $2::bigint",
        std::vector<std::string>{run_id, std::to_string(kRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        preflight::PreflightTarget t;
        t.agent_id = PQgetvalue(res.get(), i, 0);
        t.hostname = PQgetvalue(res.get(), i, 1);
        t.os = PQgetvalue(res.get(), i, 2);
        out.push_back(std::move(t));
    }
    return out;
}

std::vector<PreflightRunDeviceRow> PreflightRunStore::get_devices(const std::string& run_id) {
    std::vector<PreflightRunDeviceRow> out;
    if (!open_ || run_id.empty())
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, hostname, os, bucket, checks_json, updated_at_ms "
        "FROM preflight_run_store.run_device WHERE run_id = $1 ORDER BY hostname LIMIT $2::bigint",
        std::vector<std::string>{run_id, std::to_string(kRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        PreflightRunDeviceRow d;
        d.agent_id = PQgetvalue(res.get(), i, 0);
        d.hostname = PQgetvalue(res.get(), i, 1);
        d.os = PQgetvalue(res.get(), i, 2);
        d.bucket = PQgetvalue(res.get(), i, 3);
        d.checks_json = PQgetvalue(res.get(), i, 4);
        d.updated_at_ms = to_i64(PQgetvalue(res.get(), i, 5));
        out.push_back(std::move(d));
    }
    return out;
}

bool PreflightRunStore::persist_grid(const std::string& run_id,
                                     const std::vector<PreflightRunDeviceRow>& devices, int total,
                                     int go, int warn, int nogo, int inc) {
    if (!open_ || run_id.empty())
        return false;
    // ONE batched upsert via unnest of parallel arrays, instead of N per-row
    // round-trips inside a single held lease (#governance perf-S1/UP-7 — matches
    // create_run's batch). The string_views alias `devices`, valid for the
    // synchronous with_txn_for below; to_text_array copies the bytes (and drops
    // 0x00, which checks_json/ids never contain).
    std::vector<std::string_view> aids, hosts, oses, buckets, jsons;
    aids.reserve(devices.size());
    hosts.reserve(devices.size());
    oses.reserve(devices.size());
    buckets.reserve(devices.size());
    jsons.reserve(devices.size());
    std::int64_t ts = 0;
    for (const auto& d : devices) {
        if (d.agent_id.empty())
            continue;
        aids.emplace_back(d.agent_id);
        hosts.emplace_back(d.hostname);
        oses.emplace_back(d.os);
        buckets.emplace_back(d.bucket);
        jsons.emplace_back(d.checks_json);
        ts = d.updated_at_ms; // one tick-time stamps the whole grid
    }
    const std::string ts_s = std::to_string(ts);
    return pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        if (!aids.empty()) {
            pg::PgResult r = pg::exec_params(
                conn,
                "INSERT INTO preflight_run_store.run_device "
                "(run_id, agent_id, hostname, os, bucket, checks_json, updated_at_ms) "
                "SELECT $1, a, h, o, b, j, $7::bigint "
                "FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) "
                "  AS t(a, h, o, b, j) "
                "ON CONFLICT (run_id, agent_id) DO UPDATE SET "
                "  bucket = EXCLUDED.bucket, checks_json = EXCLUDED.checks_json, "
                "  updated_at_ms = EXCLUDED.updated_at_ms",
                std::vector<std::string>{run_id, pg::to_text_array(aids), pg::to_text_array(hosts),
                                         pg::to_text_array(oses), pg::to_text_array(buckets),
                                         pg::to_text_array(jsons), ts_s});
            if (r.status() != PGRES_COMMAND_OK && r.status() != PGRES_TUPLES_OK) {
                spdlog::warn("PreflightRunStore: grid upsert failed (run={}): {}", run_id,
                             PQerrorMessage(conn));
                return false;
            }
        }
        pg::PgResult rs = pg::exec_params(
            conn,
            "UPDATE preflight_run_store.runs SET total=$2::int, go=$3::int, warn=$4::int, "
            "nogo=$5::int, incomplete=$6::int WHERE run_id=$1 RETURNING run_id",
            std::vector<std::string>{run_id, std::to_string(total), std::to_string(go),
                                     std::to_string(warn), std::to_string(nogo),
                                     std::to_string(inc)});
        // RETURNING 0 rows ⇒ the run was deleted mid-tick (UP-14): roll back, the
        // runner won't complete it.
        return rs.status() == PGRES_TUPLES_OK && PQntuples(rs.get()) > 0;
    });
}

bool PreflightRunStore::complete_run(const std::string& run_id, std::int64_t completed_at_ms) {
    if (!open_ || run_id.empty())
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout); // a write — match the other mutations
    if (!lease)
        return false;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE preflight_run_store.runs SET status='complete', completed_at_ms=$2::bigint "
        "WHERE run_id=$1 AND status='running' RETURNING run_id",
        std::vector<std::string>{run_id, std::to_string(completed_at_ms)});
    // Require an actually-updated row: an unknown or already-complete run yields 0
    // rows → false (no silent "success" on a no-op; #governance quality/consistency).
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0;
}

int PreflightRunStore::prune_older_than(std::int64_t cutoff_ms) {
    if (!open_)
        return -1;
    auto lease = pool_.try_acquire_for(kWriteTimeout); // a DELETE — write budget
    if (!lease)
        return -1;
    pg::PgResult res =
        pg::exec_params(lease.get(),
                        "DELETE FROM preflight_run_store.runs WHERE created_at_ms < $1::bigint "
                        "RETURNING run_id",
                        std::vector<std::string>{std::to_string(cutoff_ms)});
    if (res.status() != PGRES_TUPLES_OK)
        return -1;
    return PQntuples(res.get());
}

bool PreflightRunStore::delete_run(const std::string& run_id, const std::string& created_by) {
    if (!open_ || run_id.empty())
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout); // a DELETE — write budget
    if (!lease)
        return false;
    // Owner-scope is enforced HERE at the seam (the sole chokepoint — the route
    // does not pre-check ownership): a non-owner / unknown run_id deletes 0 rows.
    // run_device cascades via the FK ON DELETE CASCADE.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM preflight_run_store.runs WHERE run_id=$1 AND created_by=$2 RETURNING run_id",
        std::vector<std::string>{run_id, created_by});
    return res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0;
}

} // namespace yuzu::server
