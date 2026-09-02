#include "execution_tracker.hpp"

#include "execution_event_bus.hpp"
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <random>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "execution_tracker";

// Bounded acquires (ADR-0012 §2). No hot-path caller here — every runtime
// acquire uses the ordinary CRUD budget (matches PatchManager/ScheduleEngine/
// ApprovalManager).
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};

std::string generate_id() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    auto hi = dist(rng);
    auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx", static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}
std::string col_str(PGresult* res, int row, int c) { return std::string(col(res, row, c)); }
std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
int to_i(const char* s) { return static_cast<int>(to_i64(s)); }
double to_d(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0.0;
    return std::strtod(s, nullptr);
}

Execution row_to_exec(PGresult* r, int i) {
    Execution e;
    e.id = col_str(r, i, 0);
    e.definition_id = col_str(r, i, 1);
    e.status = col_str(r, i, 2);
    e.scope_expression = col_str(r, i, 3);
    e.parameter_values = col_str(r, i, 4);
    e.dispatched_by = col_str(r, i, 5);
    e.dispatched_at = to_i64(col(r, i, 6));
    e.agents_targeted = to_i(col(r, i, 7));
    e.agents_responded = to_i(col(r, i, 8));
    e.agents_success = to_i(col(r, i, 9));
    e.agents_failure = to_i(col(r, i, 10));
    e.completed_at = to_i64(col(r, i, 11));
    e.parent_id = col_str(r, i, 12);
    e.rerun_of = col_str(r, i, 13);
    e.last_error_detail = col_str(r, i, 14);
    return e;
}

// Base column list — every consumer pays this. The 14 fixed columns are
// indexed via the executions PK / status / dispatched / definition indexes.
const char* kSelectBase = "id, definition_id, status, scope_expression, parameter_values, "
                          "dispatched_by, dispatched_at, agents_targeted, agents_responded, "
                          "agents_success, agents_failure, completed_at, parent_id, rerun_of";

// Opt-in correlated subquery surfacing the most-recent non-empty agent
// error. CASE-gated on `agents_failure > 0` so fully-successful runs pay
// zero cost. Out-of-band consumers (health probes, metrics tick at
// server.cpp) opt OUT via ExecutionQuery::include_error_detail = false to
// avoid the partition sort on every tick (arch-B2 / perf-B1).
const char* kSelectErrorDetailExpr =
    ", (CASE WHEN agents_failure > 0 THEN ("
    "  SELECT error_detail FROM execution_tracker.agent_exec_status "
    "  WHERE execution_id = executions.id AND error_detail != '' "
    "  ORDER BY completed_at DESC LIMIT 1"
    ") ELSE '' END) AS last_error_detail";

// Empty-string placeholder so `row_to_exec` can read column 14
// unconditionally without branching on which column list was used.
const char* kSelectErrorDetailEmpty = ", '' AS last_error_detail";

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    //
    // Folds the SQLite-era v1+v2 ladder (v2 added agent_exec_status.
    // plugin_result_status, PR1.1 ABI4 CC-07) into a single v1 DDL — the
    // typed per-agent result column is present from creation on a fresh
    // Postgres schema (ADR-0009 fresh-start-by-default).
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE executions ("
         "  id                TEXT    PRIMARY KEY,"
         "  definition_id     TEXT    NOT NULL,"
         "  status            TEXT    NOT NULL DEFAULT 'pending',"
         "  scope_expression  TEXT    NOT NULL DEFAULT '',"
         "  parameter_values  TEXT    NOT NULL DEFAULT '',"
         "  dispatched_by     TEXT    NOT NULL DEFAULT '',"
         "  dispatched_at     BIGINT  NOT NULL DEFAULT 0,"
         "  agents_targeted   INTEGER NOT NULL DEFAULT 0,"
         "  agents_responded  INTEGER NOT NULL DEFAULT 0,"
         "  agents_success    INTEGER NOT NULL DEFAULT 0,"
         "  agents_failure    INTEGER NOT NULL DEFAULT 0,"
         "  completed_at      BIGINT  NOT NULL DEFAULT 0,"
         "  parent_id         TEXT    NOT NULL DEFAULT '',"
         "  rerun_of          TEXT    NOT NULL DEFAULT ''"
         ");"
         "CREATE TABLE agent_exec_status ("
         "  execution_id          TEXT    NOT NULL,"
         "  agent_id              TEXT    NOT NULL,"
         "  status                TEXT    NOT NULL DEFAULT 'pending',"
         "  dispatched_at         BIGINT  NOT NULL DEFAULT 0,"
         "  first_response_at     BIGINT  NOT NULL DEFAULT 0,"
         "  completed_at          BIGINT  NOT NULL DEFAULT 0,"
         "  exit_code             INTEGER NOT NULL DEFAULT 0,"
         "  error_detail          TEXT    NOT NULL DEFAULT '',"
         "  plugin_result_status  INTEGER NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (execution_id, agent_id)"
         ");"
         "CREATE INDEX idx_executions_status ON executions(status);"
         "CREATE INDEX idx_agent_exec_agent ON agent_exec_status(agent_id);"
         "CREATE INDEX idx_executions_dispatched ON executions(dispatched_at);"
         "CREATE INDEX idx_executions_definition ON executions(definition_id);"},
        // HA WS-1(1b), ADR-2002 section 5: the command_id -> execution_id
        // correlation, migrated off AgentServiceImpl's in-process map so a
        // response landing on ANY server replica can resolve it. reap_meta
        // is this store's own persisted-anchor table for
        // reap_command_execution_mappings (clock-guarded-retention routed
        // concern) — deliberately separate from `executions`/
        // `agent_exec_status`, which carry no retention sweep of their own.
        {2,
         "CREATE TABLE command_execution ("
         "  command_id    TEXT   PRIMARY KEY,"
         "  execution_id  TEXT   NOT NULL,"
         "  created_at    BIGINT NOT NULL"
         ");"
         "CREATE INDEX idx_command_execution_created ON command_execution(created_at);"
         "CREATE TABLE reap_meta ("
         "  key   TEXT PRIMARY KEY,"
         "  value TEXT NOT NULL"
         ");"},
    };
    return kMigrations;
}

} // namespace

ExecutionTracker::ExecutionTracker(pg::PgPool& pool) : pool_(pool) {
    // Construction-only unbounded acquire (ADR-0012 §2) — every runtime
    // acquire elsewhere in this file is bounded.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error(
            "ExecutionTracker: no database connection at construction ({}) — execution "
            "tracker disabled",
            pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("ExecutionTracker: schema migration failed — execution tracker disabled");
        return;
    }
    open_ = true;
    // ADR-0009's 2026-08-25 fresh-start-by-default amendment: no
    // migrate_from_sqlite here, unconditionally, no flag. The caller
    // (server.cpp) separately runs legacy_sqlite_probe::warn_if_legacy_rows()
    // over the legacy instructions.db so a locally-wrong "no production
    // fleet" premise still gets a loud signal.
    spdlog::info("ExecutionTracker initialized (schema {}) — fresh start, no legacy backfill",
                 kStoreName);
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

namespace {
/// Lease-free single-row read, taking an already-held connection directly.
/// Used both by the public `get_execution`/`get_summary` (which acquire
/// their own lease) and internally by `refresh_counts`'s transaction
/// (reusing the connection it already holds) — per pg_pool.hpp's own
/// documented gotcha, calling a lease-acquiring public method from inside
/// an already-held `with_txn_for` callback would acquire a SECOND
/// connection from the same pool, deadlocking a small pool.
std::optional<Execution> exec_by_id_at(PGconn* conn, const std::string& id) {
    auto sql = std::string("SELECT ") + kSelectBase + kSelectErrorDetailExpr +
               " FROM execution_tracker.executions WHERE id = $1";
    pg::PgResult res = pg::exec_params(conn, sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return row_to_exec(res.get(), 0);
}
} // namespace

std::vector<Execution> ExecutionTracker::query_executions(const ExecutionQuery& q) const {
    std::vector<Execution> results;
    if (!open_)
        return results;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return results;

    std::string sql = std::string("SELECT ") + kSelectBase +
                      (q.include_error_detail ? kSelectErrorDetailExpr : kSelectErrorDetailEmpty) +
                      " FROM execution_tracker.executions WHERE 1=1";
    std::vector<std::string> params;
    int idx = 1;

    if (!q.definition_id.empty()) {
        sql += " AND definition_id = $" + std::to_string(idx++);
        params.push_back(q.definition_id);
    }
    if (!q.status.empty()) {
        sql += " AND status = $" + std::to_string(idx++);
        params.push_back(q.status);
    }
    if (!q.dispatched_by.empty()) {
        sql += " AND dispatched_by = $" + std::to_string(idx++);
        params.push_back(q.dispatched_by);
    }
    sql += " ORDER BY dispatched_at DESC LIMIT $" + std::to_string(idx++);
    params.push_back(std::to_string(q.limit));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return results;

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        results.push_back(row_to_exec(res.get(), i));
    return results;
}

// Single-row reads (`get_execution` / `get_summary`) always opt into the
// error-detail subquery — they're rare, called from the detail handler /
// MCP / tests, never from health-tick paths.
std::optional<Execution> ExecutionTracker::get_execution(const std::string& id) const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    return exec_by_id_at(lease.get(), id);
}

ExecutionSummary ExecutionTracker::get_summary(const std::string& id) const {
    ExecutionSummary s;
    s.id = id;
    if (!open_)
        return s;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return s;

    if (auto exec = exec_by_id_at(lease.get(), id)) {
        s.status = exec->status;
        s.agents_targeted = exec->agents_targeted;
        s.agents_responded = exec->agents_responded;
        s.agents_success = exec->agents_success;
        s.agents_failure = exec->agents_failure;
        s.progress_pct = s.agents_targeted > 0 ? (s.agents_responded * 100 / s.agents_targeted) : 0;
    }
    return s;
}

std::optional<std::vector<AgentExecStatus>>
ExecutionTracker::get_agent_statuses_checked(const std::string& execution_id) const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, status, dispatched_at, first_response_at, completed_at, exit_code, "
        "error_detail, COALESCE(plugin_result_status, 0) FROM execution_tracker.agent_exec_status "
        "WHERE execution_id = $1 ORDER BY agent_id",
        std::vector<std::string>{execution_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::nullopt;

    std::vector<AgentExecStatus> results;
    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        AgentExecStatus a;
        a.agent_id = col_str(res.get(), i, 0);
        a.status = col_str(res.get(), i, 1);
        a.dispatched_at = to_i64(col(res.get(), i, 2));
        a.first_response_at = to_i64(col(res.get(), i, 3));
        a.completed_at = to_i64(col(res.get(), i, 4));
        a.exit_code = to_i(col(res.get(), i, 5));
        a.error_detail = col_str(res.get(), i, 6);
        a.plugin_result_status = to_i(col(res.get(), i, 7));
        results.push_back(std::move(a));
    }
    return results;
}

std::vector<AgentExecStatus>
ExecutionTracker::get_agent_statuses(const std::string& execution_id) const {
    return get_agent_statuses_checked(execution_id).value_or(std::vector<AgentExecStatus>{});
}

std::unordered_map<std::string, std::vector<AgentExecStatus>>
ExecutionTracker::get_agent_statuses_for_executions(
    const std::vector<std::string>& execution_ids) const {
    std::unordered_map<std::string, std::vector<AgentExecStatus>> by_execution;
    // Engaged-empty: zero requested executions means zero rows, without
    // touching the pool — success-empty, not degrade (matches
    // ResponseStore::facet_values' convention for this same shape).
    if (execution_ids.empty())
        return by_execution;
    if (!open_)
        return by_execution;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return by_execution;

    std::vector<std::string_view> sv(execution_ids.begin(), execution_ids.end());
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT execution_id, agent_id, status, dispatched_at, first_response_at, completed_at, "
        "exit_code, error_detail, COALESCE(plugin_result_status, 0) "
        "FROM execution_tracker.agent_exec_status "
        "WHERE execution_id = ANY($1::text[]) ORDER BY execution_id, agent_id",
        std::vector<std::string>{pg::to_text_array(sv)});
    if (res.status() != PGRES_TUPLES_OK)
        return by_execution;

    const int rows = PQntuples(res.get());
    for (int i = 0; i < rows; ++i) {
        AgentExecStatus a;
        a.agent_id = col_str(res.get(), i, 1);
        a.status = col_str(res.get(), i, 2);
        a.dispatched_at = to_i64(col(res.get(), i, 3));
        a.first_response_at = to_i64(col(res.get(), i, 4));
        a.completed_at = to_i64(col(res.get(), i, 5));
        a.exit_code = to_i(col(res.get(), i, 6));
        a.error_detail = col_str(res.get(), i, 7);
        a.plugin_result_status = to_i(col(res.get(), i, 8));
        by_execution[col_str(res.get(), i, 0)].push_back(std::move(a));
    }
    return by_execution;
}

std::vector<Execution> ExecutionTracker::get_children(const std::string& parent_id) const {
    std::vector<Execution> results;
    if (!open_)
        return results;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return results;

    // get_children is used by workflow drill-down — opt out of the
    // error-detail subquery to keep the workflow-step expansion cheap.
    auto sql = std::string("SELECT ") + kSelectBase + kSelectErrorDetailEmpty +
               " FROM execution_tracker.executions WHERE parent_id = $1 ORDER BY dispatched_at DESC";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{parent_id});
    if (res.status() != PGRES_TUPLES_OK)
        return results;

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        results.push_back(row_to_exec(res.get(), i));
    return results;
}

// ---------------------------------------------------------------------------
// Mutation
// ---------------------------------------------------------------------------

std::expected<std::string, std::string> ExecutionTracker::create_execution(const Execution& exec) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("execution tracker temporarily unavailable (pool exhausted)");

    auto id = exec.id.empty() ? generate_id() : exec.id;
    auto now = now_epoch();
    auto status = exec.status.empty() ? "running" : exec.status;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO execution_tracker.executions "
        "(id, definition_id, status, scope_expression, parameter_values, "
        " dispatched_by, dispatched_at, agents_targeted, agents_responded, "
        " agents_success, agents_failure, completed_at, parent_id, rerun_of) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        std::vector<std::string>{
            id, exec.definition_id, status, exec.scope_expression, exec.parameter_values,
            exec.dispatched_by,
            std::to_string(exec.dispatched_at > 0 ? exec.dispatched_at : now),
            std::to_string(exec.agents_targeted), std::to_string(exec.agents_responded),
            std::to_string(exec.agents_success), std::to_string(exec.agents_failure),
            std::to_string(exec.completed_at), exec.parent_id, exec.rerun_of});

    if (res.status() != PGRES_COMMAND_OK) {
        // Scrubbed generic string to the caller (matches ScheduleEngine/
        // ApprovalManager's equivalent path — governance consistency-auditor,
        // 2026-08-31: this used to leak the raw Postgres diagnostic); the
        // diagnostic itself goes server-side only.
        spdlog::error("ExecutionTracker::create_execution: insert failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected("insert failed (pool degraded or transaction failed)");
    }
    return id;
}

bool ExecutionTracker::upsert_agent_status_once(const std::string& execution_id,
                                                const AgentExecStatus& s) {
    // Snapshot-and-release (governance round perf-B1 / UP-A9), preserved
    // under the pool model: build the SSE payload, release the lease
    // (scope exit), THEN publish. Holding a lease across publish would
    // hold a pool connection for the duration of every downstream SSE
    // listener body — the same "slow client stalls every other agent
    // reporting onto this execution" hazard the original mutex-based
    // rationale described, now against pool capacity instead of a mutex.
    bool should_publish = false;
    nlohmann::json payload;

    {
        auto lease = pool_.try_acquire_for(kWriteTimeout);
        if (!lease)
            return false;

        auto now = now_epoch();
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "INSERT INTO execution_tracker.agent_exec_status "
            "(execution_id, agent_id, status, dispatched_at, first_response_at, completed_at, "
            " exit_code, error_detail, plugin_result_status) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) "
            "ON CONFLICT (execution_id, agent_id) DO UPDATE SET "
            "  status=excluded.status, "
            "  first_response_at=CASE WHEN agent_exec_status.first_response_at=0 "
            "                          THEN excluded.first_response_at "
            "                          ELSE agent_exec_status.first_response_at END, "
            "  completed_at=excluded.completed_at, "
            "  exit_code=excluded.exit_code, "
            "  error_detail=excluded.error_detail, "
            "  plugin_result_status=excluded.plugin_result_status",
            std::vector<std::string>{
                execution_id, s.agent_id, s.status,
                std::to_string(s.dispatched_at > 0 ? s.dispatched_at : now),
                std::to_string(s.first_response_at > 0 ? s.first_response_at : now),
                std::to_string(s.completed_at), std::to_string(s.exit_code), s.error_detail,
                std::to_string(s.plugin_result_status)});
        if (res.status() != PGRES_COMMAND_OK)
            return false;

        if (event_bus_) {
            should_publish = true;
            payload["agent_id"] = s.agent_id;
            payload["status"] = s.status;
            payload["exit_code"] = s.exit_code;
            payload["completed_at"] = s.completed_at;
            if (!s.error_detail.empty())
                payload["error_detail"] = s.error_detail;
            if (s.plugin_result_status != 0)
                payload["plugin_result_status"] = s.plugin_result_status;
        }
    } // lease released here — publish below runs lease-free.

    if (should_publish) {
        event_bus_->publish(execution_id, "agent-transition", payload.dump());
    }
    return true;
}

void ExecutionTracker::update_agent_status(const std::string& execution_id,
                                           const AgentExecStatus& s) {
    if (!open_)
        return;

    // Retry once on failure, same rationale as refresh_counts's
    // own retry (governance adversarial review, PR review 2026-08-31,
    // Doomgoose): a lease-acquire timeout or a cancelled statement under
    // row-lock contention here is silent by default and, unlike
    // refresh_counts's failure mode, unrecoverable by #3729's reconciler —
    // the reconciler recomputes FROM agent_exec_status rows, so a row that
    // was never inserted has nothing to reconcile from (the agent does not
    // re-send). Loud logging on final failure at least surfaces the loss.
    bool ok = false;
    for (int attempt = 0; attempt < 2 && !ok; ++attempt)
        ok = upsert_agent_status_once(execution_id, s);
    if (!ok) {
        spdlog::error("ExecutionTracker::update_agent_status: upsert failed twice for "
                      "execution_id={} agent_id={} — this agent's status is NOT recorded and "
                      "will not be reconciled (agents do not re-send)",
                      execution_id, s.agent_id);
        return;
    }

    // UAT 2026-05-06: chain refresh_counts so the parent executions row's
    // agents_responded / agents_success / agents_failure aggregates reflect
    // this state change. Without this, the dashboard's executions list
    // shows "0/0 of N" even after every agent has reported. refresh_counts
    // also crosses the all-agents-responded threshold to terminal status
    // and publishes execution-progress + execution-completed events, so
    // calling it here makes update_agent_status the single mutation entry
    // point that keeps both per-agent state and parent aggregates in sync.
    // refresh_counts acquires its own lease, so this runs independently of
    // the upsert above (no nested pool acquisition). The agent-transition
    // publish above happens BEFORE the execution-progress publish below,
    // preserving the documented client-visible event ordering
    // (executions-history ladder PR 3 publisher invariant).
    refresh_counts(execution_id);
}

bool ExecutionTracker::set_agents_targeted(const std::string& execution_id, int agents_targeted) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ExecutionTracker::set_agents_targeted: pool exhausted for execution_id={}",
                      execution_id);
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "UPDATE execution_tracker.executions SET agents_targeted=$1 WHERE id=$2",
        std::vector<std::string>{std::to_string(agents_targeted), execution_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error(
            "ExecutionTracker::set_agents_targeted: update failed for execution_id={} — the "
            "row never learns its real agent count and can never reach the all-responded "
            "threshold refresh_counts checks, wedging it at 'running' with no automatic recovery",
            execution_id);
        return false;
    }
    return true;
}

void ExecutionTracker::refresh_counts(const std::string& execution_id) {
    if (!open_)
        return;

    // Retry once on failure (governance adversarial review 2026-08-31,
    // CHAOS-01): the aggregate UPDATE below takes a row-level lock other
    // concurrent refresh_counts calls for the SAME execution_id queue behind.
    // Under high agent-fanout that queue can exceed Postgres's server-side
    // lock_timeout (10s default, set once at connection-open in
    // pg::PgPool — NOT this file's kWriteTimeout, which only bounds the pool
    // lease acquisition), which cancels the statement and rolls back. The
    // pre-migration SQLite code used a recursive_mutex that blocked
    // UNBOUNDEDLY (no timeout, so it could never drop an update, only
    // queue) — this bounded-abandon failure mode is net-new to the Postgres
    // port. A single retry is not a no-op: by the time the first attempt has
    // waited out the full lock_timeout, the transaction(s) that were holding
    // the row have almost certainly long since committed or themselves timed
    // out, so the retry is very likely uncontended. A second failure is
    // logged loudly rather than silently dropped — without this, an
    // execution can wedge at "running" forever (agents_responded/success/
    // failure stale, no terminal transition, no execution-completed SSE)
    // with zero operator-visible signal (tracked for a fuller fix — a
    // periodic reconciler sweep — in the follow-up this finding filed).
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (refresh_counts_once(execution_id))
            return;
    }
    spdlog::error("ExecutionTracker: refresh_counts failed twice for execution {} — aggregate "
                  "counts and terminal transition may be stale; a subsequent agent status "
                  "update will retry, but a fully-reported execution may need operator "
                  "investigation (see docs/executions-history-ladder.md)",
                  execution_id);
}

bool ExecutionTracker::refresh_counts_once(const std::string& execution_id) {
    // Snapshot-and-release (perf-B1 / UP-A9). See update_agent_status for
    // the full rationale. We snapshot up to two SSE payloads inside the
    // transaction below, then publish after it commits and the lease is
    // released.
    bool publish_progress = false;
    bool publish_terminal = false;
    nlohmann::json progress_payload;
    nlohmann::json terminal_payload;
    bool transitioned_terminal_was = false;

    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // Recompute aggregate counts from agent_exec_status. One transaction
        // for the recompute + read-back + conditional terminal transition
        // below gives this the same consistency the SQLite-era app-level
        // mutex provided (a concurrent refresh_counts on the same execution
        // cannot observe a half-updated row), via Postgres's own MVCC
        // snapshot isolation instead of an app-level lock.
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE execution_tracker.executions SET "
            "  agents_responded = (SELECT COUNT(*) FROM execution_tracker.agent_exec_status "
            "                      WHERE execution_id=$1 AND status IN "
            "                      ('success','failure','timeout','rejected')), "
            "  agents_success   = (SELECT COUNT(*) FROM execution_tracker.agent_exec_status "
            "                      WHERE execution_id=$1 AND status='success'), "
            "  agents_failure   = (SELECT COUNT(*) FROM execution_tracker.agent_exec_status "
            "                      WHERE execution_id=$1 AND status IN "
            "                      ('failure','timeout','rejected')) "
            "WHERE id=$1",
            std::vector<std::string>{execution_id});
        if (upd.status() != PGRES_COMMAND_OK)
            return false;

        // Check if all agents responded and update status. Lease-free
        // helper (reuses `conn` directly) — calling the public
        // get_execution() here would acquire a SECOND connection from the
        // same pool mid-transaction (pg_pool.hpp's own documented
        // nesting-deadlock gotcha).
        auto exec = exec_by_id_at(conn, execution_id);
        bool transitioned_terminal = false;
        std::string final_status_str;
        if (exec && exec->agents_targeted > 0 && exec->agents_responded >= exec->agents_targeted) {
            const char* final_status = (exec->agents_failure == 0) ? "succeeded" : "completed";
            pg::PgResult term = pg::exec_params(
                conn,
                "UPDATE execution_tracker.executions SET status=$1, completed_at=$2 "
                "WHERE id=$3 AND status='running' RETURNING 1",
                std::vector<std::string>{final_status, std::to_string(now_epoch()), execution_id});
            // RETURNING carries the "row matched" signal in the result's row
            // count — closes the #1033-class sqlite3_changes()-after-step
            // race this store carried on the shared SQLite FULLMUTEX
            // connection (a bare affected-row count read after step() is
            // not atomic with the step itself under concurrent callers on
            // one connection; a per-lease Postgres connection plus
            // RETURNING has no such race to begin with).
            if (term.status() == PGRES_TUPLES_OK && PQntuples(term.get()) > 0) {
                transitioned_terminal = true;
                final_status_str = final_status;
            }
        }
        transitioned_terminal_was = transitioned_terminal;

        if (event_bus_ && exec) {
            publish_progress = true;
            progress_payload["agents_targeted"] = exec->agents_targeted;
            progress_payload["agents_responded"] = exec->agents_responded;
            progress_payload["agents_success"] = exec->agents_success;
            progress_payload["agents_failure"] = exec->agents_failure;
            if (transitioned_terminal)
                progress_payload["status"] = final_status_str;
            if (transitioned_terminal) {
                publish_terminal = true;
                terminal_payload["status"] = final_status_str;
                terminal_payload["agents_success"] = exec->agents_success;
                terminal_payload["agents_failure"] = exec->agents_failure;
            }
        }
        return true;
    }); // transaction committed / lease released here — publishes below run lease-free.

    if (!ok)
        return false;

    if (publish_progress) {
        event_bus_->publish(execution_id, "execution-progress", progress_payload.dump(),
                            transitioned_terminal_was);
    }
    if (publish_terminal) {
        event_bus_->publish(execution_id, "execution-completed", terminal_payload.dump(),
                            /*is_terminal=*/true);
    }
    return true;
}

std::expected<std::string, std::string>
ExecutionTracker::create_rerun(const std::string& original_id, const std::string& user,
                               bool failed_only) {
    auto orig = get_execution(original_id);
    if (!orig)
        return std::unexpected("original execution not found");

    Execution rerun;
    rerun.definition_id = orig->definition_id;
    rerun.scope_expression = orig->scope_expression;
    rerun.parameter_values = orig->parameter_values;
    rerun.dispatched_by = user;
    rerun.parent_id = original_id;
    rerun.rerun_of = original_id;
    rerun.status = "pending";

    if (failed_only) {
        // Count only failed agents as targets
        auto agents = get_agent_statuses(original_id);
        int failed_count = 0;
        for (const auto& a : agents) {
            if (a.status == "failure" || a.status == "timeout" || a.status == "rejected")
                ++failed_count;
        }
        rerun.agents_targeted = failed_count;
    } else {
        rerun.agents_targeted = orig->agents_targeted;
    }

    return create_execution(rerun);
}

bool ExecutionTracker::mark_cancelled(const std::string& id, const std::string& /*user*/) {
    if (!open_)
        return false;

    // Snapshot-and-release (perf-B1 / UP-A9). See update_agent_status for
    // the full rationale.
    bool should_publish = false;

    {
        auto lease = pool_.try_acquire_for(kWriteTimeout);
        if (!lease) {
            spdlog::error("ExecutionTracker::mark_cancelled: pool exhausted for execution id={}",
                          id);
            return false;
        }

        pg::PgResult res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.executions SET status='cancelled', completed_at=$1 WHERE id=$2",
            std::vector<std::string>{std::to_string(now_epoch()), id});
        if (res.status() != PGRES_COMMAND_OK) {
            spdlog::error("ExecutionTracker::mark_cancelled: update failed for execution id={} — "
                          "the execution was NOT actually cancelled",
                          id);
            return false;
        }

        if (event_bus_) {
            should_publish = true;
        }
    } // lease released — publish below runs lease-free.

    if (should_publish) {
        nlohmann::json payload;
        payload["status"] = "cancelled";
        event_bus_->publish(id, "execution-completed", payload.dump(), /*is_terminal=*/true);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Statistics (capability 1.9)
// ---------------------------------------------------------------------------

std::vector<AgentExecutionStats>
ExecutionTracker::get_agent_statistics(const ExecutionStatsQuery& q) const {
    std::vector<AgentExecutionStats> results;
    if (!open_)
        return results;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return results;

    // C5 fix: use status values actually set by update_agent_status/refresh_counts
    std::string sql = R"(
        SELECT a.agent_id,
               COUNT(*) AS total,
               SUM(CASE WHEN a.exit_code = 0 AND a.status != 'pending' THEN 1 ELSE 0 END) AS success,
               SUM(CASE WHEN a.exit_code != 0 OR a.status IN ('failure','timeout','rejected','error') THEN 1 ELSE 0 END) AS failure,
               AVG(CASE WHEN a.completed_at > a.dispatched_at
                        THEN a.completed_at - a.dispatched_at ELSE NULL END) AS avg_dur,
               MAX(a.dispatched_at) AS last_at
        FROM execution_tracker.agent_exec_status a
        JOIN execution_tracker.executions e ON e.id = a.execution_id
        WHERE a.status NOT IN ('pending','dispatched')
    )";
    std::vector<std::string> params;
    int idx = 1;
    if (!q.agent_id.empty()) {
        sql += " AND a.agent_id = $" + std::to_string(idx++);
        params.push_back(q.agent_id);
    }
    if (!q.definition_id.empty()) {
        sql += " AND e.definition_id = $" + std::to_string(idx++);
        params.push_back(q.definition_id);
    }
    if (q.since > 0) {
        sql += " AND a.dispatched_at >= $" + std::to_string(idx++);
        params.push_back(std::to_string(q.since));
    }
    if (q.until > 0) {
        sql += " AND a.dispatched_at <= $" + std::to_string(idx++);
        params.push_back(std::to_string(q.until));
    }
    sql += " GROUP BY a.agent_id ORDER BY total DESC LIMIT $" + std::to_string(idx++);
    params.push_back(std::to_string(q.limit > 0 ? q.limit : 50));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return results;

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        AgentExecutionStats s;
        s.agent_id = col_str(res.get(), i, 0);
        s.total_executions = to_i64(col(res.get(), i, 1));
        s.success_count = to_i64(col(res.get(), i, 2));
        s.failure_count = to_i64(col(res.get(), i, 3));
        s.avg_duration_seconds = to_d(col(res.get(), i, 4));
        s.last_execution_at = to_i64(col(res.get(), i, 5));
        s.success_rate = s.total_executions > 0 ? 100.0 * static_cast<double>(s.success_count) /
                                                      static_cast<double>(s.total_executions)
                                                : 0.0;
        results.push_back(std::move(s));
    }
    return results;
}

std::vector<DefinitionExecutionStats>
ExecutionTracker::get_definition_statistics(const ExecutionStatsQuery& q) const {
    std::vector<DefinitionExecutionStats> results;
    if (!open_)
        return results;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return results;

    // C5 fix: match all terminal execution statuses. NOTE (#3344): this
    // "NOT IN (pending, running)" idiom is deliberately NOT what
    // mcp_retry.hpp's is_execution_terminal() uses — that predicate is an
    // explicit allowlist so an unrecognized future status defaults to
    // non-terminal (keep polling) rather than terminal (stop silently) as
    // it would here. A new terminal status added to this analytics query
    // needs the same addition there, or the two poll tools sharing that
    // predicate will disagree with this rollup about which executions are
    // "done".
    std::string sql = R"(
        SELECT e.definition_id,
               COUNT(*) AS total,
               SUM(e.agents_targeted) AS total_agents,
               CASE WHEN SUM(e.agents_targeted) > 0
                    THEN 100.0 * SUM(e.agents_success) / SUM(e.agents_targeted) ELSE 0 END AS rate,
               AVG(CASE WHEN e.completed_at > e.dispatched_at
                        THEN e.completed_at - e.dispatched_at ELSE NULL END) AS avg_dur
        FROM execution_tracker.executions e
        WHERE e.status NOT IN ('pending','running')
    )";
    std::vector<std::string> params;
    int idx = 1;
    if (!q.definition_id.empty()) {
        sql += " AND e.definition_id = $" + std::to_string(idx++);
        params.push_back(q.definition_id);
    }
    if (q.since > 0) {
        sql += " AND e.dispatched_at >= $" + std::to_string(idx++);
        params.push_back(std::to_string(q.since));
    }
    if (q.until > 0) {
        sql += " AND e.dispatched_at <= $" + std::to_string(idx++);
        params.push_back(std::to_string(q.until));
    }
    sql += " GROUP BY e.definition_id ORDER BY total DESC LIMIT $" + std::to_string(idx++);
    params.push_back(std::to_string(q.limit > 0 ? q.limit : 50));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return results;

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        DefinitionExecutionStats s;
        s.definition_id = col_str(res.get(), i, 0);
        s.total_executions = to_i64(col(res.get(), i, 1));
        s.total_agents = to_i64(col(res.get(), i, 2));
        s.success_rate = to_d(col(res.get(), i, 3));
        s.avg_duration_seconds = to_d(col(res.get(), i, 4));
        results.push_back(std::move(s));
    }
    return results;
}

FleetExecutionSummary ExecutionTracker::get_fleet_summary(int64_t since) const {
    FleetExecutionSummary s;
    if (!open_)
        return s;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return s;

    // Total executions and success rate
    {
        std::string sql = R"(
            SELECT COUNT(*),
                   CASE WHEN SUM(agents_targeted) > 0
                        THEN 100.0 * SUM(agents_success) / SUM(agents_targeted) ELSE 0 END,
                   AVG(CASE WHEN completed_at > dispatched_at
                            THEN completed_at - dispatched_at ELSE NULL END)
            FROM execution_tracker.executions WHERE status NOT IN ('pending','running')
        )";
        std::vector<std::string> params;
        if (since > 0) {
            sql += " AND dispatched_at >= $1";
            params.push_back(std::to_string(since));
        }
        pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
        if (res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0) {
            s.total_executions = to_i64(col(res.get(), 0, 0));
            s.overall_success_rate = to_d(col(res.get(), 0, 1));
            s.avg_duration_seconds = to_d(col(res.get(), 0, 2));
        }
    }

    // Executions today
    {
        auto now = now_epoch();
        auto today_start = now - (now % 86400);
        pg::PgResult res = pg::exec_params(
            lease.get(), "SELECT COUNT(*) FROM execution_tracker.executions WHERE dispatched_at >= $1",
            std::vector<std::string>{std::to_string(today_start)});
        if (res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0)
            s.executions_today = to_i64(col(res.get(), 0, 0));
    }

    // Active agents
    {
        std::string sql = "SELECT COUNT(DISTINCT agent_id) FROM execution_tracker.agent_exec_status";
        std::vector<std::string> params;
        if (since > 0) {
            sql += " WHERE dispatched_at >= $1";
            params.push_back(std::to_string(since));
        }
        pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
        if (res.status() == PGRES_TUPLES_OK && PQntuples(res.get()) > 0)
            s.active_agents = to_i64(col(res.get(), 0, 0));
    }

    return s;
}

// ---------------------------------------------------------------------------
// Command <-> execution correlation (HA WS-1(1b), ADR-2002 section 5)
// ---------------------------------------------------------------------------

namespace {
// Substrate-tuned to this table — do not copy from session_store's
// constants (clock-guarded-retention routed concern: "never copy the
// numbers"). A command's realistic in-flight lifetime is seconds to a few
// minutes; 24h is generous headroom over any documented per-command
// timeout, so a mapping this old is stale by construction, not merely idle.
constexpr std::int64_t kCmdExecutionReapWindowSecs = 24 * 3600;
constexpr int kCmdExecutionReapCap = 5000;
// A DB `now()` reading more than this far ahead of the persisted anchor is
// an anomaly, not legitimate elapsed time between reap ticks. The nominal
// inter-pass interval is ~3600s (server.cpp's kCmdExecutionReapEveryNTicks),
// but this threshold MUST carry real headroom over that nominal value, not
// merely equal it (governance Gate 4 consistency-auditor finding, self-
// verified): four OTHER reaps share this thread's tick loop and coincide on
// the same tick as this one, and ordinary scheduler jitter across ~1800
// individual sleep_for(1s) calls between passes is a plausible, non-clock-
// skew way to exceed a zero-margin threshold — and because a declined pass
// never advances the anchor, a single false trip would NEVER self-heal (the
// gap only grows on every subsequent tick). 24h matches this table's own
// reap window (kCmdExecutionReapWindowSecs) — ~24x the nominal cadence,
// comfortably absorbing ordinary jitter while still catching a genuinely
// wrong clock (a jump of days, not seconds).
constexpr std::int64_t kMaxPlausibleSkewSecs = 24 * 3600;

// Checked parse for the two clock-guard-critical readings (the DB now()
// column and the persisted reap_meta anchor) — deliberately NOT this file's
// ambient `to_i64`, which is a lenient `strtoll`-with-no-validation helper
// appropriate for trusted DB-returned row columns elsewhere in this file,
// but NOT for a value the clock-guarded-retention routed concern (CLAUDE.md
// part 3) requires be SANITISED: "ahead-of-now / negative / unparseable =
// anomaly, never a quiet reset". A migration bug, a manual `reap_meta` repair,
// or storage corruption writing `123junk` or an overflowed value must be
// REJECTED as an anomaly, not silently truncated/wrapped by an unchecked
// strtoll (adversarial review finding, PR #3780 -- api_token_store.cpp's
// `parse_meta_i64` / response_store.cpp's inline equivalent are the
// reference shape this mirrors; a second hand-rolled copy is the drift
// those two already accepted as "duplicating this one is cheaper than a
// shared-utility header for a three-line function").
std::optional<std::int64_t> parse_reap_i64(const std::string& val) {
    errno = 0;
    char* end = nullptr;
    const long long v = std::strtoll(val.c_str(), &end, 10);
    if (val.empty() || errno != 0 || end == val.c_str() || *end != '\0')
        return std::nullopt;
    return static_cast<std::int64_t>(v);
}
} // namespace

bool ExecutionTracker::record_command_execution(const std::string& command_id,
                                                const std::string& execution_id) {
    if (!open_)
        return false;

    // SINGLE attempt, no retry — deliberately NOT update_agent_status's
    // retry-once shape (governance Gate 4 unhappy-path/Gate 3 performance
    // finding). This call sits on the SYNCHRONOUS pre-RPC dispatch path
    // (record_execution_id / server.cpp's command_dispatch_fn calls this
    // BEFORE the RPC, UP2-4); a retry-once here would double the worst-case
    // block on the calling worker thread (REST/dashboard/MCP dispatch, or a
    // background runner such as ScheduleRunner/PreflightRunner/
    // PolicyEvaluator — anything feeding the shared CommandDispatchFn
    // closure) (2*kWriteTimeout)
    // under sustained pool contention. update_agent_status's retry lives on
    // the async gateway-response path, where that tradeoff is free.
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ExecutionTracker::record_command_execution: pool exhausted for "
                      "command_id={} — this command's responses will not correlate to an "
                      "execution_id on any replica (executions-drawer/SSE degraded for it, "
                      "dispatch itself is unaffected)",
                      command_id);
        return false;
    }
    pg::PgResult res =
        execution_id.empty()
            ? pg::exec_params(lease.get(),
                              "DELETE FROM execution_tracker.command_execution "
                              "WHERE command_id = $1",
                              std::vector<std::string>{command_id})
            // created_at is authored from Postgres now() IN-SQL, not the
            // calling replica's app clock (adversarial review Should-fix,
            // PR #3780): reap_command_execution_mappings compares created_at
            // against its own DB `now()` reading, so authoring created_at
            // from a different (app) clock domain means a replica whose
            // local clock lags the DB primary by more than the reap window
            // can write a mapping that reads as already-expired the moment
            // another replica's sweep runs -- silently dropping the exact
            // correlation this migration exists to preserve, in the exact
            // multi-replica scenario it targets. Matches session_store's
            // DB-clock-authority precedent (#3715).
            : pg::exec_params(
                  lease.get(),
                  "INSERT INTO execution_tracker.command_execution "
                  "(command_id, execution_id, created_at) "
                  "VALUES ($1, $2, extract(epoch FROM now())::bigint) "
                  "ON CONFLICT (command_id) DO UPDATE SET "
                  "execution_id = EXCLUDED.execution_id, created_at = EXCLUDED.created_at",
                  std::vector<std::string>{command_id, execution_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error("ExecutionTracker::record_command_execution: write failed for "
                      "command_id={} — this command's responses will not correlate to an "
                      "execution_id on any replica (executions-drawer/SSE degraded for it, "
                      "dispatch itself is unaffected)",
                      command_id);
        return false;
    }
    return true;
}

std::optional<std::string>
ExecutionTracker::lookup_execution_id(const std::string& command_id,
                                      std::string* degrade_reason) const {
    if (!open_)
        return std::nullopt; // not a runtime degrade -- construction already failed loudly
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (degrade_reason)
            *degrade_reason = "pool_exhausted";
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(lease.get(),
                                       "SELECT execution_id FROM execution_tracker.command_execution "
                                       "WHERE command_id = $1",
                                       std::vector<std::string>{command_id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (degrade_reason)
            *degrade_reason = "query_failed";
        return std::nullopt;
    }
    if (PQntuples(res.get()) == 0)
        return std::nullopt; // genuine miss -- out-of-band dispatch or an aged-out mapping
    return col_str(res.get(), 0, 0);
}

std::expected<CommandExecutionReapOutcome, std::string>
ExecutionTracker::reap_command_execution_mappings() {
    if (!open_)
        return std::unexpected("execution tracker not open");

    // Shape mirrors SessionStore::reap_expired (clock-guarded-retention
    // routed concern) — advisory lock as its OWN statement, one in-SQL DB
    // `now()` read reused for the cutoff/anchor-compare/anchor-update,
    // persisted+sanitised anchor, forward/backward-anomaly decline,
    // unconditional cap. This table stores seconds (matching this store's
    // own `now_epoch()` convention), not the milliseconds session_store uses
    // — a substrate-tuning difference, not a shape deviation.
    int deleted = 0;
    bool clock_anomaly = false;
    std::int64_t now_s = 0;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        if (pg::exec_params(c, "SELECT pg_advisory_xact_lock(hashtext('execution_tracker:reap'))",
                            std::vector<std::string>{})
                .status() != PGRES_TUPLES_OK) {
            err = "reap advisory lock failed";
            return false;
        }
        {
            pg::PgResult nr = pg::exec_params(
                c, "SELECT extract(epoch FROM now())::bigint", std::vector<std::string>{});
            if (nr.status() != PGRES_TUPLES_OK || PQntuples(nr.get()) == 0) {
                err = "reap now() read failed";
                return false;
            }
            // SANITISE the reading (clock-guarded-retention routed concern,
            // part 3): unparseable or negative is an ANOMALY, never a quiet
            // fallback to 0/silently-truncated garbage (adversarial review
            // finding, PR #3780 -- the prior unchecked `to_i64` here would
            // parse a malformed/overflowed value with no error and no
            // rejection, in direct violation of this exact standing rule).
            auto parsed_now = parse_reap_i64(col_str(nr.get(), 0, 0));
            if (!parsed_now || *parsed_now < 0) {
                spdlog::warn("ExecutionTracker::reap_command_execution_mappings declined: "
                             "unparseable or negative now() reading '{}'",
                             col_str(nr.get(), 0, 0));
                clock_anomaly = true;
                return true; // decline, anchor unchanged
            }
            now_s = *parsed_now;
        }
        pg::PgResult ar = pg::exec_params(
            c, "SELECT value FROM execution_tracker.reap_meta WHERE key = 'cmd_exec_reap_anchor'",
            std::vector<std::string>{});
        if (ar.status() != PGRES_TUPLES_OK) {
            err = "reap anchor read failed";
            return false;
        }
        const bool has_anchor = PQntuples(ar.get()) > 0;
        std::int64_t anchor = 0;
        if (has_anchor) {
            // Same sanitisation as now_s, for the SAME reason -- reap_meta
            // is a plain key/value table a bad migration, a manual repair,
            // or storage corruption can write anything into. An unparseable
            // or negative persisted anchor is an anomaly: decline this
            // pass, do NOT silently treat it as 0 (which would read as
            // "everything is stale" and mass-delete) or as any other quiet
            // fallback.
            auto parsed_anchor = parse_reap_i64(col_str(ar.get(), 0, 0));
            if (!parsed_anchor || *parsed_anchor < 0) {
                spdlog::warn("ExecutionTracker::reap_command_execution_mappings declined: "
                             "unparseable or negative persisted anchor '{}'",
                             col_str(ar.get(), 0, 0));
                clock_anomaly = true;
                return true;
            }
            anchor = *parsed_anchor;
        }
        // Overflow-safe comparison (adversarial review Blocker round 2,
        // PR #3780): `parse_reap_i64` rejects unparseable/negative values
        // but NOT an implausibly-large one that parses cleanly (e.g.
        // INT64_MAX from a bad migration/manual repair/corruption) --
        // `anchor + kMaxPlausibleSkewSecs` on such a value is signed-
        // integer-overflow UB (confirmed via UBSan). Subtracting instead
        // of adding cannot overflow: both operands are already sanitised
        // to be non-negative int64_t, so their difference always fits
        // (int64_t's negative range strictly exceeds its positive range).
        // The `now_s >= anchor` guard preserves the existing branch order
        // -- when now_s < anchor, this condition is false and control
        // falls through to the backward-anomaly check below, unchanged.
        if (has_anchor && now_s >= anchor && now_s - anchor > kMaxPlausibleSkewSecs) {
            spdlog::warn("ExecutionTracker::reap_command_execution_mappings declined: now_s {} "
                         "implausibly ahead of anchor {}",
                         now_s, anchor);
            clock_anomaly = true;
            return true; // decline, anchor unchanged
        }
        if (has_anchor && now_s < anchor) {
            spdlog::warn("ExecutionTracker::reap_command_execution_mappings declined: now_s {} "
                         "is behind anchor {} (backward clock movement or a poisoned anchor) — "
                         "not deleting under a rewound clock",
                         now_s, anchor);
            clock_anomaly = true;
            return true;
        }
        pg::PgResult dr = pg::exec_params(
            c,
            "DELETE FROM execution_tracker.command_execution WHERE command_id IN "
            "(SELECT command_id FROM execution_tracker.command_execution "
            " WHERE created_at < $1::bigint LIMIT $2::bigint) RETURNING command_id",
            std::vector<std::string>{std::to_string(now_s - kCmdExecutionReapWindowSecs),
                                     std::to_string(kCmdExecutionReapCap)});
        if (dr.status() != PGRES_TUPLES_OK) {
            err = std::string("reap delete failed: ") + PQerrorMessage(c);
            return false;
        }
        deleted = PQntuples(dr.get());
        const std::int64_t new_anchor = has_anchor ? (std::max)(anchor, now_s) : now_s;
        pg::PgResult ur = pg::exec_params(
            c,
            "INSERT INTO execution_tracker.reap_meta (key, value) VALUES "
            "('cmd_exec_reap_anchor', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{std::to_string(new_anchor)});
        if (ur.status() != PGRES_COMMAND_OK) {
            err = "reap anchor update failed";
            return false;
        }
        return true;
    });
    if (!ok)
        return std::unexpected(err.empty() ? "reap failed" : err);
    return CommandExecutionReapOutcome{deleted, clock_anomaly};
}

} // namespace yuzu::server
