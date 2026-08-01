#include "response_store.hpp"

#include "audit_retention_rules.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "result_parsing.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <string_view>
#include <tuple>
#include <unordered_map>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "response_store";

// Bounded acquires (ADR-0012 §2(a)). Ingest runs on the gRPC thread and must
// give up fast (fail-soft — the agent's next report re-sends, or the
// executions ladder already tracked the command). Reads back interactive
// REST/dashboard/MCP callers.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
constexpr std::chrono::milliseconds kIngestTimeout{500};

// Ingest-drop / read-degrade reason labels (ADR-0037 label convention).
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr const char* kDegradeSource = "response_store";
// Sample the per-site degrade WARN so a sustained PG outage cannot flood the
// log — the counter is the continuous signal, the log a sampled breadcrumb.
// Mirrors InventoryStore / GuaranteedStateStore's constants.
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

// Clock-guarded retention (routed-concern invariant; #2496 gc_sweep shape,
// ADR-0038 pattern ported here per ADR-0039). Substrate-tuned: responses are
// high-write (every command result from every agent), so the per-pass cap
// matches GuaranteedStateStore's incident-volume figure rather than
// ResultSetStore's much smaller operator-scratch cap.
constexpr int64_t kReapCapPerPass = 10'000;
constexpr int64_t kReapBigStepSecs = 86'400; // part 7: absolute, ~1 day
// The implausibly-ahead bound (part 1) MUST exceed the legitimate TTL horizon
// or a live row's own honest ttl_expires_at gets misclassified as
// "implausibly ahead" and wrongly excluded from `datable` — flipping a
// normal partial-expiry pass into a false would_wipe decline (the ADR-0038
// lesson: this bound must be sized to THIS store's retention, never copied
// from a shorter-TTL sibling). `response_retention_days` is operator-
// configurable and UNCLAMPED (a compliance deployment may set it well above
// the 90-day default), so a FIXED constant would silently reintroduce the
// false-decline class the moment retention passes the constant — the whole
// live set would land past the bound and every pass would decline, so the
// table would never reap. The bound is therefore DERIVED from the store's own
// horizon at 2× (the ADR-0038 "size to THIS store's retention" rule taken
// literally), with a floor so a tiny/zero retention still catches genuinely
// corrupt/attacker-skewed far-future timestamps.
constexpr int64_t kReapImplausiblyAheadFloorSecs = 10'368'000; // ~120 days

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
bool to_bool(const char* s) { return s != nullptr && s[0] == 't'; }

// sanitize_utf8_strict (utf8_sanitize.hpp) scrubs invalid UTF-8 to U+FFFD but
// treats NUL (U+0000) as a valid ASCII byte and keeps it. PostgreSQL TEXT cannot
// store an embedded NUL, and libpq's text-format bind (paramLengths=nullptr)
// C-string-truncates the value at the first NUL — silently dropping everything
// after it (Gate 4 R3). On binary / mis-decoded plugin output that carries a
// 0x00 (the ADR's own motivating case) that would partially defeat #1593 (a
// real result must surface, defanged, never vanish) AND diverge the stored
// `output` from the facets derived off the same string. So after the UTF-8
// scrub, replace every NUL with U+FFFD too: the whole value survives to PG and
// facets stay byte-consistent with `output`. We do NOT touch utf8_sanitize.hpp
// itself — it is byte-identical with the agent's installed_software copy (the
// canonical-hash invariant); NUL handling is a PG-bind concern local to this
// store.
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}
double to_double(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0.0;
    return std::strtod(s, nullptr);
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col));
}

// `PQcmdTuples` — safe here because the connection is exclusively ours for
// the duration of the call (a pooled lease, never shared concurrently) —
// mirrors InventoryStore's `affected_rows` (the #1033 `sqlite3_changes()`
// replacement idiom).
std::int64_t affected_rows(const pg::PgResult& res) {
    const char* txt = PQcmdTuples(res.get());
    if (!txt || txt[0] == '\0')
        return 0;
    return std::strtoll(txt, nullptr, 10);
}

// ── Read-degrade observability ───────────────────────────────────────────────
// Mirrors InventoryStore / GuaranteedStateStore's DegradeSampler shape
// exactly (docs/postgres-store-playbook.md). One static sampler per read call
// site (declared `static DegradeSampler sampler;` inside each method) gates
// the sampled warn log; the Prometheus counter always increments.
struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};
struct DegradeLog {
    bool should_log;
    std::uint64_t occurrence;
};

DegradeLog note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason,
                             DegradeSampler& s) {
    if (metrics)
        metrics
            ->counter("yuzu_server_response_read_degrade_total",
                      {{"reason", reason}, {"source", kDegradeSource}})
            .increment();
    const std::int64_t now = now_epoch();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return {new_episode || (n % kReadDegradeLogSample) == 0, n};
}

void note_ingest_dropped(yuzu::MetricsRegistry* metrics, const char* reason) {
    if (metrics)
        metrics->counter("yuzu_server_response_ingest_dropped_total", {{"reason", reason}})
            .increment();
}

// Shared body for every degrade-distinguishable read (ADR-0039, mirrors
// GuaranteedStateStore's `dex_read<Result>` template — adapted to return
// `std::optional<Result>` since ResponseStore's reads are nullopt-on-degrade,
// not empty-on-degrade): acquire a bounded lease, run `body(conn)` (executes
// the query and returns the parsed result, or nullopt on a query-level
// failure), and count+sampled-log a degrade on store-not-open / pool-timeout
// / query-error. A successful EMPTY container is NOT a degrade — only
// `body()` returning nullopt is.
template <typename Result, typename Body>
std::optional<Result> resp_read(bool open, pg::PgPool& pool, yuzu::MetricsRegistry* metrics,
                                const char* method, DegradeSampler& sampler, Body&& body) {
    if (!open) {
        if (const auto d = note_read_degrade(metrics, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("ResponseStore::{}: store not open", method);
        return std::nullopt;
    }
    auto lease = pool.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("ResponseStore::{}: pool acquire timed out", method);
        return std::nullopt;
    }
    auto result = body(lease.get());
    if (!result) {
        if (const auto d = note_read_degrade(metrics, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("ResponseStore::{}: query failed", method);
        return std::nullopt;
    }
    return std::move(*result);
}

// ── Postgres schema (ADR-0039): the FINAL column set of the SQLite store's 3
// migrations, collapsed into one v1. Unqualified DDL — the migration runner
// sets search_path to `response_store` for the migration transaction.
// Runtime statements below schema-qualify explicitly.
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE responses (
                id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                instruction_id  TEXT    NOT NULL,
                agent_id        TEXT    NOT NULL,
                timestamp       BIGINT  NOT NULL,
                status          INTEGER NOT NULL,
                output          TEXT    NOT NULL,
                error_detail    TEXT    NOT NULL DEFAULT '',
                ttl_expires_at  BIGINT  NOT NULL DEFAULT 0,
                plugin          TEXT    NOT NULL DEFAULT '',
                execution_id    TEXT    NOT NULL DEFAULT '',
                received_at_ms  BIGINT  NOT NULL DEFAULT 0
            );
            CREATE INDEX idx_resp_instr_ts ON responses(instruction_id, timestamp);
            CREATE INDEX idx_resp_agent_ts ON responses(agent_id, timestamp);
            CREATE INDEX idx_resp_ttl ON responses(ttl_expires_at) WHERE ttl_expires_at > 0;
            CREATE INDEX idx_resp_instr_status ON responses(instruction_id, status);
            CREATE INDEX idx_resp_execution_ts
                ON responses(execution_id, timestamp) WHERE execution_id != '';

            -- ON DELETE CASCADE: a facet row never outlives its parent response —
            -- reap_expired() issues a SINGLE DELETE on `responses`; Postgres
            -- removes the matching facet rows automatically (the SQLite original
            -- had no FK and swept orphans with a second NOT-IN scan on every
            -- cleanup pass; the FK makes that second statement unnecessary).
            CREATE TABLE response_facets (
                response_id    BIGINT  NOT NULL REFERENCES responses(id) ON DELETE CASCADE,
                instruction_id TEXT    NOT NULL,
                agent_id       TEXT    NOT NULL,
                col_idx        INTEGER NOT NULL,
                value          TEXT    NOT NULL,
                line_count     INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (response_id, col_idx, value)
            );
            CREATE INDEX idx_facets_query ON response_facets(instruction_id, col_idx, value);
            CREATE INDEX idx_facets_agent ON response_facets(instruction_id, agent_id);

            -- Durable state for the reap_expired() clock-guard (#2496 shape,
            -- ADR-0038 pattern). SHARED rows (not process-local) — N server
            -- replicas each run the sweep, so the persisted reading + anomaly-
            -- dedup fact set must be one shared truth under the sweep's
            -- advisory lock.
            CREATE TABLE gc_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        )"},
    };
    return kMigrations;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

ResponseStore::ResponseStore(pg::PgPool& pool, int retention_days)
    : pool_(pool), retention_days_(retention_days) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("ResponseStore: no database connection at construction ({}) — response "
                      "persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("ResponseStore: schema migration failed — response persistence disabled");
        return;
    }
    open_ = true;
    spdlog::info("ResponseStore initialized (schema {}, retention={}d)", kStoreName,
                retention_days_);
}

int64_t ResponseStore::compute_ttl_epoch() const {
    if (retention_days_ <= 0)
        return 0; // sentinel: never expire
    return now_epoch() + static_cast<int64_t>(retention_days_) * 86400;
}

// ── Ingest (fail-soft) ────────────────────────────────────────────────────────

void ResponseStore::store(const StoredResponse& resp) {
    if (!open_) {
        note_ingest_dropped(metrics_, kReasonStoreNotOpen);
        return;
    }
    auto lease = pool_.try_acquire_for(kIngestTimeout);
    if (!lease) {
        spdlog::warn("ResponseStore: store skipped for instruction={} agent={}, no connection "
                     "({})",
                     resp.instruction_id, resp.agent_id, pool_.last_error());
        note_ingest_dropped(metrics_, kReasonPoolTimeout);
        return;
    }
    PGconn* conn = lease.get();

    const int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
    const int64_t now = now_ms / 1000;
    const int64_t ts = resp.timestamp > 0 ? resp.timestamp : now;
    const int64_t ttl = resp.ttl_expires_at > 0 ? resp.ttl_expires_at : compute_ttl_epoch();
    const int64_t received_ms = resp.received_at_ms > 0 ? resp.received_at_ms : now_ms;

    // ADR-0039 addendum: `output`/`error_detail` are untrusted agent-supplied
    // bytes — a plugin can emit arbitrary (non-UTF-8) content, which SQLite's
    // permissive TEXT affinity tolerated but Postgres TEXT rejects outright
    // (SQLSTATE 22021, invalid byte sequence for encoding UTF8). Sanitize to
    // U+FFFD BEFORE binding so the row still lands (governance #1593: a
    // malformed-but-real plugin result must still surface to the operator,
    // defanged, never silently vanish) — fail-soft stays reserved for genuine
    // infra errors, not a self-inflicted encoding rejection. Every other
    // ingest seam on untrusted text (inventory, app_perf, …) sanitizes the
    // same way before its own PG bind; `sanitize_utf8_strict` is the shared
    // implementation (utf8_sanitize.hpp).
    const std::string sanitized_output = sanitize_pg_text(resp.output);
    const std::string sanitized_error = sanitize_pg_text(resp.error_detail);

    pg::PgResult begin = pg::exec_params(conn, "BEGIN", std::vector<std::string>{});
    if (begin.status() != PGRES_COMMAND_OK) {
        spdlog::warn("ResponseStore: BEGIN failed for instruction={} agent={}: {}",
                     resp.instruction_id, resp.agent_id, PQerrorMessage(conn));
        note_ingest_dropped(metrics_, kReasonQueryError);
        return;
    }
    pg::PgTxn txn(conn);

    pg::PgResult ins = pg::exec_params(
        conn,
        "INSERT INTO response_store.responses (instruction_id, agent_id, timestamp, status, "
        "output, error_detail, ttl_expires_at, plugin, execution_id, received_at_ms) "
        "VALUES ($1,$2,$3::bigint,$4::integer,$5,$6,$7::bigint,$8,$9,$10::bigint) RETURNING id",
        std::vector<std::string>{resp.instruction_id, resp.agent_id, std::to_string(ts),
                                 std::to_string(resp.status), sanitized_output, sanitized_error,
                                 std::to_string(ttl), resp.plugin, resp.execution_id,
                                 std::to_string(received_ms)});
    if (ins.status() != PGRES_TUPLES_OK || PQntuples(ins.get()) != 1) {
        spdlog::warn("ResponseStore: insert failed for instruction={} agent={}: {}",
                     resp.instruction_id, resp.agent_id, PQerrorMessage(conn));
        note_ingest_dropped(metrics_, kReasonQueryError);
        return; // txn destructor rolls back
    }
    const int64_t response_id = to_i64(PQgetvalue(ins.get(), 0, 0));

    // Extract facets from the output using the plugin schema, then insert them
    // as a SINGLE batched multi-row INSERT under ONE savepoint. The savepoint
    // preserves the ADR-0038 guarantee (Postgres aborts the WHOLE transaction
    // on any failed statement, unlike SQLite's silent skip — so a facet failure
    // must not take the just-inserted response row down): on batch failure we
    // ROLLBACK TO this savepoint and still COMMIT the response row. But it is
    // ONE savepoint, not one-per-facet: the old per-facet loop minted a
    // subtransaction XID per distinct value, so a wide tabular output (>64
    // distinct facet values — a routine process/vuln list) suboverflowed the
    // ingest txn's snapshot and forced cluster-wide pg_subtrans SLRU lookups on
    // the SHARED server pool (Gate 4 R1). One savepoint bounds it to a single
    // subxid regardless of facet cardinality.
    if (!resp.plugin.empty() && !sanitized_output.empty()) {
        auto lines = split_output_lines(sanitized_output);
        // Accumulate (col_idx, value) → line_count. col_idx is 0-based offset
        // into the *field* array (excludes the Agent column, always column 0
        // in the schema).
        std::unordered_map<int, std::unordered_map<std::string, int>> facets;
        for (const auto& line : lines) {
            auto fields = split_fields(resp.plugin, line);
            for (int i = 0; i < static_cast<int>(fields.size()); ++i) {
                if (!fields[i].empty())
                    facets[i][fields[i]]++;
            }
        }
        std::vector<std::tuple<int, std::string, int>> flat;
        for (const auto& [col_idx, value_counts] : facets)
            for (const auto& [value, count] : value_counts)
                flat.emplace_back(col_idx, value, count);

        if (!flat.empty()) {
            pg::PgResult sp =
                pg::exec_params(conn, "SAVEPOINT facet_batch", std::vector<std::string>{});
            if (sp.status() != PGRES_COMMAND_OK) {
                spdlog::warn("ResponseStore: facet SAVEPOINT failed for response_id={}: {}",
                             response_id, PQerrorMessage(conn));
            } else {
                bool facets_ok = true;
                // Chunk so `3 + 3*chunk` stays well under libpq's 65535-param
                // ceiling; response_id/instruction_id/agent_id are $1/$2/$3
                // reused across every tuple, only (col_idx,value,count) vary.
                constexpr std::size_t kFacetChunk = 2000;
                for (std::size_t base = 0; facets_ok && base < flat.size();
                     base += kFacetChunk) {
                    const std::size_t stop = std::min(base + kFacetChunk, flat.size());
                    std::string sql =
                        "INSERT INTO response_store.response_facets (response_id, instruction_id, "
                        "agent_id, col_idx, value, line_count) VALUES ";
                    std::vector<std::string> params{std::to_string(response_id),
                                                    resp.instruction_id, resp.agent_id};
                    for (std::size_t i = base; i < stop; ++i) {
                        const auto& [col_idx, value, count] = flat[i];
                        const std::size_t p = params.size(); // 0-based; next is $(p+1)
                        if (i != base)
                            sql += ",";
                        sql += "($1::bigint,$2,$3,$" + std::to_string(p + 1) + "::integer,$" +
                               std::to_string(p + 2) + ",$" + std::to_string(p + 3) + "::integer)";
                        params.push_back(std::to_string(col_idx));
                        params.push_back(value);
                        params.push_back(std::to_string(count));
                    }
                    sql += " ON CONFLICT (response_id, col_idx, value) DO UPDATE SET "
                           "line_count = EXCLUDED.line_count";
                    pg::PgResult fi = pg::exec_params(conn, sql.c_str(), params);
                    if (fi.status() != PGRES_COMMAND_OK) {
                        spdlog::warn("ResponseStore: facet batch insert failed for response_id={}: "
                                     "{}",
                                     response_id, PQerrorMessage(conn));
                        facets_ok = false;
                    }
                }
                const char* fin_sql = facets_ok ? "RELEASE SAVEPOINT facet_batch"
                                                : "ROLLBACK TO SAVEPOINT facet_batch";
                pg::PgResult fin = pg::exec_params(conn, fin_sql, std::vector<std::string>{});
                if (fin.status() != PGRES_COMMAND_OK)
                    spdlog::warn("ResponseStore: facet savepoint finalize ({}) failed for "
                                 "response_id={}: {}",
                                 fin_sql, response_id, PQerrorMessage(conn));
            }
        }
    }

    if (!txn.commit()) {
        spdlog::warn("ResponseStore: commit failed for instruction={} agent={}: {}",
                     resp.instruction_id, resp.agent_id, PQerrorMessage(conn));
        note_ingest_dropped(metrics_, kReasonQueryError);
    }
}

ResponseStore::FinalizeResult ResponseStore::finalize_terminal_status(
    const std::string& instruction_id, const std::string& agent_id, int terminal_status,
    const std::string& error_detail, const std::string& execution_id) {
    if (!open_)
        return FinalizeResult::Error;
    auto lease = pool_.try_acquire_for(kIngestTimeout);
    if (!lease) {
        spdlog::error("ResponseStore::finalize_terminal_status: no connection: {}",
                      pool_.last_error());
        return FinalizeResult::Error;
    }
    // Sanitize the untrusted error message the SAME way store() sanitizes
    // output/error_detail (Gate 2 security MEDIUM): error_detail here is
    // resp.error().message() from the agent, so a non-UTF-8 byte would fail
    // the UPDATE (PG TEXT / SQLSTATE 22021), leaving the RUNNING row never
    // finalized and no fallback frame — the #1593 "real result must surface"
    // gap, reopened on the finalize path. U+FFFD-defang (incl. NUL, see
    // sanitize_pg_text) keeps the finalize landing.
    const std::string sanitized_error = sanitize_pg_text(error_detail);
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE response_store.responses SET status = $1::integer, error_detail = $2 "
        "WHERE instruction_id = $3 AND agent_id = $4 AND status = 0 AND execution_id = $5",
        std::vector<std::string>{std::to_string(terminal_status), sanitized_error, instruction_id,
                                 agent_id, execution_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error("ResponseStore::finalize_terminal_status: update failed: {}",
                      PQerrorMessage(lease.get()));
        return FinalizeResult::Error;
    }
    return affected_rows(res) > 0 ? FinalizeResult::Updated : FinalizeResult::NoRow;
}

// ── Reads (degrade-distinguishable) ──────────────────────────────────────────

namespace {

// Shared row-parse for the `responses` SELECT column list used by every
// query-style read below.
StoredResponse parse_response_row(PGresult* res, int row) {
    StoredResponse r;
    r.id = to_i64(PQgetvalue(res, row, 0));
    r.instruction_id = text_col(res, row, 1);
    r.agent_id = text_col(res, row, 2);
    r.timestamp = to_i64(PQgetvalue(res, row, 3));
    r.status = static_cast<int>(to_i64(PQgetvalue(res, row, 4)));
    r.output = text_col(res, row, 5);
    r.error_detail = text_col(res, row, 6);
    r.ttl_expires_at = to_i64(PQgetvalue(res, row, 7));
    r.plugin = text_col(res, row, 8);
    r.execution_id = text_col(res, row, 9);
    r.received_at_ms = to_i64(PQgetvalue(res, row, 10));
    return r;
}

constexpr const char* kResponseCols =
    "id, instruction_id, agent_id, timestamp, status, output, error_detail, ttl_expires_at, "
    "plugin, execution_id, received_at_ms";

} // namespace

std::optional<std::vector<StoredResponse>> ResponseStore::query(const std::string& instruction_id,
                                                                 const ResponseQuery& q) const {
    static DegradeSampler sampler;
    return resp_read<std::vector<StoredResponse>>(
        open_, pool_, metrics_, "query", sampler, [&](PGconn* conn) -> std::optional<std::vector<StoredResponse>> {
            std::string sql = std::string("SELECT ") + kResponseCols +
                              " FROM response_store.responses WHERE instruction_id = $1";
            std::vector<std::string> binds{instruction_id};
            int idx = 2;
            if (!q.agent_id.empty()) {
                sql += " AND agent_id = $" + std::to_string(idx++);
                binds.push_back(q.agent_id);
            }
            if (q.status >= 0) {
                sql += " AND status = $" + std::to_string(idx++) + "::integer";
                binds.push_back(std::to_string(q.status));
            }
            if (q.since > 0) {
                sql += " AND timestamp >= $" + std::to_string(idx++) + "::bigint";
                binds.push_back(std::to_string(q.since));
            }
            if (q.until > 0) {
                sql += " AND timestamp <= $" + std::to_string(idx++) + "::bigint";
                binds.push_back(std::to_string(q.until));
            }
            sql += " ORDER BY timestamp DESC LIMIT $" + std::to_string(idx++) + "::integer";
            binds.push_back(std::to_string(q.limit));
            if (q.offset > 0) {
                sql += " OFFSET $" + std::to_string(idx++) + "::integer";
                binds.push_back(std::to_string(q.offset));
            }
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), binds);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<StoredResponse> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i)
                out.push_back(parse_response_row(res.get(), i));
            return out;
        });
}

std::optional<std::vector<StoredResponse>>
ResponseStore::query_by_execution(const std::string& execution_id, const ResponseQuery& q) const {
    static DegradeSampler sampler;
    if (execution_id.empty()) {
        // arch-B1 (ported): empty execution_id is the legacy sentinel and
        // indicates a caller bug rather than a legitimate empty-result query.
        // Engaged-empty, not a degrade.
        return std::vector<StoredResponse>{};
    }
    return resp_read<std::vector<StoredResponse>>(
        open_, pool_, metrics_, "query_by_execution", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<StoredResponse>> {
            std::string sql = std::string("SELECT ") + kResponseCols +
                              " FROM response_store.responses WHERE execution_id = $1";
            std::vector<std::string> binds{execution_id};
            int idx = 2;
            if (!q.agent_id.empty()) {
                sql += " AND agent_id = $" + std::to_string(idx++);
                binds.push_back(q.agent_id);
            }
            if (q.status >= 0) {
                sql += " AND status = $" + std::to_string(idx++) + "::integer";
                binds.push_back(std::to_string(q.status));
            }
            if (q.since > 0) {
                sql += " AND timestamp >= $" + std::to_string(idx++) + "::bigint";
                binds.push_back(std::to_string(q.since));
            }
            if (q.until > 0) {
                sql += " AND timestamp <= $" + std::to_string(idx++) + "::bigint";
                binds.push_back(std::to_string(q.until));
            }
            sql += " ORDER BY timestamp DESC LIMIT $" + std::to_string(idx++) + "::integer";
            binds.push_back(std::to_string(q.limit));
            if (q.offset > 0) {
                sql += " OFFSET $" + std::to_string(idx++) + "::integer";
                binds.push_back(std::to_string(q.offset));
            }
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), binds);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<StoredResponse> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i)
                out.push_back(parse_response_row(res.get(), i));
            return out;
        });
}

std::optional<std::vector<StoredResponse>>
ResponseStore::get_by_instruction(const std::string& instruction_id) const {
    return query(instruction_id);
}

std::optional<std::vector<AggregationResult>>
ResponseStore::aggregate(const std::string& instruction_id, const AggregationQuery& aq,
                         const ResponseQuery& filter, const AggregateScope& scope) const {
    static DegradeSampler sampler;
    return resp_read<std::vector<AggregationResult>>(
        open_, pool_, metrics_, "aggregate", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<AggregationResult>> {
            // Upper bound on the management-group IN-list (#1634) — same cap
            // as the SQLite original.
            static constexpr std::size_t kScopeAgentBindCap = 10000;

            static const std::vector<std::string> allowed_group = {"status", "agent_id"};
            if (std::find(allowed_group.begin(), allowed_group.end(), aq.group_by) ==
                allowed_group.end()) {
                spdlog::warn("ResponseStore::aggregate: invalid group_by '{}'", aq.group_by);
                return std::nullopt; // allow-list miss is a caller/code bug, not a real
                                     // empty result — degrade-distinguish it (Gate 4 R5)
                                     // so the seam's empty-vs-degrade discipline holds.
            }
            static const std::vector<std::string> allowed_op_col = {"timestamp", "status", "id"};
            auto effective_op_col = aq.op_column.empty() ? "id" : aq.op_column;
            if (std::find(allowed_op_col.begin(), allowed_op_col.end(), effective_op_col) ==
                allowed_op_col.end()) {
                spdlog::warn("ResponseStore::aggregate: invalid op_column '{}'", effective_op_col);
                return std::nullopt; // as above (Gate 4 R5)
            }

            std::string agg_func;
            switch (aq.op) {
            case AggregateOp::Count: agg_func = "COUNT(*)"; break;
            case AggregateOp::Sum: agg_func = "SUM(" + effective_op_col + ")"; break;
            case AggregateOp::Avg: agg_func = "AVG(" + effective_op_col + ")"; break;
            case AggregateOp::Min: agg_func = "MIN(" + effective_op_col + ")"; break;
            case AggregateOp::Max: agg_func = "MAX(" + effective_op_col + ")"; break;
            }

            std::string sql = "SELECT " + aq.group_by + "::text, COUNT(*), " + agg_func +
                              "::double precision FROM response_store.responses WHERE "
                              "instruction_id = $1";
            std::vector<std::string> binds{instruction_id};
            int idx = 2;

            if (!filter.agent_id.empty()) {
                sql += " AND agent_id = $" + std::to_string(idx++);
                binds.push_back(filter.agent_id);
            }
            // #1634 management-group scope (filter-BEFORE-aggregate).
            if (scope.has_value()) {
                const auto& allowed = *scope;
                if (allowed.empty()) {
                    sql += " AND 1=0"; // visible to no one → exclude every row
                } else {
                    const std::size_t n = std::min<std::size_t>(allowed.size(), kScopeAgentBindCap);
                    if (n < allowed.size())
                        spdlog::warn("ResponseStore::aggregate: in-scope agent set ({}) exceeds "
                                    "bind cap ({}); totals computed over the first {} agents "
                                    "(#1634)",
                                    allowed.size(), kScopeAgentBindCap, n);
                    sql += " AND agent_id IN (";
                    for (std::size_t i = 0; i < n; ++i) {
                        sql += (i == 0) ? "$" + std::to_string(idx) : ",$" + std::to_string(idx);
                        binds.push_back(allowed[i]);
                        idx++;
                    }
                    sql += ")";
                }
            }
            if (filter.status >= 0) {
                sql += " AND status = $" + std::to_string(idx++) + "::integer";
                binds.push_back(std::to_string(filter.status));
            }
            if (filter.since > 0) {
                sql += " AND timestamp >= $" + std::to_string(idx++) + "::bigint";
                binds.push_back(std::to_string(filter.since));
            }
            if (filter.until > 0) {
                sql += " AND timestamp <= $" + std::to_string(idx++) + "::bigint";
                binds.push_back(std::to_string(filter.until));
            }
            sql += " GROUP BY " + aq.group_by + " ORDER BY COUNT(*) DESC";

            pg::PgResult res = pg::exec_params(conn, sql.c_str(), binds);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<AggregationResult> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i) {
                AggregationResult r;
                r.group_value = text_col(res.get(), i, 0);
                r.count = to_i64(PQgetvalue(res.get(), i, 1));
                r.aggregate_value = to_double(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(r));
            }
            return out;
        });
}

std::optional<std::vector<std::string>>
ResponseStore::distinct_agent_ids(const std::string& instruction_id) const {
    static DegradeSampler sampler;
    return resp_read<std::vector<std::string>>(
        open_, pool_, metrics_, "distinct_agent_ids", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<std::string>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT DISTINCT agent_id FROM response_store.responses WHERE instruction_id = "
                "$1 ORDER BY agent_id",
                std::vector<std::string>{instruction_id});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<std::string> ids;
            ids.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i)
                ids.push_back(text_col(res.get(), i, 0));
            return ids;
        });
}

std::size_t ResponseStore::total_count() const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    pg::PgResult res =
        pg::exec_params(lease.get(), "SELECT COUNT(*) FROM response_store.responses",
                        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return 0;
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

// -- Faceted query methods -----------------------------------------------------

std::optional<std::vector<FacetValue>>
ResponseStore::facet_values(const std::string& instruction_id, int col_idx) const {
    static DegradeSampler sampler;
    return resp_read<std::vector<FacetValue>>(
        open_, pool_, metrics_, "facet_values", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<FacetValue>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT value, SUM(line_count) FROM response_store.response_facets WHERE "
                "instruction_id = $1 AND col_idx = $2::integer GROUP BY value ORDER BY "
                "SUM(line_count) DESC",
                std::vector<std::string>{instruction_id, std::to_string(col_idx)});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<FacetValue> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i) {
                FacetValue fv;
                fv.value = text_col(res.get(), i, 0);
                fv.line_count = to_i64(PQgetvalue(res.get(), i, 1));
                out.push_back(std::move(fv));
            }
            return out;
        });
}

namespace {
// Shared filter-subquery builder for the facet_* methods below — one
// "response_id IN (SELECT response_id FROM response_facets WHERE
// instruction_id = $k AND col_idx = $k+1 AND value = $k+2)" clause per
// filter, ANDed together (intersection). Mirrors the SQLite original.
void append_facet_filters(std::string& sql, std::vector<std::string>& binds, int& idx,
                          const std::string& instruction_id,
                          const std::vector<FacetFilter>& filters) {
    for (const auto& f : filters) {
        const int p1 = idx++;
        const int p2 = idx++;
        const int p3 = idx++;
        sql += " AND response_id IN (SELECT response_id FROM response_store.response_facets "
               "WHERE instruction_id = $" +
               std::to_string(p1) + " AND col_idx = $" + std::to_string(p2) +
               "::integer AND value = $" + std::to_string(p3) + ")";
        binds.push_back(instruction_id);
        binds.push_back(std::to_string(f.col_idx));
        binds.push_back(f.value);
    }
}
} // namespace

std::optional<std::vector<std::string>>
ResponseStore::facet_agent_ids(const std::string& instruction_id,
                               const std::vector<FacetFilter>& filters) const {
    static DegradeSampler sampler;
    if (filters.empty())
        return std::vector<std::string>{};
    return resp_read<std::vector<std::string>>(
        open_, pool_, metrics_, "facet_agent_ids", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<std::string>> {
            std::string sql = "SELECT DISTINCT agent_id FROM response_store.response_facets "
                              "WHERE instruction_id = $1";
            std::vector<std::string> binds{instruction_id};
            int idx = 2;
            append_facet_filters(sql, binds, idx, instruction_id, filters);
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), binds);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<std::string> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i)
                out.push_back(text_col(res.get(), i, 0));
            return out;
        });
}

int64_t ResponseStore::facet_agent_count(const std::string& instruction_id,
                                         const std::vector<FacetFilter>& filters) const {
    if (!open_ || filters.empty())
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    std::string sql = "SELECT COUNT(DISTINCT agent_id) FROM response_store.response_facets "
                      "WHERE instruction_id = $1";
    std::vector<std::string> binds{instruction_id};
    int idx = 2;
    append_facet_filters(sql, binds, idx, instruction_id, filters);
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), binds);
    if (res.status() != PGRES_TUPLES_OK)
        return 0;
    return to_i64(PQgetvalue(res.get(), 0, 0));
}

int64_t ResponseStore::facet_line_count(const std::string& instruction_id,
                                        const std::vector<FacetFilter>& filters) const {
    if (!open_ || filters.empty())
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    // Use the first filter for the line count — this gives the total lines
    // matching that filter. For multi-filter intersection, the count is an
    // upper bound (true intersection count requires row-level parsing) —
    // matches the SQLite original's documented approximation.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT SUM(line_count) FROM response_store.response_facets WHERE instruction_id = $1 "
        "AND col_idx = $2::integer AND value = $3",
        std::vector<std::string>{instruction_id, std::to_string(filters[0].col_idx),
                                 filters[0].value});
    if (res.status() != PGRES_TUPLES_OK)
        return 0;
    return to_i64(PQgetvalue(res.get(), 0, 0));
}

std::optional<std::vector<int64_t>>
ResponseStore::facet_response_ids(const std::string& instruction_id,
                                  const std::vector<FacetFilter>& filters, int limit,
                                  int offset) const {
    static DegradeSampler sampler;
    if (filters.empty())
        return std::vector<int64_t>{};
    return resp_read<std::vector<int64_t>>(
        open_, pool_, metrics_, "facet_response_ids", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<int64_t>> {
            std::string sql = "SELECT DISTINCT response_id FROM response_store.response_facets "
                              "WHERE instruction_id = $1";
            std::vector<std::string> binds{instruction_id};
            int idx = 2;
            append_facet_filters(sql, binds, idx, instruction_id, filters);
            const int limit_idx = idx++;
            const int offset_idx = idx++;
            sql += " ORDER BY response_id LIMIT $" + std::to_string(limit_idx) +
                   "::integer OFFSET $" + std::to_string(offset_idx) + "::integer";
            binds.push_back(std::to_string(limit));
            binds.push_back(std::to_string(offset));
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), binds);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<int64_t> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i)
                out.push_back(to_i64(PQgetvalue(res.get(), i, 0)));
            return out;
        });
}

std::optional<std::vector<StoredResponse>>
ResponseStore::query_by_ids(const std::vector<int64_t>& response_ids) const {
    static DegradeSampler sampler;
    if (response_ids.empty())
        return std::vector<StoredResponse>{};
    return resp_read<std::vector<StoredResponse>>(
        open_, pool_, metrics_, "query_by_ids", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<StoredResponse>> {
            // IDs are int64_t (never user strings) — safe to inline as a
            // literal IN-list rather than one bind per id.
            std::string in_list;
            for (std::size_t i = 0; i < response_ids.size(); ++i) {
                if (i > 0)
                    in_list += ',';
                in_list += std::to_string(response_ids[i]);
            }
            std::string sql = std::string("SELECT ") + kResponseCols +
                              " FROM response_store.responses WHERE id IN (" + in_list +
                              ") ORDER BY id";
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), std::vector<std::string>{});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<StoredResponse> out;
            out.reserve(static_cast<std::size_t>(PQntuples(res.get())));
            for (int i = 0; i < PQntuples(res.get()); ++i)
                out.push_back(parse_response_row(res.get(), i));
            return out;
        });
}

// ── Retention (clock-guarded gc_sweep shape, #2496 / ADR-0038 / ADR-0039) ────

void ResponseStore::reap_expired() {
    if (!open_)
        return;
    const auto record_result = [this](const char* result) {
        if (metrics_)
            metrics_->counter("yuzu_server_response_reap_passes_total", {{"result", result}})
                .increment();
    };

    int64_t responses_deleted = 0;
    std::string outcome = "failed";
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // One sweeping replica at a time.
        pg::PgResult lk = pg::exec_params(
            conn,
            "SELECT pg_try_advisory_xact_lock(hashtextextended('response_store:reap', 0))",
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResponseStore::reap_expired: lock probe failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        if (!to_bool(PQgetvalue(lk.get(), 0, 0))) {
            outcome = "skipped_lock";
            return true;
        }

        const int64_t now = now_epoch();
        // Derive the implausibly-ahead bound from THIS store's configured
        // retention (2× horizon, floored) so raising `response_retention_days`
        // above a fixed constant can't push the whole live set past the bound
        // and wedge the reaper in permanent decline (consistency-auditor
        // Gate 4; the ADR-0038 false-decline lesson taken literally).
        const int64_t implausibly_ahead =
            std::max<int64_t>(kReapImplausiblyAheadFloorSecs,
                              static_cast<int64_t>(retention_days_) * 86'400 * 2);

        pg::PgResult meta = pg::exec_params(
            conn,
            "SELECT key, value FROM response_store.gc_meta WHERE key IN ('last_pass_now',"
            "'last_anomaly_facts')",
            std::vector<std::string>{});
        if (meta.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResponseStore::reap_expired: meta read failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        std::optional<int64_t> prev;
        bool prev_unusable = false;
        std::string last_facts;
        for (int i = 0; i < PQntuples(meta.get()); ++i) {
            const std::string key = text_col(meta.get(), i, 0);
            const std::string val = text_col(meta.get(), i, 1);
            if (key == "last_pass_now") {
                errno = 0;
                char* end = nullptr;
                const long long v = std::strtoll(val.c_str(), &end, 10);
                if (errno != 0 || end == val.c_str() || *end != '\0')
                    prev_unusable = true;
                else
                    prev = static_cast<int64_t>(v);
            } else if (key == "last_anomaly_facts") {
                last_facts = val;
            }
        }
        if (prev && (*prev < 0 || *prev > now)) {
            prev_unusable = true;
            prev.reset();
        }

        pg::PgResult stamp = pg::exec_params(
            conn,
            "INSERT INTO response_store.gc_meta (key, value) VALUES ('last_pass_now', $1) ON "
            "CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{std::to_string(now)});
        if (stamp.status() != PGRES_COMMAND_OK) {
            spdlog::error("ResponseStore::reap_expired: meta stamp failed: {}",
                          PQerrorMessage(conn));
            return false;
        }

        pg::PgResult probe = pg::exec_params(
            conn,
            "SELECT count(*) FILTER (WHERE ttl_expires_at > 0 AND ttl_expires_at < $1::bigint) "
            "AS expiring, count(*) FILTER (WHERE ttl_expires_at > 0 AND ttl_expires_at <= "
            "$2::bigint) AS datable FROM response_store.responses",
            std::vector<std::string>{std::to_string(now),
                                     std::to_string(now + implausibly_ahead)});
        if (probe.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResponseStore::reap_expired: probe failed: {}", PQerrorMessage(conn));
            return false;
        }
        const int64_t expiring = to_i64(PQgetvalue(probe.get(), 0, 0));
        const int64_t datable = to_i64(PQgetvalue(probe.get(), 0, 1));

        audit_retention::Facts facts{
            .has_expired = expiring > 0,
            .would_wipe = expiring > 0 && expiring >= datable,
            .big_step = prev.has_value() && expiring > 0 &&
                        audit_retention::moved_at_least(*prev, now, kReapBigStepSecs) && now > *prev,
            .prev_unusable = prev_unusable,
        };
        const auto anomaly = audit_retention::classify(facts);
        const std::string facts_ser = std::string(facts.has_expired ? "e" : "-") +
                                      (facts.would_wipe ? "w" : "-") +
                                      (facts.big_step ? "s" : "-") +
                                      (facts.prev_unusable ? "u" : "-");
        if (anomaly != audit_retention::Anomaly::None) {
            if (facts_ser != last_facts) {
                spdlog::warn("ResponseStore::reap_expired: retention clock anomaly ({} facts={}) "
                            "— declining this pass; an identical next pass will drain, capped",
                            static_cast<int>(anomaly), facts_ser);
                pg::PgResult rec = pg::exec_params(
                    conn,
                    "INSERT INTO response_store.gc_meta (key, value) VALUES "
                    "('last_anomaly_facts', $1) ON CONFLICT (key) DO UPDATE SET value = "
                    "EXCLUDED.value",
                    std::vector<std::string>{facts_ser});
                if (rec.status() != PGRES_COMMAND_OK) {
                    spdlog::error("ResponseStore::reap_expired: anomaly record failed: {}",
                                  PQerrorMessage(conn));
                    return false;
                }
                outcome = "declined";
                return true;
            }
            // Suppressed repeat of the SAME fact set — proceed with the
            // (capped) drain below.
        } else if (!last_facts.empty()) {
            pg::PgResult clr = pg::exec_params(
                conn, "DELETE FROM response_store.gc_meta WHERE key = 'last_anomaly_facts'",
                std::vector<std::string>{});
            if (clr.status() != PGRES_COMMAND_OK) {
                spdlog::error("ResponseStore::reap_expired: anomaly clear failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
        }
        if (expiring == 0) {
            outcome = "noop";
            return true;
        }

        // Single DELETE on `responses` — `response_facets` rows for the
        // reaped ids are removed automatically via ON DELETE CASCADE (no
        // second lockstep statement needed, unlike GuaranteedStateStore's
        // events/observations pair which has no FK between them).
        pg::PgResult del = pg::exec_params(
            conn,
            "DELETE FROM response_store.responses WHERE id IN (SELECT id FROM "
            "response_store.responses WHERE ttl_expires_at > 0 AND ttl_expires_at < $1::bigint "
            "ORDER BY ttl_expires_at ASC, id ASC LIMIT $2::bigint) RETURNING id",
            std::vector<std::string>{std::to_string(now), std::to_string(kReapCapPerPass)});
        if (del.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResponseStore::reap_expired: delete failed: {}", PQerrorMessage(conn));
            return false;
        }
        responses_deleted = PQntuples(del.get());
        // Report a capped pass distinctly (result="capped") so on-call can tell
        // a healthy fully-draining reaper from one whose 10k/pass ceiling is
        // being outrun by ingest (this is the higher-write store; the AuditStore
        // cap-reached shape, ported — sre Gate 6 / R2). Hitting the cap does NOT
        // prove a backlog remains: an exact-boundary pass that drained the last
        // row deleted exactly the cap with nothing left. Probe for a real
        // remaining backlog (only when the cap was hit, so the cost is rare) so
        // an exact-boundary drain labels "swept", not a false "capped" page —
        // the AuditStore post-delete backlog probe (chaos Gate 5).
        outcome = "swept";
        if (responses_deleted >= kReapCapPerPass) {
            pg::PgResult more = pg::exec_params(
                conn,
                "SELECT EXISTS(SELECT 1 FROM response_store.responses WHERE ttl_expires_at > 0 "
                "AND ttl_expires_at < $1::bigint)",
                std::vector<std::string>{std::to_string(now)});
            if (more.status() != PGRES_TUPLES_OK) {
                spdlog::error("ResponseStore::reap_expired: backlog probe failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
            if (to_bool(PQgetvalue(more.get(), 0, 0)))
                outcome = "capped";
        }
        return true;
    });

    if (!ok) {
        record_result("failed");
        spdlog::error("ResponseStore::reap_expired: pass aborted (statement failed or txn "
                      "rolled back — see the preceding error line)");
        return;
    }
    record_result(outcome.c_str());
    if (responses_deleted > 0) {
        responses_reaped_.fetch_add(static_cast<uint64_t>(responses_deleted),
                                    std::memory_order_relaxed);
        spdlog::info("ResponseStore: reap swept {} response(s)", responses_deleted);
    }
}

} // namespace yuzu::server
