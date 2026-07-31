#include "guaranteed_state_store.hpp"

#include "audit_retention_rules.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"
#include "store_errors.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/version_string.hpp> // shared canon_version — re-canon agent input at the boundary

#include <libpq-fe.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <format>
#include <functional>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "guaranteed_state_store";

// Bounded acquires (ADR-0012 §2(a)). Rule/meta reads+writes are the
// catastrophic-read/fail-hard set — they back interactive REST callers and
// the Push fan-out, so they get a longer budget than ingest. Event/status
// ingest runs on the gRPC thread and must give up fast (fail-soft — the
// agent's next report re-sends). DEX/analytics reads mirror InventoryStore's
// query budget.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
constexpr std::chrono::milliseconds kIngestTimeout{500};
constexpr std::chrono::milliseconds kDexReadTimeout{3000};

// Read-degrade / ingest-drop reason labels (ADR-0037 label convention).
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr const char* kReasonConflict = "conflict"; // event_id collision, mismatched fields
// JC-8 (coordinator review): label parity with InventoryStore's
// yuzu_inventory_read_degrade_total{reason, source} family — a constant
// "source" so a future second Guardian-adjacent read-degrade emitter
// (there is only one surface today) stays distinguishable on the same
// dashboards without a metric rename.
constexpr const char* kDegradeSource = "guardian_state";
// Sample the per-site degrade WARN so a sustained PG outage cannot flood the
// log — the counter is the continuous signal, the log a sampled breadcrumb.
// Mirrors InventoryStore's constants.
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

// Clock-guarded retention (routed-concern invariant; #2496 gc_sweep shape,
// ADR-0038). Substrate-tuned: this store's write volume is documented at up
// to ~10k events/s during a fleet-wide incident (kDefaultEventRetentionDays
// doc comment), an order of magnitude above ResultSetStore's operator-scratch
// workload, so the per-pass cap is raised accordingly (5000 -> 10000).
// kReapBigStepSecs (part 7, "did the clock move forward abnormally between
// passes") stays the reference's absolute ~1-day value — it detects a wall-
// clock jump between two passes and is deliberately unscaled to any TTL.
// kReapImplausiblyAheadSecs (part 1, "exclude forward-skewed rows from the
// datable denominator") is DIFFERENT: unlike kReapBigStepSecs it MUST exceed
// the legitimate TTL horizon, or a live row's own honest ttl_expires_at gets
// misclassified as "implausibly ahead" and wrongly excluded from `datable` —
// which flips a normal partial-expiry pass into a false would_wipe decline
// (caught in review: this store's operator-configurable retention_days
// defaults to 30 days, an order of magnitude past ResultSetStore's 1-hour TTL
// that the reference's 7-day bound was sized against). 400 days gives
// generous headroom over any realistic retention_days configuration while
// still catching genuinely corrupt/attacker-skewed far-future timestamps.
constexpr int64_t kReapCapPerPass = 10'000;
constexpr int64_t kReapBigStepSecs = 86'400;              // part 7: absolute, ~1 day
constexpr int64_t kReapImplausiblyAheadSecs = 34'560'000; // part 1: probe excludes, ~400 days

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

const char* safe(const char* p) { return p ? p : ""; }

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
bool to_bool(const char* s) { return s != nullptr && s[0] == 't'; }
double to_double(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0.0;
    double v = 0.0;
    const auto len = std::strlen(s);
    auto [ptr, ec] = std::from_chars(s, s + len, v);
    (void)ptr;
    return ec == std::errc() ? v : 0.0;
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col));
}

// Byte<->hex for the `signature` BYTEA column. Mirrors the codebase's
// existing BYTEA convention (auth_db.cpp: `encode(col,'hex')` /
// `decode($n,'hex')`, chosen deliberately over relying on the session's
// `bytea_output` GUC) — no generic hex helper exists outside the auth
// module, and signature is not a secret (it's an HMAC we already store), so
// a small local pair avoids taking a dependency on auth::AuthManager.
std::string bytes_to_hex(const std::vector<uint8_t>& b) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (uint8_t byte : b) {
        out.push_back(kDigits[byte >> 4]);
        out.push_back(kDigits[byte & 0x0F]);
    }
    return out;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            break; // malformed — server-authored hex only, defensive stop
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string format_conflict(std::string_view detail) {
    return std::string(kConflictPrefix) + " " + std::string(detail);
}

// Map a Guardian event_type to the compliance state it implies for the per-(agent,
// rule) status table, or nullptr if the event carries no compliance signal (e.g.
// guard.armed is a lifecycle marker, not a verdict). guard.compliant (Slice B) and a
// successful drift.remediated both mean the watched state is now at expected.
const char* event_state_from_type(const std::string& t) {
    if (t == "guard.compliant" || t == "drift.remediated")
        return "compliant";
    if (t == "drift.detected")
        return "drifted";
    // Slice-B collapse (deliberate): guardian-mvp-contract.md §4/decision-5 lists
    // `remediation_failed` as a state DISTINCT from `errored`, but the Slice-B census
    // exposes only compliant/drifted/errored and both render red in the worst-of badge.
    if (t == "remediation.failed" || t == "guard.unhealthy")
        return "errored";
    return nullptr; // guard.armed, resilience.escalated, … — no census change
}

// The reserved ruleless-observation sentinel (DEX crash recorder) is NEVER a rule-bound
// compliance verdict — it has no live rule. Enforce that server-side so a (mis)behaving
// agent that pairs the sentinel with a compliance event_type (e.g. drift.detected)
// cannot mint a phantom per-(agent,rule) census row keyed to the reserved id.
bool is_reserved_rule_id(const std::string& rule_id) { return rule_id == kObservationRuleId; }

// ── Read-degrade / ingest-drop observability ─────────────────────────────────
// Mirrors InventoryStore's DegradeSampler shape exactly (docs/postgres-store-
// playbook.md). One static sampler per DEX/analytics call site (declared
// `static DegradeSampler sampler;` inside each method) gates the sampled warn
// log; the Prometheus counter always increments.
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
            ->counter("yuzu_server_guardian_read_degrade_total",
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
        metrics->counter("yuzu_server_guardian_ingest_dropped_total", {{"reason", reason}}).increment();
}

// Increment the persisted policy generation via one atomic UPDATE ...
// RETURNING (no read-modify-write — the SQLite idiom does not port to
// cross-process Postgres state). Best-effort: logs on failure, matching the
// original SQLite contract (callers do not consume a result). No
// sqlite3_changes()-style race (#1033): the RETURNING result is read on the
// exclusively-owned lease connection.
void bump_policy_generation_on(PGconn* conn) {
    pg::PgResult r = pg::exec_params(
        conn,
        "UPDATE guaranteed_state_store.guardian_meta SET value = value + 1 "
        "WHERE key = 'policy_generation' RETURNING value",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        spdlog::warn("GuaranteedStateStore: policy_generation bump failed: {}",
                     PQerrorMessage(conn));
}

// Shared body for every DEX/analytics read (ADR-0038 "deferred widening",
// follow-up #2659): acquire a bounded lease, run `body(conn)` (which executes
// the query and returns the parsed result, or nullopt on a query-level
// failure), and count+sampled-log a degrade on store-not-open / pool-timeout
// / query-error via yuzu_server_guardian_read_degrade_total{reason}. A successful
// EMPTY container is NOT a degrade — only body() returning nullopt is.
template <typename Result, typename Body>
Result dex_read(bool open, pg::PgPool& pool, yuzu::MetricsRegistry* metrics, const char* method,
                DegradeSampler& sampler, Body&& body) {
    Result empty{};
    if (!open) {
        if (const auto d = note_read_degrade(metrics, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("GuaranteedStateStore::{}: store not open", method);
        return empty;
    }
    auto lease = pool.try_acquire_for(kDexReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("GuaranteedStateStore::{}: pool acquire timed out", method);
        return empty;
    }
    auto result = body(lease.get());
    if (!result) {
        if (const auto d = note_read_degrade(metrics, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("GuaranteedStateStore::{}: query failed", method);
        return empty;
    }
    return std::move(*result);
}

// ── Postgres schema (ADR-0038): the FINAL column set of all 8 SQLite
// migrations, collapsed into one v1. Unqualified DDL — the migration runner
// sets search_path to `guaranteed_state_store` for the migration transaction.
// Runtime statements below schema-qualify explicitly. No enum CHECK
// constraints exist in the legacy SQLite DDL to preserve (the H2/G9
// cross-check tests bind `guardian_rule_spec.cpp` param specs to agent-side
// arrays — a C++-level contract, not a SQL CHECK clause — so this migration
// carries none forward; verified by reading the legacy schema).
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE guaranteed_state_rules (
                rule_id          TEXT PRIMARY KEY,
                name             TEXT NOT NULL UNIQUE,
                yaml_source      TEXT NOT NULL,
                version          BIGINT NOT NULL DEFAULT 1,
                enabled          BOOLEAN NOT NULL DEFAULT TRUE,
                enforcement_mode TEXT NOT NULL DEFAULT 'enforce',
                severity         TEXT NOT NULL DEFAULT 'medium',
                os_target        TEXT NOT NULL DEFAULT '',
                scope_expr       TEXT NOT NULL DEFAULT '',
                signature        BYTEA,
                created_at       TEXT NOT NULL,
                updated_at       TEXT NOT NULL,
                created_by       TEXT NOT NULL DEFAULT '',
                updated_by       TEXT NOT NULL DEFAULT '',
                spec_json        TEXT NOT NULL DEFAULT '',
                prerequisites    TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX idx_gsr_os ON guaranteed_state_rules(os_target);

            CREATE TABLE guaranteed_state_events (
                event_id               TEXT PRIMARY KEY,
                rule_id                TEXT NOT NULL,
                agent_id                TEXT NOT NULL,
                event_type              TEXT NOT NULL,
                severity                 TEXT NOT NULL,
                guard_type               TEXT NOT NULL DEFAULT '',
                guard_category            TEXT NOT NULL DEFAULT '',
                detected_value            TEXT NOT NULL DEFAULT '',
                expected_value            TEXT NOT NULL DEFAULT '',
                remediation_action        TEXT NOT NULL DEFAULT '',
                remediation_success       BOOLEAN,
                detection_latency_us      BIGINT NOT NULL DEFAULT 0,
                remediation_latency_us    BIGINT NOT NULL DEFAULT 0,
                timestamp                 TEXT NOT NULL,
                ttl_expires_at             BIGINT NOT NULL DEFAULT 0,
                detail_json                TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX idx_gse_rule_time ON guaranteed_state_events(rule_id, timestamp DESC);
            CREATE INDEX idx_gse_agent_time ON guaranteed_state_events(agent_id, timestamp DESC);
            CREATE INDEX idx_gse_severity_time ON guaranteed_state_events(severity, timestamp DESC);
            CREATE INDEX idx_gse_time ON guaranteed_state_events(timestamp DESC);
            CREATE INDEX idx_gse_ttl ON guaranteed_state_events(ttl_expires_at) WHERE ttl_expires_at > 0;

            CREATE TABLE guardian_meta (
                key   TEXT PRIMARY KEY,
                value BIGINT NOT NULL
            );
            INSERT INTO guardian_meta(key, value) VALUES ('policy_generation', 0)
                ON CONFLICT (key) DO NOTHING;

            CREATE TABLE guardian_agent_rule_status (
                agent_id   TEXT NOT NULL,
                rule_id    TEXT NOT NULL,
                state      TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (agent_id, rule_id)
            );
            CREATE INDEX idx_gars_rule ON guardian_agent_rule_status(rule_id);

            CREATE TABLE guardian_observations (
                event_id        TEXT PRIMARY KEY,
                agent_id        TEXT NOT NULL,
                observed_at     TEXT NOT NULL,
                obs_type        TEXT NOT NULL,
                subject         TEXT NOT NULL DEFAULT '',
                reason          TEXT NOT NULL DEFAULT '',
                symbolic        TEXT NOT NULL DEFAULT '',
                component       TEXT NOT NULL DEFAULT '',
                metric          DOUBLE PRECISION NOT NULL DEFAULT 0,
                platform        TEXT NOT NULL DEFAULT '',
                ttl_expires_at  BIGINT NOT NULL DEFAULT 0,
                version         TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX idx_gobs_subject ON guardian_observations(subject);
            CREATE INDEX idx_gobs_type_time
                ON guardian_observations(obs_type, observed_at DESC, agent_id, subject);
            CREATE INDEX idx_gobs_agent_time ON guardian_observations(agent_id, observed_at DESC);
            CREATE INDEX idx_gobs_time ON guardian_observations(observed_at DESC);
            CREATE INDEX idx_gobs_ttl ON guardian_observations(ttl_expires_at) WHERE ttl_expires_at > 0;

            -- Backfill idempotency marker (ADR-0009/0038 — ADR-0036 shape,
            -- extended with ADR-0037-style per-table inserted counts +
            -- skipped_bad). A dedicated row — NEVER inferred from any table
            -- being empty (the reaper legitimately empties events/observations
            -- over the store's lifetime).
            CREATE TABLE sqlite_backfill (
                id                     SMALLINT PRIMARY KEY,
                completed_at           BIGINT NOT NULL,
                rules_inserted         BIGINT NOT NULL DEFAULT 0,
                events_inserted        BIGINT NOT NULL DEFAULT 0,
                observations_inserted  BIGINT NOT NULL DEFAULT 0,
                status_inserted        BIGINT NOT NULL DEFAULT 0,
                skipped_bad            BIGINT NOT NULL DEFAULT 0,
                CHECK (id = 1)
            );

            -- Durable state for the reap_expired() clock-guard (#2496 shape).
            -- SHARED rows (not process-local) — N server replicas each run the
            -- sweep, so the persisted reading + anomaly-dedup fact set must be
            -- one shared truth under the sweep's advisory lock.
            CREATE TABLE gc_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        )"},
    };
    return kMigrations;
}

// RAII owner for the legacy SQLite connection migrate_from_sqlite opens
// read-only, mirroring ResultSetStore's SqliteConnGuard (local to this file —
// the only sqlite3* connection this store ever opens; the runtime store lives
// entirely on pg::PgPool).
class SqliteConnGuard {
public:
    SqliteConnGuard() = default;
    ~SqliteConnGuard() { reset(); }
    SqliteConnGuard(const SqliteConnGuard&) = delete;
    SqliteConnGuard& operator=(const SqliteConnGuard&) = delete;
    SqliteConnGuard(SqliteConnGuard&& o) noexcept : db_(o.db_) { o.db_ = nullptr; }
    SqliteConnGuard& operator=(SqliteConnGuard&& o) noexcept {
        if (this != &o) {
            reset();
            db_ = o.db_;
            o.db_ = nullptr;
        }
        return *this;
    }
    sqlite3** addr() noexcept { return &db_; }
    sqlite3* get() const noexcept { return db_; }
    explicit operator bool() const noexcept { return db_ != nullptr; }
    void reset() noexcept {
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

private:
    sqlite3* db_{nullptr};
};

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

GuaranteedStateStore::GuaranteedStateStore(pg::PgPool& pool, int retention_days)
    : pool_(pool), retention_days_(retention_days) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("GuaranteedStateStore: no database connection at construction ({}) — "
                      "Guardian persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("GuaranteedStateStore: schema migration failed — Guardian persistence "
                      "disabled");
        return;
    }
    open_ = true;
    spdlog::info("GuaranteedStateStore initialized (schema {}, retention={}d)", kStoreName,
                 retention_days_);
}

int64_t GuaranteedStateStore::compute_ttl_epoch() const {
    if (retention_days_ <= 0)
        return 0; // sentinel: never expire
    return now_epoch() + static_cast<int64_t>(retention_days_) * 86400;
}

// ── Backfill (ADR-0009/0038) ─────────────────────────────────────────────────

namespace {

// Per-legacy-row struct mirrors the SQLite column set exactly (final shape
// after all 8 legacy migrations — the retained legacy file was always fully
// migrated by the pre-PG code before this PR).
struct LegacyRule {
    std::string rule_id, name, yaml_source, enforcement_mode, severity, os_target, scope_expr,
        created_at, updated_at, created_by, updated_by, spec_json, prerequisites;
    std::vector<uint8_t> signature;
    int64_t version{1};
    bool enabled{true};
};
struct LegacyMeta {
    std::string key;
    int64_t value{0};
};
struct LegacyStatus {
    std::string agent_id, rule_id, state, updated_at;
};
struct LegacyEvent {
    std::string event_id, rule_id, agent_id, event_type, severity, guard_type, guard_category,
        detected_value, expected_value, remediation_action, timestamp, detail_json;
    bool remediation_success{false};
    int64_t detection_latency_us{0}, remediation_latency_us{0}, ttl_expires_at{0};
};
struct LegacyObservation {
    std::string event_id, agent_id, observed_at, obs_type, subject, reason, symbolic, component,
        platform, version;
    double metric{0.0};
    int64_t ttl_expires_at{0};
};

// Run `insert_fn` under its own SAVEPOINT; on a row-data SQLSTATE class
// (22/23/54) roll back to the savepoint and report "skipped"; on any other
// failure (including a failed SAVEPOINT/ROLLBACK/RELEASE) treat it as an
// INFRASTRUCTURE fault — the caller aborts the whole backfill (ADR-0037 H1
// discrimination). Postgres aborts the whole transaction on ANY failed
// statement, unlike SQLite, so this SAVEPOINT discipline is load-bearing here
// in a way it wasn't for the SQLite original.
//
// SPLIT (coordinator review, overrides an earlier draft that applied this
// skip-and-continue discipline to all five tables): this skip-bad-row path is
// used ONLY for `guaranteed_state_events` / `guardian_observations` — bounded,
// agent-reported, re-derivable telemetry, matching ADR-0037's own precedent
// table. `guaranteed_state_rules` / `guardian_meta` /
// `guardian_agent_rule_status` use `backfill_row_strict` below instead: they
// are operator-authored config / the generation counter / live compliance
// state, and a silently SKIPPED row there is a quiet partial disarm smuggled
// across the cutover — exactly the class of failure the ADR's
// catastrophic-read posture exists to prevent, so ANY row-level error on
// those three tables aborts the whole backfill unstamped.
//
// Returns true = inserted (or a benign ON CONFLICT DO NOTHING no-op), false =
// skipped bad row, std::nullopt = infrastructure fault (`*out_detail` set).
std::optional<bool> backfill_row(PGconn* conn, const char* what, const std::string& row_desc,
                                 const std::function<pg::PgResult()>& insert_fn,
                                 std::string& out_detail) {
    pg::PgResult sp = pg::exec_params(conn, "SAVEPOINT legacy_row_backfill", std::vector<std::string>{});
    if (sp.status() != PGRES_COMMAND_OK) {
        out_detail = std::format("{} SAVEPOINT failed: {}", what, PQerrorMessage(conn));
        return std::nullopt;
    }
    pg::PgResult res = insert_fn();
    if (res.status() == PGRES_COMMAND_OK) {
        pg::PgResult rel = pg::exec_params(conn, "RELEASE SAVEPOINT legacy_row_backfill", std::vector<std::string>{});
        if (rel.status() != PGRES_COMMAND_OK) {
            out_detail = std::format("{} RELEASE SAVEPOINT failed: {}", what, PQerrorMessage(conn));
            return std::nullopt;
        }
        return true;
    }
    const char* sqlstate_p = res.get() ? PQresultErrorField(res.get(), PG_DIAG_SQLSTATE) : nullptr;
    const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
    const std::string row_err = res.get() ? PQresultErrorMessage(res.get()) : PQerrorMessage(conn);
    const bool row_data_error =
        sqlstate.size() == 5 && (sqlstate.starts_with("22") || sqlstate.starts_with("23") ||
                                 sqlstate.starts_with("54"));
    pg::PgResult back = pg::exec_params(conn, "ROLLBACK TO SAVEPOINT legacy_row_backfill", std::vector<std::string>{});
    if (back.status() != PGRES_COMMAND_OK) {
        out_detail = std::format("{} ROLLBACK TO SAVEPOINT failed after a bad row ({}): {}", what,
                                 row_desc, PQerrorMessage(conn));
        return std::nullopt;
    }
    if (!row_data_error) {
        out_detail = std::format("{} row {} failed with non-row-data SQLSTATE '{}': {}", what,
                                 row_desc, sqlstate.empty() ? "<none>" : sqlstate, row_err);
        return std::nullopt;
    }
    pg::PgResult rel = pg::exec_params(conn, "RELEASE SAVEPOINT legacy_row_backfill", std::vector<std::string>{});
    if (rel.status() != PGRES_COMMAND_OK) {
        out_detail = std::format("{} RELEASE SAVEPOINT failed after skip ({}): {}", what, row_desc,
                                 PQerrorMessage(conn));
        return std::nullopt;
    }
    spdlog::warn("GuaranteedStateStore::migrate_from_sqlite: skipping bad legacy {} row {} "
                 "(SQLSTATE {}): {}",
                 what, row_desc, sqlstate, row_err);
    return false;
}

// Strict counterpart for `guaranteed_state_rules` / `guardian_meta` /
// `guardian_agent_rule_status` (coordinator review, see the note above
// `backfill_row`): no SAVEPOINT-guarded skip-and-continue — ANY row-level
// insert failure (row-data or infrastructure) aborts the whole backfill
// unstamped. No SAVEPOINT is needed here either: the caller is about to
// return false and let the overall transaction roll back regardless, so
// there is nothing to "recover" mid-loop.
bool backfill_row_strict(PGconn* conn, const char* what, const std::string& row_desc,
                         const std::function<pg::PgResult()>& insert_fn, std::string& out_detail) {
    pg::PgResult res = insert_fn();
    if (res.status() == PGRES_COMMAND_OK)
        return true;
    const char* sqlstate_p = res.get() ? PQresultErrorField(res.get(), PG_DIAG_SQLSTATE) : nullptr;
    const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
    const std::string row_err = res.get() ? PQresultErrorMessage(res.get()) : PQerrorMessage(conn);
    out_detail = std::format("{} row {} failed (SQLSTATE '{}'): {} — authoritative table, "
                             "aborting the whole backfill rather than skipping",
                             what, row_desc, sqlstate.empty() ? "<none>" : sqlstate, row_err);
    return false;
}

} // namespace

bool GuaranteedStateStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    // Idempotency check on a short-lived lease, released before any legacy I/O
    // or the write transaction below.
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: no database connection");
            return false;
        }
        pg::PgResult marker = pg::exec_params(
            lease.get(), "SELECT 1 FROM guaranteed_state_store.sqlite_backfill LIMIT 1", std::vector<std::string>{});
        if (marker.status() != PGRES_TUPLES_OK) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: backfill-marker check "
                          "failed: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        if (PQntuples(marker.get()) > 0) {
            spdlog::debug("GuaranteedStateStore::migrate_from_sqlite already completed, skipping");
            return true;
        }
    }

    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("GuaranteedStateStore::migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        return false;
    }
    if (!legacy_exists) {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: no connection to stamp "
                          "marker");
            return false;
        }
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO guaranteed_state_store.sqlite_backfill (id, completed_at) VALUES (1, "
            "$1::bigint) ON CONFLICT (id) DO NOTHING",
            std::vector<std::string>{std::to_string(now_epoch())});
        if (r.status() != PGRES_COMMAND_OK) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: failed to stamp marker: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        spdlog::info("GuaranteedStateStore::migrate_from_sqlite: no legacy {} — nothing to "
                     "backfill",
                     legacy_db_path.string());
        return true;
    }

    SqliteConnGuard legacy;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK) {
        spdlog::error("GuaranteedStateStore::migrate_from_sqlite: failed to open legacy {}: {}",
                      legacy_db_path.string(), legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
        return false;
    }

    const int64_t now = now_epoch();
    std::vector<LegacyRule> legacy_rules;
    std::vector<LegacyMeta> legacy_meta;
    std::vector<LegacyStatus> legacy_status;
    std::vector<LegacyEvent> legacy_events;
    std::vector<LegacyObservation> legacy_observations;

    // rules
    {
        SqliteStmt s;
        const char* sql =
            "SELECT rule_id, name, yaml_source, version, enabled, enforcement_mode, severity, "
            "os_target, scope_expr, signature, created_at, updated_at, created_by, updated_by, "
            "spec_json, prerequisites FROM guaranteed_state_rules ORDER BY rule_id ASC;";
        if (sqlite3_prepare_v2(legacy.get(), sql, -1, s.addr(), nullptr) != SQLITE_OK) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: legacy rules query failed: "
                          "{}",
                          sqlite3_errmsg(legacy.get()));
            return false;
        }
        int rc = SQLITE_OK;
        while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
            LegacyRule r;
            r.rule_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0)));
            r.name = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1)));
            r.yaml_source = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2)));
            r.version = sqlite3_column_int64(s.get(), 3);
            r.enabled = sqlite3_column_int(s.get(), 4) != 0;
            r.enforcement_mode =
                safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 5)));
            r.severity = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 6)));
            r.os_target = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 7)));
            r.scope_expr = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 8)));
            const int sig_len = sqlite3_column_bytes(s.get(), 9);
            const auto* sig_data = static_cast<const uint8_t*>(sqlite3_column_blob(s.get(), 9));
            if (sig_data && sig_len > 0)
                r.signature.assign(sig_data, sig_data + sig_len);
            r.created_at = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 10)));
            r.updated_at = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 11)));
            r.created_by = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 12)));
            r.updated_by = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 13)));
            r.spec_json = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 14)));
            r.prerequisites = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 15)));
            legacy_rules.push_back(std::move(r));
        }
        if (rc != SQLITE_DONE) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: legacy rules scan aborted "
                          "mid-read (rc={} {}): refusing to stamp a partial backfill",
                          rc, sqlite3_errmsg(legacy.get()));
            return false;
        }
    }
    // meta
    {
        SqliteStmt s;
        if (sqlite3_prepare_v2(legacy.get(), "SELECT key, value FROM guardian_meta;", -1, s.addr(),
                               nullptr) != SQLITE_OK) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: legacy meta query failed: "
                          "{}",
                          sqlite3_errmsg(legacy.get()));
            return false;
        }
        int rc = SQLITE_OK;
        while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
            LegacyMeta m;
            m.key = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0)));
            m.value = sqlite3_column_int64(s.get(), 1);
            legacy_meta.push_back(std::move(m));
        }
        if (rc != SQLITE_DONE) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: legacy meta scan aborted "
                          "mid-read (rc={} {}): refusing to stamp a partial backfill",
                          rc, sqlite3_errmsg(legacy.get()));
            return false;
        }
    }
    // status
    {
        SqliteStmt s;
        if (sqlite3_prepare_v2(legacy.get(),
                               "SELECT agent_id, rule_id, state, updated_at FROM "
                               "guardian_agent_rule_status;",
                               -1, s.addr(), nullptr) != SQLITE_OK) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: legacy status query failed: "
                          "{}",
                          sqlite3_errmsg(legacy.get()));
            return false;
        }
        int rc = SQLITE_OK;
        while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
            LegacyStatus st;
            st.agent_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0)));
            st.rule_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1)));
            st.state = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2)));
            st.updated_at = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 3)));
            legacy_status.push_back(std::move(st));
        }
        if (rc != SQLITE_DONE) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: legacy status scan aborted "
                          "mid-read (rc={} {}): refusing to stamp a partial backfill",
                          rc, sqlite3_errmsg(legacy.get()));
            return false;
        }
    }
    // events — TTL-expired rows skipped AT SCAN TIME (never migrated-then-reaped).
    {
        SqliteStmt s;
        const char* sql =
            "SELECT event_id, rule_id, agent_id, event_type, severity, guard_type, "
            "guard_category, detected_value, expected_value, remediation_action, "
            "remediation_success, detection_latency_us, remediation_latency_us, timestamp, "
            "ttl_expires_at, detail_json FROM guaranteed_state_events "
            "WHERE ttl_expires_at = 0 OR ttl_expires_at > ?1;";
        if (sqlite3_prepare_v2(legacy.get(), sql, -1, s.addr(), nullptr) != SQLITE_OK) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: legacy events query "
                          "failed: {}",
                          sqlite3_errmsg(legacy.get()));
            return false;
        }
        sqlite3_bind_int64(s.get(), 1, now);
        int rc = SQLITE_OK;
        while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
            LegacyEvent e;
            e.event_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0)));
            e.rule_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1)));
            e.agent_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2)));
            e.event_type = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 3)));
            e.severity = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 4)));
            e.guard_type = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 5)));
            e.guard_category = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 6)));
            e.detected_value = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 7)));
            e.expected_value = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 8)));
            e.remediation_action =
                safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 9)));
            e.remediation_success = sqlite3_column_int(s.get(), 10) != 0;
            e.detection_latency_us = sqlite3_column_int64(s.get(), 11);
            e.remediation_latency_us = sqlite3_column_int64(s.get(), 12);
            e.timestamp = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 13)));
            e.ttl_expires_at = sqlite3_column_int64(s.get(), 14);
            e.detail_json = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 15)));
            legacy_events.push_back(std::move(e));
        }
        if (rc != SQLITE_DONE) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: legacy events scan aborted "
                          "mid-read (rc={} {}): refusing to stamp a partial backfill",
                          rc, sqlite3_errmsg(legacy.get()));
            return false;
        }
    }
    // observations — same TTL-expired-at-scan-time skip.
    {
        SqliteStmt s;
        const char* sql =
            "SELECT event_id, agent_id, observed_at, obs_type, subject, reason, symbolic, "
            "component, metric, platform, version, ttl_expires_at FROM guardian_observations "
            "WHERE ttl_expires_at = 0 OR ttl_expires_at > ?1;";
        if (sqlite3_prepare_v2(legacy.get(), sql, -1, s.addr(), nullptr) != SQLITE_OK) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: legacy observations query "
                          "failed: {}",
                          sqlite3_errmsg(legacy.get()));
            return false;
        }
        sqlite3_bind_int64(s.get(), 1, now);
        int rc = SQLITE_OK;
        while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
            LegacyObservation o;
            o.event_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0)));
            o.agent_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1)));
            o.observed_at = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2)));
            o.obs_type = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 3)));
            o.subject = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 4)));
            o.reason = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 5)));
            o.symbolic = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 6)));
            o.component = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 7)));
            o.metric = sqlite3_column_double(s.get(), 8);
            o.platform = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 9)));
            o.version = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 10)));
            o.ttl_expires_at = sqlite3_column_int64(s.get(), 11);
            legacy_observations.push_back(std::move(o));
        }
        if (rc != SQLITE_DONE) {
            spdlog::error("GuaranteedStateStore::migrate_from_sqlite: legacy observations scan "
                          "aborted mid-read (rc={} {}): refusing to stamp a partial backfill",
                          rc, sqlite3_errmsg(legacy.get()));
            return false;
        }
    }
    // `legacy` closes here via SqliteConnGuard's destructor.

    spdlog::info("GuaranteedStateStore::migrate_from_sqlite: backfilling {} rule(s), {} meta "
                 "row(s), {} status row(s), {} event(s), {} observation(s) from {}",
                 legacy_rules.size(), legacy_meta.size(), legacy_status.size(),
                 legacy_events.size(), legacy_observations.size(), legacy_db_path.string());

    auto lease = pool_.acquire(); // unbounded — construction-time discipline (ADR-0012 §2(a))
    if (!lease) {
        spdlog::error("GuaranteedStateStore::migrate_from_sqlite: no connection for backfill "
                      "transaction");
        return false;
    }
    PGconn* conn = lease.get();
    pg::PgResult begin = pg::exec_params(conn, "BEGIN", std::vector<std::string>{});
    if (begin.status() != PGRES_COMMAND_OK) {
        spdlog::error("GuaranteedStateStore::migrate_from_sqlite: BEGIN failed: {}",
                      PQerrorMessage(conn));
        return false;
    }
    pg::PgTxn txn(conn);

    std::int64_t skipped_bad = 0, rules_inserted = 0, events_inserted = 0,
                 observations_inserted = 0, status_inserted = 0;
    std::string failure_detail;
    bool aborted = false;

    // Order: rules -> meta -> status -> events -> observations (ADR-0038).
    //
    // rules / meta / status (coordinator review, overrides an earlier draft):
    // operator-authored config, the generation counter, and live compliance
    // state — ANY row-level error aborts the whole backfill unstamped via
    // `backfill_row_strict` (no skip-and-continue). A silently skipped
    // authored rule is a quiet partial disarm smuggled across the cutover,
    // the exact class of failure the ADR's catastrophic-read posture exists
    // to prevent. Only events/observations (below) use the skip-bad-row
    // `backfill_row` — bounded, agent-reported, re-derivable telemetry.
    for (const auto& r : legacy_rules) {
        if (!backfill_row_strict(
                conn, "rule", r.rule_id,
                [&]() {
                    return pg::exec_params(
                        conn,
                        "INSERT INTO guaranteed_state_store.guaranteed_state_rules "
                        "(rule_id, name, yaml_source, version, enabled, enforcement_mode, "
                        " severity, os_target, scope_expr, signature, created_at, updated_at, "
                        " created_by, updated_by, spec_json, prerequisites) "
                        "VALUES ($1,$2,$3,$4::bigint,$5::boolean,$6,$7,$8,$9,decode($10,'hex'),"
                        "$11,$12,$13,$14,$15,$16) ON CONFLICT (rule_id) DO NOTHING",
                        std::vector<std::optional<std::string>>{
                            r.rule_id, r.name, r.yaml_source, std::to_string(r.version),
                            std::string(r.enabled ? "true" : "false"), r.enforcement_mode,
                            r.severity, r.os_target, r.scope_expr,
                            r.signature.empty()
                                ? std::nullopt
                                : std::optional<std::string>(bytes_to_hex(r.signature)),
                            r.created_at, r.updated_at, r.created_by, r.updated_by, r.spec_json,
                            r.prerequisites});
                },
                failure_detail)) {
            aborted = true;
            break;
        }
        ++rules_inserted;
    }
    if (!aborted) {
        for (const auto& m : legacy_meta) {
            // Authoritative value overwrite: migration v1 already seeds
            // ('policy_generation', 0) — the legacy counter is the truth and
            // MUST replace the seed, unlike every other table's DO NOTHING.
            if (!backfill_row_strict(
                    conn, "meta", m.key,
                    [&]() {
                        return pg::exec_params(
                            conn,
                            "INSERT INTO guaranteed_state_store.guardian_meta (key, value) "
                            "VALUES ($1,$2::bigint) ON CONFLICT (key) DO UPDATE SET value = "
                            "EXCLUDED.value",
                            std::vector<std::string>{m.key, std::to_string(m.value)});
                    },
                    failure_detail)) {
                aborted = true;
                break;
            }
        }
    }
    if (!aborted) {
        for (const auto& st : legacy_status) {
            if (!backfill_row_strict(
                    conn, "status", st.agent_id + "/" + st.rule_id,
                    [&]() {
                        return pg::exec_params(
                            conn,
                            "INSERT INTO guaranteed_state_store.guardian_agent_rule_status "
                            "(agent_id, rule_id, state, updated_at) VALUES ($1,$2,$3,$4) "
                            "ON CONFLICT (agent_id, rule_id) DO NOTHING",
                            std::vector<std::string>{st.agent_id, st.rule_id, st.state,
                                                     st.updated_at});
                    },
                    failure_detail)) {
                aborted = true;
                break;
            }
            ++status_inserted;
        }
    }
    if (!aborted) {
        for (const auto& e : legacy_events) {
            auto ok = backfill_row(
                conn, "event", e.event_id,
                [&]() {
                    return pg::exec_params(
                        conn,
                        "INSERT INTO guaranteed_state_store.guaranteed_state_events "
                        "(event_id, rule_id, agent_id, event_type, severity, guard_type, "
                        " guard_category, detected_value, expected_value, remediation_action, "
                        " remediation_success, detection_latency_us, remediation_latency_us, "
                        " timestamp, ttl_expires_at, detail_json) "
                        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::boolean,$12::bigint,"
                        "$13::bigint,$14,$15::bigint,$16) ON CONFLICT (event_id) DO NOTHING",
                        std::vector<std::string>{
                            e.event_id, e.rule_id, e.agent_id, e.event_type, e.severity,
                            e.guard_type, e.guard_category, e.detected_value, e.expected_value,
                            e.remediation_action,
                            std::string(e.remediation_success ? "true" : "false"),
                            std::to_string(e.detection_latency_us),
                            std::to_string(e.remediation_latency_us), e.timestamp,
                            std::to_string(e.ttl_expires_at), e.detail_json});
                },
                failure_detail);
            if (!ok) {
                aborted = true;
                break;
            }
            if (*ok)
                ++events_inserted;
            else
                ++skipped_bad;
        }
    }
    if (!aborted) {
        for (const auto& o : legacy_observations) {
            auto ok = backfill_row(
                conn, "observation", o.event_id,
                [&]() {
                    return pg::exec_params(
                        conn,
                        "INSERT INTO guaranteed_state_store.guardian_observations "
                        "(event_id, agent_id, observed_at, obs_type, subject, reason, symbolic, "
                        " component, metric, platform, version, ttl_expires_at) "
                        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::double precision,$10,$11,"
                        "$12::bigint) ON CONFLICT (event_id) DO NOTHING",
                        std::vector<std::string>{
                            o.event_id, o.agent_id, o.observed_at, o.obs_type, o.subject, o.reason,
                            o.symbolic, o.component, std::to_string(o.metric), o.platform,
                            o.version, std::to_string(o.ttl_expires_at)});
                },
                failure_detail);
            if (!ok) {
                aborted = true;
                break;
            }
            if (*ok)
                ++observations_inserted;
            else
                ++skipped_bad;
        }
    }
    if (!aborted) {
        pg::PgResult stamp = pg::exec_params(
            conn,
            "INSERT INTO guaranteed_state_store.sqlite_backfill "
            "(id, completed_at, rules_inserted, events_inserted, observations_inserted, "
            " status_inserted, skipped_bad) VALUES (1, $1::bigint, $2::bigint, $3::bigint, "
            " $4::bigint, $5::bigint, $6::bigint) ON CONFLICT (id) DO NOTHING",
            std::vector<std::string>{
                std::to_string(now_epoch()), std::to_string(rules_inserted),
                std::to_string(events_inserted), std::to_string(observations_inserted),
                std::to_string(status_inserted), std::to_string(skipped_bad)});
        if (stamp.status() != PGRES_COMMAND_OK) {
            failure_detail = std::format("backfill marker stamp: {}", PQerrorMessage(conn));
            aborted = true;
        }
    }
    if (aborted || !txn.commit()) {
        spdlog::error(
            "GuaranteedStateStore::migrate_from_sqlite: backfill transaction failed and was "
            "rolled back — Guardian data NOT migrated. Offending: {}. Remediation: inspect/fix "
            "the referenced row in the retained read-only legacy file ({}) — e.g. `sqlite3 {} "
            "\"SELECT * FROM guaranteed_state_rules WHERE rule_id='<id>'\"` — then restart the "
            "server; the backfill marker was NOT stamped, so the next boot retries the whole "
            "backfill.",
            failure_detail.empty() ? "unknown (see the specific-row error above)" : failure_detail,
            legacy_db_path.string(), legacy_db_path.string());
        return false;
    }
    spdlog::info("GuaranteedStateStore::migrate_from_sqlite: backfill complete — rules={} "
                 "events={} observations={} status={} skipped_bad={}",
                 rules_inserted, events_inserted, observations_inserted, status_inserted,
                 skipped_bad);
    return true;
}

// ── Rule CRUD (fail-hard) ─────────────────────────────────────────────────────

std::expected<void, std::string>
GuaranteedStateStore::create_rule(const GuaranteedStateRuleRow& row) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    PGconn* conn = lease.get();

    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO guaranteed_state_store.guaranteed_state_rules "
        "(rule_id, name, yaml_source, version, enabled, enforcement_mode, severity, os_target, "
        " scope_expr, signature, created_at, updated_at, created_by, updated_by, spec_json, "
        " prerequisites) "
        "VALUES ($1,$2,$3,$4::bigint,$5::boolean,$6,$7,$8,$9,decode($10,'hex'),$11,$12,$13,$14,"
        "$15,$16)",
        std::vector<std::optional<std::string>>{
            row.rule_id, row.name, row.yaml_source, std::to_string(row.version),
            std::string(row.enabled ? "true" : "false"), row.enforcement_mode, row.severity,
            row.os_target, row.scope_expr,
            row.signature.empty() ? std::nullopt
                                  : std::optional<std::string>(bytes_to_hex(row.signature)),
            row.created_at, row.updated_at, row.created_by, row.updated_by, row.spec_json,
            row.prerequisites});
    if (res.status() != PGRES_COMMAND_OK) {
        const char* sqlstate_p = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
        const std::string err = PQresultErrorMessage(res.get());
        if (sqlstate == "23505") {
            const char* constraint_p = PQresultErrorField(res.get(), PG_DIAG_CONSTRAINT_NAME);
            const std::string constraint = constraint_p ? constraint_p : "";
            const bool name_collision = constraint.find("_name_key") != std::string::npos;
            const std::string what = name_collision
                                         ? ("rule name '" + row.name + "' already exists")
                                         : ("rule_id '" + row.rule_id + "' already exists");
            return std::unexpected(format_conflict(what));
        }
        return std::unexpected("insert failed: " + err);
    }
    bump_policy_generation_on(conn); // rule set changed → new generation
    return {};
}

std::expected<void, std::string>
GuaranteedStateStore::update_rule(const GuaranteedStateRuleRow& row) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    PGconn* conn = lease.get();

    pg::PgResult res = pg::exec_params(
        conn,
        "UPDATE guaranteed_state_store.guaranteed_state_rules SET "
        "name = $1, yaml_source = $2, version = $3::bigint, enabled = $4::boolean, "
        "enforcement_mode = $5, severity = $6, os_target = $7, scope_expr = $8, "
        "signature = decode($9,'hex'), updated_at = $10, updated_by = $11, spec_json = $12, "
        "prerequisites = $13 WHERE rule_id = $14 RETURNING rule_id",
        std::vector<std::optional<std::string>>{
            row.name, row.yaml_source, std::to_string(row.version),
            std::string(row.enabled ? "true" : "false"), row.enforcement_mode, row.severity,
            row.os_target, row.scope_expr,
            row.signature.empty() ? std::nullopt
                                  : std::optional<std::string>(bytes_to_hex(row.signature)),
            row.updated_at, row.updated_by, row.spec_json, row.prerequisites, row.rule_id});
    if (res.status() != PGRES_TUPLES_OK) {
        const char* sqlstate_p = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
        if (sqlstate == "23505")
            return std::unexpected(format_conflict("rule name '" + row.name + "' already exists"));
        return std::unexpected("update failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not found: rule_id '" + row.rule_id + "'");
    bump_policy_generation_on(conn); // rule set changed → new generation
    return {};
}

std::expected<void, std::string> GuaranteedStateStore::delete_rule(const std::string& rule_id) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    PGconn* conn = lease.get();

    pg::PgResult res = pg::exec_params(
        conn,
        "DELETE FROM guaranteed_state_store.guaranteed_state_rules WHERE rule_id = $1 "
        "RETURNING rule_id",
        std::vector<std::string>{rule_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("delete failed: " + std::string(PQresultErrorMessage(res.get())));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not found: rule_id '" + rule_id + "'");

    // Drop the rule's CURRENT compliance states — unlike the event log (an
    // immutable audit stream kept past rule deletion), this table holds live
    // state. Best-effort, matching the original (no changes-count check).
    pg::PgResult del_status = pg::exec_params(
        conn, "DELETE FROM guaranteed_state_store.guardian_agent_rule_status WHERE rule_id = $1",
        std::vector<std::string>{rule_id});
    if (del_status.status() != PGRES_COMMAND_OK)
        spdlog::warn("GuaranteedStateStore::delete_rule: status cleanup for rule_id={} failed: {}",
                     rule_id, PQerrorMessage(conn));

    bump_policy_generation_on(conn); // rule set changed → new generation
    return {};
}

void GuaranteedStateStore::bump_policy_generation() {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("GuaranteedStateStore::bump_policy_generation: no database connection: {}",
                     pool_.last_error());
        return;
    }
    bump_policy_generation_on(lease.get());
}

std::optional<uint64_t> GuaranteedStateStore::current_policy_generation() const {
    // Type-distinguishable (governance Gate 2 LOW1, ADR-0038): a degraded read
    // returns std::nullopt, NEVER 0. Collapsing degrade to 0 silently
    // suppressed the heartbeat reconcile (every `agent_gen >= 0` is true, so a
    // transient meta-read blip disabled reconcile fleet-wide) and stamped a
    // push with a wrong generation → re-push churn. Both consumers (push /
    // reconcile) treat nullopt as "abort this pass", the same posture list_rules
    // uses. The seeded row means a healthy store always has a value; nullopt is
    // strictly the not-open / lease-timeout / query-error path.
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT value FROM guaranteed_state_store.guardian_meta WHERE key = 'policy_generation'",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;
    return static_cast<uint64_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

namespace {
constexpr const char* kRuleCols =
    "rule_id, name, yaml_source, version, enabled, enforcement_mode, severity, os_target, "
    "scope_expr, encode(signature,'hex'), created_at, updated_at, created_by, updated_by, "
    "spec_json, prerequisites";

GuaranteedStateRuleRow read_rule_row(PGresult* res, int i) {
    GuaranteedStateRuleRow r;
    int c = 0;
    r.rule_id = text_col(res, i, c++);
    r.name = text_col(res, i, c++);
    r.yaml_source = text_col(res, i, c++);
    r.version = to_i64(PQgetvalue(res, i, c++));
    r.enabled = to_bool(PQgetvalue(res, i, c++));
    r.enforcement_mode = text_col(res, i, c++);
    r.severity = text_col(res, i, c++);
    r.os_target = text_col(res, i, c++);
    r.scope_expr = text_col(res, i, c++);
    r.signature = hex_to_bytes(text_col(res, i, c++));
    r.created_at = text_col(res, i, c++);
    r.updated_at = text_col(res, i, c++);
    r.created_by = text_col(res, i, c++);
    r.updated_by = text_col(res, i, c++);
    r.spec_json = text_col(res, i, c++);
    r.prerequisites = text_col(res, i, c++);
    return r;
}
} // namespace

std::expected<std::optional<GuaranteedStateRuleRow>, GuaranteedStateReadError>
GuaranteedStateStore::get_rule(const std::string& rule_id) const {
    if (!open_)
        return std::unexpected(GuaranteedStateReadError::kDegraded);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(GuaranteedStateReadError::kDegraded);
    const std::string sql = std::string("SELECT ") + kRuleCols +
                            " FROM guaranteed_state_store.guaranteed_state_rules WHERE rule_id "
                            "= $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{rule_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(GuaranteedStateReadError::kDegraded);
    if (PQntuples(res.get()) == 0)
        return std::optional<GuaranteedStateRuleRow>{std::nullopt};
    return std::optional<GuaranteedStateRuleRow>{read_rule_row(res.get(), 0)};
}

std::expected<std::vector<GuaranteedStateRuleRow>, std::string>
GuaranteedStateStore::list_rules() const {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    const std::string sql = std::string("SELECT ") + kRuleCols +
                            " FROM guaranteed_state_store.guaranteed_state_rules ORDER BY name";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    std::vector<GuaranteedStateRuleRow> rows;
    const int n = PQntuples(res.get());
    rows.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        rows.push_back(read_rule_row(res.get(), i));
    return rows;
}

// ── Event ingest (fail-soft) ─────────────────────────────────────────────────

namespace {

// Compare the persisted row against `in` across every immutable agent-supplied
// field. EXCLUDED: severity (server-enriched — can legitimately differ across
// a redelivery if the rule's severity changed) and ttl_expires_at
// (receipt-derived). event_id is the PK (equal by definition).
//
// Postgres column typing is STATIC (declared in DDL) — unlike SQLite's
// dynamic per-value storage classes, a TEXT column can never spontaneously
// hold an INTEGER storage class, so the original's defensive
// sqlite3_column_type() check has no Postgres analogue and is dropped;
// straightforward std::string equality on PQgetvalue suffices (the
// embedded-NUL reject at the ingest boundary already rules out a truncated
// exact-match false positive).
//
// Returns: true = idempotent redelivery, false = genuine field mismatch,
// unexpected = the compare itself could NOT be performed (an OPERATIONAL
// error) — mapped to Error by the caller, never a false collision.
std::expected<bool, std::string> stored_event_matches(PGconn* conn,
                                                       const GuaranteedStateEventRow& in) {
    pg::PgResult res = pg::exec_params(
        conn,
        "SELECT rule_id, agent_id, event_type, guard_type, guard_category, detected_value, "
        "expected_value, remediation_action, remediation_success, detection_latency_us, "
        "remediation_latency_us, timestamp, detail_json "
        "FROM guaranteed_state_store.guaranteed_state_events WHERE event_id = $1",
        std::vector<std::string>{in.event_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("compare query failed: ") +
                               PQresultErrorMessage(res.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("conflicting row not found for compare (raced reaper?)");
    const bool match =
        text_col(res.get(), 0, 0) == in.rule_id && text_col(res.get(), 0, 1) == in.agent_id &&
        text_col(res.get(), 0, 2) == in.event_type && text_col(res.get(), 0, 3) == in.guard_type &&
        text_col(res.get(), 0, 4) == in.guard_category &&
        text_col(res.get(), 0, 5) == in.detected_value &&
        text_col(res.get(), 0, 6) == in.expected_value &&
        text_col(res.get(), 0, 7) == in.remediation_action &&
        to_bool(PQgetvalue(res.get(), 0, 8)) == in.remediation_success &&
        to_i64(PQgetvalue(res.get(), 0, 9)) == in.detection_latency_us &&
        to_i64(PQgetvalue(res.get(), 0, 10)) == in.remediation_latency_us &&
        text_col(res.get(), 0, 11) == in.timestamp && text_col(res.get(), 0, 12) == in.detail_json;
    return match;
}

// Project one ruleless DEX observation into guardian_observations. Caller
// MUST run this inside its own SAVEPOINT (a projection failure must degrade,
// not abort the enclosing event-insert transaction — Postgres aborts on ANY
// failed statement, unlike SQLite). `detail_json` is parsed defensively:
// malformed -> empty crash fields, never drops the observation. `ttl` is the
// parent event's expiry so the reaper sweeps both in lockstep.
std::expected<void, std::string> project_observation(PGconn* conn,
                                                      const GuaranteedStateEventRow& row,
                                                      int64_t ttl) {
    nlohmann::json j = nlohmann::json::parse(row.detail_json, nullptr, /*allow_exceptions=*/false);
    constexpr std::size_t kProjFieldMax = 256;
    const auto field = [&](const char* k) -> std::string {
        if (j.is_object())
            if (auto it = j.find(k); it != j.end() && it->is_string()) {
                std::string v = it->get<std::string>();
                if (v.size() > kProjFieldMax) {
                    v.resize(kProjFieldMax);
                    while (!v.empty() && (static_cast<unsigned char>(v.back()) & 0xC0) == 0x80)
                        v.pop_back();
                    if (!v.empty() && (static_cast<unsigned char>(v.back()) & 0xC0) == 0xC0)
                        v.pop_back();
                }
                return v;
            }
        return {};
    };
    std::string subject = field("subject");
    if (subject.empty())
        subject = field("process");
    std::string reason = field("reason");
    if (reason.empty())
        reason = field("exception_code");
    const std::string symbolic = field("symbolic");
    std::string component = field("component");
    if (component.empty())
        component = field("faulting_module");
    std::string platform = field("platform");
    for (auto& c : platform)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (platform.starts_with("win"))
        platform = "windows";
    else if (platform.starts_with("lin"))
        platform = "linux";
    else if (platform.starts_with("darwin") || platform.starts_with("macos"))
        platform = "macos";
    const std::string version = yuzu::util::canon_version(field("version"));
    double metric = 0.0;
    if (j.is_object())
        if (auto it = j.find("metric"); it != j.end() && it->is_number()) {
            const double v = it->get<double>();
            if (v > 0.0 && v < 1.0e12)
                metric = v;
        }

    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO guaranteed_state_store.guardian_observations "
        "(event_id, agent_id, observed_at, obs_type, subject, reason, symbolic, component, "
        "metric, platform, version, ttl_expires_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::double precision,$10,$11,$12::bigint)",
        std::vector<std::string>{row.event_id, row.agent_id, row.timestamp, row.event_type,
                                 subject, reason, symbolic, component, std::to_string(metric),
                                 platform, version, std::to_string(ttl)});
    if (res.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string("insert(observation) failed: ") +
                               PQresultErrorMessage(res.get()));
    return {};
}

// Upsert one (agent, rule) compliance state. Best-effort — logs on a genuine
// SQL error; the ON CONFLICT ... WHERE guard makes a stale-event no-op a
// normal zero-rows-affected outcome, not an error.
void upsert_rule_status(PGconn* conn, const std::string& agent_id, const std::string& rule_id,
                        const char* state, const std::string& updated_at) {
    if (agent_id.empty() || rule_id.empty())
        return;
    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO guaranteed_state_store.guardian_agent_rule_status "
        "(agent_id, rule_id, state, updated_at) VALUES ($1,$2,$3,$4) "
        "ON CONFLICT (agent_id, rule_id) DO UPDATE SET state = EXCLUDED.state, "
        "updated_at = EXCLUDED.updated_at "
        "WHERE EXCLUDED.updated_at >= guardian_agent_rule_status.updated_at",
        std::vector<std::string>{agent_id, rule_id, std::string(state), updated_at});
    if (res.status() != PGRES_COMMAND_OK)
        spdlog::warn("GuaranteedStateStore: status upsert failed for agent_id={} rule_id={}: {}",
                     agent_id, rule_id, PQerrorMessage(conn));
}

} // namespace

EventInsertResult
GuaranteedStateStore::insert_event_classified(const GuaranteedStateEventRow& row) {
    if (!open_)
        return {EventInsertOutcome::Error, "database not open"};

    // Reject malformed input up front (untrusted agent boundary): libpq's
    // text-format bind (paramLengths=nullptr) computes length via strlen,
    // exactly like SQLite's -1 bind — an embedded NUL would silently
    // truncate, corrupting the event_id PK dedup and the redelivery compare.
    for (const std::string* f :
        {&row.event_id, &row.rule_id, &row.agent_id, &row.event_type, &row.severity,
         &row.guard_type, &row.guard_category, &row.detected_value, &row.expected_value,
         &row.remediation_action, &row.timestamp, &row.detail_json})
        if (f->find('\0') != std::string::npos)
            return {EventInsertOutcome::Error, "event field contains an embedded NUL byte"};

    const auto op_error = [this](std::string msg, const char* reason) {
        events_ingest_errors_.fetch_add(1, std::memory_order_relaxed);
        note_ingest_dropped(metrics_, reason);
        return EventInsertResult{EventInsertOutcome::Error, std::move(msg)};
    };

    auto lease = pool_.try_acquire_for(kIngestTimeout);
    if (!lease) {
        events_ingest_errors_.fetch_add(1, std::memory_order_relaxed);
        note_ingest_dropped(metrics_, kReasonPoolTimeout);
        return {EventInsertOutcome::Error, "no database connection: " + pool_.last_error()};
    }
    PGconn* conn = lease.get();

    pg::PgResult begin = pg::exec_params(conn, "BEGIN", std::vector<std::string>{});
    if (begin.status() != PGRES_COMMAND_OK)
        return op_error(std::string("BEGIN failed: ") + PQerrorMessage(conn), kReasonQueryError);
    pg::PgTxn txn(conn);
    const int64_t ttl = compute_ttl_epoch();

    pg::PgResult sp = pg::exec_params(conn, "SAVEPOINT event_insert", std::vector<std::string>{});
    if (sp.status() != PGRES_COMMAND_OK)
        return op_error(std::string("SAVEPOINT failed: ") + PQerrorMessage(conn), kReasonQueryError);

    pg::PgResult ins = pg::exec_params(
        conn,
        "INSERT INTO guaranteed_state_store.guaranteed_state_events "
        "(event_id, rule_id, agent_id, event_type, severity, guard_type, guard_category, "
        " detected_value, expected_value, remediation_action, remediation_success, "
        " detection_latency_us, remediation_latency_us, timestamp, ttl_expires_at, detail_json) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::boolean,$12::bigint,$13::bigint,$14,"
        "$15::bigint,$16)",
        std::vector<std::string>{row.event_id, row.rule_id, row.agent_id, row.event_type,
                                 row.severity, row.guard_type, row.guard_category,
                                 row.detected_value, row.expected_value, row.remediation_action,
                                 std::string(row.remediation_success ? "true" : "false"),
                                 std::to_string(row.detection_latency_us),
                                 std::to_string(row.remediation_latency_us), row.timestamp,
                                 std::to_string(ttl), row.detail_json});

    if (ins.status() != PGRES_COMMAND_OK) {
        const char* sqlstate_p = PQresultErrorField(ins.get(), PG_DIAG_SQLSTATE);
        const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
        const std::string err = PQresultErrorMessage(ins.get());
        if (sqlstate == "23505") {
            // event_id already present. Un-abort the transaction (Postgres aborts the
            // WHOLE transaction on a failed statement, unlike SQLite) so the compare
            // SELECT below can run on the SAME connection/transaction — load-bearing
            // for the no-TOCTOU-with-the-reaper invariant.
            pg::PgResult back = pg::exec_params(conn, "ROLLBACK TO SAVEPOINT event_insert", std::vector<std::string>{});
            if (back.status() != PGRES_COMMAND_OK)
                return op_error(std::string("ROLLBACK TO SAVEPOINT failed: ") +
                                    PQerrorMessage(conn),
                                kReasonQueryError);
            auto matched = stored_event_matches(conn, row);
            if (!matched)
                return op_error("redelivery compare failed: " + matched.error(), kReasonQueryError);
            if (*matched) {
                events_redelivered_.fetch_add(1, std::memory_order_relaxed);
                return {EventInsertOutcome::Redelivered, {}};
            }
            events_dropped_.fetch_add(1, std::memory_order_relaxed);
            note_ingest_dropped(metrics_, kReasonConflict);
            return {EventInsertOutcome::Conflict,
                    format_conflict("event_id '" + row.event_id +
                                    "' already exists with different fields")};
        }
        return op_error("insert failed: " + err, kReasonQueryError);
    }

    // DEX projection: ruleless observations only, under its own SAVEPOINT so a
    // projection failure degrades (event kept) instead of aborting the whole
    // transaction.
    if (is_reserved_rule_id(row.rule_id)) {
        pg::PgResult sp2 = pg::exec_params(conn, "SAVEPOINT observation_projection", std::vector<std::string>{});
        if (sp2.status() == PGRES_COMMAND_OK) {
            if (auto pr = project_observation(conn, row, ttl); !pr) {
                observations_proj_failures_.fetch_add(1, std::memory_order_relaxed);
                spdlog::error("GuaranteedStateStore: observation projection failed "
                              "(event kept, read-model row lost) event_id={} agent_id={}: {}",
                              row.event_id, row.agent_id, pr.error());
                pg::exec_params(conn, "ROLLBACK TO SAVEPOINT observation_projection", std::vector<std::string>{});
            } else {
                pg::exec_params(conn, "RELEASE SAVEPOINT observation_projection", std::vector<std::string>{});
            }
        } else {
            observations_proj_failures_.fetch_add(1, std::memory_order_relaxed);
            spdlog::error("GuaranteedStateStore: observation projection SAVEPOINT failed "
                          "event_id={}: {}",
                          row.event_id, PQerrorMessage(conn));
        }
    }

    if (!txn.commit())
        return op_error(std::string("commit failed: ") + PQerrorMessage(conn), kReasonQueryError);

    events_written_.fetch_add(1, std::memory_order_relaxed);
    // Census upsert AFTER commit, as a separate best-effort autocommit
    // statement on the same connection (mirrors the original SQLite ordering
    // — a status-upsert failure here must never take the already-committed
    // event with it).
    if (!is_reserved_rule_id(row.rule_id))
        if (const char* state = event_state_from_type(row.event_type))
            upsert_rule_status(conn, row.agent_id, row.rule_id, state, row.timestamp);
    return {EventInsertOutcome::Inserted, {}};
}

std::expected<void, std::string>
GuaranteedStateStore::insert_event(const GuaranteedStateEventRow& row) {
    EventInsertResult r = insert_event_classified(row);
    switch (r.outcome) {
    case EventInsertOutcome::Inserted:
    case EventInsertOutcome::Redelivered:
        return {};
    case EventInsertOutcome::Conflict:
    case EventInsertOutcome::Error:
        return std::unexpected(std::move(r.error));
    }
    return std::unexpected("insert_event: unreachable outcome");
}

// HARD CONSTRAINT (item-7 PR-Sv, arch-S1 / UP-11): this batch path does NOT classify
// redelivery vs collision and does NOT drive the DEX observers — on ANY event_id conflict
// it aborts and rolls back the WHOLE batch. That is safe ONLY because it has no live caller
// today. The durable agent lifecycle journal makes redelivery the common case, so replays
// MUST ingest one-at-a-time via insert_event_classified, NEVER through this batch path.
std::expected<std::size_t, std::string>
GuaranteedStateStore::insert_events(const std::vector<GuaranteedStateEventRow>& rows) {
    if (rows.empty())
        return 0;
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kIngestTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    PGconn* conn = lease.get();

    pg::PgResult begin = pg::exec_params(conn, "BEGIN", std::vector<std::string>{});
    if (begin.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string("BEGIN failed: ") + PQerrorMessage(conn));
    pg::PgTxn txn(conn);
    const int64_t ttl = compute_ttl_epoch();

    for (const auto& row : rows) {
        pg::PgResult ins = pg::exec_params(
            conn,
            "INSERT INTO guaranteed_state_store.guaranteed_state_events "
            "(event_id, rule_id, agent_id, event_type, severity, guard_type, guard_category, "
            " detected_value, expected_value, remediation_action, remediation_success, "
            " detection_latency_us, remediation_latency_us, timestamp, ttl_expires_at, "
            " detail_json) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::boolean,$12::bigint,$13::bigint,$14,"
            "$15::bigint,$16)",
            std::vector<std::string>{row.event_id, row.rule_id, row.agent_id, row.event_type,
                                     row.severity, row.guard_type, row.guard_category,
                                     row.detected_value, row.expected_value,
                                     row.remediation_action,
                                     std::string(row.remediation_success ? "true" : "false"),
                                     std::to_string(row.detection_latency_us),
                                     std::to_string(row.remediation_latency_us), row.timestamp,
                                     std::to_string(ttl), row.detail_json});
        if (ins.status() != PGRES_COMMAND_OK) {
            const char* sqlstate_p = PQresultErrorField(ins.get(), PG_DIAG_SQLSTATE);
            const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
            if (sqlstate == "23505")
                return std::unexpected(
                    format_conflict("event_id '" + row.event_id + "' already exists"));
            return std::unexpected("insert failed: " + std::string(PQresultErrorMessage(ins.get())));
        }
        // Census upsert INSIDE the transaction here (unlike the single-event path):
        // rolled back with the batch on any later failure, so events and status
        // never diverge (matches the original's explicit intent for this path).
        if (!is_reserved_rule_id(row.rule_id))
            if (const char* state = event_state_from_type(row.event_type))
                upsert_rule_status(conn, row.agent_id, row.rule_id, state, row.timestamp);
        // DEX projection — same degrade-don't-destroy contract as insert_event,
        // under its own SAVEPOINT (Postgres aborts on any failed statement).
        if (is_reserved_rule_id(row.rule_id)) {
            pg::PgResult sp = pg::exec_params(conn, "SAVEPOINT observation_projection", std::vector<std::string>{});
            if (sp.status() == PGRES_COMMAND_OK) {
                if (auto pr = project_observation(conn, row, ttl); !pr) {
                    observations_proj_failures_.fetch_add(1, std::memory_order_relaxed);
                    spdlog::error("GuaranteedStateStore: observation projection failed in batch "
                                  "(event kept) event_id={} agent_id={}: {}",
                                  row.event_id, row.agent_id, pr.error());
                    pg::exec_params(conn, "ROLLBACK TO SAVEPOINT observation_projection", std::vector<std::string>{});
                } else {
                    pg::exec_params(conn, "RELEASE SAVEPOINT observation_projection", std::vector<std::string>{});
                }
            }
        }
    }

    if (!txn.commit())
        return std::unexpected(std::string("COMMIT failed: ") + PQerrorMessage(conn));
    events_written_.fetch_add(rows.size(), std::memory_order_relaxed);
    return rows.size();
}

// ── DEX / analytics reads (plain, empty-on-degrade — ADR-0038 #2659) ─────────

std::vector<GuaranteedStateEventRow>
GuaranteedStateStore::query_events(const GuaranteedStateEventQuery& q) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<GuaranteedStateEventRow>>(
        open_, pool_, metrics_, "query_events", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<GuaranteedStateEventRow>> {
            std::string sql =
                "SELECT event_id, rule_id, agent_id, event_type, severity, guard_type, "
                "guard_category, detected_value, expected_value, remediation_action, "
                "remediation_success, detection_latency_us, remediation_latency_us, timestamp, "
                "detail_json FROM guaranteed_state_store.guaranteed_state_events WHERE 1=1";
            std::vector<std::string> params;
            int idx = 1;
            if (!q.rule_id.empty()) {
                sql += " AND rule_id = $" + std::to_string(idx++);
                params.push_back(q.rule_id);
            }
            if (!q.agent_id.empty()) {
                sql += " AND agent_id = $" + std::to_string(idx++);
                params.push_back(q.agent_id);
            }
            if (!q.severity.empty()) {
                sql += " AND severity = $" + std::to_string(idx++);
                params.push_back(q.severity);
            }
            sql += " ORDER BY timestamp DESC, event_id DESC LIMIT $" + std::to_string(idx++) +
                   "::bigint";
            params.push_back(std::to_string(std::clamp(q.limit, 0, kMaxEventsLimit)));
            if (q.offset > 0) {
                sql += " OFFSET $" + std::to_string(idx++) + "::bigint";
                params.push_back(std::to_string(q.offset));
            }
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<GuaranteedStateEventRow> rows;
            const int n = PQntuples(res.get());
            rows.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                GuaranteedStateEventRow r;
                int c = 0;
                r.event_id = text_col(res.get(), i, c++);
                r.rule_id = text_col(res.get(), i, c++);
                r.agent_id = text_col(res.get(), i, c++);
                r.event_type = text_col(res.get(), i, c++);
                r.severity = text_col(res.get(), i, c++);
                r.guard_type = text_col(res.get(), i, c++);
                r.guard_category = text_col(res.get(), i, c++);
                r.detected_value = text_col(res.get(), i, c++);
                r.expected_value = text_col(res.get(), i, c++);
                r.remediation_action = text_col(res.get(), i, c++);
                r.remediation_success = to_bool(PQgetvalue(res.get(), i, c++));
                r.detection_latency_us = to_i64(PQgetvalue(res.get(), i, c++));
                r.remediation_latency_us = to_i64(PQgetvalue(res.get(), i, c++));
                r.timestamp = text_col(res.get(), i, c++);
                r.detail_json = text_col(res.get(), i, c++);
                rows.push_back(std::move(r));
            }
            return rows;
        });
}

namespace {
GuardianObservationRow read_observation_row(PGresult* res, int i, bool has_version = true) {
    GuardianObservationRow r;
    int c = 0;
    r.event_id = text_col(res, i, c++);
    r.agent_id = text_col(res, i, c++);
    r.observed_at = text_col(res, i, c++);
    r.obs_type = text_col(res, i, c++);
    r.subject = text_col(res, i, c++);
    r.reason = text_col(res, i, c++);
    r.symbolic = text_col(res, i, c++);
    r.component = text_col(res, i, c++);
    r.metric = to_double(PQgetvalue(res, i, c++));
    r.platform = text_col(res, i, c++);
    if (has_version)
        r.version = text_col(res, i, c++);
    return r;
}
} // namespace

std::vector<GuardianObservationRow> GuaranteedStateStore::query_observations(int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<GuardianObservationRow>>(
        open_, pool_, metrics_, "query_observations", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<GuardianObservationRow>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT event_id, agent_id, observed_at, obs_type, subject, reason, symbolic, "
                "component, metric, platform, version FROM "
                "guaranteed_state_store.guardian_observations ORDER BY observed_at DESC, "
                "event_id DESC LIMIT $1::bigint",
                std::vector<std::string>{
                    std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<GuardianObservationRow> rows;
            const int n = PQntuples(res.get());
            rows.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i)
                rows.push_back(read_observation_row(res.get(), i));
            return rows;
        });
}

DexCrashSummary GuaranteedStateStore::dex_crash_summary(const std::string& since,
                                                        const std::string& platform) const {
    static DegradeSampler sampler;
    return dex_read<DexCrashSummary>(
        open_, pool_, metrics_, "dex_crash_summary", sampler,
        [&](PGconn* conn) -> std::optional<DexCrashSummary> {
            std::string sql =
                "SELECT COUNT(*), COUNT(DISTINCT agent_id), COUNT(DISTINCT subject) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND observed_at >= $1";
            std::vector<std::string> params{since};
            if (!platform.empty()) {
                sql += " AND platform = $2";
                params.push_back(platform);
            }
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            DexCrashSummary s;
            if (PQntuples(res.get()) > 0) {
                s.total_crashes = to_i64(PQgetvalue(res.get(), 0, 0));
                s.distinct_devices = to_i64(PQgetvalue(res.get(), 0, 1));
                s.distinct_apps = to_i64(PQgetvalue(res.get(), 0, 2));
            }
            return s;
        });
}

std::vector<DexAppCrashCount> GuaranteedStateStore::dex_top_apps(const std::string& since,
                                                                 int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexAppCrashCount>>(
        open_, pool_, metrics_, "dex_top_apps", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexAppCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT subject, "
                "COUNT(*) FILTER (WHERE obs_type = 'process.crashed') AS crashes, "
                "COUNT(*) FILTER (WHERE obs_type = 'process.hung') AS hangs, "
                "COUNT(DISTINCT agent_id), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type IN ('process.crashed', 'process.hung') AND observed_at >= $1 "
                "GROUP BY subject ORDER BY (COUNT(*) FILTER (WHERE obs_type = 'process.crashed') "
                "+ COUNT(*) FILTER (WHERE obs_type = 'process.hung')) DESC, subject ASC "
                "LIMIT $2::bigint",
                std::vector<std::string>{since, std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexAppCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexAppCrashCount a;
                a.subject = text_col(res.get(), i, 0);
                a.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                a.hangs = to_i64(PQgetvalue(res.get(), i, 2));
                a.distinct_devices = to_i64(PQgetvalue(res.get(), i, 3));
                a.last_seen = text_col(res.get(), i, 4);
                out.push_back(std::move(a));
            }
            return out;
        });
}

std::vector<DexAppCrashCount>
GuaranteedStateStore::dex_device_top_apps(const std::string& agent_id, const std::string& since,
                                          int limit) const {
    static DegradeSampler sampler;
    if (agent_id.empty())
        return {};
    return dex_read<std::vector<DexAppCrashCount>>(
        open_, pool_, metrics_, "dex_device_top_apps", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexAppCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT subject, version, "
                "COUNT(*) FILTER (WHERE obs_type = 'process.crashed') AS crashes, "
                "COUNT(*) FILTER (WHERE obs_type = 'process.hung') AS hangs, MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE agent_id = $1 AND obs_type IN ('process.crashed', 'process.hung') "
                "AND observed_at >= $2 GROUP BY subject, version "
                "ORDER BY (COUNT(*) FILTER (WHERE obs_type = 'process.crashed') + "
                "COUNT(*) FILTER (WHERE obs_type = 'process.hung')) DESC, subject ASC, "
                "version ASC LIMIT $3::bigint",
                std::vector<std::string>{agent_id, since,
                                         std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexAppCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexAppCrashCount a;
                a.subject = text_col(res.get(), i, 0);
                a.version = text_col(res.get(), i, 1);
                a.crashes = to_i64(PQgetvalue(res.get(), i, 2));
                a.hangs = to_i64(PQgetvalue(res.get(), i, 3));
                a.distinct_devices = 1;
                a.last_seen = text_col(res.get(), i, 4);
                out.push_back(std::move(a));
            }
            return out;
        });
}

std::vector<DexModuleCrashCount> GuaranteedStateStore::dex_top_modules(const std::string& since,
                                                                       int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexModuleCrashCount>>(
        open_, pool_, metrics_, "dex_top_modules", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexModuleCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT component, COUNT(*), COUNT(DISTINCT subject) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND observed_at >= $1 "
                "GROUP BY component ORDER BY COUNT(*) DESC, component ASC LIMIT $2::bigint",
                std::vector<std::string>{since, std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexModuleCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexModuleCrashCount m;
                m.component = text_col(res.get(), i, 0);
                m.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                m.distinct_apps = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(m));
            }
            return out;
        });
}

std::vector<DexDeviceCrashCount> GuaranteedStateStore::dex_top_devices(const std::string& since,
                                                                       int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDeviceCrashCount>>(
        open_, pool_, metrics_, "dex_top_devices", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDeviceCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT agent_id, COUNT(*), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND observed_at >= $1 "
                "GROUP BY agent_id ORDER BY COUNT(*) DESC, agent_id ASC LIMIT $2::bigint",
                std::vector<std::string>{since, std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDeviceCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDeviceCrashCount d;
                d.agent_id = text_col(res.get(), i, 0);
                d.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                d.last_seen = text_col(res.get(), i, 2);
                out.push_back(std::move(d));
            }
            return out;
        });
}

std::vector<DexOsCrashCount> GuaranteedStateStore::dex_crashes_by_os(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexOsCrashCount>>(
        open_, pool_, metrics_, "dex_crashes_by_os", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexOsCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT platform, COUNT(*), COUNT(DISTINCT agent_id) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND observed_at >= $1 "
                "GROUP BY platform ORDER BY COUNT(*) DESC",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexOsCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexOsCrashCount o;
                o.platform = text_col(res.get(), i, 0);
                o.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                o.distinct_devices = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(o));
            }
            return out;
        });
}

std::vector<DexDayCrashCount>
GuaranteedStateStore::dex_crashes_by_day(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDayCrashCount>>(
        open_, pool_, metrics_, "dex_crashes_by_day", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDayCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT substr(observed_at, 1, 10) AS day, COUNT(*) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND observed_at >= $1 "
                "GROUP BY day ORDER BY day ASC",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDayCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDayCrashCount d;
                d.day = text_col(res.get(), i, 0);
                d.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                out.push_back(std::move(d));
            }
            return out;
        });
}

std::vector<DexSignalCount>
GuaranteedStateStore::dex_signal_summary(const std::string& since, const std::string& platform) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexSignalCount>>(
        open_, pool_, metrics_, "dex_signal_summary", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexSignalCount>> {
            std::string sql =
                "SELECT obs_type, COUNT(*), COUNT(DISTINCT agent_id), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations WHERE observed_at >= $1";
            std::vector<std::string> params{since};
            if (!platform.empty()) {
                sql += " AND platform = $2";
                params.push_back(platform);
            }
            sql += " GROUP BY obs_type ORDER BY COUNT(*) DESC, obs_type ASC";
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexSignalCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexSignalCount c;
                c.obs_type = text_col(res.get(), i, 0);
                c.count = to_i64(PQgetvalue(res.get(), i, 1));
                c.distinct_devices = to_i64(PQgetvalue(res.get(), i, 2));
                c.last_seen = text_col(res.get(), i, 3);
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::vector<DexSignalCount>
GuaranteedStateStore::dex_device_signal_summary(const std::string& agent_id,
                                                const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexSignalCount>>(
        open_, pool_, metrics_, "dex_device_signal_summary", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexSignalCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT obs_type, COUNT(*), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE agent_id = $1 AND observed_at >= $2 "
                "GROUP BY obs_type ORDER BY COUNT(*) DESC, obs_type ASC",
                std::vector<std::string>{agent_id, since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexSignalCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexSignalCount c;
                c.obs_type = text_col(res.get(), i, 0);
                c.count = to_i64(PQgetvalue(res.get(), i, 1));
                c.distinct_devices = 1;
                c.last_seen = text_col(res.get(), i, 2);
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::vector<DexSubjectCount>
GuaranteedStateStore::dex_signal_subjects(const std::string& obs_type, const std::string& since,
                                          int limit, const std::string& platform) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexSubjectCount>>(
        open_, pool_, metrics_, "dex_signal_subjects", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexSubjectCount>> {
            std::string sql =
                "SELECT subject, COUNT(*), COUNT(DISTINCT agent_id), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = $1 AND observed_at >= $2 AND subject <> ''";
            std::vector<std::string> params{obs_type, since,
                                            std::to_string(std::clamp(limit, 0, kMaxEventsLimit))};
            if (!platform.empty()) {
                sql += " AND platform = $4";
                params.push_back(platform);
            }
            sql += " GROUP BY subject ORDER BY COUNT(*) DESC, subject ASC LIMIT $3::bigint";
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexSubjectCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexSubjectCount c;
                c.subject = text_col(res.get(), i, 0);
                c.count = to_i64(PQgetvalue(res.get(), i, 1));
                c.distinct_devices = to_i64(PQgetvalue(res.get(), i, 2));
                c.last_seen = text_col(res.get(), i, 3);
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::vector<DexOsCrashCount>
GuaranteedStateStore::dex_signal_by_os(const std::string& obs_type, const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexOsCrashCount>>(
        open_, pool_, metrics_, "dex_signal_by_os", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexOsCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT platform, COUNT(*), COUNT(DISTINCT agent_id) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = $1 AND observed_at >= $2 GROUP BY platform ORDER BY COUNT(*) "
                "DESC",
                std::vector<std::string>{obs_type, since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexOsCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexOsCrashCount c;
                c.platform = text_col(res.get(), i, 0);
                c.crashes = to_i64(PQgetvalue(res.get(), i, 1)); // generic event count
                c.distinct_devices = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::vector<DexDeviceCrashCount>
GuaranteedStateStore::dex_signal_devices(const std::string& obs_type, const std::string& since,
                                         int limit, const std::string& platform) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDeviceCrashCount>>(
        open_, pool_, metrics_, "dex_signal_devices", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDeviceCrashCount>> {
            std::string sql =
                "SELECT agent_id, COUNT(*), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = $1 AND observed_at >= $2";
            std::vector<std::string> params{obs_type, since,
                                            std::to_string(std::clamp(limit, 0, kMaxEventsLimit))};
            if (!platform.empty()) {
                sql += " AND platform = $4";
                params.push_back(platform);
            }
            sql += " GROUP BY agent_id ORDER BY COUNT(*) DESC, agent_id ASC LIMIT $3::bigint";
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDeviceCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDeviceCrashCount c;
                c.agent_id = text_col(res.get(), i, 0);
                c.crashes = to_i64(PQgetvalue(res.get(), i, 1)); // generic event count
                c.last_seen = text_col(res.get(), i, 2);
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::vector<DexDayCrashCount>
GuaranteedStateStore::dex_signal_by_day(const std::string& obs_type, const std::string& since,
                                        const std::string& platform) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDayCrashCount>>(
        open_, pool_, metrics_, "dex_signal_by_day", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDayCrashCount>> {
            std::string sql =
                "SELECT substr(observed_at, 1, 10) AS day, COUNT(*) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = $1 AND observed_at >= $2";
            std::vector<std::string> params{obs_type, since};
            if (!platform.empty()) {
                sql += " AND platform = $3";
                params.push_back(platform);
            }
            sql += " GROUP BY day ORDER BY day ASC";
            pg::PgResult res = pg::exec_params(conn, sql.c_str(), params);
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDayCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDayCrashCount c;
                c.day = text_col(res.get(), i, 0);
                c.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::vector<DexOsScope> GuaranteedStateStore::dex_os_signal_scope(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexOsScope>>(
        open_, pool_, metrics_, "dex_os_signal_scope", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexOsScope>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT platform, COUNT(DISTINCT obs_type), COUNT(*) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE observed_at >= $1 AND platform <> '' "
                "GROUP BY platform ORDER BY COUNT(*) DESC",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexOsScope> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexOsScope c;
                c.platform = text_col(res.get(), i, 0);
                c.distinct_types = to_i64(PQgetvalue(res.get(), i, 1));
                c.total_events = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(c));
            }
            return out;
        });
}

std::vector<DexDaySignal>
GuaranteedStateStore::dex_signal_day_matrix(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDaySignal>>(
        open_, pool_, metrics_, "dex_signal_day_matrix", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDaySignal>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT substr(observed_at, 1, 10) AS day, obs_type, COUNT(*) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE observed_at >= $1 GROUP BY day, obs_type ORDER BY day ASC, obs_type ASC",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDaySignal> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDaySignal c;
                c.day = text_col(res.get(), i, 0);
                c.obs_type = text_col(res.get(), i, 1);
                c.count = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(c));
            }
            return out;
        });
}

DexBootStats GuaranteedStateStore::dex_boot_stats(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<DexBootStats>(
        open_, pool_, metrics_, "dex_boot_stats", sampler,
        [&](PGconn* conn) -> std::optional<DexBootStats> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT COUNT(*), AVG(metric), MAX(metric), COUNT(DISTINCT agent_id) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'os.boot' AND metric > 0 AND observed_at >= $1",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            DexBootStats s;
            if (PQntuples(res.get()) > 0) {
                s.boots = to_i64(PQgetvalue(res.get(), 0, 0));
                s.avg_ms = to_double(PQgetvalue(res.get(), 0, 1));
                s.max_ms = to_double(PQgetvalue(res.get(), 0, 2));
                s.distinct_devices = to_i64(PQgetvalue(res.get(), 0, 3));
            }
            return s;
        });
}

std::vector<DexDeviceBoot> GuaranteedStateStore::dex_slowest_boots(const std::string& since,
                                                                   int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDeviceBoot>>(
        open_, pool_, metrics_, "dex_slowest_boots", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDeviceBoot>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT agent_id, AVG(metric), MAX(metric), COUNT(*) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'os.boot' AND metric > 0 AND observed_at >= $1 "
                "GROUP BY agent_id ORDER BY AVG(metric) DESC, agent_id ASC LIMIT $2::bigint",
                std::vector<std::string>{since, std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDeviceBoot> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDeviceBoot b;
                b.agent_id = text_col(res.get(), i, 0);
                b.avg_ms = to_double(PQgetvalue(res.get(), i, 1));
                b.max_ms = to_double(PQgetvalue(res.get(), i, 2));
                b.boots = to_i64(PQgetvalue(res.get(), i, 3));
                out.push_back(std::move(b));
            }
            return out;
        });
}

DexEntitySummary GuaranteedStateStore::dex_app_summary(const std::string& process_name,
                                                       const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<DexEntitySummary>(
        open_, pool_, metrics_, "dex_app_summary", sampler,
        [&](PGconn* conn) -> std::optional<DexEntitySummary> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT COUNT(*) FILTER (WHERE obs_type = 'process.crashed'), "
                "COUNT(*) FILTER (WHERE obs_type = 'process.hung'), COUNT(*), "
                "COUNT(DISTINCT agent_id), MIN(observed_at), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type IN ('process.crashed', 'process.hung') AND subject = $1 "
                "AND observed_at >= $2",
                std::vector<std::string>{process_name, since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            DexEntitySummary s;
            if (PQntuples(res.get()) > 0) {
                s.crashes = to_i64(PQgetvalue(res.get(), 0, 0));
                s.hangs = to_i64(PQgetvalue(res.get(), 0, 1));
                s.signals = to_i64(PQgetvalue(res.get(), 0, 2));
                s.distinct_devices = to_i64(PQgetvalue(res.get(), 0, 3));
                s.distinct_apps = 1;
                s.first_seen = text_col(res.get(), 0, 4);
                s.last_seen = text_col(res.get(), 0, 5);
            }
            return s;
        });
}

std::vector<DexModuleCrashCount>
GuaranteedStateStore::dex_app_modules(const std::string& process_name, const std::string& since,
                                      int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexModuleCrashCount>>(
        open_, pool_, metrics_, "dex_app_modules", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexModuleCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT component, COUNT(*), COUNT(DISTINCT subject) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND subject = $1 AND observed_at >= $2 "
                "GROUP BY component ORDER BY COUNT(*) DESC, component ASC LIMIT $3::bigint",
                std::vector<std::string>{process_name, since,
                                         std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexModuleCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexModuleCrashCount m;
                m.component = text_col(res.get(), i, 0);
                m.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                m.distinct_apps = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(m));
            }
            return out;
        });
}

std::vector<DexExceptionCount>
GuaranteedStateStore::dex_app_exceptions(const std::string& process_name, const std::string& since,
                                         int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexExceptionCount>>(
        open_, pool_, metrics_, "dex_app_exceptions", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexExceptionCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT reason, symbolic, COUNT(*) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND subject = $1 AND observed_at >= $2 "
                "GROUP BY reason, symbolic ORDER BY COUNT(*) DESC, reason ASC LIMIT $3::bigint",
                std::vector<std::string>{process_name, since,
                                         std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexExceptionCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexExceptionCount e;
                e.reason = text_col(res.get(), i, 0);
                e.symbolic = text_col(res.get(), i, 1);
                e.crashes = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(e));
            }
            return out;
        });
}

std::vector<DexDeviceCrashCount>
GuaranteedStateStore::dex_app_devices(const std::string& process_name, const std::string& since,
                                      int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<DexDeviceCrashCount>>(
        open_, pool_, metrics_, "dex_app_devices", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<DexDeviceCrashCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT agent_id, COUNT(*), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE obs_type = 'process.crashed' AND subject = $1 AND observed_at >= $2 "
                "GROUP BY agent_id ORDER BY COUNT(*) DESC, agent_id ASC LIMIT $3::bigint",
                std::vector<std::string>{process_name, since,
                                         std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<DexDeviceCrashCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                DexDeviceCrashCount d;
                d.agent_id = text_col(res.get(), i, 0);
                d.crashes = to_i64(PQgetvalue(res.get(), i, 1));
                d.last_seen = text_col(res.get(), i, 2);
                out.push_back(std::move(d));
            }
            return out;
        });
}

DexEntitySummary GuaranteedStateStore::dex_device_summary(const std::string& agent_id,
                                                          const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<DexEntitySummary>(
        open_, pool_, metrics_, "dex_device_summary", sampler,
        [&](PGconn* conn) -> std::optional<DexEntitySummary> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT COUNT(*) FILTER (WHERE obs_type = 'process.crashed'), "
                "COUNT(*) FILTER (WHERE obs_type = 'process.hung'), COUNT(*), "
                "COUNT(DISTINCT CASE WHEN obs_type IN ('process.crashed', 'process.hung') "
                "THEN subject END), MIN(observed_at), MAX(observed_at) "
                "FROM guaranteed_state_store.guardian_observations "
                "WHERE agent_id = $1 AND observed_at >= $2",
                std::vector<std::string>{agent_id, since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            DexEntitySummary s;
            if (PQntuples(res.get()) > 0) {
                s.crashes = to_i64(PQgetvalue(res.get(), 0, 0));
                s.hangs = to_i64(PQgetvalue(res.get(), 0, 1));
                s.signals = to_i64(PQgetvalue(res.get(), 0, 2));
                s.distinct_apps = to_i64(PQgetvalue(res.get(), 0, 3));
                s.distinct_devices = 1;
                s.first_seen = text_col(res.get(), 0, 4);
                s.last_seen = text_col(res.get(), 0, 5);
            }
            return s;
        });
}

std::vector<GuardianObservationRow>
GuaranteedStateStore::dex_device_history(const std::string& agent_id, const std::string& since,
                                         int limit) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<GuardianObservationRow>>(
        open_, pool_, metrics_, "dex_device_history", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<GuardianObservationRow>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT event_id, agent_id, observed_at, obs_type, subject, reason, symbolic, "
                "component, metric, platform FROM guaranteed_state_store.guardian_observations "
                "WHERE agent_id = $1 AND observed_at >= $2 ORDER BY observed_at DESC, "
                "event_id DESC LIMIT $3::bigint",
                std::vector<std::string>{agent_id, since,
                                         std::to_string(std::clamp(limit, 0, kMaxEventsLimit))});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<GuardianObservationRow> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i)
                out.push_back(read_observation_row(res.get(), i, /*has_version=*/false));
            return out;
        });
}

std::optional<GuardianObservationRow>
GuaranteedStateStore::dex_observation(const std::string& event_id) const {
    static DegradeSampler sampler;
    if (event_id.empty())
        return std::nullopt;
    // Single-object read stays plain optional (not a catastrophic-set read):
    // a store fault and a genuine not-found are both surfaced as nullopt to
    // the caller, but the degrade path IS counted+logged (below) so the loss
    // is visible on /metrics — matching the ADR-0038 "deferred widening"
    // posture for every non-catastrophic read.
    if (!open_) {
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("GuaranteedStateStore::dex_observation: store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kDexReadTimeout);
    if (!lease) {
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("GuaranteedStateStore::dex_observation: pool acquire timed out");
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT event_id, agent_id, observed_at, obs_type, subject, reason, symbolic, "
        "component, metric, platform FROM guaranteed_state_store.guardian_observations "
        "WHERE event_id = $1 LIMIT 1",
        std::vector<std::string>{event_id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("GuaranteedStateStore::dex_observation: query failed: {}",
                         PQresultErrorMessage(res.get()));
        return std::nullopt;
    }
    if (PQntuples(res.get()) == 0)
        return std::nullopt; // genuine not-found, not a degrade
    return read_observation_row(res.get(), 0, /*has_version=*/false);
}

std::vector<GuardianRuleActivity>
GuaranteedStateStore::rule_activity(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<GuardianRuleActivity>>(
        open_, pool_, metrics_, "rule_activity", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<GuardianRuleActivity>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT rule_id, "
                "COUNT(*) FILTER (WHERE event_type = 'drift.detected'), "
                "COUNT(*) FILTER (WHERE event_type = 'drift.remediated'), "
                "COUNT(*) FILTER (WHERE event_type = 'remediation.failed'), "
                "COUNT(*) FILTER (WHERE event_type = 'guard.unhealthy'), "
                "COUNT(DISTINCT agent_id), MAX(timestamp) "
                "FROM guaranteed_state_store.guaranteed_state_events "
                "WHERE ($1 = '' OR timestamp >= $1) GROUP BY rule_id",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<GuardianRuleActivity> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                GuardianRuleActivity a;
                a.rule_id = text_col(res.get(), i, 0);
                a.detected = to_i64(PQgetvalue(res.get(), i, 1));
                a.remediated = to_i64(PQgetvalue(res.get(), i, 2));
                a.failed = to_i64(PQgetvalue(res.get(), i, 3));
                a.unhealthy = to_i64(PQgetvalue(res.get(), i, 4));
                a.distinct_agents = to_i64(PQgetvalue(res.get(), i, 5));
                a.last_activity = text_col(res.get(), i, 6);
                out.push_back(std::move(a));
            }
            return out;
        });
}

std::vector<GuardianDayCount>
GuaranteedStateStore::daily_remediations(const std::string& since) const {
    static DegradeSampler sampler;
    return dex_read<std::vector<GuardianDayCount>>(
        open_, pool_, metrics_, "daily_remediations", sampler,
        [&](PGconn* conn) -> std::optional<std::vector<GuardianDayCount>> {
            pg::PgResult res = pg::exec_params(
                conn,
                "SELECT substr(timestamp, 1, 10) AS day, "
                "COUNT(*) FILTER (WHERE event_type = 'drift.remediated'), "
                "COUNT(*) FILTER (WHERE event_type = 'remediation.failed') "
                "FROM guaranteed_state_store.guaranteed_state_events "
                "WHERE ($1 = '' OR timestamp >= $1) "
                "AND event_type IN ('drift.remediated', 'remediation.failed') "
                "GROUP BY day ORDER BY day",
                std::vector<std::string>{since});
            if (res.status() != PGRES_TUPLES_OK)
                return std::nullopt;
            std::vector<GuardianDayCount> out;
            const int n = PQntuples(res.get());
            out.reserve(static_cast<std::size_t>(n));
            for (int i = 0; i < n; ++i) {
                GuardianDayCount d;
                d.day = text_col(res.get(), i, 0);
                d.remediated = to_i64(PQgetvalue(res.get(), i, 1));
                d.failed = to_i64(PQgetvalue(res.get(), i, 2));
                out.push_back(std::move(d));
            }
            return out;
        });
}

// ── Status + name lookups (ADR-0038 catastrophic-read set) ───────────────────

std::expected<std::vector<GuardianAgentRuleStatus>, std::string>
GuaranteedStateStore::agent_rule_statuses(const std::string& rule_id) const {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    std::string sql =
        "SELECT agent_id, rule_id, state, updated_at FROM "
        "guaranteed_state_store.guardian_agent_rule_status";
    std::vector<std::string> params;
    if (!rule_id.empty()) {
        sql += " WHERE rule_id = $1"; // idx_gars_rule covers this for the drill-down
        params.push_back(rule_id);
    }
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    std::vector<GuardianAgentRuleStatus> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        GuardianAgentRuleStatus r;
        r.agent_id = text_col(res.get(), i, 0);
        r.rule_id = text_col(res.get(), i, 1);
        r.state = text_col(res.get(), i, 2);
        r.updated_at = text_col(res.get(), i, 3);
        out.push_back(std::move(r));
    }
    return out;
}

std::expected<std::vector<GuardianAgentRuleStatus>, std::string>
GuaranteedStateStore::agent_rule_statuses_for_agent(const std::string& agent_id) const {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    // Rides the (agent_id, rule_id) PK auto-index (agent_id leading).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, rule_id, state, updated_at FROM "
        "guaranteed_state_store.guardian_agent_rule_status WHERE agent_id = $1",
        std::vector<std::string>{agent_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    std::vector<GuardianAgentRuleStatus> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        GuardianAgentRuleStatus r;
        r.agent_id = text_col(res.get(), i, 0);
        r.rule_id = text_col(res.get(), i, 1);
        r.state = text_col(res.get(), i, 2);
        r.updated_at = text_col(res.get(), i, 3);
        out.push_back(std::move(r));
    }
    return out;
}

std::expected<std::unordered_map<std::string, std::string>, std::string>
GuaranteedStateStore::rule_names() const {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT rule_id, name FROM guaranteed_state_store.guaranteed_state_rules",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    std::unordered_map<std::string, std::string> out;
    const int n = PQntuples(res.get());
    for (int i = 0; i < n; ++i)
        out.emplace(text_col(res.get(), i, 0), text_col(res.get(), i, 1));
    return out;
}

std::expected<std::unordered_map<std::string, std::string>, std::string>
GuaranteedStateStore::rule_names_for(const std::vector<std::string>& rule_ids) const {
    std::unordered_map<std::string, std::string> out;
    if (rule_ids.empty())
        return out; // success, not degrade
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    // CHUNKED at 500 ids per statement (mirrors the SQLite original) — a
    // Baseline whose deployed-snapshot is very large cannot make one giant
    // IN-list statement time out or exceed a param-count limit.
    constexpr std::size_t kChunk = 500;
    for (std::size_t base = 0; base < rule_ids.size(); base += kChunk) {
        const std::size_t n = std::min(kChunk, rule_ids.size() - base);
        std::string sql =
            "SELECT rule_id, name FROM guaranteed_state_store.guaranteed_state_rules WHERE "
            "rule_id IN (";
        std::vector<std::string> params;
        params.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            sql += (i == 0 ? "$" : ",$") + std::to_string(i + 1);
            params.push_back(rule_ids[base + i]);
        }
        sql += ")";
        pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
        if (res.status() != PGRES_TUPLES_OK)
            return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
        const int rows = PQntuples(res.get());
        for (int i = 0; i < rows; ++i)
            out.emplace(text_col(res.get(), i, 0), text_col(res.get(), i, 1));
    }
    return out;
}

std::size_t GuaranteedStateStore::rule_count() const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT COUNT(*) FROM guaranteed_state_store.guaranteed_state_rules", std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return 0;
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

std::size_t GuaranteedStateStore::event_count() const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT COUNT(*) FROM guaranteed_state_store.guaranteed_state_events", std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return 0;
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

// ── Retention reaper (#2496 gc_sweep shape, ADR-0038) ─────────────────────────

void GuaranteedStateStore::reap_expired() {
    if (!open_)
        return;
    const auto record_result = [this](const char* result) {
        if (metrics_)
            metrics_->counter("yuzu_server_guardian_reap_passes_total", {{"result", result}}).increment();
    };

    int64_t events_deleted = 0;
    int64_t observations_deleted = 0;
    std::string outcome = "failed";
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // One sweeping replica at a time.
        pg::PgResult lk = pg::exec_params(
            conn,
            "SELECT pg_try_advisory_xact_lock(hashtextextended("
            "'guaranteed_state_store:reap', 0))",
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            spdlog::error("GuaranteedStateStore::reap_expired: lock probe failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        if (!to_bool(PQgetvalue(lk.get(), 0, 0))) {
            outcome = "skipped_lock";
            return true;
        }

        const int64_t now = now_epoch();

        pg::PgResult meta = pg::exec_params(
            conn,
            "SELECT key, value FROM guaranteed_state_store.gc_meta WHERE key IN "
            "('last_pass_now','last_anomaly_facts')",
            std::vector<std::string>{});
        if (meta.status() != PGRES_TUPLES_OK) {
            spdlog::error("GuaranteedStateStore::reap_expired: meta read failed: {}",
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
            "INSERT INTO guaranteed_state_store.gc_meta (key, value) VALUES ('last_pass_now', "
            "$1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{std::to_string(now)});
        if (stamp.status() != PGRES_COMMAND_OK) {
            spdlog::error("GuaranteedStateStore::reap_expired: meta stamp failed: {}",
                          PQerrorMessage(conn));
            return false;
        }

        // Probe by OUTCOME against the parent events table — the observation
        // projection's ttl_expires_at always mirrors its parent event's (set
        // atomically at insert), so one probe/classify decision governs both
        // tables in this guarded pass (the lockstep invariant).
        pg::PgResult probe = pg::exec_params(
            conn,
            "SELECT count(*) FILTER (WHERE ttl_expires_at > 0 AND ttl_expires_at < $1::bigint) "
            "AS expiring, "
            "count(*) FILTER (WHERE ttl_expires_at > 0 AND ttl_expires_at <= $2::bigint) "
            "AS datable "
            "FROM guaranteed_state_store.guaranteed_state_events",
            std::vector<std::string>{std::to_string(now),
                                     std::to_string(now + kReapImplausiblyAheadSecs)});
        if (probe.status() != PGRES_TUPLES_OK) {
            spdlog::error("GuaranteedStateStore::reap_expired: probe failed: {}",
                          PQerrorMessage(conn));
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
                spdlog::warn("GuaranteedStateStore::reap_expired: retention clock anomaly ({} "
                             "facts={}) — declining this pass; an identical next pass will "
                             "drain, capped",
                             static_cast<int>(anomaly), facts_ser);
                pg::PgResult rec = pg::exec_params(
                    conn,
                    "INSERT INTO guaranteed_state_store.gc_meta (key, value) VALUES "
                    "('last_anomaly_facts', $1) ON CONFLICT (key) DO UPDATE SET value = "
                    "EXCLUDED.value",
                    std::vector<std::string>{facts_ser});
                if (rec.status() != PGRES_COMMAND_OK) {
                    spdlog::error("GuaranteedStateStore::reap_expired: anomaly record failed: {}",
                                  PQerrorMessage(conn));
                    return false;
                }
                outcome = "declined";
                return true;
            }
            // Suppressed repeat of the SAME fact set — condition already
            // reported; proceed with the (capped) drain below.
        } else if (!last_facts.empty()) {
            pg::PgResult clr = pg::exec_params(
                conn, "DELETE FROM guaranteed_state_store.gc_meta WHERE key = 'last_anomaly_facts'",
                std::vector<std::string>{});
            if (clr.status() != PGRES_COMMAND_OK) {
                spdlog::error("GuaranteedStateStore::reap_expired: anomaly clear failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
        }
        if (expiring == 0) {
            outcome = "noop";
            return true;
        }

        // Lockstep: events AND observations reaped in the SAME guarded pass —
        // the PII projection must never outlive its parent event. Unconditional
        // per-pass cap on each (substrate-tuned: 10x ResultSetStore's cap for
        // this store's documented up-to-10k-events/s incident write volume).
        pg::PgResult ev = pg::exec_params(
            conn,
            "DELETE FROM guaranteed_state_store.guaranteed_state_events WHERE event_id IN ("
            "SELECT event_id FROM guaranteed_state_store.guaranteed_state_events "
            "WHERE ttl_expires_at > 0 AND ttl_expires_at < $1::bigint "
            "ORDER BY ttl_expires_at ASC LIMIT $2::bigint) RETURNING event_id",
            std::vector<std::string>{std::to_string(now), std::to_string(kReapCapPerPass)});
        if (ev.status() != PGRES_TUPLES_OK) {
            spdlog::error("GuaranteedStateStore::reap_expired: events delete failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        events_deleted = PQntuples(ev.get());

        pg::PgResult obs = pg::exec_params(
            conn,
            "DELETE FROM guaranteed_state_store.guardian_observations WHERE event_id IN ("
            "SELECT event_id FROM guaranteed_state_store.guardian_observations "
            "WHERE ttl_expires_at > 0 AND ttl_expires_at < $1::bigint "
            "ORDER BY ttl_expires_at ASC LIMIT $2::bigint) RETURNING event_id",
            std::vector<std::string>{std::to_string(now), std::to_string(kReapCapPerPass)});
        if (obs.status() != PGRES_TUPLES_OK) {
            spdlog::error("GuaranteedStateStore::reap_expired: observations delete failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        observations_deleted = PQntuples(obs.get());
        outcome = "swept";
        return true;
    });

    if (!ok) {
        record_result("failed");
        spdlog::error("GuaranteedStateStore::reap_expired: pass aborted (statement failed or "
                      "txn rolled back — see the preceding error line)");
        return;
    }
    if (events_deleted > 0)
        events_reaped_.fetch_add(static_cast<uint64_t>(events_deleted), std::memory_order_relaxed);
    if (observations_deleted > 0)
        observations_reaped_.fetch_add(static_cast<uint64_t>(observations_deleted),
                                       std::memory_order_relaxed);
    record_result(outcome.c_str());
    if (events_deleted > 0 || observations_deleted > 0)
        spdlog::info("GuaranteedStateStore: reap swept {} event(s), {} observation(s)",
                     events_deleted, observations_deleted);
}

} // namespace yuzu::server
