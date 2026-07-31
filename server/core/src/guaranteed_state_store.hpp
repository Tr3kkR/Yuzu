#pragma once

/// @file guaranteed_state_store.hpp
/// Server-side storage for Yuzu Guardian — the "Guaranteed State" system.
/// Migrated to PostgreSQL (ADR-0006/0008/0009/0038, schema
/// `guaranteed_state_store`); was `guaranteed-state.db` (SQLite). See
/// docs/yuzu-guardian-design-v1.1.md §9.1 for the schema design and
/// docs/adr/0038-guaranteed-state-store-postgres-migration.md for the
/// migration's posture decisions (this header follows that ADR verbatim).
///
/// Responsibilities:
///   - Persist GuaranteedStateRule definitions (yaml_source is authoritative;
///     the denormalised columns are for indexing / listing / RBAC filtering).
///     Caller (REST handler) is responsible for deriving the denormalised
///     fields (severity / os_target / scope_expr) from yaml_source atomically
///     on create/update — the store does NOT re-parse.
///   - Persist GuaranteedStateEvent rows reported by agents (drift detected,
///     drift remediated, guard unhealthy, resilience escalated, etc.).
///   - Reap expired events + their DEX projection via `reap_expired()`, called
///     from the server's maintenance tick (the #2496 `gc_sweep` clock-guarded
///     shape — see the .cpp) so multi-GB/day ingest during a fleet-wide
///     incident does not grow the database unbounded.
///
/// Events are an **immutable audit-style log** — intentionally no foreign key
/// from `guaranteed_state_events.rule_id` to `guaranteed_state_rules(rule_id)`.
/// When a rule is deleted, its historical events remain for forensic review.
/// Time-based expiry is the single retention mechanism.
///
/// ── Posture (ADR-0012 §1 / ADR-0038), split by table family ─────────────────
///  - **Rules + meta reads — AUTHORITATIVE, type-distinguishable** (the
///    catastrophic read): `list_rules` / `rule_names` / `rule_names_for`
///    return `std::expected<std::vector<T>, std::string>`; `get_rule` keeps a
///    three-state `std::expected<std::optional<Row>, GuaranteedStateReadError>`
///    (found / genuinely-absent / degraded — mirrors
///    `DeviceInventoryStore::CiReadError`). `agent_rule_statuses` /
///    `agent_rule_statuses_for_agent` (enforce-gate/census input) are the same
///    `std::expected<std::vector<T>, std::string>` shape. A degraded read
///    collapsing to silent empty would push an EMPTY rule set to the fleet —
///    a Guardian-wide disarm — so every push/reconcile consumer MUST abort
///    (503 / no-op push) on `!result`, never fan out an empty container it
///    cannot distinguish from "no rules configured".
///  - **Rule/meta writes — fail-hard**: `create_rule`/`update_rule`/
///    `delete_rule` stay `std::expected<void, std::string>`, surfaced to the
///    REST caller. `bump_policy_generation` is one atomic
///    `UPDATE ... RETURNING` (cross-process state on Postgres; the SQLite
///    read-modify-write idiom does not port).
///  - **Event/observation ingest — FAIL-SOFT** (mirrors ADR-0037 ingest): a
///    dropped enforcement-history row is re-derivable from the agent's next
///    report cycle; ingest must never block the gRPC thread. Infra-level
///    drops (pool exhaustion / lease timeout / BEGIN-prepare-exec-commit
///    failure) bump `yuzu_server_guardian_ingest_dropped_total{reason}` (ADR-0037
///    label convention) IN ADDITION to the existing four-way
///    `EventInsertOutcome` classification + its per-outcome atomics below.
///  - **Status upserts — fail-soft with the same counter**; status READS stay
///    type-distinguishable (see above).
///  - **DEX analytic reads — deferred widening (ADR-0038, follow-up #2659).**
///    The ~20 `dex_*` aggregate reads plus `query_events` / `rule_activity` /
///    `daily_remediations` / `query_observations` KEEP their plain
///    `std::vector<T>` / value-type signatures this PR (empty-on-degrade,
///    behavior-identical to the SQLite store) — the `std::optional` widening
///    fans out to ~68 call sites across 5 consumer files and is tracked as a
///    follow-up (#2659), amendable per-file. What THIS PR lands at the store
///    seam: every such read counts+logs a degrade via
///    `yuzu_server_guardian_read_degrade_total{reason}` + a sampled `DegradeSampler`
///    warn on store-not-open / lease-timeout / query-error, so the silent
///    empty is at least visible on `/metrics` even though the return type
///    does not yet distinguish it. None of these reads feeds an
///    enforce/target decision (playbook's deny-or-benign class).

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

// Reserved sentinel rule_id marking a RULELESS DEX observation (no live rule).
// Single server-side source of truth — `is_reserved_rule_id` (the projection +
// census guard) and `ingest_guardian_response` (the blast-radius feed gate)
// both reference this, so a rename can't silently desync the two paths
// (gov architect/consistency). MUST stay equal to the agent's
// `kObservationRuleSentinel` (agents/core .../dex_event.hpp) — different binary,
// shared wire convention.
inline constexpr const char* kObservationRuleId = "__observation__";

struct GuaranteedStateRuleRow {
    std::string rule_id;           // UUID
    std::string name;              // unique, human-authored
    std::string yaml_source;       // human-readable rendering (generated; see spec_json)
    // Canonical structured JSON of the Guard (spark/assertion/remediation) —
    // the AUTHORITATIVE form the agent enforces from and that the push proto is
    // built from. yaml_source is rendered one-way from this.
    std::string spec_json;
    // RESERVED (stored, not yet evaluated): the Guard's Prerequisites — a Scope
    // expression over device facts that must hold for the Guard to apply on a
    // device, finer than a Baseline's management-group assignment.
    std::string prerequisites;
    int64_t version{1};
    bool enabled{true};
    std::string enforcement_mode;  // "enforce" | "audit" (validated at the REST boundary; `enabled` controls disable)
    std::string severity;          // "critical" | "high" | "medium" | "low"
    std::string os_target;         // "windows" | "linux" | "macos" | ""=all
    std::string scope_expr;        // server-side scope expression
    std::vector<uint8_t> signature;// HMAC-SHA256 over yaml_source
    std::string created_at;        // ISO-8601
    std::string updated_at;        // ISO-8601
    // Principal who authored the rule (created_by) and who last modified it
    // (updated_by). Required for SOC 2 audit-chain reconstruction alongside
    // audit_events — the REST handler populates both from the session
    // principal; the store is a plain passthrough.
    std::string created_by;
    std::string updated_by;
};

struct GuaranteedStateEventRow {
    std::string event_id;          // UUID
    std::string rule_id;
    std::string agent_id;
    std::string event_type;        // "drift.detected" | "drift.remediated" | ...
    std::string severity;
    std::string guard_type;        // "registry" | "etw" | ...
    std::string guard_category;    // "event" | "condition"
    std::string detected_value;
    std::string expected_value;
    // Structured, machine-readable detail (JSON, keyed by event_type). Companion
    // to the human `detected_value`, not a replacement. For DEX observations
    // (process.crashed) it carries the projectable crash facts; "" for plain
    // drift. The DEX read model projects this into indexed columns.
    std::string detail_json;
    std::string remediation_action;
    bool remediation_success{false};
    int64_t detection_latency_us{0};
    int64_t remediation_latency_us{0};
    std::string timestamp;         // ISO-8601
};

struct GuaranteedStateEventQuery {
    std::string rule_id;           // filter by rule, optional
    std::string agent_id;          // filter by agent, optional
    std::string severity;          // "critical" ... optional
    int limit{100};                // clamped to [1, kMaxEventsLimit] by the store
    int offset{0};
};

// ── Overview aggregation result types (Slice A dashboard overview) ───────────
struct GuardianRuleActivity {
    std::string rule_id;
    int64_t detected{0};        // drift.detected
    int64_t remediated{0};      // drift.remediated
    int64_t failed{0};          // remediation.failed
    int64_t unhealthy{0};       // guard.unhealthy
    int64_t distinct_agents{0}; // distinct agents with any event in the window
    std::string last_activity;  // max timestamp in window ("" if none)
};

struct GuardianDayCount {
    std::string day;        // YYYY-MM-DD
    int64_t remediated{0};
    int64_t failed{0};
};

struct GuardianAgentRuleStatus {
    std::string agent_id;
    std::string rule_id;
    std::string state;       // "compliant" | "drifted" | "errored"
    std::string updated_at;  // ISO-8601 of the event that set it
};

struct GuardianObservationRow {
    std::string event_id;          // shares the event journal dedup key
    std::string agent_id;
    std::string observed_at;       // ISO-8601 (= event timestamp)
    std::string obs_type;          // = event_type, e.g. "process.crashed", "os.boot"
    std::string subject;           // e.g. "notepad.exe", "Spooler", "HP LaserJet"
    std::string reason;            // e.g. "0xC0000005", "0x80070643", "timeout"
    std::string symbolic;          // e.g. "ACCESS_VIOLATION", "WIFI_DISCONNECT"
    std::string component;         // e.g. "ntdll.dll" (faulting module)
    std::string version;           // crashed/hung app's file version "a.b.c.d", "" if unknown
    double metric{0.0};            // numeric payload (boot duration ms); 0 = none
    std::string platform;          // "windows" | "linux" | "macos"
};

// ── DEX read-model aggregations over guardian_observations ───────────────────
struct DexCrashSummary {
    int64_t total_crashes{0};
    int64_t distinct_devices{0};   // devices impacted (crash-free numerator)
    int64_t distinct_apps{0};
};
struct DexAppCrashCount {          // top unreliable apps + blast radius
    std::string subject;           // process name
    std::string version;           // app file version, "" = unknown/all (version-blind query)
    int64_t crashes{0};
    int64_t hangs{0};
    int64_t distinct_devices{0};   // blast radius = distinct devices, not event count
    std::string last_seen;
};
struct DexModuleCrashCount {       // top faulting modules (crash-scoped)
    std::string component;         // module name
    int64_t crashes{0};
    int64_t distinct_apps{0};
};
struct DexDeviceCrashCount {       // most-affected devices (crash-scoped)
    std::string agent_id;
    int64_t crashes{0};
    std::string last_seen;
};
struct DexOsCrashCount {           // per-OS split (coverage-normalised at the route)
    std::string platform;
    int64_t crashes{0};
    int64_t distinct_devices{0};
};
struct DexDayCrashCount {          // crashes-per-day trend
    std::string day;               // YYYY-MM-DD
    int64_t crashes{0};
};
struct DexExceptionCount {         // top failure reasons (per-app drill-down)
    std::string reason;            // e.g. "0xC0000005"
    std::string symbolic;          // e.g. "ACCESS_VIOLATION"
    int64_t crashes{0};
};
struct DexEntitySummary {          // per-app / per-device drill-down summary
    int64_t crashes{0};
    int64_t hangs{0};
    int64_t signals{0};            // ALL observation rows for the entity (any type)
    int64_t distinct_devices{0};
    int64_t distinct_apps{0};
    std::string first_seen;
    std::string last_seen;
};
struct DexSignalCount {            // the whole-catalogue rollup (overview panel)
    std::string obs_type;
    int64_t count{0};
    int64_t distinct_devices{0};
    std::string last_seen;
};
struct DexSubjectCount {           // top subjects for ONE obs_type (signal drill-down)
    std::string subject;
    int64_t count{0};
    int64_t distinct_devices{0};
    std::string last_seen;
};
struct DexOsScope {                // per-OS coverage: how many types each OS collects
    std::string platform;
    int64_t distinct_types{0};
    int64_t total_events{0};
};
struct DexDaySignal {              // one (day, obs_type) cell of the trends matrix
    std::string day;               // YYYY-MM-DD
    std::string obs_type;
    int64_t count{0};
};
struct DexBootStats {              // boot-performance rollup (os.boot metric, ms)
    int64_t boots{0};
    double avg_ms{0.0};
    double max_ms{0.0};
    int64_t distinct_devices{0};
};
struct DexDeviceBoot {             // slowest-booting devices
    std::string agent_id;
    double avg_ms{0.0};
    double max_ms{0.0};
    int64_t boots{0};
};

// Hard upper bound on `GuaranteedStateEventQuery::limit` and every DEX
// `limit` parameter. Defence-in-depth: materialising millions of rows into a
// std::vector would produce a GB-scale RSS spike.
inline constexpr int kMaxEventsLimit = 10'000;

// Default retention for `guaranteed_state_events` (+ its lockstep
// `guardian_observations` projection). 30 days matches `audit_store`.
// Override via the GuaranteedStateStore constructor.
inline constexpr int kDefaultEventRetentionDays = 30;

// Outcome of a single-event ingest. The agent journal re-sends on every
// reconnect, so a matching-fields event_id redelivery is EXPECTED + idempotent
// — it must be quiet and counted apart from a genuine collision (same
// event_id but MISMATCHED immutable fields). Ingest runs the DEX blast-radius
// + alert observers ONLY on `Inserted`; Redelivered / Conflict / Error all
// return before the observers.
enum class EventInsertOutcome { Inserted, Redelivered, Conflict, Error };
struct EventInsertResult {
    EventInsertOutcome outcome{EventInsertOutcome::Error};
    std::string error; // set for Conflict (mismatch detail) + Error (db message); empty otherwise
};

// Error surface for the type-distinguishable single-object read (`get_rule`).
// The success type is `std::optional<GuaranteedStateRuleRow>`: a value ==
// found, `std::nullopt` == genuinely no row for this rule_id.
// `std::unexpected(kDegraded)` == store/pool/query failure — the caller shows
// a degrade banner/503, never treats it as absent (mirrors
// `DeviceInventoryStore::CiReadError` / `InventoryReadError` exactly).
enum class GuaranteedStateReadError { kDegraded };

class GuaranteedStateStore {
public:
    /// Borrows the shared pool and runs the `guaranteed_state_store` schema
    /// migration on a pinned lease. `is_open()` is false if the lease was
    /// empty or the migration failed.
    explicit GuaranteedStateStore(pg::PgPool& pool,
                                   int retention_days = kDefaultEventRetentionDays);

    GuaranteedStateStore(const GuaranteedStateStore&) = delete;
    GuaranteedStateStore& operator=(const GuaranteedStateStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for `yuzu_server_guardian_read_degrade_total{reason}`
    /// (DEX/analytics reads) and `yuzu_server_guardian_ingest_dropped_total{reason}`
    /// (fail-soft ingest) and the reap-pass counter. Set ONCE during
    /// single-threaded startup, before serving — the pointer is read without
    /// synchronisation on serving threads. A null registry (default, e.g.
    /// unit tests) disables emission; every emit site is null-guarded.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// One-time, idempotent legacy-SQLite backfill (ADR-0009/0038). Call once
    /// at server startup, before serving, after construction proved the
    /// Postgres schema is open. All FIVE tables (rules, guardian_meta,
    /// guardian_agent_rule_status, guaranteed_state_events,
    /// guardian_observations) in ONE transaction, idempotent via a dedicated
    /// `sqlite_backfill` marker row (never row-count-inferred — the reaper
    /// legitimately empties the event/observation tables over the store's
    /// lifetime). Per-row SAVEPOINT + SQLSTATE discrimination exactly as
    /// ADR-0037 settled it (22xxx/23xxx/54xxx = skip + counted in
    /// `skipped_bad`; anything else aborts UNSTAMPED — the next boot
    /// retries). TTL-expired legacy event/observation rows are skipped AT
    /// SCAN TIME (never migrated-then-reaped). FAILS CLOSED on any
    /// infrastructure error (initial connection, the backfill transaction's
    /// own BEGIN/SAVEPOINT/COMMIT, a non-row-data SQLSTATE, or a failed
    /// ROLLBACK TO SAVEPOINT) — the caller MUST treat `false` as fatal
    /// (`startup_failed_ = true` in server.cpp), same as `!is_open()`.
    [[nodiscard]] bool migrate_from_sqlite(const std::filesystem::path& legacy_db_path);

    // Rule CRUD. Mutating methods return `std::expected<void, std::string>`
    // (fail-hard — ADR-0038 posture). Duplicate-UNIQUE collisions (name or
    // rule_id) are reported as an error prefixed with `kConflictPrefix` so
    // REST handlers map them to HTTP 409 (see `store_errors.hpp`).
    std::expected<void, std::string> create_rule(const GuaranteedStateRuleRow& row);
    std::expected<void, std::string> update_rule(const GuaranteedStateRuleRow& row);
    std::expected<void, std::string> delete_rule(const std::string& rule_id);
    /// Three-state read (ADR-0038 catastrophic-read set): found / genuinely
    /// absent (`std::nullopt`) / degraded (`std::unexpected`). Callers MUST
    /// treat a degrade as "cannot verify" (503), never as "not found" (404).
    std::expected<std::optional<GuaranteedStateRuleRow>, GuaranteedStateReadError>
    get_rule(const std::string& rule_id) const;
    /// AUTHORITATIVE, type-distinguishable (ADR-0038 catastrophic-read set):
    /// `std::unexpected` on a store/pool/query degrade, NEVER a silent empty
    /// vector — the Push fan-out / reconcile / baseline-deploy consumers MUST
    /// abort (503 / no-op push) on `!result`, never fan out an empty set they
    /// cannot distinguish from "no rules configured".
    std::expected<std::vector<GuaranteedStateRuleRow>, std::string> list_rules() const;

    // Event ingest + query. FAIL-SOFT (ADR-0038): a lease/query/transaction
    // failure is logged + counted (`yuzu_server_guardian_ingest_dropped_total` +
    // `events_ingest_errors_total()`), never throws, never blocks the caller.
    //
    // insert_event_classified() is the primary ingest entry point: it returns the
    // four-way EventInsertResult so the caller gates DEX observers on `Inserted`,
    // treats a matching `Redelivered` as a quiet idempotent no-op, and keeps a
    // mismatched `Conflict` on the loud CC7.3 drop metric. insert_event() is the
    // back-compat convenience wrapper (Inserted/Redelivered -> ok; Conflict/Error ->
    // unexpected) for callers that don't distinguish redelivery (tests, batch seed).
    // [[nodiscard]]: the four-way outcome is what the caller gates the DEX observers on
    // (only `Inserted` may run them).
    [[nodiscard]] EventInsertResult insert_event_classified(const GuaranteedStateEventRow& row);
    std::expected<void, std::string> insert_event(const GuaranteedStateEventRow& row);

    /// Batch ingest: wraps all rows in a single transaction. On failure, the
    /// whole batch is rolled back — see the HARD CONSTRAINT note on the .cpp
    /// definition (no live caller today; must not be used for redelivery-prone
    /// ingress).
    std::expected<std::size_t, std::string>
    insert_events(const std::vector<GuaranteedStateEventRow>& rows);

    // ── DEX / analytics reads (ADR-0038 "deferred widening", #2659) ──────────
    // Plain value-type returns, empty-on-degrade — behavior-identical to the
    // SQLite store. Every degrade path (store not open / lease timeout / query
    // error) counts `yuzu_server_guardian_read_degrade_total{reason}` + a sampled
    // warn log via the store-local DegradeSampler (see the .cpp), so the loss
    // is visible on /metrics even though the type does not yet distinguish it.

    std::vector<GuaranteedStateEventRow> query_events(const GuaranteedStateEventQuery& q = {}) const;

    std::vector<GuardianObservationRow> query_observations(int limit = kMaxEventsLimit) const;

    DexCrashSummary dex_crash_summary(const std::string& since = "",
                                      const std::string& platform = "") const;
    std::vector<DexAppCrashCount> dex_top_apps(const std::string& since = "", int limit = 20) const;
    std::vector<DexAppCrashCount> dex_device_top_apps(const std::string& agent_id,
                                                      const std::string& since = "",
                                                      int limit = 50) const;
    std::vector<DexModuleCrashCount> dex_top_modules(const std::string& since = "", int limit = 20) const;
    std::vector<DexDeviceCrashCount> dex_top_devices(const std::string& since = "", int limit = 20) const;
    std::vector<DexOsCrashCount> dex_crashes_by_os(const std::string& since = "") const;
    std::vector<DexDayCrashCount> dex_crashes_by_day(const std::string& since = "") const;
    std::vector<DexSignalCount> dex_signal_summary(const std::string& since = "",
                                                    const std::string& platform = "") const;
    DexBootStats dex_boot_stats(const std::string& since = "") const;
    std::vector<DexDeviceBoot> dex_slowest_boots(const std::string& since = "",
                                                 int limit = 10) const;

    std::vector<DexSubjectCount> dex_signal_subjects(const std::string& obs_type,
                                                     const std::string& since = "",
                                                     int limit = 20,
                                                     const std::string& platform = "") const;
    std::vector<DexOsCrashCount> dex_signal_by_os(const std::string& obs_type,
                                                  const std::string& since = "") const;
    std::vector<DexDeviceCrashCount> dex_signal_devices(const std::string& obs_type,
                                                        const std::string& since = "",
                                                        int limit = 20,
                                                        const std::string& platform = "") const;
    std::vector<DexDayCrashCount> dex_signal_by_day(const std::string& obs_type,
                                                    const std::string& since = "",
                                                    const std::string& platform = "") const;
    std::vector<DexOsScope> dex_os_signal_scope(const std::string& since = "") const;
    std::vector<DexDaySignal> dex_signal_day_matrix(const std::string& since = "") const;

    DexEntitySummary dex_app_summary(const std::string& process_name,
                                     const std::string& since = "") const;
    std::vector<DexModuleCrashCount> dex_app_modules(const std::string& process_name,
                                                     const std::string& since = "",
                                                     int limit = 20) const;
    std::vector<DexExceptionCount> dex_app_exceptions(const std::string& process_name,
                                                      const std::string& since = "",
                                                      int limit = 20) const;
    std::vector<DexDeviceCrashCount> dex_app_devices(const std::string& process_name,
                                                     const std::string& since = "",
                                                     int limit = 20) const;
    DexEntitySummary dex_device_summary(const std::string& agent_id,
                                        const std::string& since = "") const;
    std::vector<GuardianObservationRow> dex_device_history(const std::string& agent_id,
                                                           const std::string& since = "",
                                                           int limit = 100) const;
    std::optional<GuardianObservationRow> dex_observation(const std::string& event_id) const;
    std::vector<DexSignalCount> dex_device_signal_summary(const std::string& agent_id,
                                                          const std::string& since = "") const;

    std::vector<GuardianRuleActivity> rule_activity(const std::string& since = "") const;
    std::vector<GuardianDayCount> daily_remediations(const std::string& since = "") const;

    // ── Status + name lookups (ADR-0038 catastrophic-read set) ───────────────
    /// AUTHORITATIVE, type-distinguishable: feeds the enforce-gate/dashboard
    /// census — empty must stay distinguishable from "could not read".
    std::expected<std::vector<GuardianAgentRuleStatus>, std::string>
    agent_rule_statuses(const std::string& rule_id = "") const;
    std::expected<std::vector<GuardianAgentRuleStatus>, std::string>
    agent_rule_statuses_for_agent(const std::string& agent_id) const;

    /// rule_id -> name for the whole catalogue (Push/reconcile input set).
    std::expected<std::unordered_map<std::string, std::string>, std::string> rule_names() const;
    /// Bounded variant of rule_names(): resolve names ONLY for the given
    /// rule_ids. Empty input -> empty map (success, not degrade).
    std::expected<std::unordered_map<std::string, std::string>, std::string>
    rule_names_for(const std::vector<std::string>& rule_ids) const;

    std::size_t rule_count() const;
    std::size_t event_count() const;

    // Monotonic policy generation — the version stamp of the rule SET, bumped
    // atomically on every create/update/delete. Persisted (survives restart)
    // and strictly increasing.
    std::optional<uint64_t> current_policy_generation() const;

    // Bump the persisted policy generation WITHOUT mutating any rule (the
    // Baseline deploy path). Best-effort: logs on failure (mirrors the
    // original SQLite contract — callers do not currently consume a result).
    void bump_policy_generation();

    // Observability — lock-free cumulative counters for Prometheus scraping.
    uint64_t events_written_total() const noexcept { return events_written_.load(); }
    uint64_t events_reaped_total() const noexcept { return events_reaped_.load(); }
    uint64_t observations_proj_failures_total() const noexcept {
        return observations_proj_failures_.load();
    }
    uint64_t observations_reaped_total() const noexcept { return observations_reaped_.load(); }
    uint64_t events_dropped_total() const noexcept { return events_dropped_.load(); }
    uint64_t events_redelivered_total() const noexcept { return events_redelivered_.load(); }
    uint64_t events_ingest_errors_total() const noexcept { return events_ingest_errors_.load(); }

    /// Clock-guarded retention sweep (#2496 `gc_sweep` shape — ADR-0038,
    /// replaces the SQLite background cleanup thread). Called from the
    /// server's maintenance tick (~60-minute cadence, matching the old
    /// thread's default `cleanup_interval_min`). Reaps
    /// `guaranteed_state_events` AND its lockstep `guardian_observations`
    /// projection in the SAME guarded pass (the PII projection must never
    /// outlive its parent event). One sweeping replica at a time via
    /// `pg_try_advisory_xact_lock`; a durable `gc_meta` reading +
    /// anomaly-fact-set guards against a skewed wall clock mass-expiring
    /// live rows. Emits `yuzu_server_guardian_reap_passes_total{result=swept|noop|
    /// declined|failed|skipped_lock}`.
    void reap_expired();

private:
    pg::PgPool& pool_;
    bool open_{false};
    int retention_days_;
    yuzu::MetricsRegistry* metrics_{nullptr};

    std::atomic<uint64_t> events_written_{0};
    std::atomic<uint64_t> events_reaped_{0};
    std::atomic<uint64_t> observations_proj_failures_{0};
    std::atomic<uint64_t> observations_reaped_{0};
    std::atomic<uint64_t> events_dropped_{0};      // event_id conflict, MISMATCHED payload
    std::atomic<uint64_t> events_redelivered_{0};  // event_id conflict, MATCHING payload
    std::atomic<uint64_t> events_ingest_errors_{0}; // operational ingest fault

    // Compute ttl_expires_at = now + retention_days*86400 in epoch seconds;
    // retention_days <= 0 means "never expire" (returns 0, the sentinel the
    // reaper's `ttl_expires_at > 0` predicate excludes).
    int64_t compute_ttl_epoch() const;
};

} // namespace yuzu::server
