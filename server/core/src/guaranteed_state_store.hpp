#pragma once

#include <sqlite3.h>

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

namespace yuzu::server {

// Server-side storage for Yuzu Guardian — the "Guaranteed State" system.
// See docs/yuzu-guardian-design-v1.1.md §9.1 for the schema design.
//
// Responsibilities:
//   - Persist GuaranteedStateRule definitions (yaml_source is authoritative;
//     the denormalised columns are for indexing / listing / RBAC filtering).
//     Caller (REST handler in PR 2+) is responsible for deriving the
//     denormalised fields (severity / os_target / scope_expr) from
//     yaml_source atomically on create/update — the store does NOT re-parse.
//   - Persist GuaranteedStateEvent rows reported by agents (drift detected,
//     drift remediated, guard unhealthy, resilience escalated, etc.).
//   - Reap expired events via a background cleanup thread (mirrors
//     AuditStore) so multi-GB/day ingest during a fleet-wide incident does
//     not fill the data directory.
//
// Events are an **immutable audit-style log** — intentionally no foreign key
// from `guaranteed_state_events.rule_id` to `guaranteed_state_rules(rule_id)`.
// When a rule is deleted, its historical events remain for forensic review
// (matches `audit_store`'s retention discipline). Time-based expiry is the
// single retention mechanism — operators control lifetime with the
// `retention_days` constructor argument, not rule deletion cascades.
//
// This store is intentionally write-heavy on events and read-heavy on rules.
// SQLite full-mutex + WAL is the same pattern the other stores use.

struct GuaranteedStateRuleRow {
    std::string rule_id;           // UUID
    std::string name;              // unique, human-authored
    std::string yaml_source;       // human-readable rendering (generated; see spec_json)
    // Canonical structured JSON of the Guard (spark/assertion/remediation) — the
    // AUTHORITATIVE form the agent enforces from and that the push proto is built
    // from. yaml_source is rendered one-way from this. See
    // docs/guardian-mvp-contract.md decisions 1-2. Empty for pre-migration rows.
    std::string spec_json;
    // RESERVED (stored, not yet evaluated): the Guard's Prerequisites — a Scope
    // expression over device facts that must hold for the Guard to apply on a
    // device, finer than a Baseline's management-group assignment. Authoring +
    // live agent-side evaluation are engine-dependent and MVP-deferred (the
    // scope engine must become a shared server+agent lib first); see
    // docs/guardian-baseline-model.md. Empty for rules with no Prerequisites.
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
    // audit_events — the REST handler in PR 2 populates both from the
    // session principal; the store is a plain passthrough.
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
    // Structured, machine-readable detail (JSON, keyed by event_type; route a').
    // Companion to the human `detected_value`, not a replacement. For DEX
    // observations (process.crashed) it carries the projectable crash facts; "" for
    // plain drift. The DEX read model projects this into indexed columns.
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
// Per-rule event activity within a window — powers the per-Guard table + the
// fleet effectiveness rollup. Counts cover the supplied ISO-8601 `since` cutoff.
struct GuardianRuleActivity {
    std::string rule_id;
    int64_t detected{0};        // drift.detected
    int64_t remediated{0};      // drift.remediated
    int64_t failed{0};          // remediation.failed
    int64_t unhealthy{0};       // guard.unhealthy
    int64_t distinct_agents{0}; // distinct agents with any event in the window
    std::string last_activity;  // max timestamp in window ("" if none)
};

// One day's remediation outcomes — for the overview's 7-day trend.
struct GuardianDayCount {
    std::string day;        // YYYY-MM-DD
    int64_t remediated{0};
    int64_t failed{0};
};

// One agent's CURRENT compliance state for one rule (Slice B compliance census).
// Maintained by insert_event from the agent's on-change status feed (guard.compliant
// / drift.detected / drift.remediated / remediation.failed / guard.unhealthy). The
// route folds in agent liveness (offline → "unknown") at query time — this row is the
// last state the agent REPORTED, not a live probe.
struct GuardianAgentRuleStatus {
    std::string agent_id;
    std::string rule_id;
    std::string state;       // "compliant" | "drifted" | "errored"
    std::string updated_at;  // ISO-8601 of the event that set it
};

// One DEX observation projected from a ruleless signal event (the
// guardian_observations read model). DERIVED from guaranteed_state_events: written
// atomically with the event so it inherits the event_id dedup, reaped in lockstep.
// Promotes the detail_json UNIFORM facts into queryable columns the DEX
// aggregations GROUP BY. Column semantics are generic across the 103-signal
// catalogue (docs/dex-signal-catalog.md): subject = the failing entity (app,
// service, printer, update title, SSID…), reason = failure code, component =
// secondary entity (faulting module, NIC…), metric = numeric payload (boot ms).
struct GuardianObservationRow {
    std::string event_id;          // shares the event journal dedup key
    std::string agent_id;
    std::string observed_at;       // ISO-8601 (= event timestamp)
    std::string obs_type;          // = event_type, e.g. "process.crashed", "os.boot"
    std::string subject;           // e.g. "notepad.exe", "Spooler", "HP LaserJet"
    std::string reason;            // e.g. "0xC0000005", "0x80070643", "timeout"
    std::string symbolic;          // e.g. "ACCESS_VIOLATION", "WIFI_DISCONNECT"
    std::string component;         // e.g. "ntdll.dll" (faulting module)
    double metric{0.0};            // numeric payload (boot duration ms); 0 = none
    std::string platform;          // "windows" | "linux" | "macos"
};

// ── DEX read-model aggregations over guardian_observations ───────────────────
// Crash-scoped aggregations keep obs_type='process.crashed' (the headline rate
// stays a crash rate); app aggregations span crash+hang; the signal summary
// spans the whole catalogue. Each takes an ISO-8601 `since` cutoff (empty = all
// retained), aggregated in SQL (GROUP BY, no row materialisation). These provide
// the NUMERATORS; the crash-free-% / per-1k-device-days RATES compose these with
// the fleet-size DENOMINATOR from the agent registry at the route layer
// (cross-store) — deliberately not here.
struct DexCrashSummary {
    int64_t total_crashes{0};
    int64_t distinct_devices{0};   // devices impacted (crash-free numerator)
    int64_t distinct_apps{0};
};
struct DexAppCrashCount {          // top unreliable apps + blast radius
    std::string subject;           // process name
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

// Hard upper bound on `GuaranteedStateEventQuery::limit`. Defence-in-depth
// against a misconfigured or malicious caller: materialising millions of
// event rows into a std::vector would produce a GB-scale RSS spike. The
// REST layer (PR 2) may apply a tighter clamp on top.
inline constexpr int kMaxEventsLimit = 10'000;

// Default retention for `guaranteed_state_events`. Per the design's stated
// 10k events/s during a fleet-wide incident (~864M rows/day), unbounded
// retention fills the data directory within a day. 30 days matches the
// default for `audit_store` and is documented in the data inventory under
// workstream E. Override via the GuaranteedStateStore constructor.
inline constexpr int kDefaultEventRetentionDays = 30;

class GuaranteedStateStore {
public:
    explicit GuaranteedStateStore(const std::filesystem::path& db_path,
                                   int retention_days = kDefaultEventRetentionDays,
                                   int cleanup_interval_min = 60);
    ~GuaranteedStateStore();

    GuaranteedStateStore(const GuaranteedStateStore&) = delete;
    GuaranteedStateStore& operator=(const GuaranteedStateStore&) = delete;

    bool is_open() const;

    // Rule CRUD. Mutating methods return `std::expected<void, std::string>`.
    // Duplicate-UNIQUE collisions (name or rule_id) are reported as an error
    // prefixed with `kConflictPrefix` so REST handlers map them to HTTP 409
    // via `is_conflict_error()` — see `server/core/src/store_errors.hpp`.
    std::expected<void, std::string> create_rule(const GuaranteedStateRuleRow& row);
    std::expected<void, std::string> update_rule(const GuaranteedStateRuleRow& row);
    std::expected<void, std::string> delete_rule(const std::string& rule_id);
    std::optional<GuaranteedStateRuleRow> get_rule(const std::string& rule_id) const;
    std::vector<GuaranteedStateRuleRow> list_rules() const;

    // Event ingest + query.
    std::expected<void, std::string> insert_event(const GuaranteedStateEventRow& row);

    // Batch ingest: wraps all rows in a single transaction. At 10–50x the
    // per-row throughput (one fsync per batch instead of one per row), this
    // is the preferred path for the gRPC `GuaranteedStatePush` handler in
    // PR 2. On failure, the whole batch is rolled back — there is no
    // partial-success state. Returns the number of rows written on success.
    std::expected<std::size_t, std::string>
    insert_events(const std::vector<GuaranteedStateEventRow>& rows);

    std::vector<GuaranteedStateEventRow> query_events(const GuaranteedStateEventQuery& q = {}) const;

    // DEX read model — all projected observations, newest first (slice 1B). A
    // foundation read for tests + the dashboard; the GROUP BY aggregations (top
    // apps / modules / by-OS / blast radius) land in slice 2. Bounded by
    // kMaxEventsLimit for the same RSS defence as query_events.
    std::vector<GuardianObservationRow> query_observations(int limit = kMaxEventsLimit) const;

    // DEX aggregations — GROUP BY over guardian_observations. `since` = ISO-8601
    // cutoff ('' = all). `limit` clamped to kMaxEventsLimit. Rates (crash-free-%,
    // /1k device-days) are composed with the agent-registry fleet size at the
    // route layer, not here. Crash-scoped unless noted.
    DexCrashSummary dex_crash_summary(const std::string& since = "") const;
    // Spans process.crashed + process.hung (the app-reliability table).
    std::vector<DexAppCrashCount> dex_top_apps(const std::string& since = "", int limit = 20) const;
    std::vector<DexModuleCrashCount> dex_top_modules(const std::string& since = "", int limit = 20) const;
    std::vector<DexDeviceCrashCount> dex_top_devices(const std::string& since = "", int limit = 20) const;
    std::vector<DexOsCrashCount> dex_crashes_by_os(const std::string& since = "") const;
    std::vector<DexDayCrashCount> dex_crashes_by_day(const std::string& since = "") const;
    // Whole-catalogue rollup: every obs_type present in the window, with count +
    // blast radius — the overview's "all signals" panel. One GROUP BY pass.
    std::vector<DexSignalCount> dex_signal_summary(const std::string& since = "") const;
    // Boot performance (os.boot, metric = ms; rows with metric<=0 excluded).
    DexBootStats dex_boot_stats(const std::string& since = "") const;
    std::vector<DexDeviceBoot> dex_slowest_boots(const std::string& since = "",
                                                 int limit = 10) const;

    // Generic per-obs_type drill-down (catalogue signal-detail, View 3) — these
    // are the dex_top_apps/_devices/_by_os/_by_day family GENERALISED over any
    // obs_type, not crash-scoped. The "crashes" field on the reused structs holds
    // the generic event count. `dex_os_signal_scope` is the per-OS coverage (how
    // many distinct types each OS collects) — drives the live cross-OS captions
    // that replace the mockups' stale "macOS 6 of 103".
    std::vector<DexSubjectCount> dex_signal_subjects(const std::string& obs_type,
                                                     const std::string& since = "",
                                                     int limit = 20) const;
    std::vector<DexOsCrashCount> dex_signal_by_os(const std::string& obs_type,
                                                  const std::string& since = "") const;
    std::vector<DexDeviceCrashCount> dex_signal_devices(const std::string& obs_type,
                                                        const std::string& since = "",
                                                        int limit = 20) const;
    std::vector<DexDayCrashCount> dex_signal_by_day(const std::string& obs_type,
                                                    const std::string& since = "") const;
    std::vector<DexOsScope> dex_os_signal_scope(const std::string& since = "") const;
    // The (day, obs_type, count) matrix — aggregated to family×day in the route
    // for the Trends small-multiples + heatmap. One GROUP BY pass.
    std::vector<DexDaySignal> dex_signal_day_matrix(const std::string& since = "") const;

    // DEX drill-downs — single-entity scope. App summaries span crash+hang;
    // device summary + history span ALL signal types.
    // Per-app (process_name = the observation subject):
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
    // Per-device (agent_id):
    DexEntitySummary dex_device_summary(const std::string& agent_id,
                                        const std::string& since = "") const;
    std::vector<GuardianObservationRow> dex_device_history(const std::string& agent_id,
                                                           const std::string& since = "",
                                                           int limit = 100) const;

    // ── Overview aggregations (read-only GROUP BY; no event materialisation) ──
    // Each takes an ISO-8601 `since` cutoff (empty = all retained events) and
    // aggregates in SQL — kind to RAM/CPU at fleet scale. See the result structs.
    std::vector<GuardianRuleActivity> rule_activity(const std::string& since = "") const;
    std::vector<GuardianDayCount> daily_remediations(const std::string& since = "") const;

    // Every (agent, rule) current compliance state from the pruning-immune status
    // table (Slice B census). One row per pair; the caller buckets by `state` and
    // applies its own liveness policy (offline agent → "unknown"). Unlike the event
    // log this survives retention reaping, so a long-quiet compliant guard stays
    // visible. Pass a `rule_id` to get just that Guard's per-device rows (the Slice C
    // drill-down, served by idx_gars_rule); empty = the whole fleet. Read-only.
    std::vector<GuardianAgentRuleStatus> agent_rule_statuses(const std::string& rule_id = "") const;

    std::size_t rule_count() const;
    std::size_t event_count() const;

    // Monotonic policy generation — the version stamp of the rule SET, bumped
    // atomically on every create/update/delete (see bump_policy_generation_locked).
    // The Guardian push proto carries this so an agent can tell a newer push from
    // a stale one; the heartbeat reconcile (M5) compares an agent's applied
    // generation against this value to decide whether it has fallen behind.
    // Persisted (survives restart) and strictly increasing — unlike the prior
    // wall-clock seconds, which could repeat or step backwards (M6 / #1209).
    // A *reconcile* re-push reads this value WITHOUT bumping it, so catching one
    // lagging agent up never makes the rest of the fleet look stale.
    uint64_t current_policy_generation() const;

    // Bump the persisted policy generation WITHOUT mutating any rule. The
    // Baseline deploy path calls this: deploying (or undeploying) a Baseline
    // changes which Guards are active on the fleet — the desired set — without
    // editing any rule, and the heartbeat reconcile keys off the generation to
    // decide an agent is stale. Takes the write lock (do NOT call while holding
    // it). The rule-mutation methods bump internally via the _locked variant.
    void bump_policy_generation();

    // Observability — lock-free cumulative counters for Prometheus scraping.
    // Cover the counts that a Prometheus alert on ingest health wants (bytes
    // or rows written, reaper activity) without forcing the collector to
    // issue a SQL `COUNT(*)` every scrape.
    uint64_t events_written_total() const noexcept { return events_written_.load(); }
    uint64_t events_reaped_total() const noexcept { return events_reaped_.load(); }
    // DEX projection health (governance UP-1): projection failures degrade to
    // event-only commits and are counted here so the read-model loss is
    // alertable; the reap counter is the disposal-evidence twin of
    // events_reaped_ for the guardian_observations table (compliance WS-E).
    uint64_t observations_proj_failures_total() const noexcept {
        return observations_proj_failures_.load();
    }
    uint64_t observations_reaped_total() const noexcept { return observations_reaped_.load(); }

    void start_cleanup();
    void stop_cleanup();

private:
    sqlite3* db_{nullptr};
    int retention_days_;
    int cleanup_interval_min_;
    mutable std::shared_mutex mtx_;

    std::atomic<uint64_t> events_written_{0};
    std::atomic<uint64_t> events_reaped_{0};
    std::atomic<uint64_t> observations_proj_failures_{0};
    std::atomic<uint64_t> observations_reaped_{0};

#ifdef __cpp_lib_jthread
    std::jthread cleanup_thread_;
#else
    std::thread cleanup_thread_;
    std::atomic<bool> stop_requested_{false};
#endif

    void create_tables();
#ifdef __cpp_lib_jthread
    void run_cleanup(std::stop_token stop);
#else
    void run_cleanup();
#endif

    // Increment the persisted policy generation. Caller MUST hold mtx_ as a
    // unique_lock (called from within the rule-mutation methods, which already
    // hold it). Single fixed UPDATE — no sqlite3_changes() read, so it does not
    // add a #1033 race site.
    void bump_policy_generation_locked();

    // Upsert one (agent, rule) compliance state into guardian_agent_rule_status.
    // Caller MUST hold mtx_ as a unique_lock (called from insert_event / insert_events
    // inside their existing lock + transaction). The ON CONFLICT clause is guarded by
    // `excluded.updated_at >= existing.updated_at` so a late-arriving older event
    // cannot regress a newer state. No sqlite3_changes() read (not a #1033 site).
    void upsert_rule_status_locked(const std::string& agent_id, const std::string& rule_id,
                                   const char* state, const std::string& updated_at);

    // Project one ruleless DEX observation into guardian_observations. Caller MUST
    // hold mtx_ AND have an OPEN transaction (called from insert_event / insert_events
    // right after the event INSERT) so the projection is atomic with the event and
    // inherits its event_id dedup — a redelivered crash fails the event PK and rolls
    // back both, so the projection never double-counts. `detail_json` is parsed
    // defensively (malformed → empty crash fields, never drops the observation);
    // `ttl` is the parent event's expiry so the reaper sweeps both in lockstep.
    std::expected<void, std::string>
    project_observation_locked(const GuaranteedStateEventRow& row, int64_t ttl);

    // Compute ttl_expires_at = now + retention_days*86400 in epoch seconds;
    // retention_days <= 0 means "never expire" (returns 0, the sentinel the
    // reaper's `WHERE ttl_expires_at > 0` clause excludes).
    int64_t compute_ttl_epoch() const;
};

} // namespace yuzu::server
