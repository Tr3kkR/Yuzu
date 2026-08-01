#pragma once

/// @file audit_store.hpp
/// SOC 2 evidence chain — operator actions, agent enrolment, fleet-topology
/// events, background schedule execution, and every behavioural-PII access.
/// Born on SQLite (`audit.db`), migrated to PostgreSQL (ADR-0006/0008/0009/
/// 0040, schema `audit_store`). Highest-stakes store on the ladder: a lost or
/// silently-truncated audit trail is a compliance failure (CC6.6/CC7.2), not
/// degraded telemetry.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, migrates at
/// construction on a pinned lease, schema-qualifies every runtime statement
/// (`audit_store.audit_events`). No `sqlite3_changes()` (#1033) — mutators use
/// `RETURNING` / `PQcmdTuples`.
///
/// Failure posture (ADR-0012 §1 / ADR-0040), split by operation class — this is
/// the distinguishing decision vs ResponseStore's fail-soft ingest:
///  - **Write (`log`): FAIL-HARD.** A dropped audit event is a compliance
///    failure, not re-derivable telemetry. `log()` keeps its `bool` contract:
///    a store-not-open / pool-acquire-timeout / query error returns `false`,
///    and callers already fail-closed on `false` (behavioural-PII REST routes
///    → 503 + `Sec-Audit-Failed`; `emit_behavioral_audit`, #1647).
///    `emit_failed_` counts every `false`. Single `INSERT`, never a
///    SAVEPOINT-tolerant path.
///  - **Reads (`query`/`total_count`): degrade-distinguishable, DENY on
///    degrade.** The audit trail is authoritative evidence — a store/pool
///    failure MUST NOT read as "no audit events" (that would let a reviewer or
///    a SIEM conclude an absence of activity from an infrastructure blip). Both
///    return `std::optional<…>` / nullopt-on-degrade; the audit-log REST/MCP
///    consumers surface 503, never a false-empty. Stricter than ResponseStore's
///    deny-or-benign carve-out: the audit read is evidence, so degrade → deny.
///  - **Retention (`cleanup_once`): migration-REQUIRED clock guard** — the
///    #2360 guard ported to a single-sweeper advisory lease with durable dedup
///    (see the .cpp). Fail-hard within its advisory-lease-held transaction; a
///    probe/delete failure declines the pass (never a blind delete).
///  - **Backfill: MANDATORY (ADR-0009 mandatory class).** 365-day SOC 2
///    retention makes pre-cutover rows mandatory evidence; `migrate_from_sqlite`
///    streams the legacy `audit.db` in bounded, id-resumable batches and boot
///    FAILS CLOSED on backfill failure.

#include "audit_retention_rules.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

struct AuditEvent {
    int64_t id{0};
    int64_t timestamp{0}; // epoch seconds
    std::string principal;
    std::string principal_role;
    std::string action;
    std::string target_type;
    std::string target_id;
    std::string detail;
    std::string source_ip;
    std::string user_agent;
    std::string session_id;
    std::string result;   // "success", "failure", "denied"
    std::string mcp_tool; // MCP tool name if action was MCP-initiated (empty otherwise)
    // Actor class (ADR-1005 Decision 9 / execution-plan Phase 3a), mirroring
    // principal_class.hpp's HTTP request-metric label: "human" (session
    // cookie), "agent" (bearer/API token), "none" (unauthenticated — a failed
    // login, a probe-adjacent request; honest label, not a guess at human vs.
    // agent), or "" for any row this program cannot attribute to an HTTP
    // session/token principal at all (the agent-daemon's own gRPC channel,
    // gateway-proxied calls, server-internal/background writers — a different
    // kind of actor `principal_class_of` was never meant to classify; see its
    // own header comment). "engine" is reserved, live once Phase 4 engine-token
    // sessions exist. Populated at `AuthRoutes::make_audit_event`/
    // `audit_log_for_principal` (the two HTTP-request-shaped constructors) via
    // `principal_class_of(req)`; every other AuditEvent construction leaves it
    // at its default "".
    std::string principal_class;
};

struct AuditQuery {
    std::string principal;
    std::string action;
    std::string target_type;
    std::string target_id;
    int64_t since{0};
    int64_t until{0};
    int limit{100};
    int offset{0};
    // Match any action that starts with one of these prefixes (OR-combined),
    // e.g. {"auth.","mfa.","session."} to scope to the authentication surface
    // (sampled auth-log evidence export, #4 / SOC 2 CC7.2). Empty = no prefix
    // filter. Combines with `action` (exact) if both are set.
    //
    // CONTRACT (Hermes I-1): prefixes are bound as a SQL `LIKE <prefix>%` pattern
    // and are NOT escaped, so a caller must only ever pass code-controlled literal
    // prefixes — never untrusted input, which could smuggle `%`/`_` wildcards.
    // A degenerate all-empty list does NOT widen to "all actions" (query() emits
    // an always-false guard), so it fails closed.
    std::vector<std::string> action_prefixes;
    // When true, the result is a pseudo-random sample rather than newest-first:
    // query() fetches a bounded candidate pool in indexed timestamp order (capped
    // at kAuditSampleScanCap to bound CPU + memory — NOT `ORDER BY RANDOM()`,
    // which would full-scan the window), then shuffles in C++ and truncates to
    // `limit`. When the window holds more than the cap, the pool is the
    // most-recent kAuditSampleScanCap events (a recency bias above the cap —
    // callers presenting this as evidence must surface it). `offset` is ignored.
    bool random_sample{false};
};

// Candidate-pool cap for AuditQuery::random_sample. A sample is drawn from at
// most this many most-recent matching rows; above it the sample is recency-biased
// (see random_sample). Public so the REST layer can report `recency_capped` to an
// auditor (#4 / SOC 2 CC7.2 evidence honesty).
inline constexpr std::size_t kAuditSampleScanCap = 10000;

// ── Retention clock guard (#2360) ──────────────────────────────────────────
//
// Retention deletes rows whose TTL has passed, with "has passed" decided by the
// server's wall clock. One forward step -- a restored VM snapshot, an NTP
// correction after a dead CMOS battery, a hand-set date -- marks the whole
// evidence table expired at once, and an unguarded `DELETE ... WHERE ttl < now`
// then acts on that in a single statement. These constants bound it.
//
// The division of labour matters and is easy to get backwards: the CAP is the
// guarantee, the detectors are best-effort. See `cleanup_once`.

// Rows whose TTL lands more than this far in the future are excluded from the
// "would this pass delete everything datable?" question. See the .cpp's reap for
// the full rationale (ported verbatim from the SQLite guard): a forward-skewed
// row that can never itself expire must not be counted as a survivor, or ONE bad
// row vetoes the guard for the life of the store.
inline constexpr std::int64_t kAuditTtlFutureSlackSec = 2 * 86400;

// Upper bound on rows deleted by ONE retention pass. The load-bearing half of
// the guard: it applies unconditionally, turning an accepted wipe into a paced
// ageing-out an operator can still catch. Now safe as a per-pass DRAIN RATE for
// the ONE sweeping process (the advisory lease makes "N × 25k" impossible), so
// the 0.6M rows/day @ 60-min-interval calibration stays valid.
inline constexpr std::size_t kMaxAuditDeletesPerPass = 25000;

// Threshold for the elapsed-time detector. ABSOLUTE -- how far the clock moved
// has nothing to do with how long rows are kept. Deriving it from the retention
// window is the fatal mistake (at 365d it becomes a YEAR and never fires). Set
// past the point where an outage is itself remarkable; a server genuinely down
// for eight days declines one pass, the right trade for catching a month jump.
inline constexpr std::int64_t kAuditMinBigStepSec = 7 * 86400;

class AuditStore {
public:
    /// Borrows the shared pool and runs the `audit_store` schema migration on a
    /// pinned lease. `is_open()` is false if the lease was empty or the
    /// migration failed (fail-closed — every operation then declines, the right
    /// posture for an evidence store whose schema is wrong).
    explicit AuditStore(pg::PgPool& pool, int retention_days = 365,
                        int cleanup_interval_min = 60);
    ~AuditStore();

    AuditStore(const AuditStore&) = delete;
    AuditStore& operator=(const AuditStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for `yuzu_server_audit_read_degrade_total{reason}`
    /// (degrade-distinguishable reads). Set ONCE during single-threaded startup,
    /// before serving — read without synchronisation on serving threads. A null
    /// registry (default, e.g. unit tests) disables emission; every emit site is
    /// null-guarded. The eight retention/write counters below are ALSO exposed as
    /// lock-free atomic accessors, scraped as gauges by the server maintenance
    /// loop independently of this registry.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// MANDATORY backfill (ADR-0009 mandatory class / ADR-0040). On first boot
    /// against an empty `audit_store.audit_events` with a legacy `audit.db`
    /// present, streams every row (ALL columns incl. `principal_class` and
    /// `ttl_expires_at`, so the retention horizon is preserved exactly) into PG
    /// in bounded, id-resumable batches (`ON CONFLICT (id) DO NOTHING`, resume
    /// from `MAX(id)` in PG), copies `audit_retention_meta`, reconciles row
    /// counts, then stamps a one-time `backfill_complete` marker and advances the
    /// identity sequence past the migrated ids. Returns TRUE on success or when
    /// already complete; FALSE on any failure — the caller MUST refuse boot
    /// (fail-closed: never serve with a knowingly-incomplete evidence chain, retry
    /// next start). The verified-migrated legacy file is moved aside, not deleted.
    [[nodiscard]] bool migrate_from_sqlite(const std::filesystem::path& legacy_db_path);

    /// Persist an audit event. FAIL-HARD: returns true iff the row was written.
    /// The bool is part of the SOC 2 CC6.6/CC7.2 evidence-integrity chain —
    /// handlers that emit an audit row as compliance evidence for a privileged
    /// mutation MUST observe the return and surface partial-success. On failure
    /// (store not open, pool-acquire timeout, or query error) `emit_failed_`
    /// increments and the row is lost. `[[nodiscard]]` makes any discard visible.
    [[nodiscard]] bool log(const AuditEvent& event);

    /// Degrade-distinguishable read: `std::nullopt` on a store/pool/query failure
    /// (evidence integrity — a blip must not read as "no audit activity"); an
    /// engaged EMPTY vector is a genuine "no rows". When `q.random_sample` is set
    /// and `out_pool_size` is non-null, `*out_pool_size` receives the candidate
    /// pool size BEFORE shuffle/truncate (<= kAuditSampleScanCap) so the caller
    /// can report `recency_capped` (#4). For non-sample queries it is untouched.
    [[nodiscard]] std::optional<std::vector<AuditEvent>>
    query(const AuditQuery& q = {}, std::size_t* out_pool_size = nullptr) const;

    /// Degrade-distinguishable total row count: `std::nullopt` on degrade.
    [[nodiscard]] std::optional<std::size_t> total_count() const;

    /// Cumulative audit-event write counts grouped by `result` value. Exposed for
    /// Prometheus scraping; reset at process start. Lock-free reads.
    uint64_t events_written(const std::string& result) const noexcept;

    /// Cumulative count of audit events that failed to persist. Audit pipeline
    /// degradation is a SOC 2 CC7.2 evidence-chain risk; surface it on /metrics.
    uint64_t emit_failed_count() const noexcept {
        return emit_failed_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of retention passes that DECLINED to delete (clock
    /// anomaly: would-wipe, big elapsed step, or an unusable durable reading).
    uint64_t clock_anomaly_skips_count() const noexcept {
        return clock_anomaly_skips_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of retention passes that did NOT do their job (probe
    /// failure, delete failure, closed store, implausible caller clock, or an
    /// exception at the thread boundary). Read as "retention is not fully
    /// healthy", never as "nothing was deleted". Scraped SEPARATELY from
    /// clock_anomaly_skips so an operator can tell "the guard is protecting the
    /// table" from "the cleanup loop is broken".
    uint64_t cleanup_failed_count() const noexcept {
        return cleanup_failed_.load(std::memory_order_relaxed);
    }

    /// Cumulative rows deleted by retention, and passes that hit the per-pass cap
    /// AND left a backlog behind (expiry outrunning the drain — otherwise
    /// invisible on /metrics).
    uint64_t rows_deleted_count() const noexcept {
        return rows_deleted_.load(std::memory_order_relaxed);
    }
    uint64_t cap_reached_count() const noexcept {
        return cap_reached_.load(std::memory_order_relaxed);
    }

    /// Cumulative retention passes ATTEMPTED, and the wall-clock reading of the
    /// most recent pass WHOSE CLOCK WAS USABLE (0 if none yet). Every other
    /// counter here is silence-means-healthy; an operator alerts on ABSENCE of
    /// movement here.
    std::uint64_t retention_passes_count() const noexcept {
        return retention_passes_.load(std::memory_order_relaxed);
    }
    std::int64_t last_pass_unixtime() const noexcept {
        return last_pass_unixtime_.load(std::memory_order_relaxed);
    }

    /// Cumulative failures to persist the retention clock reading. A sustained
    /// non-zero rate means the restart-surviving half of the guard is degraded.
    uint64_t persist_failed_count() const noexcept {
        return persist_failed_.load(std::memory_order_relaxed);
    }

    /// Run exactly ONE retention pass against `now` (epoch seconds) and return
    /// the number of rows deleted. Returns 0 when the pass declined (clock
    /// guard), when nothing was expired, when another replica held the advisory
    /// lease, or when the pass failed. Factored out so tests can drive a pass at
    /// an arbitrary `now` without sleeping the cleanup interval.
    std::size_t cleanup_once(std::int64_t now);

    void start_cleanup();
    void stop_cleanup();

private:
    pg::PgPool& pool_;
    bool open_{false};
    int retention_days_;
    int cleanup_interval_min_;
    yuzu::MetricsRegistry* metrics_{nullptr};

    // Cumulative event write counters bucketed by `result`. Lock-free.
    std::atomic<uint64_t> events_success_{0};
    std::atomic<uint64_t> events_failure_{0};
    std::atomic<uint64_t> events_denied_{0};
    std::atomic<uint64_t> events_other_{0};
    std::atomic<uint64_t> emit_failed_{0};
    // Retention-guard counters (#2360). Atomic because the /metrics scrape reads
    // them without synchronisation.
    std::atomic<uint64_t> clock_anomaly_skips_{0};
    std::atomic<uint64_t> cleanup_failed_{0};
    std::atomic<uint64_t> rows_deleted_{0};
    std::atomic<uint64_t> cap_reached_{0};
    std::atomic<uint64_t> persist_failed_{0};
    // Liveness — stamped on EVERY pass including declined/failed/lock-skipped
    // ones: the question is "did the reaper run at all", not "did it delete".
    std::atomic<uint64_t> retention_passes_{0};
    std::atomic<std::int64_t> last_pass_unixtime_{0};

#ifdef __cpp_lib_jthread
    std::jthread cleanup_thread_;
    void run_cleanup(std::stop_token stop);
#else
    std::thread cleanup_thread_;
    std::atomic<bool> stop_requested_{false};
    void run_cleanup();
#endif
};

} // namespace yuzu::server
