#pragma once

/// @file pg_retention_guard.hpp
/// WS-10 (#2508): the clock-guarded, SINGLE-WRITER-safe retention DELETE for
/// Postgres stores, as ONE reviewed implementation the #2508 prunes share
/// (`app_perf_fleet_store`, `preflight_run_store`, `deployment_run_store`).
///
/// WHY SHARED, not copied per store. The routed "clock-guarded retention" concern
/// says "copy the SHAPE, never the numbers." The three #2508 targets are
/// structurally identical Postgres retention deletes differing ONLY in table,
/// timestamp column/unit, and their substrate-tuned constants — so this helper IS
/// the shape, and every number is a per-store parameter (`ClockGuardedPruneSpec`).
/// For catastrophic-if-wrong retention code, one implementation exercised by an
/// exhaustive table test is strictly safer to verify than three hand-copies, and
/// it matches the codebase's single-chokepoint discipline
/// (`dispatch_confined_arms`, `authz_topology_floor`, `body_cap_policy`). The
/// pure decision rule stays the shared `audit_retention::classify` (part 6's
/// "record which way you went" is the per-call-site `missing_anchor` choice +
/// comment; it is NOT hidden in here).
///
/// The seven parts (all implemented here; the reference is
/// `execution_tracker.cpp::reconcile_stale_concurrency_claims` + `audit_store`):
///   1. probe by OUTCOME (would-wipe), excluding implausibly-future rows via a
///      PER-STORE `implausibility_bound` that MUST exceed that store's max TTL;
///   2. a PERSISTED clock reading in `retention_meta` (survives restarts);
///   3. SANITISE it (below `min_plausible_reading` → prev_unusable/BadState);
///   4. SUPPRESS only a repeat of the SAME full fact set;
///   5. cap every accepted pass UNCONDITIONALLY (`cap_per_pass` LIMIT);
///   6. a DELIBERATE missing-anchor decision (`MissingAnchorPolicy`), recorded
///      at the call site;
///   7. absolute elapsed-time step floor (`big_step_floor`, in the column's unit).
/// SINGLE-WRITER: the whole probe-decide-delete runs in ONE txn whose first
/// statement is `pg_try_advisory_xact_lock(advisory_lock_key)` — a replica that
/// loses the race skips this tick (another drains it; the anchor advances on the
/// winner), so N replicas never race the anchor or the delete. The clock is read
/// from Postgres `now()` in-SQL (the shared clock, #3715), never a replica's
/// `system_clock`, so cross-host skew cannot split the guard.
///
/// UNIT-AGNOSTIC. Everything is expressed in the timestamp COLUMN's native unit
/// (ms for `created_at_ms`, unix-days for `day`), so `now_expr` yields the current
/// time in that unit and `retention_window`, `big_step_floor`,
/// `implausibility_bound` and `min_plausible_reading` are all in that same unit.

#include "pg_pool.hpp"

#include <yuzu/audit_retention_rules.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

namespace yuzu::server::pg {

/// Part 6: what a missing durable anchor means for THIS store. Decline = a
/// from-boot skewed clock must not silently delete (non-regenerable data;
/// audit_store's answer). Proceed = the data is regenerable/re-mintable, so a
/// decline buys nothing (ResultSetStore's answer).
enum class MissingAnchorPolicy { Decline, Proceed };

struct ClockGuardedPruneSpec {
    std::string_view store_label;      ///< for logs/metrics, e.g. "app_perf_fleet_store"
    std::string_view target_table;     ///< schema-qualified, e.g. "preflight_run_store.runs"
    std::string_view ts_column;        ///< the retention timestamp column, e.g. "created_at_ms"
    /// SQL yielding "now" in the column's unit, e.g.
    ///   "(EXTRACT(EPOCH FROM now())*1000)::bigint"  (ms) or
    ///   "(EXTRACT(EPOCH FROM now())/86400)::bigint"  (unix-days).
    std::string_view now_expr;
    std::string_view meta_table;       ///< schema-qualified retention_meta(key TEXT PK, value TEXT)
    std::string_view anchor_key;       ///< retention_meta key for the persisted reading
    std::string_view settled_key;      ///< retention_meta key for the bootstrap-settled marker
    std::string_view facts_key;        ///< retention_meta key for the last anomaly fact set
    /// SQL bigint expression for the advisory-lock key, DISTINCT per store, e.g.
    ///   "hashtext('preflight_run_store:runs_prune')".
    std::string_view advisory_lock_key;
    std::int64_t retention_window;     ///< delete rows older than now - this (column unit)
    std::int64_t big_step_floor;       ///< part 7 absolute step threshold (column unit)
    std::int64_t implausibility_bound; ///< part 1: ignore rows stamped > now + this ahead (column unit); MUST exceed max TTL
    std::int64_t min_plausible_reading;///< part 3: an anchor below this is unusable (column unit)
    std::int64_t cap_per_pass;         ///< part 5 unconditional LIMIT
    MissingAnchorPolicy missing_anchor;///< part 6 (recorded at the call site)
};

struct ClockGuardedPruneOutcome {
    int deleted = 0;                                          ///< rows deleted this pass
    audit_retention::Anomaly anomaly = audit_retention::Anomaly::None;
    bool declined = false;    ///< a new anomaly declined this pass
    bool skipped_lock = false;///< another replica held the advisory lock this tick
    bool error = false;       ///< the txn failed (connection/query); nothing deleted
};

/// Run one clock-guarded, single-writer, capped retention pass per the spec.
/// Best-effort: on connection/query failure returns `error=true, deleted=0` and
/// leaves the anchor unchanged (the caller's liveness signal). Never throws.
[[nodiscard]] ClockGuardedPruneOutcome run_clock_guarded_prune(
    PgPool& pool, const ClockGuardedPruneSpec& spec,
    std::chrono::milliseconds acquire_timeout);

} // namespace yuzu::server::pg
