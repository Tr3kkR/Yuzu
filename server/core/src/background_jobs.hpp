#pragma once

/// @file background_jobs.hpp
/// WS-10 (ADR-2002 §Decomposition item 10): the checked-in, exhaustive
/// classification of EVERY server background pass for replica-safety, so a
/// newly-added pass cannot silently double-run under a second replica.
///
/// THE UNIT IS THE PASS, NOT THE THREAD. One thread multiplexes many passes of
/// different classes — `result_set_maint_thread_` alone runs 11 (the per-replica
/// event-outbox poll, several advisory-locked reaps, gauge refreshes), and
/// `health_recompute_thread_` runs a mix of read-only gauges, a fleet-wide CRL
/// re-publish, and a per-replica stream teardown. Classifying a thread wholesale
/// would falsely certify an unsafe pass riding a mostly-safe thread. Each entry
/// below is one unit of work.
///
/// THREE CLASSES (ADR-2002 item 10):
///   - ReplicaSafe          — correct to run on every replica concurrently,
///                            because it is read-only/local, idempotent, an
///                            execute-once CAS, or an advisory-lock SINGLE-WRITER
///                            retention pass. MUST-run-per-replica passes (the
///                            event-outbox poll, ADR-2002 §5) are ReplicaSafe and
///                            must NEVER be leader-gated.
///   - FencedLeaderOnly     — side-effecting singleton work that double-fires
///                            across replicas (agent dispatch, CRL numbering).
///                            Runs only on the WS-3 fenced leader; ENFORCEMENT is
///                            slice 10.3 (rides WS-3 3.2), not this file.
///   - DisabledUntilFixed   — not yet replica-safe and not yet leader-gated; must
///                            not run per-replica until its named fix lands.
///
/// HOW CLASSIFICATION IS ENFORCED — and the honest limit of it. This array is the
/// single compile-time source of truth (git-auditable, CI-compiled), and
/// `tests/unit/server/test_background_jobs.cpp` pins its internal consistency +
/// completeness against the audited inventory (a count tripwire). Every
/// CATASTROPHIC-CLASS site carries `YUZU_ASSERT_BACKGROUND_JOB(...)` — a consteval
/// lookup that makes removing/renaming its table entry a BUILD FAILURE (the
/// `command_capability.hpp` ExecuteGate precedent): all FencedLeaderOnly and
/// DisabledUntilFixed passes (schedule/policy/quarantine dispatch, ca.publish_crl,
/// nvd_sync), plus the load-bearing ReplicaSafe ones (the event-outbox poll, the
/// concurrency reconciler, the three retention prunes, the app_perf rollup
/// upsert). This proves
/// named⇒classified for those sites. It does NOT yet prove pass⇒named for every
/// read-only ReplicaSafe gauge/reap site (a consteval sweep visiting ALL dispatch
/// sites is a tracked follow-up), so completeness across those rests on THIS array
/// plus the routed-concern review (cpp-safety+sre+compliance-officer on any new
/// background pass). A new side-effecting pass is a diff against THIS array, never
/// a silent addition.

#include <array>
#include <cstddef>
#include <string_view>

namespace yuzu::server {

enum class BackgroundJobClass {
    ReplicaSafe,
    FencedLeaderOnly,
    DisabledUntilFixed,
};

struct BackgroundJobDecl {
    std::string_view pass;          ///< stable pass symbol (unique key)
    std::string_view owning_thread; ///< the thread whose tick invokes it
    BackgroundJobClass cls;
    std::string_view mechanism;     ///< why the class holds (the recorded rationale)
};

/// The exhaustive inventory. Verified against the source sweep 2026-09-06.
inline constexpr std::array kBackgroundJobs = std::to_array<BackgroundJobDecl>({
    // ---- result_set_maint_thread_ (2s tick) ----
    {"session_clock_monitor.observe", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica local host-clock drift metric"},
    {"result_set_store.materialize", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "execute-once via status='pending' CAS UPDATE; device rows ON CONFLICT DO NOTHING"},
    {"result_set_store.gc_sweep", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded (ADR-0036/0040); regenerable scratch, a double-gc of already-expired rows is harmless"},
    {"response_store.reap_expired", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (ADR-0039)"},
    {"guaranteed_state_store.reap_expired", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (ADR-0038, #2663)"},
    {"session_store.reap_expired", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory-lock own-statement (ADR-2002 §4)"},
    {"execution_tracker.reap_command_execution_mappings", "result_set_maint_thread_",
     BackgroundJobClass::ReplicaSafe, "clock-guarded + pg_advisory_xact_lock"},
    {"execution_tracker.reconcile_stale_concurrency_claims", "result_set_maint_thread_",
     BackgroundJobClass::ReplicaSafe,
     "advisory-lock SINGLE-WRITER (pg_try_advisory_xact_lock, WS-10 10.2, this change) — prevents "
     "concurrent double-reconcile. CAVEAT: its clock authority is still replica-local system_clock "
     "(both the claim expires_at write and the reconcile read), NOT shared PG-now; a concurrency_claims "
     "DB-clock-authority migration (WS-1 class, #3715 shape) is a prerequisite before a 2nd replica, or "
     "a skewed winner could release a live claim early"},
    {"execution_tracker.reap_event_outbox", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + pg_try_advisory_xact_lock"},
    {"execution_tracker.poll_event_outbox_once", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "MUST run per-replica — cross-replica SSE delivery (ADR-2002 §5); NEVER leader-gate"},
    {"result_set_store.counts", "result_set_maint_thread_", BackgroundJobClass::ReplicaSafe,
     "read-only gauge refresh"},

    // ---- app_perf_rollup_thread_ (1h tick) ----
    {"app_perf_rollup.roll_window", "app_perf_rollup_thread_", BackgroundJobClass::ReplicaSafe,
     "idempotent upsert (ON CONFLICT (app_name,version,day) DO UPDATE)"},
    {"app_perf_fleet_store.run_retention_prune", "app_perf_rollup_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (WS-10 10.2)"},

    // ---- preflight_runner_thread_ (60s tick) ----
    {"preflight_runner.redispatch_readonly_checks", "preflight_runner_thread_",
     BackgroundJobClass::ReplicaSafe,
     "read-only/idempotent check re-dispatch to a frozen cohort (routed concern: safe ONLY while read-only)"},
    {"preflight_run_store.run_retention_prune", "preflight_runner_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (WS-10 10.2)"},
    {"deployment_run_store.run_retention_prune", "preflight_runner_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (WS-10 10.2); piggybacks the preflight thread"},

    // ---- policy_eval_thread_ (10s tick) ----
    {"policy_evaluator.tick", "policy_eval_thread_", BackgroundJobClass::FencedLeaderOnly,
     "side-effecting remediation dispatch; ADR-0056 claim_due_policies is fleet-safe but the loop is leader-only (WS-3 3.2/3.4)"},

    // ---- schedule_tick_thread_ (30s tick) ----
    {"schedule_runner.tick", "schedule_tick_thread_", BackgroundJobClass::FencedLeaderOnly,
     "side-effecting scheduled dispatch — double-fire across replicas without a fenced leader (WS-3 3.2)"},

    // ---- quarantine_reconcile_thread_ (20s tick) ----
    {"quarantine_reconciler.tick", "quarantine_reconcile_thread_", BackgroundJobClass::FencedLeaderOnly,
     "side-effecting containment re-dispatch (WS-3 3.2; confirm WS-4/5 stream-locality interaction)"},

    // ---- quarantine_snapshot_refresh_thread_ (20s tick) ----
    {"quarantine_store.list_quarantined_snapshot", "quarantine_snapshot_refresh_thread_",
     BackgroundJobClass::ReplicaSafe, "per-replica read-only cache for the #881 dispatch gate"},

    // ---- health_recompute_thread_ (15s tick) ----
    {"health_store.recompute_metrics", "health_recompute_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica read-only fleet gauges (incl. stream-budget/pg-pool/KEK-state/cohort-perf gauges)"},
    {"software_inventory_store.count_stale_agents", "health_recompute_thread_",
     BackgroundJobClass::ReplicaSafe, "read-only inventory-freshness gauge"},
    {"registry.reap_stale_sessions", "health_recompute_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica in-memory Subscribe-stream reap (local presence)"},
    {"ca.publish_crl", "health_recompute_thread_", BackgroundJobClass::FencedLeaderOnly,
     "DB-WRITE: CRL row + crlNumber bump must be single-writer or numbering diverges (WS-6)"},
    {"registry.teardown_revoked_streams", "health_recompute_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica: tears down only the Subscribe streams connected to THIS replica"},

    // ---- engine_rotation_sweep_thread_ (60s tick) ----
    {"api_token_store.sweep_expired_rotations", "engine_rotation_sweep_thread_",
     BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (SkippedLock outcome); already single-writer compliant"},

    // ---- insecure_tls_reminder_thread_ (300s tick) ----
    {"insecure_tls_reminder", "insecure_tls_reminder_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica idempotent log + audit reminder"},

    // ---- web_thread_ / redirect_thread_ (blocking listeners, no periodic pass) ----
    {"web_server.listen", "web_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica HTTP listener; work is per-request handlers, not a periodic pass"},
    {"redirect_server.listen", "redirect_thread_", BackgroundJobClass::ReplicaSafe,
     "per-replica HTTP→HTTPS 301 listener"},

    // ---- store-internal threads ----
    {"audit_store.cleanup_once", "AuditStore::cleanup_thread_", BackgroundJobClass::ReplicaSafe,
     "clock-guarded + advisory lock (the canonical retention reference impl)"},
    {"analytics_event_store.drain_batch", "AnalyticsEventStore::drain_thread_",
     BackgroundJobClass::ReplicaSafe, "per-replica local buffer drain to the operator-supplied sink"},
    {"nvd_sync.do_sync", "NvdSyncManager::sync_thread_", BackgroundJobClass::DisabledUntilFixed,
     "engine-tier migration pending (ADR-1005 Phase 7 / ADR-0023); only a process-local single-flight (sync_active_ CAS), not cross-replica — must move to the engine tier or be leader-gated before a 2nd replica"},
});

/// Index of `pass` in kBackgroundJobs, or -1 if absent. consteval so a site
/// assertion resolves at compile time.
consteval int background_job_index(std::string_view pass) {
    for (std::size_t i = 0; i < kBackgroundJobs.size(); ++i)
        if (kBackgroundJobs[i].pass == pass)
            return static_cast<int>(i);
    return -1;
}

/// Assert (at compile time) that a background pass is classified in
/// kBackgroundJobs. Place at each pass's dispatch site. An unregistered pass is
/// a build failure — the "nothing silently escapes" guarantee.
#define YUZU_ASSERT_BACKGROUND_JOB(pass_literal) \
    static_assert(::yuzu::server::background_job_index(pass_literal) >= 0, \
                  "background pass '" pass_literal \
                  "' is not classified in kBackgroundJobs (server/core/src/background_jobs.hpp) — " \
                  "WS-10 requires every background pass be classified for replica-safety")

} // namespace yuzu::server
