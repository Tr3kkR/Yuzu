#pragma once

/// @file preflight_run_store.hpp
/// Born-on-Postgres store (ADR-0006, schema `preflight_run_store`) for `/auto`
/// pre-flight RUNS — the persistence behind the saved-runs rail and the
/// re-dispatch-on-reconnect runner. The store is the ONLY home for run state (no
/// in-memory duplicate) yet is wired FAIL-SOFT — durability-on-top per ADR-0012,
/// NOT fail-hard: it's a feature page, so a store outage degrades /auto to an
/// honest note rather than failing the server (do not "fix" it to fail-closed).
///
/// Two tables:
///   * runs       — metadata + frozen config + window + status + summary counts.
///   * run_device — PK(run_id, agent_id); hostname/os FROZEN at creation (the
///                  cohort denominator + the owner-scoped read surface), bucket +
///                  checks_json COMPUTED/upserted by the runner.
///
/// Owner scoping: `created_by` is captured at creation; the rail lists a viewer's
/// own runs and the result route reads via get_run(run_id, viewer), so another
/// operator's run is indistinguishable from not-found (no existence oracle).
/// Admin-sees-all (the `is_admin` list_runs path) is a tracked follow-up — not
/// wired; callers pass is_admin=false today.
///
/// Durability rationale: the computed grid is persisted (not recomputed from the
/// ResponseStore at render) so a run revisited days later survives ResponseStore
/// pruning. A *running* run is still rendered live (handler computes from
/// query_by_execution); the stored grid is the source for *complete* runs.
///
/// Substrate contract (ADR-0008/0012): holds a `PgPool&`, runs its migration at
/// construction on a pinned lease, schema-qualifies every runtime statement,
/// RETURNING is the mutate-and-return idiom. Bounded acquires everywhere; a
/// lease is NEVER held across a dispatch or a ResponseStore read (the runner
/// owns that ordering).

#include "preflight_parse.hpp" // preflight::PreflightTarget

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// One persisted run (metadata + frozen config + lifecycle + summary).
struct PreflightRunRow {
    std::string run_id;
    std::string execution_id; ///< "preflight-<run_id>" (per-check ids derive from it)
    std::string created_by;   ///< frozen creator username (owner-scope key)
    std::string name;
    std::string scope_label;
    std::string group_id;
    std::string os_filter;
    std::string config_json; ///< serialized PreflightConfig + applicable check keys
    int window_seconds = 0;
    std::int64_t created_at_ms = 0;
    std::int64_t deadline_at_ms = 0;
    std::string status = "running"; ///< "running" | "complete"
    std::int64_t completed_at_ms = 0;
    int total = 0;
    int go = 0;
    int warn = 0;
    int nogo = 0;
    int incomplete = 0;
};

/// One device row of a run (frozen identity + the latest computed grid cell).
struct PreflightRunDeviceRow {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::string bucket = "inc"; ///< preflight::bucket_token (go|nogo|warn|inc)
    std::string checks_json;    ///< serialized vector<PreflightDeviceCheck>
    std::int64_t updated_at_ms = 0;
};

class PreflightRunStore {
public:
    explicit PreflightRunStore(pg::PgPool& pool);

    PreflightRunStore(const PreflightRunStore&) = delete;
    PreflightRunStore& operator=(const PreflightRunStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Create a run + its frozen target rows in ONE transaction (run_device seeded
    /// bucket='inc'). Returns false on error.
    bool create_run(const PreflightRunRow& run, const std::vector<preflight::PreflightTarget>& targets);

    /// Run metadata by id; nullopt if absent/error. When `created_by` is non-empty
    /// the read is OWNER-SCOPED at the seam: a not-yours run reads as nullopt, same
    /// as not-found — closes the existence oracle on the result route. Empty
    /// `created_by` = unscoped (internal callers).
    [[nodiscard]] std::optional<PreflightRunRow> get_run(const std::string& run_id,
                                                         const std::string& created_by = "");

    /// A viewer's recent runs (created_by = viewer, or all when `is_admin`),
    /// newest first, capped at `limit`.
    [[nodiscard]] std::vector<PreflightRunRow> list_runs(const std::string& viewer, bool is_admin,
                                                         int limit);

    /// Every `running` run — the runner's per-tick worklist.
    [[nodiscard]] std::vector<PreflightRunRow> list_running();

    /// Frozen target cohort for a run (the denominator).
    [[nodiscard]] std::vector<preflight::PreflightTarget> get_targets(const std::string& run_id);

    /// Stored device grid for a run (complete-run revisit).
    [[nodiscard]] std::vector<PreflightRunDeviceRow> get_devices(const std::string& run_id);

    /// Runner: upsert the whole computed device grid + the summary counts in ONE
    /// transaction (kinder to the pool than per-device leases; atomic snapshot).
    /// Called BEFORE complete_run (compute → persist grid → THEN flip complete).
    bool persist_grid(const std::string& run_id, const std::vector<PreflightRunDeviceRow>& devices,
                      int total, int go, int warn, int nogo, int inc);

    /// Runner: flip a run to complete (compute → persist_grid → THEN this).
    bool complete_run(const std::string& run_id, std::int64_t completed_at_ms);

    /// Runner: delete runs created before `cutoff_ms` (run_device cascades).
    /// Returns rows deleted, or -1 on error.
    int prune_older_than(std::int64_t cutoff_ms);

    /// Delete one run, OWNER-SCOPED at the seam (`created_by` must match;
    /// run_device cascades). Returns true if a row was deleted.
    bool delete_run(const std::string& run_id, const std::string& created_by);

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
