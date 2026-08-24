#pragma once

/// @file policy_store.hpp
/// Compliance definition + status store (ADR-0056, schema `policy_store`) —
/// six operator-authored tables (`policy_fragments`/`policies`/
/// `policy_inputs`/`policy_triggers`/`policy_groups`/`policy_status`) plus one
/// new, purely operational table (`policy_dispatch_state`) that exists only
/// to make `PolicyEvaluator`'s dispatch decision safe across replicas.
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned lease,
/// and schema-qualifies every runtime statement (`policy_store.policies`) —
/// pooled connections carry no per-store search_path. Mutate-and-return uses
/// `RETURNING` (the #1033-banning idiom), never `sqlite3_changes()`.
///
/// Posture (ADR-0012 §1, split by table class — see ADR-0056 "Posture"):
/// operator-authored intent (fragments/policies/inputs/triggers/groups) is
/// AUTHORITATIVE/fail-hard; reads that feed `PolicyEvaluator`'s dispatch
/// claim, a compliance percentage, or a remediation target list are
/// degrade-distinguishable (`PolicyReadError::kDegraded`, never a silent
/// empty) per ADR-0036 — collapsing "the DB could not answer" into "there is
/// nothing to do" on any of those paths reads as false fleet compliance or a
/// remediation that silently fixes nobody. `policy_dispatch_state` is
/// internal-only, never read outside `claim_due_policies`.
///
/// `create_fragment`/`create_policy` write once — there is no update path for
/// a fragment or a policy's own detail rows (only `enable_policy`/
/// `disable_policy` and the entire `policy_status` table mutate after
/// creation). This is why the backfill IDENTITY/LIFECYCLE partition in
/// ADR-0056 is unusually clean: five tables are pure write-once IDENTITY, one
/// column pair (`policies.enabled`/`updated_at`) is LIFECYCLE, and
/// `policy_status` is fully LIFECYCLE.

#include "pg/pg_pool.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

// ── Data types (unchanged shape from the SQLite store) ──────────────────────

struct PolicyFragment {
    std::string id;
    std::string name;
    std::string description;
    std::string yaml_source;
    std::string check_instruction;
    std::string check_compliance;     // CEL expression (stored, evaluated later)
    std::string check_parameters;     // JSON of parameter bindings
    std::string fix_instruction;
    std::string fix_parameters;       // JSON of parameter bindings
    std::string post_check_instruction;
    std::string post_check_compliance;
    std::string post_check_parameters;
    int64_t created_at{0};
    int64_t updated_at{0};
};

struct PolicyTrigger {
    int64_t id{0};
    std::string policy_id;
    std::string trigger_type;  // "interval", "file_change", "event_log", etc.
    std::string config_json;   // type-specific config (e.g. {"interval_seconds": 300})
};

struct PolicyInput {
    std::string policy_id;
    std::string key;
    std::string value;
};

struct PolicyGroupBinding {
    std::string policy_id;
    std::string group_id;
};

struct Policy {
    std::string id;
    std::string name;
    std::string description;
    std::string yaml_source;
    std::string fragment_id;
    std::string scope_expression;
    bool enabled{true};
    int64_t created_at{0};
    int64_t updated_at{0};

    // Populated by query methods (not stored in the policies table directly)
    std::vector<PolicyInput> inputs;
    std::vector<PolicyTrigger> triggers;
    std::vector<std::string> management_groups;
};

struct PolicyAgentStatus {
    std::string policy_id;
    std::string agent_id;
    std::string status;        // "compliant", "non_compliant", "unknown", "fixing", "error"
    int64_t last_check_at{0};
    int64_t last_fix_at{0};
    std::string check_result;  // JSON of last check output
};

struct ComplianceSummary {
    std::string policy_id;
    int64_t compliant{0};
    int64_t non_compliant{0};
    int64_t unknown{0};
    int64_t fixing{0};
    int64_t error{0};
    int64_t total{0};
};

struct FleetCompliance {
    int64_t total_checks{0};     // total (policy, agent) pairs
    int64_t compliant{0};
    int64_t non_compliant{0};
    int64_t unknown{0};
    int64_t fixing{0};
    int64_t error{0};
    double compliance_pct{0.0};  // compliant / total * 100
};

struct PolicyQuery {
    std::string name_filter;
    std::string fragment_filter;
    bool enabled_only{false};
    int limit{100};
};

struct FragmentQuery {
    std::string name_filter;
    int limit{100};
};

/// ADR-0036 degrade marker: a read on a dispatch/compliance-feeding path
/// could not be answered (store not open / pool-acquire timeout / query
/// error) — distinct from a genuinely empty result. Callers must never
/// collapse this into "nothing due" / "nothing non-compliant" / "0% fleet
/// compliance".
enum class PolicyReadError { kDegraded };

/// Prefix for a genuine DB/lease failure on a mutator, so callers (route
/// handlers) can classify 503 (this prefix) vs 400/404/409 (a validation or
/// not-found message, or `kConflictPrefix` from store_errors.hpp) without
/// string-matching arbitrary text. Mirrors `kSwDeployDbErrorPrefix`.
inline constexpr std::string_view kPolicyDbErrorPrefix = "db_error: ";

/// Governance (2026-08-24): originally defined above but never checked
/// anywhere — every mutator route mapped a degraded-store error the same as a
/// validation error (400), leaking the raw internal string into the
/// response body. Mirrors `is_conflict_error`/`strip_conflict_prefix` in
/// store_errors.hpp.
inline bool is_db_error(std::string_view msg) {
    return msg.rfind(kPolicyDbErrorPrefix, 0) == 0;
}

inline std::string_view strip_db_error_prefix(std::string_view msg) {
    if (!is_db_error(msg))
        return msg;
    return msg.substr(kPolicyDbErrorPrefix.size());
}

// ── PolicyStore ──────────────────────────────────────────────────────────────

class PolicyStore {
public:
    explicit PolicyStore(pg::PgPool& pool);

    PolicyStore(const PolicyStore&) = delete;
    PolicyStore& operator=(const PolicyStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// One-time idempotent first-boot backfill from a legacy SQLite
    /// `policies.db` (ADR-0009). Mandatory for the five operator-intent tables;
    /// `policy_status` is copied (not fresh-started, see ADR-0056); the new
    /// `policy_dispatch_state` table is deliberately excluded — it is pure
    /// claim-tracking state invented by this migration, not legacy data.
    /// Fails closed on any error. Idempotent: a fingerprint marker makes a
    /// repeat call (or a second replica racing the same legacy file) a
    /// cheap no-op.
    [[nodiscard]] bool migrate_from_sqlite(const std::filesystem::path& legacy_db_path);

    // ── Fragments ────────────────────────────────────────────────────────
    [[nodiscard]] std::expected<std::string, std::string>
    create_fragment(const std::string& yaml_source);
    [[nodiscard]] std::expected<std::vector<PolicyFragment>, PolicyReadError>
    query_fragments(const FragmentQuery& q = {}) const;
    [[nodiscard]] std::expected<std::optional<PolicyFragment>, PolicyReadError>
    get_fragment(const std::string& id) const;
    [[nodiscard]] bool delete_fragment(const std::string& id);

    /// Extract the operator-facing fragment name from a YAML source string
    /// without parsing the entire fragment. Used by route handlers that
    /// need to attribute denial audits before calling create_fragment().
    /// Returns the displayName, falling back to name, falling back to id,
    /// finally falling back to "" if none are present. Defined as a static
    /// helper because route layers should not own YAML parsing themselves.
    static std::string peek_fragment_name(const std::string& yaml_source);

    // ── Policies ─────────────────────────────────────────────────────────
    [[nodiscard]] std::expected<std::string, std::string>
    create_policy(const std::string& yaml_source);
    [[nodiscard]] std::expected<std::vector<Policy>, PolicyReadError>
    query_policies(const PolicyQuery& q = {}) const;
    [[nodiscard]] std::expected<std::optional<Policy>, PolicyReadError>
    get_policy(const std::string& id) const;
    [[nodiscard]] std::expected<void, std::string> enable_policy(const std::string& id);
    [[nodiscard]] std::expected<void, std::string> disable_policy(const std::string& id);
    [[nodiscard]] bool delete_policy(const std::string& id);

    // ── Compliance tracking ──────────────────────────────────────────────
    [[nodiscard]] std::expected<void, std::string>
    update_agent_status(const std::string& policy_id, const std::string& agent_id,
                        const std::string& status, const std::string& check_result = "");
    [[nodiscard]] std::expected<std::optional<PolicyAgentStatus>, PolicyReadError>
    get_agent_status(const std::string& policy_id, const std::string& agent_id) const;
    [[nodiscard]] std::expected<std::vector<PolicyAgentStatus>, PolicyReadError>
    get_policy_agent_statuses(const std::string& policy_id) const;
    [[nodiscard]] std::expected<ComplianceSummary, PolicyReadError>
    get_compliance_summary(const std::string& policy_id) const;
    [[nodiscard]] std::expected<FleetCompliance, PolicyReadError> get_fleet_compliance() const;

    // ── Cache invalidation ───────────────────────────────────────────────
    /// Reset all agent statuses to 'unknown' for a specific policy, forcing
    /// re-check. Returns the number of agent statuses invalidated.
    [[nodiscard]] std::expected<int64_t, std::string>
    invalidate_policy(const std::string& policy_id);

    /// Reset all agent statuses to 'unknown' across ALL policies. Returns the
    /// total number of agent statuses invalidated.
    [[nodiscard]] std::expected<int64_t, std::string> invalidate_all_policies();

    // ── Multi-replica dispatch claim (ADR-0056 "headline decision") ────────
    /// Single-sweeper CLAIM: under `pg_try_advisory_xact_lock('policy_store:
    /// dispatch')`, sweeps stranded `fixing` rows (`last_fix_at` older than
    /// `fixing_stale_seconds`) back to `unknown`, then claims every enabled
    /// policy whose interval has elapsed (durable in `policy_dispatch_state`,
    /// replacing the evaluator's old in-memory `last_eval_`) and returns the
    /// claimed policies fully loaded. Lock not acquired -> `{}` (empty, Ok —
    /// another replica is claiming this tick, the normal skip). A genuine DB
    /// error -> `unexpected` — the caller (`PolicyEvaluator::dispatch_due`)
    /// MUST skip the tick on this, never treat it as "nothing due".
    [[nodiscard]] std::expected<std::vector<Policy>, std::string>
    claim_due_policies(int64_t now, int64_t default_interval_seconds,
                       int64_t fixing_stale_seconds);

    /// Unconditionally stamps `policy_dispatch_state.last_dispatched_at` for
    /// a manual, operator-triggered dispatch (`PolicyEvaluator::evaluate_now`)
    /// — no advisory lock, no WHERE-guard, no interval check (evaluate_now
    /// deliberately bypasses the interval). Without this, a manual dispatch
    /// leaves no durable record, so the very next automatic tick's
    /// claim_due_policies sees an unclaimed policy (no row = the fresh-INSERT
    /// branch, which always succeeds regardless of the WHERE guard) and
    /// re-dispatches immediately — a duplicate check within seconds of the
    /// manual one, found in testing (the interval-throttle regression
    /// ADR-0056's removal of the in-memory last_eval_ would otherwise cause).
    [[nodiscard]] std::expected<void, std::string> record_dispatch(const std::string& policy_id,
                                                                    int64_t now);

private:
    pg::PgPool& pool_;
    bool open_{false};

    // Fleet compliance cache (recomputed at most every 60s). A plain mutex
    // (not the SQLite-era shared_mutex) since the pool itself provides real
    // concurrency — this only protects the two cache fields.
    mutable std::mutex cache_mtx_;
    mutable FleetCompliance cached_fleet_compliance_;
    mutable std::chrono::steady_clock::time_point fleet_compliance_last_computed_{};
    static constexpr auto kFleetComplianceCacheTtl = std::chrono::seconds(60);

    static std::string generate_id();

    // Compute fleet compliance fresh from the DB. Returns kDegraded on a
    // read failure — the cache is never populated from a degraded read.
    std::expected<FleetCompliance, PolicyReadError> compute_fleet_compliance() const;
};

} // namespace yuzu::server
