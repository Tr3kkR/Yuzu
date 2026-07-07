#pragma once

/// @file vuln_finding_store.hpp
/// Born-on-Postgres store (ADR-0006/0012, schema `vuln_finding_store`) for the
/// CAVM vulnerability-findings + per-agent coverage projection. It is the home
/// for "which CVEs affect which packages on which agent" and the per-agent
/// assessment-coverage tallies the fleet dashboard (PR 6) reads.
///
/// **UNITS — read this first.** Every timestamp column and every `_ms` field in
/// this header is epoch **MILLISECONDS**. The sibling `SoftwareInventoryStore`
/// (ADR-0016) stamps epoch **SECONDS** (`now_secs()`). That is the unit boundary
/// between the two stores: the PR-4 matching engine MUST derive its run timestamp
/// in ms (from `system_clock` → `milliseconds`) and MUST NEVER copy a
/// SoftwareInventoryStore `last_seen`/`first_seen` (seconds) into any `_ms`
/// column here — a 1000× skew would silently mis-resolve every finding.
///
/// Substrate contract (ADR-0008/0012): holds a `pg::PgPool&`, runs its migration
/// at construction on a pinned lease, schema-qualifies every runtime statement,
/// RETURNING is the mutate-and-return idiom, bounded lease acquires everywhere.
/// CONSTRUCTION is fail-CLOSED — a reachable database whose schema can't
/// migrate/open leaves `is_open()` false, which server.cpp wires to
/// `startup_failed_` (refuse to start, same as PreflightRunStore). RUNTIME is
/// fail-soft: a transient lease timeout / query error degrades a read to
/// nullopt/empty and rolls a write back, never blocking a hot path.
///
/// READ POSTURE is AUTHORITATIVE (like SoftwareInventoryStore, ADR-0016 §7): a
/// store/pool/query degrade on the coverage + summary reads surfaces as a
/// distinguishable "degraded" signal, NEVER coerced to an empty/zero value — a
/// PG hiccup on a fleet vuln read must not read as "nothing is vulnerable". The
/// list-read (`query_findings`) returns an empty vector on both no-rows and
/// degrade (the same shape PreflightRunStore::list_runs uses); the callers that
/// need to tell them apart use the three-way / optional reads below.
///
/// DORMANT in this PR: constructed and wired into /readyz + /healthz, but no
/// engine calls `reconcile_agent` yet (PR 4 lands the matching engine).
///
/// Two tables (schema `vuln_finding_store`):
///   * finding        — PK(agent_id, cve_id, package_name); one row per (agent,
///                      CVE, package). `resolved_at_ms IS NULL` == open.
///   * agent_coverage — PK(agent_id); the per-agent assessment tallies + the last
///                      run + feed-sync stamps. KEEP-LAST-GOOD: only an
///                      authoritative reconcile pass overwrites it.
///
/// DATA CLASSIFICATION: findings + coverage are asset / vulnerability-posture data
/// (which CVE affects which package on which agent) — NOT PII and NOT a secret, so
/// there is no behavioural-PII audit tier or SecretCodec envelope on this store.
/// Per-device retention / right-to-erasure of an agent's findings is the
/// cross-store agent-removal work tracked in #1666 (see `delete_agent`), deferred.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
struct PgMigration;
}

namespace yuzu::server {

/// One finding to upsert for an agent. `agent_id` is carried on the parent
/// `AgentReconcile` (this whole batch is for one agent). Nullable fields use
/// `std::optional` so SQL NULL round-trips as absence, never 0.0/"".
///
/// IDENTITY FIELDS MUST BE NUL-FREE. The identity columns (`agent_id`, `cve_id`,
/// `package_name`) are bound through `pg_exec.hpp`'s `exec_params`, which passes
/// each value as a NUL-terminated C string (no explicit length) — a property
/// shared by every born-on-PG store, not unique to this one. An embedded NUL is
/// therefore silently truncated at the first NUL byte, which could collide two
/// distinct identities onto one PK row. The PR-4 producer sanitizes identity
/// fields to be NUL-free before calling `reconcile_agent`; the store ALSO rejects
/// (returns false) any batch whose `agent_id`, `cve_id`, or `package_name`
/// carries an embedded NUL — defence-in-depth, not a trusted-producer assumption.
struct FindingUpsert {
    std::string cve_id;
    std::string package_name;
    std::string status = "potential";        ///< 'potential' | 'vulnerable' (CHECK-enforced)
    std::string package_version;
    std::string ecosystem;
    std::string severity = "unknown";        ///< normalized to the vocab before bind
    std::optional<double> cvss;              ///< nullopt → SQL NULL
    std::optional<std::string> fixed_in;     ///< nullopt → SQL NULL
    std::string confidence = "low";          ///< 'high' | 'low' (CHECK-enforced)
    std::int64_t feed_synced_at_ms = 0;      ///< when the feed row backing this was synced
};

/// One (cve_id, package_name) tuple — the finding identity within an agent.
struct FindingKey {
    std::string cve_id;
    std::string package_name;
};

/// Per-agent coverage tallies written by an AUTHORITATIVE reconcile pass. NOTE:
/// `last_run_at_ms` is NOT here — it is derived in-transaction (the monotonic
/// run_ts) and never caller-supplied. `feed_synced_at_ms` IS caller-supplied.
struct AgentCoverageCounts {
    std::int64_t feed_synced_at_ms = 0;
    int total_packages = 0;
    int potential = 0;
    int vulnerable = 0;
    int assessed_clean = 0;
    int not_assessed = 0;
    int na_no_identity = 0;
    int na_no_version = 0;
    int na_absent = 0;
    int na_os_native = 0;
    int na_low_confidence = 0;
};

/// One reconcile batch for a single agent — the whole result of a PR-4 matching
/// pass. NO caller-supplied run_ts: the store derives a monotonic one in-txn.
///
/// `authoritative` contract (LOAD-BEARING, the B1 fix): true means "this pass
/// fully assessed the WHOLE inventory — packages absent from `findings` are
/// truly resolved, AND `coverage` is ground truth" → the disappear-sweep, the
/// `disposed_clean` delete, and the coverage upsert all move together. false
/// means "suspect / partial read" → ONLY the observed `findings` are refreshed;
/// NO resolve sweep, NO dispose, and the coverage row is left untouched
/// (keep-last-good — a partial read must not clobber coverage to zero). The PR-4
/// engine sets false on a suspect read and MUST NOT call reconcile on a fully
/// degraded read.
struct AgentReconcile {
    std::string agent_id;
    std::vector<FindingUpsert> findings;
    AgentCoverageCounts coverage;
    std::vector<FindingKey> disposed_clean; ///< M1b OVAL-reassessed-clean fold; empty in M1a
    bool authoritative = false;
};

/// One finding row as read back. Nullable columns are `std::optional`.
struct FindingRow {
    std::string agent_id;
    std::string cve_id;
    std::string package_name;
    std::string status;
    std::string package_version;
    std::string ecosystem;
    std::string severity;
    std::optional<double> cvss;
    std::optional<std::string> fixed_in;
    std::string confidence;
    std::int64_t feed_synced_at_ms = 0;
    std::int64_t first_seen_ms = 0;
    std::int64_t last_seen_ms = 0;
    std::optional<std::int64_t> resolved_at_ms; ///< nullopt == open
};

/// Per-agent coverage row as read back.
struct AgentCoverage {
    std::string agent_id;
    std::int64_t last_run_at_ms = 0;
    std::int64_t feed_synced_at_ms = 0;
    int total_packages = 0;
    int potential = 0;
    int vulnerable = 0;
    int assessed_clean = 0;
    int not_assessed = 0;
    int na_no_identity = 0;
    int na_no_version = 0;
    int na_absent = 0;
    int na_os_native = 0;
    int na_low_confidence = 0;
};

/// Three-way coverage read. A query error (Degraded) and a never-correlated
/// agent (NotFound) are DIFFERENT outcomes and must not be conflated as a single
/// nullopt — Degraded must not read as "this agent has never been assessed".
struct CoverageRead {
    enum class Status { Ok, NotFound, Degraded };
    Status status = Status::Degraded;
    AgentCoverage row;
};

/// Fleet-wide vulnerability rollup (PR 6 headline). GLOBAL, NOT scope-filtered —
/// PR 6 must gate it behind the GLOBAL Vuln:Read (ADR-0017), same posture as the
/// software catalogue. Aggregated over agent_coverage + open `finding` rows.
struct FleetVulnSummary {
    std::int64_t agent_count = 0;         ///< rows in agent_coverage
    std::int64_t total_packages = 0;      ///< SUM(total_packages)
    std::int64_t potential_packages = 0;  ///< SUM(potential)
    std::int64_t vulnerable_packages = 0; ///< SUM(vulnerable)
    std::int64_t assessed_clean = 0;      ///< SUM(assessed_clean)
    std::int64_t not_assessed = 0;        ///< SUM(not_assessed)
    std::int64_t open_findings = 0;       ///< COUNT(*) finding WHERE resolved_at_ms IS NULL
    std::int64_t critical_open = 0;       ///< open findings with severity='critical'
    std::int64_t high_open = 0;           ///< open findings with severity='high'
};

/// Filter for `query_findings`. All fields optional; empty/absent match all.
struct FindingQuery {
    std::optional<std::string> status;   ///< 'potential' | 'vulnerable'
    std::optional<std::string> severity; ///< a severity-vocab value
    bool include_resolved = false;       ///< default: open findings only
    int limit = 0;                       ///< <=0 → the store's hard cap
};

class VulnFindingStore {
public:
    /// Borrows the shared pool and runs the `vuln_finding_store` schema migration
    /// on a pinned lease. `is_open()` is false if the lease was empty or the
    /// migration failed (the server fails closed before reaching here).
    explicit VulnFindingStore(pg::PgPool& pool);

    VulnFindingStore(const VulnFindingStore&) = delete;
    VulnFindingStore& operator=(const VulnFindingStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Apply one agent's matching pass in ONE transaction. Sequence (see .cpp):
    /// per-agent advisory lock → derive monotonic run_ts → upsert every finding
    /// (always) → IF authoritative: dispose_clean delete, disappear sweep, and
    /// coverage upsert (all gated together on `authoritative`). Any failed row
    /// aborts the whole batch (no partial write). Returns false on any error /
    /// !is_open / empty agent_id / a batch exceeding the internal findings cap /
    /// an embedded NUL in an identity field.
    ///
    /// UP-2 BACKSTOP on `authoritative`: an authoritative pass whose coverage
    /// reports ZERO `total_packages` against an agent that PREVIOUSLY had state
    /// (prior open findings potential+vulnerable > 0, OR a prior non-zero
    /// total_packages) is treated as NON-authoritative — the sweep / dispose /
    /// coverage-clobber are skipped (keep-last-good), the call still returns true.
    /// The suspect signal is the EMPTY INVENTORY READ (total_packages == 0), NOT
    /// empty findings: a pass with total_packages > 0 and empty findings is a
    /// GENUINELY-PATCHED agent and MUST sweep-resolve its now-fixed findings, so
    /// keying the backstop on findings.empty() would strand patched findings open
    /// forever. This defends the fleet against a PR-4 producer / inventory-read bug
    /// mass-false-resolving every agent on a "whole inventory vanished" read.
    ///
    /// [[nodiscard]]: dropping the bool silently loses a whole agent's batch.
    [[nodiscard]] bool reconcile_agent(const AgentReconcile& r);

    /// Findings for one agent, most-severe first then most-recent. Open-only
    /// unless `q.include_resolved`. Hard-capped regardless of `q.limit`. Returns
    /// an empty vector for BOTH no-rows and degrade (list-read shape) — use the
    /// coverage/summary reads when the caller must distinguish.
    [[nodiscard]] std::vector<FindingRow> query_findings(std::string_view agent_id,
                                                         const FindingQuery& q = {});

    /// Three-way per-agent coverage read (Ok / NotFound / Degraded). AUTHORITATIVE:
    /// a store/pool/query degrade is Status::Degraded, distinct from NotFound.
    [[nodiscard]] CoverageRead get_agent_coverage(std::string_view agent_id);

    /// Fleet vulnerability rollup. AUTHORITATIVE: `std::nullopt` on a
    /// store/pool/query degrade, NEVER a silent zero. GLOBAL (see FleetVulnSummary).
    [[nodiscard]] std::optional<FleetVulnSummary> fleet_summary();

    /// Drop all rows for an agent (both tables) in ONE transaction. Best-effort.
    /// UNWIRED: no fleet-wide agent-removal fanout calls this yet (there is no
    /// central agent-deletion hook that reaches every born-on-PG store; cf.
    /// #1666). Provided so the removal path can adopt it without a schema change,
    /// NOT presented as a delivered removal feature.
    void delete_agent(std::string_view agent_id);

    /// The store's migration set — exposed for tests (white-box schema_meta
    /// rewind / idempotency assertions), like the sibling PG stores.
    [[nodiscard]] static const std::vector<pg::PgMigration>& migrations();

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
