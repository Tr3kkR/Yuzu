#pragma once

/// @file execution_tracker.hpp
/// Postgres-backed execution-history store (ADR-0009/0065). Schema
/// `execution_tracker`, two tables (`executions`, `agent_exec_status`).
///
/// Posture (ADR-0012 §1): AUTHORITATIVE/fail-hard construction — a
/// reachable database whose schema can't migrate/open is a fatal startup
/// error (`startup_failed_`), a posture UPGRADE from the SQLite era, where
/// migration failure set `migration_ok_ = false` but `server.cpp` never
/// checked it (the shared `InstructionDbPool`'s own `is_open()` was the
/// only thing `/readyz` keyed on). Runtime reads/writes keep their
/// pre-migration plain-container/`std::expected<std::string,std::string>`
/// shapes — this store's consumers (gRPC `AgentServiceImpl`, REST v1,
/// legacy REST, MCP, dashboard, `ScheduleRunner`) are unaffected by this
/// migration.
///
/// Backfill: NONE (ADR-0009's 2026-08-25 fresh-start-by-default amendment).
/// The legacy `instructions.db` (shared with the ScheduleEngine/
/// ApprovalManager siblings, both already migrated — ADR-0065) is never
/// read for data; construction logs a one-time "fresh start, no legacy
/// backfill" line, and the caller (`server.cpp`) runs
/// `legacy_sqlite_probe::warn_if_legacy_rows()` over the legacy file so an
/// environment where "no production fleet" turns out to be locally wrong
/// gets a loud signal instead of silent loss. This is the LAST of the 7
/// Wave-4 SQLite components — `InstructionDbPool` is deleted once this
/// store moves.

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
} // namespace yuzu::server::pg

namespace yuzu::server {

class ExecutionEventBus;

struct Execution {
    std::string id;
    std::string definition_id;
    std::string status;
    std::string scope_expression;
    std::string parameter_values;
    std::string dispatched_by;
    int64_t dispatched_at{0};
    int agents_targeted{0};
    int agents_responded{0};
    int agents_success{0};
    int agents_failure{0};
    int64_t completed_at{0};
    std::string parent_id;
    std::string rerun_of;
    /// Most recent non-empty agent error_detail for this execution. Populated
    /// only when the caller passes `ExecutionQuery::include_error_detail =
    /// true` (LIST fragment) or via `get_execution(id)` which always opts in.
    /// **PII-adjacent: contains agent stderr** — paths, hostnames, env values,
    /// possibly customer data captured from a broken plugin invocation. Gate
    /// behind `perm_fn(req, res, "Execution", "Read")` before serializing to
    /// any caller (mirrors mcp_server.cpp:get_execution_status).
    std::string last_error_detail;
};

struct ExecutionQuery {
    std::string definition_id;
    std::string status;
    /// #1634: restricts to executions dispatched by this exact principal.
    /// Empty (the default) is unrestricted. Used by MCP `list_executions`
    /// for a management-group-confined caller — executions carry no single
    /// `agent_id` to filter by (they fan out to many), so "own dispatches
    /// only" is the cheap, provably-safe confinement until a real per-row
    /// visible-agent-intersection check exists (that would need a
    /// per-execution agent-status lookup per row — an N+1 pattern ADR-0017
    /// INV-10 calls out as a latency/DoS surface, not something to add
    /// silently inside a LIST route).
    std::string dispatched_by;
    int limit{100};
    /// When true, populate `Execution::last_error_detail` via a correlated
    /// subquery on `agent_exec_status`. Default false because most callers
    /// (health probes, metrics ticks, server.cpp:1727 with limit=1000) do
    /// not consume the field, and the per-row subquery cost amortises
    /// poorly on hot paths (arch-B2). Set true only on the executions
    /// LIST fragment, which renders a per-row error preview.
    bool include_error_detail{false};
};

struct ExecutionSummary {
    std::string id;
    std::string status;
    int agents_targeted{0};
    int agents_responded{0};
    int agents_success{0};
    int agents_failure{0};
    int progress_pct{0};
};

struct AgentExecStatus {
    std::string agent_id;
    std::string status;
    int64_t dispatched_at{0};
    int64_t first_response_at{0};
    int64_t completed_at{0};
    int exit_code{0};
    std::string error_detail;
    /// CC-07 plugin→host typed result status (agent.proto CommandResponse
    /// .plugin_result_status, mirrors YuzuResultStatus from
    /// sdk/include/yuzu/plugin.h). 0 (PLUGIN_RESULT_UNDECLARED) for legacy
    /// rows and for any response whose plugin never reported a typed status.
    int plugin_result_status{0};
};

// ── Execution statistics (capability 1.9) ────────────────────────────

struct AgentExecutionStats {
    std::string agent_id;
    int64_t total_executions{0};
    int64_t success_count{0};
    int64_t failure_count{0};
    double success_rate{0.0};
    double avg_duration_seconds{0.0};
    int64_t last_execution_at{0};
};

struct DefinitionExecutionStats {
    std::string definition_id;
    int64_t total_executions{0};
    int64_t total_agents{0};
    double success_rate{0.0};
    double avg_duration_seconds{0.0};
};

struct FleetExecutionSummary {
    int64_t total_executions{0};
    int64_t executions_today{0};
    int64_t active_agents{0};
    double overall_success_rate{0.0};
    double avg_duration_seconds{0.0};
};

struct ExecutionStatsQuery {
    std::string agent_id;
    std::string definition_id;
    int64_t since{0};
    int64_t until{0};
    int limit{50};
};

/// HA WS-1(1b), ADR-2002 section 5. Outcome of a `command_execution`
/// correlation-table retention pass. Mirrors `SessionStore::ReapOutcome`'s
/// shape (clock-guarded-retention routed concern) — `clock_anomaly` true
/// means the pass declined due to an implausible DB `now()` reading, not
/// that rows were deleted.
struct CommandExecutionReapOutcome {
    int deleted{0};
    bool clock_anomaly{false};
};

class ExecutionTracker {
public:
    explicit ExecutionTracker(pg::PgPool& pool);
    ~ExecutionTracker() = default;

    ExecutionTracker(const ExecutionTracker&) = delete;
    ExecutionTracker& operator=(const ExecutionTracker&) = delete;

    /// Idempotent no-op kept for call-site compatibility — migration now
    /// runs unconditionally inside the constructor (PgMigrationRunner),
    /// unlike the SQLite era where callers invoked this explicitly.
    void create_tables() {}

    /// PR 3 — attach a per-execution SSE bus. When set, every mutating call
    /// (update_agent_status, refresh_counts, mark_cancelled) publishes a
    /// transition event onto the bus's per-execution channel. The bus is
    /// owned by the server; the tracker only borrows it. nullptr disables
    /// publishing — used by harnesses that don't exercise SSE.
    void set_event_bus(ExecutionEventBus* bus) { event_bus_ = bus; }

    // Query
    std::vector<Execution> query_executions(const ExecutionQuery& q = {}) const;
    std::optional<Execution> get_execution(const std::string& id) const;
    ExecutionSummary get_summary(const std::string& id) const;
    std::vector<AgentExecStatus> get_agent_statuses(const std::string& execution_id) const;
    std::vector<Execution> get_children(const std::string& parent_id) const;

    // Mutation
    std::expected<std::string, std::string> create_execution(const Execution& exec);
    void update_agent_status(const std::string& execution_id, const AgentExecStatus& status);
    void refresh_counts(const std::string& execution_id);

    /// PR 2: set agents_targeted post-creation. Used by the workflow execute
    /// handler which now creates the execution row BEFORE dispatch (to thread
    /// execution_id into cmd_dispatch and close the FAST-agent race UP2-4),
    /// then updates `agents_targeted` once dispatch confirms how many agents
    /// the command actually reached. Returns false on a pool/query failure
    /// (governance PR review, 2026-08-31) — the row never learns its real
    /// agent count and can never reach refresh_counts's all-responded
    /// threshold, wedging it at "running"; callers should log/surface this.
    /// `[[nodiscard]]` (scoped re-review, cpp-expert) matches this
    /// codebase's own convention for a must-check success signal
    /// (`AuditStore::log`) — a future call site silently discarding this
    /// return would reintroduce the exact bug this fix closes.
    [[nodiscard]] bool set_agents_targeted(const std::string& execution_id, int agents_targeted);

    std::expected<std::string, std::string> create_rerun(const std::string& original_id,
                                                         const std::string& user, bool failed_only);

    /// Returns false on a pool/query failure (governance PR review,
    /// 2026-08-31) — the execution was NOT actually cancelled; callers must
    /// not report success (an audit "success" row or an HTTP 200) on a
    /// false return. `[[nodiscard]]` for the same reason as
    /// `set_agents_targeted` above.
    [[nodiscard]] bool mark_cancelled(const std::string& id, const std::string& user);

    // Statistics (capability 1.9)
    std::vector<AgentExecutionStats> get_agent_statistics(const ExecutionStatsQuery& q = {}) const;
    std::vector<DefinitionExecutionStats> get_definition_statistics(const ExecutionStatsQuery& q = {}) const;
    FleetExecutionSummary get_fleet_summary(int64_t since = 0) const;

    // ── Command <-> execution correlation (HA WS-1(1b), ADR-2002 section 5) ──
    //
    // Replaces AgentServiceImpl's former in-process `cmd_execution_ids_` map.
    // That map was replica-local: a command dispatched on one server instance
    // populated it only in that process's memory, so a CommandResponse that
    // landed on a DIFFERENT gateway-fronted replica found no mapping and
    // silently dropped the correlation (no responses.execution_id stamp, no
    // executions-drawer SSE event, no tracker-counter advance for that
    // response) — exactly the cross-instance correlation hazard ADR-2002
    // section 5 names `cmd_execution_ids_` as a required PG migration to close.

    /// Records (or clears) a command_id -> execution_id mapping. Last-write-
    /// wins on a repeated command_id, matching the former map's `operator[]=`
    /// semantics. An empty `execution_id` deletes any existing mapping (the
    /// former map's explicit-clear branch; no current caller exercises it).
    /// Best-effort by design: a write failure degrades OBSERVABILITY for
    /// this one command — the executions drawer misses its agent-transition
    /// events — it never FAILS the dispatch that is calling this
    /// (record_execution_id / server.cpp's command_dispatch_fn calls this
    /// BEFORE the RPC, UP2-4; the return value is best-effort telemetry for
    /// the caller to count, not a signal to act on).
    ///
    /// It DOES have a bounded worst-case DELAY: a single attempt at
    /// `kWriteTimeout` (no retry — deliberately NOT `update_agent_status`'s
    /// retry-once shape, because that call sits on the async gateway-
    /// response path while this one sits on the SYNCHRONOUS pre-RPC dispatch
    /// path; a second attempt here would double the worst-case block on the
    /// calling worker thread — REST/dashboard/MCP dispatch, or a background
    /// runner such as ScheduleRunner/PreflightRunner/PolicyEvaluator,
    /// anything feeding the shared CommandDispatchFn closure — under
    /// sustained pool contention). Returns false on failure so the caller can count a
    /// degrade metric; a caller MUST NOT fail or delay dispatch on a false
    /// return (governance Gate 4 unhappy-path UP-1/UP-11, Gate 3 performance
    /// review — the prior wording here claimed zero delay, which was false).
    [[nodiscard]] bool record_command_execution(const std::string& command_id,
                                                const std::string& execution_id);

    /// Resolves a previously-recorded mapping. Returns nullopt for an unknown
    /// command_id (out-of-band dispatch, a reaped/aged-out mapping, or a
    /// degraded read) — callers treat nullopt exactly like the former map's
    /// find()==end() branch: nothing to publish, not an error.
    /// NON-DESTRUCTIVE: a lookup never deletes the row. HF-1 (multi-agent
    /// fan-out): one command_id is dispatched to N agents, each sending its
    /// own response against the same command_id — deleting on the first
    /// response would strand agents 2..N with no execution_id to stamp.
    /// `degrade_reason`, when non-null, is set to "pool_exhausted" or
    /// "query_failed" iff the nullopt return is a STORE DEGRADE rather than
    /// a genuine miss (adversarial review Should-fix, PR #3780: previously
    /// indistinguishable from an ordinary out-of-band-dispatch/aged-out
    /// miss, which is the common case on every CommandResponse — a
    /// sustained pool-exhaustion degrade on this hot path had no signal
    /// pointing at it specifically). Left untouched on success or a
    /// genuine miss; callers should only inspect it when the return is
    /// nullopt.
    [[nodiscard]] std::optional<std::string>
    lookup_execution_id(const std::string& command_id, std::string* degrade_reason = nullptr) const;

    /// Clock-guarded retention sweep for the `command_execution` table
    /// (routed concern "Clock-guarded retention", CLAUDE.md). Mirrors
    /// `SessionStore::reap_expired`'s shape: an advisory lock taken as its
    /// own statement, DB `now()` read once in-SQL under that lock (so the
    /// cutoff, the anchor comparison, and the anchor update share one clock
    /// domain), a persisted+sanitised anchor, forward- and backward-anomaly
    /// decline, and an unconditional per-pass cap — copy the SHAPE, never the
    /// constants (this table's window/cap are tuned to it, not borrowed from
    /// `session_store`'s). Missing-anchor decision: PROCEED on the first pass
    /// (`ResultSetStore`'s answer, same choice `SessionStore` made) — a
    /// mapping is a regenerable observability aid, not compliance evidence,
    /// so a from-boot skewed clock deleting a batch of already-consumed
    /// mappings is an acceptable worst case.
    [[nodiscard]] std::expected<CommandExecutionReapOutcome, std::string>
    reap_command_execution_mappings();

    /// Whether the store is usable (schema migrated). False after a failed
    /// migration — feeds the `/readyz` probe so a broken execution-history
    /// schema fails closed instead of serving errors (or silently wedging
    /// every execution at `dispatched`) behind a green light.
    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Alias kept for calling-code continuity across the migration —
    /// `schema_ok()` and `is_open()` mean the same thing now that there is
    /// no separate borrowed-handle-vs-migration-applied distinction to make
    /// (the SQLite era needed both: `db_ != nullptr` for "the pool is still
    /// open" and `migration_ok_` for "this store's own migration succeeded
    /// on that shared handle").
    [[nodiscard]] bool schema_ok() const noexcept { return open_; }

private:
    /// One attempt at `refresh_counts`'s aggregate recompute + conditional
    /// terminal transition + SSE publish. Returns false on a bounded-timeout
    /// abandon (row-lock contention) or a lease-acquire failure; `true`
    /// otherwise, including the ordinary "nothing changed" case. See
    /// `refresh_counts`'s retry-and-log wrapper for why this is split out.
    bool refresh_counts_once(const std::string& execution_id);

    /// One attempt at `update_agent_status`'s upsert + agent-transition SSE
    /// publish. Returns false on a lease-acquire failure or a query failure;
    /// `true` otherwise. See `update_agent_status`'s retry-and-log wrapper.
    bool upsert_agent_status_once(const std::string& execution_id, const AgentExecStatus& s);

    pg::PgPool& pool_;
    bool open_{false};
    /// Borrowed — owned by the server. nullptr = no SSE publishing.
    ExecutionEventBus* event_bus_{nullptr};
};

} // namespace yuzu::server
