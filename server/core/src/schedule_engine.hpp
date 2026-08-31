#pragma once

/// @file schedule_engine.hpp
/// Postgres-backed recurring-schedule store (ADR-0009/0065). Schema
/// `schedule_engine`, one table (`schedules`).
///
/// Posture (ADR-0012 §1): AUTHORITATIVE/fail-hard construction — a
/// reachable database whose schema can't migrate/open is a fatal startup
/// error (`startup_failed_`), a posture UPGRADE from the SQLite era, where
/// migration failure was log-only and no caller ever checked an
/// availability flag (there wasn't one). Runtime reads/writes keep their
/// pre-migration plain-container/`std::expected<std::string,std::string>`
/// shapes — this store's consumers (`ScheduleRoutes`, `mcp_server.cpp`,
/// `ScheduleRunner`) are unaffected by this migration by design.
///
/// Backfill: NONE (ADR-0009's 2026-08-25 fresh-start-by-default amendment —
/// no production fleet has ever run a pre-Postgres build of any Yuzu
/// store). The legacy `instructions.db` (shared with the ExecutionTracker/
/// ApprovalManager siblings, ADR-0065) is never read for data; construction
/// logs a one-time "fresh start, no legacy backfill" line, and the caller
/// (`server.cpp`) runs `legacy_sqlite_probe::warn_if_legacy_rows()` over
/// the legacy file so an environment where "no production fleet" turns out
/// to be locally wrong gets a loud signal instead of silent loss.

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
} // namespace yuzu::server::pg

namespace yuzu::server {

struct InstructionSchedule {
    std::string id;
    std::string name;
    std::string definition_id;
    std::string frequency_type;
    int interval_minutes{60};
    std::string time_of_day;
    int day_of_week{0};
    int day_of_month{1};
    std::string scope_expression;
    bool requires_approval{false};
    bool enabled{true};
    int64_t next_execution_at{0};
    int64_t last_executed_at{0};
    int execution_count{0};
    std::string created_by;
    int64_t created_at{0};
    // Canonical JSON object (PR1.5a, schedule_params_parsers.hpp), sorted
    // keys, scalar values only. create_schedule() defaults an empty value to
    // "{}" and re-canonicalizes whatever is supplied, so a row read back
    // from storage always carries a validated canonical blob — never the raw
    // caller-supplied text and never truly empty.
    std::string parameter_values;
};

struct ScheduleQuery {
    std::string definition_id;
    bool enabled_only{false};
};

class ScheduleEngine {
public:
    explicit ScheduleEngine(pg::PgPool& pool);
    ~ScheduleEngine() = default;

    ScheduleEngine(const ScheduleEngine&) = delete;
    ScheduleEngine& operator=(const ScheduleEngine&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Idempotent no-op kept for call-site compatibility — migration now
    /// runs unconditionally inside the constructor (PgMigrationRunner),
    /// unlike the SQLite era where callers invoked this explicitly.
    void create_tables() {}
    void stop();

    std::vector<InstructionSchedule> query_schedules(const ScheduleQuery& q = {}) const;
    std::expected<std::string, std::string> create_schedule(const InstructionSchedule& sched);

    /// Owner-scoped delete (M-01, #1806): `created_by` is REQUIRED (no
    /// default) so a caller cannot accidentally pass an empty principal and
    /// have it silently match every legacy row with an empty created_by —
    /// that would reopen the exact cross-tenant mutation gap this closes.
    /// Returns false for a wrong-owner id exactly like a nonexistent one, so
    /// this cannot be used to probe id existence across owners.
    bool delete_schedule(const std::string& id, const std::string& created_by);

    /// Owner-scoped enable/disable (M-01, #1806) — same required-`created_by`
    /// contract as delete_schedule. Returns true iff a row matched (id AND
    /// created_by), so the route can audit only on an actual change.
    bool set_enabled(const std::string& id, bool enabled, const std::string& created_by);

    std::vector<InstructionSchedule> evaluate_due() const;
    void advance_schedule(const std::string& id);

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
