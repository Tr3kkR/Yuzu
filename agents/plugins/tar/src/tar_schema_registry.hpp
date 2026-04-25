#pragma once

/**
 * tar_schema_registry.hpp -- Capture source definitions for the TAR data warehouse
 *
 * Defines every capture source, its supported granularity tiers (Live, Hourly,
 * Daily, Monthly), typed column schemas per tier, and the DDL + rollup SQL
 * needed to create and maintain the warehouse tables.
 *
 * The $-name convention ($Process_Live, $TCP_Hourly, etc.) maps to snake_case
 * SQLite table names (process_live, tcp_hourly) via a whitelist translation.
 */

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::tar {

// ── Column and table metadata ───────────────────────────────────────────────

struct ColumnDef {
    std::string_view name;
    std::string_view sql_type; // INTEGER, TEXT, REAL
};

enum class RetentionType { kRowCount, kTimeBased };

struct GranularityDef {
    std::string_view suffix;      // "live", "hourly", "daily", "monthly"
    RetentionType retention_type;
    int64_t retention_default;    // row count or seconds
    std::vector<ColumnDef> columns;
};

// ── Per-source OS support metadata (issue #59) ─────────────────────────────
//
// Each capture source declares, per supported operating system, how it
// gathers data and any known constraints. The metadata is read at runtime
// by the TAR `compatibility` action so operators can see exactly what is
// captured on each platform without reading the source.
//
// `kSupported`           -- fully wired and exercised in CI
// `kSupportedConstrained`-- works but with a known limitation (e.g., legacy
//                           Windows API that returns less detail; documented
//                           in `notes`)
// `kPlanned`             -- not yet implemented, but the `capture_method`
//                           field names the planned implementation so the
//                           configuration surface can validate against it
// `kUnsupported`         -- platform cannot supply the data at all (e.g.,
//                           `services` on a kernel that has no service
//                           manager)
enum class OsSupportStatus { kSupported, kSupportedConstrained, kPlanned, kUnsupported };

struct OsSupport {
    std::string_view os;             // "windows", "linux", "macos"
    OsSupportStatus status;
    std::string_view capture_method; // "polling", "etw", "systemctl", "wts",
                                      // "utmpx", "launchctl", "iphlpapi", ...
    std::string_view notes;           // free-form constraint description
};

struct CaptureSourceDef {
    std::string_view name;        // "process", "tcp", "service", "user"
    std::string_view dollar_name; // "Process", "TCP", "Service", "User"
    std::vector<OsSupport> os_support;
    std::vector<GranularityDef> granularities;
};

// ── Per-source capture-method validation (issue #59) ───────────────────────
//
// Returns the list of accepted `capture_method` values for a given source.
// Used by the plugin's `configure` action to reject mistyped or unsupported
// methods (e.g. `etw` for `tcp` on Linux) at write time, instead of
// silently storing a value that the collector ignores.
//
// The accept-list is the union over all OS rows in `os_support` whose
// `status != kUnsupported`. `kPlanned` methods are intentionally accepted
// so an operator can pre-stage configuration ahead of an implementation
// landing.
[[nodiscard]] std::vector<std::string> accepted_capture_methods(std::string_view source_name);

// ── Registry access ─────────────────────────────────────────────────────────

/** Get all registered capture source definitions. */
const std::vector<CaptureSourceDef>& capture_sources();

/**
 * Generate DDL for all typed warehouse tables.
 * Returns a single SQL string containing CREATE TABLE IF NOT EXISTS + indexes.
 */
std::string generate_warehouse_ddl();

/**
 * Translate a $-prefixed table name to its real SQLite table name.
 * e.g. "$Process_Live" -> "process_live", "$TCP_Hourly" -> "tcp_hourly".
 * Returns nullopt if the name is not in the whitelist.
 */
std::optional<std::string> translate_dollar_name(std::string_view dollar_name);

/**
 * Get all valid $-prefixed table names.
 * Used for schema browsing and documentation.
 */
std::vector<std::string> all_dollar_names();

/**
 * Get column names for a given real table name.
 * Returns empty vector if the table is unknown.
 */
std::vector<std::string> columns_for_table(const std::string& real_table_name);

/**
 * Generate rollup SQL for a specific source and target granularity.
 * The SQL is an INSERT INTO ... SELECT that aggregates from the source tier.
 * @param source_name  e.g. "process"
 * @param target_suffix e.g. "hourly"
 * @return SQL string, or empty if rollup is not defined for this combination.
 */
std::string rollup_sql(std::string_view source_name, std::string_view target_suffix);

/**
 * Generate retention SQL for a specific table.
 * Row-count retention: DELETE oldest rows exceeding the limit.
 * Time-based retention: DELETE rows older than the cutoff.
 * @param real_table_name  e.g. "process_live"
 * @param now_epoch        Current epoch seconds (for time-based retention).
 * @return SQL string to execute, or empty if no retention defined.
 */
std::string retention_sql(const std::string& real_table_name, int64_t now_epoch);

} // namespace yuzu::tar
