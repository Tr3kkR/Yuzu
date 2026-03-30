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

struct CaptureSourceDef {
    std::string_view name;        // "process", "tcp", "service", "user"
    std::string_view dollar_name; // "Process", "TCP", "Service", "User"
    std::vector<GranularityDef> granularities;
};

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
