#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <vector>

struct sqlite3;

namespace yuzu::server {

/// A single schema migration step.
struct Migration {
    int version;          ///< Target version after this migration runs.
    std::string_view sql; ///< SQL statement(s) to execute.
};

/**
 * Runs sequential schema migrations on a SQLite database.
 *
 * Each store registers its migrations as a vector of {version, sql} pairs.
 * The runner creates a `schema_meta` table, checks the current version,
 * and applies any pending migrations in a transaction.
 *
 * Usage:
 *   MigrationRunner::run(db, "audit_store", {
 *       {1, "CREATE TABLE IF NOT EXISTS ..."},
 *       {2, "ALTER TABLE ... ADD COLUMN ..."},
 *   });
 */
class MigrationRunner {
public:
    /// Run all pending migrations for the named store.
    /// Returns true if all migrations succeeded (or none were needed).
    [[nodiscard]] static bool run(sqlite3* db, std::string_view store_name,
                                  const std::vector<Migration>& migrations);

    /// Get the current schema version for a store. Returns 0 if untracked.
    [[nodiscard]] static int current_version(sqlite3* db, std::string_view store_name);

private:
    static bool ensure_meta_table(sqlite3* db);
    static bool set_version(sqlite3* db, std::string_view store_name, int version);
};

} // namespace yuzu::server
