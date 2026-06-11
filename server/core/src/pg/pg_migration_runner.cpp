#include "pg_migration_runner.hpp"

#include "pg_raii.hpp"

#include <spdlog/spdlog.h>

#include <libpq-fe.h>

#include <cstdlib>
#include <cstring>

namespace yuzu::server::pg {

namespace {

// First key of the two-int advisory-lock pair every runner transaction
// takes; the second key is hashtext(store_name). Transaction-scoped
// (pg_advisory_xact_lock), so a crashed runner can never leave the lock
// behind. 0x79757A75 is "yuzu" read as big-endian ASCII.
//
// Advisory locks are CLUSTER-wide, not per-database: two runners migrating
// the same store name in *different* databases on one Postgres instance
// (e.g. two test binaries against the shared yuzu-ci-postgres container)
// serialize on each other. That is benign — transaction-scoped locks
// release on commit/abort/disconnect, so the worst case is brief
// serialization, never deadlock or cross-database corruption.
constexpr const char* kAdvisoryLockSql =
    "SELECT pg_advisory_xact_lock(2037545589, hashtext($1::text))";

/// One-row, one-param text query helper.
PgResult exec_param(PGconn* conn, const char* sql, const std::string& param) {
    const char* values[] = {param.c_str()};
    return PgResult{
        PQexecParams(conn, sql, 1, nullptr, values, nullptr, nullptr, /*resultFormat=*/0)};
}

/// Version row lookup. Returns 0 when absent, -1 on error. `missing_table_ok`
/// maps SQLSTATE 42P01 (undefined_table — schema_meta not created yet) to 0.
int read_version(PGconn* conn, const std::string& store, bool missing_table_ok) {
    PgResult res =
        exec_param(conn, "SELECT version FROM public.schema_meta WHERE store = $1", store);
    if (res.status() != PGRES_TUPLES_OK) {
        const char* sqlstate = res ? PQresultErrorField(res.get(), PG_DIAG_SQLSTATE) : nullptr;
        if (missing_table_ok && sqlstate && std::strcmp(sqlstate, "42P01") == 0)
            return 0;
        spdlog::error("PgMigrationRunner: version lookup failed for {}: {}", store,
                      PQerrorMessage(conn));
        return -1;
    }
    if (PQntuples(res.get()) < 1)
        return 0;
    // Bounds-checked above (1 row); field 0 exists by construction of the
    // SELECT. PQgetvalue never returns NULL for a valid coordinate.
    return std::atoi(PQgetvalue(res.get(), 0, 0));
}

bool exec_ok(PGconn* conn, const std::string& sql, std::string_view what, std::string_view store) {
    PgResult res{PQexec(conn, sql.c_str())};
    if (!res.ok()) {
        spdlog::error("PgMigrationRunner: {} failed for {}: {}", what, store, PQerrorMessage(conn));
        return false;
    }
    return true;
}

} // namespace

bool PgMigrationRunner::valid_store_name(std::string_view name) {
    if (name.empty() || name.size() > 63)
        return false;
    const auto lower_or_underscore = [](char c) {
        return (c >= 'a' && c <= 'z') || c == '_';
    };
    if (!lower_or_underscore(name.front()))
        return false;
    for (char c : name) {
        if (!lower_or_underscore(c) && !(c >= '0' && c <= '9'))
            return false;
    }
    // Reserved namespaces (Gate 3 arch/qe): "public" would land the store's
    // tables next to public.schema_meta and shadow it via search_path;
    // "information_schema" pollutes a system schema; Postgres itself
    // rejects "pg_*" schemas (42939) but we fail it at validation so the
    // error names the actual rule. Tightening this AFTER a store ships
    // would be a breaking substrate change — hence locked down now, while
    // the substrate has zero consumers.
    if (name == "public" || name == "information_schema" || name.starts_with("pg_"))
        return false;
    return true;
}

bool PgMigrationRunner::ensure_meta_and_schema(PGconn* conn, std::string_view store_name) {
    const std::string store{store_name};
    if (!exec_ok(conn, "BEGIN", "BEGIN (meta)", store))
        return false;
    PgTxn txn{conn};

    // Serialize concurrent runners before the IF NOT EXISTS DDL — two
    // simultaneous CREATE TABLE IF NOT EXISTS can still collide on the
    // catalog unique index and fail one of them spuriously.
    {
        PgResult lock = exec_param(conn, kAdvisoryLockSql, store);
        if (lock.status() != PGRES_TUPLES_OK) {
            spdlog::error("PgMigrationRunner: advisory lock failed for {}: {}", store,
                          PQerrorMessage(conn));
            return false;
        }
    }
    if (!exec_ok(conn,
                 "CREATE TABLE IF NOT EXISTS public.schema_meta ("
                 "  store       TEXT PRIMARY KEY,"
                 "  version     INTEGER NOT NULL,"
                 "  upgraded_at BIGINT NOT NULL)",
                 "CREATE schema_meta", store))
        return false;
    // store_name is validated as [a-z_][a-z0-9_]* by run(); quoted anyway.
    if (!exec_ok(conn, "CREATE SCHEMA IF NOT EXISTS \"" + store + "\"", "CREATE SCHEMA", store))
        return false;
    return txn.commit();
}

int PgMigrationRunner::current_version(PGconn* conn, std::string_view store_name) {
    if (!conn)
        return -1;
    // Read-only: tolerate the meta table not existing yet (0 = untracked)
    // instead of creating it here — keeps this path free of DDL so it can
    // never race another process's CREATE TABLE IF NOT EXISTS.
    return read_version(conn, std::string{store_name}, /*missing_table_ok=*/true);
}

bool PgMigrationRunner::run(PGconn* conn, std::string_view store_name,
                            const std::vector<PgMigration>& migrations) {
    // Null connection is an error even with nothing to do — PR 3 feeds this
    // from Lease::get(), which is nullptr on an empty lease; reporting
    // success there would boot a store against a database it never reached
    // (Gate 2 sec finding: fail-open).
    if (!conn)
        return false;
    if (migrations.empty())
        return true;
    if (!valid_store_name(store_name)) {
        spdlog::error("PgMigrationRunner: invalid store name '{}' — must match "
                      "[a-z_][a-z0-9_]*, max 63 bytes",
                      store_name);
        return false;
    }
    const std::string store{store_name};

    if (!ensure_meta_and_schema(conn, store))
        return false;

    int current = read_version(conn, store, /*missing_table_ok=*/false);
    if (current < 0)
        return false;

    bool any_applied = false;
    for (const auto& m : migrations) {
        if (m.version <= current)
            continue;

        if (!exec_ok(conn, "BEGIN", "BEGIN", store))
            return false;
        PgTxn txn{conn};

        // Per-store advisory lock, then re-read: the loser of a two-server
        // race blocks here until the winner commits, then sees the winner's
        // version and skips.
        {
            PgResult lock = exec_param(conn, kAdvisoryLockSql, store);
            if (lock.status() != PGRES_TUPLES_OK) {
                spdlog::error("PgMigrationRunner: advisory lock failed for {}: {}", store,
                              PQerrorMessage(conn));
                return false;
            }
        }
        const int locked_version = read_version(conn, store, /*missing_table_ok=*/false);
        if (locked_version < 0)
            return false;
        if (m.version <= locked_version) { // another process applied it
            current = locked_version;
            continue; // txn dtor rolls back the empty transaction
        }

        // Transaction-local search_path so the migration's unqualified DDL
        // lands in the store's schema and nothing leaks onto the pooled
        // connection after COMMIT/ROLLBACK.
        if (!exec_ok(conn, "SET LOCAL search_path TO \"" + store + "\", public", "SET search_path",
                     store))
            return false;

        if (!exec_ok(conn, m.sql, "migration v" + std::to_string(m.version), store))
            return false;

        {
            const std::string version_str = std::to_string(m.version);
            const char* values[] = {store.c_str(), version_str.c_str()};
            PgResult res{
                PQexecParams(conn,
                             "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                             "VALUES ($1, $2::int, extract(epoch FROM now())::bigint) "
                             "ON CONFLICT (store) DO UPDATE "
                             "SET version = EXCLUDED.version, upgraded_at = EXCLUDED.upgraded_at",
                             2, nullptr, values, nullptr, nullptr, 0)};
            if (res.status() != PGRES_COMMAND_OK) {
                spdlog::error("PgMigrationRunner: failed to set version {} for {}: {}", m.version,
                              store, PQerrorMessage(conn));
                return false;
            }
        }

        if (!txn.commit()) {
            spdlog::error("PgMigrationRunner: COMMIT failed for {} v{}: {}", store, m.version,
                          PQerrorMessage(conn));
            return false;
        }

        spdlog::info("PgMigrationRunner: {} migrated to v{}", store, m.version);
        any_applied = true;
        current = m.version;
    }

    if (!any_applied)
        spdlog::debug("PgMigrationRunner: {} at v{} (up to date)", store, current);

    return true;
}

} // namespace yuzu::server::pg
