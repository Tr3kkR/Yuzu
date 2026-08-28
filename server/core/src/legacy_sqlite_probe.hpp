#pragma once

/// @file legacy_sqlite_probe.hpp
/// Fresh-start-by-default (ADR-0009 2026-08-25 amendment) detect-and-warn
/// helper, shared by every server store that migrates off its own SQLite
/// file with NO data backfill. `docs/postgres-store-playbook.md`'s Backfill
/// bullet requires this: skip the legacy-file *copy*, but still check
/// whether the file exists and holds operator-authored rows, and `warn` if
/// so — so an environment where "no production fleet has ever run a
/// pre-Postgres build" turns out to be locally wrong gets a loud signal
/// instead of the silent data loss a bare skip would otherwise produce.
/// Modeled on `RuntimeConfigStore::warn_if_legacy_data_present`
/// (`runtime_config_store.cpp`), generalized from that store's single named
/// table to an arbitrary table list so a multi-table store (`DirectorySync`,
/// `PatchManager`) can reuse it directly.
///
/// Never reads column data, never mutates the legacy file, never itself
/// constitutes a backfill — this is detection only.
///
/// No 0600/sidecar hardening here. ADR-0010 §Consequences (a)'s "force 0600
/// before the first read" obligation applies specifically to a legacy file
/// that may hold a PLAINTEXT secret column (`RuntimeConfigStore`,
/// `WebhookStore`); a caller whose legacy table(s) hold no secret material
/// has no such obligation and can use this helper as-is. A future
/// secret-bearing caller should either harden the file itself before
/// calling this, or extend this helper rather than fork it — do not copy
/// `RuntimeConfigStore::warn_if_legacy_data_present`'s 0600 block into a
/// store that doesn't need it.

#include "sqlite_raii.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace yuzu::server::legacy_sqlite_probe {

/// `legacy_db_path` — the retired SQLite file's location (never deleted,
/// never opened read-write, never read for anything beyond a row count).
/// `store_name` — used only in the log line, to attribute the warning.
/// `tables` — every table name to probe; these are CALLER-supplied literals
/// (a store's own fixed schema), never external input, so they are
/// concatenated into the row-count SQL as quoted identifiers rather than
/// bound as parameters (SQL does not allow binding a table name). A table
/// absent from the file (it predates a later SQLite-era migration, or the
/// file is simply not this store's) is silently skipped, not warned on.
///
/// Silent (no log line at all) when: the file does not exist (the ordinary
/// fresh-install case); every probed table is absent; or every present
/// table is empty. Emits one `spdlog::warn` per non-empty table, and one
/// more per table whose existence/count could not be determined (a locked
/// file, corruption, an I/O error) — distinct from "table absent", which
/// says nothing.
inline void warn_if_legacy_rows(const std::filesystem::path& legacy_db_path,
                                std::string_view store_name,
                                const std::vector<std::string_view>& tables) {
    std::error_code ec;
    // is_regular_file, not exists() -- a FIFO/symlink/device node at this path would
    // otherwise reach sqlite3_open_v2() below, which blocks indefinitely on a FIFO with
    // no writer (empirically confirmed: adversarial review, 2026-08-28). Same guard as
    // the established server.cpp::legacy_sqlite_row_count precedent this helper
    // generalizes -- "refuse a FIFO/symlink/device node -- never block on open()".
    const bool is_regular = std::filesystem::is_regular_file(legacy_db_path, ec);
    // is_regular_file's error_code overload does NOT special-case "no such file" the
    // way exists() does (empirically verified on this platform's libstdc++: exists()
    // clears `ec` for ENOENT, is_regular_file does not) -- so a bare `if (ec)` here
    // would misfire on the ordinary fresh-install case, which is exactly the silent
    // path this function must not warn on. Only a REAL check failure (EACCES on the
    // containing directory, not the file itself -- the case this branch exists for)
    // should warn; genuine absence (ENOENT/ENOTDIR: the path itself, or a directory
    // component of it, doesn't exist) stays silent same as exists()'s contract.
    if (ec && ec != std::errc::no_such_file_or_directory && ec != std::errc::not_a_directory) {
        // Real operator-authored legacy rows could exist behind this permission wall
        // undetected; a silent return here is indistinguishable from the unremarkable
        // fresh-install case. Warn instead (empirically found: adversarial review,
        // 2026-08-28).
        spdlog::warn("{}: legacy {} could not be checked ({}) -- verify manually whether "
                    "it holds operator-authored rows that need reapplying",
                    store_name, legacy_db_path.string(), ec.message());
        return;
    }
    if (!is_regular)
        return; // genuine fresh install (or a non-regular path we refuse to open) -- silent

    SqliteDb db;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), db.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK) {
        spdlog::warn("{}: legacy {} exists but could not be opened ({}) -- verify manually "
                    "whether it holds operator-authored rows that need reapplying",
                    store_name, legacy_db_path.string(), sqlite3_errmsg(db.get()));
        return;
    }

    for (std::string_view table : tables) {
        // sqlite3_open_v2 is lazy -- it succeeds even against a file that is not a
        // valid SQLite database at all; the format is only checked on first real
        // access. Check sqlite_master FIRST, distinctly from the row-count query
        // below, so "this file cannot be read as a SQLite database" is never
        // conflated with "this file IS a SQLite database, just without this table"
        // (RuntimeConfigStore::warn_if_legacy_data_present precedent).
        SqliteStmt table_check;
        if (sqlite3_prepare_v2(db.get(),
                               "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", -1,
                               table_check.addr(), nullptr) != SQLITE_OK) {
            spdlog::warn("{}: legacy {} exists but could not be read as a SQLite database ({}) "
                        "-- verify manually whether it holds operator-authored rows that need "
                        "reapplying",
                        store_name, legacy_db_path.string(), sqlite3_errmsg(db.get()));
            return; // whole-file failure -- no other table probe will fare better
        }
        sqlite3_bind_text(table_check.get(), 1, table.data(), static_cast<int>(table.size()),
                          SQLITE_TRANSIENT);
        const int exists_rc = sqlite3_step(table_check.get());
        if (exists_rc == SQLITE_DONE)
            continue; // no such table in this legacy file -- not this store's data, silent
        if (exists_rc != SQLITE_ROW) {
            // SQLITE_BUSY from a concurrent lock-holder, SQLITE_IOERR, SQLITE_CORRUPT, ... —
            // an execution FAILURE, not "no such table", and exactly the case this
            // obligation must not silently wave through.
            spdlog::warn("{}: legacy {} table '{}' could not be checked ({}) -- verify "
                        "manually whether it holds operator-authored rows that need "
                        "reapplying",
                        store_name, legacy_db_path.string(), table, sqlite3_errmsg(db.get()));
            continue;
        }

        // Defense-in-depth (table names are caller literals per this function's
        // contract, never external input, but the identifier is concatenated rather
        // than bound as a parameter -- SQL has no bind syntax for a table name): refuse
        // an embedded double quote rather than emit malformed/unintended SQL.
        if (table.find('"') != std::string_view::npos) {
            spdlog::warn("{}: legacy {} table name '{}' contains a double quote -- refusing "
                        "to probe it (caller bug: table names must be plain identifiers)",
                        store_name, legacy_db_path.string(), table);
            continue;
        }

        SqliteStmt count_stmt;
        const std::string count_sql = "SELECT COUNT(*) FROM \"" + std::string(table) + "\"";
        if (sqlite3_prepare_v2(db.get(), count_sql.c_str(), -1, count_stmt.addr(), nullptr) !=
                SQLITE_OK ||
            sqlite3_step(count_stmt.get()) != SQLITE_ROW) {
            spdlog::warn("{}: legacy {} table '{}' row count could not be read -- verify "
                        "manually whether it holds operator-authored rows that need "
                        "reapplying",
                        store_name, legacy_db_path.string(), table);
            continue;
        }
        const auto count = static_cast<std::size_t>(sqlite3_column_int64(count_stmt.get(), 0));
        if (count > 0)
            spdlog::warn("{}: legacy {} table '{}' holds {} row(s) that will NOT be carried "
                        "over (ADR-0009 fresh-start-by-default) -- reapply manually after this "
                        "boot if still needed",
                        store_name, legacy_db_path.string(), table, count);
    }
}

} // namespace yuzu::server::legacy_sqlite_probe
