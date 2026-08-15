#include "notification_store.hpp"
#include "sqlite_raii.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>
#include <yuzu/metrics.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "notification_store";

// Bounded acquires (ADR-0012 §2). create() is called from agent-facing
// gRPC/response-handling code (agent_service_impl.cpp) on enrollment and
// execution-failure events — not a tight per-heartbeat hot path, but still
// short enough that a saturated pool never stalls that thread. Reads/other
// writes are dashboard HTTP handlers and can wait a little longer.
constexpr std::chrono::milliseconds kCreateAcquireTimeout{500};
constexpr std::chrono::milliseconds kReadAcquireTimeout{2000};
constexpr std::chrono::milliseconds kWriteAcquireTimeout{2000};
constexpr std::chrono::milliseconds kBackfillTxnTimeout{60000};

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so both tables land in `notification_store`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE notifications ("
         "  id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         "  ts_ms     BIGINT NOT NULL,"
         "  level     TEXT NOT NULL DEFAULT 'info',"
         "  title     TEXT NOT NULL,"
         "  message   TEXT NOT NULL DEFAULT '',"
         "  read      BOOLEAN NOT NULL DEFAULT FALSE,"
         "  dismissed BOOLEAN NOT NULL DEFAULT FALSE);"
         "CREATE INDEX notifications_read_ts_idx ON notifications (read, ts_ms);"
         "CREATE INDEX notifications_ts_id_idx ON notifications (ts_ms DESC, id DESC);"
         "CREATE TABLE notification_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"},
    };
    return kMigrations;
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

bool to_bool(const char* s) { return s != nullptr && s[0] == 't'; }

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

Notification row_to_notification(PGresult* res, int row) {
    Notification n;
    int c = 0;
    n.id = to_i64(PQgetvalue(res, row, c++));
    n.timestamp = to_i64(PQgetvalue(res, row, c++));
    n.level = PQgetvalue(res, row, c++);
    n.title = PQgetvalue(res, row, c++);
    n.message = PQgetvalue(res, row, c++);
    n.read = to_bool(PQgetvalue(res, row, c++));
    n.dismissed = to_bool(PQgetvalue(res, row, c++));
    return n;
}

// ── Legacy (SQLite) backfill — ADR-0009, mandatory ───────────────────────────
//
// "Local source absence never creates terminal migration state on its own"
// (docs/postgres-store-playbook.md, ADR-0040 round 3, #2697). A process that
// finds no local legacy `notifications.db` cannot tell "genuine fresh
// install" from "a sibling replica holds the real one" — stamping the SHARED
// `backfill_complete` marker from that observation alone would let a fileless
// replica permanently foreclose migration for a sibling that boots later
// with the real file still on disk. Right-sized port of `RbacStore`'s
// post-#2703 fix (`rbac_store.cpp`) for this store's small, single-table,
// single-shot legacy dataset: the marker and a fingerprint of the migrated
// content are always stamped together, in the SAME transaction as the row
// backfill itself (simpler than RbacStore's multi-transaction shape — a lost
// fingerprint-stamp race here rolls back the WHOLE backfill atomically, so
// there is no "already-committed, needs manual reconciliation" case to
// document).
constexpr const char* kSourcelessFingerprint = "sourceless";

// Length-prefixed ("<byte-length>:<bytes>") so two different field sequences
// can never encode to the same preimage regardless of what bytes they
// contain — title/message are free text with no charset restriction
// (governance re-review precedent: RbacStore's original unescaped-delimiter
// canonicalization collided on crafted input, PR #2703).
void append_field(std::string& out, std::string_view f) {
    out += std::to_string(f.size());
    out += ':';
    out.append(f.data(), f.size());
}
void append_field(std::string& out, std::int64_t v) { append_field(out, std::to_string(v)); }

// Returns nullopt only on an EVP_Digest failure (essentially unreachable for
// SHA-256) — the contract stays fail-closed; a caller must never treat an
// empty-string fingerprint as valid.
std::optional<std::string> sha256_hex(std::string_view in) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return std::nullopt;
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

struct LegacyNotification {
    std::int64_t id{0};
    std::int64_t timestamp{0};
    std::string level;
    std::string title;
    std::string message;
    std::int64_t read{0};
    std::int64_t dismissed{0};
};

struct LegacySnapshot {
    std::vector<LegacyNotification> rows; // read ORDER BY id — already unique + deterministic
};

// nullopt means "could not determine" (a genuine prepare/step error),
// distinct from `false` ("determined the table is absent") — callers must
// treat nullopt as a read failure, never coerce it to "absent".
std::optional<bool> legacy_has_table(sqlite3* db, const char* table) {
    SqliteStmt s;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", -1,
                           s.addr(), nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(s.get(), 1, table, -1, SQLITE_STATIC);
    const int rc = sqlite3_step(s.get());
    if (rc == SQLITE_ROW)
        return true;
    if (rc == SQLITE_DONE)
        return false;
    return std::nullopt;
}

std::string sqlite_text(sqlite3_stmt* s, int col) {
    const auto* v = sqlite3_column_text(s, col);
    return v ? std::string(reinterpret_cast<const char*>(v),
                           static_cast<std::size_t>(sqlite3_column_bytes(s, col)))
             : std::string{};
}

// Reads every row from an ALREADY-OPEN legacy connection already known to
// have a `notifications` table. Fails closed (nullopt) on any partial/
// corrupt read.
std::optional<LegacySnapshot> read_legacy_snapshot(sqlite3* legacy) {
    SqliteStmt s;
    if (sqlite3_prepare_v2(legacy,
                           "SELECT id, timestamp, level, title, message, read, dismissed "
                           "FROM notifications ORDER BY id",
                           -1, s.addr(), nullptr) != SQLITE_OK)
        return std::nullopt;
    LegacySnapshot snap;
    for (;;) {
        const int rc = sqlite3_step(s.get());
        if (rc == SQLITE_DONE)
            break;
        if (rc != SQLITE_ROW)
            return std::nullopt;
        LegacyNotification r;
        r.id = sqlite3_column_int64(s.get(), 0);
        r.timestamp = sqlite3_column_int64(s.get(), 1);
        r.level = sqlite_text(s.get(), 2);
        r.title = sqlite_text(s.get(), 3);
        r.message = sqlite_text(s.get(), 4);
        r.read = sqlite3_column_int64(s.get(), 5);
        r.dismissed = sqlite3_column_int64(s.get(), 6);
        snap.rows.push_back(std::move(r));
    }
    return snap;
}

std::string canonicalize_legacy_snapshot(const LegacySnapshot& snap) {
    std::string canon = "notification-legacy-fingerprint-v1\n";
    for (const auto& r : snap.rows) {
        append_field(canon, r.id);
        append_field(canon, r.timestamp);
        append_field(canon, r.level);
        append_field(canon, r.title);
        append_field(canon, r.message);
        append_field(canon, r.read);
        append_field(canon, r.dismissed);
    }
    return canon;
}

std::optional<std::string> fingerprint_legacy_snapshot(const LegacySnapshot& snap) {
    const auto hash = sha256_hex(canonicalize_legacy_snapshot(snap));
    if (!hash)
        return std::nullopt;
    return "v1:" + *hash;
}

// Path-based convenience for the holder-side verification call site (which
// has no already-open connection to reuse): opens read-only, probes for
// corruption, and either returns the sourceless sentinel (no `notifications`
// table — same "nothing to protect" class as no local file at all) or reads
// a full snapshot and fingerprints it via the exact same function the real
// migration path uses. Returns nullopt only on a corrupt/unreadable file or
// a snapshot read failure — the caller MUST fail closed on that, never treat
// it as sourceless-equivalent.
std::optional<std::string> legacy_notification_fingerprint(const std::filesystem::path& legacy_db_path) {
    SqliteDb legacy;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_exec(legacy.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    {
        SqliteStmt probe;
        if (sqlite3_prepare_v2(legacy.get(), "SELECT count(*) FROM sqlite_master", -1, probe.addr(),
                               nullptr) != SQLITE_OK ||
            sqlite3_step(probe.get()) != SQLITE_ROW)
            return std::nullopt;
    }
    const auto has_notifications = legacy_has_table(legacy.get(), "notifications");
    if (!has_notifications)
        return std::nullopt; // genuine read error, NOT "no notifications table"
    if (!*has_notifications)
        return std::string(kSourcelessFingerprint);

    const auto snap = read_legacy_snapshot(legacy.get());
    if (!snap)
        return std::nullopt;
    return fingerprint_legacy_snapshot(*snap);
}

} // namespace

NotificationStore::NotificationStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("NotificationStore: no database connection at construction ({})",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("NotificationStore: schema migration failed");
        return;
    }
    open_ = true;
}

bool NotificationStore::migrate_from_sqlite_impl(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    // Marker + fingerprint are ALWAYS stamped together, in the SAME
    // transaction as the row backfill (the fresh-migration call site below)
    // or alone (the sourceless call sites). Monotonic-promotion upsert,
    // matching RbacStore/AuditStore's fixed reference: a real fingerprint
    // may promote a stored "sourceless" value; a stored real value is never
    // overwritten by anyone; a writer whose value already equals what's
    // stored counts as success. RETURNING + PQntuples() (not PQcmdTuples on
    // a DO NOTHING) reads "did this call's value end up as the stored one".
    const auto stamp_markers = [](PGconn* c, std::string_view source_fingerprint) -> bool {
        pg::PgResult mk = pg::exec_params(
            c,
            "INSERT INTO notification_store.notification_meta (key, value) VALUES "
            "('backfill_complete', $1) ON CONFLICT (key) DO NOTHING",
            std::vector<std::string>{std::to_string(now_secs())});
        if (mk.status() != PGRES_COMMAND_OK) {
            spdlog::error("NotificationStore: migrate_from_sqlite: marker stamp failed: {}",
                          PQerrorMessage(c));
            return false;
        }
        pg::PgResult fp = pg::exec_params(
            c,
            "INSERT INTO notification_store.notification_meta (key, value) VALUES "
            "('backfill_source_fingerprint', $1) ON CONFLICT (key) DO UPDATE SET "
            "value = EXCLUDED.value WHERE notification_store.notification_meta.value = "
            "'sourceless' OR notification_store.notification_meta.value = EXCLUDED.value "
            "RETURNING value",
            std::vector<std::string>{std::string(source_fingerprint)});
        if (fp.status() != PGRES_TUPLES_OK) {
            spdlog::error(
                "NotificationStore: migrate_from_sqlite: source-fingerprint stamp failed: {}",
                PQerrorMessage(c));
            return false;
        }
        if (PQntuples(fp.get()) == 0 && source_fingerprint != kSourcelessFingerprint) {
            spdlog::error(
                "NotificationStore: migrate_from_sqlite: lost the race to record this "
                "backfill's own source fingerprint — a DIFFERENT real fingerprint already "
                "stamped backfill_source_fingerprint concurrently. Rolling back this whole "
                "backfill attempt (single-transaction — nothing committed); a retry on the "
                "next boot will find the marker present and holder-side-verify normally.");
            return false;
        }
        // A sourceless stamp losing this same race is NOT an error: whichever
        // writer's "sourceless" value won is the same value this call would
        // have written.
        return true;
    };
    const auto stamp_complete_alone = [&](std::string_view source_fingerprint) -> bool {
        return pool_.with_txn_for(kBackfillTxnTimeout, [&](PGconn* c) -> bool {
            return stamp_markers(c, source_fingerprint);
        });
    };

    // Non-fatal on failure — logged for an operator to clean up manually
    // (matches AuditStore/RbacStore's equivalent). Probes for an unused
    // destination rather than trusting the clock alone to be unique
    // (std::filesystem::rename silently replaces an existing destination).
    const auto move_legacy_aside = [](const std::filesystem::path& path) {
        std::filesystem::path aside;
        for (int suffix = 0;; ++suffix) {
            aside = path;
            aside += ".migrated-" + std::to_string(now_secs());
            if (suffix > 0)
                aside += "-" + std::to_string(suffix);
            std::error_code exists_ec;
            if (!std::filesystem::exists(aside, exists_ec))
                break;
        }
        std::error_code mv_ec;
        std::filesystem::rename(path, aside, mv_ec);
        if (mv_ec)
            spdlog::warn("NotificationStore: migrate_from_sqlite: could not move legacy {} "
                         "aside ({}); it is safe to archive/remove manually",
                         path.string(), mv_ec.message());
        else
            spdlog::info("NotificationStore: migrate_from_sqlite: moved legacy notification db "
                         "to {}",
                         aside.string());
    };

    // 1. Local legacy-file presence (cheap stat) — checked BEFORE the marker
    // lookup so step 2 knows whether THIS replica has something to verify a
    // pre-existing marker against.
    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("NotificationStore: migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        return false;
    }

    // 2. Idempotency marker (short-lived lease released before any legacy I/O).
    bool marker_present = false;
    std::optional<std::string> stored_fingerprint;
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("NotificationStore: migrate_from_sqlite: no database connection ({})",
                          pool_.last_error());
            return false;
        }
        pg::PgResult mk = pg::exec_params(
            lease.get(),
            "SELECT key, value FROM notification_store.notification_meta WHERE key IN "
            "('backfill_complete', 'backfill_source_fingerprint')",
            std::vector<std::string>{});
        if (mk.status() != PGRES_TUPLES_OK) {
            spdlog::error("NotificationStore: migrate_from_sqlite: marker lookup failed: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        for (int i = 0; i < PQntuples(mk.get()); ++i) {
            const std::string key = PQgetvalue(mk.get(), i, 0);
            if (key == "backfill_complete")
                marker_present = true;
            else if (key == "backfill_source_fingerprint")
                stored_fingerprint = std::string(PQgetvalue(mk.get(), i, 1));
        }
        // lease released HERE (end of scope) — the verification work below is
        // a SQLite file read + SHA-256 hash and must not hold a PG lease.
    }

    if (marker_present) {
        if (!legacy_exists) {
            spdlog::debug("NotificationStore: migrate_from_sqlite already completed, skipping");
            return true;
        }
        // This replica still holds a local legacy file even though the fleet
        // marker is already set — verify it was actually the file that got
        // migrated before trusting the marker.
        const auto verify_fp = legacy_notification_fingerprint(legacy_db_path);
        if (!verify_fp) {
            spdlog::error(
                "NotificationStore: migrate_from_sqlite: backfill_complete is already set, and "
                "this replica's own legacy db {} exists but is unreadable/corrupt while being "
                "fingerprint-verified against it — refusing (fail-closed; never silently trust "
                "a marker over an unverifiable local file)",
                legacy_db_path.string());
            return false;
        }
        if (*verify_fp == kSourcelessFingerprint) {
            spdlog::debug("NotificationStore: migrate_from_sqlite already completed; this "
                         "replica's own legacy db has no notifications table (nothing to "
                         "lose), skipping");
            return true;
        }
        if (!stored_fingerprint) {
            // Unreachable in normal operation — this store's ONLY writer of
            // backfill_complete always stamps backfill_source_fingerprint in
            // the same transaction. A marker with no fingerprint means the
            // notification_meta row was tampered with or corrupted; refuse
            // rather than guess.
            spdlog::error(
                "NotificationStore: migrate_from_sqlite: backfill_complete is already set with "
                "NO recorded source fingerprint (should be unreachable — this store's only "
                "writer always stamps both together), and this replica's own legacy db {} "
                "still holds real content (fingerprint '{}'). Refusing to guess (fail-closed).",
                legacy_db_path.string(), *verify_fp);
            return false;
        }
        if (*stored_fingerprint == kSourcelessFingerprint) {
            spdlog::error(
                "NotificationStore: migrate_from_sqlite: backfill_complete is already set with "
                "a sourceless source fingerprint (no legacy notifications.db has been migrated "
                "for this fleet yet), and this replica's own legacy db {} still holds real "
                "content (fingerprint '{}'). Refusing to auto-migrate on this later boot: this "
                "replica may already have accepted live notifications since the sourceless "
                "stamp that a fresh re-migration would clobber (id collisions aside, stale rows "
                "would resurrect already-dismissed items).",
                legacy_db_path.string(), *verify_fp);
            return false;
        }
        if (*stored_fingerprint != *verify_fp) {
            spdlog::error(
                "NotificationStore: migrate_from_sqlite: HOLDER-SIDE VERIFICATION FAILED — "
                "backfill_complete is already set with a DIFFERENT recorded source fingerprint "
                "('{}') than this replica's own legacy db {} ('{}') — some other replica's "
                "legacy data was migrated, not this one's (docs/postgres-store-playbook.md "
                "anti-pattern 'Local source absence never creates terminal migration state on "
                "its own', #2697). Refusing to silently accept a completion this replica's "
                "notifications were never part of.",
                *stored_fingerprint, legacy_db_path.string(), *verify_fp);
            return false;
        }
        spdlog::debug(
            "NotificationStore: migrate_from_sqlite already completed (fingerprint verified), "
            "skipping");
        move_legacy_aside(legacy_db_path);
        return true;
    }

    if (!legacy_exists) {
        // Fresh install. Fingerprint is the sourceless sentinel, not
        // skipped: a later process that DOES hold a legacy file must be
        // able to tell this marker was never derived from any real content.
        if (!stamp_complete_alone(kSourcelessFingerprint)) {
            return false;
        }
        spdlog::info(
            "NotificationStore: migrate_from_sqlite: no legacy notifications.db at {}; marking "
            "backfill complete (fresh install)",
            legacy_db_path.string());
        return true;
    }

    // 3. Open legacy read-only.
    SqliteDb legacy;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK) {
        spdlog::error("NotificationStore: migrate_from_sqlite: failed to open legacy db {}: {}",
                      legacy_db_path.string(),
                      legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
        return false;
    }
    sqlite3_exec(legacy.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    // Corruption probe: a non-empty, non-SQLite file opens lazily under
    // READONLY, then the first real query fails with SQLITE_NOTADB.
    {
        SqliteStmt probe;
        if (sqlite3_prepare_v2(legacy.get(), "SELECT count(*) FROM sqlite_master", -1, probe.addr(),
                               nullptr) != SQLITE_OK ||
            sqlite3_step(probe.get()) != SQLITE_ROW) {
            spdlog::error(
                "NotificationStore: migrate_from_sqlite: legacy db {} is unreadable/corrupt "
                "({}); refusing backfill (fail-closed — never silently drop operator "
                "notification history)",
                legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
            return false;
        }
    }
    const auto has_notifications = legacy_has_table(legacy.get(), "notifications");
    if (!has_notifications) {
        spdlog::error(
            "NotificationStore: migrate_from_sqlite: legacy db {} could not be probed for a "
            "notifications table ({}); refusing backfill (fail-closed)",
            legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
        return false;
    }
    if (!*has_notifications) {
        if (!stamp_complete_alone(kSourcelessFingerprint)) {
            return false;
        }
        spdlog::warn(
            "NotificationStore: migrate_from_sqlite: legacy db {} has no notifications table; "
            "marking backfill complete",
            legacy_db_path.string());
        // Close before move-aside (same Windows rename-with-open-handle rule
        // as the real-content path below) — tidies the schema-less file so
        // later boots don't re-open/re-probe it every time.
        legacy.close();
        move_legacy_aside(legacy_db_path);
        return true;
    }

    // 3b. Read every legacy row ONCE — the single source both the real
    // migration (below) and this stamp's own trust-anchor fingerprint
    // derive from (no second file read anywhere in this function).
    const auto snap_opt = read_legacy_snapshot(legacy.get());
    if (!snap_opt) {
        spdlog::error("NotificationStore: migrate_from_sqlite: legacy read failed: {}",
                      sqlite3_errmsg(legacy.get()));
        return false;
    }
    const LegacySnapshot& snap = *snap_opt;
    const auto fp = fingerprint_legacy_snapshot(snap);
    if (!fp) {
        spdlog::error(
            "NotificationStore: migrate_from_sqlite: fingerprinting the legacy snapshot failed "
            "(SHA-256 digest error); refusing backfill (fail-closed)");
        return false;
    }

    // 4. Backfill rows + advance the identity sequence past the migrated ids
    // + stamp both markers — ONE transaction. `id` is GENERATED ALWAYS AS
    // IDENTITY; OVERRIDING SYSTEM VALUE supplies the legacy ids explicitly
    // (the dashboard's mark_read/dismiss reference them). Advancing the
    // sequence in the SAME transaction is load-bearing: without it the
    // sequence still starts at 1 and the first live create() after backfill
    // would collide with a backfilled id.
    const bool ok = pool_.with_txn_for(kBackfillTxnTimeout, [&](PGconn* c) -> bool {
        // SET LOCAL statement_timeout: with_txn_for's timeout bounds only the
        // pool-ACQUIRE wait, never statement execution — the pool-wide
        // connection default (30s, pg_pool.hpp) is what actually governs this
        // transaction otherwise, silently ignoring kBackfillTxnTimeout's 60s
        // intent on a large legacy table (docs/postgres-store-playbook.md
        // anti-pattern "Assuming a per-operation timeout parameter bounds
        // statement execution"; AuditStore::migrate_from_sqlite is the
        // reference shape).
        const std::string set_timeout_sql =
            std::format("SET LOCAL statement_timeout = '{}ms'", kBackfillTxnTimeout.count());
        pg::PgResult st = pg::exec_params(c, set_timeout_sql.c_str(), std::vector<std::string>{});
        if (st.status() != PGRES_COMMAND_OK) {
            spdlog::error("NotificationStore: migrate_from_sqlite: statement_timeout set failed: {}",
                          PQerrorMessage(c));
            return false;
        }
        // Refuse to backfill over a table that already holds rows this pass
        // never wrote (adversarial-review, HIGH — both Kimi and Codex
        // independently reproduced this empirically): a plain
        // `ON CONFLICT DO NOTHING` only reports PGRES_COMMAND_OK — true
        // whether the row inserted or silently no-opped on a pre-existing
        // conflicting id — so a stray/partial prior write at the same id
        // would be silently dropped while this transaction still stamps the
        // completion marker as if every legacy row survived
        // (docs/postgres-store-playbook.md anti-pattern "Trusting
        // PQresultStatus() == PGRES_COMMAND_OK on ON CONFLICT DO NOTHING").
        // migrate_from_sqlite only ever reaches this transaction when no
        // completion marker exists yet (checked above), so a non-empty table
        // here is unambiguously NOT this store's own prior successful
        // backfill — refuse rather than silently accept partial data
        // (matches AuditStore::stamp_complete's require_empty re-check).
        pg::PgResult precheck = pg::exec_params(
            c, "SELECT COUNT(*) FROM notification_store.notifications", std::vector<std::string>{});
        if (precheck.status() != PGRES_TUPLES_OK) {
            spdlog::error("NotificationStore: migrate_from_sqlite: pre-backfill emptiness check "
                          "failed: {}",
                          PQerrorMessage(c));
            return false;
        }
        if (to_i64(PQgetvalue(precheck.get(), 0, 0)) > 0) {
            spdlog::error(
                "NotificationStore: migrate_from_sqlite: refusing to backfill — "
                "notification_store.notifications already holds row(s) even though no "
                "backfill_complete marker exists. Backfilling over them could silently drop a "
                "legacy row on an id conflict while still stamping completion. Refusing "
                "(fail-closed) — an operator must reconcile which rows are authoritative before "
                "retrying.");
            return false;
        }
        for (const auto& r : snap.rows) {
            // RETURNING id + require exactly one row back, never a bare
            // PGRES_COMMAND_OK check on ON CONFLICT DO NOTHING (the same
            // anti-pattern the precheck above guards against) — the
            // precheck already proved the table was empty at transaction
            // start, so ON CONFLICT here can only fire against a row THIS
            // loop itself already inserted, which cannot happen (ids are
            // the legacy file's own primary keys, read once into `snap` and
            // therefore unique). ON CONFLICT DO NOTHING stays as the
            // idempotency guard of last resort; the RETURNING check is what
            // proves a landed insert rather than trusting the command
            // status (RbacStore's trust-anchor upsert is the reference
            // shape for RETURNING + PQntuples() over PQcmdTuples()).
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO notification_store.notifications "
                "(id, ts_ms, level, title, message, read, dismissed) "
                "OVERRIDING SYSTEM VALUE VALUES "
                "($1::bigint, $2::bigint, $3, $4, $5, $6::boolean, $7::boolean) "
                "ON CONFLICT (id) DO NOTHING RETURNING id",
                std::vector<std::string>{std::to_string(r.id), std::to_string(r.timestamp),
                                         r.level, r.title, r.message,
                                         r.read != 0 ? "true" : "false",
                                         r.dismissed != 0 ? "true" : "false"});
            if (ins.status() != PGRES_TUPLES_OK) {
                spdlog::error("NotificationStore: migrate_from_sqlite: insert of id {} failed: {}",
                              r.id, PQerrorMessage(c));
                return false;
            }
            if (PQntuples(ins.get()) != 1) {
                spdlog::error(
                    "NotificationStore: migrate_from_sqlite: insert of id {} did not land (0 "
                    "rows returned — conflicted with a pre-existing row the empty-table "
                    "precheck should have ruled out); refusing to stamp completion over a "
                    "partial backfill",
                    r.id);
                return false;
            }
        }
        pg::PgResult sv = pg::exec_params(
            c,
            "SELECT setval(pg_get_serial_sequence('notification_store.notifications','id'), "
            "GREATEST((SELECT COALESCE(MAX(id),0) FROM notification_store.notifications), 1), "
            "(SELECT COUNT(*) FROM notification_store.notifications) > 0)",
            std::vector<std::string>{});
        if (sv.status() != PGRES_TUPLES_OK) {
            spdlog::error("NotificationStore: migrate_from_sqlite: sequence advance failed: {}",
                          PQerrorMessage(c));
            return false;
        }
        return stamp_markers(c, *fp);
    });
    if (!ok) {
        spdlog::error(
            "NotificationStore: migrate_from_sqlite: backfill transaction failed and was rolled "
            "back; legacy db {} left untouched — will retry on next boot",
            legacy_db_path.string());
        return false;
    }
    spdlog::info("NotificationStore: migrate_from_sqlite: backfilled {} notification(s)",
                 snap.rows.size());
    // Close the legacy read-only handle FIRST: Windows refuses to rename a
    // file with an open handle (ERROR_SHARING_VIOLATION) — matches
    // RbacStore/AuditStore's identical fix. All legacy reads are already
    // materialised in `snap` above, so nothing further needs `legacy` open.
    legacy.close();
    move_legacy_aside(legacy_db_path);
    return true;
}

bool NotificationStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    const bool ok = migrate_from_sqlite_impl(legacy_db_path);
    if (metrics_)
        metrics_->counter("yuzu_server_notification_backfill_total",
                          {{"result", ok ? "success" : "failed"}})
            .increment();
    return ok;
}

int64_t NotificationStore::create(const std::string& level, const std::string& title,
                                  const std::string& message) {
    if (!open_)
        return -1;
    auto lease = pool_.try_acquire_for(kCreateAcquireTimeout);
    if (!lease) {
        spdlog::debug("NotificationStore: create skipped, no connection in time ({})",
                      pool_.last_error());
        return -1;
    }
    const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO notification_store.notifications (ts_ms, level, title, message) "
        "VALUES ($1::bigint, $2, $3, $4) RETURNING id",
        std::vector<std::string>{std::to_string(now_ms), level, title, message});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
        spdlog::debug("NotificationStore: create failed: {}", PQerrorMessage(lease.get()));
        return -1;
    }
    return to_i64(PQgetvalue(res.get(), 0, 0));
}

std::vector<Notification> NotificationStore::list_unread(int limit) {
    std::vector<Notification> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadAcquireTimeout);
    if (!lease) {
        spdlog::debug("NotificationStore: list_unread skipped, no connection in time ({})",
                      pool_.last_error());
        return out;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, ts_ms, level, title, message, read, dismissed "
        "FROM notification_store.notifications WHERE read = FALSE AND dismissed = FALSE "
        "ORDER BY ts_ms DESC LIMIT $1::bigint",
        std::vector<std::string>{std::to_string(limit)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("NotificationStore: list_unread failed: {}", PQerrorMessage(lease.get()));
        return out;
    }
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(row_to_notification(res.get(), i));
    return out;
}

std::vector<Notification> NotificationStore::list_all(int limit, int offset) {
    std::vector<Notification> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadAcquireTimeout);
    if (!lease) {
        spdlog::debug("NotificationStore: list_all skipped, no connection in time ({})",
                      pool_.last_error());
        return out;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, ts_ms, level, title, message, read, dismissed "
        "FROM notification_store.notifications ORDER BY ts_ms DESC, id DESC "
        "LIMIT $1::bigint OFFSET $2::bigint",
        std::vector<std::string>{std::to_string(limit), std::to_string(offset)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("NotificationStore: list_all failed: {}", PQerrorMessage(lease.get()));
        return out;
    }
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(row_to_notification(res.get(), i));
    return out;
}

bool NotificationStore::mark_read(int64_t id) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteAcquireTimeout);
    if (!lease) {
        spdlog::debug("NotificationStore: mark_read skipped, no connection in time ({})",
                      pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "UPDATE notification_store.notifications SET read = TRUE WHERE id = $1::bigint",
        std::vector<std::string>{std::to_string(id)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::debug("NotificationStore: mark_read({}) failed: {}", id, PQerrorMessage(lease.get()));
        return false;
    }
    // PQcmdTuples(), not the bare PGRES_COMMAND_OK check above: that status
    // is identical whether the WHERE clause matched a row or not — the
    // #1033-class mutate-then-count trap this codebase's sqlite3_changes()
    // ban exists to close on the Postgres side too.
    return std::string_view(PQcmdTuples(res.get())) != "0";
}

bool NotificationStore::dismiss(int64_t id) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteAcquireTimeout);
    if (!lease) {
        spdlog::debug("NotificationStore: dismiss skipped, no connection in time ({})",
                      pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE notification_store.notifications SET dismissed = TRUE WHERE id = $1::bigint",
        std::vector<std::string>{std::to_string(id)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::debug("NotificationStore: dismiss({}) failed: {}", id, PQerrorMessage(lease.get()));
        return false;
    }
    return std::string_view(PQcmdTuples(res.get())) != "0";
}

std::size_t NotificationStore::count_unread() {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadAcquireTimeout);
    if (!lease) {
        spdlog::debug("NotificationStore: count_unread skipped, no connection in time ({})",
                      pool_.last_error());
        return 0;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT COUNT(*) FROM notification_store.notifications WHERE read = FALSE AND "
        "dismissed = FALSE",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("NotificationStore: count_unread failed: {}", PQerrorMessage(lease.get()));
        return 0;
    }
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

} // namespace yuzu::server
