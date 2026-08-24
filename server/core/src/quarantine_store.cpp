#include "quarantine_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>
#include <openssl/evp.h>
#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "quarantine_store";

// Bounded acquires (ADR-0012 §2(a)). Quarantine is an operator/dashboard +
// MCP surface, not a per-heartbeat hot path — budgets are generous relative
// to e.g. the gRPC ingest path.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
constexpr std::chrono::milliseconds kBackfillTxnTimeout{60000};

// Read-degrade observability (mirrors DiscoveryStore/ManagementGroupStore).
constexpr const char* kReasonStoreClosed = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

// ADR-0040 pattern (RbacStore/DiscoveryStore the reference implementations):
// a process finding no local legacy file cannot distinguish "genuine fresh
// install" from "a sibling replica holds the real file" — the fingerprint
// sentinel for "this replica's own migration pass found nothing to
// protect" (no local file, or a local file with no quarantine_records
// table).
constexpr const char* kSourcelessFingerprint = "sourceless";

// Sanity/DoS cap on the legacy row count a single backfill transaction will
// stream and hold in memory (ADR-0012 §2(b) "cap per-row memory"). Refused
// (fail-closed) rather than silently truncated if exceeded — quarantine
// records are manually-curated security events, not a high-volume telemetry
// stream, so this ceiling is not expected to bind in practice.
//
// gov-fix(architect, Gate 3): sized against kBackfillTxnTimeout, not chosen
// independently of it. commit_backfill's row-insert loop is one round-trip
// PER ROW under the exclusive backfill advisory lock (no batching) — every
// OTHER replica reaching that lock (a same-boot race, or a later boot before
// this one's marker commits) blocks for the winner's full insert duration.
// At a much larger cap this could mean minutes of fleet-wide boot refusal
// for every replica but the winner. 5,000 keeps even a pessimistic ~10ms/row
// round-trip (contention, network) comfortably under kBackfillTxnTimeout
// (60s), leaving margin rather than racing its own bound.
constexpr std::size_t kMaxBackfillRows = 5000;

// Serializes concurrent first-ever-migration attempts across replicas (see
// ADR-0047 "Backfill" — no natural per-row key means the row-insert loop
// itself, not just the completion marker, must be protected). Its own
// leading statement in an explicit transaction, strictly BEFORE the
// check-and-mutate work that follows (docs/postgres-store-playbook.md's
// RbacStore-derived warning: a lock embedded via CTE in the same statement
// as the check does not re-evaluate that statement's already-fixed
// snapshot).
constexpr const char* kBackfillLockSql =
    "SELECT pg_advisory_xact_lock(hashtextextended('quarantine_store:backfill', 0))";

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};

bool note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason, DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_server_quarantine_read_degrade_total", {{"reason", reason}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return new_episode || (n % kReadDegradeLogSample) == 0;
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

// Applied to every free-text column reaching Postgres, including the
// backfill path (a bad byte at-rest in a legacy quarantine.db must not
// brick the mandatory backfill). Scrubs invalid UTF-8 to U+FFFD, then
// replaces any embedded NUL (PostgreSQL TEXT cannot store one; libpq's text
// bind C-string-truncates at the first one).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

QuarantineRecord read_record(PGresult* res, int row) {
    QuarantineRecord r;
    int c = 0;
    r.id = to_i64(PQgetvalue(res, row, c++));
    r.agent_id = text_col(res, row, c++);
    r.status = text_col(res, row, c++);
    r.quarantined_by = text_col(res, row, c++);
    r.quarantined_at = to_i64(PQgetvalue(res, row, c++));
    r.released_at = to_i64(PQgetvalue(res, row, c++));
    r.whitelist = text_col(res, row, c++);
    r.reason = text_col(res, row, c++);
    r.last_applied_at = to_i64(PQgetvalue(res, row, c++));
    r.last_confirmed_at = to_i64(PQgetvalue(res, row, c++));
    return r;
}

constexpr const char* kRecordCols =
    "id, agent_id, status, quarantined_by, quarantined_at, released_at, whitelist, reason, "
    "last_applied_at, last_confirmed_at";

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

// nullopt = could not determine (genuine prepare/step error) — distinct
// from `false` ("determined the table is absent"). Every caller MUST treat
// nullopt as a read failure, never coerce it to "absent" (mirrors
// rbac_store.cpp's legacy_has_table / discovery_store.cpp's copy).
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

struct LRecord {
    std::string agent_id, status, quarantined_by, whitelist, reason;
    std::int64_t quarantined_at{0}, released_at{0};
};

// Every row this backfill reads from a legacy quarantine.db, read ONCE and
// shared by the real migration (INSERT loop) and this backfill's own
// trust-anchor fingerprint — no second file read on the normal path
// (mirrors discovery_store.cpp's read_legacy_snapshot / LDevice).
std::optional<std::vector<LRecord>> read_legacy_snapshot(sqlite3* legacy) {
    std::vector<LRecord> rows;
    SqliteStmt s;
    if (sqlite3_prepare_v2(legacy,
                           "SELECT agent_id, status, quarantined_by, quarantined_at, "
                           "released_at, whitelist, reason FROM quarantine_records",
                           -1, s.addr(), nullptr) != SQLITE_OK)
        return std::nullopt;
    int rc;
    while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
        LRecord r;
        r.agent_id = sqlite_text(s.get(), 0);
        r.status = sqlite_text(s.get(), 1);
        r.quarantined_by = sqlite_text(s.get(), 2);
        r.quarantined_at = sqlite3_column_int64(s.get(), 3);
        r.released_at = sqlite3_column_int64(s.get(), 4);
        r.whitelist = sqlite_text(s.get(), 5);
        r.reason = sqlite_text(s.get(), 6);
        rows.push_back(std::move(r));
    }
    if (rc != SQLITE_DONE)
        return std::nullopt;
    return rows;
}

// Injective preimage: every field length-prefixed so two different field
// sequences can never encode to the same preimage regardless of what bytes
// they contain (mirrors rbac_store.cpp/discovery_store.cpp). Rows are
// sorted so on-disk order (WAL/vacuum state can reorder identical rows
// without changing their meaning) never changes the result.
void append_field(std::string& out, std::string_view f) {
    out += std::to_string(f.size());
    out += ':';
    out.append(f.data(), f.size());
}
void append_field(std::string& out, std::int64_t v) { append_field(out, std::to_string(v)); }

std::string canonicalize_legacy_snapshot(const std::vector<LRecord>& snap) {
    std::vector<std::string> rows;
    rows.reserve(snap.size());
    for (const auto& r : snap) {
        std::string row;
        append_field(row, r.agent_id);
        append_field(row, r.status);
        append_field(row, r.quarantined_by);
        append_field(row, r.quarantined_at);
        append_field(row, r.released_at);
        append_field(row, r.whitelist);
        append_field(row, r.reason);
        rows.push_back(std::move(row));
    }
    std::sort(rows.begin(), rows.end());
    std::string canon = "quarantine-legacy-fingerprint-v1\n";
    for (const auto& r : rows)
        canon += r;
    return canon;
}

std::optional<std::string> fingerprint_legacy_snapshot(const std::vector<LRecord>& snap) {
    const auto hash = sha256_hex(canonicalize_legacy_snapshot(snap));
    if (!hash)
        return std::nullopt;
    return "v1:" + *hash;
}

// Path-based convenience for the holder-side verification call site: opens
// read-only, probes for corruption, and either returns the sourceless
// sentinel (no `quarantine_records` table — same "nothing to protect"
// class as no local file at all) or reads a full snapshot and fingerprints
// it via the exact same function the real migration path uses. Returns
// nullopt only on a corrupt/unreadable file or a snapshot read failure —
// the caller MUST fail closed on that, never treat it as
// sourceless-equivalent.
std::optional<std::string>
legacy_quarantine_fingerprint(const std::filesystem::path& legacy_db_path) {
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
    const auto has_records = legacy_has_table(legacy.get(), "quarantine_records");
    if (!has_records)
        return std::nullopt; // genuine read error, NOT "no table"
    if (!*has_records)
        return std::string(kSourcelessFingerprint);

    const auto snap = read_legacy_snapshot(legacy.get());
    if (!snap)
        return std::nullopt;
    return fingerprint_legacy_snapshot(*snap);
}

struct BackfillOutcome {
    bool ok{false};        ///< the transaction (whatever it did) committed cleanly
    bool lost_race{false}; ///< a concurrent replica's backfill won; nothing was inserted here
};

// Runs the entire "record backfill completion" step under the store's
// backfill advisory lock: re-checks the marker (a concurrent racer may have
// committed since the caller's own short-lease marker check), and if still
// absent, inserts every row in `rows` (empty for the sourceless/no-real-
// content case) plus the backfill_complete + backfill_source_fingerprint
// marker rows, all in ONE transaction (the ADR-0012 §2(b) documented
// exception for a one-time legacy backfill's atomic insert-plus-completion
// stamp). Used for BOTH the sourceless stamp and the real-content backfill
// — unifying both through one lock removes the need to separately reason
// about a sourceless stamper racing a real-content backfiller across two
// different locking schemes.
BackfillOutcome commit_backfill(pg::PgPool& pool, const std::vector<LRecord>& rows,
                                std::string_view fingerprint) {
    BackfillOutcome out;
    out.ok = pool.with_txn_for(kBackfillTxnTimeout, [&](PGconn* c) -> bool {
        // gov-fix(security-guardian, cpp-expert): the pool's connection-level
        // lock_timeout GUC (default 10s, ADR-0012) is far shorter than
        // kBackfillTxnTimeout — a replica losing the first-ever-migration race
        // would otherwise abort its wait for kBackfillLockSql (and thus
        // refuse to boot) whenever the WINNER's own row-insert loop simply
        // takes longer than 10s, even though the winner's transaction is
        // itself correctly bounded by kBackfillTxnTimeout. Widening ONLY
        // lock_timeout is insufficient (cpp-expert Gate 3 re-review): the
        // pool's connection-level statement_timeout GUC (default 30s,
        // pg_pool.hpp, not overridden by server.cpp's PgPool::Options) ALSO
        // bounds a lock wait — a lock-wait IS the statement executing, just
        // blocked — so it silently caps the effective wait at 30s regardless
        // of what lock_timeout is set to. Both must be widened together; this
        // is the SAME anti-pattern docs/postgres-store-playbook.md documents
        // ("Assuming a per-operation timeout parameter bounds statement
        // execution — it only bounds the pool-ACQUIRE wait") and the same fix
        // shape NotificationStore::migrate_from_sqlite already uses.
        const std::string set_timeout_sql =
            std::format("SET LOCAL statement_timeout = '{}ms'", kBackfillTxnTimeout.count());
        pg::PgResult st = pg::exec_params(c, set_timeout_sql.c_str(), std::vector<std::string>{});
        if (st.status() != PGRES_COMMAND_OK) {
            spdlog::error("QuarantineStore: migrate_from_sqlite: backfill statement_timeout set "
                         "failed: {}",
                         PQerrorMessage(c));
            return false;
        }
        const std::string set_lock_timeout_sql =
            std::format("SET LOCAL lock_timeout = '{}ms'", kBackfillTxnTimeout.count());
        pg::PgResult lt =
            pg::exec_params(c, set_lock_timeout_sql.c_str(), std::vector<std::string>{});
        if (lt.status() != PGRES_COMMAND_OK) {
            spdlog::error("QuarantineStore: migrate_from_sqlite: backfill lock_timeout set "
                         "failed: {}",
                         PQerrorMessage(c));
            return false;
        }

        pg::PgResult lk = pg::exec_params(c, kBackfillLockSql, std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            spdlog::error("QuarantineStore: migrate_from_sqlite: backfill lock failed (retryable "
                         "on next boot if this was a same-boot race against another replica): "
                         "{}",
                         PQerrorMessage(c));
            return false;
        }

        pg::PgResult mk = pg::exec_params(
            c, "SELECT 1 FROM quarantine_store.quarantine_meta WHERE key = 'backfill_complete'",
            std::vector<std::string>{});
        if (mk.status() != PGRES_TUPLES_OK) {
            spdlog::error("QuarantineStore: migrate_from_sqlite: in-lock marker check failed: {}",
                          PQerrorMessage(c));
            return false;
        }
        if (PQntuples(mk.get()) > 0) {
            // A concurrent replica committed between our caller's short-lease
            // check and this transaction acquiring the lock. Nothing to do —
            // commit this as a no-op; the caller re-verifies via the normal
            // marker-present holder-side path.
            out.lost_race = true;
            return true;
        }

        for (const auto& r : rows) {
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO quarantine_store.quarantine_records "
                "(agent_id, status, quarantined_by, quarantined_at, released_at, whitelist, "
                "reason) "
                "VALUES ($1, $2, $3, $4::bigint, $5::bigint, $6, $7)",
                std::vector<std::string>{
                    sanitize_pg_text(r.agent_id), r.status, sanitize_pg_text(r.quarantined_by),
                    std::to_string(r.quarantined_at), std::to_string(r.released_at),
                    sanitize_pg_text(r.whitelist), sanitize_pg_text(r.reason)});
            if (ins.status() != PGRES_COMMAND_OK) {
                spdlog::error(
                    "QuarantineStore: migrate_from_sqlite: row insert failed for agent={}: {}",
                    sanitize_pg_text(r.agent_id), PQerrorMessage(c));
                return false;
            }
        }

        pg::PgResult mkc = pg::exec_params(
            c,
            "INSERT INTO quarantine_store.quarantine_meta (key, value) VALUES "
            "('backfill_complete', $1) ON CONFLICT (key) DO NOTHING",
            std::vector<std::string>{std::to_string(now_secs())});
        if (mkc.status() != PGRES_COMMAND_OK) {
            spdlog::error("QuarantineStore: migrate_from_sqlite: marker stamp failed: {}",
                          PQerrorMessage(c));
            return false;
        }

        // gov-fix(compliance-officer C-5): the only completeness evidence
        // this backfill left behind was the fact that boot succeeded — no
        // info-level log naming how much was migrated, and nothing queryable
        // afterward. Persisted alongside the marker in the SAME transaction
        // (reached only by the actual winner — a lost_race no-op returns
        // before this point, so `rows.size()` here is this transaction's own
        // insert count, never a racer's).
        pg::PgResult rcr = pg::exec_params(
            c,
            "INSERT INTO quarantine_store.quarantine_meta (key, value) VALUES "
            "('backfill_row_count', $1) ON CONFLICT (key) DO NOTHING",
            std::vector<std::string>{std::to_string(rows.size())});
        if (rcr.status() != PGRES_COMMAND_OK) {
            spdlog::error("QuarantineStore: migrate_from_sqlite: row-count stamp failed: {}",
                          PQerrorMessage(c));
            return false;
        }

        // Monotonic promotion (mirrors discovery_store.cpp's stamp_complete):
        // "sourceless" carries no evidence worth protecting, so a real
        // fingerprint may promote a stored "sourceless" value; a stored REAL
        // value is never overwritten; a writer whose value already equals
        // what's stored counts as success.
        pg::PgResult fpr = pg::exec_params(
            c,
            "INSERT INTO quarantine_store.quarantine_meta (key, value) VALUES "
            "('backfill_source_fingerprint', $1) ON CONFLICT (key) DO UPDATE SET "
            "value = EXCLUDED.value WHERE quarantine_store.quarantine_meta.value = 'sourceless' "
            "OR quarantine_store.quarantine_meta.value = EXCLUDED.value RETURNING value",
            std::vector<std::string>{std::string(fingerprint)});
        if (fpr.status() != PGRES_TUPLES_OK) {
            spdlog::error(
                "QuarantineStore: migrate_from_sqlite: source-fingerprint stamp failed: {}",
                PQerrorMessage(c));
            return false;
        }
        if (PQntuples(fpr.get()) == 0 && fingerprint != kSourcelessFingerprint) {
            // Should be unreachable — the advisory lock excludes every other
            // real-content backfiller, and we just confirmed the marker was
            // absent under that same lock. Treat as an internal invariant
            // violation rather than silently losing this replica's real
            // fingerprint.
            spdlog::error(
                "QuarantineStore: migrate_from_sqlite: lost the race to record this backfill's "
                "own REAL source fingerprint while holding the backfill advisory lock — this "
                "should be impossible; refusing (fail-closed) rather than trust an "
                "inconsistent marker/fingerprint pair");
            return false;
        }
        return true;
    });
    return out;
}

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so this table lands in `quarantine_store`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE quarantine_records ("
         "  id              BIGSERIAL PRIMARY KEY,"
         "  agent_id        TEXT NOT NULL,"
         "  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', "
         "'released')),"
         "  quarantined_by  TEXT NOT NULL DEFAULT '',"
         "  quarantined_at  BIGINT NOT NULL DEFAULT 0,"
         "  released_at     BIGINT NOT NULL DEFAULT 0,"
         "  whitelist       TEXT NOT NULL DEFAULT '',"
         "  reason          TEXT NOT NULL DEFAULT '');"
         "CREATE INDEX idx_quarantine_agent ON quarantine_records(agent_id);"
         // gov-fix(architect, Gate 3): a plain index on `status` (ported
         // column-for-column from the legacy SQLite schema) was dropped — the
         // only status-predicated query is `list_quarantined`'s
         // `WHERE status = 'active'`, already servable by the partial unique
         // index below (Postgres can use a partial index whose predicate
         // matches a query's WHERE clause even when the query doesn't filter
         // on the index's own key column). No query filters on any other
         // status value. A second, redundant btree on a 2-value column would
         // be pure write amplification on this append-only history table.
         //
         // Enforces "at most one active record per agent" at the database
         // level — quarantine_device's ON CONFLICT target.
         "CREATE UNIQUE INDEX idx_quarantine_agent_active ON quarantine_records(agent_id) "
         "WHERE status = 'active';"
         // Durable one-time backfill markers (ADR-0009/0040 pattern).
         "CREATE TABLE quarantine_meta ("
         "  key   TEXT PRIMARY KEY,"
         "  value TEXT NOT NULL"
         ");"},
        // #3425: endpoint-containment confirmation state for
        // QuarantineContainmentReconciler. 0 = never, matching this table's
        // existing `released_at` never-happened sentinel — no optional
        // plumbing, no nullable column. A brief ACCESS EXCLUSIVE lock during
        // the ALTER is negligible at this table's size (manually-curated
        // security events, not a telemetry stream — see kMaxBackfillRows'
        // sizing rationale above).
        {2,
         "ALTER TABLE quarantine_records ADD COLUMN last_applied_at BIGINT NOT NULL DEFAULT 0;"
         "ALTER TABLE quarantine_records ADD COLUMN last_confirmed_at BIGINT NOT NULL DEFAULT 0;"},
    };
    return kMigrations;
}

} // namespace

// ── Construction ──────────────────────────────────────────────────────────

QuarantineStore::QuarantineStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("QuarantineStore: no database connection at construction ({}) — "
                      "quarantine persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("QuarantineStore: schema migration failed — quarantine persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

// ── Operations ───────────────────────────────────────────────────────────────

std::expected<void, std::string>
QuarantineStore::quarantine_device(const std::string& agent_id, const std::string& by,
                                   const std::string& reason, const std::string& whitelist) {
    if (!open_)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "database not open");
    if (agent_id.empty())
        return std::unexpected("agent_id is required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "database unavailable — try again");

    // Single race-safe statement: the partial unique index
    // idx_quarantine_agent_active is the ON CONFLICT target, replacing the
    // legacy check-then-insert-under-mutex. PQntuples()==0 means the
    // conflict fired (an active record already exists).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO quarantine_store.quarantine_records "
        "(agent_id, status, quarantined_by, quarantined_at, whitelist, reason) "
        "VALUES ($1, 'active', $2, $3::bigint, $4, $5) "
        "ON CONFLICT (agent_id) WHERE status = 'active' DO NOTHING "
        "RETURNING id",
        std::vector<std::string>{sanitize_pg_text(agent_id), sanitize_pg_text(by),
                                 std::to_string(now_secs()), sanitize_pg_text(whitelist),
                                 sanitize_pg_text(reason)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "quarantine_device failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("device is already quarantined");
    return {};
}

std::expected<void, std::string> QuarantineStore::release_device(const std::string& agent_id) {
    if (!open_)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "database not open");
    if (agent_id.empty())
        return std::unexpected("agent_id is required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "database unavailable — try again");

    // Single guarded UPDATE (the #3062 cancel_job pattern) — not
    // lock-then-check. RETURNING replaces sqlite3_changes() (#1033).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE quarantine_store.quarantine_records SET status = 'released', released_at = "
        "$1::bigint "
        "WHERE agent_id = $2 AND status = 'active' RETURNING id",
        std::vector<std::string>{std::to_string(now_secs()), sanitize_pg_text(agent_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "release_device failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("device is not quarantined");
    return {};
}

namespace {
// Shared body for mark_endpoint_applied/mark_endpoint_confirmed — same
// guarded-UPDATE-WHERE-active shape as release_device (the #3062 cancel_job
// pattern), differing only in which column is stamped. `record_id` scopes
// the write to the SPECIFIC row a dispatch/status-read was actually about
// (governance Gate 4, unhappy-path Finding A) — `agent_id`+`status='active'`
// alone is not a stable identity across a release-then-requarantine race.
std::expected<void, std::string> mark_endpoint_column(pg::PgPool& pool, const char* column,
                                                       const std::string& agent_id,
                                                       std::int64_t record_id, std::int64_t at,
                                                       bool open) {
    if (!open)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "database not open");
    if (agent_id.empty())
        return std::unexpected("agent_id is required");

    auto lease = pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("UPDATE quarantine_store.quarantine_records SET ") + column +
                      " = $1::bigint WHERE agent_id = $2 AND id = $3::bigint AND status = "
                      "'active' RETURNING id";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{std::to_string(at), sanitize_pg_text(agent_id),
                                 std::to_string(record_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + column +
                               " update failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("device is not quarantined");
    return {};
}
} // namespace

std::expected<void, std::string>
QuarantineStore::mark_endpoint_applied(const std::string& agent_id, std::int64_t record_id,
                                       std::int64_t at) {
    return mark_endpoint_column(pool_, "last_applied_at", agent_id, record_id, at, open_);
}

std::expected<void, std::string>
QuarantineStore::mark_endpoint_confirmed(const std::string& agent_id, std::int64_t record_id,
                                         std::int64_t at) {
    return mark_endpoint_column(pool_, "last_confirmed_at", agent_id, record_id, at, open_);
}

std::expected<std::optional<QuarantineRecord>, std::string>
QuarantineStore::get_status(const std::string& agent_id) {
    if (!open_)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "database not open");
    if (agent_id.empty())
        return std::optional<QuarantineRecord>{std::nullopt};

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kRecordCols +
                      " FROM quarantine_store.quarantine_records WHERE agent_id = $1 AND status "
                      "= 'active' LIMIT 1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{sanitize_pg_text(agent_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kQuarantineDbErrorPrefix) + "get_status failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::optional<QuarantineRecord>{std::nullopt};
    return std::optional<QuarantineRecord>{read_record(res.get(), 0)};
}

std::optional<std::vector<QuarantineRecord>> QuarantineStore::list_quarantined() {
    static DegradeSampler sampler;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("QuarantineStore: list_quarantined degraded — store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("QuarantineStore: list_quarantined degraded — pool acquire timed out "
                         "({})",
                         pool_.last_error());
        return std::nullopt;
    }

    std::string sql = std::string("SELECT ") + kRecordCols +
                      " FROM quarantine_store.quarantine_records WHERE status = 'active' "
                      "ORDER BY quarantined_at DESC, id DESC";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("QuarantineStore: list_quarantined degraded — query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    const int rows = PQntuples(res.get());
    std::vector<QuarantineRecord> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_record(res.get(), i));
    return out;
}

std::optional<std::vector<QuarantineRecord>>
QuarantineStore::get_history(const std::string& agent_id) {
    static DegradeSampler sampler;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("QuarantineStore: get_history degraded — store not open");
        return std::nullopt;
    }
    if (agent_id.empty())
        return std::vector<QuarantineRecord>{};

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("QuarantineStore: get_history degraded — pool acquire timed out ({})",
                        pool_.last_error());
        return std::nullopt;
    }

    std::string sql = std::string("SELECT ") + kRecordCols +
                      " FROM quarantine_store.quarantine_records WHERE agent_id = $1 "
                      "ORDER BY quarantined_at DESC, id DESC";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{sanitize_pg_text(agent_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("QuarantineStore: get_history degraded — query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    const int rows = PQntuples(res.get());
    std::vector<QuarantineRecord> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_record(res.get(), i));
    return out;
}

// ── MANDATORY backfill (ADR-0009, fingerprint-verified per ADR-0040/0047) ──

bool QuarantineStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    const auto backfill_metric = [this](const char* result) {
        if (metrics_)
            metrics_->counter("yuzu_server_quarantine_backfill_total", {{"result", result}})
                .increment();
    };

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
            spdlog::warn("QuarantineStore: migrate_from_sqlite: could not move legacy {} aside "
                         "({}); it is safe to archive/remove manually",
                         path.string(), mv_ec.message());
        else
            spdlog::info("QuarantineStore: migrate_from_sqlite: moved legacy quarantine db to {}",
                         aside.string());
    };

    std::error_code ec;
    const bool legacy_exists_initial = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("QuarantineStore: migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        backfill_metric("failed");
        return false;
    }

    // At most 2 attempts: the second only runs if this replica loses a
    // same-boot race to a concurrent backfill (see commit_backfill's
    // lost_race outcome) — on retry the marker is present and the loop
    // takes the marker_present verification branch below instead.
    for (int attempt = 0; attempt < 2; ++attempt) {
        bool marker_present = false;
        std::optional<std::string> stored_fingerprint;
        {
            auto lease = pool_.acquire();
            if (!lease) {
                spdlog::error("QuarantineStore: migrate_from_sqlite: no database connection ({})",
                              pool_.last_error());
                backfill_metric("failed");
                return false;
            }
            pg::PgResult mk = pg::exec_params(
                lease.get(),
                "SELECT key, value FROM quarantine_store.quarantine_meta WHERE key IN "
                "('backfill_complete', 'backfill_source_fingerprint')",
                std::vector<std::string>{});
            if (mk.status() != PGRES_TUPLES_OK) {
                spdlog::error("QuarantineStore: migrate_from_sqlite: marker lookup failed: {}",
                              PQerrorMessage(lease.get()));
                backfill_metric("failed");
                return false;
            }
            for (int i = 0; i < PQntuples(mk.get()); ++i) {
                const std::string key = text_col(mk.get(), i, 0);
                if (key == "backfill_complete")
                    marker_present = true;
                else if (key == "backfill_source_fingerprint")
                    stored_fingerprint = text_col(mk.get(), i, 1);
            }
        }

        if (marker_present) {
            if (!legacy_exists_initial) {
                spdlog::debug("QuarantineStore: migrate_from_sqlite already completed, skipping");
                return true;
            }
            const auto verify_fp = legacy_quarantine_fingerprint(legacy_db_path);
            if (!verify_fp) {
                spdlog::error(
                    "QuarantineStore: migrate_from_sqlite: backfill_complete is already set, "
                    "and this replica's own legacy db {} exists but is unreadable/corrupt "
                    "while being fingerprint-verified against it — refusing (fail-closed; "
                    "never silently trust a marker over an unverifiable local file)",
                    legacy_db_path.string());
                backfill_metric("failed");
                return false;
            }
            if (*verify_fp == kSourcelessFingerprint) {
                if (stored_fingerprint && *stored_fingerprint == kSourcelessFingerprint) {
                    std::error_code size_ec;
                    const auto sz = std::filesystem::file_size(legacy_db_path, size_ec);
                    if (!size_ec && sz == 0) {
                        spdlog::error(
                            "QuarantineStore: migrate_from_sqlite: backfill_complete is "
                            "already set sourceless (no real migration has ever completed for "
                            "this fleet), and this replica's own legacy db {} is 0 bytes — "
                            "this is NOT evidence of nothing to lose, it is a truncated real "
                            "database indistinguishable from one. Refusing (fail-closed): "
                            "either the legacy store was created but never used (safe to "
                            "delete this empty file manually and retry) or a real file was "
                            "truncated (restore from backup before retrying).",
                            legacy_db_path.string());
                        backfill_metric("failed");
                        return false;
                    }
                }
                spdlog::debug("QuarantineStore: migrate_from_sqlite already completed; this "
                             "replica's own legacy db has no quarantine_records table "
                             "(nothing to lose), skipping");
                return true;
            }
            if (!stored_fingerprint) {
                spdlog::error(
                    "QuarantineStore: migrate_from_sqlite: backfill_complete is already set "
                    "with NO recorded source fingerprint (this marker predates the "
                    "fingerprint-verification mechanism), and this replica's own legacy db {} "
                    "still holds real content (fingerprint '{}'). Refusing to guess whether "
                    "this is this replica's own prior migration or a different replica's — "
                    "manual reconciliation required.",
                    legacy_db_path.string(), *verify_fp);
                backfill_metric("failed");
                return false;
            }
            if (*stored_fingerprint == kSourcelessFingerprint) {
                spdlog::error(
                    "QuarantineStore: migrate_from_sqlite: backfill_complete is already set "
                    "with a sourceless source fingerprint (no legacy quarantine.db has been "
                    "migrated for this fleet yet), and this replica's own legacy db {} still "
                    "holds real content (fingerprint '{}'). Refusing to auto-migrate on this "
                    "later boot: quarantine_store may already have accepted live "
                    "post-cutover quarantine/release writes this file's stale content would "
                    "silently clobber.",
                    legacy_db_path.string(), *verify_fp);
                backfill_metric("failed");
                return false;
            }
            if (*stored_fingerprint != *verify_fp) {
                spdlog::error(
                    "QuarantineStore: migrate_from_sqlite: HOLDER-SIDE VERIFICATION FAILED — "
                    "backfill_complete is already set with a DIFFERENT recorded source "
                    "fingerprint ('{}') than this replica's own legacy db {} ('{}'). Two "
                    "distinct causes produce this same symptom: (1) on a multi-replica "
                    "deployment, some OTHER replica's legacy data was migrated, not this "
                    "one's; (2) on a SINGLE replica, this server was rolled back to a "
                    "pre-migration build after the backfill completed, ran against the legacy "
                    "quarantine.db again (creating new content), and is now being re-upgraded "
                    "— the file no longer matches what was already migrated. Refusing to "
                    "silently accept a completion this replica's current legacy content was "
                    "never verified against; see the quarantine-store backfill recovery "
                    "runbook for the remediation for each cause.",
                    *stored_fingerprint, legacy_db_path.string(), *verify_fp);
                backfill_metric("failed");
                return false;
            }
            spdlog::debug("QuarantineStore: migrate_from_sqlite already completed (fingerprint "
                         "verified), skipping");
            move_legacy_aside(legacy_db_path);
            return true;
        }

        // No marker yet — this replica MIGHT be the first-ever migration.
        if (legacy_exists_initial) {
            std::error_code size_ec;
            const auto legacy_size = std::filesystem::file_size(legacy_db_path, size_ec);
            // SQLite treats a 0-byte file as a valid, empty database,
            // indistinguishable downstream from the legitimate
            // no-quarantine_records-table case. A genuine fresh install
            // never has a file here at all (the old store only creates one
            // on first open) — a 0-byte file at this path, on a first-ever
            // migration, is always a truncated real db, never a fresh
            // install.
            if (!size_ec && legacy_size == 0) {
                spdlog::error(
                    "QuarantineStore: migrate_from_sqlite: legacy db {} exists but is 0 bytes "
                    "— this is NOT a fresh install (a fresh install has no file here at all), "
                    "it is a truncated/corrupted real database. Refusing (fail-closed): "
                    "either the legacy store was created but never used (safe to delete this "
                    "empty file manually and retry) or a real file was truncated (restore "
                    "from backup before retrying).",
                    legacy_db_path.string());
                backfill_metric("failed");
                return false;
            }
        }

        if (!legacy_exists_initial) {
            const auto outcome = commit_backfill(pool_, {}, kSourcelessFingerprint);
            if (!outcome.ok) {
                backfill_metric("failed");
                return false;
            }
            if (outcome.lost_race)
                continue; // retry: marker_present branch above handles it
            spdlog::info("QuarantineStore: migrate_from_sqlite: no legacy quarantine.db at {}; "
                         "marking backfill complete (fresh install)",
                         legacy_db_path.string());
            backfill_metric("fresh");
            return true;
        }

        // Open legacy read-only.
        SqliteDb legacy;
        if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                            nullptr) != SQLITE_OK) {
            spdlog::error("QuarantineStore: migrate_from_sqlite: failed to open legacy db {}: {}",
                          legacy_db_path.string(),
                          legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
            backfill_metric("failed");
            return false;
        }
        sqlite3_exec(legacy.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
        // Corruption probe: an unreadable legacy DB must NOT be silently
        // skipped, which would drop every active quarantine record.
        {
            SqliteStmt probe;
            if (sqlite3_prepare_v2(legacy.get(), "SELECT count(*) FROM sqlite_master", -1,
                                   probe.addr(), nullptr) != SQLITE_OK ||
                sqlite3_step(probe.get()) != SQLITE_ROW) {
                spdlog::error("QuarantineStore: migrate_from_sqlite: legacy db {} is "
                             "unreadable/corrupt ({}); refusing backfill (fail-closed — never "
                             "silently drop active quarantine records)",
                             legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
                backfill_metric("failed");
                return false;
            }
        }
        const auto has_records = legacy_has_table(legacy.get(), "quarantine_records");
        if (!has_records) {
            spdlog::error("QuarantineStore: migrate_from_sqlite: legacy db {} could not be "
                         "probed for a quarantine_records table ({}); refusing backfill "
                         "(fail-closed)",
                         legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
            backfill_metric("failed");
            return false;
        }
        if (!*has_records) {
            const auto outcome = commit_backfill(pool_, {}, kSourcelessFingerprint);
            if (!outcome.ok) {
                backfill_metric("failed");
                return false;
            }
            if (outcome.lost_race)
                continue;
            spdlog::warn("QuarantineStore: migrate_from_sqlite: legacy db {} has no "
                        "quarantine_records table; marking backfill complete",
                        legacy_db_path.string());
            backfill_metric("fresh");
            return true;
        }

        const auto snap_opt = read_legacy_snapshot(legacy.get());
        if (!snap_opt) {
            spdlog::error("QuarantineStore: migrate_from_sqlite: legacy read failed: {}",
                          sqlite3_errmsg(legacy.get()));
            backfill_metric("failed");
            return false;
        }
        const std::vector<LRecord>& snap = *snap_opt;

        if (snap.size() > kMaxBackfillRows) {
            spdlog::error(
                "QuarantineStore: migrate_from_sqlite: legacy db {} holds {} quarantine "
                "records, exceeding the {} sanity cap for a single backfill transaction — "
                "refusing (fail-closed); NEVER prune the legacy file to get under this cap "
                "(a quarantine record is SOC 2 containment evidence — see ADR-0047); see "
                "docs/ops-runbooks/quarantine-store-backfill-recovery.md for remediation "
                "(engage engineering to raise the compile-time cap)",
                legacy_db_path.string(), snap.size(), kMaxBackfillRows);
            backfill_metric("failed");
            return false;
        }

        // Validate legacy enum-ish `status` field BEFORE any row reaches
        // Postgres — an unrecognised value fails the boot closed, never
        // silently inserted or silently dropped.
        for (const auto& r : snap) {
            if (r.status != "active" && r.status != "released") {
                spdlog::error(
                    "QuarantineStore: migrate_from_sqlite: legacy db {} row for agent_id='{}' "
                    "has an unrecognised status '{}' (expected 'active' or 'released') — "
                    "refusing backfill (fail-closed); repair the legacy row before retrying",
                    legacy_db_path.string(), sanitize_pg_text(r.agent_id),
                    sanitize_pg_text(r.status));
                backfill_metric("failed");
                return false;
            }
        }

        // gov-fix(security-guardian): the legacy SQLite schema had no DB-level
        // uniqueness on (agent_id, 'active') — only the in-process mutex this
        // migration retires — so a legacy file COULD hold more than one active
        // row for the same agent (a bug in the pre-migration app, or manual
        // edits). Left unchecked, that row would reach commit_backfill's INSERT
        // loop and abort mid-transaction on a raw
        // "duplicate key value violates unique constraint" error instead of a
        // named, actionable log line. Catch it here, before any row reaches
        // Postgres, matching the status-value check above.
        {
            // gov-fix(cpp-safety): key on the SANITIZED agent_id — the same
            // transform commit_backfill's INSERT actually binds. Two
            // raw-distinct ids that sanitize to the same value (e.g. differing
            // only in an invalid-UTF-8 byte) would otherwise bypass this
            // check and still hit the raw unique-constraint abort it exists
            // to prevent.
            std::unordered_set<std::string> seen_active;
            for (const auto& r : snap) {
                if (r.status != "active")
                    continue;
                if (!seen_active.insert(sanitize_pg_text(r.agent_id)).second) {
                    spdlog::error(
                        "QuarantineStore: migrate_from_sqlite: legacy db {} has more than one "
                        "'active' record for agent_id='{}' — the legacy SQLite schema never "
                        "enforced this uniqueness (an in-process mutex did, not the database), "
                        "so this can only be pre-existing data corruption or a hand-edited "
                        "file. Refusing backfill (fail-closed); release/repair the duplicate "
                        "legacy row(s) before retrying.",
                        legacy_db_path.string(), sanitize_pg_text(r.agent_id));
                    backfill_metric("failed");
                    return false;
                }
            }
        }

        const auto source_fp = fingerprint_legacy_snapshot(snap);
        if (!source_fp) {
            spdlog::error("QuarantineStore: migrate_from_sqlite: could not derive this file's "
                         "own fingerprint before backfilling it; refusing to proceed without a "
                         "trust anchor");
            backfill_metric("failed");
            return false;
        }

        const auto outcome = commit_backfill(pool_, snap, *source_fp);
        if (!outcome.ok) {
            backfill_metric("failed");
            return false;
        }
        if (outcome.lost_race)
            continue; // retry: marker_present branch above handles it

        // gov-fix(compliance-officer C-5): named completeness evidence, not
        // just a boot that happened to succeed — the row count is also
        // queryable afterward via quarantine_meta.backfill_row_count.
        spdlog::info(
            "QuarantineStore: migrate_from_sqlite: backfill complete, {} legacy quarantine "
            "record(s) migrated from {}",
            snap.size(), legacy_db_path.string());
        legacy.close(); // Windows refuses to rename a file with an open handle
        move_legacy_aside(legacy_db_path);
        backfill_metric("completed");
        return true;
    }

    spdlog::error("QuarantineStore: migrate_from_sqlite: exhausted backfill retry attempts — "
                  "this should be unreachable (at most one same-boot race is expected); "
                  "refusing (fail-closed)");
    backfill_metric("failed");
    return false;
}

} // namespace yuzu::server
