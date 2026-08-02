#include "audit_store.hpp"

#include "audit_retention_rules.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "audit_store";

// Bounded acquires (ADR-0012 §2(a)). Writes fail-HARD but must still give up
// eventually so a saturated pool cannot wedge a serving thread indefinitely;
// reads back interactive REST/dashboard/MCP callers.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
// Retention runs on the background thread; a generous deadline is fine.
constexpr std::chrono::milliseconds kReapTimeout{8000};
// Backfill runs at construction, single-threaded, before serving — a wide
// deadline so a large batch on slow storage does not spuriously abort boot.
constexpr std::chrono::milliseconds kBackfillTxnTimeout{60000};

// Read-degrade reason labels (ADR-0037 convention).
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
// Sample the per-site degrade WARN so a sustained PG outage cannot flood the log
// — the counter is the continuous signal, the log a sampled breadcrumb.
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

// Backfill batch size. 14 columns/row × this must stay well under libpq's 65535
// bind-parameter ceiling (14 × 2000 = 28 000). Streaming the legacy table in
// id-ordered batches this size bounds peak memory independently of total
// legacy volume (the table can reach tens of millions of rows / ~16 GB; a
// whole-table read would OOM — #2661).
constexpr std::size_t kBackfillBatchRows = 2000;

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
bool to_bool(const char* s) { return s != nullptr && s[0] == 't'; }

// sanitize_utf8_strict scrubs invalid UTF-8 to U+FFFD but keeps embedded NUL
// (a valid ASCII byte). PostgreSQL TEXT cannot store a NUL and libpq's
// text-format bind C-string-truncates at the first one, silently dropping the
// rest. On the FAIL-HARD audit path a hostile or mis-encoded value would
// otherwise fail the INSERT (SQLSTATE 22021 / truncation) and take a real audit
// event down — the exact evidence-integrity hole this closes (ADR-0040 /
// #1593). So after the UTF-8 scrub, replace every NUL with U+FFFD too. We do
// NOT touch utf8_sanitize.hpp itself — NUL handling is a PG-bind concern local
// to the PG stores.
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col));
}

// ── Read-degrade observability (mirrors ResponseStore/InventoryStore) ────────
struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};

bool note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason, DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_server_audit_read_degrade_total", {{"reason", reason}}).increment();
    const std::int64_t now = now_epoch();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return new_episode || (n % kReadDegradeLogSample) == 0;
}

// Serialize the four guard facts to a stable string — the durable dedup key
// (mirrors ResponseStore's `facts_ser`). Compares the whole FACT SET, not the
// classified enum, so a Wipe arriving underneath a standing BadState (the
// dead-CMOS-then-NTP sequence that silently wiped the whole trail) is NOT
// suppressed: the fact set differs, so the pass declines again.
std::string serialize_facts(const audit_retention::Facts& f) {
    return std::string(f.has_expired ? "e" : "-") + (f.would_wipe ? "w" : "-") +
           (f.big_step ? "s" : "-") + (f.prev_unusable ? "u" : "-");
}

// ── Postgres schema (ADR-0040): the FINAL column set of the SQLite store's
// three migrations, collapsed into one v1. Unqualified DDL — the migration
// runner sets search_path to `audit_store` for the migration transaction.
// Runtime statements below schema-qualify explicitly. Unlike SQLite, the
// partial retention index is created IN the migration: a PG index build runs
// inside the migration txn and a failure correctly fails the migration, which
// for an evidence store is the right fail-closed posture (ADR-0040).
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE audit_events (
                id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                timestamp       BIGINT  NOT NULL,
                principal       TEXT    NOT NULL,
                principal_role  TEXT    NOT NULL,
                action          TEXT    NOT NULL,
                target_type     TEXT    NOT NULL DEFAULT '',
                target_id       TEXT    NOT NULL DEFAULT '',
                detail          TEXT    NOT NULL DEFAULT '',
                source_ip       TEXT    NOT NULL DEFAULT '',
                user_agent      TEXT    NOT NULL DEFAULT '',
                session_id      TEXT    NOT NULL DEFAULT '',
                result          TEXT    NOT NULL,
                ttl_expires_at  BIGINT  NOT NULL DEFAULT 0,
                principal_class TEXT    NOT NULL DEFAULT ''
            );
            CREATE INDEX idx_audit_ts ON audit_events(timestamp);
            CREATE INDEX idx_audit_principal_ts ON audit_events(principal, timestamp);
            CREATE INDEX idx_audit_action_ts ON audit_events(action, timestamp);
            CREATE INDEX idx_audit_target_ts ON audit_events(target_type, target_id, timestamp);
            CREATE INDEX idx_audit_ttl_id
                ON audit_events(ttl_expires_at, id) WHERE ttl_expires_at > 0;

            -- Durable state for the reap clock-guard (#2360, ADR-0040). SHARED
            -- k/v rows (not process-local) — N server replicas each run the
            -- sweep, so the persisted reading + anomaly-dedup fact set must be
            -- one shared truth under the sweep's advisory lock. `value` is TEXT
            -- (holds the integer `last_pass_now`, the `last_anomaly_facts`
            -- string, and the one-time `backfill_complete` marker).
            CREATE TABLE audit_retention_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        )"},
    };
    return kMigrations;
}

// ── Legacy (SQLite) schema introspection for the backfill ────────────────────
bool legacy_has_column(sqlite3* db, const char* table, const char* col) {
    // Table names here are code literals, so inlining is injection-free; PRAGMA
    // does not accept a bound table name.
    const std::string q = std::string("PRAGMA table_info(") + table + ")";
    SqliteStmt s;
    if (sqlite3_prepare_v2(db, q.c_str(), -1, s.addr(), nullptr) != SQLITE_OK)
        return false;
    while (sqlite3_step(s.get()) == SQLITE_ROW) {
        const auto* name = sqlite3_column_text(s.get(), 1); // column 1 = name
        if (name && std::strcmp(reinterpret_cast<const char*>(name), col) == 0)
            return true;
    }
    return false;
}

bool legacy_has_table(sqlite3* db, const char* table) {
    SqliteStmt s;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", -1,
                           s.addr(), nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_text(s.get(), 1, table, -1, SQLITE_STATIC);
    return sqlite3_step(s.get()) == SQLITE_ROW;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

AuditStore::AuditStore(pg::PgPool& pool, int retention_days, int cleanup_interval_min)
    : pool_(pool), retention_days_(retention_days), cleanup_interval_min_(cleanup_interval_min) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("AuditStore: no database connection at construction ({}) — audit "
                      "persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("AuditStore: schema migration failed — audit persistence disabled");
        return;
    }
    open_ = true;
    spdlog::info("AuditStore initialized (schema {}, retention={}d)", kStoreName, retention_days_);
}

AuditStore::~AuditStore() {
    // Join FIRST: the cleanup thread leases `pool_` every pass, so it must be
    // stopped before this object (and, upstream, the pool) is torn down.
    stop_cleanup();
}

// ── Backfill (ADR-0009 MANDATORY class / ADR-0040) ───────────────────────────

bool AuditStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    const auto backfill_metric = [this](const char* result) {
        if (metrics_)
            metrics_->counter("yuzu_server_audit_backfill_total", {{"result", result}}).increment();
    };

    // Stamp the one-time completion marker + advance the identity sequence past
    // the migrated ids, atomically. Called once at the end (and on the
    // no-legacy fresh-install path with an empty table). Advancing the sequence
    // is LOAD-BEARING: the id column is GENERATED ALWAYS AS IDENTITY and the
    // backfill supplies explicit ids via OVERRIDING SYSTEM VALUE, so without
    // this the sequence still starts at 1 and the first live log() would collide
    // with a backfilled id and fail the fail-HARD write forever.
    const auto stamp_complete = [this]() -> bool {
        return pool_.with_txn_for(kBackfillTxnTimeout, [](PGconn* c) -> bool {
            pg::PgResult sv = pg::exec_params(
                c,
                "SELECT setval(pg_get_serial_sequence('audit_store.audit_events','id'), "
                "GREATEST((SELECT COALESCE(MAX(id),0) FROM audit_store.audit_events), 1), "
                "(SELECT COUNT(*) FROM audit_store.audit_events) > 0)",
                std::vector<std::string>{});
            if (sv.status() != PGRES_TUPLES_OK) {
                spdlog::error("AuditStore: migrate_from_sqlite: sequence advance failed: {}",
                              PQerrorMessage(c));
                return false;
            }
            pg::PgResult mk = pg::exec_params(
                c,
                "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
                "('backfill_complete', $1) ON CONFLICT (key) DO NOTHING",
                std::vector<std::string>{std::to_string(now_epoch())});
            if (mk.status() != PGRES_COMMAND_OK) {
                spdlog::error("AuditStore: migrate_from_sqlite: marker stamp failed: {}",
                              PQerrorMessage(c));
                return false;
            }
            return true;
        });
    };

    // 1. Idempotency marker + resume point, on a short-lived lease released
    // before any legacy I/O (holding two size-1-pool leases at once deadlocks).
    // Resume point ASSUMES the intended cutover shape (PG starts empty, legacy
    // present): during backfill the only rows in PG are backfilled ones (log()
    // is inert until this returns and boot completes), so `MAX(id)` is a safe
    // id-ordered resume cursor after a mid-backfill crash.
    //
    // Why "PG non-empty AND no backfill_complete marker" is ALWAYS a crash-resume
    // (Gate 4 architect): native rows can only appear AFTER the marker is stamped
    // — a fresh install stamps `backfill_complete` before serving, and log() is
    // inert until boot completes, so the first native write happens strictly
    // after the marker exists. Therefore no-marker + non-empty is only reachable
    // via a partial prior backfill, for which resume-from-MAX(id) + ON CONFLICT
    // DO NOTHING is exactly correct. A "refuse boot if non-empty + no marker"
    // guard would instead BREAK that legitimate crash-resume, so it is not added.
    //
    // Multi-replica first boot (Gate 6 sre): the supported cutover is single-
    // writer SQLite → shared PG with ONE legacy audit.db (the SQLite substrate
    // never permitted N concurrent servers). N new-binary replicas racing the
    // SAME audit.db is idempotent (identical ids+content, ON CONFLICT DO NOTHING;
    // one wins the marker stamp, the rest no-op). The only unsafe shape —
    // DIVERGENT per-replica audit.db copies with colliding ids — cannot arise
    // from a single-writer history; operators scaling out MUST let the first
    // replica finish the backfill (marker stamped) before starting the rest
    // (documented in upgrading.md). A cross-txn advisory lock is deliberately NOT
    // taken here: it would reintroduce the two-lease deadlock this block avoids.
    std::int64_t resume_from = 0;
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("AuditStore: migrate_from_sqlite: no database connection ({})",
                          pool_.last_error());
            backfill_metric("failed");
            return false;
        }
        pg::PgResult mk = pg::exec_params(
            lease.get(), "SELECT 1 FROM audit_store.audit_retention_meta WHERE key='backfill_complete'",
            std::vector<std::string>{});
        if (mk.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: migrate_from_sqlite: marker lookup failed: {}",
                          PQerrorMessage(lease.get()));
            backfill_metric("failed");
            return false;
        }
        if (PQntuples(mk.get()) > 0) {
            spdlog::debug("AuditStore: migrate_from_sqlite already completed, skipping");
            return true;
        }
        pg::PgResult mx = pg::exec_params(lease.get(),
                                          "SELECT COALESCE(MAX(id),0) FROM audit_store.audit_events",
                                          std::vector<std::string>{});
        if (mx.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: migrate_from_sqlite: resume-point read failed: {}",
                          PQerrorMessage(lease.get()));
            backfill_metric("failed");
            return false;
        }
        resume_from = to_i64(PQgetvalue(mx.get(), 0, 0));
    }

    // 2. Legacy present?
    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("AuditStore: migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        backfill_metric("failed");
        return false;
    }
    if (!legacy_exists) {
        // Fresh install — nothing to migrate. Stamp complete so every later boot
        // is a cheap no-op.
        if (!stamp_complete()) {
            backfill_metric("failed");
            return false;
        }
        spdlog::info("AuditStore: migrate_from_sqlite: no legacy audit.db at {}; marking backfill "
                     "complete (fresh install)",
                     legacy_db_path.string());
        backfill_metric("fresh");
        return true;
    }

    // 3. Open the legacy DB read-only.
    SqliteDb legacy;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK) {
        spdlog::error("AuditStore: migrate_from_sqlite: failed to open legacy db {}: {}",
                      legacy_db_path.string(),
                      legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
        backfill_metric("failed");
        return false;
    }
    sqlite3_exec(legacy.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    if (!legacy_has_table(legacy.get(), "audit_events")) {
        // A legacy file with no audit_events table is not a migration source —
        // treat like a fresh install rather than looping forever.
        if (!stamp_complete()) {
            backfill_metric("failed");
            return false;
        }
        spdlog::warn("AuditStore: migrate_from_sqlite: legacy db {} has no audit_events table; "
                     "marking backfill complete",
                     legacy_db_path.string());
        backfill_metric("fresh");
        return true;
    }
    const bool has_principal_class =
        legacy_has_column(legacy.get(), "audit_events", "principal_class");

    // Legacy row count for reconciliation.
    std::int64_t legacy_count = 0;
    {
        SqliteStmt cnt;
        if (sqlite3_prepare_v2(legacy.get(), "SELECT COUNT(*) FROM audit_events", -1, cnt.addr(),
                               nullptr) != SQLITE_OK ||
            sqlite3_step(cnt.get()) != SQLITE_ROW) {
            spdlog::error("AuditStore: migrate_from_sqlite: legacy count failed: {}",
                          sqlite3_errmsg(legacy.get()));
            backfill_metric("failed");
            return false;
        }
        legacy_count = sqlite3_column_int64(cnt.get(), 0);
    }

    // 4. Stream in bounded, id-ordered batches; each batch is one PG txn with a
    // multi-row INSERT ... OVERRIDING SYSTEM VALUE ... ON CONFLICT (id) DO
    // NOTHING (idempotent + resumable). ALL columns copied incl. principal_class
    // + ttl_expires_at so the retention horizon is preserved exactly.
    const std::string select_sql =
        std::string("SELECT id, timestamp, principal, principal_role, action, "
                    "IFNULL(target_type,''), IFNULL(target_id,''), IFNULL(detail,''), "
                    "IFNULL(source_ip,''), IFNULL(user_agent,''), IFNULL(session_id,''), "
                    "result, IFNULL(ttl_expires_at,0), ") +
        (has_principal_class ? "IFNULL(principal_class,'')" : "''") +
        " FROM audit_events WHERE id > ? ORDER BY id ASC LIMIT ?";
    SqliteStmt sel;
    if (sqlite3_prepare_v2(legacy.get(), select_sql.c_str(), -1, sel.addr(), nullptr) != SQLITE_OK) {
        spdlog::error("AuditStore: migrate_from_sqlite: legacy prepare failed: {}",
                      sqlite3_errmsg(legacy.get()));
        backfill_metric("failed");
        return false;
    }

    struct Row {
        std::int64_t id{0};
        std::int64_t timestamp{0};
        std::string principal, principal_role, action, target_type, target_id, detail, source_ip,
            user_agent, session_id, result;
        std::int64_t ttl{0};
        std::string principal_class;
    };
    std::int64_t inserted = 0;
    for (;;) {
        std::vector<Row> batch;
        batch.reserve(kBackfillBatchRows);
        sqlite3_reset(sel.get());
        sqlite3_bind_int64(sel.get(), 1, resume_from);
        sqlite3_bind_int64(sel.get(), 2, static_cast<std::int64_t>(kBackfillBatchRows));
        int rc = SQLITE_DONE;
        const auto col = [&](int i) {
            const auto* v = sqlite3_column_text(sel.get(), i);
            return v ? std::string(reinterpret_cast<const char*>(v)) : std::string{};
        };
        while ((rc = sqlite3_step(sel.get())) == SQLITE_ROW) {
            Row r;
            r.id = sqlite3_column_int64(sel.get(), 0);
            r.timestamp = sqlite3_column_int64(sel.get(), 1);
            r.principal = col(2);
            r.principal_role = col(3);
            r.action = col(4);
            r.target_type = col(5);
            r.target_id = col(6);
            r.detail = col(7);
            r.source_ip = col(8);
            r.user_agent = col(9);
            r.session_id = col(10);
            r.result = col(11);
            r.ttl = sqlite3_column_int64(sel.get(), 12);
            r.principal_class = col(13);
            batch.push_back(std::move(r));
        }
        if (rc != SQLITE_DONE) {
            spdlog::error("AuditStore: migrate_from_sqlite: legacy read failed (rc={})", rc);
            backfill_metric("failed");
            return false;
        }
        if (batch.empty())
            break;

        const bool ok = pool_.with_txn_for(kBackfillTxnTimeout, [&](PGconn* c) -> bool {
            std::string sql =
                "INSERT INTO audit_store.audit_events (id, timestamp, principal, principal_role, "
                "action, target_type, target_id, detail, source_ip, user_agent, session_id, "
                "result, ttl_expires_at, principal_class) OVERRIDING SYSTEM VALUE VALUES ";
            std::vector<std::string> params;
            params.reserve(batch.size() * 14);
            for (std::size_t i = 0; i < batch.size(); ++i) {
                const auto& r = batch[i];
                const std::size_t p = params.size(); // 0-based; first placeholder is $(p+1)
                if (i != 0)
                    sql += ",";
                sql += "($" + std::to_string(p + 1) + "::bigint,$" + std::to_string(p + 2) +
                       "::bigint,$" + std::to_string(p + 3) + ",$" + std::to_string(p + 4) + ",$" +
                       std::to_string(p + 5) + ",$" + std::to_string(p + 6) + ",$" +
                       std::to_string(p + 7) + ",$" + std::to_string(p + 8) + ",$" +
                       std::to_string(p + 9) + ",$" + std::to_string(p + 10) + ",$" +
                       std::to_string(p + 11) + ",$" + std::to_string(p + 12) + ",$" +
                       std::to_string(p + 13) + "::bigint,$" + std::to_string(p + 14) + ")";
                params.push_back(std::to_string(r.id));
                params.push_back(std::to_string(r.timestamp));
                // Sanitize the untrusted free-text columns the SAME way log()
                // does, so a mis-encoded legacy byte cannot fail the fail-HARD
                // batch INSERT (SQLSTATE 22021 / NUL truncation) and abort the
                // whole backfill. result/principal_class are enum-controlled.
                params.push_back(sanitize_pg_text(r.principal));
                params.push_back(sanitize_pg_text(r.principal_role));
                params.push_back(sanitize_pg_text(r.action));
                params.push_back(sanitize_pg_text(r.target_type));
                params.push_back(sanitize_pg_text(r.target_id));
                params.push_back(sanitize_pg_text(r.detail));
                params.push_back(sanitize_pg_text(r.source_ip));
                params.push_back(sanitize_pg_text(r.user_agent));
                params.push_back(sanitize_pg_text(r.session_id));
                // result/principal_class are enum-controlled on the LIVE write
                // path, but the backfill reads them from an UNTRUSTED-at-rest
                // legacy audit.db — a single embedded NUL / invalid-UTF-8 byte
                // in either would fail this fail-hard batch INSERT (SQLSTATE
                // 22021), fail the MANDATORY backfill, and fail-close boot
                // FOREVER (every retry re-hits the same row → un-upgradeable
                // server). Sanitize them too on the backfill path (Gate 4
                // cpp-safety/unhappy #2).
                params.push_back(sanitize_pg_text(r.result));
                params.push_back(std::to_string(r.ttl));
                params.push_back(sanitize_pg_text(r.principal_class));
            }
            sql += " ON CONFLICT (id) DO NOTHING";
            pg::PgResult ins = pg::exec_params(c, sql.c_str(), params);
            if (ins.status() != PGRES_COMMAND_OK) {
                spdlog::error("AuditStore: migrate_from_sqlite: batch insert failed: {}",
                              PQerrorMessage(c));
                return false;
            }
            return true;
        });
        if (!ok) {
            spdlog::error("AuditStore: migrate_from_sqlite: batch commit failed (aborting "
                          "backfill unstamped; the next boot retries from MAX(id))");
            backfill_metric("failed");
            return false;
        }
        inserted += static_cast<std::int64_t>(batch.size());
        resume_from = batch.back().id;
        if (batch.size() < kBackfillBatchRows)
            break;
    }

    // 5. Copy audit_retention_meta (durable clock-guard reading). Legacy `value`
    // is INTEGER; PG `value` is TEXT — copy as text. DO NOTHING never clobbers a
    // reading a running replica has already advanced past.
    if (legacy_has_table(legacy.get(), "audit_retention_meta")) {
        SqliteStmt ms;
        if (sqlite3_prepare_v2(legacy.get(), "SELECT key, value FROM audit_retention_meta", -1,
                               ms.addr(), nullptr) != SQLITE_OK) {
            spdlog::error("AuditStore: migrate_from_sqlite: legacy meta prepare failed: {}",
                          sqlite3_errmsg(legacy.get()));
            backfill_metric("failed");
            return false;
        }
        std::vector<std::pair<std::string, std::string>> meta_rows;
        int rc = SQLITE_DONE;
        while ((rc = sqlite3_step(ms.get())) == SQLITE_ROW) {
            const auto* k = sqlite3_column_text(ms.get(), 0);
            if (!k)
                continue;
            std::string key(reinterpret_cast<const char*>(k));
            // Never carry a stale marker across; it is stamped fresh below.
            if (key == "backfill_complete")
                continue;
            meta_rows.emplace_back(std::move(key),
                                   std::to_string(sqlite3_column_int64(ms.get(), 1)));
        }
        if (rc != SQLITE_DONE) {
            spdlog::error("AuditStore: migrate_from_sqlite: legacy meta read failed (rc={})", rc);
            backfill_metric("failed");
            return false;
        }
        if (!meta_rows.empty()) {
            const bool ok = pool_.with_txn_for(kBackfillTxnTimeout, [&](PGconn* c) -> bool {
                for (const auto& [k, v] : meta_rows) {
                    pg::PgResult r = pg::exec_params(
                        c,
                        "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES ($1, $2) "
                        "ON CONFLICT (key) DO NOTHING",
                        std::vector<std::string>{k, v});
                    if (r.status() != PGRES_COMMAND_OK) {
                        spdlog::error("AuditStore: migrate_from_sqlite: meta copy failed: {}",
                                      PQerrorMessage(c));
                        return false;
                    }
                }
                return true;
            });
            if (!ok) {
                backfill_metric("failed");
                return false;
            }
        }
    }

    // 6. Row-count reconciliation (ADR-0040: logged AND asserted).
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("AuditStore: migrate_from_sqlite: reconciliation lease failed ({})",
                          pool_.last_error());
            backfill_metric("failed");
            return false;
        }
        pg::PgResult pc = pg::exec_params(
            lease.get(), "SELECT COUNT(*) FROM audit_store.audit_events", std::vector<std::string>{});
        if (pc.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: migrate_from_sqlite: reconciliation count failed: {}",
                          PQerrorMessage(lease.get()));
            backfill_metric("failed");
            return false;
        }
        const std::int64_t pg_count = to_i64(PQgetvalue(pc.get(), 0, 0));
        if (pg_count < legacy_count) {
            spdlog::error("AuditStore: migrate_from_sqlite: reconciliation FAILED — legacy has {} "
                          "row(s) but PostgreSQL has {}; refusing to mark complete (fail-closed, "
                          "the next boot retries)",
                          legacy_count, pg_count);
            backfill_metric("failed");
            return false;
        }
        spdlog::info("AuditStore: migrate_from_sqlite: reconciled — legacy {} row(s), PostgreSQL "
                     "{} row(s) ({} inserted this run)",
                     legacy_count, pg_count, inserted);
    }

    // 7. Advance the identity sequence + stamp the one-time marker atomically.
    if (!stamp_complete()) {
        backfill_metric("failed");
        return false;
    }

    // 8. Move the verified legacy file aside (not delete) — the pre-cutover
    // evidence stays recoverable (operator-managed-backup convention). Failure
    // here is NON-fatal: the backfill is already committed + marked, so a
    // rename failure must not refuse boot.
    // Close the legacy read-only handle FIRST: Windows refuses to rename a file
    // with an open handle (ERROR_SHARING_VIOLATION), so leaving `legacy` open
    // silently defeated the move-aside on the Wee Tam MSVC leg (POSIX allows
    // rename-with-open-handle, so it passed on Linux/macOS). All legacy reads
    // are already materialised in memory above.
    legacy.close();
    std::error_code mv_ec;
    auto aside = legacy_db_path;
    aside += ".migrated-" + std::to_string(now_epoch());
    std::filesystem::rename(legacy_db_path, aside, mv_ec);
    if (mv_ec)
        spdlog::warn("AuditStore: migrate_from_sqlite: backfill complete but could not move legacy "
                     "{} aside ({}); it is safe to archive/remove manually",
                     legacy_db_path.string(), mv_ec.message());
    else
        spdlog::info("AuditStore: migrate_from_sqlite: moved legacy audit db to {}", aside.string());

    backfill_metric("completed");
    return true;
}

// ── Write (FAIL-HARD) ────────────────────────────────────────────────────────

bool AuditStore::log(const AuditEvent& event) {
    if (!open_) {
        // Audit DB not open — surface as a failure so callers can flag the gap
        // on the response (HIGH-2, PR #883). Operators running audit-off never
        // reach here (AuthRoutes short-circuits on a null store).
        emit_failed_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        emit_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::error("AuditStore::log: no connection for action={} ({}); event lost",
                      event.action, pool_.last_error());
        return false;
    }
    PGconn* conn = lease.get();

    const int64_t now = now_epoch();
    const int64_t ts = event.timestamp > 0 ? event.timestamp : now;
    const int64_t ttl = retention_days_ > 0 ? now + static_cast<int64_t>(retention_days_) * 86400 : 0;

    // Sanitize the untrusted free-text columns; result/principal_class are
    // enum-controlled (ADR-0040) and bound verbatim.
    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO audit_store.audit_events (timestamp, principal, principal_role, action, "
        "target_type, target_id, detail, source_ip, user_agent, session_id, result, "
        "ttl_expires_at, principal_class) "
        "VALUES ($1::bigint,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::bigint,$13) RETURNING id",
        std::vector<std::string>{std::to_string(ts), sanitize_pg_text(event.principal),
                                 sanitize_pg_text(event.principal_role),
                                 sanitize_pg_text(event.action),
                                 sanitize_pg_text(event.target_type),
                                 sanitize_pg_text(event.target_id), sanitize_pg_text(event.detail),
                                 sanitize_pg_text(event.source_ip),
                                 sanitize_pg_text(event.user_agent),
                                 sanitize_pg_text(event.session_id), event.result,
                                 std::to_string(ttl), event.principal_class});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
        emit_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::error("AuditStore::log: insert failed for action={}: {}; event lost", event.action,
                      PQerrorMessage(conn));
        return false;
    }

    // Bucket the write into a Prometheus-friendly counter. Result vocabulary is
    // open-ended at call sites — collapse anything unrecognised into "other".
    if (event.result == "success")
        events_success_.fetch_add(1, std::memory_order_relaxed);
    else if (event.result == "failure")
        events_failure_.fetch_add(1, std::memory_order_relaxed);
    else if (event.result == "denied")
        events_denied_.fetch_add(1, std::memory_order_relaxed);
    else
        events_other_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

uint64_t AuditStore::events_written(const std::string& result) const noexcept {
    if (result == "success")
        return events_success_.load(std::memory_order_relaxed);
    if (result == "failure")
        return events_failure_.load(std::memory_order_relaxed);
    if (result == "denied")
        return events_denied_.load(std::memory_order_relaxed);
    if (result == "other")
        return events_other_.load(std::memory_order_relaxed);
    return 0;
}

// ── Reads (degrade-distinguishable, DENY on degrade) ─────────────────────────

std::optional<std::vector<AuditEvent>> AuditStore::query(const AuditQuery& q,
                                                         std::size_t* out_pool_size) const {
    static DegradeSampler sampler;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, sampler))
            spdlog::warn("AuditStore::query: store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("AuditStore::query: pool acquire timed out");
        return std::nullopt;
    }
    PGconn* conn = lease.get();

    std::string sql =
        "SELECT id, timestamp, principal, principal_role, action, target_type, target_id, detail, "
        "source_ip, user_agent, session_id, result, principal_class FROM audit_store.audit_events "
        "WHERE 1=1";
    std::vector<std::string> binds;
    int idx = 1;
    if (!q.principal.empty()) {
        sql += " AND principal = $" + std::to_string(idx++);
        binds.push_back(q.principal);
    }
    if (!q.action.empty()) {
        sql += " AND action = $" + std::to_string(idx++);
        binds.push_back(q.action);
    }
    if (!q.target_type.empty()) {
        sql += " AND target_type = $" + std::to_string(idx++);
        binds.push_back(q.target_type);
    }
    if (!q.target_id.empty()) {
        sql += " AND target_id = $" + std::to_string(idx++);
        binds.push_back(q.target_id);
    }
    if (q.since > 0) {
        sql += " AND timestamp >= $" + std::to_string(idx++) + "::bigint";
        binds.push_back(std::to_string(q.since));
    }
    if (q.until > 0) {
        sql += " AND timestamp <= $" + std::to_string(idx++) + "::bigint";
        binds.push_back(std::to_string(q.until));
    }
    // Prefix OR-group (auth./mfa./session. for the auth-log sample, #4).
    // Prefixes are code-controlled constants; each binds as `<prefix>%`. Any
    // prefix carrying a LIKE metacharacter is dropped (fails closed for that
    // prefix); an all-empty group emits an always-false guard so it never
    // silently widens to "all actions" (Hermes M-2).
    if (!q.action_prefixes.empty()) {
        sql += " AND (";
        bool first = true;
        for (const auto& p : q.action_prefixes) {
            if (p.empty() || p.find_first_of("%_\\") != std::string::npos)
                continue;
            sql += first ? "action LIKE $" + std::to_string(idx)
                         : " OR action LIKE $" + std::to_string(idx);
            binds.push_back(p + "%");
            ++idx;
            first = false;
        }
        sql += first ? "1=0)" : ")";
    }

    // Always order by the indexed timestamp — never ORDER BY RANDOM() (a full
    // scan of the window). For random_sample, over-fetch a bounded candidate
    // pool and shuffle+truncate in C++ (Hermes M-1). OFFSET is meaningless under
    // random order, so it is skipped there.
    const int64_t fetch_limit =
        q.random_sample ? std::max(static_cast<int64_t>(q.limit),
                                   static_cast<int64_t>(kAuditSampleScanCap))
                        : static_cast<int64_t>(q.limit);
    sql += " ORDER BY timestamp DESC LIMIT $" + std::to_string(idx++) + "::bigint";
    binds.push_back(std::to_string(fetch_limit));
    if (q.offset > 0 && !q.random_sample) {
        sql += " OFFSET $" + std::to_string(idx++) + "::bigint";
        binds.push_back(std::to_string(q.offset));
    }

    pg::PgResult res = pg::exec_params(conn, sql.c_str(), binds);
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("AuditStore::query: query failed: {}", PQerrorMessage(conn));
        return std::nullopt;
    }
    std::vector<AuditEvent> results;
    const int n = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        AuditEvent e;
        e.id = to_i64(PQgetvalue(res.get(), i, 0));
        e.timestamp = to_i64(PQgetvalue(res.get(), i, 1));
        e.principal = text_col(res.get(), i, 2);
        e.principal_role = text_col(res.get(), i, 3);
        e.action = text_col(res.get(), i, 4);
        e.target_type = text_col(res.get(), i, 5);
        e.target_id = text_col(res.get(), i, 6);
        e.detail = text_col(res.get(), i, 7);
        e.source_ip = text_col(res.get(), i, 8);
        e.user_agent = text_col(res.get(), i, 9);
        e.session_id = text_col(res.get(), i, 10);
        e.result = text_col(res.get(), i, 11);
        e.principal_class = text_col(res.get(), i, 12);
        results.push_back(std::move(e));
    }

    if (q.random_sample) {
        if (out_pool_size)
            *out_pool_size = results.size();
        const auto keep = static_cast<std::size_t>(std::max(q.limit, 0));
        if (results.size() > keep) {
            static thread_local std::mt19937_64 rng{std::random_device{}()};
            std::shuffle(results.begin(), results.end(), rng);
            results.resize(keep);
        }
    }
    return results;
}

std::optional<std::size_t> AuditStore::total_count() const {
    static DegradeSampler sampler;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, sampler))
            spdlog::warn("AuditStore::total_count: store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("AuditStore::total_count: pool acquire timed out");
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(lease.get(), "SELECT COUNT(*) FROM audit_store.audit_events",
                                       std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("AuditStore::total_count: query failed: {}", PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

// ── Retention (clock-guarded, single-sweeper advisory lease — #2360/ADR-0040) ─

std::size_t AuditStore::cleanup_once(std::int64_t now) {
    // Liveness, stamped for EVERY pass (attempted) — including declines,
    // failures, and lock-skips. A reaper that runs and declines is healthy; one
    // that never runs is the failure these expose. Stamped BEFORE any return.
    retention_passes_.fetch_add(1, std::memory_order_relaxed);

    // Sanitise the CALLER's clock: `now + window + slack` below is signed-
    // overflow UB near INT64_MAX. UPPER bound only — a NEGATIVE `now` is the
    // legitimate dead-CMOS case this guard exists for.
    constexpr std::int64_t kMaxPlausibleNow = std::numeric_limits<std::int64_t>::max() / 4;
    if (now > kMaxPlausibleNow) {
        cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::warn("AuditStore: retention pass called with an implausible clock reading ({}); "
                     "declining the pass",
                     now);
        return 0;
    }
    // Stamped only for a reading the guard will reason about. The ATTEMPT is
    // counted above; stamping a value just declared unusable would poison the
    // staleness gauge permanently.
    last_pass_unixtime_.store(now, std::memory_order_relaxed);

    if (!open_) {
        // A store that never opened has stopped retaining permanently; count a
        // failed pass rather than silence (else an ever-growing table reads as a
        // healthy guard).
        cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }

    const std::int64_t window =
        retention_days_ > 0 ? static_cast<std::int64_t>(retention_days_) * 86400 : 0;

    // Outcomes captured under the txn, acted on after it commits so counters
    // only move for committed passes and no spdlog formatting runs under lock.
    std::size_t deleted = 0;
    bool skipped_lock = false;
    bool declined = false;
    bool cap_backlog = false;
    bool persist_failed = false;
    std::string decline_msg;

    const bool ok = pool_.with_txn_for(kReapTimeout, [&](PGconn* conn) -> bool {
        // Exactly one replica sweeps per tick fleet-wide.
        pg::PgResult lk = pg::exec_params(
            conn, "SELECT pg_try_advisory_xact_lock(hashtextextended('audit_store:reap', 0))",
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: reap lock probe failed: {}", PQerrorMessage(conn));
            return false;
        }
        if (!to_bool(PQgetvalue(lk.get(), 0, 0))) {
            skipped_lock = true;
            return true; // another replica is sweeping; not a failure
        }

        // Durable dedup state (shared across replicas + restarts).
        pg::PgResult meta = pg::exec_params(
            conn,
            "SELECT key, value FROM audit_store.audit_retention_meta WHERE key IN ('last_pass_now',"
            "'last_anomaly_facts')",
            std::vector<std::string>{});
        if (meta.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: reap meta read failed: {}", PQerrorMessage(conn));
            return false;
        }
        std::optional<std::int64_t> prev;
        bool prev_unusable = false;
        std::string last_facts;
        for (int i = 0; i < PQntuples(meta.get()); ++i) {
            const std::string key = text_col(meta.get(), i, 0);
            const std::string val = text_col(meta.get(), i, 1);
            if (key == "last_pass_now") {
                // A stored reading that is not an integer is corrupted/hand-
                // edited durable state — an anomaly, not a clean slate.
                errno = 0;
                char* end = nullptr;
                const long long v = std::strtoll(val.c_str(), &end, 10);
                if (val.empty() || errno != 0 || end == val.c_str() || *end != '\0')
                    prev_unusable = true;
                else
                    prev = static_cast<std::int64_t>(v);
            } else if (key == "last_anomaly_facts") {
                last_facts = val;
            }
        }
        // A reading ahead of the clock (backward NTP correction) or negative
        // (corruption) cannot be reasoned about — decline either way.
        if (prev && (*prev < 0 || *prev > now)) {
            prev_unusable = true;
            prev.reset();
        }

        // Re-anchor the reading for the next pass BEFORE any early return, so a
        // decline still updates the comparison point and a poisoned value
        // self-heals. Persisting it is the only half of the guard that works
        // when the clock was already wrong before the process started.
        pg::PgResult stamp = pg::exec_params(
            conn,
            "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES ('last_pass_now', $1) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{std::to_string(now)});
        if (stamp.status() != PGRES_COMMAND_OK) {
            spdlog::error("AuditStore: reap meta stamp failed: {}", PQerrorMessage(conn));
            persist_failed = true;
            return false; // fail closed — roll back the whole pass
        }

        // Detect by OUTCOME: two counts answer the whole question and stay
        // index-driven. A forward-skewed row past `now + window + slack` can
        // never expire, so it is EXCLUDED from the survivor question — else one
        // bad row vetoes the guard for the store's life.
        const std::int64_t datable_horizon = now + window + kAuditTtlFutureSlackSec;
        pg::PgResult probe = pg::exec_params(
            conn,
            "SELECT count(*) FILTER (WHERE ttl_expires_at > 0 AND ttl_expires_at < $1::bigint) AS "
            "expiring, count(*) FILTER (WHERE ttl_expires_at > 0 AND ttl_expires_at >= $1::bigint "
            "AND ttl_expires_at <= $2::bigint) AS survivor FROM audit_store.audit_events",
            std::vector<std::string>{std::to_string(now), std::to_string(datable_horizon)});
        if (probe.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: reap probe failed: {}", PQerrorMessage(conn));
            return false;
        }
        const std::int64_t expiring = to_i64(PQgetvalue(probe.get(), 0, 0));
        const std::int64_t survivor = to_i64(PQgetvalue(probe.get(), 0, 1));

        const bool has_expired = expiring > 0;
        const bool would_wipe = has_expired && survivor == 0;
        // Supplement to would_wipe: a half-window jump expires a large slice
        // while leaving survivors, which the cap bounds but nothing else reports.
        // Gated on window > 0 and strictly greater than the absolute floor.
        const bool big_step = prev.has_value() && window > 0 && has_expired &&
                              (now - *prev) > kAuditMinBigStepSec;

        const audit_retention::Facts facts{.has_expired = has_expired,
                                           .would_wipe = would_wipe,
                                           .big_step = big_step,
                                           .prev_unusable = prev_unusable};
        const audit_retention::Anomaly anomaly = audit_retention::classify(facts);
        const std::string facts_ser = serialize_facts(facts);

        if (anomaly != audit_retention::Anomaly::None) {
            // Decline-once per DISTINCT fact set: a new anomaly declines and
            // records; an identical repeat is suppressed and drains (paced by
            // the cap), so a legitimately all-expired store still ages out.
            if (facts_ser != last_facts) {
                pg::PgResult rec = pg::exec_params(
                    conn,
                    "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
                    "('last_anomaly_facts', $1) ON CONFLICT (key) DO UPDATE SET value = "
                    "EXCLUDED.value",
                    std::vector<std::string>{facts_ser});
                if (rec.status() != PGRES_COMMAND_OK) {
                    spdlog::error("AuditStore: reap anomaly record failed: {}",
                                  PQerrorMessage(conn));
                    return false;
                }
                declined = true;
                decline_msg = "AuditStore: retention clock anomaly (facts=" + facts_ser +
                              ") — declining this pass; an identical next pass will drain, capped";
                return true; // commit the stamp + anomaly record
            }
            // Suppressed repeat of the same fact set — fall through to drain.
        } else if (!last_facts.empty()) {
            pg::PgResult clr = pg::exec_params(
                conn, "DELETE FROM audit_store.audit_retention_meta WHERE key = 'last_anomaly_facts'",
                std::vector<std::string>{});
            if (clr.status() != PGRES_COMMAND_OK) {
                spdlog::error("AuditStore: reap anomaly clear failed: {}", PQerrorMessage(conn));
                return false;
            }
        }
        if (expiring == 0)
            return true; // nothing to do

        // Bounded, oldest-first delete so even an allowed wipe ages out at a
        // paced rate. RETURNING carries the count (no sqlite3_changes()/#1033).
        pg::PgResult del = pg::exec_params(
            conn,
            "DELETE FROM audit_store.audit_events WHERE id IN (SELECT id FROM "
            "audit_store.audit_events WHERE ttl_expires_at > 0 AND ttl_expires_at < $1::bigint "
            "ORDER BY ttl_expires_at ASC, id ASC LIMIT $2::bigint) RETURNING id",
            std::vector<std::string>{std::to_string(now),
                                     std::to_string(static_cast<std::int64_t>(
                                         kMaxAuditDeletesPerPass))});
        if (del.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: reap delete failed: {}", PQerrorMessage(conn));
            return false;
        }
        deleted = static_cast<std::size_t>(PQntuples(del.get()));

        // Hitting the cap does NOT prove a backlog remains (an exact-boundary
        // pass drained the last row). Probe for a real remainder, and ONLY when
        // the cap bound, so the healthy path pays nothing.
        if (deleted >= kMaxAuditDeletesPerPass) {
            pg::PgResult more = pg::exec_params(
                conn,
                "SELECT EXISTS(SELECT 1 FROM audit_store.audit_events WHERE ttl_expires_at > 0 AND "
                "ttl_expires_at < $1::bigint)",
                std::vector<std::string>{std::to_string(now)});
            if (more.status() != PGRES_TUPLES_OK) {
                spdlog::error("AuditStore: reap backlog probe failed: {}", PQerrorMessage(conn));
                return false;
            }
            cap_backlog = to_bool(PQgetvalue(more.get(), 0, 0));
        }
        return true;
    });

    if (!ok) {
        if (persist_failed)
            persist_failed_.fetch_add(1, std::memory_order_relaxed);
        cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::warn("AuditStore: retention pass aborted (statement failed or txn rolled back — "
                     "see the preceding error line)");
        return 0;
    }
    if (skipped_lock)
        return 0; // another replica swept this tick
    if (declined) {
        clock_anomaly_skips_.fetch_add(1, std::memory_order_relaxed);
        spdlog::warn("{}", decline_msg);
        return 0;
    }
    if (deleted > 0) {
        rows_deleted_.fetch_add(deleted, std::memory_order_relaxed);
        if (cap_backlog) {
            cap_reached_.fetch_add(1, std::memory_order_relaxed);
            spdlog::info("AuditStore: expired {} rows (per-pass cap reached; the remainder ages "
                         "out on subsequent passes)",
                         deleted);
        } else {
            spdlog::info("AuditStore: expired {} rows", deleted);
        }
    }
    return deleted;
}

void AuditStore::start_cleanup() {
    if (!open_ || cleanup_interval_min_ <= 0)
        return;
#ifdef __cpp_lib_jthread
    cleanup_thread_ = std::jthread([this](std::stop_token stop) { run_cleanup(stop); });
#else
    stop_requested_ = false;
    cleanup_thread_ = std::thread([this]() { run_cleanup(); });
#endif
}

void AuditStore::stop_cleanup() {
#ifdef __cpp_lib_jthread
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.request_stop();
        cleanup_thread_.join();
    }
#else
    stop_requested_ = true;
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
#endif
}

#ifdef __cpp_lib_jthread
void AuditStore::run_cleanup(std::stop_token stop) {
    while (!stop.stop_requested()) {
        for (int i = 0; i < cleanup_interval_min_ * 60 && !stop.stop_requested(); ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (stop.stop_requested())
            break;
#else
void AuditStore::run_cleanup() {
    while (!stop_requested_.load()) {
        for (int i = 0; i < cleanup_interval_min_ * 60 && !stop_requested_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (stop_requested_.load())
            break;
#endif
        const auto now = now_epoch();
        // NOTHING may escape a thread function: an exception here is
        // std::terminate. cleanup_once allocates and formats, so the surface is
        // real (#2037 class).
        try {
            cleanup_once(now);
        } catch (...) {
            cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
            try {
                try {
                    throw;
                } catch (const std::exception& e) {
                    spdlog::error("AuditStore: retention pass threw ({}); abandoned, retried at "
                                  "the next interval",
                                  e.what());
                } catch (...) {
                    spdlog::error("AuditStore: retention pass threw a non-std exception; "
                                  "abandoned, retried at the next interval");
                }
            } catch (...) {
                // Nothing escapes a thread function, not even a failure to report.
            }
        }
    }
}

} // namespace yuzu::server
