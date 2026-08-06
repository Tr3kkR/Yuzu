#include "audit_store.hpp"
#include "config_secret_keys.hpp"

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
#include <format>
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

// Serialize the five guard facts to a stable string — the durable dedup key
// (mirrors ResponseStore's `facts_ser`). Compares the whole FACT SET, not the
// classified enum, so a Wipe arriving underneath a standing BadState (the
// dead-CMOS-then-NTP sequence that silently wiped the whole trail) is NOT
// suppressed: the fact set differs, so the pass declines again.
// The `no_anchor` character is part of the set on purpose (#2579): the pass that
// declines for it also settles the bootstrap marker, so the NEXT pass differs in
// this very field and is a different set — which is what lets the trigger decline
// once and then stand down without any anti-latch special case. There is no
// four-character legacy value to worry about here: migration v1 creates this
// table fresh, and the SQLite predecessor's meta table held only an INTEGER
// `last_pass_now`, never a fact-set string. (An earlier revision of this comment
// reasoned about upgrading from a four-character value, carried over from a
// store where that was possible.)
std::string serialize_facts(const audit_retention::Facts& f) {
    return std::string(f.has_expired ? "e" : "-") + (f.would_wipe ? "w" : "-") +
           (f.big_step ? "s" : "-") + (f.prev_unusable ? "u" : "-") + (f.no_anchor ? "b" : "-");
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

// Three outcomes, not two. `sqlite3_prepare_v2` failing (corrupt file, encrypted
// file, disk I/O error — bytes present that do not parse as a SQLite header)
// is NOT the same fact as "the table genuinely does not exist" — the former
// means this process cannot see what the file holds, the latter means it can
// see the file holds nothing of interest. Collapsing them to one `bool` let a
// corrupt `audit.db` read as "no source, fresh install" and silently forfeit
// the mandatory backfill (Gate 4 unhappy-path UP-1, measured on a 38-byte junk
// file). A genuinely zero-byte file is `Absent`, not `Error` — measured
// separately: SQLite treats 0 bytes as a valid, uninitialized database and
// `sqlite_master` reads back empty rather than failing, which is the correct
// answer, since a 0-byte file cannot encode any evidence to lose.
enum class LegacyTableStatus { Present, Absent, Error };

LegacyTableStatus legacy_has_table(sqlite3* db, const char* table) {
    SqliteStmt s;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", -1,
                           s.addr(), nullptr) != SQLITE_OK)
        return LegacyTableStatus::Error;
    sqlite3_bind_text(s.get(), 1, table, -1, SQLITE_STATIC);
    const int rc = sqlite3_step(s.get());
    if (rc == SQLITE_ROW)
        return LegacyTableStatus::Present;
    if (rc == SQLITE_DONE)
        return LegacyTableStatus::Absent;
    return LegacyTableStatus::Error;
}

// ── Legacy content fingerprint ────────────────────────────────────────────
//
// One shape, two uses. `(COUNT, SUM(id), SUM(timestamp), MIN(timestamp),
// MAX(timestamp))` over `audit_events`, optionally bounded to `id <= max_id`:
//   * bounded — the ADR-0009 prefix proof at resume time, comparing against
//     what PG already holds at or below the resume cursor;
//   * unbounded (`max_id = nullopt`) — the WHOLE file's fingerprint, computed
//     once a backfill has streamed every row, and stored as this run's
//     `backfill_source_fingerprint` alongside the completion marker. That
//     stored value is what a LATER boot compares a still-present legacy file
//     against (see `migrate_from_sqlite`'s marker-present branch) — never
//     against PG's live content, which drifts as retention deletes backfilled
//     rows and native writes accumulate. A stored fingerprint is immutable
//     once written and immune to that drift; PG's current state is not.
//
// Ids run `1..k` contiguously in every deployment (`GENERATED ALWAYS AS
// IDENTITY` here, `rowid` there), so a count or an id-sum alone is defeated
// SYSTEMATICALLY by any other table of the same size, not by coincidence —
// the timestamp components are what actually differ between two histories.
struct LegacyFingerprint {
    std::int64_t count = 0;
    std::int64_t id_sum = 0;
    std::int64_t ts_sum = 0;
    std::int64_t ts_min = 0;
    std::int64_t ts_max = 0;

    [[nodiscard]] std::string to_string() const {
        return std::format("{}:{}:{}:{}:{}", count, id_sum, ts_sum, ts_min, ts_max);
    }
    bool operator==(const LegacyFingerprint&) const = default;
};

std::optional<LegacyFingerprint> legacy_fingerprint(sqlite3* legacy,
                                                     std::optional<std::int64_t> max_id) {
    const char* sql =
        max_id ? "SELECT COUNT(*), COALESCE(SUM(id),0), COALESCE(SUM(timestamp),0), "
                 "COALESCE(MIN(timestamp),0), COALESCE(MAX(timestamp),0) FROM audit_events "
                 "WHERE id <= ?"
               : "SELECT COUNT(*), COALESCE(SUM(id),0), COALESCE(SUM(timestamp),0), "
                 "COALESCE(MIN(timestamp),0), COALESCE(MAX(timestamp),0) FROM audit_events";
    SqliteStmt s;
    if (sqlite3_prepare_v2(legacy, sql, -1, s.addr(), nullptr) != SQLITE_OK)
        return std::nullopt;
    if (max_id)
        sqlite3_bind_int64(s.get(), 1, *max_id);
    if (sqlite3_step(s.get()) != SQLITE_ROW)
        return std::nullopt;
    LegacyFingerprint fp;
    fp.count = sqlite3_column_int64(s.get(), 0);
    fp.id_sum = sqlite3_column_int64(s.get(), 1);
    fp.ts_sum = sqlite3_column_int64(s.get(), 2);
    fp.ts_min = sqlite3_column_int64(s.get(), 3);
    fp.ts_max = sqlite3_column_int64(s.get(), 4);
    return fp;
}

// Parses a `LegacyFingerprint::to_string()` value read back from
// `audit_retention_meta`. `nullopt` on any malformed input (wrong field count,
// non-numeric field) — a fingerprint that fails to parse is exactly as
// untrustworthy as one that fails to match, and the caller treats both
// identically (refuse, never "assume it matches").
std::optional<LegacyFingerprint> parse_fingerprint(std::string_view s) {
    std::vector<std::string_view> parts;
    std::size_t start = 0;
    for (;;) {
        const std::size_t colon = s.find(':', start);
        parts.push_back(s.substr(
            start, colon == std::string_view::npos ? std::string_view::npos : colon - start));
        if (colon == std::string_view::npos)
            break;
        start = colon + 1;
    }
    if (parts.size() != 5)
        return std::nullopt;
    std::int64_t values[5];
    for (std::size_t i = 0; i < 5; ++i) {
        if (parts[i].empty())
            return std::nullopt;
        const std::string part_str(parts[i]);
        errno = 0;
        char* end = nullptr;
        const long long v = std::strtoll(part_str.c_str(), &end, 10);
        if (errno != 0 || end != part_str.c_str() + part_str.size())
            return std::nullopt;
        values[i] = static_cast<std::int64_t>(v);
    }
    LegacyFingerprint fp;
    fp.count = values[0];
    fp.id_sum = values[1];
    fp.ts_sum = values[2];
    fp.ts_min = values[3];
    fp.ts_max = values[4];
    return fp;
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

void AuditStore::set_metrics(yuzu::MetricsRegistry* m) {
    metrics_ = m;
    if (!m)
        return;
    // Pre-seed both closed label sets this store owns, per
    // docs/observability-conventions.md: a bounded-label counter is initialised
    // at startup so the family is present on a healthy server and `absent()`
    // alerts stay meaningful.
    //
    // LOAD-BEARING for the backfill family. `YuzuAuditBackfillFailing` keys on
    // the ABSENCE of a success outcome, and the ordinary restart of an
    // already-migrated server returns at the marker check in
    // `migrate_from_sqlite` without ever reaching an outcome — so an unseeded
    // family means a HEALTHY server exports no `completed`/`fresh` series and
    // the critical alert fires on every routine restart. Seeded where the store
    // OWNS the family rather than in server.cpp's metrics block (where the
    // management-group twin is seeded) so that wiring a registry is what
    // guarantees the series, and a unit test can pin it.
    m->describe("yuzu_server_audit_backfill_total",
                "Outcome of the one-time legacy audit.db -> PostgreSQL backfill (ADR-0040): "
                "completed = streamed and reconciled; fresh = nothing to migrate; failed = "
                "fail-closed refusal. All three stay 0 on a restart that finds the "
                "backfill_complete marker already stamped",
                "counter");
    for (const char* result : {"completed", "fresh", "failed"})
        m->counter("yuzu_server_audit_backfill_total", {{"result", result}});

    m->describe("yuzu_server_audit_read_degrade_total",
                "Audit READ queries that could not be served and returned 503 instead of a "
                "false-empty 200 (deny-on-degrade), by reason",
                "counter");
    for (const char* reason : {kReasonStoreNotOpen, kReasonPoolTimeout, kReasonQueryError})
        m->counter("yuzu_server_audit_read_degrade_total", {{"reason", reason}});
}

// ── Backfill (ADR-0009 MANDATORY class / ADR-0040) ───────────────────────────

bool AuditStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path,
                                     Sourceless sourceless) {
    if (!open_)
        return false;

    // Arm the write gate for the duration. It is cleared only where this
    // function SUCCEEDS; every failure path below leaves it armed, so `log()`
    // declines until a later attempt succeeds. See the header for why the
    // constructor's own audit hooks make this necessary rather than defensive.
    backfill_pending_.store(true, std::memory_order_release);
    const auto backfill_ok = [this] {
        backfill_pending_.store(false, std::memory_order_release);
        return true;
    };

    const auto backfill_metric = [this](const char* result) {
        if (metrics_)
            metrics_->counter("yuzu_server_audit_backfill_total", {{"result", result}}).increment();
    };

    // Move a verified legacy file aside (never delete). Shared by the normal
    // end-of-backfill path and the marker-present verification path below —
    // the latter exists specifically to RETRY a move that failed on an earlier
    // boot (Windows file-in-use, a transient permissions issue). Failure here
    // is non-fatal in both callers: the trail's presence in PG has already been
    // established by the time this runs, so a rename failure only means the
    // retained copy stays where it is and a later boot tries again.
    const auto move_legacy_aside = [&legacy_db_path]() {
        std::error_code mv_ec;
        auto aside = legacy_db_path;
        aside += ".migrated-" + std::to_string(now_epoch());
        std::filesystem::rename(legacy_db_path, aside, mv_ec);
        if (mv_ec) {
            spdlog::warn(
                "AuditStore: migrate_from_sqlite: could not move legacy {} aside ({}); it is safe "
                "to archive/remove manually, or a later boot retries",
                legacy_db_path.string(), mv_ec.message());
            return;
        }
        // Carry the WAL/SHM sidecars across with the main file — see the
        // move-aside rationale where this was originally inline: a clean
        // shutdown checkpoints them away, but after an unclean stop the
        // committed tail lives in `-wal`, and the retained copy is unopenable
        // standalone without it.
        for (const char* suffix : {"-wal", "-shm"}) {
            auto side = legacy_db_path;
            side += suffix;
            std::error_code side_ec;
            if (!std::filesystem::exists(side, side_ec) || side_ec)
                continue;
            auto side_aside = aside;
            side_aside += suffix;
            std::filesystem::rename(side, side_aside, side_ec);
            if (side_ec)
                spdlog::warn(
                    "AuditStore: migrate_from_sqlite: moved the legacy audit db but not its {} "
                    "sidecar ({}); the retained copy at {} may not open standalone until the "
                    "sidecar is moved beside it",
                    suffix, side_ec.message(), aside.string());
        }
        spdlog::info("AuditStore: migrate_from_sqlite: moved legacy audit db to {}", aside.string());
    };

    // Stamp the one-time completion marker + advance the identity sequence past
    // the migrated ids, atomically. Called once at the end (and on the
    // no-legacy fresh-install path with an empty table). Advancing the sequence
    // is LOAD-BEARING: the id column is GENERATED ALWAYS AS IDENTITY and the
    // backfill supplies explicit ids via OVERRIDING SYSTEM VALUE, so without
    // this the sequence still starts at 1 and the first live log() would collide
    // with a backfilled id and fail the fail-HARD write forever.
    // `require_empty` is for the sourceless callers: the emptiness they checked
    // outside this transaction is a TOCTOU read — a peer replica can stream rows
    // in between. Re-checking INSIDE the stamping transaction closes it, because
    // the marker and the check then commit or roll back together.
    //
    // `source_fingerprint` is stamped in the SAME transaction as the marker —
    // one commit, one fact. It is what a LATER boot, finding the marker present
    // AND a legacy file still on disk, compares that file's own fingerprint
    // against (see the marker-present branch below). A real backfill passes the
    // whole-file `LegacyFingerprint` it just proved; `complete_without_source`
    // passes the literal `"sourceless"`, which can never equal a real
    // fingerprint — so a host with a genuine, non-empty legacy file can never
    // be waved through by a marker some OTHER process stamped without ever
    // reading a file (Gate 3 architect A-4 / Sol: local absence must not be
    // trusted as proof of deployment-wide absence).
    const auto stamp_complete = [this](bool require_empty, std::string_view source_fingerprint) -> bool {
        return pool_.with_txn_for(
            kBackfillTxnTimeout, [require_empty, source_fingerprint](PGconn* c) -> bool {
                if (require_empty) {
                    pg::PgResult n = pg::exec_params(c,
                                                     "SELECT COUNT(*) FROM audit_store.audit_events",
                                                     std::vector<std::string>{});
                    if (n.status() != PGRES_TUPLES_OK) {
                        spdlog::error(
                            "AuditStore: migrate_from_sqlite: emptiness re-check failed: {}",
                            PQerrorMessage(c));
                        return false;
                    }
                    if (to_i64(PQgetvalue(n.get(), 0, 0)) > 0) {
                        spdlog::error(
                            "AuditStore: migrate_from_sqlite: refusing to mark the backfill "
                            "complete — audit_events became NON-EMPTY while this pass was "
                            "deciding, so another process is writing or streaming into it. Let "
                            "that process finish; it stamps the marker.");
                        return false;
                    }
                }
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
                pg::PgResult fp = pg::exec_params(
                    c,
                    "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
                    "('backfill_source_fingerprint', $1) ON CONFLICT (key) DO NOTHING",
                    std::vector<std::string>{std::string(source_fingerprint)});
                if (fp.status() != PGRES_COMMAND_OK) {
                    spdlog::error(
                        "AuditStore: migrate_from_sqlite: source-fingerprint stamp failed: {}",
                        PQerrorMessage(c));
                    return false;
                }
                return true;
            });
    };

    // 1. Idempotency marker + resume point, on a short-lived lease released
    // before any legacy I/O (holding two size-1-pool leases at once deadlocks).
    // Resume point ASSUMES the intended cutover shape (PG starts empty, legacy
    // present): during backfill the only rows in PG are backfilled ones, so
    // `MAX(id)` is a safe id-ordered resume cursor after a mid-backfill crash.
    // What makes that true is the write gate at the top of `log()` — this
    // function armed `backfill_pending_` on entry, so nothing can write a native
    // row until it succeeds. It is NOT true by virtue of "boot has not completed
    // yet": the constructor keeps running after a failed backfill and its own
    // audit hooks would otherwise fire (Gate 3 cpp-safety disproved the earlier
    // wording, which claimed exactly that).
    //
    // Why "PG non-empty AND no backfill_complete marker, WITH a legacy source in
    // hand" is a crash-resume (Gate 4 architect): native rows only appear after
    // the marker is stamped — a fresh install stamps `backfill_complete` before
    // serving, log() is inert until boot completes, and every one-shot CLI writer
    // of a native row runs this backfill first (main.cpp `open_one_shot_audit`;
    // that call is the whole reason the property holds, and removing it re-opens
    // Gate 3 architect A-2). So with a source present, no-marker + non-empty is
    // reachable only via a partial prior backfill, for which resume-from-MAX(id)
    // + ON CONFLICT DO NOTHING is exactly correct, and a blanket "refuse boot if
    // non-empty + no marker" guard would BREAK that legitimate resume — hence it
    // is not added HERE. Without a usable source the same state proves nothing
    // and IS refused; see `complete_without_source` below.
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
    // Fingerprint of what Postgres already holds, compared below against the
    // legacy rows at or below the resume cursor.
    std::int64_t pg_rows_before = 0;
    std::int64_t pg_id_sum_before = 0;
    std::int64_t pg_ts_sum_before = 0;
    std::int64_t pg_ts_min_before = 0;
    std::int64_t pg_ts_max_before = 0;
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
            // Marker present. An ordinary restart has no legacy file left at
            // this path — a completed backfill moves it aside — so that is the
            // cheap, common case: nothing further to check.
            //
            // A stat FAILURE is not the same fact as "genuinely absent", and
            // must not be handled the same way: this branch existed to fail
            // OPEN on any error (a permissions problem, a transient I/O fault
            // on the legacy path) exactly where the marker-ABSENT branch below
            // fails CLOSED on the identical class of error. Both sides read
            // the same filesystem entry to decide whether a verification is
            // owed; only one of them refused when it could not find out.
            std::error_code exists_ec;
            const bool file_still_here = std::filesystem::exists(legacy_db_path, exists_ec);
            if (exists_ec) {
                spdlog::error(
                    "AuditStore: migrate_from_sqlite: cannot stat legacy path {} to verify a "
                    "completed backfill: {}; refusing rather than assuming the file is gone.",
                    legacy_db_path.string(), exists_ec.message());
                backfill_metric("failed");
                return false;
            }
            if (!file_still_here) {
                spdlog::debug("AuditStore: migrate_from_sqlite already completed, skipping");
                return backfill_ok();
            }

            // A legacy file exists ALONGSIDE a completed marker. Two honest
            // explanations: (a) THIS host (or an identical shared-storage
            // sibling) completed a real backfill and the move-aside failed
            // afterward — safe to retry; (b) a DIFFERENT process stamped the
            // marker (a sourceless boot on a fileless peer, or another
            // replica's own unrelated backfill) and THIS host's trail was
            // NEVER migrated (Gate 3 architect A-4, and Sol's diagnosis of
            // why two rounds of guards on the sourceless SIDE failed to close
            // it: no process can prove deployment-wide absence from its own
            // filesystem, so the fix has to live on the holder's side).
            //
            // Distinguish them by PROVENANCE, not by comparing this file
            // against PG's CURRENT content — that comparison decays: retention
            // deletes backfilled rows over time and native writes accumulate,
            // so a perfectly healthy, long-running server would eventually
            // fail a live-content comparison. Compare instead against the
            // fingerprint `stamp_complete` recorded IN THE MARKER at the
            // moment a real backfill proved completeness — that value is
            // written once, in the same transaction as the marker, and never
            // changes afterward.
            spdlog::warn(
                "AuditStore: migrate_from_sqlite: backfill_complete is set but legacy {} still "
                "exists; verifying this host's trail was actually migrated before trusting the "
                "marker",
                legacy_db_path.string());
            SqliteDb verify_db;
            if (sqlite3_open_v2(legacy_db_path.string().c_str(), verify_db.addr(),
                                SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
                spdlog::error(
                    "AuditStore: migrate_from_sqlite: marker present but legacy {} exists and "
                    "could not be opened for verification ({}); refusing to serve without proof "
                    "this host's trail was migrated. If this file is known-empty or irrelevant, "
                    "remove it and restart; otherwise see "
                    "docs/ops-runbooks/audit-store-backfill-recovery.md.",
                    legacy_db_path.string(),
                    verify_db ? sqlite3_errmsg(verify_db.get()) : "open failed");
                backfill_metric("failed");
                return false;
            }
            sqlite3_exec(verify_db.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
            const auto table_status = legacy_has_table(verify_db.get(), "audit_events");
            if (table_status == LegacyTableStatus::Error) {
                spdlog::error(
                    "AuditStore: migrate_from_sqlite: marker present but legacy {} is unreadable "
                    "or corrupt; refusing to serve without proof this host's trail was migrated. "
                    "See docs/ops-runbooks/audit-store-backfill-recovery.md.",
                    legacy_db_path.string());
                backfill_metric("failed");
                return false;
            }
            if (table_status == LegacyTableStatus::Absent) {
                // A table-less file left behind is not a migration source —
                // nothing here could have been lost. Same posture as "no
                // file at all".
                spdlog::debug("AuditStore: migrate_from_sqlite: legacy {} has no audit_events "
                              "table; nothing to verify",
                              legacy_db_path.string());
                return backfill_ok();
            }
            const auto legacy_fp = legacy_fingerprint(verify_db.get(), std::nullopt);
            if (!legacy_fp) {
                spdlog::error("AuditStore: migrate_from_sqlite: marker present but legacy {} "
                              "fingerprint read failed; refusing to serve without proof this "
                              "host's trail was migrated.",
                              legacy_db_path.string());
                backfill_metric("failed");
                return false;
            }
            if (legacy_fp->count == 0) {
                // Empty table left behind — nothing to lose regardless of who
                // stamped the marker or why.
                return backfill_ok();
            }
            pg::PgResult fp_row = pg::exec_params(
                lease.get(),
                "SELECT value FROM audit_store.audit_retention_meta WHERE key = "
                "'backfill_source_fingerprint'",
                std::vector<std::string>{});
            if (fp_row.status() != PGRES_TUPLES_OK) {
                spdlog::error(
                    "AuditStore: migrate_from_sqlite: source-fingerprint lookup failed: {}",
                    PQerrorMessage(lease.get()));
                backfill_metric("failed");
                return false;
            }
            const std::optional<LegacyFingerprint> stored_fp =
                PQntuples(fp_row.get()) > 0 ? parse_fingerprint(text_col(fp_row.get(), 0, 0))
                                            : std::nullopt;
            if (!stored_fp || *stored_fp != *legacy_fp) {
                spdlog::error(
                    "AuditStore: migrate_from_sqlite: refusing to serve — legacy {} ({} row(s), "
                    "id-sum {}, timestamp-sum {}) was NEVER proven migrated. The completion "
                    "marker's recorded provenance is {}. Some other process declared this "
                    "deployment's evidence migration complete without ever reading this host's "
                    "trail — the file is UNTOUCHED at its original path and no evidence has been "
                    "lost, but boot refuses until this is resolved by an operator: confirm "
                    "whether this file's content genuinely reached PostgreSQL (via another "
                    "replica sharing this storage) or is the ONLY copy (in which case follow "
                    "docs/ops-runbooks/audit-store-backfill-recovery.md before proceeding).",
                    legacy_db_path.string(), legacy_fp->count, legacy_fp->id_sum, legacy_fp->ts_sum,
                    stored_fp ? "a DIFFERENT legacy source" : "sourceless — no legacy file was "
                                                              "ever read before this marker was "
                                                              "stamped");
                backfill_metric("failed");
                return false;
            }
            // Fingerprints match exactly: this file's content IS what a real
            // backfill proved migrated (this host's own prior run, or an
            // identical shared-storage file a sibling replica streamed). Safe
            // to retry the move-aside that evidently failed before.
            verify_db.close();
            move_legacy_aside();
            spdlog::info(
                "AuditStore: migrate_from_sqlite: verified legacy {} matches the migrated trail; "
                "retried the move-aside",
                legacy_db_path.string());
            return backfill_ok();
        }
        pg::PgResult mx =
            pg::exec_params(lease.get(),
                            "SELECT COALESCE(MAX(id),0), COUNT(*), COALESCE(SUM(id),0), "
                            "COALESCE(SUM(timestamp),0), COALESCE(MIN(timestamp),0), "
                            "COALESCE(MAX(timestamp),0) FROM audit_store.audit_events",
                            std::vector<std::string>{});
        if (mx.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: migrate_from_sqlite: resume-point read failed: {}",
                          PQerrorMessage(lease.get()));
            backfill_metric("failed");
            return false;
        }
        resume_from = to_i64(PQgetvalue(mx.get(), 0, 0));
        pg_rows_before = to_i64(PQgetvalue(mx.get(), 0, 1));
        pg_id_sum_before = to_i64(PQgetvalue(mx.get(), 0, 2));
        pg_ts_sum_before = to_i64(PQgetvalue(mx.get(), 0, 3));
        pg_ts_min_before = to_i64(PQgetvalue(mx.get(), 0, 4));
        pg_ts_max_before = to_i64(PQgetvalue(mx.get(), 0, 5));
    }

    // A "nothing to migrate" exit may only stamp the marker over an EMPTY table.
    // The marker asserts the trail is COMPLETE, and with no migration source in
    // hand nothing on this path can establish that. Rows + no marker + no usable
    // source is either a sibling replica still streaming the legacy audit.db
    // (this replica has none of its own), or a partial backfill whose legacy file
    // was moved aside — and stamping over either closes a knowingly-incomplete
    // SOC 2 evidence chain forever, silently (Gate 3 architect A-1). Fail closed
    // and make the operator decide. NOTE this is deliberately NOT the "refuse
    // when non-empty + no marker" guard rejected above: the crash-resume path
    // HAS a source, so it never reaches here.
    const auto complete_without_source = [&](std::string_view situation) -> bool {
        if (pg_rows_before > 0) {
            spdlog::error(
                "AuditStore: migrate_from_sqlite: refusing to mark the backfill complete — {}, but "
                "audit_store.audit_events already holds {} row(s) with no backfill_complete marker. "
                "Another replica may still be streaming the legacy trail (let it finish; it stamps "
                "the marker, then restart this one), or a partial backfill's legacy audit.db was "
                "moved aside. Stamping here would bless a knowingly-incomplete evidence chain. If "
                "the legacy trail is genuinely unrecoverable, follow the abandon procedure in "
                "docs/ops-runbooks/audit-store-backfill-recovery.md.",
                situation, pg_rows_before);
            backfill_metric("failed");
            return false;
        }
        // A one-shot CLI (or any other Refuse caller) must never be the thing
        // that declares the fleet's evidence migration complete. A host that
        // merely does not hold `audit.db` would otherwise stamp over its empty
        // table, and the host that DOES hold the legacy trail then boots, sees
        // the marker, and skips the mandatory backfill reporting success —
        // 365 days of evidence silently never migrated (Gate 3 architect A-4).
        if (sourceless == Sourceless::Refuse) {
            spdlog::error(
                "AuditStore: migrate_from_sqlite: {} — refusing to declare the backfill complete "
                "from this entry point. Only a server boot may do that, because this process "
                "cannot tell a genuine fresh install from a host that simply does not hold the "
                "legacy audit.db. Start the server once, then retry.",
                situation);
            backfill_metric("failed");
            return false;
        }
        if (!stamp_complete(/*require_empty=*/true, /*source_fingerprint=*/"sourceless")) {
            backfill_metric("failed");
            return false;
        }
        // WARN, not info: on a genuine fresh install this is routine, but this
        // code cannot distinguish that from a replica whose peer holds the
        // legacy trail — and in the second case it has just foreclosed the
        // migration. Name what was foreclosed so the line is actionable.
        spdlog::warn("AuditStore: migrate_from_sqlite: {}; marking the backfill COMPLETE over an "
                     "empty audit_events. If any host in this deployment still holds a legacy "
                     "audit.db, its trail will now NOT be migrated — that host's boot will skip "
                     "the backfill on this marker. Expected on a fresh install; see "
                     "docs/user-manual/upgrading.md if this is an upgrade.",
                     situation);
        backfill_metric("fresh");
        return backfill_ok();
    };

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
        // is a cheap no-op (only over an empty table; see above).
        return complete_without_source(
            std::format("no legacy audit.db at {} (fresh install)", legacy_db_path.string()));
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
    const auto audit_events_status = legacy_has_table(legacy.get(), "audit_events");
    if (audit_events_status == LegacyTableStatus::Error) {
        // A prepare failure here is NOT "no table" — it means this file HAS
        // bytes that fail to parse as a SQLite header: corrupt, encrypted, or
        // otherwise unreadable (Gate 4 unhappy-path UP-1, measured on a
        // 38-byte junk file). Routing that through `complete_without_source`
        // declared a corrupt evidence trail a "fresh install" and silently
        // forfeited it. A file this process cannot read is not proof there is
        // nothing to migrate. A genuinely ZERO-BYTE file is a DIFFERENT,
        // legitimate case, not this one — measured, it opens and its
        // `sqlite_master` read returns EMPTY (Absent), not an error, because
        // SQLite treats 0 bytes as a valid uninitialized database. That is
        // correct: a 0-byte file cannot encode any evidence, so there is
        // nothing to lose by treating it the same as no file at all.
        spdlog::error(
            "AuditStore: migrate_from_sqlite: legacy db {} could not be read (corrupt, "
            "encrypted, or otherwise unreadable); refusing to treat an unreadable file as "
            "having nothing to migrate. Repair or restore the file, or move it aside by hand "
            "if it is genuinely not a migration source, then retry.",
            legacy_db_path.string());
        backfill_metric("failed");
        return false;
    }
    if (audit_events_status == LegacyTableStatus::Absent) {
        // A legacy file with no audit_events table is not a migration source —
        // treat like a fresh install rather than looping forever, subject to the
        // same empty-table condition.
        return complete_without_source(
            std::format("legacy db {} has no audit_events table", legacy_db_path.string()));
    }
    const bool has_principal_class =
        legacy_has_column(legacy.get(), "audit_events", "principal_class");
    // (No separate early row-count read: the prefix-proof fingerprint query
    // immediately below already reads the file's aggregate shape, and the
    // reconciliation fingerprint after streaming reads it again — a third,
    // standalone COUNT(*) added nothing but a stale value to keep in sync.)

    // 3b. PREFIX PROOF (ADR-0009). The ADR's trigger is "finds its Postgres
    // schema EMPTY and a legacy .db present"; the resume cursor below relaxes
    // that to "start after MAX(pg.id)" so a crashed backfill can continue. That
    // relaxation is only sound while the rows already in Postgres ARE the
    // already-copied prefix of THIS legacy id stream — so prove it rather than
    // assume it. Without this, marker-absent Postgres holding unrelated rows
    // above the legacy id range skips every legacy row, still satisfies the
    // count check below, and stamps the mandatory audit backfill complete having
    // migrated nothing (the legacy file is then moved aside). No product path
    // creates that state — a failed backfill refuses to serve and the marker is
    // never deleted — but a selective restore of `audit_events` without
    // `audit_retention_meta`, a DSN aimed at another deployment, or a manual
    // partial import all do, and this store is the SOC 2 evidence chain.
    // Fingerprint on CONTENT, not on id shape. Every row already in Postgres
    // sits at or below the cursor by construction (the cursor IS MAX(pg.id)), so
    // both sides are compared over that same id range.
    //
    // Which columns, and why it is not just the ids: a count alone is defeated by
    // any equal-sized foreign set, and (count, SUM(id)) is defeated SYSTEMATICALLY
    // rather than by coincidence — ids are `GENERATED ALWAYS AS IDENTITY` here and
    // rowid in the legacy file, so they run 1..k contiguously in EVERY deployment.
    // A foreign table holding ids 1..k therefore produces exactly the same count
    // and id-sum as this legacy file's own first k rows, the cursor skips those k
    // legacy rows, and the equality reconciliation downstream still balances. The
    // timestamps are the part that differs between two deployments: they are real
    // event times, not a sequence. Comparing SUM/MIN/MAX of them alongside the id
    // aggregates means a false match needs two databases whose first k audit rows
    // coincide in count, id-sum, timestamp-sum, earliest and latest — which is a
    // different claim entirely from "both tables start at id 1".
    {
        const auto prefix_fp = legacy_fingerprint(legacy.get(), resume_from);
        if (!prefix_fp) {
            spdlog::error("AuditStore: migrate_from_sqlite: legacy prefix fingerprint read "
                          "failed: {}",
                          sqlite3_errmsg(legacy.get()));
            backfill_metric("failed");
            return false;
        }
        const LegacyFingerprint pg_before{pg_rows_before, pg_id_sum_before, pg_ts_sum_before,
                                          pg_ts_min_before, pg_ts_max_before};
        if (pg_before != *prefix_fp) {
            spdlog::error(
                "AuditStore: migrate_from_sqlite: PostgreSQL already holds {} audit row(s) "
                "(id sum {}, timestamp sum {}, earliest {}, latest {}) but the legacy database has "
                "{} row(s) (id sum {}, timestamp sum {}, earliest {}, latest {}) at or below the "
                "resume point id <= {} — the existing rows are NOT an interrupted copy of {}, so "
                "resuming from that cursor would skip legacy evidence while the row counts still "
                "balanced. Refusing to migrate (fail-closed, ADR-0009: the backfill runs against an "
                "EMPTY schema or its own partial copy, nothing else). Operator remediation: point "
                "at the correct database, or clear audit_store.audit_events if those rows are not "
                "wanted, then reboot.",
                pg_before.count, pg_before.id_sum, pg_before.ts_sum, pg_before.ts_min,
                pg_before.ts_max, prefix_fp->count, prefix_fp->id_sum, prefix_fp->ts_sum,
                prefix_fp->ts_min, prefix_fp->ts_max, resume_from, legacy_db_path.string());
            backfill_metric("failed");
            return false;
        }
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
        // LENGTH-AWARE, not C-string: `std::string(const char*)` stops at the
        // first embedded NUL, which would drop the remainder BEFORE
        // `sanitize_pg_text` can turn that NUL into U+FFFD — truncating rather
        // than defanging (ADR-0040 requires the latter). Yuzu's own legacy
        // writer always bound with `-1`, so no row it wrote can carry bytes past
        // a NUL; this is robustness against anything else that wrote the file.
        // `ca_store.cpp` uses the same `sqlite3_column_bytes` pattern.
        const auto col = [&](int i) {
            const auto* v = sqlite3_column_text(sel.get(), i);
            const int n = sqlite3_column_bytes(sel.get(), i);
            return v ? std::string(reinterpret_cast<const char*>(v), static_cast<std::size_t>(n))
                     : std::string{};
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

        // Rows this batch ACTUALLY inserted, per `PQcmdTuples` — not
        // `batch.size()`. `ON CONFLICT (id) DO NOTHING` silently drops a row
        // whose id collides with one already in PG, and on a clean resume
        // that should never happen (the query is `WHERE id > resume_from`,
        // and `resume_from` tracks PG's own MAX(id)) — a discard here means a
        // FOREIGN writer put a row at an id this legacy file also claims (Gate
        // 3 architect F2 / Sol: the fingerprint reconciliation below is what
        // actually catches the consequence, but this is where the count
        // itself stops lying about what happened).
        std::int64_t batch_inserted = 0;
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
                // Redact credentials captured in pre-fix `config.update` rows
                // DURING the copy, not only on read. The ladder's migration
                // contract required this decision to be made explicitly, so:
                // the substrate never receives the plaintext. Reads redact
                // identically, so nothing legitimately readable is lost, and
                // unlike an ADR-0010 SecretCodec column there is no rekey story
                // for a credential sitting in free-form text — CLAUDE.md's "a
                // secret is NEVER a plain Postgres column" applies to a value
                // that lands in one by migration just as much as by writer.
                // The unredacted original is not destroyed: it remains in the
                // legacy file, which is moved aside rather than deleted.
                params.push_back(
                    sanitize_pg_text(sanitized_detail(r.target_type, r.target_id, r.detail)));
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
            batch_inserted = to_i64(PQcmdTuples(ins.get()));
            return true;
        });
        if (!ok) {
            spdlog::error("AuditStore: migrate_from_sqlite: batch commit failed (aborting "
                          "backfill unstamped; the next boot retries from MAX(id))");
            backfill_metric("failed");
            return false;
        }
        if (batch_inserted != static_cast<std::int64_t>(batch.size())) {
            // Not fatal by itself — the whole-file reconciliation below is
            // what decides pass/fail — but this is the earliest, most precise
            // signal that a foreign row occupied one of this legacy file's
            // ids, so it is worth a loud line even if reconciliation later
            // happens to balance.
            spdlog::warn(
                "AuditStore: migrate_from_sqlite: batch offered {} row(s) but PostgreSQL "
                "accepted only {} — {} row(s) collided with an id already present (ON CONFLICT "
                "DO NOTHING discarded them); the reconciliation fingerprint below will refuse "
                "the backfill if that discard is not accounted for",
                batch.size(), batch_inserted, static_cast<std::int64_t>(batch.size()) - batch_inserted);
        }
        inserted += batch_inserted;
        resume_from = batch.back().id;
        if (batch.size() < kBackfillBatchRows)
            break;
    }

    // 5. Copy audit_retention_meta (durable clock-guard reading). Legacy `value`
    // is INTEGER; PG `value` is TEXT — copy as text. DO NOTHING never clobbers a
    // reading a running replica has already advanced past.
    const auto retention_meta_status = legacy_has_table(legacy.get(), "audit_retention_meta");
    if (retention_meta_status == LegacyTableStatus::Error) {
        // The SAME handle just read `audit_events` fine, so this would be a
        // genuine anomaly rather than routine corruption — but the tri-state
        // exists precisely so a read failure is never silently folded into
        // "the table doesn't exist" (Gate 4 unhappy-path UP-1).
        spdlog::error("AuditStore: migrate_from_sqlite: legacy audit_retention_meta existence "
                      "check failed: {}",
                      sqlite3_errmsg(legacy.get()));
        backfill_metric("failed");
        return false;
    }
    if (retention_meta_status == LegacyTableStatus::Present) {
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
        // LENGTH-AWARE, not C-string: `std::string(const char*)` stops at the
        // first embedded NUL, which for `key` would silently rename the row
        // (a truncated key still writes, just under the wrong name) and for
        // `value` would carry a truncated reading past the "unparseable is
        // an anomaly" check below instead of into it — e.g. a legacy value
        // of `"0\0junk"` (non-INTEGER, so this branch runs) would truncate to
        // `"0"`, which parses as a clean anchor of 0 rather than the unusable
        // reading it actually is. Same `sqlite3_column_bytes` pattern as the
        // row-copy `col()` lambda above.
        const auto meta_col = [&](int i) {
            const auto* v = sqlite3_column_text(ms.get(), i);
            const int n = sqlite3_column_bytes(ms.get(), i);
            return v ? std::string(reinterpret_cast<const char*>(v), static_cast<std::size_t>(n))
                     : std::string{};
        };
        while ((rc = sqlite3_step(ms.get())) == SQLITE_ROW) {
            if (!sqlite3_column_text(ms.get(), 0))
                continue;
            std::string key = meta_col(0);
            // Gate 2 security (round 3): reject an embedded NUL in the KEY
            // outright, rather than sanitize it. `pg::exec_params` binds
            // text-format parameters with `paramLengths=nullptr`
            // (`pg_exec.hpp`), so libpq truncates any value — including this
            // one — at the first NUL regardless of the C++ string's real
            // length. A key compared and excluded correctly in C++ (full
            // bytes, post-243a6d02) can still arrive at Postgres truncated to
            // a DIFFERENT, shorter name than the one just compared — e.g.
            // `"backfill_source_fingerprint\0x"` is NOT equal to the reserved
            // name below in C++, so it is not excluded there, but INSERTs as
            // the reserved name once libpq truncates it. A legitimate legacy
            // key is a plain identifier and never contains a NUL, so refusing
            // the row (not migrating that one meta key) is the safe default —
            // unlike a VALUE column, there is no free-text case to preserve.
            if (key.find('\0') != std::string::npos) {
                spdlog::warn("AuditStore: migrate_from_sqlite: legacy audit_retention_meta key "
                             "contains an embedded NUL; refusing to migrate it (a legitimate key "
                             "is never binary)");
                continue;
            }
            // Never carry a stale marker across; it is stamped fresh below —
            // and never carry ANY `backfill_`-prefixed key at all: that
            // namespace is reserved for values THIS process establishes
            // (`backfill_complete`, `backfill_source_fingerprint`) as its own
            // trust anchors, never copied from an untrusted legacy source. A
            // legacy row inserted first under `backfill_source_fingerprint`
            // would otherwise poison it before `stamp_complete` (below) ever
            // runs — its own INSERT is `ON CONFLICT (key) DO NOTHING`, so the
            // REAL, freshly-computed fingerprint silently loses to whatever
            // arrived here first (Gate 2 security HIGH finding, round 3).
            if (key.rfind("backfill_", 0) == 0)
                continue;
            // The legacy table is not STRICT, so this column can hold a
            // non-integer. `sqlite3_column_int64` would COERCE that to 0, and 0
            // is a perfectly usable `last_pass_now` — the clock guard would then
            // anchor on a value that was actually corruption, which is exactly
            // the "unparseable reading is an anomaly, never a quiet reset"
            // requirement of the routed clock-guard concern. The SQLite store
            // checked the column type for this reason; carry the check across
            // rather than let the migration launder it (Gate 3 cpp-expert F5).
            if (sqlite3_column_type(ms.get(), 1) != SQLITE_INTEGER) {
                spdlog::warn("AuditStore: migrate_from_sqlite: legacy audit_retention_meta['{}'] "
                             "is not an INTEGER; carrying it across as the non-numeric text it is, "
                             "so the clock guard treats it as an unusable reading rather than 0",
                             key);
                meta_rows.emplace_back(std::move(key),
                                       sqlite3_column_text(ms.get(), 1)
                                           ? sanitize_pg_text(meta_col(1))
                                           : std::string{"corrupt"});
                continue;
            }
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

    // 6. Whole-file FINGERPRINT reconciliation (ADR-0040: logged AND asserted).
    // Not a bare count. A bare count is defeated by a foreign writer occupying
    // an id this legacy file also claims: `ON CONFLICT (id) DO NOTHING`
    // silently drops the legacy row, and IF a native row already held that id
    // (Gate 3 architect F2 / Sol's diagnosis of the A-4 race — a fileless peer
    // stamps the marker sourcelessly, then writes native rows starting at
    // id=1, the same id this legacy file's own first row claims), the total
    // row count comes out unchanged: one row lost, one row gained, same id.
    // `SUM(id)` does not catch it either — the id itself is still there,
    // just holding different content. The TIMESTAMP components do: a native
    // write's timestamp is "now", a legacy event's timestamp is historical,
    // and they coincide only by extraordinary coincidence.
    //
    // This whole-file fingerprint is ALSO what gets stamped as
    // `backfill_source_fingerprint` below — the value a LATER boot compares a
    // still-present legacy file against (see the marker-present branch).
    LegacyFingerprint whole_legacy_fp;
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("AuditStore: migrate_from_sqlite: reconciliation lease failed ({})",
                          pool_.last_error());
            backfill_metric("failed");
            return false;
        }
        pg::PgResult pc = pg::exec_params(
            lease.get(),
            "SELECT COUNT(*), COALESCE(SUM(id),0), COALESCE(SUM(timestamp),0), "
            "COALESCE(MIN(timestamp),0), COALESCE(MAX(timestamp),0) FROM "
            "audit_store.audit_events",
            std::vector<std::string>{});
        if (pc.status() != PGRES_TUPLES_OK) {
            spdlog::error(
                "AuditStore: migrate_from_sqlite: reconciliation fingerprint read failed: {}",
                PQerrorMessage(lease.get()));
            backfill_metric("failed");
            return false;
        }
        const LegacyFingerprint pg_fp{to_i64(PQgetvalue(pc.get(), 0, 0)),
                                      to_i64(PQgetvalue(pc.get(), 0, 1)),
                                      to_i64(PQgetvalue(pc.get(), 0, 2)),
                                      to_i64(PQgetvalue(pc.get(), 0, 3)),
                                      to_i64(PQgetvalue(pc.get(), 0, 4))};
        const auto legacy_fp = legacy_fingerprint(legacy.get(), std::nullopt);
        if (!legacy_fp) {
            spdlog::error(
                "AuditStore: migrate_from_sqlite: legacy whole-file fingerprint read failed: {}",
                sqlite3_errmsg(legacy.get()));
            backfill_metric("failed");
            return false;
        }
        whole_legacy_fp = *legacy_fp;
        // EQUALITY, not "at least" (ADR-0040: "no duplication and no loss").
        // The prefix proof above establishes that every pre-existing row was
        // part of this legacy stream, so after a complete copy the two
        // fingerprints must match exactly.
        if (pg_fp != whole_legacy_fp) {
            spdlog::error(
                "AuditStore: migrate_from_sqlite: reconciliation FAILED — legacy has {} row(s) "
                "(id sum {}, timestamp sum {}, earliest {}, latest {}) but PostgreSQL has {} "
                "row(s) (id sum {}, timestamp sum {}, earliest {}, latest {}); refusing to mark "
                "complete (fail-closed, the next boot retries). A matching row COUNT with a "
                "differing fingerprint means a foreign write occupies one of this file's ids — "
                "see the batch-collision warning above, if one was logged.",
                whole_legacy_fp.count, whole_legacy_fp.id_sum, whole_legacy_fp.ts_sum,
                whole_legacy_fp.ts_min, whole_legacy_fp.ts_max, pg_fp.count, pg_fp.id_sum,
                pg_fp.ts_sum, pg_fp.ts_min, pg_fp.ts_max);
            backfill_metric("failed");
            return false;
        }
        spdlog::info("AuditStore: migrate_from_sqlite: reconciled — legacy {} row(s), PostgreSQL "
                     "{} row(s) ({} inserted this run)",
                     whole_legacy_fp.count, pg_fp.count, inserted);
    }

    // 7. Advance the identity sequence + stamp the one-time marker atomically,
    // together with the fingerprint that PROVES it: a later boot finding this
    // marker AND a still-present legacy file compares that file against
    // exactly this value (see the marker-present branch above), never against
    // PG's live content.
    if (!stamp_complete(/*require_empty=*/false, whole_legacy_fp.to_string())) {
        backfill_metric("failed");
        return false;
    }

    // 8. Move the verified legacy file aside (not delete) — the pre-cutover
    // evidence stays recoverable (operator-managed-backup convention). Failure
    // here is NON-fatal: the backfill is already committed + marked, so a
    // rename failure must not refuse boot (a later boot's marker-present
    // verification retries it — see `move_legacy_aside` and the branch above).
    // Close the legacy read-only handle FIRST: Windows refuses to rename a file
    // with an open handle (ERROR_SHARING_VIOLATION), so leaving `legacy` open
    // silently defeated the move-aside on the Wee Tam MSVC leg (POSIX allows
    // rename-with-open-handle, so it passed on Linux/macOS). All legacy reads
    // are already materialised in memory above.
    //
    // `sel` must be finalized BEFORE that close, not left to scope exit:
    // `SqliteDb::close()` is `sqlite3_close_v2`, which does NOT close a
    // connection with an outstanding statement — it marks it a zombie and defers
    // the close (and the OS file handle) until the last statement finalizes
    // (`sqlite_raii.hpp`). `sel` is function-scoped and lives past this point, so
    // closing without finalizing it leaves the file locked and the rename below
    // still fails on Windows.
    sel.reset();
    legacy.close();
    move_legacy_aside();

    backfill_metric("completed");
    return backfill_ok();
}

// ── Write (FAIL-HARD) ────────────────────────────────────────────────────────

bool AuditStore::log(const AuditEvent& event) {
    // A mandatory backfill that STARTED and did not finish gates the write path.
    // A native row written now sits ahead of the `backfill_complete` marker, and
    // the prefix proof then rejects the legacy trail on every later boot — the
    // host is permanently unbootable and the documented remediation deletes the
    // very rows written here. Declining is the safe direction: the caller sees
    // fail-hard false, exactly as for any other persistence failure.
    //
    // NOT redundant with the caller refusing to serve. `ServerImpl`'s ctor sets
    // `startup_failed_` on a failed backfill and then KEEPS CONSTRUCTING —
    // `startup_failed_` is not read again for ~600 lines — and several hooks it
    // installs on the way (the secret-codec audit hook among them) are guarded
    // only on `is_open()` (Gate 3 cpp-safety).
    if (backfill_pending_.load(std::memory_order_acquire)) {
        emit_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::error("AuditStore::log: the mandatory legacy backfill has not completed; declining "
                      "action={} rather than writing a native row ahead of the completion marker "
                      "(that would refuse every later boot). Resolve the backfill first.",
                      event.action);
        return false;
    }
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

    // Sanitize EVERY text column, including `result` and `principal_class`.
    // They were bound verbatim on the claim that they are enum-controlled. All
    // the assignment sites in the tree today do use literals — but the backfill
    // path (below) sanitizes both, with a comment explaining precisely why, and
    // the failure modes are not symmetric with the free-text ones: MEASURED on
    // PG 18, `result="\xff\xfe"` fails the INSERT and LOSES the event on a
    // fail-hard write path, and `result="suc\0cess"` stores `"suc"` — a
    // SILENTLY TRUNCATED audit result. A convention enforced only by every
    // caller remembering is not what should stand between an audit event and
    // being dropped (Gate 3 cpp-expert, who ran the bytes).
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
                                 sanitize_pg_text(event.session_id),
                                 sanitize_pg_text(event.result), std::to_string(ttl),
                                 sanitize_pg_text(event.principal_class)});
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
    // The random-sample pool is ALWAYS exactly the cap, never the caller's
    // limit: below the cap a smaller pool would collapse the sample into "the N
    // most recent" (no randomness left to draw), and above it the pool would
    // breach the `<= kAuditSampleScanCap` bound the header promises and the REST
    // layer reports to an auditor as `recency_capped`. Was `std::max(limit,
    // cap)`, which honoured the first half and broke the second — a limit above
    // the cap fetched `limit` rows. No shipped caller reaches it (REST clamps to
    // 1000, MCP to 500 and does not set random_sample), so nothing was exposed;
    // it is the store contract that was wrong.
    // Clamp at the SINK. A negative limit reaches PostgreSQL as `LIMIT -1`,
    // which errors (`LIMIT must not be negative`) — and this store reports a
    // query error as a DEGRADE: 503 plus
    // `yuzu_server_audit_read_degrade_total{reason="query_error"}`, the series
    // `YuzuAuditReadDegraded` pages on. So any read-privileged client could make
    // the evidence-availability control fire at will, and send the on-call after
    // a database fault that does not exist (Gate 2 security). The parsers below
    // reject it as the 400 it is; this is the defence-in-depth half, and it uses
    // the same `std::max(q.limit, 0)` idiom the sample truncation already uses.
    //
    // `offset` needs no clamp here: the OFFSET clause is emitted only under
    // `q.offset > 0`, so a negative offset is already inert at this seam.
    const int64_t fetch_limit = q.random_sample ? static_cast<int64_t>(kAuditSampleScanCap)
                                                : static_cast<int64_t>(std::max(q.limit, 0));
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
        // Read-time redaction of credentials captured in pre-fix
        // `config.update` rows (see sanitized_detail). Applied at the ROW
        // MATERIALISATION point so every reader gets it — the SQLite store
        // did this and the port must not drop it.
        e.detail = sanitized_detail(e.target_type, e.target_id, text_col(res.get(), i, 7));
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

std::string AuditStore::sanitized_detail(std::string_view target_type, std::string_view target_id,
                                         std::string detail) {
    // Keyed on the TARGET (a runtime-config row naming a secret key), not on one
    // writer's action string. `config.update` is the only such writer today, but
    // keying on it would leave a future writer -- a settings handler recording the
    // same key under its own verb -- outside the rule, and nothing would fail.
    // Still narrow: a blanket "redact anything that looks secret" across every audit
    // detail would gut the evidence value of the log, which is what this store is for.
    if (target_type != "RuntimeConfig" || !is_secret_config_key(target_id))
        return detail;
    if (detail.empty())
        return detail;

    // ONLY the exact shape today's writer emits -- a detail that STARTS `value=` --
    // keeps its `value=` label. Anything else is replaced wholesale.
    //
    // An earlier revision preserved `detail.substr(0, pos)` for a `value=` found at
    // ANY offset, to keep a future writer's surrounding context. Two reviewers
    // independently rejected that, and both were right: a writer that placed the
    // credential BEFORE a `value=` token would have had it preserved verbatim, and
    // the comment promising that context is kept held only for one token ordering
    // that nothing enforces. No writer of either shape exists today, so this gives
    // up nothing real and removes a trap that fires the moment someone trusts the
    // comment. If a future writer needs context to survive, give `detail` structure
    // (named JSON fields) rather than adding a second string-surgery rule.
    if (detail.rfind("value=", 0) == 0)
        return "value=" + std::string(kRedactedPlaceholder);
    return std::string(kRedactedPlaceholder);
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
    bool declined_no_anchor = false;
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

        // PostgreSQL's OWN clock, not the caller's, for every DECISION below.
        // The caller-supplied `now` remains a liveness signal only
        // (`last_pass_unixtime_`, stamped before this transaction even runs)
        // and still gates the cheap pre-txn implausibility check.
        //
        // Gate 4 unhappy-path UP-2 / Sol: comparing one replica's PROCESS
        // clock against `last_pass_now` — itself stamped by whichever
        // replica's process clock swept last — means clock disagreement
        // BETWEEN replicas, not just an NTP jump on one machine, can make two
        // sweepers alternate distinct fact sets forever, each declining a
        // pass the other just anchored. PostgreSQL is the ONE authority every
        // sweeper already serialises through (the advisory lock above), so
        // reading its clock HERE — after the lock, inside this transaction —
        // gives every replica the identical comparison point regardless of
        // its own process clock's accuracy. `EXTRACT(EPOCH FROM now())::bigint`
        // is SQL this codebase already runs (`software_inventory_store.cpp`'s
        // migration backfill), and the single-sweeper advisory lease itself is
        // precedented in `result_set_store.cpp`/`software_inventory_store.cpp`
        // — but reading PG's clock to DRIVE an ongoing retention verdict is new
        // here: `ResultSetStore::gc_sweep` (the same `#2360`-class guard,
        // `result_set_store.cpp:1312`) still compares against its own process
        // clock via `now_epoch()`, carrying the identical cross-replica
        // divergence this fix closes for AuditStore. That sibling is a
        // deferred follow-up, not a precedent this fix is copying. `now()` is
        // the transaction's start time, stable and adequate for a
        // single-statement read.
        pg::PgResult clk = pg::exec_params(conn, "SELECT EXTRACT(EPOCH FROM now())::bigint",
                                           std::vector<std::string>{});
        if (clk.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: reap clock read failed: {}", PQerrorMessage(conn));
            return false;
        }
        const std::int64_t pg_now = to_i64(PQgetvalue(clk.get(), 0, 0));
        // Same overflow guard as the pre-txn check on the caller's clock,
        // applied to PG's — `datable_horizon` below adds `window + slack` to
        // this value, and it is cheap to bound both sources the same way
        // rather than trust one implicitly because it is "the database".
        if (pg_now > kMaxPlausibleNow) {
            spdlog::error("AuditStore: reap declined — PostgreSQL's own clock reading ({}) is "
                          "implausible",
                          pg_now);
            return false;
        }

        // Durable dedup state (shared across replicas + restarts).
        pg::PgResult meta = pg::exec_params(
            conn,
            "SELECT key, value FROM audit_store.audit_retention_meta WHERE key IN ('last_pass_now',"
            "'last_anomaly_facts','bootstrap_settled')",
            std::vector<std::string>{});
        if (meta.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: reap meta read failed: {}", PQerrorMessage(conn));
            return false;
        }
        std::optional<std::int64_t> prev;
        bool prev_unusable = false;
        std::string last_facts;
        // #2579: has ANY pass on this database ever reached a verdict? Durable
        // and SHARED rather than the per-process flag the SQLite store carries,
        // because on Postgres N replicas sweep the same table and a process-local
        // trigger would be spent by whichever replica happened to boot first
        // (ADR-0012 / the routed clock-guard concern's single-writer caveat).
        bool bootstrap_settled = false;
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
            } else if (key == "bootstrap_settled") {
                bootstrap_settled = true;
            }
        }
        // A reading ahead of the clock (backward NTP correction) or negative
        // (corruption) cannot be reasoned about — decline either way.
        if (prev && (*prev < 0 || *prev > pg_now)) {
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
            std::vector<std::string>{std::to_string(pg_now)});
        if (stamp.status() != PGRES_COMMAND_OK) {
            spdlog::error("AuditStore: reap meta stamp failed: {}", PQerrorMessage(conn));
            persist_failed = true;
            return false; // fail closed — roll back the whole pass
        }

        // Detect by OUTCOME: two probes answer the whole question, both
        // index-eligible. The two halves are deliberately different SHAPES —
        // see `kAuditRetentionProbeSql`'s own comment (1f) for why the
        // survivor half is `ORDER BY ... LIMIT 1` rather than a second bare
        // EXISTS, and don't re-derive it here; this is the read site, not the
        // definition. A forward-skewed row past
        // `now + window + slack` can never expire, so it is EXCLUDED from the
        // survivor question — else one bad row vetoes the guard for the store's
        // life.
        //
        // EXISTS, NOT `count(*) FILTER (...)`. The guard only ever asks "any?",
        // and the counting form has no statement-level WHERE, so every row —
        // including the `ttl_expires_at = 0` majority, which sits OUTSIDE the
        // partial index `idx_audit_ttl_id ... WHERE ttl_expires_at > 0` declared
        // in kMigrations above — must be visited before either count is known.
        // That is a full scan of the audit trail on every pass, on the one table
        // designed to grow without bound (Gate 3 performance PERF-1; plan
        // evidence in the commit message). EXISTS carries the `> 0` predicate
        // into the index and stops at the first matching row.
        //
        // The SQLite-side note about `BETWEEN` being load-bearing does NOT
        // transfer: Postgres expands BETWEEN to exactly these two comparisons,
        // and either way the pair is one index range condition on the leading
        // column.
        const std::int64_t datable_horizon = pg_now + window + kAuditTtlFutureSlackSec;
        pg::PgResult probe = pg::exec_params(
            conn, std::string(kAuditRetentionProbeSql).c_str(),
            std::vector<std::string>{std::to_string(pg_now), std::to_string(datable_horizon)});
        if (probe.status() != PGRES_TUPLES_OK) {
            spdlog::error("AuditStore: reap probe failed: {}", PQerrorMessage(conn));
            return false;
        }
        const bool has_expired = to_bool(PQgetvalue(probe.get(), 0, 0));
        const bool has_survivor = to_bool(PQgetvalue(probe.get(), 0, 1));

        const bool would_wipe = has_expired && !has_survivor;
        // Supplement to would_wipe: a half-window jump expires a large slice
        // while leaving survivors, which the cap bounds but nothing else reports.
        // Gated on window > 0 and strictly greater than the absolute floor.
        const bool big_step = prev.has_value() && window > 0 && has_expired &&
                              (pg_now - *prev) > kAuditMinBigStepSec;

        const audit_retention::Facts facts{.has_expired = has_expired,
                                           .would_wipe = would_wipe,
                                           .big_step = big_step,
                                           .prev_unusable = prev_unusable,
                                           .no_anchor = !bootstrap_settled};
        const audit_retention::Anomaly anomaly = audit_retention::classify(facts);
        const std::string facts_ser = serialize_facts(facts);

        // The pass has now REACHED A VERDICT, so settle the bootstrap marker —
        // and settle it HERE, not at the re-anchor above. The re-anchor happens
        // before the probes, so deriving the trigger from the stored reading
        // would let one transient probe failure spend it permanently: the next
        // pass would see a reading, call itself anchored, and delete with every
        // detector false — the exact defect #2579 closes. Every early return
        // above this line rolls the whole transaction back, so a pass that never
        // reached a verdict leaves the trigger armed.
        if (!bootstrap_settled) {
            pg::PgResult settle = pg::exec_params(
                conn,
                "INSERT INTO audit_store.audit_retention_meta (key, value) VALUES "
                "('bootstrap_settled', '1') ON CONFLICT (key) DO NOTHING",
                std::vector<std::string>{});
            if (settle.status() != PGRES_COMMAND_OK) {
                spdlog::error("AuditStore: reap bootstrap settle failed: {}", PQerrorMessage(conn));
                persist_failed = true;
                return false;
            }
        }

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
                // A missing-anchor decline is counted APART from the clock
                // anomalies (#2579). It asserts only that nothing can yet be
                // ruled out — a weaker claim than "the clock moved in a way that
                // would have wiped evidence", which is what the sibling counter's
                // alert says. Sharing the counter would make that alert's own
                // description untrue for this case and fire it on every server
                // carrying a backlog through an upgrade.
                declined_no_anchor = (anomaly == audit_retention::Anomaly::NoAnchor);
                decline_msg =
                    declined_no_anchor
                        ? std::string(
                              "AuditStore: no usable previous retention clock reading and rows are "
                              "already expired — declining this pass and anchoring; the next pass "
                              "has a comparison point and proceeds (#2579)")
                        : "AuditStore: retention clock anomaly (facts=" + facts_ser +
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
        if (!has_expired)
            return true; // nothing to do

        // Bounded, oldest-first delete so even an allowed wipe ages out at a
        // paced rate. RETURNING carries the count (no sqlite3_changes()/#1033).
        pg::PgResult del = pg::exec_params(
            conn,
            "DELETE FROM audit_store.audit_events WHERE id IN (SELECT id FROM "
            "audit_store.audit_events WHERE ttl_expires_at > 0 AND ttl_expires_at < $1::bigint "
            "ORDER BY ttl_expires_at ASC, id ASC LIMIT $2::bigint) RETURNING id",
            std::vector<std::string>{std::to_string(pg_now),
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
                std::vector<std::string>{std::to_string(pg_now)});
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
        if (declined_no_anchor)
            bootstrap_declines_.fetch_add(1, std::memory_order_relaxed);
        else
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

// `wait_s` is recomputed after every pass: the full interval normally, but
// kAuditBacklogRearmSec while the per-pass cap is BINDING and a real backlog
// remains. Draining at one capped pass per hour is what turns the cap into a
// permanent growth ceiling rather than a per-pass bound (see the constant).
// The signal is `cap_reached_` moving, which `cleanup_once` increments only when
// the cap bound AND its post-delete probe found a genuine remainder — so a
// declined pass, or an exact-boundary pass that drained the last row, returns to
// the full interval rather than spinning.
#ifdef __cpp_lib_jthread
void AuditStore::run_cleanup(std::stop_token stop) {
    int wait_s = cleanup_interval_min_ * 60;
    while (!stop.stop_requested()) {
        for (int i = 0; i < wait_s && !stop.stop_requested(); ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (stop.stop_requested())
            break;
#else
void AuditStore::run_cleanup() {
    int wait_s = cleanup_interval_min_ * 60;
    while (!stop_requested_.load()) {
        for (int i = 0; i < wait_s && !stop_requested_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (stop_requested_.load())
            break;
#endif
        const auto now = now_epoch();
        const uint64_t caps_before = cap_reached_.load(std::memory_order_relaxed);
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
        wait_s = audit_next_wait_s(cap_reached_.load(std::memory_order_relaxed) > caps_before,
                                   cleanup_interval_min_);
    }
}

} // namespace yuzu::server
