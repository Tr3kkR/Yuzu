#include "inventory_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <string_view>
#include <system_error>
#include <utility>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "inventory_store";

// Bounded acquires (ADR-0012 lease discipline). Ingest runs on the gRPC/
// gateway thread so it must give up fast on a saturated pool — best-effort,
// the agent's next report re-sends the same blob. Reads get a longer budget
// since they back interactive REST/MCP/dashboard callers.
constexpr std::chrono::milliseconds kIngestAcquireTimeout{500};
constexpr std::chrono::milliseconds kQueryAcquireTimeout{3000};
// Hard ceiling on rows a single query will materialise, independent of the
// caller's `limit`, so the store can never allocate an unbounded result set.
constexpr int kQueryRowCap = 100000;

// Read-degrade reason labels (mirror SoftwareInventoryStore / DeviceInventoryStore
// / the alert taxonomy). Shared counter, distinguished by the "source" label.
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr const char* kReasonInvalidKey = "invalid_key";
constexpr const char* kReasonStale = "stale"; // conflict-predicate suppression (H2)
constexpr const char* kDegradeSource = "generic";
// Sample the per-site degrade WARN (leading edge of an episode, then every Nth)
// so a sustained PG outage cannot flood the log — the counter is the continuous
// signal, the log a sampled breadcrumb. Values match the sibling stores.
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so these tables land in `inventory_store`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE inventory_data ("
         "  agent_id     TEXT NOT NULL,"
         "  plugin       TEXT NOT NULL,"
         "  data_json    TEXT NOT NULL DEFAULT '{}',"
         "  collected_at BIGINT NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (agent_id, plugin));"
         "CREATE INDEX inventory_data_plugin_idx ON inventory_data (plugin);"
         "CREATE INDEX inventory_data_collected_idx ON inventory_data (collected_at);"},
        {2,
         // Backfill stamp (ADR-0009/0037): a single-row sentinel so
         // migrate_from_sqlite() is a cheap no-op on every boot after the
         // first. `legacy_rows` records rows ACTUALLY inserted (not the size
         // of the in-memory legacy row list — see migrate_from_sqlite).
         // `skipped_bad` (governance H1) makes a row-data skip AUDITABLE
         // after the fact — a stamp with skipped_bad > 0 says the backfill
         // completed but filed N legacy rows as malformed (22xxx/23xxx
         // SQLSTATE only; infrastructure errors abort unstamped instead).
         "CREATE TABLE backfill_state ("
         "  id           INT PRIMARY KEY,"
         "  migrated_at  BIGINT NOT NULL,"
         "  legacy_rows  BIGINT NOT NULL DEFAULT 0,"
         "  skipped_bad  BIGINT NOT NULL DEFAULT 0);"},
    };
    return kMigrations;
}

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// True when `s` is empty or contains only whitespace — the GDPR orphan guard
// (UP-7): a blank agent_id/plugin must never be written (upsert) or backfilled
// (migrate_from_sqlite), because the decommission cascade's empty-id
// short-circuit could never reach it, leaving an un-erasable row.
bool is_blank(std::string_view s) {
    return std::all_of(s.begin(), s.end(),
                       [](unsigned char c) { return std::isspace(c) != 0; });
}

// Parse a Postgres text-format integer cell into int64 (count(*)/MAX()/etc.
// are text on the wire). Mirrors SoftwareInventoryStore::result_i64.
std::int64_t result_i64(const pg::PgResult& res, int row, int col) {
    const char* txt = PQgetvalue(res.get(), row, col);
    const auto len = static_cast<std::size_t>(PQgetlength(res.get(), row, col));
    std::int64_t v = 0;
    std::from_chars(txt, txt + len, v); // leaves v=0 on parse failure/NULL
    return v;
}

// Affected-row count for a just-executed command (INSERT/UPDATE/DELETE) via
// `PQcmdTuples` — safe here because this connection is exclusively ours for
// the duration of the transaction (unlike the SQLite `sqlite3_changes()`
// anti-pattern, #1033, whose hazard is a RACE on a connection shared across
// threads/FULLMUTEX; a single-owner libpq connection has no such race).
std::int64_t affected_rows(const pg::PgResult& res) {
    const char* txt = PQcmdTuples(res.get());
    if (!txt || txt[0] == '\0')
        return 0;
    std::int64_t v = 0;
    std::from_chars(txt, txt + std::string_view(txt).size(), v);
    return v;
}

// ── Read-degrade observability (shared yuzu_inventory_read_degrade_total) ────

struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};
struct DegradeLog {
    bool should_log;
    std::uint64_t occurrence;
};

DegradeLog note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason,
                             DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_inventory_read_degrade_total",
                         {{"reason", reason}, {"source", kDegradeSource}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return {new_episode || (n % kReadDegradeLogSample) == 0, n};
}

// Ingest (upsert) drop counter — a dropped write previously had no metric
// (UP-3/4): sre needs to see this independent of the spdlog::warn breadcrumb.
void note_ingest_dropped(yuzu::MetricsRegistry* metrics, const char* reason) {
    if (metrics)
        metrics->counter("yuzu_inventory_ingest_dropped_total", {{"reason", reason}}).increment();
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

InventoryStore::InventoryStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("InventoryStore: no database connection at construction ({}) — generic "
                      "inventory persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("InventoryStore: schema migration failed — generic inventory persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

// ── Backfill (ADR-0009/0037) ─────────────────────────────────────────────────

bool InventoryStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    // Idempotency check on a short-lived lease, released BEFORE any legacy
    // SQLite I/O or the write transaction below — holding two connections
    // from this call at once would deadlock a size-1 pool (e.g. a test pool).
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("InventoryStore: migrate_from_sqlite: no database connection ({})",
                          pool_.last_error());
            return false;
        }
        pg::PgResult stamp_check = pg::exec_params(
            lease.get(), "SELECT 1 FROM inventory_store.backfill_state WHERE id = 1",
            std::vector<std::string>{});
        if (stamp_check.status() != PGRES_TUPLES_OK) {
            spdlog::error("InventoryStore: migrate_from_sqlite: backfill_state lookup failed: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        if (PQntuples(stamp_check.get()) > 0) {
            spdlog::debug("InventoryStore: migrate_from_sqlite already completed, skipping");
            return true;
        }
    }

    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("InventoryStore: migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        return false;
    }

    struct LegacyRow {
        std::string agent_id;
        std::string plugin;
        std::string data_json;
        std::int64_t collected_at{0};
    };
    std::vector<LegacyRow> legacy_rows;

    if (legacy_exists) {
        // RAII connection owner (IB1, cpp-safety BLOCKING): `sqlite3_close` runs
        // on every scope exit including a throw mid read-loop (e.g. a
        // `std::bad_alloc` from `std::string` construction) — no manual
        // finalize/close path to leak. Declared BEFORE `stmt` so the statement
        // finalizes first on unwind (SQLite wants live statements finalized
        // before the connection closes).
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> legacy{nullptr, &sqlite3_close};
        {
            sqlite3* raw = nullptr;
            // READONLY: the legacy file is retained as a read-only rollback net
            // for one release (ADR-0009) — this call never writes to it.
            const int rc =
                sqlite3_open_v2(legacy_db_path.string().c_str(), &raw, SQLITE_OPEN_READONLY, nullptr);
            legacy.reset(raw); // adopt even on failure — sqlite3_open_v2 may still allocate a handle
            if (rc != SQLITE_OK) {
                spdlog::error("InventoryStore: migrate_from_sqlite: failed to open legacy db {}: {}",
                              legacy_db_path.string(),
                              legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
                return false;
            }
        }

        SqliteStmt stmt;
        const char* sql = "SELECT agent_id, plugin, data_json, collected_at FROM inventory_data";
        if (sqlite3_prepare_v2(legacy.get(), sql, -1, stmt.addr(), nullptr) != SQLITE_OK) {
            spdlog::error("InventoryStore: migrate_from_sqlite: legacy prepare failed: {}",
                          sqlite3_errmsg(legacy.get()));
            return false;
        }

        auto col_text = [&](int i) {
            auto p = sqlite3_column_text(stmt.get(), i);
            return p ? std::string(reinterpret_cast<const char*>(p)) : std::string{};
        };

        int rc = SQLITE_DONE;
        while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
            LegacyRow r;
            r.agent_id = col_text(0);
            r.plugin = col_text(1);
            r.data_json = col_text(2);
            r.collected_at = sqlite3_column_int64(stmt.get(), 3);
            legacy_rows.push_back(std::move(r));
        }
        const bool read_ok = (rc == SQLITE_DONE);
        stmt.reset(); // finalize before `legacy` closes (destruction order would do this anyway)
        if (!read_ok) {
            spdlog::error("InventoryStore: migrate_from_sqlite: legacy read failed (rc={})", rc);
            return false;
        }
    }

    // One transaction: insert every legacy row, then stamp completion,
    // atomically. Each row's INSERT runs under its own SAVEPOINT (IB2, UP-1):
    // a single BAD ROW (encoding/constraint violation) rolls back to the
    // savepoint and is SKIPPED — it does NOT abort the whole backfill/boot,
    // because this store is fail-soft/self-healing (the agent re-pushes) and
    // a permanently bricked server over one malformed legacy blob would be
    // strictly worse than a skipped row. A `ROLLBACK TO SAVEPOINT` that
    // itself fails to execute means the connection/transaction is broken at
    // the INFRASTRUCTURE level (not a per-row problem) — THAT aborts the
    // whole backfill (fail-closed). A one-time cost (row-by-row insert is
    // fine for a boot-time backfill of this scale; a fleet-scale batched
    // insert is the follow-up if a future fleet's legacy table proves large).
    std::int64_t inserted = 0;
    std::int64_t skipped_bad = 0;
    std::int64_t skipped_blank_key = 0;
    const bool ok = pool_.with_txn([&](PGconn* c) -> bool {
        for (const auto& r : legacy_rows) {
            // GDPR orphan guard (IS5/UP-7): never backfill a row the
            // decommission cascade's empty-id short-circuit could never
            // reach.
            if (is_blank(r.agent_id) || is_blank(r.plugin)) {
                ++skipped_blank_key;
                spdlog::warn("InventoryStore: migrate_from_sqlite: skipping legacy row with a "
                            "blank agent_id/plugin");
                continue;
            }

            pg::PgResult sp = pg::exec_params(c, "SAVEPOINT legacy_row_backfill",
                                              std::vector<std::string>{});
            if (sp.status() != PGRES_COMMAND_OK) {
                spdlog::error("InventoryStore: migrate_from_sqlite: SAVEPOINT failed (infra "
                             "error, aborting backfill): {}",
                             PQerrorMessage(c));
                return false; // infra-level failure: fail closed
            }

            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO inventory_store.inventory_data "
                "(agent_id, plugin, data_json, collected_at) "
                "VALUES ($1, $2, $3, $4::bigint) ON CONFLICT (agent_id, plugin) DO NOTHING",
                // Clamp the legacy timestamp too (governance round-2 LOW):
                // a far-future-skewed row written by a pre-clamp deployment
                // would otherwise survive the backfill and suppress honest
                // upserts until wall-clock catches up — the same class the
                // sibling store's #1685 migration v3 clamp closed for
                // retrofitted rows.
                std::vector<std::string>{r.agent_id, r.plugin, r.data_json,
                                         std::to_string(std::min(r.collected_at, now_secs()))});
            if (ins.status() == PGRES_COMMAND_OK) {
                pg::PgResult rel_ok = pg::exec_params(c, "RELEASE SAVEPOINT legacy_row_backfill",
                                                      std::vector<std::string>{});
                if (rel_ok.status() != PGRES_COMMAND_OK) {
                    // LOW (governance): checked like every neighbouring
                    // statement — a failed RELEASE is an infra-level signal.
                    spdlog::error("InventoryStore: migrate_from_sqlite: RELEASE SAVEPOINT failed "
                                  "(infra error, aborting backfill): {}",
                                  PQerrorMessage(c));
                    return false;
                }
                inserted += affected_rows(ins); // 0 on ON CONFLICT DO NOTHING no-op, else 1
                continue;
            }

            // Per-row failure. Governance H1 (2026-07-29): "rollback
            // succeeded" is NOT a discriminator between a malformed row and
            // a RECOVERABLE INFRASTRUCTURE error — statement_timeout (57014,
            // the pool pins statement_timeout=30000 on every connection),
            // deadlock (40P01), serialization failure (40001) and
            // lock_not_available (55P03) are all per-statement AND
            // savepoint-recoverable by design, and all reachable during a
            // loaded first-boot backfill. Filing one of those as a "bad row"
            // loses the row PERMANENTLY and SILENTLY (the completion stamp
            // below short-circuits every later boot). Read the SQLSTATE and
            // skip ONLY genuine row-data classes: 22xxx (data exception) and
            // 23xxx (integrity constraint). Everything else — class 40
            // (txn rollback), 53 (insufficient resources), 55 (object state),
            // 57 (operator intervention/timeout), 58 (system error),
            // XX (internal), and anything unrecognised — fails the backfill
            // closed so the next boot retries with the marker unstamped
            // (the header's own contract: "FAILS CLOSED only on a genuine
            // INFRASTRUCTURE error ... never on a single bad row").
            const std::string row_err =
                ins.get() ? PQresultErrorMessage(ins.get()) : PQerrorMessage(c);
            const char* sqlstate_p =
                ins.get() ? PQresultErrorField(ins.get(), PG_DIAG_SQLSTATE) : nullptr;
            const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
            const bool row_data_error =
                sqlstate.size() == 5 && (sqlstate.starts_with("22") || sqlstate.starts_with("23") ||
                                         sqlstate.starts_with("54"));
            // 54xxx (program_limit_exceeded: oversized field/statement) is
            // row-data by construction — a legacy data_json blob bigger than
            // Postgres will take fails on THAT row every boot; treating it as
            // infra would make one pathological blob a permanent boot loop
            // (Gate 4 UP-1).
            pg::PgResult back = pg::exec_params(c, "ROLLBACK TO SAVEPOINT legacy_row_backfill",
                                                std::vector<std::string>{});
            if (back.status() != PGRES_COMMAND_OK) {
                // The recovery itself failed — the connection/transaction is
                // broken at the infrastructure level, not a per-row problem.
                // Fail closed rather than silently losing more rows.
                spdlog::error("InventoryStore: migrate_from_sqlite: ROLLBACK TO SAVEPOINT failed "
                             "after a bad row (infra error, aborting backfill): {}",
                             PQerrorMessage(c));
                return false;
            }
            if (!row_data_error) {
                spdlog::error("InventoryStore: migrate_from_sqlite: row insert failed with "
                              "non-row-data SQLSTATE '{}' (agent_id={} plugin={}): {} — treating "
                              "as an infrastructure error and aborting the backfill unstamped; "
                              "the next boot retries",
                              sqlstate.empty() ? "<none>" : sqlstate, r.agent_id, r.plugin,
                              row_err);
                return false;
            }
            pg::PgResult rel = pg::exec_params(c, "RELEASE SAVEPOINT legacy_row_backfill",
                                               std::vector<std::string>{});
            if (rel.status() != PGRES_COMMAND_OK) {
                spdlog::error("InventoryStore: migrate_from_sqlite: RELEASE SAVEPOINT failed "
                              "(infra error, aborting backfill): {}",
                              PQerrorMessage(c));
                return false;
            }
            ++skipped_bad;
            spdlog::warn("InventoryStore: migrate_from_sqlite: skipping bad legacy row "
                        "agent_id={} plugin={} (SQLSTATE {}): {}",
                        r.agent_id, r.plugin, sqlstate, row_err);
        }
        pg::PgResult stamp = pg::exec_params(
            c,
            "INSERT INTO inventory_store.backfill_state (id, migrated_at, legacy_rows, "
            "skipped_bad) "
            "VALUES (1, $1::bigint, $2::bigint, $3::bigint) ON CONFLICT (id) DO NOTHING",
            std::vector<std::string>{std::to_string(now_secs()), std::to_string(inserted),
                                     std::to_string(skipped_bad)});
        return stamp.status() == PGRES_COMMAND_OK;
    });
    if (!ok) {
        spdlog::error("InventoryStore: migrate_from_sqlite: backfill transaction failed for {}",
                      legacy_db_path.string());
        return false;
    }

    spdlog::info("InventoryStore: migrate_from_sqlite backfilled {} legacy row(s) from {} "
                "(skipped: {} bad, {} blank-key)",
                inserted, legacy_db_path.string(), skipped_bad, skipped_blank_key);
    return true;
}

// ── Upsert (fail-soft ingest) ────────────────────────────────────────────────

void InventoryStore::upsert(const std::string& agent_id, const std::string& plugin,
                            const std::string& data_json, int64_t collected_at) {
    if (!open_) {
        spdlog::warn("InventoryStore: upsert skipped for agent={} plugin={}, store not open",
                     agent_id, plugin);
        note_ingest_dropped(metrics_, kReasonStoreNotOpen);
        return;
    }
    // GDPR orphan guard (IS5/UP-7): reject before ever reaching SQL — a blank
    // key would be un-erasable by the decommission cascade's empty-id guard.
    if (is_blank(agent_id) || is_blank(plugin)) {
        spdlog::warn("InventoryStore: upsert rejected: blank agent_id/plugin (plugin={})", plugin);
        note_ingest_dropped(metrics_, kReasonInvalidKey);
        return;
    }
    if (collected_at == 0)
        collected_at = now_secs();
    // Governance H2 (2026-07-29): CLAMP the agent-supplied clock to server
    // receipt time — the stale-overwrite guard below compares collected_at,
    // so without a clamp ONE future-skewed (or hostile) report pins its row
    // forever: every later honest report fails the conflict predicate,
    // updates zero rows, and returns success. Same defect the sibling
    // SoftwareInventoryStore already fixed (#1685, ADR-0016 Update
    // 2026-06-27, incl. its migration v3 clamp for pre-fix rows) and the
    // standing clock-guard rule: on an endpoint the user controls, a quiet
    // reset IS the bypass. Backfill is unaffected (legacy rows predate now).
    if (collected_at > now_secs())
        collected_at = now_secs();
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease) {
        spdlog::warn("InventoryStore: upsert skipped for agent={} plugin={}, no connection ({})",
                     agent_id, plugin, pool_.last_error());
        note_ingest_dropped(metrics_, kReasonPoolTimeout);
        return;
    }
    // Stale-overwrite guard (IS6/UP-8): a reordered/duplicate OLDER report
    // must never clobber a newer row — the WHERE clause on the conflict
    // action only fires the UPDATE when the incoming row is at least as
    // fresh as what's stored (equal collected_at still updates, matching the
    // pre-existing same-instant re-report behaviour).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO inventory_store.inventory_data (agent_id, plugin, data_json, collected_at) "
        "VALUES ($1, $2, $3, $4::bigint) "
        "ON CONFLICT (agent_id, plugin) DO UPDATE SET "
        "data_json = EXCLUDED.data_json, collected_at = EXCLUDED.collected_at "
        "WHERE EXCLUDED.collected_at >= inventory_store.inventory_data.collected_at",
        std::vector<std::string>{agent_id, plugin, data_json, std::to_string(collected_at)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::warn("InventoryStore: upsert failed for agent={} plugin={}: {}", agent_id, plugin,
                     PQerrorMessage(lease.get()));
        note_ingest_dropped(metrics_, kReasonQueryError);
        return;
    }
    // Governance H2, observability half: a conflict-predicate suppression
    // (stored row is newer) updates ZERO rows but still returns
    // PGRES_COMMAND_OK — without this check a suppressed write is invisible
    // (no log, no metric), which is exactly how the pre-clamp freeze hid.
    // With the clamp above this now only fires for genuinely-reordered older
    // reports (and any row pinned ahead by a PRE-clamp deployment — those
    // drain as their stored collected_at ages past now).
    if (affected_rows(res) == 0) {
        note_ingest_dropped(metrics_, kReasonStale);
        spdlog::debug("InventoryStore: upsert suppressed stale report for agent={} plugin={} "
                      "(incoming collected_at={} older than stored)",
                      agent_id, plugin, collected_at);
    }
}

// ── List tables (authoritative read) ─────────────────────────────────────────

std::optional<std::vector<InventoryTable>> InventoryStore::list_tables() const {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("InventoryStore: list_tables degraded — store not open (occurrence {})",
                        d.occurrence);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("InventoryStore: list_tables degraded — no connection ({}) (occurrence {})",
                        pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT plugin, COUNT(DISTINCT agent_id) AS agent_count, "
        "MAX(collected_at) AS last_collected "
        "FROM inventory_store.inventory_data GROUP BY plugin ORDER BY plugin",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("InventoryStore: list_tables degraded — query failed: {} (occurrence {})",
                        PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    std::vector<InventoryTable> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        InventoryTable t;
        t.plugin = PQgetvalue(res.get(), i, 0);
        t.agent_count = result_i64(res, i, 1);
        t.last_collected = result_i64(res, i, 2);
        out.push_back(std::move(t));
    }
    return out;
}

// ── Get single record (authoritative, three-state) ──────────────────────────

std::expected<std::optional<InventoryRecord>, InventoryReadError>
InventoryStore::get(const std::string& agent_id, const std::string& plugin) const {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("InventoryStore: get degraded — store not open (occurrence {})",
                        d.occurrence);
        return std::unexpected(InventoryReadError::kDegraded);
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("InventoryStore: get degraded — no connection ({}) (occurrence {})",
                        pool_.last_error(), d.occurrence);
        return std::unexpected(InventoryReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, plugin, data_json, collected_at "
        "FROM inventory_store.inventory_data WHERE agent_id = $1 AND plugin = $2",
        std::vector<std::string>{agent_id, plugin});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("InventoryStore: get degraded — query failed: {} (occurrence {})",
                        PQerrorMessage(lease.get()), d.occurrence);
        return std::unexpected(InventoryReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<InventoryRecord>{std::nullopt}; // genuinely absent, not a degrade

    InventoryRecord r;
    r.agent_id = PQgetvalue(res.get(), 0, 0);
    r.plugin = PQgetvalue(res.get(), 0, 1);
    r.data_json = PQgetvalue(res.get(), 0, 2);
    r.collected_at = result_i64(res, 0, 3);
    return std::optional<InventoryRecord>{std::move(r)};
}

// ── Query (authoritative read) ───────────────────────────────────────────────

std::optional<std::vector<InventoryRecord>> InventoryStore::query(const InventoryQuery& q,
                                                                  bool* truncated) const {
    if (truncated)
        *truncated = false;
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("InventoryStore: query degraded — store not open (occurrence {})",
                        d.occurrence);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("InventoryStore: query degraded — no connection ({}) (occurrence {})",
                        pool_.last_error(), d.occurrence);
        return std::nullopt;
    }

    int limit = q.limit > 0 ? q.limit : 100;
    if (limit > kQueryRowCap)
        limit = kQueryRowCap;
    const int offset = q.offset > 0 ? q.offset : 0;

    std::string sql =
        "SELECT agent_id, plugin, data_json, collected_at FROM inventory_store.inventory_data "
        "WHERE 1=1";
    std::vector<std::string> params;
    int p = 0;
    if (!q.agent_id.empty()) {
        sql += " AND agent_id = $" + std::to_string(++p);
        params.push_back(q.agent_id);
    }
    if (!q.plugin.empty()) {
        sql += " AND plugin = $" + std::to_string(++p);
        params.push_back(q.plugin);
    }
    if (q.since > 0) {
        sql += " AND collected_at >= $" + std::to_string(++p) + "::bigint";
        params.push_back(std::to_string(q.since));
    }
    if (q.until > 0) {
        sql += " AND collected_at <= $" + std::to_string(++p) + "::bigint";
        params.push_back(std::to_string(q.until));
    }
    // Two separate statements (not one chained `++p` expression): the
    // relative evaluation order of multiple `++p` calls combined via
    // `operator+` on the same line is unspecified/unsequenced between
    // sibling subexpressions — a latent correctness bug the compiler now
    // flags (-Wunsequenced), fixed while touching this code.
    const int limit_param = ++p;
    const int offset_param = ++p;
    sql += " ORDER BY collected_at DESC LIMIT $" + std::to_string(limit_param) +
           "::bigint OFFSET $" + std::to_string(offset_param) + "::bigint";
    params.push_back(std::to_string(limit));
    params.push_back(std::to_string(offset));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("InventoryStore: query degraded — query failed: {} (occurrence {})",
                        PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    std::vector<InventoryRecord> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        InventoryRecord r;
        r.agent_id = PQgetvalue(res.get(), i, 0);
        r.plugin = PQgetvalue(res.get(), i, 1);
        r.data_json = PQgetvalue(res.get(), i, 2);
        r.collected_at = result_i64(res, i, 3);
        out.push_back(std::move(r));
    }
    // Truncation signal (IS4/UP-5/UP-6): the result count hit the effective
    // limit, so more rows may exist past what is returned — a silent cap
    // here can omit agents from a fleet action without any indication. The
    // hard-cap case gets a WARN (a caller asked for more than the store will
    // ever return in one call); a caller-supplied smaller limit gets a debug
    // breadcrumb (expected/routine pagination-adjacent truncation).
    if (static_cast<int>(out.size()) == limit) {
        if (truncated)
            *truncated = true; // governance M1: in-process signal, see header
        if (metrics_)
            metrics_->counter("yuzu_inventory_query_truncated_total").increment();
        if (limit == kQueryRowCap)
            spdlog::warn("InventoryStore: query hit the hard row cap ({}) — result is truncated, "
                        "more rows may exist",
                        kQueryRowCap);
        else
            spdlog::debug("InventoryStore: query result truncated at limit={} — more rows may "
                         "exist",
                         limit);
    }
    return out;
}

// ── Get agent inventory (delegates to query) ─────────────────────────────────

std::optional<std::vector<InventoryRecord>> InventoryStore::get_agent_inventory(
    const std::string& agent_id) const {
    InventoryQuery q;
    q.agent_id = agent_id;
    q.limit = 1000;
    return query(q);
}

// ── Delete agent ──────────────────────────────────────────────────────────────

bool InventoryStore::delete_agent(const std::string& agent_id) {
    // Empty-id guard, matching every sibling PG store: never run a
    // `DELETE ... WHERE agent_id = ''` (a footgun, never a fleet wipe). The
    // decommission cascade already short-circuits an empty id to all-Skipped,
    // but guarding here keeps that safety local to the store.
    if (agent_id.empty())
        return false;
    if (!open_) {
        spdlog::debug("InventoryStore: delete_agent skipped for agent={}, store not open",
                      agent_id);
        return false;
    }
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease) {
        spdlog::debug("InventoryStore: delete_agent skipped for agent={}, no connection ({})",
                      agent_id, pool_.last_error());
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM inventory_store.inventory_data WHERE agent_id = $1",
        std::vector<std::string>{agent_id});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::debug("InventoryStore: delete_agent failed for agent={}: {}", agent_id,
                      PQerrorMessage(lease.get()));
        return false;
    }
    return true;
}

// ── Count (authoritative read) ───────────────────────────────────────────────

std::optional<int64_t> InventoryStore::count() const {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("InventoryStore: count degraded — store not open (occurrence {})",
                        d.occurrence);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("InventoryStore: count degraded — no connection ({}) (occurrence {})",
                        pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(lease.get(),
                                       "SELECT COUNT(*) FROM inventory_store.inventory_data",
                                       std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("InventoryStore: count degraded — query failed: {} (occurrence {})",
                        PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    return result_i64(res, 0, 0);
}

} // namespace yuzu::server
