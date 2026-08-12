#include "discovery_store.hpp"

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
#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "discovery_store";

// Bounded acquires (ADR-0012 §2(a)). Discovery is an operator/dashboard
// surface fed by agent scan reports — not a per-heartbeat hot path — so the
// budgets are generous relative to e.g. the gRPC ingest path.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
constexpr std::chrono::milliseconds kBackfillTxnTimeout{60000};

// Read-degrade observability (mirrors ManagementGroupStore/AccessReviewStore).
constexpr const char* kReasonStoreClosed = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

// ADR-0040 pattern (RbacStore/#2703 the reference implementation): a process
// finding no local legacy file cannot distinguish "genuine fresh install"
// from "a sibling replica holds the real file" — stamping the shared
// backfill_complete marker from that observation alone would let a fileless
// replica permanently foreclose migration for a sibling that boots later
// with the real discovery.db still on disk. The fingerprint sentinel for
// "this replica's own migration pass found nothing to protect" (no local
// file, or a local file with no discovered_devices table).
constexpr const char* kSourcelessFingerprint = "sourceless";

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
        metrics->counter("yuzu_server_discovery_read_degrade_total", {{"reason", reason}})
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

bool to_bool(const char* s) {
    return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1');
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

// Applied to every free-text column reaching Postgres, including the
// backfill path (a bad byte at-rest in a legacy discovery.db must not brick
// the mandatory backfill). Scrubs invalid UTF-8 to U+FFFD, then replaces any
// embedded NUL (PostgreSQL TEXT cannot store one; libpq's text bind
// C-string-truncates at the first one).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

DiscoveredDevice read_device(PGresult* res, int row) {
    DiscoveredDevice d;
    int c = 0;
    d.id = to_i64(PQgetvalue(res, row, c++));
    d.ip_address = text_col(res, row, c++);
    d.mac_address = text_col(res, row, c++);
    d.hostname = text_col(res, row, c++);
    d.managed = to_bool(PQgetvalue(res, row, c++));
    d.agent_id = text_col(res, row, c++);
    d.discovered_by = text_col(res, row, c++);
    d.discovered_at = to_i64(PQgetvalue(res, row, c++));
    d.last_seen = to_i64(PQgetvalue(res, row, c++));
    d.subnet = text_col(res, row, c++);
    return d;
}

constexpr const char* kDeviceCols =
    "id, ip_address, mac_address, hostname, managed, agent_id, discovered_by, discovered_at, "
    "last_seen, subnet";

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

// nullopt = could not determine (genuine prepare/step error) — distinct from
// `false` ("determined the table is absent"). Every caller MUST treat
// nullopt as a read failure, never coerce it to "absent" (mirrors
// rbac_store.cpp's legacy_has_table).
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

struct LDevice {
    std::string ip_address, mac_address, hostname, agent_id, discovered_by, subnet;
    std::int64_t managed{0}, discovered_at{0}, last_seen{0};
};

// Every row this backfill reads from a legacy discovery.db, read ONCE and
// shared by the real migration (INSERT loop) and both fingerprint call sites
// (holder-side verification, and the post-migration trust-anchor stamp) — no
// second file read anywhere in this mechanism (mirrors rbac_store.cpp's
// read_legacy_snapshot / LegacySnapshot).
std::optional<std::vector<LDevice>> read_legacy_snapshot(sqlite3* legacy) {
    std::vector<LDevice> rows;
    SqliteStmt s;
    if (sqlite3_prepare_v2(legacy,
                           "SELECT ip_address, mac_address, hostname, managed, agent_id, "
                           "discovered_by, discovered_at, last_seen, subnet FROM "
                           "discovered_devices",
                           -1, s.addr(), nullptr) != SQLITE_OK)
        return std::nullopt;
    int rc;
    while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
        LDevice d;
        d.ip_address = sqlite_text(s.get(), 0);
        d.mac_address = sqlite_text(s.get(), 1);
        d.hostname = sqlite_text(s.get(), 2);
        d.managed = sqlite3_column_int64(s.get(), 3);
        d.agent_id = sqlite_text(s.get(), 4);
        d.discovered_by = sqlite_text(s.get(), 5);
        d.discovered_at = sqlite3_column_int64(s.get(), 6);
        d.last_seen = sqlite3_column_int64(s.get(), 7);
        d.subnet = sqlite_text(s.get(), 8);
        rows.push_back(std::move(d));
    }
    if (rc != SQLITE_DONE)
        return std::nullopt;
    return rows;
}

// Injective preimage: every field length-prefixed so two different field
// sequences can never encode to the same preimage regardless of what bytes
// they contain (mirrors rbac_store.cpp's append_field/canonicalize_legacy_
// snapshot — governance re-review on that store found an unescaped-delimiter
// canonicalization collision; length-prefixing is the fixed shape). Rows are
// sorted so on-disk order (WAL/vacuum state can reorder identical rows
// without changing their meaning) never changes the result.
void append_field(std::string& out, std::string_view f) {
    out += std::to_string(f.size());
    out += ':';
    out.append(f.data(), f.size());
}
void append_field(std::string& out, std::int64_t v) { append_field(out, std::to_string(v)); }

std::string canonicalize_legacy_snapshot(const std::vector<LDevice>& snap) {
    std::vector<std::string> rows;
    rows.reserve(snap.size());
    for (const auto& d : snap) {
        std::string r;
        append_field(r, d.ip_address);
        append_field(r, d.mac_address);
        append_field(r, d.hostname);
        append_field(r, d.managed);
        append_field(r, d.agent_id);
        append_field(r, d.discovered_by);
        append_field(r, d.discovered_at);
        append_field(r, d.last_seen);
        append_field(r, d.subnet);
        rows.push_back(std::move(r));
    }
    std::sort(rows.begin(), rows.end());
    std::string canon = "discovery-legacy-fingerprint-v1\n";
    for (const auto& r : rows)
        canon += r;
    return canon;
}

std::optional<std::string> fingerprint_legacy_snapshot(const std::vector<LDevice>& snap) {
    const auto hash = sha256_hex(canonicalize_legacy_snapshot(snap));
    if (!hash)
        return std::nullopt;
    return "v1:" + *hash;
}

// Path-based convenience for the holder-side verification call site: opens
// read-only, probes for corruption, and either returns the sourceless
// sentinel (no `discovered_devices` table — same "nothing to protect" class
// as no local file at all) or reads a full snapshot and fingerprints it via
// the exact same function the real migration path uses. Returns nullopt only
// on a corrupt/unreadable file or a snapshot read failure — the caller MUST
// fail closed on that, never treat it as sourceless-equivalent.
std::optional<std::string> legacy_discovery_fingerprint(const std::filesystem::path& legacy_db_path) {
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
    const auto has_devices = legacy_has_table(legacy.get(), "discovered_devices");
    if (!has_devices)
        return std::nullopt; // genuine read error, NOT "no table"
    if (!*has_devices)
        return std::string(kSourcelessFingerprint);

    const auto snap = read_legacy_snapshot(legacy.get());
    if (!snap)
        return std::nullopt;
    return fingerprint_legacy_snapshot(*snap);
}

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so this table lands in `discovery_store`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE discovered_devices ("
         "  id             BIGSERIAL PRIMARY KEY,"
         "  ip_address     TEXT NOT NULL UNIQUE,"
         "  mac_address    TEXT NOT NULL DEFAULT '',"
         "  hostname       TEXT NOT NULL DEFAULT '',"
         "  managed        BOOLEAN NOT NULL DEFAULT FALSE,"
         "  agent_id       TEXT NOT NULL DEFAULT '',"
         "  discovered_by  TEXT NOT NULL DEFAULT '',"
         "  discovered_at  BIGINT NOT NULL DEFAULT 0,"
         "  last_seen      BIGINT NOT NULL DEFAULT 0,"
         "  subnet         TEXT NOT NULL DEFAULT '');"
         "CREATE INDEX idx_discovery_managed ON discovered_devices(managed);"
         "CREATE INDEX idx_discovery_subnet ON discovered_devices(subnet);"
         // Durable one-time backfill markers (ADR-0009/0040 pattern).
         "CREATE TABLE discovery_meta ("
         "  key   TEXT PRIMARY KEY,"
         "  value TEXT NOT NULL"
         ");"},
    };
    return kMigrations;
}

} // namespace

// ── Construction ──────────────────────────────────────────────────────────

DiscoveryStore::DiscoveryStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("DiscoveryStore: no database connection at construction ({}) — discovery "
                      "persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("DiscoveryStore: schema migration failed — discovery persistence disabled");
        return;
    }
    open_ = true;
}

// ── Operations ───────────────────────────────────────────────────────────────

std::expected<void, std::string> DiscoveryStore::upsert_device(const DiscoveredDevice& device) {
    if (!open_)
        return std::unexpected("database not open");
    if (device.ip_address.empty())
        return std::unexpected("ip_address is required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    const auto now = now_secs();
    // ON CONFLICT semantics preserved from the legacy SQLite implementation
    // (see the header doc): mac_address/last_seen/subnet always refresh;
    // hostname refreshes only when the new value is non-empty; discovered_at/
    // discovered_by/managed/agent_id are untouched by a re-scan. last_seen is
    // UNCONDITIONALLY "now" on every call (insert or update) — independent of
    // discovered_at, which only falls back to "now" when the caller did not
    // supply one. The two must bind as SEPARATE parameters: reusing one bind
    // slot for both silently couples them, which the legacy sqlite3_bind_int64
    // pair (discovered_at, then a second, unconditional `now` for last_seen)
    // never did. managed/agent_id ARE part of the INSERT column list (a fresh
    // insert honors the caller's values, matching the legacy implementation's
    // bind positions 4/5) but are absent from the DO UPDATE SET clause — the
    // "untouched by a re-scan" guarantee applies only to an ALREADY-EXISTING
    // row, never to a device seen for the first time.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO discovery_store.discovered_devices "
        "(ip_address, mac_address, hostname, managed, agent_id, discovered_by, discovered_at, "
        "last_seen, subnet) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7::bigint, $8::bigint, $9) "
        "ON CONFLICT (ip_address) DO UPDATE SET "
        "  mac_address = EXCLUDED.mac_address, "
        "  hostname = CASE WHEN EXCLUDED.hostname != '' THEN EXCLUDED.hostname "
        "                  ELSE discovery_store.discovered_devices.hostname END, "
        "  last_seen = EXCLUDED.last_seen, "
        "  subnet = EXCLUDED.subnet "
        "RETURNING id",
        std::vector<std::string>{
            sanitize_pg_text(device.ip_address), sanitize_pg_text(device.mac_address),
            sanitize_pg_text(device.hostname), device.managed ? "true" : "false",
            sanitize_pg_text(device.agent_id), sanitize_pg_text(device.discovered_by),
            std::to_string(device.discovered_at > 0 ? device.discovered_at : now),
            std::to_string(now), sanitize_pg_text(device.subnet)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("upsert_device failed: ") +
                               PQerrorMessage(lease.get()));
    return {};
}

std::optional<std::vector<DiscoveredDevice>>
DiscoveryStore::list_devices(const std::string& subnet_filter) {
    static DegradeSampler sampler;
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreClosed, sampler))
            spdlog::warn("DiscoveryStore: list_devices degraded — store not open");
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("DiscoveryStore: list_devices degraded — pool acquire timed out ({})",
                        pool_.last_error());
        return std::nullopt;
    }

    std::string sql = std::string("SELECT ") + kDeviceCols +
                      " FROM discovery_store.discovered_devices ";
    pg::PgResult res;
    if (subnet_filter.empty()) {
        sql += "ORDER BY last_seen DESC";
        res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    } else {
        sql += "WHERE subnet = $1 ORDER BY last_seen DESC";
        // sanitize_pg_text: match the same transform applied on write, so a
        // filter value containing invalid UTF-8/NUL still matches the
        // sanitized bytes actually stored (rather than silently no-op-ing to
        // "no rows found" against the caller's untransformed original).
        res = pg::exec_params(lease.get(), sql.c_str(),
                              std::vector<std::string>{sanitize_pg_text(subnet_filter)});
    }
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("DiscoveryStore: list_devices degraded — query failed: {}",
                        PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    const int rows = PQntuples(res.get());
    std::vector<DiscoveredDevice> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_device(res.get(), i));
    return out;
}

std::expected<std::optional<DiscoveredDevice>, std::string>
DiscoveryStore::get_device(const std::string& ip_address) {
    if (!open_)
        return std::unexpected("database not open");
    if (ip_address.empty())
        return std::nullopt;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    std::string sql = std::string("SELECT ") + kDeviceCols +
                      " FROM discovery_store.discovered_devices WHERE ip_address = $1 LIMIT 1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{sanitize_pg_text(ip_address)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("get_device failed: ") + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::optional<DiscoveredDevice>{std::nullopt};
    return std::optional<DiscoveredDevice>{read_device(res.get(), 0)};
}

std::expected<void, std::string>
DiscoveryStore::mark_managed(const std::string& ip_address, const std::string& agent_id) {
    if (!open_)
        return std::unexpected("database not open");
    if (ip_address.empty())
        return std::unexpected("ip_address is required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE discovery_store.discovered_devices SET managed = TRUE, agent_id = $1 "
        "WHERE ip_address = $2 RETURNING id",
        std::vector<std::string>{sanitize_pg_text(agent_id), sanitize_pg_text(ip_address)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("mark_managed failed: ") +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not_found: no device with this ip_address");
    return {};
}

std::expected<void, std::string> DiscoveryStore::clear_results(const std::string& subnet) {
    if (!open_)
        return std::unexpected("database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    pg::PgResult res;
    if (subnet.empty()) {
        res = pg::exec_params(lease.get(), "DELETE FROM discovery_store.discovered_devices",
                              std::vector<std::string>{});
    } else {
        res = pg::exec_params(lease.get(),
                              "DELETE FROM discovery_store.discovered_devices WHERE subnet = $1",
                              std::vector<std::string>{sanitize_pg_text(subnet)});
    }
    if (res.status() != PGRES_COMMAND_OK)
        return std::unexpected(std::string("clear_results failed: ") +
                               PQerrorMessage(lease.get()));
    return {};
}

// ── MANDATORY backfill (ADR-0009, fingerprint-verified per ADR-0040/#2703) ──

bool DiscoveryStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    const auto backfill_metric = [this](const char* result) {
        if (metrics_)
            metrics_->counter("yuzu_server_discovery_backfill_total", {{"result", result}})
                .increment();
    };

    // The marker and its source fingerprint are ALWAYS stamped together, in
    // the SAME transaction. Monotonic promotion (mirrors rbac_store.cpp's
    // stamp_complete): "sourceless" carries no evidence worth protecting, so
    // a real fingerprint may promote a stored "sourceless" value; a stored
    // REAL value is never overwritten by anyone; a writer whose value
    // already equals what's stored counts as success, not a lost race.
    const auto stamp_complete = [&](std::string_view source_fingerprint) -> bool {
        return pool_.with_txn_for(kBackfillTxnTimeout, [source_fingerprint](PGconn* c) -> bool {
            pg::PgResult mk = pg::exec_params(
                c,
                "INSERT INTO discovery_store.discovery_meta (key, value) VALUES "
                "('backfill_complete', $1) ON CONFLICT (key) DO NOTHING",
                std::vector<std::string>{std::to_string(now_secs())});
            if (mk.status() != PGRES_COMMAND_OK) {
                spdlog::error("DiscoveryStore: migrate_from_sqlite: marker stamp failed: {}",
                              PQerrorMessage(c));
                return false;
            }
            pg::PgResult fp = pg::exec_params(
                c,
                "INSERT INTO discovery_store.discovery_meta (key, value) VALUES "
                "('backfill_source_fingerprint', $1) ON CONFLICT (key) DO UPDATE SET "
                "value = EXCLUDED.value WHERE discovery_store.discovery_meta.value = 'sourceless' "
                "OR discovery_store.discovery_meta.value = EXCLUDED.value RETURNING value",
                std::vector<std::string>{std::string(source_fingerprint)});
            if (fp.status() != PGRES_TUPLES_OK) {
                spdlog::error(
                    "DiscoveryStore: migrate_from_sqlite: source-fingerprint stamp failed: {}",
                    PQerrorMessage(c));
                return false;
            }
            if (PQntuples(fp.get()) == 0 && source_fingerprint != kSourcelessFingerprint) {
                spdlog::error(
                    "DiscoveryStore: migrate_from_sqlite: lost the race to record this "
                    "backfill's own source fingerprint — a DIFFERENT real fingerprint already "
                    "stamped backfill_source_fingerprint between this pass's marker-absent "
                    "check and this commit. This replica's own migration steps already "
                    "committed to Postgres; a retry will find the marker present, fail "
                    "holder-side fingerprint verification against the winning replica's "
                    "value, and require manual reconciliation (which replica's discovered-"
                    "device inventory is authoritative).");
                return false;
            }
            return true;
        });
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
            spdlog::warn("DiscoveryStore: migrate_from_sqlite: could not move legacy {} aside "
                         "({}); it is safe to archive/remove manually",
                         path.string(), mv_ec.message());
        else
            spdlog::info("DiscoveryStore: migrate_from_sqlite: moved legacy discovery db to {}",
                         aside.string());
    };

    // 1. Local legacy-file presence (cheap stat) — checked BEFORE the marker
    // lookup so step 2 knows whether THIS replica has something to verify a
    // pre-existing marker against.
    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("DiscoveryStore: migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        backfill_metric("failed");
        return false;
    }

    // 2. Idempotency marker (short-lived lease released before any legacy I/O).
    bool marker_present = false;
    std::optional<std::string> stored_fingerprint;
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("DiscoveryStore: migrate_from_sqlite: no database connection ({})",
                          pool_.last_error());
            backfill_metric("failed");
            return false;
        }
        pg::PgResult mk = pg::exec_params(
            lease.get(),
            "SELECT key, value FROM discovery_store.discovery_meta WHERE key IN "
            "('backfill_complete', 'backfill_source_fingerprint')",
            std::vector<std::string>{});
        if (mk.status() != PGRES_TUPLES_OK) {
            spdlog::error("DiscoveryStore: migrate_from_sqlite: marker lookup failed: {}",
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
        if (!legacy_exists) {
            spdlog::debug("DiscoveryStore: migrate_from_sqlite already completed, skipping");
            return true;
        }
        // This replica still holds a local legacy file even though the fleet
        // marker is already set — verify it was actually the file that got
        // migrated before trusting the marker.
        const auto verify_fp = legacy_discovery_fingerprint(legacy_db_path);
        if (!verify_fp) {
            spdlog::error(
                "DiscoveryStore: migrate_from_sqlite: backfill_complete is already set, and "
                "this replica's own legacy db {} exists but is unreadable/corrupt while being "
                "fingerprint-verified against it — refusing (fail-closed; never silently "
                "trust a marker over an unverifiable local file)",
                legacy_db_path.string());
            backfill_metric("failed");
            return false;
        }
        if (*verify_fp == kSourcelessFingerprint) {
            spdlog::debug("DiscoveryStore: migrate_from_sqlite already completed; this "
                         "replica's own legacy db has no discovered_devices table (nothing to "
                         "lose), skipping");
            return true;
        }
        if (!stored_fingerprint) {
            spdlog::error(
                "DiscoveryStore: migrate_from_sqlite: backfill_complete is already set with NO "
                "recorded source fingerprint (this marker predates the fingerprint-"
                "verification mechanism), and this replica's own legacy db {} still holds "
                "real content (fingerprint '{}'). Refusing to guess whether this is this "
                "replica's own prior migration or a different replica's — manual "
                "reconciliation required.",
                legacy_db_path.string(), *verify_fp);
            backfill_metric("failed");
            return false;
        }
        if (*stored_fingerprint == kSourcelessFingerprint) {
            spdlog::error(
                "DiscoveryStore: migrate_from_sqlite: backfill_complete is already set with a "
                "sourceless source fingerprint (no legacy discovery.db has been migrated for "
                "this fleet yet), and this replica's own legacy db {} still holds real "
                "content (fingerprint '{}'). Refusing to auto-migrate on this later boot: "
                "discovery_store may already have accepted live post-cutover scan results "
                "this file's stale content would silently clobber.",
                legacy_db_path.string(), *verify_fp);
            backfill_metric("failed");
            return false;
        }
        if (*stored_fingerprint != *verify_fp) {
            spdlog::error(
                "DiscoveryStore: migrate_from_sqlite: HOLDER-SIDE VERIFICATION FAILED — "
                "backfill_complete is already set with a DIFFERENT recorded source "
                "fingerprint ('{}') than this replica's own legacy db {} ('{}') — some other "
                "replica's legacy data was migrated, not this one's. Refusing to silently "
                "accept a completion this replica's discovered devices were never part of.",
                *stored_fingerprint, legacy_db_path.string(), *verify_fp);
            backfill_metric("failed");
            return false;
        }
        spdlog::debug("DiscoveryStore: migrate_from_sqlite already completed (fingerprint "
                     "verified), skipping");
        move_legacy_aside(legacy_db_path);
        return true;
    }

    if (!legacy_exists) {
        // Fresh install. Fingerprint is the sourceless sentinel, not
        // skipped: a later process that DOES hold a legacy file must be
        // able to tell this marker was never derived from any real content.
        if (!stamp_complete(kSourcelessFingerprint)) {
            backfill_metric("failed");
            return false;
        }
        spdlog::info("DiscoveryStore: migrate_from_sqlite: no legacy discovery.db at {}; "
                     "marking backfill complete (fresh install)",
                     legacy_db_path.string());
        backfill_metric("fresh");
        return true;
    }

    // 3. Open legacy read-only.
    SqliteDb legacy;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK) {
        spdlog::error("DiscoveryStore: migrate_from_sqlite: failed to open legacy db {}: {}",
                      legacy_db_path.string(),
                      legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
        backfill_metric("failed");
        return false;
    }
    sqlite3_exec(legacy.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    // Corruption probe: an unreadable legacy DB must NOT be silently
    // skipped, which would drop every operator-set managed flag.
    {
        SqliteStmt probe;
        if (sqlite3_prepare_v2(legacy.get(), "SELECT count(*) FROM sqlite_master", -1, probe.addr(),
                               nullptr) != SQLITE_OK ||
            sqlite3_step(probe.get()) != SQLITE_ROW) {
            spdlog::error("DiscoveryStore: migrate_from_sqlite: legacy db {} is "
                         "unreadable/corrupt ({}); refusing backfill (fail-closed — never "
                         "silently drop operator-set managed flags)",
                         legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
            backfill_metric("failed");
            return false;
        }
    }
    const auto has_devices = legacy_has_table(legacy.get(), "discovered_devices");
    if (!has_devices) {
        spdlog::error("DiscoveryStore: migrate_from_sqlite: legacy db {} could not be probed "
                     "for a discovered_devices table ({}); refusing backfill (fail-closed)",
                     legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
        backfill_metric("failed");
        return false;
    }
    if (!*has_devices) {
        if (!stamp_complete(kSourcelessFingerprint)) {
            backfill_metric("failed");
            return false;
        }
        spdlog::warn("DiscoveryStore: migrate_from_sqlite: legacy db {} has no "
                     "discovered_devices table; marking backfill complete",
                     legacy_db_path.string());
        backfill_metric("fresh");
        return true;
    }

    // 3b. Read every legacy row ONCE into the shared snapshot — the single
    // source both the real migration and this stamp's own trust-anchor
    // fingerprint (step 7) derive from. No second file read anywhere in this
    // function.
    const auto snap_opt = read_legacy_snapshot(legacy.get());
    if (!snap_opt) {
        spdlog::error("DiscoveryStore: migrate_from_sqlite: legacy read failed: {}",
                      sqlite3_errmsg(legacy.get()));
        backfill_metric("failed");
        return false;
    }
    const std::vector<LDevice>& snap = *snap_opt;
    const std::int64_t legacy_count = static_cast<std::int64_t>(snap.size());

    // 4. Insert every row in one transaction. ON CONFLICT DO NOTHING →
    // idempotent + crash-resumable by re-run.
    const bool insert_ok = pool_.with_txn_for(kBackfillTxnTimeout, [&](PGconn* c) -> bool {
        for (const auto& d : snap) {
            pg::PgResult r = pg::exec_params(
                c,
                "INSERT INTO discovery_store.discovered_devices "
                "(ip_address, mac_address, hostname, managed, agent_id, discovered_by, "
                "discovered_at, last_seen, subnet) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7::bigint, $8::bigint, $9) "
                "ON CONFLICT (ip_address) DO NOTHING",
                std::vector<std::string>{sanitize_pg_text(d.ip_address),
                                         sanitize_pg_text(d.mac_address),
                                         sanitize_pg_text(d.hostname),
                                         d.managed != 0 ? "true" : "false",
                                         sanitize_pg_text(d.agent_id),
                                         sanitize_pg_text(d.discovered_by),
                                         std::to_string(d.discovered_at),
                                         std::to_string(d.last_seen),
                                         sanitize_pg_text(d.subnet)});
            if (r.status() != PGRES_COMMAND_OK) {
                spdlog::error("DiscoveryStore: migrate_from_sqlite: device insert failed: {}",
                              PQerrorMessage(c));
                return false;
            }
        }
        return true;
    });
    if (!insert_ok) {
        backfill_metric("failed");
        return false;
    }

    // 5. Row-count reconciliation — PG must hold at least the legacy count
    // (DO NOTHING never drops a legacy row).
    {
        auto lease = pool_.acquire();
        if (!lease) {
            backfill_metric("failed");
            return false;
        }
        pg::PgResult r = pg::exec_params(
            lease.get(), "SELECT COUNT(*) FROM discovery_store.discovered_devices",
            std::vector<std::string>{});
        if (r.status() != PGRES_TUPLES_OK) {
            spdlog::error("DiscoveryStore: migrate_from_sqlite: reconciliation count failed");
            backfill_metric("failed");
            return false;
        }
        const std::int64_t pg_count = to_i64(PQgetvalue(r.get(), 0, 0));
        if (pg_count < legacy_count) {
            spdlog::error("DiscoveryStore: migrate_from_sqlite: reconciliation FAILED — legacy "
                         "devices={} vs PG devices={}; refusing marker",
                         legacy_count, pg_count);
            backfill_metric("failed");
            return false;
        }
        spdlog::info("DiscoveryStore: migrate_from_sqlite: reconciled — legacy devices={}, PG "
                     "devices={}",
                     legacy_count, pg_count);
    }

    // 6. Stamp the one-time marker with THIS file's real fingerprint —
    // derived from the SAME snapshot already read at step 3b, not a second
    // file read.
    const auto source_fp = fingerprint_legacy_snapshot(snap);
    if (!source_fp) {
        spdlog::error("DiscoveryStore: migrate_from_sqlite: could not derive this file's own "
                     "fingerprint immediately after successfully backfilling it; refusing to "
                     "stamp complete without a trust anchor");
        backfill_metric("failed");
        return false;
    }
    if (!stamp_complete(*source_fp)) {
        backfill_metric("failed");
        return false;
    }

    // 7. Move the verified legacy file aside (non-fatal on failure). Close
    // the legacy read-only handle FIRST: Windows refuses to rename a file
    // with an open handle.
    legacy.close();
    move_legacy_aside(legacy_db_path);

    backfill_metric("completed");
    return true;
}

} // namespace yuzu::server
