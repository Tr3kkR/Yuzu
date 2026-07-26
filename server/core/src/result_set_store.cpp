#include "result_set_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <random>
#include <string_view>
#include <utility>

namespace yuzu::server {

// ── Small helpers ────────────────────────────────────────────────────────────

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static int64_t now_epoch_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Only used against legacy SQLite text columns (may be nullptr).
static const char* safe(const char* p) {
    return p ? p : "";
}

const char* to_string(ResultSetStatus s) {
    switch (s) {
    case ResultSetStatus::Pending:
        return "pending";
    case ResultSetStatus::Materialized:
        return "materialized";
    case ResultSetStatus::Failed:
        return "failed";
    }
    return "materialized";
}

ResultSetStatus result_set_status_from(std::string_view s) {
    if (s == "pending")
        return ResultSetStatus::Pending;
    if (s == "failed")
        return ResultSetStatus::Failed;
    return ResultSetStatus::Materialized;
}

const char* to_string(ResultSetError e) {
    switch (e) {
    case ResultSetError::NotFound:
        return "RESULT_SET_NOT_FOUND";
    case ResultSetError::NotOwner:
        return "RESULT_SET_NOT_OWNER";
    case ResultSetError::QuotaExceeded:
        return "RESULT_SET_QUOTA";
    case ResultSetError::PinLimit:
        return "PIN_LIMIT";
    case ResultSetError::Pinned:
        return "RESULT_SET_PINNED";
    case ResultSetError::TooManyMembers:
        return "RESULT_SET_TOO_MANY_MEMBERS";
    case ResultSetError::DbError:
        return "RESULT_SET_DB_ERROR";
    }
    return "RESULT_SET_DB_ERROR";
}

// Cursor: keyset over (last_used_at, created_at, id) descending. Encoded as
// "<last_used_at>|<created_at>|<id>". Empty string means first page.
static std::string make_cursor(const ResultSet& r) {
    return std::to_string(r.last_used_at) + "|" + std::to_string(r.created_at) + "|" + r.id;
}

static bool parse_cursor(const std::string& c, int64_t& lu, int64_t& ca, std::string& id) {
    auto p1 = c.find('|');
    if (p1 == std::string::npos)
        return false;
    auto p2 = c.find('|', p1 + 1);
    if (p2 == std::string::npos)
        return false;
    try {
        lu = std::stoll(c.substr(0, p1));
        ca = std::stoll(c.substr(p1 + 1, p2 - p1 - 1));
    } catch (...) {
        return false;
    }
    id = c.substr(p2 + 1);
    return true;
}

// ── ID generation ────────────────────────────────────────────────────────────

std::string ResultSetStore::generate_id() {
    // Time-prefixed, lexically sortable (ULID-like) without a new dependency:
    // "rs_" + 11 hex digits of epoch-ms (sortable to ~year 2527) + 16 hex
    // digits of randomness for collision resistance within the same ms.
    //
    // Entropy note (review finding E, preserved from the SQLite implementation):
    // the random suffix is collision resistance, NOT an authenticator. rs_ ids
    // are display identifiers; the authorization boundary is the per-owner
    // check in evaluate_scope and member_set_owned() on every route, not id
    // unguessability.
    thread_local std::mt19937_64 rng{std::random_device{}()};
    std::array<char, 40> buf{};
    std::snprintf(buf.data(), buf.size(), "rs_%011llx%016llx",
                  static_cast<unsigned long long>(now_epoch_ms()),
                  static_cast<unsigned long long>(rng()));
    return std::string(buf.data());
}

namespace {

constexpr const char* kStoreName = "result_set_store";

// Bounded acquires (ADR-0012 §2(a)): authoritative store, so reads/writes wait
// a little longer than a fail-soft store's hot-path budget, but every runtime
// acquire is still bounded — none may block indefinitely on a saturated pool.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so `result_sets` et al. land in
    // `result_set_store`. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE result_sets ("
         "  id                  TEXT PRIMARY KEY,"
         "  name                TEXT,"
         "  owner_principal     TEXT NOT NULL,"
         "  created_at          BIGINT NOT NULL,"
         "  ttl_at              BIGINT NOT NULL,"
         "  last_used_at        BIGINT NOT NULL,"
         "  pinned              BOOLEAN NOT NULL DEFAULT FALSE,"
         "  parent_id           TEXT REFERENCES result_sets(id) ON DELETE SET NULL,"
         "  source_kind         TEXT NOT NULL,"
         "  source_payload      TEXT NOT NULL,"
         "  status              TEXT NOT NULL DEFAULT 'materialized',"
         "  source_execution_id TEXT NOT NULL DEFAULT '',"
         "  matcher             TEXT NOT NULL DEFAULT '',"
         "  device_count        BIGINT NOT NULL DEFAULT 0,"
         "  CHECK (length(id) >= 5 AND substr(id,1,3) = 'rs_'),"
         "  CHECK (ttl_at >= created_at));"
         "CREATE TABLE result_set_members ("
         "  result_set_id TEXT NOT NULL REFERENCES result_sets(id) ON DELETE CASCADE,"
         "  device_id     TEXT NOT NULL,"
         "  PRIMARY KEY (result_set_id, device_id));"
         "CREATE INDEX idx_result_sets_owner_used ON result_sets(owner_principal, last_used_at);"
         "CREATE INDEX idx_result_sets_owner_name ON result_sets(owner_principal, name);"
         "CREATE INDEX idx_result_sets_parent ON result_sets(parent_id);"
         "CREATE INDEX idx_result_sets_status ON result_sets(status);"
         "CREATE INDEX idx_result_set_members_dev ON result_set_members(device_id);"
         // Backfill idempotency marker (ADR-0009). A dedicated row — NEVER
         // inferred from result_sets being empty, since gc_sweep legitimately
         // empties it over the store's lifetime.
         "CREATE TABLE sqlite_backfill ("
         "  id           SMALLINT PRIMARY KEY,"
         "  completed_at BIGINT NOT NULL,"
         "  CHECK (id = 1));"},
    };
    return kMigrations;
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
int to_int(const char* s) { return static_cast<int>(to_i64(s)); }
bool to_bool(const char* s) { return s != nullptr && s[0] == 't'; }

constexpr const char* kRowCols =
    "id, name, owner_principal, created_at, ttl_at, last_used_at, pinned, parent_id, "
    "source_kind, source_payload, status, source_execution_id, matcher, device_count";

ResultSet read_row(PGresult* res, int i) {
    ResultSet r;
    int c = 0;
    r.id = PQgetvalue(res, i, c++);
    // NULL and "" are indistinguishable via PQgetvalue on a text column — same
    // ambiguity the legacy SQLite reader had (sqlite3_column_text on a NULL
    // column also yields ""), so this is not a behavioral change.
    r.name = PQgetvalue(res, i, c++);
    r.owner_principal = PQgetvalue(res, i, c++);
    r.created_at = to_i64(PQgetvalue(res, i, c++));
    r.ttl_at = to_i64(PQgetvalue(res, i, c++));
    r.last_used_at = to_i64(PQgetvalue(res, i, c++));
    r.pinned = to_bool(PQgetvalue(res, i, c++));
    if (!PQgetisnull(res, i, c))
        r.parent_id = PQgetvalue(res, i, c);
    ++c;
    r.source_kind = PQgetvalue(res, i, c++);
    r.source_payload = PQgetvalue(res, i, c++);
    r.status = result_set_status_from(PQgetvalue(res, i, c++));
    r.source_execution_id = PQgetvalue(res, i, c++);
    r.matcher = PQgetvalue(res, i, c++);
    r.device_count = to_i64(PQgetvalue(res, i, c++));
    return r;
}

std::vector<std::string_view> as_views(const std::vector<std::string>& v) {
    std::vector<std::string_view> out;
    out.reserve(v.size());
    for (const auto& s : v)
        out.emplace_back(s);
    return out;
}

// Shared by pin() (same connection, no extra round trip) and the public
// count_pinned_for_owner(). Returns -1 on query error so callers can
// distinguish "zero pinned" from "could not determine" (authoritative posture
// — a caller must not silently treat a DB error as "under the limit").
int count_pinned_on(PGconn* conn, const std::string& owner) {
    pg::PgResult res = pg::exec_params(
        conn,
        "SELECT COUNT(*) FROM result_set_store.result_sets WHERE owner_principal = $1 AND "
        "pinned = true",
        std::vector<std::string>{owner});
    if (res.status() != PGRES_TUPLES_OK)
        return -1;
    return to_int(PQgetvalue(res.get(), 0, 0));
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

ResultSetStore::ResultSetStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("ResultSetStore: no database connection at construction ({}) — result-set "
                      "persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("ResultSetStore: schema migration failed — result-set persistence disabled");
        return;
    }
    open_ = true;
}

// ── Backfill (ADR-0009) ──────────────────────────────────────────────────────

bool ResultSetStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    // Idempotency check: a dedicated marker row, never row-count-inferred
    // (gc_sweep legitimately empties result_sets over the store's lifetime).
    // Unbounded acquire() here is construction-time discipline (ADR-0012
    // §2(a)) — this runs once at boot, before serving, same as the ctor.
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("ResultSetStore::migrate_from_sqlite: no database connection");
            return false;
        }
        pg::PgResult marker = pg::exec_params(
            lease.get(), "SELECT 1 FROM result_set_store.sqlite_backfill LIMIT 1",
            std::vector<std::string>{});
        if (marker.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::migrate_from_sqlite: backfill-marker check failed: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        if (PQntuples(marker.get()) > 0) {
            spdlog::info("ResultSetStore::migrate_from_sqlite: already backfilled, skipping");
            return true;
        }
    }

    std::error_code ec;
    if (!std::filesystem::exists(legacy_db_path, ec)) {
        // Fresh install — nothing to backfill. Stamp the marker so this branch
        // is not re-evaluated on every future boot.
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("ResultSetStore::migrate_from_sqlite: no connection to stamp marker");
            return false;
        }
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO result_set_store.sqlite_backfill (id, completed_at) VALUES (1, "
            "$1::bigint) ON CONFLICT (id) DO NOTHING",
            std::vector<std::string>{std::to_string(now_epoch())});
        if (r.status() != PGRES_COMMAND_OK) {
            spdlog::error("ResultSetStore::migrate_from_sqlite: failed to stamp marker: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        spdlog::info("ResultSetStore::migrate_from_sqlite: no legacy {} — nothing to backfill",
                     legacy_db_path.string());
        return true;
    }

    // Read the legacy SQLite file READ-ONLY. It is retained by the caller
    // (never deleted here) for the ADR-0009 one-release rollback window.
    sqlite3* legacy = nullptr;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), &legacy, SQLITE_OPEN_READONLY, nullptr) !=
        SQLITE_OK) {
        spdlog::error("ResultSetStore::migrate_from_sqlite: failed to open legacy {}: {}",
                      legacy_db_path.string(), legacy ? sqlite3_errmsg(legacy) : "open failed");
        if (legacy)
            sqlite3_close(legacy);
        return false;
    }

    std::vector<ResultSet> legacy_sets;
    {
        sqlite3_stmt* s = nullptr;
        const char* sql =
            "SELECT id, name, owner_principal, created_at, ttl_at, last_used_at, pinned, "
            "parent_id, source_kind, source_payload, status, source_execution_id, matcher, "
            "device_count FROM result_sets;";
        if (sqlite3_prepare_v2(legacy, sql, -1, &s, nullptr) != SQLITE_OK) {
            spdlog::error(
                "ResultSetStore::migrate_from_sqlite: legacy result_sets query failed: {}",
                sqlite3_errmsg(legacy));
            sqlite3_close(legacy);
            return false;
        }
        while (sqlite3_step(s) == SQLITE_ROW) {
            ResultSet r;
            r.id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
            r.name = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
            r.owner_principal = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
            r.created_at = sqlite3_column_int64(s, 3);
            r.ttl_at = sqlite3_column_int64(s, 4);
            r.last_used_at = sqlite3_column_int64(s, 5);
            r.pinned = sqlite3_column_int64(s, 6) != 0;
            if (sqlite3_column_type(s, 7) != SQLITE_NULL)
                r.parent_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 7)));
            r.source_kind = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 8)));
            r.source_payload = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 9)));
            r.status = result_set_status_from(
                safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 10))));
            r.source_execution_id =
                safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 11)));
            r.matcher = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 12)));
            r.device_count = sqlite3_column_int64(s, 13);
            legacy_sets.push_back(std::move(r));
        }
        sqlite3_finalize(s);
    }

    std::vector<std::pair<std::string, std::string>> legacy_members; // (result_set_id, device_id)
    {
        sqlite3_stmt* s = nullptr;
        const char* sql = "SELECT result_set_id, device_id FROM result_set_members;";
        if (sqlite3_prepare_v2(legacy, sql, -1, &s, nullptr) != SQLITE_OK) {
            spdlog::error(
                "ResultSetStore::migrate_from_sqlite: legacy result_set_members query failed: {}",
                sqlite3_errmsg(legacy));
            sqlite3_close(legacy);
            return false;
        }
        while (sqlite3_step(s) == SQLITE_ROW) {
            legacy_members.emplace_back(
                safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0))),
                safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1))));
        }
        sqlite3_finalize(s);
    }
    sqlite3_close(legacy);

    spdlog::info("ResultSetStore::migrate_from_sqlite: backfilling {} result set(s), {} member "
                 "row(s) from {}",
                 legacy_sets.size(), legacy_members.size(), legacy_db_path.string());

    // ONE transaction: fail closed on any error, nothing partially committed
    // (ADR-0009 "fails closed on any error"). Unbounded with_txn (not
    // with_txn_for): startup is serial, same discipline as the ctor's
    // unbounded acquire() (ADR-0012 §2(a)).
    bool ok = pool_.with_txn([&](PGconn* conn) -> bool {
        for (const auto& r : legacy_sets) {
            pg::PgResult res = pg::exec_params(
                conn,
                "INSERT INTO result_set_store.result_sets "
                "(id, name, owner_principal, created_at, ttl_at, last_used_at, pinned, "
                " parent_id, source_kind, source_payload, status, source_execution_id, matcher, "
                " device_count) "
                "VALUES ($1,$2,$3,$4::bigint,$5::bigint,$6::bigint,$7::boolean,$8,$9,$10,$11,"
                "$12,$13,$14::bigint) ON CONFLICT (id) DO NOTHING",
                std::vector<std::optional<std::string>>{
                    r.id, r.name.empty() ? std::nullopt : std::optional<std::string>(r.name),
                    r.owner_principal, std::to_string(r.created_at), std::to_string(r.ttl_at),
                    std::to_string(r.last_used_at), std::string(r.pinned ? "true" : "false"),
                    r.parent_id, r.source_kind, r.source_payload,
                    std::string(to_string(r.status)), r.source_execution_id, r.matcher,
                    std::to_string(r.device_count)});
            if (res.status() != PGRES_COMMAND_OK) {
                spdlog::error("ResultSetStore::migrate_from_sqlite: insert of {} failed: {}", r.id,
                              PQerrorMessage(conn));
                return false;
            }
        }
        for (const auto& [rs_id, dev_id] : legacy_members) {
            pg::PgResult res = pg::exec_params(
                conn,
                "INSERT INTO result_set_store.result_set_members (result_set_id, device_id) "
                "VALUES ($1,$2) ON CONFLICT DO NOTHING",
                std::vector<std::string>{rs_id, dev_id});
            if (res.status() != PGRES_COMMAND_OK) {
                spdlog::error(
                    "ResultSetStore::migrate_from_sqlite: member insert ({}, {}) failed: {}",
                    rs_id, dev_id, PQerrorMessage(conn));
                return false;
            }
        }
        pg::PgResult marker = pg::exec_params(
            conn,
            "INSERT INTO result_set_store.sqlite_backfill (id, completed_at) VALUES (1, "
            "$1::bigint) ON CONFLICT (id) DO NOTHING",
            std::vector<std::string>{std::to_string(now_epoch())});
        if (marker.status() != PGRES_COMMAND_OK) {
            spdlog::error("ResultSetStore::migrate_from_sqlite: failed to stamp backfill marker: {}",
                          PQerrorMessage(conn));
            return false;
        }
        return true;
    });
    if (!ok) {
        spdlog::error("ResultSetStore::migrate_from_sqlite: backfill transaction failed — "
                      "result-set data NOT migrated");
        return false;
    }
    spdlog::info("ResultSetStore::migrate_from_sqlite: backfill complete");
    return true;
}

// ── Create ───────────────────────────────────────────────────────────────────

std::expected<ResultSet, ResultSetError> ResultSetStore::insert_row_impl(
    const CreateRequest& req, ResultSetStatus status, const std::string& execution_id,
    const std::vector<std::string>& members) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);

    // Deduplicate members up front: device_count must reflect the rows
    // actually stored (ON CONFLICT DO NOTHING silently drops duplicates —
    // review finding L, preserved from the SQLite implementation), and the
    // per-set cap is a DoS guard that must bound the *distinct* membership,
    // not the raw request size (review finding C).
    std::vector<std::string> uniq;
    uniq.reserve(members.size());
    {
        std::unordered_set<std::string> seen;
        seen.reserve(members.size() * 2);
        for (const auto& dev : members)
            if (!dev.empty() && seen.insert(dev).second)
                uniq.push_back(dev);
    }
    if (uniq.size() > static_cast<size_t>(kMaxMembersPerSet))
        return std::unexpected(ResultSetError::TooManyMembers);

    ResultSet row;
    row.id = generate_id();
    row.name = req.name;
    row.owner_principal = req.owner_principal;
    row.created_at = now_epoch();
    row.ttl_at = row.created_at + kDefaultTtlSeconds;
    row.last_used_at = row.created_at;
    row.pinned = false;
    row.parent_id = req.parent_id;
    row.source_kind = req.source_kind;
    row.source_payload = req.source_payload;
    row.status = status;
    row.source_execution_id = execution_id;
    row.matcher = req.matcher;
    row.device_count = static_cast<int64_t>(uniq.size());

    const std::vector<std::string_view> member_views = as_views(uniq);
    bool quota_exceeded = false;

    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        // Hard per-operator quota (design §3.3). A small race against a
        // concurrent create for the same owner is possible (Postgres real
        // concurrency replaces the SQLite single-writer mutex) — acceptable
        // for a soft DoS guard, not a security boundary.
        pg::PgResult qc = pg::exec_params(
            conn, "SELECT COUNT(*) FROM result_set_store.result_sets WHERE owner_principal = $1",
            std::vector<std::string>{req.owner_principal});
        if (qc.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::insert_row_impl: quota check failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        if (to_int(PQgetvalue(qc.get(), 0, 0)) >= kMaxPerOwner) {
            quota_exceeded = true;
            return false;
        }

        pg::PgResult r1 = pg::exec_params(
            conn,
            "INSERT INTO result_set_store.result_sets "
            "(id, name, owner_principal, created_at, ttl_at, last_used_at, pinned, parent_id, "
            " source_kind, source_payload, status, source_execution_id, matcher, device_count) "
            "VALUES ($1,$2,$3,$4::bigint,$5::bigint,$6::bigint,false,$7,$8,$9,$10,$11,$12,"
            "$13::bigint) RETURNING id",
            std::vector<std::optional<std::string>>{
                row.id, row.name.empty() ? std::nullopt : std::optional<std::string>(row.name),
                row.owner_principal, std::to_string(row.created_at), std::to_string(row.ttl_at),
                std::to_string(row.last_used_at), row.parent_id, row.source_kind,
                row.source_payload, std::string(to_string(row.status)), row.source_execution_id,
                row.matcher, std::to_string(row.device_count)});
        if (r1.status() != PGRES_TUPLES_OK || PQntuples(r1.get()) == 0) {
            spdlog::error("ResultSetStore::insert_row_impl: row insert failed: {}",
                          PQerrorMessage(conn));
            return false;
        }

        if (!uniq.empty()) {
            pg::PgResult r2 = pg::exec_params(
                conn,
                "INSERT INTO result_set_store.result_set_members (result_set_id, device_id) "
                "SELECT $1, d FROM unnest($2::text[]) AS d ON CONFLICT DO NOTHING",
                std::vector<std::string>{row.id, pg::to_text_array(member_views)});
            if (r2.status() != PGRES_COMMAND_OK && r2.status() != PGRES_TUPLES_OK) {
                spdlog::error("ResultSetStore::insert_row_impl: member insert failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
        }
        return true;
    });

    if (!ok)
        return std::unexpected(quota_exceeded ? ResultSetError::QuotaExceeded
                                              : ResultSetError::DbError);
    return row;
}

std::expected<ResultSet, ResultSetError> ResultSetStore::create_materialized(
    const CreateRequest& req, const std::vector<std::string>& members) {
    return insert_row_impl(req, ResultSetStatus::Materialized, /*execution_id=*/"", members);
}

std::expected<ResultSet, ResultSetError> ResultSetStore::create_pending(
    const CreateRequest& req, const std::string& execution_id) {
    return insert_row_impl(req, ResultSetStatus::Pending, execution_id, /*members=*/{});
}

// ── Read ─────────────────────────────────────────────────────────────────────

std::expected<std::optional<ResultSet>, ResultSetError> ResultSetStore::get(const std::string& id) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::get: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }
    std::string sql = std::string("SELECT ") + kRowCols +
                      " FROM result_set_store.result_sets WHERE id = $1 LIMIT 1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::get: query failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<ResultSet>(std::nullopt);
    return std::optional<ResultSet>(read_row(res.get(), 0));
}

std::vector<ResultSet> ResultSetStore::list_by_owner(const std::string& owner,
                                                     const std::string& cursor, int limit,
                                                     std::string& out_next_cursor) {
    out_next_cursor.clear();
    std::vector<ResultSet> result;
    if (!open_)
        return result;
    if (limit <= 0)
        limit = 50;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::list_by_owner: no connection ({})", pool_.last_error());
        return result;
    }

    int64_t cur_lu = 0, cur_ca = 0;
    std::string cur_id;
    bool has_cursor = !cursor.empty() && parse_cursor(cursor, cur_lu, cur_ca, cur_id);

    // Keyset pagination over (last_used_at, created_at, id) DESC.
    std::string sql = std::string("SELECT ") + kRowCols +
                      " FROM result_set_store.result_sets WHERE owner_principal = $1";
    std::vector<std::string> params{owner};
    if (has_cursor) {
        sql += " AND (last_used_at < $2::bigint OR (last_used_at = $2::bigint AND "
              "(created_at < $3::bigint OR (created_at = $3::bigint AND id < $4))))"
              " ORDER BY last_used_at DESC, created_at DESC, id DESC LIMIT $5::bigint";
        params.push_back(std::to_string(cur_lu));
        params.push_back(std::to_string(cur_ca));
        params.push_back(cur_id);
    } else {
        sql += " ORDER BY last_used_at DESC, created_at DESC, id DESC LIMIT $2::bigint";
    }
    params.push_back(std::to_string(limit + 1)); // fetch one extra to detect next page

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::list_by_owner: query failed: {}",
                      PQerrorMessage(lease.get()));
        return result;
    }
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.push_back(read_row(res.get(), i));

    if (static_cast<int>(result.size()) > limit) {
        result.resize(limit);
        out_next_cursor = make_cursor(result.back());
    }
    return result;
}

std::vector<std::string> ResultSetStore::members(const std::string& id, const std::string& cursor,
                                                 int limit, std::string& out_next_cursor) {
    out_next_cursor.clear();
    std::vector<std::string> result;
    if (!open_)
        return result;
    if (limit <= 0)
        limit = 1000;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::members: no connection ({})", pool_.last_error());
        return result;
    }

    // Keyset over device_id ASC.
    std::string sql =
        "SELECT device_id FROM result_set_store.result_set_members WHERE result_set_id = $1";
    std::vector<std::string> params{id};
    if (!cursor.empty()) {
        sql += " AND device_id > $2 ORDER BY device_id ASC LIMIT $3::bigint";
        params.push_back(cursor);
    } else {
        sql += " ORDER BY device_id ASC LIMIT $2::bigint";
    }
    params.push_back(std::to_string(limit + 1));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::members: query failed: {}", PQerrorMessage(lease.get()));
        return result;
    }
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.emplace_back(PQgetvalue(res.get(), i, 0));

    if (static_cast<int>(result.size()) > limit) {
        result.resize(limit);
        out_next_cursor = result.back();
    }
    return result;
}

std::vector<LineageNode> ResultSetStore::lineage(const std::string& id, const std::string& owner) {
    std::vector<LineageNode> chain;
    if (!open_)
        return chain;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::lineage: no connection ({})", pool_.last_error());
        return chain;
    }

    // One logical operation, one lease (ADR-0012 §2(c)) — up to kLineageDepthCap
    // sequential hops on the same connection.
    std::optional<std::string> cur = id;
    int depth = 0;
    std::unordered_set<std::string> visited; // cycle guard (review finding J)
    while (cur && depth < kLineageDepthCap) {
        if (!visited.insert(*cur).second)
            break; // a parent_id loop would otherwise spin to the depth cap
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "SELECT id, name, source_kind, device_count, parent_id, owner_principal "
            "FROM result_set_store.result_sets WHERE id = $1 LIMIT 1",
            std::vector<std::string>{*cur});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::lineage: query failed: {}", PQerrorMessage(lease.get()));
            break;
        }
        std::optional<std::string> next;
        if (PQntuples(res.get()) > 0) {
            // Owner-filter (review finding B2): stop at the first node not
            // owned by `owner` so a cross-operator ancestor's name/
            // source_kind/device_count never reaches the caller.
            std::string node_owner = PQgetvalue(res.get(), 0, 5);
            if (node_owner != owner)
                break;
            LineageNode n;
            n.id = PQgetvalue(res.get(), 0, 0);
            n.name = PQgetvalue(res.get(), 0, 1);
            n.source_kind = PQgetvalue(res.get(), 0, 2);
            n.device_count = to_i64(PQgetvalue(res.get(), 0, 3));
            chain.push_back(std::move(n));
            if (!PQgetisnull(res.get(), 0, 4))
                next = PQgetvalue(res.get(), 0, 4);
        }
        cur = next;
        ++depth;
    }
    // chain is leaf→root; reverse to root→leaf for breadcrumb display.
    std::reverse(chain.begin(), chain.end());
    return chain;
}

std::expected<bool, ResultSetError> ResultSetStore::contains(const std::string& id,
                                                             const std::string& device_id) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::contains: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT 1 FROM result_set_store.result_set_members WHERE result_set_id = $1 AND "
        "device_id = $2 LIMIT 1",
        std::vector<std::string>{id, device_id});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::contains: query failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    return PQntuples(res.get()) > 0;
}

std::expected<std::unordered_set<std::string>, ResultSetError>
ResultSetStore::member_set_owned(const std::string& id, const std::string& owner) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::member_set_owned: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }
    // The owner join is the authorization gate: a set not owned by `owner`
    // yields zero rows, so the caller sees an empty (non-matching) membership
    // and never learns it exists — the documented "stale members drop
    // silently" contract extends cleanly to "not-yours members drop silently".
    // A DB ERROR is DISTINCT from both of those (std::unexpected, never an
    // empty set) — see the header's type-distinguishable-reads note; the
    // caller (AgentRegistry::evaluate_scope) MUST abort on DbError rather
    // than proceed with a partial preload (the fleet-wide fail-open under a
    // NOT combinator this contract exists to prevent).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT m.device_id FROM result_set_store.result_set_members m "
        "JOIN result_set_store.result_sets r ON r.id = m.result_set_id "
        "WHERE m.result_set_id = $1 AND r.owner_principal = $2",
        std::vector<std::string>{id, owner});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::member_set_owned: query failed: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    std::unordered_set<std::string> out;
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.insert(PQgetvalue(res.get(), i, 0));
    return out;
}

std::expected<std::optional<std::string>, ResultSetError>
ResultSetStore::resolve_alias(const std::string& owner, const std::string& name) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    if (name.empty())
        return std::optional<std::string>(std::nullopt); // trivial not-found, not a DB error
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::resolve_alias: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id FROM result_set_store.result_sets WHERE owner_principal = $1 AND name = $2 "
        "ORDER BY created_at DESC LIMIT 1",
        std::vector<std::string>{owner, name});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::resolve_alias: query failed: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<std::string>(std::nullopt);
    return std::optional<std::string>(std::string(PQgetvalue(res.get(), 0, 0)));
}

int ResultSetStore::count_for_owner(const std::string& owner) {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::count_for_owner: no connection ({})", pool_.last_error());
        return 0;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT COUNT(*) FROM result_set_store.result_sets WHERE owner_principal = $1",
        std::vector<std::string>{owner});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::count_for_owner: query failed: {}",
                      PQerrorMessage(lease.get()));
        return 0;
    }
    return to_int(PQgetvalue(res.get(), 0, 0));
}

int ResultSetStore::count_pinned_for_owner(const std::string& owner) {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::count_pinned_for_owner: no connection ({})",
                      pool_.last_error());
        return 0;
    }
    int n = count_pinned_on(lease.get(), owner);
    if (n < 0) {
        spdlog::error("ResultSetStore::count_pinned_for_owner: query failed: {}",
                      PQerrorMessage(lease.get()));
        return 0;
    }
    return n;
}

ResultSetStore::Counts ResultSetStore::counts() {
    Counts c;
    if (!open_)
        return c;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::counts: no connection ({})", pool_.last_error());
        return c;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT COUNT(*), COALESCE(SUM(pinned::int), 0), "
        "COALESCE(SUM((status = 'pending')::int), 0) FROM result_set_store.result_sets",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        spdlog::error("ResultSetStore::counts: query failed: {}", PQerrorMessage(lease.get()));
        return c;
    }
    c.total = to_int(PQgetvalue(res.get(), 0, 0));
    c.pinned = to_int(PQgetvalue(res.get(), 0, 1));
    c.pending = to_int(PQgetvalue(res.get(), 0, 2));
    return c;
}

// ── Mutate ───────────────────────────────────────────────────────────────────

std::expected<ResultSet, ResultSetError> ResultSetStore::pin(const std::string& id) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::pin: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }

    std::string sel_sql = std::string("SELECT ") + kRowCols +
                          " FROM result_set_store.result_sets WHERE id = $1 LIMIT 1";
    pg::PgResult get_res =
        pg::exec_params(lease.get(), sel_sql.c_str(), std::vector<std::string>{id});
    if (get_res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::pin: read failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    if (PQntuples(get_res.get()) == 0)
        return std::unexpected(ResultSetError::NotFound);
    ResultSet row = read_row(get_res.get(), 0);
    if (row.pinned)
        return row; // idempotent — no ttl_at renewal, matches the SQLite behavior

    // Pin-storm guard (design §3.3): per-operator cap.
    int pinned_count = count_pinned_on(lease.get(), row.owner_principal);
    if (pinned_count < 0) {
        spdlog::error("ResultSetStore::pin: pin-count check failed: {}",
                      PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    if (pinned_count >= kMaxPinsPerOwner)
        return std::unexpected(ResultSetError::PinLimit);

    std::string upd_sql = std::string("UPDATE result_set_store.result_sets SET pinned = true, "
                                      "ttl_at = $1::bigint WHERE id = $2 RETURNING ") +
                          kRowCols;
    pg::PgResult upd = pg::exec_params(
        lease.get(), upd_sql.c_str(),
        std::vector<std::string>{std::to_string(std::numeric_limits<int64_t>::max()), id});
    if (upd.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::pin: update failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    if (PQntuples(upd.get()) == 0)
        return std::unexpected(ResultSetError::NotFound); // deleted concurrently
    return read_row(upd.get(), 0);
}

std::expected<ResultSet, ResultSetError> ResultSetStore::unpin(const std::string& id) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::unpin: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }
    // Restore ttl_at = now + default (design §3.3). The original was
    // INT64_MAX while pinned, so this clamps rather than "restoring" a prior
    // value — same behavior as the SQLite implementation.
    int64_t new_ttl = now_epoch() + kDefaultTtlSeconds;
    std::string sql = std::string("UPDATE result_set_store.result_sets SET pinned = false, "
                                  "ttl_at = $1::bigint WHERE id = $2 RETURNING ") +
                      kRowCols;
    pg::PgResult upd = pg::exec_params(
        lease.get(), sql.c_str(), std::vector<std::string>{std::to_string(new_ttl), id});
    if (upd.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::unpin: update failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    if (PQntuples(upd.get()) == 0)
        return std::unexpected(ResultSetError::NotFound);
    return read_row(upd.get(), 0);
}

void ResultSetStore::touch(const std::string& id) {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::touch: no connection ({})", pool_.last_error());
        return;
    }
    int64_t now = now_epoch();
    // Do not shorten a pinned set's INT64_MAX ttl; only ever extend.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE result_set_store.result_sets SET last_used_at = $1::bigint, "
        "ttl_at = GREATEST(ttl_at, $2::bigint) WHERE id = $3",
        std::vector<std::string>{std::to_string(now), std::to_string(now + kDefaultTtlSeconds),
                                 id});
    if (res.status() != PGRES_COMMAND_OK)
        spdlog::error("ResultSetStore::touch: update failed: {}", PQerrorMessage(lease.get()));
}

std::expected<void, ResultSetError> ResultSetStore::delete_set(const std::string& id) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::delete_set: no connection ({})", pool_.last_error());
        return std::unexpected(ResultSetError::DbError);
    }
    pg::PgResult get_res = pg::exec_params(
        lease.get(), "SELECT pinned FROM result_set_store.result_sets WHERE id = $1 LIMIT 1",
        std::vector<std::string>{id});
    if (get_res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::delete_set: read failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    if (PQntuples(get_res.get()) == 0)
        return std::unexpected(ResultSetError::NotFound);
    if (to_bool(PQgetvalue(get_res.get(), 0, 0)))
        return std::unexpected(ResultSetError::Pinned); // must unpin first (design §6)

    pg::PgResult del = pg::exec_params(
        lease.get(), "DELETE FROM result_set_store.result_sets WHERE id = $1 RETURNING id",
        std::vector<std::string>{id});
    if (del.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::delete_set: delete failed: {}", PQerrorMessage(lease.get()));
        return std::unexpected(ResultSetError::DbError);
    }
    if (PQntuples(del.get()) == 0)
        return std::unexpected(ResultSetError::NotFound);
    return {};
}

// ── Async materialisation ────────────────────────────────────────────────────

std::vector<PendingSet> ResultSetStore::list_pending() {
    std::vector<PendingSet> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::list_pending: no connection ({})", pool_.last_error());
        return result;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, owner_principal, source_kind, source_execution_id, matcher, created_at "
        "FROM result_set_store.result_sets WHERE status = 'pending' ORDER BY created_at ASC",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::list_pending: query failed: {}", PQerrorMessage(lease.get()));
        return result;
    }
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        PendingSet p;
        p.id = PQgetvalue(res.get(), i, 0);
        p.owner_principal = PQgetvalue(res.get(), i, 1);
        p.source_kind = PQgetvalue(res.get(), i, 2);
        p.source_execution_id = PQgetvalue(res.get(), i, 3);
        p.matcher = PQgetvalue(res.get(), i, 4);
        p.created_at = to_i64(PQgetvalue(res.get(), i, 5));
        result.push_back(std::move(p));
    }
    return result;
}

std::expected<void, ResultSetError> ResultSetStore::materialize(
    const std::string& id, const std::vector<std::string>& members) {
    if (!open_)
        return std::unexpected(ResultSetError::DbError);
    const std::vector<std::string_view> member_views = as_views(members);
    bool not_found = false;

    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        if (!members.empty()) {
            pg::PgResult r = pg::exec_params(
                conn,
                "INSERT INTO result_set_store.result_set_members (result_set_id, device_id) "
                "SELECT $1, d FROM unnest($2::text[]) AS d ON CONFLICT DO NOTHING",
                std::vector<std::string>{id, pg::to_text_array(member_views)});
            if (r.status() != PGRES_COMMAND_OK && r.status() != PGRES_TUPLES_OK) {
                spdlog::error("ResultSetStore::materialize: member insert failed: {}",
                              PQerrorMessage(conn));
                return false;
            }
        }
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE result_set_store.result_sets SET status = 'materialized', "
            "device_count = $1::bigint WHERE id = $2 AND status = 'pending' RETURNING id",
            std::vector<std::string>{std::to_string(static_cast<int64_t>(members.size())), id});
        if (upd.status() != PGRES_TUPLES_OK) {
            spdlog::error("ResultSetStore::materialize: update failed: {}", PQerrorMessage(conn));
            return false;
        }
        if (PQntuples(upd.get()) == 0) {
            not_found = true;
            return false;
        }
        return true;
    });
    if (!ok)
        return std::unexpected(not_found ? ResultSetError::NotFound : ResultSetError::DbError);
    return {};
}

void ResultSetStore::mark_failed(const std::string& id, const std::string& reason) {
    if (!open_)
        return;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::mark_failed: no connection ({})", pool_.last_error());
        return;
    }
    pg::PgResult sel = pg::exec_params(
        lease.get(),
        "SELECT source_payload FROM result_set_store.result_sets WHERE id = $1 AND status = "
        "'pending'",
        std::vector<std::string>{id});
    if (sel.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::mark_failed: read failed: {}", PQerrorMessage(lease.get()));
        return;
    }
    if (PQntuples(sel.get()) == 0)
        return; // not pending (or gone) — nothing to mark

    // Merge {"failure": reason} into the payload in C++ rather than relying on
    // a Postgres JSON-validity cast (source_payload is a plain TEXT column,
    // not jsonb, and an operator-supplied string is not guaranteed valid
    // JSON) — replicates the SQLite json1 `json_set(... CASE WHEN
    // json_valid ...)` fallback-to-'{}' behavior.
    nlohmann::json payload;
    try {
        payload = nlohmann::json::parse(std::string(PQgetvalue(sel.get(), 0, 0)));
        if (!payload.is_object())
            payload = nlohmann::json::object();
    } catch (...) {
        payload = nlohmann::json::object();
    }
    payload["failure"] = reason;

    pg::PgResult upd = pg::exec_params(
        lease.get(),
        "UPDATE result_set_store.result_sets SET status = 'failed', source_payload = $1 "
        "WHERE id = $2 AND status = 'pending'",
        std::vector<std::string>{payload.dump(), id});
    if (upd.status() != PGRES_COMMAND_OK)
        spdlog::error("ResultSetStore::mark_failed: update failed: {}", PQerrorMessage(lease.get()));
}

// ── GC ───────────────────────────────────────────────────────────────────────

int ResultSetStore::gc_sweep() {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::error("ResultSetStore::gc_sweep: no connection ({})", pool_.last_error());
        return 0;
    }
    // Single DELETE ... RETURNING: count the rows the statement actually
    // removed (the #1033-banning idiom), rather than a pre-count we assume
    // succeeds. Cascades to result_set_members via the FK.
    int64_t now = now_epoch();
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM result_set_store.result_sets WHERE pinned = false AND ttl_at < $1::bigint "
        "RETURNING id",
        std::vector<std::string>{std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("ResultSetStore::gc_sweep: delete failed: {}", PQerrorMessage(lease.get()));
        return 0;
    }
    return PQntuples(res.get());
}

} // namespace yuzu::server
