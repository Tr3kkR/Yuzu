#include "software_inventory_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "software_inventory_store";
constexpr const char* kSourceInstalledSoftware = "installed_software";

// Bounded acquires (ADR-0012 lease discipline). Ingest runs on the gRPC thread
// (direct ReportInventory / gateway ProxyInventory) so it must give up fast on a
// saturated pool — best-effort, the agent retries next cycle + weekly floor.
constexpr std::chrono::milliseconds kIngestAcquireTimeout{500};
constexpr std::chrono::milliseconds kQueryAcquireTimeout{3000};
// Hard ceiling on rows a single fleet query will materialise, independent of the
// caller's `limit`, so the store can never allocate an unbounded result set.
constexpr int kFleetQueryRowCap = 100000;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for the
    // migration transaction, so these tables land in `software_inventory_store`.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         // Generic per-source parent (one row per agent+source). Source-agnostic
         // so future typed sources reuse it; the typed projection is the child.
         "CREATE TABLE inventory_state ("
         "  agent_id     TEXT NOT NULL,"
         "  source       TEXT NOT NULL,"
         "  content_hash TEXT NOT NULL DEFAULT '',"
         "  first_seen   BIGINT NOT NULL,"
         "  last_seen    BIGINT NOT NULL,"
         "  PRIMARY KEY (agent_id, source));"
         // Typed child for source #1. Machine-scope only (no per-user/PII).
         "CREATE TABLE installed_software ("
         "  agent_id     TEXT NOT NULL,"
         "  name         TEXT NOT NULL,"
         "  version      TEXT NOT NULL DEFAULT '',"
         "  publisher    TEXT NOT NULL DEFAULT '',"
         "  install_date TEXT NOT NULL DEFAULT '');"
         "CREATE INDEX installed_software_agent_idx ON installed_software (agent_id);"
         "CREATE INDEX installed_software_name_idx  ON installed_software (name);"},
    };
    return kMigrations;
}

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// SHA-256 hex of a byte string (OpenSSL EVP one-shot). Kept local so the store
// has no dependency on AuthManager; identical bytes in → identical hex out as
// the agent's OpenSSL hash, which is what makes the hash-skip comparison work.
std::string sha256_hex(const std::string& in) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return {};
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

bool entry_less(const SoftwareEntry& a, const SoftwareEntry& b) {
    if (a.name != b.name)
        return a.name < b.name;
    if (a.version != b.version)
        return a.version < b.version;
    if (a.publisher != b.publisher)
        return a.publisher < b.publisher;
    return a.install_date < b.install_date;
}

bool entry_equal(const SoftwareEntry& a, const SoftwareEntry& b) {
    return a.name == b.name && a.version == b.version && a.publisher == b.publisher &&
           a.install_date == b.install_date;
}

// Sort + dedup in place so both the canonical hash and the persisted rows are
// order- and duplicate-independent (the 64-bit/WOW6432 hive can list a package
// twice; that is not a content change).
void normalize(std::vector<SoftwareEntry>& entries) {
    std::sort(entries.begin(), entries.end(), entry_less);
    entries.erase(std::unique(entries.begin(), entries.end(), entry_equal), entries.end());
}

} // namespace

std::string SoftwareInventoryStore::canonical_hash(std::vector<SoftwareEntry> entries) {
    normalize(entries);
    std::string canon;
    canon.reserve(entries.size() * 48);
    for (const auto& e : entries) {
        canon += e.name;
        canon += '\x1f';
        canon += e.version;
        canon += '\x1f';
        canon += e.publisher;
        canon += '\x1f';
        canon += e.install_date;
        canon += '\x1e';
    }
    return sha256_hex(canon);
}

SoftwareInventoryStore::SoftwareInventoryStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("SoftwareInventoryStore: no database connection at construction ({}) — "
                      "software inventory persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("SoftwareInventoryStore: schema migration failed — software inventory "
                      "persistence disabled");
        return;
    }
    open_ = true;
}

InventoryIngestOutcome SoftwareInventoryStore::apply_installed_software(
    std::string_view agent_id, std::string_view claimed_hash,
    const std::optional<std::vector<SoftwareEntry>>& rows, std::int64_t collected_at) {
    if (!open_ || agent_id.empty())
        return InventoryIngestOutcome::kError;

    const std::int64_t ts = collected_at > 0 ? collected_at : now_secs();

    // ── Hash-only report: compare against the stored (server-recomputed) hash ──
    if (!rows.has_value()) {
        auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
        if (!lease) {
            spdlog::debug("SoftwareInventoryStore: hash-only ingest skipped, no connection ({})",
                          pool_.last_error());
            return InventoryIngestOutcome::kError;
        }
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "SELECT content_hash FROM software_inventory_store.inventory_state "
            "WHERE agent_id = $1 AND source = $2",
            std::vector<std::string>{std::string(agent_id), kSourceInstalledSoftware});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::debug("SoftwareInventoryStore: hash lookup failed for agent={}: {}", agent_id,
                          PQerrorMessage(lease.get()));
            return InventoryIngestOutcome::kError;
        }
        if (PQntuples(res.get()) == 0)
            return InventoryIngestOutcome::kNeedFull; // cold cache: nothing to match
        const std::string stored = PQgetvalue(res.get(), 0, 0);
        if (stored != std::string(claimed_hash))
            return InventoryIngestOutcome::kNeedFull; // drifted: ask for the full list
        // Match — bump last_seen only (RETURNING carries the result, #1033).
        pg::PgResult upd = pg::exec_params(
            lease.get(),
            "UPDATE software_inventory_store.inventory_state SET last_seen = $3::bigint "
            "WHERE agent_id = $1 AND source = $2 RETURNING agent_id",
            std::vector<std::string>{std::string(agent_id), kSourceInstalledSoftware,
                                     std::to_string(ts)});
        if (upd.status() != PGRES_TUPLES_OK) {
            spdlog::debug("SoftwareInventoryStore: last_seen bump failed for agent={}: {}", agent_id,
                          PQerrorMessage(lease.get()));
            return InventoryIngestOutcome::kError;
        }
        return InventoryIngestOutcome::kTouched;
    }

    // ── Full payload: recompute the hash from the rows, replace atomically ─────
    std::vector<SoftwareEntry> entries = *rows;
    normalize(entries);
    const std::string server_hash = SoftwareInventoryStore::canonical_hash(entries);
    const std::string agent_id_s{agent_id};

    const bool ok = pool_.with_txn([&](PGconn* c) -> bool {
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM software_inventory_store.installed_software WHERE agent_id = $1",
            std::vector<std::string>{agent_id_s});
        if (del.status() != PGRES_COMMAND_OK)
            return false;
        for (const auto& e : entries) {
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO software_inventory_store.installed_software "
                "(agent_id, name, version, publisher, install_date) VALUES ($1,$2,$3,$4,$5)",
                std::vector<std::string>{agent_id_s, e.name, e.version, e.publisher,
                                         e.install_date});
            if (ins.status() != PGRES_COMMAND_OK)
                return false;
        }
        // Upsert parent: $4 seeds first_seen on insert; on conflict keep
        // first_seen, refresh content_hash + last_seen.
        pg::PgResult par = pg::exec_params(
            c,
            "INSERT INTO software_inventory_store.inventory_state "
            "(agent_id, source, content_hash, first_seen, last_seen) "
            "VALUES ($1, $2, $3, $4::bigint, $4::bigint) "
            "ON CONFLICT (agent_id, source) DO UPDATE SET "
            "  content_hash = EXCLUDED.content_hash, last_seen = EXCLUDED.last_seen "
            "RETURNING agent_id",
            std::vector<std::string>{agent_id_s, kSourceInstalledSoftware, server_hash,
                                     std::to_string(ts)});
        return par.status() == PGRES_TUPLES_OK;
    });
    if (!ok) {
        spdlog::debug("SoftwareInventoryStore: full ingest transaction failed for agent={}",
                      agent_id);
        return InventoryIngestOutcome::kError;
    }
    return InventoryIngestOutcome::kStored;
}

std::vector<SoftwareEntry> SoftwareInventoryStore::get_agent_software(std::string_view agent_id) {
    std::vector<SoftwareEntry> out;
    if (!open_ || agent_id.empty())
        return out;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::debug("SoftwareInventoryStore: get_agent_software skipped, no connection ({})",
                      pool_.last_error());
        return out;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT name, version, publisher, install_date "
        "FROM software_inventory_store.installed_software "
        "WHERE agent_id = $1 ORDER BY name, version LIMIT $2::bigint",
        std::vector<std::string>{std::string(agent_id), std::to_string(kFleetQueryRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("SoftwareInventoryStore: get_agent_software failed: {}",
                      PQerrorMessage(lease.get()));
        return out;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        SoftwareEntry e;
        e.name = PQgetvalue(res.get(), i, 0);
        e.version = PQgetvalue(res.get(), i, 1);
        e.publisher = PQgetvalue(res.get(), i, 2);
        e.install_date = PQgetvalue(res.get(), i, 3);
        out.push_back(std::move(e));
    }
    return out;
}

std::vector<SoftwareFleetRow> SoftwareInventoryStore::query_software(const SoftwareFleetQuery& q) {
    std::vector<SoftwareFleetRow> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::debug("SoftwareInventoryStore: query_software skipped, no connection ({})",
                      pool_.last_error());
        return out;
    }
    int limit = q.limit > 0 ? q.limit : 1000;
    if (limit > kFleetQueryRowCap)
        limit = kFleetQueryRowCap;
    const int offset = q.offset > 0 ? q.offset : 0;

    std::string sql =
        "SELECT agent_id, name, version, publisher, install_date "
        "FROM software_inventory_store.installed_software WHERE 1=1";
    std::vector<std::string> params;
    int p = 0;
    if (!q.agent_id.empty()) {
        sql += " AND agent_id = $" + std::to_string(++p);
        params.push_back(q.agent_id);
    }
    if (!q.name.empty()) {
        sql += " AND name = $" + std::to_string(++p);
        params.push_back(q.name);
    }
    sql += " ORDER BY name, agent_id LIMIT $" + std::to_string(++p) + "::bigint";
    params.push_back(std::to_string(limit));
    sql += " OFFSET $" + std::to_string(++p) + "::bigint";
    params.push_back(std::to_string(offset));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("SoftwareInventoryStore: query_software failed: {}",
                      PQerrorMessage(lease.get()));
        return out;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        SoftwareFleetRow row;
        row.agent_id = PQgetvalue(res.get(), i, 0);
        row.entry.name = PQgetvalue(res.get(), i, 1);
        row.entry.version = PQgetvalue(res.get(), i, 2);
        row.entry.publisher = PQgetvalue(res.get(), i, 3);
        row.entry.install_date = PQgetvalue(res.get(), i, 4);
        out.push_back(std::move(row));
    }
    return out;
}

void SoftwareInventoryStore::delete_agent(std::string_view agent_id) {
    if (!open_ || agent_id.empty())
        return;
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease)
        return;
    const std::string id{agent_id};
    pg::exec_params(lease.get(),
                    "DELETE FROM software_inventory_store.installed_software WHERE agent_id = $1",
                    std::vector<std::string>{id});
    pg::exec_params(lease.get(),
                    "DELETE FROM software_inventory_store.inventory_state WHERE agent_id = $1",
                    std::vector<std::string>{id});
}

} // namespace yuzu::server
