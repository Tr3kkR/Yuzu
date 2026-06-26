#include "software_inventory_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <system_error>
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
// The stale-agents freshness gauge runs on the metrics sweep, whose serial
// budget is shared with security-relevant revocation teardown (server.cpp). Use
// a SHORT acquire — well under the ingest/query timeouts — so a saturated pool
// (the condition this gauge instruments) can never delay teardown; a degrade
// returns nullopt and the caller leaves the gauge at its previous value.
constexpr std::chrono::milliseconds kStaleCountAcquireTimeout{250};
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
         // Composite (name, agent_id): the flagship fleet query is
         // `WHERE name=$1 ORDER BY name, agent_id LIMIT N`. A single-column (name)
         // index satisfies the equality but forces a sort by agent_id before LIMIT
         // over the whole matching set (perf S-1); the composite serves equality AND
         // order → ordered index scan + early LIMIT termination. Leading `name`
         // subsumes the old single-column index, so the index count is unchanged.
         "CREATE INDEX installed_software_name_idx  ON installed_software (name, agent_id);"},
        {2,
         // (source, last_seen) serves the freshness count (count_stale_agents):
         // `WHERE source=$1 AND last_seen<$2`. Without it the count is a full
         // seq-scan of inventory_state on every metrics sweep; with it the count
         // is an index range scan touching only the stale rows — stale-proportional,
         // not fleet-proportional. This bounds the count's execution time on the
         // metrics-sweep thread that also runs the revocation-teardown backstop
         // (CH-IN3/UP-2), complementing the per-statement statement_timeout cap in
         // count_stale_agents. Leading `source` matches the equality predicate;
         // `last_seen` serves the range.
         "CREATE INDEX inventory_state_source_lastseen_idx "
         "ON inventory_state (source, last_seen);"},
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

// ── Read-degrade observability (#1675) ───────────────────────────────────────
// The authoritative reads return nullopt on a store/pool/query degrade, but
// /readyz stays green under pure pool saturation (it trips only on connection
// failure, to avoid false LB evictions), so a read-degrade is otherwise
// dashboard-invisible. These reason labels match the alert rule
// (YuzuInventoryReadDegraded) and the docs.
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
// Sample the per-site WARN: log the 1st occurrence then every Nth. Under a
// sustained read outage at agentic fan-out (10k queries) an unsampled per-read
// WARN floods the log; the counter is the authoritative continuous signal, the
// log a sampled breadcrumb.
constexpr std::uint64_t kReadDegradeLogSample = 100;

// Bump the read-degrade counter (always) and return this site's running
// occurrence count; the caller logs a sampled subset via should_log_degrade().
std::uint64_t note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason,
                                std::atomic<std::uint64_t>& seen) {
    if (metrics)
        metrics->counter("yuzu_inventory_read_degrade_total", {{"reason", reason}}).increment();
    return seen.fetch_add(1, std::memory_order_relaxed) + 1;
}

bool should_log_degrade(std::uint64_t occurrence) {
    return occurrence == 1 || (occurrence % kReadDegradeLogSample) == 0;
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
            spdlog::warn("SoftwareInventoryStore: hash-only ingest skipped for agent={}, no "
                         "connection ({})",
                         agent_id, pool_.last_error());
            return InventoryIngestOutcome::kError;
        }
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "SELECT content_hash FROM software_inventory_store.inventory_state "
            "WHERE agent_id = $1 AND source = $2",
            std::vector<std::string>{std::string(agent_id), kSourceInstalledSoftware});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::warn("SoftwareInventoryStore: hash lookup failed for agent={}: {}", agent_id,
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
            spdlog::warn("SoftwareInventoryStore: last_seen bump failed for agent={}: {}", agent_id,
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

    const bool ok = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        // Serialise concurrent full-replaces for THIS agent. Without it, two
        // in-flight fulls for one agent_id under READ COMMITTED interleave: txn B's
        // DELETE cannot see txn A's freshly-inserted rows, so A's and B's rows both
        // survive and the parent content_hash matches neither (governance UP-IN2/3,
        // reachable when a slow ingest outlives the agent's 30s client deadline and
        // the scheduler retries). The lock is transaction-scoped (auto-released at
        // COMMIT/ROLLBACK); distinct agents hash to distinct keys, so steady-state
        // contention is nil. hashtextextended() gives a native 64-bit key (vs the
        // 32-bit hashtext) so cross-agent false contention is negligible (gov fjarvis
        // LOW); correctness never depended on it (the DELETE+INSERT is agent-scoped).
        //
        // Blocking (not try_) on purpose: same-agent contention is the rare
        // post-restart-retry case; the loser WAITS for the winner to commit, then
        // does its own clean replace → outcome="stored", no alert noise. A
        // try-lock would return kError on benign contention and trip
        // YuzuInventorySustainedIngestErrors (gov Gate-8 advisor — the error/alert
        // taxonomy is sre's gate, out of scope for this round). The wait is
        // transaction-scoped + bounded by the pool's statement_timeout; a distinct
        // "contended" outcome label is the right pool-hygiene follow-up.
        pg::PgResult lk = pg::exec_params(c, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                                          std::vector<std::string>{agent_id_s});
        if (lk.status() != PGRES_TUPLES_OK)
            return false;
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM software_inventory_store.installed_software WHERE agent_id = $1",
            std::vector<std::string>{agent_id_s});
        if (del.status() != PGRES_COMMAND_OK)
            return false;
        // Batched insert (#1664): one statement carrying the per-row columns as
        // four parallel text[] arrays — agent_id is the scalar $1, so the param
        // count is a constant 5 regardless of row count. A multi-row VALUES would
        // hit libpq's 65535-parameter ceiling at ~13k rows (5 params/row); up to
        // kMaxEntries (20k) rows arrive here. unnest() pairs the arrays
        // positionally and they are equal-length by construction. Collapsing up
        // to 20k single-row INSERTs into one statement shrinks the transaction's
        // connection-hold + statement_timeout exposure, which is the UP-IN4/5
        // pool-saturation blast (a need_full herd flipping healthy agents
        // touched→full) this change targets. Skip entirely when empty (a
        // legitimate empty inventory): the DELETE above already cleared the rows.
        if (!entries.empty()) {
            std::vector<std::string_view> names, versions, publishers, dates;
            names.reserve(entries.size());
            versions.reserve(entries.size());
            publishers.reserve(entries.size());
            dates.reserve(entries.size());
            for (const auto& e : entries) {
                names.emplace_back(e.name);
                versions.emplace_back(e.version);
                publishers.emplace_back(e.publisher);
                dates.emplace_back(e.install_date);
            }
            // push_back (not a braced init-list) so each large to_text_array
            // prvalue is MOVED into params, not copied — an init_list's backing
            // array is `const std::string[]`, forcing copies of these up-to-MB
            // literals on the hot path (cpp-expert).
            std::vector<std::string> params;
            params.reserve(5);
            params.push_back(agent_id_s);
            params.push_back(pg::to_text_array(names));
            params.push_back(pg::to_text_array(versions));
            params.push_back(pg::to_text_array(publishers));
            params.push_back(pg::to_text_array(dates));
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO software_inventory_store.installed_software "
                "(agent_id, name, version, publisher, install_date) "
                "SELECT $1, n, v, p, d "
                "FROM unnest($2::text[], $3::text[], $4::text[], $5::text[]) AS t(n, v, p, d)",
                params);
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
        spdlog::warn("SoftwareInventoryStore: full ingest transaction failed for agent={}",
                     agent_id);
        return InventoryIngestOutcome::kError;
    }
    return InventoryIngestOutcome::kStored;
}

std::optional<std::vector<SoftwareEntry>>
SoftwareInventoryStore::get_agent_software(std::string_view agent_id) {
    // AUTHORITATIVE read (ADR-0016 §7): a degrade returns nullopt, never a silent
    // empty. !open_ / no-lease / query-error are degrades; an empty agent_id is a
    // precondition miss (genuine empty, not a degrade).
    if (!open_) {
        static std::atomic<std::uint64_t> seen{0};
        const auto n = note_read_degrade(metrics_, kReasonStoreNotOpen, seen);
        if (should_log_degrade(n))
            spdlog::warn("SoftwareInventoryStore: get_agent_software degraded — store not open "
                         "(occurrence {})",
                         n);
        return std::nullopt;
    }
    std::vector<SoftwareEntry> out;
    if (agent_id.empty())
        return out;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static std::atomic<std::uint64_t> seen{0};
        const auto n = note_read_degrade(metrics_, kReasonPoolTimeout, seen);
        if (should_log_degrade(n))
            spdlog::warn("SoftwareInventoryStore: get_agent_software degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), n);
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT name, version, publisher, install_date "
        "FROM software_inventory_store.installed_software "
        "WHERE agent_id = $1 ORDER BY name, version LIMIT $2::bigint",
        std::vector<std::string>{std::string(agent_id), std::to_string(kFleetQueryRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        static std::atomic<std::uint64_t> seen{0};
        const auto occ = note_read_degrade(metrics_, kReasonQueryError, seen);
        if (should_log_degrade(occ))
            spdlog::warn("SoftwareInventoryStore: get_agent_software degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), occ);
        return std::nullopt;
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

std::optional<std::vector<SoftwareFleetRow>>
SoftwareInventoryStore::query_software(const SoftwareFleetQuery& q) {
    // AUTHORITATIVE read (ADR-0016 §7): a store/pool/query failure returns nullopt
    // (degraded), never a silent empty — a fleet vuln query must not read a PG hiccup
    // as "installed nowhere". An empty value = genuinely no matches.
    if (!open_) {
        static std::atomic<std::uint64_t> seen{0};
        const auto n = note_read_degrade(metrics_, kReasonStoreNotOpen, seen);
        if (should_log_degrade(n))
            spdlog::warn("SoftwareInventoryStore: query_software degraded — store not open "
                         "(occurrence {})",
                         n);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static std::atomic<std::uint64_t> seen{0};
        const auto n = note_read_degrade(metrics_, kReasonPoolTimeout, seen);
        if (should_log_degrade(n))
            spdlog::warn("SoftwareInventoryStore: query_software degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), n);
        return std::nullopt;
    }
    int limit = q.limit > 0 ? q.limit : 1000;
    if (limit > kFleetQueryRowCap)
        limit = kFleetQueryRowCap;

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
    // No OFFSET: offset-paging over a fleet table that mutates on sync cadence, with
    // the scope filter applied after LIMIT, yields unstable/duplicating windows
    // (gov consistency N1). Complete >cap collection is the keyset follow-up (#1634).

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK) {
        static std::atomic<std::uint64_t> seen{0};
        const auto occ = note_read_degrade(metrics_, kReasonQueryError, seen);
        if (should_log_degrade(occ))
            spdlog::warn("SoftwareInventoryStore: query_software degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), occ);
        return std::nullopt;
    }
    std::vector<SoftwareFleetRow> out;
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
    const std::string id{agent_id};
    // Both deletes in one transaction so an agent removal can't leave a parent
    // inventory_state row without its child rows, or vice versa (Gate 2 INFO).
    pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        pg::PgResult d1 = pg::exec_params(
            c, "DELETE FROM software_inventory_store.installed_software WHERE agent_id = $1",
            std::vector<std::string>{id});
        pg::PgResult d2 = pg::exec_params(
            c, "DELETE FROM software_inventory_store.inventory_state WHERE agent_id = $1",
            std::vector<std::string>{id});
        return d1.status() == PGRES_COMMAND_OK && d2.status() == PGRES_COMMAND_OK;
    });
}

std::optional<std::int64_t>
SoftwareInventoryStore::count_stale_agents(std::int64_t stale_before_secs) {
    if (!open_)
        return std::nullopt;
    std::optional<std::int64_t> result;
    // Run inside a txn so a `SET LOCAL statement_timeout` caps the count's
    // EXECUTION, not merely the lease acquire. This runs on the metrics-sweep
    // thread that next runs the revocation-teardown backstop (server.cpp), so a
    // bloated-table seq-scan must NOT be allowed to run to the pool's 30s
    // statement_timeout (CH-IN3/UP-2) — the 250ms acquire bounds only the wait
    // for a connection, never the query. SET LOCAL reverts at COMMIT/ROLLBACK; a
    // timeout makes the SELECT error → with_txn_for ROLLs back → nullopt → the
    // caller holds the gauge at its prior value. The (source,last_seen) index
    // (migration v2) keeps the steady-state plan an index scan so the cap is
    // never reached; the cap defends against bloat / plan regression.
    pool_.with_txn_for(kStaleCountAcquireTimeout, [&](PGconn* c) -> bool {
        pg::PgResult t = pg::exec_params(c, "SET LOCAL statement_timeout = '250ms'",
                                         std::vector<std::string>{});
        if (t.status() != PGRES_COMMAND_OK)
            return false;
        pg::PgResult res = pg::exec_params(
            c,
            "SELECT count(*) FROM software_inventory_store.inventory_state "
            "WHERE source = $1 AND last_seen < $2::bigint",
            std::vector<std::string>{kSourceInstalledSoftware, std::to_string(stale_before_secs)});
        if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
            return false;
        const char* txt = PQgetvalue(res.get(), 0, 0);
        const auto len = static_cast<std::size_t>(PQgetlength(res.get(), 0, 0));
        std::int64_t count = 0;
        if (std::from_chars(txt, txt + len, count).ec != std::errc{})
            return false;
        result = count;
        return true;
    });
    return result;
}

} // namespace yuzu::server
