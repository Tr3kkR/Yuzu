#include "software_licensing_store.hpp"

#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "software_licensing_store";

// Bounded acquires (ADR-0012 lease discipline). The ingest-path methods
// (stored_hash / touch / replace_agent_licenses / delete_agent) run on the
// gRPC thread (direct ReportInventory / gateway ProxyInventory) so they give
// up fast on a saturated pool — best-effort, the agent retries next cycle.
// Reads + the evaluator's posture/alert writes can wait a little longer.
constexpr std::chrono::milliseconds kIngestAcquireTimeout{500};
constexpr std::chrono::milliseconds kQueryAcquireTimeout{3000};
// The staleness count may run on a shared serial sweep (the sibling's
// metrics-sweep lesson, CH-IN3/UP-2): a SHORT acquire plus a per-statement
// execution cap so it can never stall that thread.
constexpr std::chrono::milliseconds kStaleCountAcquireTimeout{250};
// Hard ceilings on rows a single read will materialise, independent of any
// caller limit, so the store can never allocate an unbounded result set. The
// per-agent set is capped upstream by the R5 blob caps (≤ 10 000 records);
// the fleet-distinct and posture sets are one row per product — bounded.
constexpr int kAgentRowCap = 20000;
constexpr int kDistinctRowCap = 20000;
constexpr int kPostureRowCap = 20000;
// Rollup-input groups are bounded by products × states × distinct expiry
// dates — realistically thousands; the ceiling is deep headroom. Hitting it
// truncates a deterministic sorted tail, so the evaluator's rollup would be
// silently partial for the products sorting last — hence the warn on cap.
constexpr int kPostureInputRowCap = 50000;
// Alias fan-out for ONE product_key (the devices read's pair list) is small
// by construction — a registry product rarely has more than a handful of raw
// spellings per source.
constexpr std::size_t kDevicePairCap = 64;

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for
    // the migration transaction, so these tables land in
    // `software_licensing_store`. Runtime statements below schema-qualify
    // explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         // Per-agent sync parent (roadmap §7.2). content_hash is the RAW
         // received blob bytes' SHA-256, recomputed by the ingest seam and
         // persisted VERBATIM (ADR-0024 Decision 3 / roadmap D-2 — never
         // re-derived from parsed rows). effective_user_ref_mode is the
         // blob's config-stable `cfg|user_ref` record (roadmap D-10).
         // first_seen/last_seen are the SERVER receipt time (#1685 /
         // ADR-0016 clock-skew rule) — the C-10 staleness read keys on
         // last_seen, served by the index below.
         "CREATE TABLE agent_license_state ("
         "  agent_id                TEXT PRIMARY KEY,"
         "  content_hash            TEXT NOT NULL DEFAULT '',"
         "  effective_user_ref_mode TEXT NOT NULL DEFAULT '',"
         "  first_seen              BIGINT NOT NULL,"
         "  last_seen               BIGINT NOT NULL);"
         "CREATE INDEX agent_license_state_lastseen_idx ON agent_license_state (last_seen);"
         // Detected licence rows, replaced wholesale per agent on each stored
         // sync. Same-schema FK ON DELETE CASCADE onto the parent (cross-
         // schema FKs are banned — ADR-0024 Decision 4; within one store they
         // are the normal tool). confidence and exe_hints ship in migration
         // v1: hash-skip means a column added later would stay empty forever
         // on stable estates — confidence is how operators weight heuristic
         // rows (ADR-0024 Decisions 1/2/7); exe_hints is the R6 product↔exe
         // bridge. expiry_at is the agent-observed epoch (0 =
         // none); the partial index serves the evaluator's expiry sweep
         // without indexing the expiry-less majority.
         "CREATE TABLE agent_licenses ("
         "  id           BIGSERIAL PRIMARY KEY,"
         "  agent_id     TEXT NOT NULL REFERENCES agent_license_state (agent_id) ON DELETE CASCADE,"
         "  product      TEXT NOT NULL DEFAULT '',"
         "  vendor       TEXT NOT NULL DEFAULT '',"
         "  version      TEXT NOT NULL DEFAULT '',"
         "  license_type TEXT NOT NULL DEFAULT '',"
         "  state        TEXT NOT NULL DEFAULT '',"
         "  expiry_at    BIGINT NOT NULL DEFAULT 0,"
         "  channel      TEXT NOT NULL DEFAULT '',"
         "  key_hint     TEXT NOT NULL DEFAULT '',"
         "  detector     TEXT NOT NULL DEFAULT '',"
         "  confidence   TEXT NOT NULL DEFAULT '',"
         "  exe_hints    TEXT NOT NULL DEFAULT '',"
         "  user_scope   TEXT NOT NULL DEFAULT '',"
         "  user_ref     TEXT NOT NULL DEFAULT '',"
         "  collected_at BIGINT NOT NULL DEFAULT 0,"
         "  first_seen   BIGINT NOT NULL,"
         "  last_seen    BIGINT NOT NULL);"
         "CREATE INDEX agent_licenses_agent_idx  ON agent_licenses (agent_id);"
         "CREATE INDEX agent_licenses_state_idx  ON agent_licenses (state);"
         "CREATE INDEX agent_licenses_expiry_idx ON agent_licenses (expiry_at) "
         "WHERE expiry_at > 0;"
         // Evaluator posture rollup (roadmap §7.2), replaced atomically each
         // cycle. product_key is the SOFT registry norm_key ('' = the honest
         // unmatched bucket, roadmap R7); the per-effective-state counts
         // follow the closed §3.2 status vocabulary; refreshed_at is the
         // as-of stamp compliance surfaces carry (roadmap G-4). The PK is the
         // multi-instance correctness backstop behind the advisory lock in
         // replace_posture_rollup (the catalog-rollup ARCH-1 lesson).
         "CREATE TABLE license_posture_rollup ("
         "  product_key               TEXT PRIMARY KEY,"
         "  vendor                    TEXT NOT NULL DEFAULT '',"
         "  title                     TEXT NOT NULL DEFAULT '',"
         "  device_count              BIGINT NOT NULL DEFAULT 0,"
         "  install_count             BIGINT NOT NULL DEFAULT 0,"
         "  licensed_count            BIGINT NOT NULL DEFAULT 0,"
         "  subscription_active_count BIGINT NOT NULL DEFAULT 0,"
         "  trial_count               BIGINT NOT NULL DEFAULT 0,"
         "  grace_count               BIGINT NOT NULL DEFAULT 0,"
         "  expired_count             BIGINT NOT NULL DEFAULT 0,"
         "  unlicensed_count          BIGINT NOT NULL DEFAULT 0,"
         "  unknown_count             BIGINT NOT NULL DEFAULT 0,"
         "  next_expiry_at            BIGINT NOT NULL DEFAULT 0,"
         "  expiring_soon_count       BIGINT NOT NULL DEFAULT 0,"
         "  refreshed_at              BIGINT NOT NULL DEFAULT 0);"
         // Alert dedup state (ADR-0024 Decision 8). PK(product_key, kind) per
         // the §7.2 I-6 review note, adopted at implementation: `expired` and
         // `expiring` dedup independently per product. kind is a CLOSED
         // vocabulary — the CHECK keeps a typo'd kind from silently minting a
         // third dedup stream.
         "CREATE TABLE license_alert_state ("
         "  product_key   TEXT NOT NULL,"
         "  kind          TEXT NOT NULL CHECK (kind IN ('expired', 'expiring')),"
         "  fingerprint   TEXT NOT NULL DEFAULT '',"
         "  bucket        BIGINT NOT NULL DEFAULT 0,"
         "  last_fired_at BIGINT NOT NULL DEFAULT 0,"
         "  PRIMARY KEY (product_key, kind));"},
        {2,
         // First-class posture as-of stamp (roadmap G-4), seeded 0 ("never
         // evaluated") so an evaluated-but-empty estate (refreshed_at > 0,
         // zero rollup rows) is distinguishable from a never-run one — the
         // read promised at sle_routes.cpp's summary handler.
         // replace_posture_rollup stamps it in the SAME transaction as the
         // row replace, so keep-last-good covers the stamp too.
         "CREATE TABLE license_posture_meta ("
         "  singleton    BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),"
         "  refreshed_at BIGINT NOT NULL DEFAULT 0);"
         "INSERT INTO license_posture_meta (singleton, refreshed_at) VALUES (TRUE, 0);"},
    };
    return kMigrations;
}

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// ── Read-degrade observability (#1675 convention) ────────────────────────────
// Reason labels + sampled-WARN machinery mirror SoftwareInventoryStore /
// DeviceInventoryStore (a further per-store copy is the convention). The
// counter joins the SHARED read-degrade family with the wire-source label so
// the existing YuzuInventoryReadDegraded alert covers this source too.
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

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
                         {{"reason", reason}, {"source", "software_licensing"}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return {new_episode || (n % kReadDegradeLogSample) == 0, n};
}

// Parse a Postgres text-format integer cell into int64 (BIGINT columns and
// count(*) are text on the wire). Leaves 0 on a parse failure.
std::int64_t result_i64(const pg::PgResult& res, int row, int col) {
    const char* txt = PQgetvalue(res.get(), row, col);
    const auto len = static_cast<std::size_t>(PQgetlength(res.get(), row, col));
    std::int64_t v = 0;
    std::from_chars(txt, txt + len, v);
    return v;
}

// Shared SELECT column list for agent_licenses reads, order matched by
// fill_license_row (id/agent_id are query keys, not row fields).
constexpr const char* kLicenseCols =
    "product, vendor, version, license_type, state, expiry_at, channel, key_hint, "
    "detector, confidence, exe_hints, user_scope, user_ref, collected_at, first_seen, last_seen";

void fill_license_row(const pg::PgResult& res, int row, AgentLicenseRow& out) {
    out.product = PQgetvalue(res.get(), row, 0);
    out.vendor = PQgetvalue(res.get(), row, 1);
    out.version = PQgetvalue(res.get(), row, 2);
    out.license_type = PQgetvalue(res.get(), row, 3);
    out.state = PQgetvalue(res.get(), row, 4);
    out.expiry_at = result_i64(res, row, 5);
    out.channel = PQgetvalue(res.get(), row, 6);
    out.key_hint = PQgetvalue(res.get(), row, 7);
    out.detector = PQgetvalue(res.get(), row, 8);
    out.confidence = PQgetvalue(res.get(), row, 9);
    out.exe_hints = PQgetvalue(res.get(), row, 10);
    out.user_scope = PQgetvalue(res.get(), row, 11);
    out.user_ref = PQgetvalue(res.get(), row, 12);
    out.collected_at = result_i64(res, row, 13);
    out.first_seen = result_i64(res, row, 14);
    out.last_seen = result_i64(res, row, 15);
}

constexpr const char* kPostureCols =
    "product_key, vendor, title, device_count, install_count, licensed_count, "
    "subscription_active_count, trial_count, grace_count, expired_count, unlicensed_count, "
    "unknown_count, next_expiry_at, expiring_soon_count, refreshed_at";

void fill_posture_row(const pg::PgResult& res, int row, LicensePostureRow& out) {
    out.product_key = PQgetvalue(res.get(), row, 0);
    out.vendor = PQgetvalue(res.get(), row, 1);
    out.title = PQgetvalue(res.get(), row, 2);
    out.device_count = result_i64(res, row, 3);
    out.install_count = result_i64(res, row, 4);
    out.licensed_count = result_i64(res, row, 5);
    out.subscription_active_count = result_i64(res, row, 6);
    out.trial_count = result_i64(res, row, 7);
    out.grace_count = result_i64(res, row, 8);
    out.expired_count = result_i64(res, row, 9);
    out.unlicensed_count = result_i64(res, row, 10);
    out.unknown_count = result_i64(res, row, 11);
    out.next_expiry_at = result_i64(res, row, 12);
    out.expiring_soon_count = result_i64(res, row, 13);
    out.refreshed_at = result_i64(res, row, 14);
}

} // namespace

SoftwareLicensingStore::SoftwareLicensingStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("SoftwareLicensingStore: no database connection at construction ({}) — "
                      "software licensing persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("SoftwareLicensingStore: schema migration failed — software licensing "
                      "persistence disabled");
        return;
    }
    open_ = true;
}

std::expected<std::optional<std::string>, LicensingReadError>
SoftwareLicensingStore::stored_hash(std::string_view agent_id) {
    // Ingest-path helper (the seam's hash-skip compare): a degrade maps to
    // kError at the seam, so plain warn logging suffices here (the sibling
    // hash-only precedent) — the samplers guard the fan-out read surfaces.
    if (!open_ || agent_id.empty())
        return std::unexpected(LicensingReadError::kDegraded);
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease) {
        spdlog::warn("SoftwareLicensingStore: stored_hash skipped for agent={}, no connection ({})",
                     agent_id, pool_.last_error());
        return std::unexpected(LicensingReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT content_hash FROM software_licensing_store.agent_license_state "
        "WHERE agent_id = $1",
        std::vector<std::string>{std::string(agent_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("SoftwareLicensingStore: stored_hash failed for agent={}: {}", agent_id,
                     PQerrorMessage(lease.get()));
        return std::unexpected(LicensingReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<std::string>{}; // cold cache → the seam answers need_full
    return std::optional<std::string>{PQgetvalue(res.get(), 0, 0)};
}

bool SoftwareLicensingStore::touch(std::string_view agent_id) {
    if (!open_ || agent_id.empty())
        return false;
    auto lease = pool_.try_acquire_for(kIngestAcquireTimeout);
    if (!lease) {
        spdlog::warn("SoftwareLicensingStore: touch skipped for agent={}, no connection ({})",
                     agent_id, pool_.last_error());
        return false;
    }
    // last_seen is the SERVER receipt time (#1685) — never an agent-supplied
    // stamp. RETURNING carries the row-hit result (#1033): zero tuples = the
    // state row is missing (a touch on a cold cache is a caller sequencing
    // bug; the seam should have answered need_full off stored_hash).
    pg::PgResult upd = pg::exec_params(
        lease.get(),
        "UPDATE software_licensing_store.agent_license_state SET last_seen = $2::bigint "
        "WHERE agent_id = $1 RETURNING agent_id",
        std::vector<std::string>{std::string(agent_id), std::to_string(now_secs())});
    if (upd.status() != PGRES_TUPLES_OK || PQntuples(upd.get()) != 1) {
        spdlog::warn("SoftwareLicensingStore: touch failed for agent={}: {}", agent_id,
                     PQerrorMessage(lease.get()));
        return false;
    }
    return true;
}

bool SoftwareLicensingStore::replace_agent_licenses(std::string_view agent_id,
                                                    const std::vector<AgentLicenseRow>& rows,
                                                    std::string_view content_hash,
                                                    std::string_view effective_user_ref_mode) {
    if (!open_ || agent_id.empty())
        return false;
    // first_seen/last_seen are the SERVER receipt time on the state row AND
    // the child rows (#1685); the agent's collected_at is persisted as data,
    // never as a freshness stamp.
    const std::int64_t ts = now_secs();
    const std::string agent_id_s{agent_id};

    const bool ok = pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        // Serialise concurrent full-replaces for THIS agent (the software-
        // inventory UP-IN2/3 lesson): two in-flight fulls under READ COMMITTED
        // interleave (B's DELETE cannot see A's fresh rows) and both row sets
        // survive with a parent hash matching neither. Blocking (not try_) on
        // purpose — the loser waits, then does its own clean replace; bounded
        // by the pool's statement_timeout. The key is salted with the store
        // name so a same-agent replace in ANOTHER store's tables never
        // contends (advisory lock keys are database-wide, not schema-scoped).
        pg::PgResult lk = pg::exec_params(
            c, "SELECT pg_advisory_xact_lock(hashtextextended('software_licensing:' || $1, 0))",
            std::vector<std::string>{agent_id_s});
        if (lk.status() != PGRES_TUPLES_OK)
            return false;
        // Parent upsert FIRST (the children's FK targets it): persist the
        // seam-recomputed raw-blob hash VERBATIM + the effective user-ref
        // mode; keep first_seen on conflict, refresh the rest.
        pg::PgResult par = pg::exec_params(
            c,
            "INSERT INTO software_licensing_store.agent_license_state "
            "(agent_id, content_hash, effective_user_ref_mode, first_seen, last_seen) "
            "VALUES ($1, $2, $3, $4::bigint, $4::bigint) "
            "ON CONFLICT (agent_id) DO UPDATE SET "
            "  content_hash = EXCLUDED.content_hash, "
            "  effective_user_ref_mode = EXCLUDED.effective_user_ref_mode, "
            "  last_seen = EXCLUDED.last_seen "
            "RETURNING agent_id",
            std::vector<std::string>{agent_id_s, std::string(content_hash),
                                     std::string(effective_user_ref_mode), std::to_string(ts)});
        if (par.status() != PGRES_TUPLES_OK)
            return false;
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM software_licensing_store.agent_licenses WHERE agent_id = $1",
            std::vector<std::string>{agent_id_s});
        if (del.status() != PGRES_COMMAND_OK)
            return false;
        // Batched insert (#1664 pattern): one statement, per-row columns as
        // parallel arrays, so the parameter count is a constant 16 regardless
        // of row count (up to the R5 10k-record cap arrives here). Skip when
        // empty — a legitimate replace-to-empty; the DELETE above cleared the
        // rows.
        if (!rows.empty()) {
            // 12 text columns as string_view arrays over the caller's rows;
            // the 2 BIGINT columns need owned decimal strings first.
            std::vector<std::string_view> text_cols[12];
            for (auto& col : text_cols)
                col.reserve(rows.size());
            std::vector<std::string> expiry_strs;
            std::vector<std::string> collected_strs;
            expiry_strs.reserve(rows.size());
            collected_strs.reserve(rows.size());
            for (const auto& r : rows) {
                text_cols[0].emplace_back(r.product);
                text_cols[1].emplace_back(r.vendor);
                text_cols[2].emplace_back(r.version);
                text_cols[3].emplace_back(r.license_type);
                text_cols[4].emplace_back(r.state);
                text_cols[5].emplace_back(r.channel);
                text_cols[6].emplace_back(r.key_hint);
                text_cols[7].emplace_back(r.detector);
                text_cols[8].emplace_back(r.confidence);
                text_cols[9].emplace_back(r.exe_hints);
                text_cols[10].emplace_back(r.user_scope);
                text_cols[11].emplace_back(r.user_ref);
                expiry_strs.push_back(std::to_string(r.expiry_at));
                collected_strs.push_back(std::to_string(r.collected_at));
            }
            std::vector<std::string_view> expiry_views(expiry_strs.begin(), expiry_strs.end());
            std::vector<std::string_view> collected_views(collected_strs.begin(),
                                                          collected_strs.end());
            // push_back (not a braced init-list) so each to_text_array prvalue
            // is MOVED into params (the sibling's cpp-expert note). Constant
            // 16 params: $1 agent_id, $2 receipt time, $3..$16 arrays.
            std::vector<std::string> params;
            params.reserve(16);
            params.push_back(agent_id_s);
            params.push_back(std::to_string(ts));
            for (const auto& col : text_cols)
                params.push_back(pg::to_text_array(col));
            params.push_back(pg::to_text_array(expiry_views));
            params.push_back(pg::to_text_array(collected_views));
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO software_licensing_store.agent_licenses "
                "(agent_id, product, vendor, version, license_type, state, channel, key_hint, "
                "detector, confidence, exe_hints, user_scope, user_ref, expiry_at, collected_at, "
                "first_seen, last_seen) "
                "SELECT $1, p, v, ver, lt, st, ch, kh, det, conf, eh, us, ur, ex, ca, "
                "$2::bigint, $2::bigint "
                "FROM unnest($3::text[], $4::text[], $5::text[], $6::text[], $7::text[], "
                "$8::text[], $9::text[], $10::text[], $11::text[], $12::text[], $13::text[], "
                "$14::text[], $15::bigint[], $16::bigint[]) "
                "AS t(p, v, ver, lt, st, ch, kh, det, conf, eh, us, ur, ex, ca)",
                params);
            if (ins.status() != PGRES_COMMAND_OK)
                return false;
        }
        return true;
    });
    if (!ok)
        spdlog::warn("SoftwareLicensingStore: replace transaction failed for agent={}", agent_id);
    return ok;
}

std::optional<std::vector<AgentLicenseRow>>
SoftwareLicensingStore::agent_licenses(std::string_view agent_id) {
    // AUTHORITATIVE read (ADR-0024 Decision 4): a degrade returns nullopt,
    // never a silent empty — an empty licence drill on a degrade would read as
    // "nothing detected". An empty agent_id is a precondition miss → empty
    // value.
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: agent_licenses degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    std::vector<AgentLicenseRow> out;
    if (agent_id.empty())
        return out;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: agent_licenses degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    const std::string sql = std::string("SELECT ") + kLicenseCols +
                            " FROM software_licensing_store.agent_licenses "
                            "WHERE agent_id = $1 ORDER BY product, vendor, version, id "
                            "LIMIT $2::bigint";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{std::string(agent_id), std::to_string(kAgentRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: agent_licenses degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        AgentLicenseRow r;
        fill_license_row(res, i, r);
        out.push_back(std::move(r));
    }
    return out;
}

std::expected<std::optional<std::string>, LicensingReadError>
SoftwareLicensingStore::effective_user_ref_mode(std::string_view agent_id) {
    // Drill read (roadmap D-10 read-back), same authoritative posture as the
    // sibling single-row reads: kDegraded on failure, a value holding nullopt
    // when the agent never synced this source.
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: effective_user_ref_mode degraded — store not "
                         "open (occurrence {})",
                         d.occurrence);
        return std::unexpected(LicensingReadError::kDegraded);
    }
    if (agent_id.empty())
        return std::optional<std::string>{}; // precondition miss → absent, not a degrade
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: effective_user_ref_mode degraded — no "
                         "connection ({}) (occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::unexpected(LicensingReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT effective_user_ref_mode FROM software_licensing_store.agent_license_state "
        "WHERE agent_id = $1",
        std::vector<std::string>{std::string(agent_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: effective_user_ref_mode degraded — query "
                         "failed: {} (occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::unexpected(LicensingReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<std::string>{}; // agent never synced this source
    return std::optional<std::string>{PQgetvalue(res.get(), 0, 0)};
}

std::optional<std::vector<DetectedProduct>> SoftwareLicensingStore::distinct_products() {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: distinct_products degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: distinct_products degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT DISTINCT product, vendor FROM software_licensing_store.agent_licenses "
        "ORDER BY product, vendor LIMIT $1::bigint",
        std::vector<std::string>{std::to_string(kDistinctRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: distinct_products degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    std::vector<DetectedProduct> out;
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        DetectedProduct p;
        p.product = PQgetvalue(res.get(), i, 0);
        p.vendor = PQgetvalue(res.get(), i, 1);
        out.push_back(std::move(p));
    }
    return out;
}

std::optional<std::vector<AgentLicenseDeviceRow>>
SoftwareLicensingStore::license_devices(const std::vector<DetectedProduct>& pairs, int limit) {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: license_devices degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    std::vector<AgentLicenseDeviceRow> out;
    if (pairs.empty())
        return out; // no alias pairs → genuinely no devices, not a degrade
    // Deterministic truncation of an oversized pair list (see kDevicePairCap
    // rationale): the caller passes the registry's alias order.
    const std::size_t n_pairs = std::min(pairs.size(), kDevicePairCap);
    if (n_pairs < pairs.size())
        spdlog::warn("SoftwareLicensingStore: license_devices pair list truncated ({} -> {})",
                     pairs.size(), n_pairs);
    const int row_cap = std::clamp(limit, 1, kAgentRowCap);
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: license_devices degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    // Pair list as parallel text arrays (#1664 pattern): constant 3 params
    // regardless of pair count.
    std::vector<std::string_view> prod_views;
    std::vector<std::string_view> vend_views;
    prod_views.reserve(n_pairs);
    vend_views.reserve(n_pairs);
    for (std::size_t i = 0; i < n_pairs; ++i) {
        prod_views.emplace_back(pairs[i].product);
        vend_views.emplace_back(pairs[i].vendor);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT agent_id, state, expiry_at FROM software_licensing_store.agent_licenses "
        "WHERE (product, vendor) IN "
        "(SELECT p, v FROM unnest($1::text[], $2::text[]) AS t(p, v)) "
        "ORDER BY agent_id, expiry_at, id LIMIT $3::bigint",
        std::vector<std::string>{pg::to_text_array(prod_views), pg::to_text_array(vend_views),
                                 std::to_string(row_cap)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: license_devices degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        AgentLicenseDeviceRow r;
        r.agent_id = PQgetvalue(res.get(), i, 0);
        r.state = PQgetvalue(res.get(), i, 1);
        r.expiry_at = result_i64(res, i, 2);
        out.push_back(std::move(r));
    }
    return out;
}

std::optional<LicensePostureInputs> SoftwareLicensingStore::posture_inputs() {
    // The evaluator rollup pass's ONE authoritative input read (two grouped
    // aggregates on one lease). Any failure → nullopt → the evaluator skips
    // the cycle (F4 keep-last-good) — never a partial rollup.
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: posture_inputs degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: posture_inputs degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    LicensePostureInputs inputs;
    pg::PgResult groups = pg::exec_params(
        lease.get(),
        "SELECT product, vendor, state, license_type, expiry_at, "
        "count(*), count(DISTINCT agent_id) "
        "FROM software_licensing_store.agent_licenses "
        "GROUP BY product, vendor, state, license_type, expiry_at "
        "ORDER BY product, vendor, state, license_type, expiry_at LIMIT $1::bigint",
        std::vector<std::string>{std::to_string(kPostureInputRowCap)});
    if (groups.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: posture_inputs degraded — group query failed: "
                         "{} (occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int gn = PQntuples(groups.get());
    if (gn == kPostureInputRowCap)
        spdlog::warn("SoftwareLicensingStore: posture_inputs hit the group cap ({}) — the "
                     "posture rollup will be PARTIAL for products sorting last",
                     kPostureInputRowCap);
    inputs.groups.reserve(static_cast<std::size_t>(gn));
    for (int i = 0; i < gn; ++i) {
        LicensePostureInputGroup g;
        g.product = PQgetvalue(groups.get(), i, 0);
        g.vendor = PQgetvalue(groups.get(), i, 1);
        g.state = PQgetvalue(groups.get(), i, 2);
        g.license_type = PQgetvalue(groups.get(), i, 3);
        g.expiry_at = result_i64(groups, i, 4);
        g.row_count = result_i64(groups, i, 5);
        g.device_count = result_i64(groups, i, 6);
        inputs.groups.push_back(std::move(g));
    }
    pg::PgResult pairs = pg::exec_params(
        lease.get(),
        "SELECT product, vendor, count(DISTINCT agent_id) "
        "FROM software_licensing_store.agent_licenses "
        "GROUP BY product, vendor ORDER BY product, vendor LIMIT $1::bigint",
        std::vector<std::string>{std::to_string(kPostureInputRowCap)});
    if (pairs.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: posture_inputs degraded — pair query failed: "
                         "{} (occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int pn = PQntuples(pairs.get());
    inputs.pair_device_counts.reserve(static_cast<std::size_t>(pn));
    for (int i = 0; i < pn; ++i) {
        LicensePairDeviceCount p;
        p.product = PQgetvalue(pairs.get(), i, 0);
        p.vendor = PQgetvalue(pairs.get(), i, 1);
        p.device_count = result_i64(pairs, i, 2);
        inputs.pair_device_counts.push_back(std::move(p));
    }
    return inputs;
}

bool SoftwareLicensingStore::replace_posture_rollup(const std::vector<LicensePostureRow>& rows,
                                                    std::int64_t refreshed_at) {
    if (!open_)
        return false;
    // ONE transaction: atomic replace of the whole rollup. KEEP-LAST-GOOD: any
    // lease/SQL failure returns false → with_txn_for ROLLs back → the prior
    // rollup + its as-of stamp survive untouched (the stamp visibly ages —
    // evaluator staleness stays observable, ADR-0024 Decision 7).
    return pool_.with_txn_for(kQueryAcquireTimeout, [&](PGconn* c) -> bool {
        // Cluster-wide serialisation (the catalog-rollup ARCH-1 lesson): two
        // server instances sharing one Postgres both run evaluators; a racing
        // DELETE+INSERT under READ COMMITTED can leave duplicate rows.
        // Blocking (not try_): each instance carries its own freshly derived
        // rows, so the loser waits and applies its own replace (last writer
        // wins — both derive from the same tables); the wait is transaction-
        // scoped and bounded by the pool's statement_timeout. The PK is the
        // belt-and-braces backstop behind the lock.
        pg::PgResult lk = pg::exec_params(
            c, "SELECT pg_advisory_xact_lock(hashtextextended('sle_license_posture_rollup', 0))",
            std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK)
            return false;
        // Stamp the singleton meta row in the SAME transaction (roadmap G-4):
        // a rollback rolls the stamp back with the rows, and an empty estate
        // still records "evaluated at <refreshed_at>". RETURNING carries the
        // row-hit result — a missing singleton (broken migration) fails the
        // replace rather than silently un-stamping.
        pg::PgResult meta = pg::exec_params(
            c,
            "UPDATE software_licensing_store.license_posture_meta "
            "SET refreshed_at = $1::bigint RETURNING singleton",
            std::vector<std::string>{std::to_string(refreshed_at)});
        if (meta.status() != PGRES_TUPLES_OK || PQntuples(meta.get()) != 1)
            return false;
        if (pg::exec_params(c, "DELETE FROM software_licensing_store.license_posture_rollup",
                            std::vector<std::string>{})
                .status() != PGRES_COMMAND_OK)
            return false;
        if (rows.empty())
            return true; // an empty estate replaces to an empty rollup
        // Parallel-array batch insert (#1664 pattern): constant 15 params —
        // $1 the shared as-of stamp, $2..$15 the per-column arrays.
        std::vector<std::string_view> text_cols[3];
        for (auto& col : text_cols)
            col.reserve(rows.size());
        std::vector<std::string> num_strs[11];
        for (auto& col : num_strs)
            col.reserve(rows.size());
        for (const auto& r : rows) {
            text_cols[0].emplace_back(r.product_key);
            text_cols[1].emplace_back(r.vendor);
            text_cols[2].emplace_back(r.title);
            num_strs[0].push_back(std::to_string(r.device_count));
            num_strs[1].push_back(std::to_string(r.install_count));
            num_strs[2].push_back(std::to_string(r.licensed_count));
            num_strs[3].push_back(std::to_string(r.subscription_active_count));
            num_strs[4].push_back(std::to_string(r.trial_count));
            num_strs[5].push_back(std::to_string(r.grace_count));
            num_strs[6].push_back(std::to_string(r.expired_count));
            num_strs[7].push_back(std::to_string(r.unlicensed_count));
            num_strs[8].push_back(std::to_string(r.unknown_count));
            num_strs[9].push_back(std::to_string(r.next_expiry_at));
            num_strs[10].push_back(std::to_string(r.expiring_soon_count));
        }
        std::vector<std::string> params;
        params.reserve(15);
        params.push_back(std::to_string(refreshed_at));
        for (const auto& col : text_cols)
            params.push_back(pg::to_text_array(col));
        for (const auto& col : num_strs) {
            std::vector<std::string_view> views(col.begin(), col.end());
            params.push_back(pg::to_text_array(views));
        }
        pg::PgResult ins = pg::exec_params(
            c,
            "INSERT INTO software_licensing_store.license_posture_rollup "
            "(product_key, vendor, title, device_count, install_count, licensed_count, "
            "subscription_active_count, trial_count, grace_count, expired_count, "
            "unlicensed_count, unknown_count, next_expiry_at, expiring_soon_count, refreshed_at) "
            "SELECT pk, ven, ti, dc, ic, lc, sac, tc, gc, ec, ulc, uc, nea, esc, $1::bigint "
            "FROM unnest($2::text[], $3::text[], $4::text[], $5::bigint[], $6::bigint[], "
            "$7::bigint[], $8::bigint[], $9::bigint[], $10::bigint[], $11::bigint[], "
            "$12::bigint[], $13::bigint[], $14::bigint[], $15::bigint[]) "
            "AS t(pk, ven, ti, dc, ic, lc, sac, tc, gc, ec, ulc, uc, nea, esc)",
            params);
        return ins.status() == PGRES_COMMAND_OK;
    });
}

std::optional<std::vector<LicensePostureRow>> SoftwareLicensingStore::posture_rollup() {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: posture_rollup degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: posture_rollup degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    const std::string sql = std::string("SELECT ") + kPostureCols +
                            " FROM software_licensing_store.license_posture_rollup "
                            "ORDER BY device_count DESC, product_key LIMIT $1::bigint";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{std::to_string(kPostureRowCap)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: posture_rollup degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    const int n = PQntuples(res.get());
    std::vector<LicensePostureRow> out;
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        LicensePostureRow r;
        fill_posture_row(res, i, r);
        out.push_back(std::move(r));
    }
    return out;
}

std::optional<std::int64_t> SoftwareLicensingStore::posture_refreshed_at() {
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: posture_refreshed_at degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: posture_refreshed_at degraded — no connection "
                         "({}) (occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::nullopt;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT refreshed_at FROM software_licensing_store.license_posture_meta",
        std::vector<std::string>{});
    // The migration seeds the singleton, so zero rows = a broken schema, not
    // "never evaluated" — that is a degrade (never a false 0/never-run).
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: posture_refreshed_at degraded — query failed "
                         "or singleton missing: {} (occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::nullopt;
    }
    return result_i64(res, 0, 0);
}

std::expected<std::optional<LicenseAlertState>, LicensingReadError>
SoftwareLicensingStore::alert_state(std::string_view product_key, std::string_view kind) {
    // AUTHORITATIVE read: the evaluator must NOT read a degrade as "never
    // fired" — that would re-fire the alert on every degraded cycle, exactly
    // the spam Decision 8's dedup exists to prevent.
    if (!open_) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonStoreNotOpen, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: alert_state degraded — store not open "
                         "(occurrence {})",
                         d.occurrence);
        return std::unexpected(LicensingReadError::kDegraded);
    }
    if (product_key.empty() || kind.empty())
        return std::optional<LicenseAlertState>{}; // precondition miss → absent, not a degrade
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonPoolTimeout, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: alert_state degraded — no connection ({}) "
                         "(occurrence {})",
                         pool_.last_error(), d.occurrence);
        return std::unexpected(LicensingReadError::kDegraded);
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT fingerprint, bucket, last_fired_at "
        "FROM software_licensing_store.license_alert_state "
        "WHERE product_key = $1 AND kind = $2",
        std::vector<std::string>{std::string(product_key), std::string(kind)});
    if (res.status() != PGRES_TUPLES_OK) {
        static DegradeSampler sampler;
        if (const auto d = note_read_degrade(metrics_, kReasonQueryError, sampler); d.should_log)
            spdlog::warn("SoftwareLicensingStore: alert_state degraded — query failed: {} "
                         "(occurrence {})",
                         PQerrorMessage(lease.get()), d.occurrence);
        return std::unexpected(LicensingReadError::kDegraded);
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<LicenseAlertState>{}; // never fired (or dedup state lost) → G-3
    LicenseAlertState out;
    out.fingerprint = PQgetvalue(res.get(), 0, 0);
    out.bucket = result_i64(res, 0, 1);
    out.last_fired_at = result_i64(res, 0, 2);
    return std::optional<LicenseAlertState>{std::move(out)};
}

bool SoftwareLicensingStore::upsert_alert_state(std::string_view product_key,
                                                std::string_view kind,
                                                std::string_view fingerprint, std::int64_t bucket,
                                                std::int64_t last_fired_at) {
    if (!open_ || product_key.empty() || kind.empty())
        return false;
    auto lease = pool_.try_acquire_for(kQueryAcquireTimeout);
    if (!lease) {
        spdlog::warn("SoftwareLicensingStore: upsert_alert_state skipped for ({}, {}), no "
                     "connection ({})",
                     product_key, kind, pool_.last_error());
        return false;
    }
    // A kind outside the closed vocabulary fails the schema CHECK and lands in
    // the error branch (fail-soft, never throws).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO software_licensing_store.license_alert_state "
        "(product_key, kind, fingerprint, bucket, last_fired_at) "
        "VALUES ($1, $2, $3, $4::bigint, $5::bigint) "
        "ON CONFLICT (product_key, kind) DO UPDATE SET "
        "  fingerprint = EXCLUDED.fingerprint, bucket = EXCLUDED.bucket, "
        "  last_fired_at = EXCLUDED.last_fired_at "
        "RETURNING product_key",
        std::vector<std::string>{std::string(product_key), std::string(kind),
                                 std::string(fingerprint), std::to_string(bucket),
                                 std::to_string(last_fired_at)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
        spdlog::warn("SoftwareLicensingStore: upsert_alert_state failed for ({}, {}): {}",
                     product_key, kind, PQerrorMessage(lease.get()));
        return false;
    }
    return true;
}

void SoftwareLicensingStore::delete_agent(std::string_view agent_id) {
    if (!open_ || agent_id.empty())
        return;
    const std::string id{agent_id};
    // Both deletes in one transaction so an agent removal can't leave a parent
    // state row without its child rows or vice versa (the sibling's Gate-2
    // rationale). The child DELETE is explicit even though the FK cascades —
    // the intent stays visible and survives an FK refactor. Best-effort: a
    // failure is logged by with_txn_for's caller contract; the next
    // decommission pass self-heals.
    pool_.with_txn_for(kIngestAcquireTimeout, [&](PGconn* c) -> bool {
        // Take the SAME per-agent advisory lock replace_agent_licenses holds,
        // with the IDENTICAL key derivation ('software_licensing:' || agent_id).
        // Without it a decommission and an in-flight full-replace ingest for THIS
        // agent interleave under READ COMMITTED: the ingest's INSERT can land
        // AFTER the delete's DELETE, resurrecting the just-erased user_ref PII and
        // breaking the ADR-0024 Decision-11 erasure guarantee. Serialising the two
        // on this lock closes that race — the loser waits, then runs cleanly.
        // Blocking (not try_) on purpose, bounded by the pool's lock_timeout.
        pg::PgResult lk = pg::exec_params(
            c, "SELECT pg_advisory_xact_lock(hashtextextended('software_licensing:' || $1, 0))",
            std::vector<std::string>{id});
        if (lk.status() != PGRES_TUPLES_OK)
            return false;
        pg::PgResult d1 = pg::exec_params(
            c, "DELETE FROM software_licensing_store.agent_licenses WHERE agent_id = $1",
            std::vector<std::string>{id});
        pg::PgResult d2 = pg::exec_params(
            c, "DELETE FROM software_licensing_store.agent_license_state WHERE agent_id = $1",
            std::vector<std::string>{id});
        return d1.status() == PGRES_COMMAND_OK && d2.status() == PGRES_COMMAND_OK;
    });
}

std::optional<std::int64_t>
SoftwareLicensingStore::count_stale_agents(std::int64_t stale_before_secs) {
    if (!open_)
        return std::nullopt;
    std::optional<std::int64_t> result;
    // Run inside a txn so `SET LOCAL statement_timeout` caps the count's
    // EXECUTION, not merely the lease acquire (the sibling CH-IN3/UP-2
    // lesson): a caller on a shared serial sweep must never wait out the
    // pool's 30s default behind a bloated-table scan. The last_seen index
    // (migration v1) keeps the steady-state plan an index range scan; the cap
    // defends against bloat / plan regression. A timeout errors the SELECT →
    // ROLLBACK → nullopt → the caller holds its previous value.
    pool_.with_txn_for(kStaleCountAcquireTimeout, [&](PGconn* c) -> bool {
        pg::PgResult t = pg::exec_params(c, "SET LOCAL statement_timeout = '250ms'",
                                         std::vector<std::string>{});
        if (t.status() != PGRES_COMMAND_OK)
            return false;
        pg::PgResult res =
            pg::exec_params(c,
                            "SELECT count(*) FROM software_licensing_store.agent_license_state "
                            "WHERE last_seen < $1::bigint",
                            std::vector<std::string>{std::to_string(stale_before_secs)});
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
