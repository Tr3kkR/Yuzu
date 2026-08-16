#include "software_deployment_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"

#include <libpq-fe.h>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <random>
#include <string_view>
#include <unordered_set>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "software_deployment_store";

// Authoritative store (ADR-0012 §1) — operator-initiated deployment intent,
// no in-memory layer behind it. Not a hot path (operator-driven, low
// frequency), so budgets are generous relative to a heartbeat-path store's,
// same values as DeploymentStore/ADR-0043.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};

// gov UP-5 precedent: bounded materialization regardless of table growth —
// an operator convenience list, not a paged feed.
constexpr int kListRowCap = 10000;

// Sentinel fingerprint for "this replica's legacy file is absent, or present
// but holds no software_packages table/rows worth migrating" — see
// migrate_from_sqlite's doc comment. Mirrors DeploymentStore's
// kSourcelessFingerprint (deployment_store.cpp).
constexpr const char* kSourcelessFingerprint = "sourceless";

std::int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

int to_int(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<int>(std::strtol(s, nullptr, 10));
}

// Only used against legacy SQLite text columns (may be nullptr).
const char* safe(const char* p) {
    return p ? p : "";
}

std::string sqlite_text(sqlite3_stmt* s, int col) {
    return safe(reinterpret_cast<const char*>(sqlite3_column_text(s, col)));
}

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

// Length-prefixed field encoding (`<byte-length>:<bytes>`, the standard
// netstring/bencode technique) — NOT raw `\x1f`/`\x1e` delimiter bytes,
// which are not injective over unconstrained legacy TEXT (a delimiter byte
// embedded in one field can shift a row's apparent field boundary enough
// to make two DIFFERENT row sets hash identically; see
// deployment_store.cpp's identical rationale, ADR-0043). With a FIXED field
// count per row this makes the whole per-row encoding injective.
void append_field(std::string& out, std::string_view field) {
    out += std::to_string(field.size());
    out += ':';
    out += field;
}

std::string canon_package(const SoftwarePackage& p) {
    std::string r;
    append_field(r, p.id);
    append_field(r, p.name);
    append_field(r, p.version);
    append_field(r, p.platform);
    append_field(r, p.installer_type);
    append_field(r, p.content_hash);
    append_field(r, p.content_url);
    append_field(r, p.silent_args);
    append_field(r, p.verify_command);
    append_field(r, p.rollback_command);
    append_field(r, std::to_string(p.size_bytes));
    append_field(r, std::to_string(p.created_at));
    append_field(r, p.created_by);
    return r;
}

std::string canon_deployment(const SoftwareDeployment& d) {
    std::string r;
    append_field(r, d.id);
    append_field(r, d.package_id);
    append_field(r, d.scope_expression);
    append_field(r, d.status);
    append_field(r, d.created_by);
    append_field(r, std::to_string(d.created_at));
    append_field(r, std::to_string(d.started_at));
    append_field(r, std::to_string(d.completed_at));
    append_field(r, std::to_string(d.agents_targeted));
    append_field(r, std::to_string(d.agents_success));
    append_field(r, std::to_string(d.agents_failure));
    return r;
}

std::string canon_agent_status(const AgentDeploymentStatus& a) {
    std::string r;
    append_field(r, a.deployment_id);
    append_field(r, a.agent_id);
    append_field(r, a.status);
    append_field(r, std::to_string(a.started_at));
    append_field(r, std::to_string(a.completed_at));
    append_field(r, a.error);
    return r;
}

// One fingerprint over ALL THREE tables' rows, each section independently
// sorted (so physical SELECT order never affects the hash) and separated by
// a literal tag. A tag can never be mistaken for a row boundary: every row
// inside a section begins with a decimal length-prefix digit, and "PKG"/
// "DEP"/"AGT" are not digits, so the tag is unambiguous — the same
// injectivity argument as append_field, one level up.
std::string canonicalize_legacy_snapshot(const std::vector<SoftwarePackage>& pkgs,
                                         const std::vector<SoftwareDeployment>& deps,
                                         const std::vector<AgentDeploymentStatus>& agents) {
    std::vector<std::string> pkg_rows, dep_rows, agt_rows;
    pkg_rows.reserve(pkgs.size());
    for (const auto& p : pkgs)
        pkg_rows.push_back(canon_package(p));
    dep_rows.reserve(deps.size());
    for (const auto& d : deps)
        dep_rows.push_back(canon_deployment(d));
    agt_rows.reserve(agents.size());
    for (const auto& a : agents)
        agt_rows.push_back(canon_agent_status(a));
    std::sort(pkg_rows.begin(), pkg_rows.end());
    std::sort(dep_rows.begin(), dep_rows.end());
    std::sort(agt_rows.begin(), agt_rows.end());

    std::string canon = "software-deployment-legacy-fingerprint-v1\nPKG\n";
    for (const auto& r : pkg_rows)
        canon += r;
    canon += "DEP\n";
    for (const auto& r : dep_rows)
        canon += r;
    canon += "AGT\n";
    for (const auto& r : agt_rows)
        canon += r;
    return canon;
}

// Deployment status's documented intended progression (software_deployment_
// store.hpp's SoftwareDeployment::status comment): staged -> deploying ->
// verifying -> completed, with cancelled/rolled_back/failed reachable as
// terminal exits from various points (cancel_deployment guards
// staged/deploying; rollback_deployment guards deploying/verifying/
// completed) — so `completed` is NOT terminal here (rollback can follow
// it), unlike DeploymentStore's status enum where it is. The three named
// terminal exits are tied at the same maximal rank: a same-rank difference
// between them is a genuine disagreement about which terminal outcome
// occurred, not "who progressed further" (mirrors DeploymentStore's
// terminal_disagreement fix, ADR-0043 Finding UP-E). Only
// staged/deploying/cancelled/rolled_back have a store writer today; a
// legacy row may still hold verifying/completed/failed from the store's
// wired era or a future orchestration engine — validity, not reachability,
// is what this function and its caller enforce.
int deployment_lifecycle_rank(std::string_view status) {
    if (status == "staged")
        return 0;
    if (status == "deploying")
        return 1;
    if (status == "verifying")
        return 2;
    if (status == "completed")
        return 3;
    if (status == "cancelled" || status == "rolled_back" || status == "failed")
        return 4;
    return 5; // unrecognised — one past the terminal band, the validity check below
}

// Agent status's documented intended progression (AgentDeploymentStatus::
// status comment): pending -> downloading -> installing -> verifying ->
// {success, failed, rolled_back} (terminal, tied). UNLIKE the deployment
// table, `update_agent_status` is an unguarded upsert on the live path —
// nothing proves a real transition ever respects this order. The backfill's
// direction check below therefore treats this rank as a documented
// heuristic contract, not a proven-safe guard: a "legacy ahead"/"terminal
// disagreement" classification here can in principle be wrong if a live
// caller wrote an out-of-order transition, in which case the backfill fails
// closed on data that was actually fine — the safe direction for an
// operator-facing per-agent install outcome to err in.
int agent_lifecycle_rank(std::string_view status) {
    if (status == "pending")
        return 0;
    if (status == "downloading")
        return 1;
    if (status == "installing")
        return 2;
    if (status == "verifying")
        return 3;
    if (status == "success" || status == "failed" || status == "rolled_back")
        return 4;
    return 5; // unrecognised
}

bool is_fk_violation(const pg::PgResult& res) {
    const char* sqlstate = res.get() ? PQresultErrorField(res.get(), PG_DIAG_SQLSTATE) : nullptr;
    return sqlstate && std::string_view(sqlstate) == "23503";
}

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE software_packages ("
         "  id               TEXT PRIMARY KEY,"
         "  name             TEXT NOT NULL,"
         "  version          TEXT NOT NULL DEFAULT '',"
         "  platform         TEXT NOT NULL DEFAULT '',"
         "  installer_type   TEXT NOT NULL DEFAULT '',"
         "  content_hash     TEXT NOT NULL DEFAULT '',"
         "  content_url      TEXT NOT NULL DEFAULT '',"
         "  silent_args      TEXT NOT NULL DEFAULT '',"
         "  verify_command   TEXT NOT NULL DEFAULT '',"
         "  rollback_command TEXT NOT NULL DEFAULT '',"
         "  size_bytes       BIGINT NOT NULL DEFAULT 0,"
         "  created_at       BIGINT NOT NULL DEFAULT 0,"
         "  created_by       TEXT NOT NULL DEFAULT '');"
         "CREATE INDEX idx_swpkg_name ON software_packages(name);"
         "CREATE INDEX idx_swpkg_platform ON software_packages(platform);"

         "CREATE TABLE software_deployments ("
         "  id               TEXT PRIMARY KEY,"
         "  package_id       TEXT NOT NULL REFERENCES software_packages(id),"
         "  scope_expression TEXT NOT NULL DEFAULT '',"
         "  status           TEXT NOT NULL DEFAULT 'staged',"
         "  created_by       TEXT NOT NULL DEFAULT '',"
         "  created_at       BIGINT NOT NULL DEFAULT 0,"
         "  started_at       BIGINT NOT NULL DEFAULT 0,"
         "  completed_at     BIGINT NOT NULL DEFAULT 0,"
         "  agents_targeted  INTEGER NOT NULL DEFAULT 0,"
         "  agents_success   INTEGER NOT NULL DEFAULT 0,"
         "  agents_failure   INTEGER NOT NULL DEFAULT 0);"
         "CREATE INDEX idx_swdep_status ON software_deployments(status);"
         "CREATE INDEX idx_swdep_package ON software_deployments(package_id);"
         "CREATE INDEX idx_swdep_created ON software_deployments(created_at);"

         // No separate index on agent_software_status(deployment_id): the
         // PRIMARY KEY (deployment_id, agent_id) below already gives
         // Postgres a leading-column btree index, unlike the pre-migration
         // SQLite schema (kept as a distinct idx_agentstatus_dep there).
         "CREATE TABLE agent_software_status ("
         "  deployment_id TEXT NOT NULL REFERENCES software_deployments(id),"
         "  agent_id      TEXT NOT NULL,"
         "  status        TEXT NOT NULL DEFAULT 'pending',"
         "  started_at    BIGINT NOT NULL DEFAULT 0,"
         "  completed_at  BIGINT NOT NULL DEFAULT 0,"
         "  error         TEXT NOT NULL DEFAULT '',"
         "  PRIMARY KEY (deployment_id, agent_id));"
         "CREATE INDEX idx_agentstatus_agent ON agent_software_status(agent_id);"

         // ADR-0009 backfill idempotency — content-fingerprinted, not a
         // single completion flag (DeploymentStore/ADR-0043 shape). One row
         // per DISTINCT legacy-file content (or the sourceless sentinel)
         // ever observed by any replica.
         "CREATE TABLE sqlite_backfill_source ("
         "  fingerprint  TEXT PRIMARY KEY,"
         "  completed_at BIGINT NOT NULL);"},
    };
    return kMigrations;
}

constexpr const char* kPackageCols = "id, name, version, platform, installer_type, content_hash, "
                                     "content_url, silent_args, verify_command, "
                                     "rollback_command, size_bytes, created_at, created_by";

SoftwarePackage read_package(PGresult* res, int i) {
    SoftwarePackage p;
    int col = 0;
    p.id = PQgetvalue(res, i, col++);
    p.name = PQgetvalue(res, i, col++);
    p.version = PQgetvalue(res, i, col++);
    p.platform = PQgetvalue(res, i, col++);
    p.installer_type = PQgetvalue(res, i, col++);
    p.content_hash = PQgetvalue(res, i, col++);
    p.content_url = PQgetvalue(res, i, col++);
    p.silent_args = PQgetvalue(res, i, col++);
    p.verify_command = PQgetvalue(res, i, col++);
    p.rollback_command = PQgetvalue(res, i, col++);
    p.size_bytes = to_i64(PQgetvalue(res, i, col++));
    p.created_at = to_i64(PQgetvalue(res, i, col++));
    p.created_by = PQgetvalue(res, i, col++);
    return p;
}

constexpr const char* kDeploymentCols =
    "id, package_id, scope_expression, status, created_by, created_at, started_at, "
    "completed_at, agents_targeted, agents_success, agents_failure";

SoftwareDeployment read_deployment(PGresult* res, int i) {
    SoftwareDeployment d;
    int col = 0;
    d.id = PQgetvalue(res, i, col++);
    d.package_id = PQgetvalue(res, i, col++);
    d.scope_expression = PQgetvalue(res, i, col++);
    d.status = PQgetvalue(res, i, col++);
    d.created_by = PQgetvalue(res, i, col++);
    d.created_at = to_i64(PQgetvalue(res, i, col++));
    d.started_at = to_i64(PQgetvalue(res, i, col++));
    d.completed_at = to_i64(PQgetvalue(res, i, col++));
    d.agents_targeted = to_int(PQgetvalue(res, i, col++));
    d.agents_success = to_int(PQgetvalue(res, i, col++));
    d.agents_failure = to_int(PQgetvalue(res, i, col++));
    return d;
}

constexpr const char* kAgentStatusCols =
    "deployment_id, agent_id, status, started_at, completed_at, error";

AgentDeploymentStatus read_agent_status(PGresult* res, int i) {
    AgentDeploymentStatus a;
    int col = 0;
    a.deployment_id = PQgetvalue(res, i, col++);
    a.agent_id = PQgetvalue(res, i, col++);
    a.status = PQgetvalue(res, i, col++);
    a.started_at = to_i64(PQgetvalue(res, i, col++));
    a.completed_at = to_i64(PQgetvalue(res, i, col++));
    a.error = PQgetvalue(res, i, col++);
    return a;
}

// Three outcomes, not two — ported from audit_store.cpp's reference fix for
// this exact defect class (found by cpp-safety, Gate 3, on THIS store's own
// governance run; independently re-derived by unhappy-path, Gate 4, as its
// own UP-2). A
// `sqlite3_prepare_v2`/`sqlite3_step` failure (corrupt file, encrypted file,
// disk I/O error — bytes present that don't parse as a SQLite header) is NOT
// the same fact as "the table genuinely does not exist": the former means
// this process cannot see what the file holds, the latter means it can see
// the file holds nothing of interest. Collapsing them to one `bool` lets a
// corrupt legacy file masquerade as a fresh install and silently forfeit the
// mandatory backfill. A genuinely zero-byte file is `Absent`, not `Error` —
// SQLite treats 0 bytes as a valid, uninitialized database and
// `sqlite_master` reads back empty rather than failing.
enum class LegacyTableStatus { Present, Absent, Error };

LegacyTableStatus legacy_has_table(sqlite3* db, const char* table) {
    SqliteStmt s;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", -1,
                           s.addr(), nullptr) != SQLITE_OK)
        return LegacyTableStatus::Error;
    sqlite3_bind_text(s.get(), 1, table, -1, SQLITE_TRANSIENT);
    const int rc = sqlite3_step(s.get());
    if (rc == SQLITE_ROW)
        return LegacyTableStatus::Present;
    if (rc == SQLITE_DONE)
        return LegacyTableStatus::Absent;
    return LegacyTableStatus::Error;
}

} // namespace

// ── ID generation ────────────────────────────────────────────────────────────

// Preserves the pre-migration store's exact ID format: two independent
// 64-bit mt19937_64 draws formatted as 16 hex chars each (32 total). NOT a
// cryptographic random source — `id` is a non-security surrogate key
// (uniqueness, not unguessability, is what matters).
std::string SoftwareDeploymentStore::generate_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    const auto hi = dist(rng);
    const auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx", static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

// ── Construction ─────────────────────────────────────────────────────────────

SoftwareDeploymentStore::SoftwareDeploymentStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("SoftwareDeploymentStore: no database connection at construction ({}) — "
                      "software deployment persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("SoftwareDeploymentStore: schema migration failed — software deployment "
                      "persistence disabled");
        return;
    }
    open_ = true;
}

// ── Backfill (ADR-0009 / ADR-0051) ────────────────────────────────────────
//
// Content-fingerprinted, not a single fleet-wide completion flag — same
// design as DeploymentStore/ADR-0043, extended to three tables. A replica
// with no local legacy file (or a present-but-schema-less one) computes and
// stamps the `sourceless` sentinel; a replica holding real rows computes a
// SHA-256 fingerprint of ALL THREE tables' canonicalized content (see
// canonicalize_legacy_snapshot) and checks/stamps that specific value.
//
// PARTIAL SCHEMA is treated as corruption, not as sourceless (ADR-0051
// decision this store adds beyond the single-table precedent): the
// pre-migration store's own migration always creates all three tables
// together in one statement, so a real legacy file produced by this store's
// code has all three or none. ANY partial combination — not just
// "software_packages present, the others missing" — cannot be a genuine
// fresh-install/no-data case; it fails the backfill closed rather than
// silently treating the file as empty. This must be checked symmetrically
// across all three tables (an earlier version of this function checked only
// one direction and was fixed in the same governance round that shipped it,
// per Gate 3/4's independently-converging BLOCKING findings). A table-probe
// FAILURE (corrupt/unreadable file) is itself a distinct, always-fail-closed
// outcome — see `LegacyTableStatus` above — never silently folded into
// "absent".
//
// REFERENTIAL CLOSURE is validated CLIENT-SIDE, before any Postgres round
// trip (ADR-0051 decision beyond the single-table precedent): Postgres
// ENFORCES the package_id/deployment_id foreign keys (the pre-migration
// SQLite store never did — `PRAGMA foreign_keys` was never set), so a
// wired-era legacy file can hold a genuine orphan (e.g. a deployment whose
// package was deleted via delete_package while the deployment row was
// never cleaned up). There is no valid parent to satisfy the FK with and no
// "which side is right" adjudication to make — unlike an identity mismatch
// or a lifecycle disagreement, an orphan cannot be reconciled by picking a
// value, only by editing the legacy data. The whole backfill fails closed,
// naming the orphan row and its missing parent id, rather than either
// fabricating a placeholder parent or silently dropping the row (and, for a
// dangling deployment, its own child agent_software_status rows).
//
// Per-row conflict handling partitions columns into IDENTITY (write-once)
// vs LIFECYCLE (mutated by live post-migration traffic), exactly as
// DeploymentStore/ADR-0043 established — see that store's file header for
// the full rationale. software_packages rows are ALL-IDENTITY (a write-once
// catalog: create_package is the only write path and there is no update);
// any content difference on a conflicting id fails the boot closed, and an
// identical re-encounter is a benign no-op. software_deployments partitions
// into IDENTITY (package_id, scope_expression, created_by, created_at) vs
// LIFECYCLE (status, started_at, completed_at, the three agent counters),
// using deployment_lifecycle_rank's direction check (see that function's
// doc comment for why this store's rank differs from DeploymentStore's —
// `completed` is not terminal here). agent_software_status partitions its
// PK (deployment_id, agent_id, both write-once by construction — the PK
// cannot change) from LIFECYCLE (status, started_at, completed_at, error),
// using agent_lifecycle_rank's HEURISTIC direction check (see that
// function's doc comment — update_agent_status has no transition guard on
// the live path, so this is a documented-contract heuristic, not a proven
// safe direction).
bool SoftwareDeploymentStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: cannot stat legacy path {}: "
                      "{}",
                      legacy_db_path.string(), ec.message());
        return false;
    }

    std::string fingerprint;
    std::vector<SoftwarePackage> legacy_pkgs;
    std::vector<SoftwareDeployment> legacy_deps;
    std::vector<AgentDeploymentStatus> legacy_agents;

    if (!legacy_exists) {
        fingerprint = kSourcelessFingerprint;
    } else {
        SqliteDb legacy;
        if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                            nullptr) != SQLITE_OK) {
            spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: failed to open legacy "
                          "{}: {}",
                          legacy_db_path.string(),
                          legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
            return false;
        }

        const LegacyTableStatus pkg_status = legacy_has_table(legacy.get(), "software_packages");
        const LegacyTableStatus dep_status = legacy_has_table(legacy.get(), "software_deployments");
        const LegacyTableStatus agent_status =
            legacy_has_table(legacy.get(), "agent_software_status");
        if (pkg_status == LegacyTableStatus::Error || dep_status == LegacyTableStatus::Error ||
            agent_status == LegacyTableStatus::Error) {
            spdlog::error(
                "SoftwareDeploymentStore::migrate_from_sqlite: legacy {} table-existence probe "
                "failed (corrupt or unreadable file?) — a probe failure is never treated as "
                "absence; refusing (fail-closed)",
                legacy_db_path.string());
            return false;
        }
        const bool has_pkg_table = pkg_status == LegacyTableStatus::Present;
        const bool has_dep_table = dep_status == LegacyTableStatus::Present;
        const bool has_agent_table = agent_status == LegacyTableStatus::Present;
        if (!has_pkg_table && !has_dep_table && !has_agent_table) {
            fingerprint = kSourcelessFingerprint;
        } else if (!has_pkg_table || !has_dep_table || !has_agent_table) {
            spdlog::error(
                "SoftwareDeploymentStore::migrate_from_sqlite: legacy {} has a PARTIAL schema "
                "(missing {}{}{}) — a genuine fresh/empty file never has a partial schema (all "
                "three tables are created together); refusing (fail-closed, likely corruption)",
                legacy_db_path.string(), !has_pkg_table ? "software_packages " : "",
                !has_dep_table ? "software_deployments " : "",
                !has_agent_table ? "agent_software_status " : "");
            return false;
        } else {
            const auto read_all = [&](const char* sql,
                                      const std::function<void(sqlite3_stmt*)>& row) -> bool {
                SqliteStmt s;
                if (sqlite3_prepare_v2(legacy.get(), sql, -1, s.addr(), nullptr) != SQLITE_OK)
                    return false;
                int rc;
                while ((rc = sqlite3_step(s.get())) == SQLITE_ROW)
                    row(s.get());
                return rc == SQLITE_DONE;
            };

            bool read_ok = true;
            read_ok &= read_all(
                "SELECT id, name, version, platform, installer_type, content_hash, content_url, "
                "silent_args, verify_command, rollback_command, size_bytes, created_at, "
                "created_by FROM software_packages ORDER BY created_at ASC, id ASC",
                [&](sqlite3_stmt* s) {
                    SoftwarePackage p;
                    p.id = sqlite_text(s, 0);
                    p.name = sqlite_text(s, 1);
                    p.version = sqlite_text(s, 2);
                    p.platform = sqlite_text(s, 3);
                    p.installer_type = sqlite_text(s, 4);
                    p.content_hash = sqlite_text(s, 5);
                    p.content_url = sqlite_text(s, 6);
                    p.silent_args = sqlite_text(s, 7);
                    p.verify_command = sqlite_text(s, 8);
                    p.rollback_command = sqlite_text(s, 9);
                    p.size_bytes = sqlite3_column_int64(s, 10);
                    p.created_at = sqlite3_column_int64(s, 11);
                    p.created_by = sqlite_text(s, 12);
                    legacy_pkgs.push_back(std::move(p));
                });
            if (!read_ok) {
                spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: legacy "
                              "software_packages scan aborted mid-read: {}",
                              sqlite3_errmsg(legacy.get()));
                return false;
            }

            read_ok &= read_all(
                "SELECT id, package_id, scope_expression, status, created_by, created_at, "
                "started_at, completed_at, agents_targeted, agents_success, agents_failure "
                "FROM software_deployments ORDER BY created_at ASC, id ASC",
                [&](sqlite3_stmt* s) {
                    SoftwareDeployment d;
                    d.id = sqlite_text(s, 0);
                    d.package_id = sqlite_text(s, 1);
                    d.scope_expression = sqlite_text(s, 2);
                    d.status = sqlite_text(s, 3);
                    d.created_by = sqlite_text(s, 4);
                    d.created_at = sqlite3_column_int64(s, 5);
                    d.started_at = sqlite3_column_int64(s, 6);
                    d.completed_at = sqlite3_column_int64(s, 7);
                    d.agents_targeted = sqlite3_column_int(s, 8);
                    d.agents_success = sqlite3_column_int(s, 9);
                    d.agents_failure = sqlite3_column_int(s, 10);
                    legacy_deps.push_back(std::move(d));
                });
            if (!read_ok) {
                spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: legacy "
                              "software_deployments scan aborted mid-read: {}",
                              sqlite3_errmsg(legacy.get()));
                return false;
            }

            read_ok &= read_all(
                "SELECT deployment_id, agent_id, status, started_at, completed_at, error FROM "
                "agent_software_status ORDER BY deployment_id ASC, agent_id ASC",
                [&](sqlite3_stmt* s) {
                    AgentDeploymentStatus a;
                    a.deployment_id = sqlite_text(s, 0);
                    a.agent_id = sqlite_text(s, 1);
                    a.status = sqlite_text(s, 2);
                    a.started_at = sqlite3_column_int64(s, 3);
                    a.completed_at = sqlite3_column_int64(s, 4);
                    a.error = sqlite_text(s, 5);
                    legacy_agents.push_back(std::move(a));
                });
            if (!read_ok) {
                spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: legacy "
                              "agent_software_status scan aborted mid-read: {}",
                              sqlite3_errmsg(legacy.get()));
                return false;
            }

            // Validate BOTH status enums before any row can reach Postgres
            // (DeploymentStore/ADR-0043 Finding DW-8 precedent, applied to
            // both enums this store carries).
            for (const auto& d : legacy_deps) {
                if (deployment_lifecycle_rank(d.status) == 5) {
                    spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: legacy "
                                  "software_deployments row {} has an unrecognised status '{}' "
                                  "— refusing to stamp a backfill containing it",
                                  d.id, d.status);
                    return false;
                }
            }
            for (const auto& a : legacy_agents) {
                if (agent_lifecycle_rank(a.status) == 5) {
                    spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: legacy "
                                  "agent_software_status row (deployment_id={}, agent_id={}) has "
                                  "an unrecognised status '{}' — refusing to stamp a backfill "
                                  "containing it",
                                  a.deployment_id, a.agent_id, a.status);
                    return false;
                }
            }

            // Referential closure — see the file header above this
            // function for the rationale (Postgres enforces FKs the legacy
            // store never did).
            {
                std::unordered_set<std::string> pkg_ids;
                pkg_ids.reserve(legacy_pkgs.size());
                for (const auto& p : legacy_pkgs)
                    pkg_ids.insert(p.id);
                for (const auto& d : legacy_deps) {
                    if (!pkg_ids.contains(d.package_id)) {
                        spdlog::error(
                            "SoftwareDeploymentStore::migrate_from_sqlite: legacy "
                            "software_deployments row {} references package_id='{}', which does "
                            "not exist in this legacy snapshot — Postgres enforces this foreign "
                            "key (the legacy store never did), so this orphan cannot be "
                            "migrated; refusing the whole backfill (fail-closed). Reconcile by "
                            "either removing the orphan deployment row or restoring its package "
                            "row in the retained legacy file, then restart",
                            d.id, d.package_id);
                        return false;
                    }
                }
                std::unordered_set<std::string> dep_ids;
                dep_ids.reserve(legacy_deps.size());
                for (const auto& d : legacy_deps)
                    dep_ids.insert(d.id);
                for (const auto& a : legacy_agents) {
                    if (!dep_ids.contains(a.deployment_id)) {
                        spdlog::error(
                            "SoftwareDeploymentStore::migrate_from_sqlite: legacy "
                            "agent_software_status row (agent_id={}) references "
                            "deployment_id='{}', which does not exist in this legacy snapshot — "
                            "refusing the whole backfill (fail-closed). Reconcile by either "
                            "removing the orphan agent status row or restoring its deployment "
                            "row in the retained legacy file, then restart",
                            a.agent_id, a.deployment_id);
                        return false;
                    }
                }
            }

            if (legacy_pkgs.empty() && legacy_deps.empty() && legacy_agents.empty()) {
                fingerprint = kSourcelessFingerprint;
            } else {
                fingerprint =
                    sha256_hex(canonicalize_legacy_snapshot(legacy_pkgs, legacy_deps, legacy_agents));
                if (fingerprint.empty()) {
                    spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: SHA-256 hashing "
                                  "failed for legacy content at {} — refusing (fail-closed)",
                                  legacy_db_path.string());
                    return false;
                }
            }
        }
    }
    // `legacy` (if opened) closed here via SqliteDb's destructor.

    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: no database connection");
            return false;
        }
        pg::PgResult marker = pg::exec_params(
            lease.get(),
            "SELECT 1 FROM software_deployment_store.sqlite_backfill_source WHERE fingerprint=$1",
            std::vector<std::string>{fingerprint});
        if (marker.status() != PGRES_TUPLES_OK) {
            spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: backfill-marker check "
                          "failed: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        if (PQntuples(marker.get()) > 0) {
            spdlog::debug("SoftwareDeploymentStore::migrate_from_sqlite: fingerprint already "
                          "processed, skipping");
            return true;
        }
    }

    if (fingerprint == kSourcelessFingerprint) {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: no connection to stamp "
                          "marker");
            return false;
        }
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO software_deployment_store.sqlite_backfill_source (fingerprint, "
            "completed_at) VALUES ($1, $2::bigint) ON CONFLICT (fingerprint) DO NOTHING",
            std::vector<std::string>{fingerprint, std::to_string(now_epoch())});
        if (r.status() != PGRES_COMMAND_OK) {
            spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: failed to stamp marker: "
                          "{}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        spdlog::info("SoftwareDeploymentStore::migrate_from_sqlite: no legacy software "
                     "deployment data at {} — nothing to backfill",
                     legacy_db_path.string());
        return true;
    }

    spdlog::info("SoftwareDeploymentStore::migrate_from_sqlite: backfilling {} package(s), {} "
                 "deployment(s), {} agent status row(s) from {}",
                 legacy_pkgs.size(), legacy_deps.size(), legacy_agents.size(),
                 legacy_db_path.string());

    std::string failure_detail;
    bool row_conflict_guidance = false;
    // Unbounded with_txn (not with_txn_for): startup is serial, same
    // discipline as the ctor's unbounded acquire() (ADR-0012 §2(a)).
    bool ok = pool_.with_txn([&](PGconn* conn) -> bool {
        // Parents first: packages, then deployments, then agent status —
        // the ported FKs reject a child inserted before its parent exists.
        for (const auto& p : legacy_pkgs) {
            pg::PgResult res = pg::exec_params(
                conn,
                "INSERT INTO software_deployment_store.software_packages "
                "(id, name, version, platform, installer_type, content_hash, content_url, "
                " silent_args, verify_command, rollback_command, size_bytes, created_at, "
                " created_by) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::bigint,$12::bigint,$13) "
                "ON CONFLICT (id) DO NOTHING RETURNING id",
                std::vector<std::string>{
                    p.id, p.name, p.version, p.platform, p.installer_type, p.content_hash,
                    p.content_url, p.silent_args, p.verify_command, p.rollback_command,
                    std::to_string(p.size_bytes), std::to_string(p.created_at), p.created_by});
            if (res.status() != PGRES_TUPLES_OK) {
                failure_detail =
                    std::string("legacy software_packages row id='") + p.id + "': " +
                    PQerrorMessage(conn);
                spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: package insert {} "
                              "failed: {}",
                              p.id, PQerrorMessage(conn));
                return false;
            }
            if (PQntuples(res.get()) > 0)
                continue; // inserted cleanly

            // Conflict on id — all-IDENTITY table (write-once catalog, no
            // update path), so ANY content difference fails closed; an
            // identical re-encounter is a benign no-op.
            std::string existing_sql =
                std::string("SELECT ") + kPackageCols +
                " FROM software_deployment_store.software_packages WHERE id=$1";
            pg::PgResult existing =
                pg::exec_params(conn, existing_sql.c_str(), std::vector<std::string>{p.id});
            if (existing.status() != PGRES_TUPLES_OK || PQntuples(existing.get()) == 0) {
                failure_detail = std::string("legacy software_packages row id='") + p.id +
                                 "': conflicted on insert but the existing row could not be "
                                 "read back for comparison: " +
                                 PQerrorMessage(conn);
                spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: package {} "
                              "conflicted but the existing row read-back failed: {}",
                              p.id, PQerrorMessage(conn));
                return false;
            }
            const SoftwarePackage stored = read_package(existing.get(), 0);
            const bool identical =
                stored.name == p.name && stored.version == p.version &&
                stored.platform == p.platform && stored.installer_type == p.installer_type &&
                stored.content_hash == p.content_hash && stored.content_url == p.content_url &&
                stored.silent_args == p.silent_args &&
                stored.verify_command == p.verify_command &&
                stored.rollback_command == p.rollback_command &&
                stored.size_bytes == p.size_bytes && stored.created_at == p.created_at &&
                stored.created_by == p.created_by;
            if (!identical) {
                row_conflict_guidance = true;
                failure_detail = std::string("legacy software_packages row id='") + p.id +
                                 "' already exists with DIFFERENT content — refusing to silently "
                                 "discard it";
                spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: package {} conflicts "
                              "with different content — refusing to stamp a backfill that would "
                              "silently discard it",
                              p.id);
                return false;
            }
            spdlog::debug("SoftwareDeploymentStore::migrate_from_sqlite: package {} already "
                          "present with identical content, skipping (benign no-op)",
                          p.id);
        }

        for (const auto& d : legacy_deps) {
            pg::PgResult res = pg::exec_params(
                conn,
                "INSERT INTO software_deployment_store.software_deployments "
                "(id, package_id, scope_expression, status, created_by, created_at, started_at, "
                " completed_at, agents_targeted, agents_success, agents_failure) "
                "VALUES ($1,$2,$3,$4,$5,$6::bigint,$7::bigint,$8::bigint,$9::int,$10::int,"
                "$11::int) "
                "ON CONFLICT (id) DO NOTHING RETURNING id",
                std::vector<std::string>{d.id, d.package_id, d.scope_expression, d.status,
                                         d.created_by, std::to_string(d.created_at),
                                         std::to_string(d.started_at),
                                         std::to_string(d.completed_at),
                                         std::to_string(d.agents_targeted),
                                         std::to_string(d.agents_success),
                                         std::to_string(d.agents_failure)});
            if (res.status() != PGRES_TUPLES_OK) {
                failure_detail = std::string("legacy software_deployments row id='") + d.id +
                                 "': " + PQerrorMessage(conn);
                spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: deployment insert "
                              "{} failed: {}",
                              d.id, PQerrorMessage(conn));
                return false;
            }
            if (PQntuples(res.get()) > 0)
                continue;

            std::string existing_sql =
                std::string("SELECT ") + kDeploymentCols +
                " FROM software_deployment_store.software_deployments WHERE id=$1";
            pg::PgResult existing =
                pg::exec_params(conn, existing_sql.c_str(), std::vector<std::string>{d.id});
            if (existing.status() != PGRES_TUPLES_OK || PQntuples(existing.get()) == 0) {
                failure_detail = std::string("legacy software_deployments row id='") + d.id +
                                 "': conflicted on insert but the existing row could not be "
                                 "read back for comparison: " +
                                 PQerrorMessage(conn);
                spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: deployment {} "
                              "conflicted but the existing row read-back failed: {}",
                              d.id, PQerrorMessage(conn));
                return false;
            }
            const SoftwareDeployment stored = read_deployment(existing.get(), 0);
            const bool identity_matches =
                stored.package_id == d.package_id &&
                stored.scope_expression == d.scope_expression &&
                stored.created_by == d.created_by && stored.created_at == d.created_at;
            if (!identity_matches) {
                row_conflict_guidance = true;
                failure_detail =
                    std::string("legacy software_deployments row id='") + d.id +
                    "' already exists with DIFFERENT identity (stored: package_id='" +
                    stored.package_id + "' scope_expression='" + stored.scope_expression +
                    "' created_by='" + stored.created_by +
                    "' created_at=" + std::to_string(stored.created_at) + "; legacy: package_id='" +
                    d.package_id + "' scope_expression='" + d.scope_expression + "' created_by='" +
                    d.created_by + "' created_at=" + std::to_string(d.created_at) +
                    ") — refusing to silently discard it";
                spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: deployment {} "
                              "conflicts with different IDENTITY — refusing to stamp a backfill "
                              "that would silently discard it",
                              d.id);
                return false;
            }
            const bool lifecycle_matches =
                stored.status == d.status && stored.started_at == d.started_at &&
                stored.completed_at == d.completed_at &&
                stored.agents_targeted == d.agents_targeted &&
                stored.agents_success == d.agents_success &&
                stored.agents_failure == d.agents_failure;
            if (lifecycle_matches) {
                spdlog::debug("SoftwareDeploymentStore::migrate_from_sqlite: deployment {} "
                              "already present with identical content, skipping (benign no-op)",
                              d.id);
                continue;
            }
            const int legacy_rank = deployment_lifecycle_rank(d.status);
            const int stored_rank = deployment_lifecycle_rank(stored.status);
            const bool legacy_ahead = legacy_rank > stored_rank;
            const bool terminal_disagreement =
                legacy_rank == stored_rank && legacy_rank == 4 && d.status != stored.status;
            if (legacy_ahead || terminal_disagreement) {
                row_conflict_guidance = true;
                failure_detail =
                    std::string("legacy software_deployments row id='") + d.id +
                    "' lifecycle " +
                    (legacy_ahead ? "shows MORE progress than"
                                  : "reports a DIFFERENT terminal outcome than") +
                    " Postgres's current value (stored: status='" + stored.status +
                    "' started_at=" + std::to_string(stored.started_at) +
                    " completed_at=" + std::to_string(stored.completed_at) + "; legacy: status='" +
                    d.status + "' started_at=" + std::to_string(d.started_at) +
                    " completed_at=" + std::to_string(d.completed_at) +
                    ") — likely a rollback-then-roll-forward cycle (ADR-0009) progressed this "
                    "deployment while running the pre-migration binary; refusing to silently "
                    "discard that evidence. Postgres's value is the STALE or CONTRADICTED side "
                    "here — do NOT edit the retained legacy file to make it match Postgres. "
                    "Reconcile Postgres to the correct outcome or, to explicitly accept the "
                    "loss, move the whole legacy file aside so this backfill is never retried "
                    "against it, then restart";
                spdlog::error(
                    "SoftwareDeploymentStore::migrate_from_sqlite: deployment {} legacy "
                    "snapshot conflicts with the current Postgres value ({}) — refusing to "
                    "stamp a backfill that would silently discard it",
                    d.id, legacy_ahead ? "more progress" : "different terminal outcome");
                return false;
            }
            spdlog::warn(
                "SoftwareDeploymentStore::migrate_from_sqlite: deployment {} already migrated "
                "with lifecycle progress since this legacy snapshot was taken (legacy status='{}' "
                "vs current status='{}') — keeping the current Postgres value; this is expected "
                "on a replica whose legacy file predates that progress, not a conflict",
                d.id, d.status, stored.status);
        }

        for (const auto& a : legacy_agents) {
            pg::PgResult res = pg::exec_params(
                conn,
                "INSERT INTO software_deployment_store.agent_software_status "
                "(deployment_id, agent_id, status, started_at, completed_at, error) "
                "VALUES ($1,$2,$3,$4::bigint,$5::bigint,$6) "
                "ON CONFLICT (deployment_id, agent_id) DO NOTHING RETURNING deployment_id",
                std::vector<std::string>{a.deployment_id, a.agent_id, a.status,
                                         std::to_string(a.started_at),
                                         std::to_string(a.completed_at), a.error});
            if (res.status() != PGRES_TUPLES_OK) {
                failure_detail = std::string("legacy agent_software_status row (deployment_id='") +
                                 a.deployment_id + "', agent_id='" + a.agent_id +
                                 "'): " + PQerrorMessage(conn);
                spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: agent status insert "
                              "(deployment_id={}, agent_id={}) failed: {}",
                              a.deployment_id, a.agent_id, PQerrorMessage(conn));
                return false;
            }
            if (PQntuples(res.get()) > 0)
                continue;

            std::string existing_sql =
                std::string("SELECT ") + kAgentStatusCols +
                " FROM software_deployment_store.agent_software_status WHERE deployment_id=$1 "
                "AND agent_id=$2";
            pg::PgResult existing = pg::exec_params(
                conn, existing_sql.c_str(),
                std::vector<std::string>{a.deployment_id, a.agent_id});
            if (existing.status() != PGRES_TUPLES_OK || PQntuples(existing.get()) == 0) {
                failure_detail =
                    std::string("legacy agent_software_status row (deployment_id='") +
                    a.deployment_id + "', agent_id='" + a.agent_id +
                    "'): conflicted on insert but the existing row could not be read back for "
                    "comparison: " +
                    PQerrorMessage(conn);
                spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: agent status "
                              "(deployment_id={}, agent_id={}) conflicted but the existing row "
                              "read-back failed: {}",
                              a.deployment_id, a.agent_id, PQerrorMessage(conn));
                return false;
            }
            const AgentDeploymentStatus stored = read_agent_status(existing.get(), 0);
            // deployment_id/agent_id are the PK — write-once by
            // construction, nothing left to compare there. Only LIFECYCLE
            // fields can differ.
            const bool lifecycle_matches = stored.status == a.status &&
                                           stored.started_at == a.started_at &&
                                           stored.completed_at == a.completed_at &&
                                           stored.error == a.error;
            if (lifecycle_matches) {
                spdlog::debug("SoftwareDeploymentStore::migrate_from_sqlite: agent status "
                              "(deployment_id={}, agent_id={}) already present with identical "
                              "content, skipping (benign no-op)",
                              a.deployment_id, a.agent_id);
                continue;
            }
            const int legacy_rank = agent_lifecycle_rank(a.status);
            const int stored_rank = agent_lifecycle_rank(stored.status);
            const bool legacy_ahead = legacy_rank > stored_rank;
            const bool terminal_disagreement =
                legacy_rank == stored_rank && legacy_rank == 4 && a.status != stored.status;
            if (legacy_ahead || terminal_disagreement) {
                row_conflict_guidance = true;
                failure_detail =
                    std::string("legacy agent_software_status row (deployment_id='") +
                    a.deployment_id + "', agent_id='" + a.agent_id + "') lifecycle " +
                    (legacy_ahead ? "shows MORE progress than"
                                  : "reports a DIFFERENT terminal outcome than") +
                    " Postgres's current value (stored: status='" + stored.status +
                    "'; legacy: status='" + a.status +
                    "') — refusing to silently discard it. update_agent_status has no live "
                    "transition guard, so this direction check is a documented-contract "
                    "heuristic, not a proven-safe one — reconcile Postgres to the correct "
                    "outcome or move the whole legacy file aside, then restart";
                spdlog::error(
                    "SoftwareDeploymentStore::migrate_from_sqlite: agent status "
                    "(deployment_id={}, agent_id={}) legacy snapshot conflicts with the current "
                    "Postgres value ({}) — refusing to stamp a backfill that would silently "
                    "discard it",
                    a.deployment_id, a.agent_id,
                    legacy_ahead ? "more progress" : "different terminal outcome");
                return false;
            }
            spdlog::warn(
                "SoftwareDeploymentStore::migrate_from_sqlite: agent status (deployment_id={}, "
                "agent_id={}) already migrated with lifecycle progress since this legacy "
                "snapshot was taken (legacy status='{}' vs current status='{}') — keeping the "
                "current Postgres value",
                a.deployment_id, a.agent_id, a.status, stored.status);
        }

        pg::PgResult marker = pg::exec_params(
            conn,
            "INSERT INTO software_deployment_store.sqlite_backfill_source (fingerprint, "
            "completed_at) VALUES ($1, $2::bigint) ON CONFLICT (fingerprint) DO NOTHING",
            std::vector<std::string>{fingerprint, std::to_string(now_epoch())});
        if (marker.status() != PGRES_COMMAND_OK) {
            failure_detail = std::string("backfill marker stamp: ") + PQerrorMessage(conn);
            spdlog::error("SoftwareDeploymentStore::migrate_from_sqlite: failed to stamp backfill "
                          "marker: {}",
                          PQerrorMessage(conn));
            return false;
        }
        return true;
    });
    if (!ok) {
        const std::string& offending =
            failure_detail.empty() ? std::string("unknown (see the specific-row error above)")
                                   : failure_detail;
        if (row_conflict_guidance) {
            spdlog::error(
                "SoftwareDeploymentStore::migrate_from_sqlite: backfill transaction failed and "
                "was rolled back — software deployment data NOT migrated. Offending: {}. See "
                "the guidance above for which side to reconcile. The retained read-only legacy "
                "file is at {} — inspect it with sqlite3, compare against Postgres's current "
                "row, then restart the server once resolved; the backfill marker was NOT "
                "stamped, so the next boot retries the whole backfill.",
                offending, legacy_db_path.string());
        } else {
            spdlog::error(
                "SoftwareDeploymentStore::migrate_from_sqlite: backfill transaction failed and "
                "was rolled back — software deployment data NOT migrated. Offending: {}. This "
                "is a database or legacy-file-read failure, not a row-content disagreement — "
                "resolve the underlying error above and restart the server; the backfill marker "
                "was NOT stamped, so the next boot retries the whole backfill.",
                offending);
        }
        return false;
    }
    spdlog::info("SoftwareDeploymentStore::migrate_from_sqlite: backfill complete");
    return true;
}

// ── Packages ─────────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
SoftwareDeploymentStore::create_package(const SoftwarePackage& pkg) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");
    if (pkg.name.empty())
        return std::unexpected("name is required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    const std::string id = generate_id();
    const std::int64_t now = now_epoch();
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO software_deployment_store.software_packages "
        "(id, name, version, platform, installer_type, content_hash, content_url, silent_args, "
        " verify_command, rollback_command, size_bytes, created_at, created_by) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::bigint,$12::bigint,$13) RETURNING id",
        std::vector<std::string>{id, pkg.name, pkg.version, pkg.platform, pkg.installer_type,
                                 pkg.content_hash, pkg.content_url, pkg.silent_args,
                                 pkg.verify_command, pkg.rollback_command,
                                 std::to_string(pkg.size_bytes), std::to_string(now),
                                 pkg.created_by});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "create_package failed: " + PQerrorMessage(lease.get()));

    spdlog::info("SoftwareDeploymentStore: created package {} ({})", id, pkg.name);
    return id;
}

std::expected<std::vector<SoftwarePackage>, std::string> SoftwareDeploymentStore::list_packages() {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kPackageCols +
                      " FROM software_deployment_store.software_packages ORDER BY created_at "
                      "DESC LIMIT $1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{std::to_string(kListRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "list_packages failed: " + PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<SoftwarePackage> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_package(res.get(), i));
    return out;
}

std::expected<std::optional<SoftwarePackage>, std::string>
SoftwareDeploymentStore::get_package(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kPackageCols +
                      " FROM software_deployment_store.software_packages WHERE id=$1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "get_package failed: " + PQerrorMessage(lease.get()));

    if (PQntuples(res.get()) == 0)
        return std::optional<SoftwarePackage>{std::nullopt};
    return std::optional<SoftwarePackage>{read_package(res.get(), 0)};
}

std::expected<void, std::string> SoftwareDeploymentStore::delete_package(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM software_deployment_store.software_packages WHERE id=$1 RETURNING id",
        std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK) {
        if (is_fk_violation(res))
            return std::unexpected(
                "package is referenced by an existing deployment and cannot be deleted");
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "delete_package failed: " + PQerrorMessage(lease.get()));
    }
    if (PQntuples(res.get()) == 0)
        return std::unexpected("package not found");
    return {};
}

// ── Deployments ──────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
SoftwareDeploymentStore::create_deployment(const SoftwareDeployment& dep) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");
    if (dep.package_id.empty())
        return std::unexpected("package_id is required");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    const std::string id = generate_id();
    const std::int64_t now = now_epoch();
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO software_deployment_store.software_deployments "
        "(id, package_id, scope_expression, status, created_by, created_at, agents_targeted) "
        "VALUES ($1,$2,$3,'staged',$4,$5::bigint,$6::int) RETURNING id",
        std::vector<std::string>{id, dep.package_id, dep.scope_expression, dep.created_by,
                                 std::to_string(now), std::to_string(dep.agents_targeted)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        if (is_fk_violation(res))
            return std::unexpected("package_id does not exist");
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "create_deployment failed: " + PQerrorMessage(lease.get()));
    }

    spdlog::info("SoftwareDeploymentStore: created deployment {} for package {}", id,
                 dep.package_id);
    return id;
}

std::expected<std::vector<SoftwareDeployment>, std::string>
SoftwareDeploymentStore::list_deployments(const std::string& status) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res;
    if (status.empty()) {
        std::string sql = std::string("SELECT ") + kDeploymentCols +
                          " FROM software_deployment_store.software_deployments ORDER BY "
                          "created_at DESC LIMIT $1";
        res = pg::exec_params(lease.get(), sql.c_str(),
                              std::vector<std::string>{std::to_string(kListRowCap)});
    } else {
        std::string sql = std::string("SELECT ") + kDeploymentCols +
                          " FROM software_deployment_store.software_deployments WHERE status=$1 "
                          "ORDER BY created_at DESC LIMIT $2";
        res = pg::exec_params(
            lease.get(), sql.c_str(),
            std::vector<std::string>{status, std::to_string(kListRowCap)});
    }
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "list_deployments failed: " + PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<SoftwareDeployment> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_deployment(res.get(), i));
    return out;
}

std::expected<std::optional<SoftwareDeployment>, std::string>
SoftwareDeploymentStore::get_deployment(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kDeploymentCols +
                      " FROM software_deployment_store.software_deployments WHERE id=$1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "get_deployment failed: " + PQerrorMessage(lease.get()));

    if (PQntuples(res.get()) == 0)
        return std::optional<SoftwareDeployment>{std::nullopt};
    return std::optional<SoftwareDeployment>{read_deployment(res.get(), 0)};
}

namespace {

// Shared shape for the three guarded single-UPDATE transitions below
// (start/cancel/rollback) — mirrors DeploymentStore::cancel_job's
// not-found-vs-wrong-state disambiguation, applied to all three here per
// ADR-0051 (kickoff lesson: route handlers need the split to map
// 404/400/503 instead of one catch-all).
std::expected<void, std::string>
guarded_transition(pg::PgPool& pool, const std::string& id, const char* update_sql,
                   const char* wrong_state_msg, const char* op_name) {
    auto lease = pool.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    // App-computed timestamp (never DB-side now()), matching every other
    // write in this store (create_package/create_deployment).
    pg::PgResult res = pg::exec_params(
        lease.get(), update_sql, std::vector<std::string>{std::to_string(now_epoch()), id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + op_name +
                               " failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) > 0)
        return {};

    pg::PgResult check = pg::exec_params(
        lease.get(), "SELECT status FROM software_deployment_store.software_deployments WHERE id=$1",
        std::vector<std::string>{id});
    if (check.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + op_name +
                               " disambiguation read failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(check.get()) > 0)
        return std::unexpected(wrong_state_msg);
    return std::unexpected("deployment not found");
}

} // namespace

std::expected<void, std::string> SoftwareDeploymentStore::start_deployment(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");
    return guarded_transition(
        pool_, id,
        "UPDATE software_deployment_store.software_deployments SET status='deploying', "
        "started_at=$1::bigint WHERE id=$2 AND status='staged' RETURNING id",
        "deployment is not staged", "start_deployment");
}

std::expected<void, std::string>
SoftwareDeploymentStore::cancel_deployment(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");
    return guarded_transition(
        pool_, id,
        "UPDATE software_deployment_store.software_deployments SET status='cancelled', "
        "completed_at=$1::bigint WHERE id=$2 AND status IN ('staged','deploying') "
        "RETURNING id",
        "only staged or deploying deployments can be cancelled", "cancel_deployment");
}

std::expected<void, std::string>
SoftwareDeploymentStore::rollback_deployment(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");
    return guarded_transition(
        pool_, id,
        "UPDATE software_deployment_store.software_deployments SET status='rolled_back', "
        "completed_at=$1::bigint WHERE id=$2 AND status IN "
        "('deploying','verifying','completed') RETURNING id",
        "only deploying, verifying, or completed deployments can be rolled back",
        "rollback_deployment");
}

std::expected<void, std::string>
SoftwareDeploymentStore::update_agent_status(const std::string& deployment_id,
                                             const AgentDeploymentStatus& status) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");
    if (agent_lifecycle_rank(status.status) == 5)
        return std::unexpected("invalid status");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO software_deployment_store.agent_software_status "
        "(deployment_id, agent_id, status, started_at, completed_at, error) "
        "VALUES ($1,$2,$3,$4::bigint,$5::bigint,$6) "
        "ON CONFLICT (deployment_id, agent_id) DO UPDATE SET status=EXCLUDED.status, "
        "started_at=EXCLUDED.started_at, completed_at=EXCLUDED.completed_at, "
        "error=EXCLUDED.error RETURNING deployment_id",
        std::vector<std::string>{deployment_id, status.agent_id, status.status,
                                 std::to_string(status.started_at),
                                 std::to_string(status.completed_at), status.error});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        if (is_fk_violation(res))
            return std::unexpected("deployment_id does not exist");
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "update_agent_status failed: " + PQerrorMessage(lease.get()));
    }
    return {};
}

std::expected<void, std::string>
SoftwareDeploymentStore::refresh_counts(const std::string& deployment_id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE software_deployment_store.software_deployments SET "
        "agents_success = (SELECT COUNT(*) FROM software_deployment_store.agent_software_status "
        "  WHERE deployment_id = $1 AND status = 'success'), "
        "agents_failure = (SELECT COUNT(*) FROM software_deployment_store.agent_software_status "
        "  WHERE deployment_id = $1 AND status = 'failed') "
        "WHERE id = $1 RETURNING id",
        std::vector<std::string>{deployment_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "refresh_counts failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("deployment not found");
    return {};
}

std::expected<std::vector<AgentDeploymentStatus>, std::string>
SoftwareDeploymentStore::get_agent_statuses(const std::string& deployment_id) {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kAgentStatusCols +
                      " FROM software_deployment_store.agent_software_status WHERE "
                      "deployment_id=$1 ORDER BY agent_id LIMIT $2";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{deployment_id, std::to_string(kListRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "get_agent_statuses failed: " + PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<AgentDeploymentStatus> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_agent_status(res.get(), i));
    return out;
}

std::expected<int, std::string> SoftwareDeploymentStore::active_count() {
    if (!open_)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT COUNT(*) FROM software_deployment_store.software_deployments WHERE status IN "
        "('deploying','verifying')",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kSwDeployDbErrorPrefix) +
                               "active_count failed: " + PQerrorMessage(lease.get()));
    return to_int(PQgetvalue(res.get(), 0, 0));
}

} // namespace yuzu::server
