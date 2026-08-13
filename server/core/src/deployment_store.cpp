#include "deployment_store.hpp"

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
#include <random>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "deployment_store";

// Authoritative store (ADR-0012 §1) — operator-initiated deployment intent,
// no in-memory layer behind it. Not a hot path (operator-driven, low
// frequency), so budgets are generous relative to e.g. a gRPC-heartbeat-path
// store's.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};

// gov UP-5: bounded materialization regardless of table growth — an
// operator convenience list, not a paged feed.
constexpr int kListRowCap = 10000;

// Sentinel fingerprint for "this replica's legacy file is absent, or present
// but holds no deployment_jobs table/rows worth migrating" — see
// migrate_from_sqlite's doc comment. Mirrors RbacStore's
// kSourcelessFingerprint (rbac_store.cpp).
constexpr const char* kSourcelessFingerprint = "sourceless";

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

// Canonicalizes a legacy job snapshot into a stable, order-independent
// string for fingerprinting. Sorted so the same set of rows always
// canonicalizes identically regardless of the SELECT's physical row order.
//
// Length-prefixed fields (gov fjarvis MEDIUM), not raw delimiter bytes: an
// unescaped '\x1f'/'\x1e' separator is not injective over unconstrained
// legacy TEXT — id="a", target_host="b\x1fc" and id="a\x1fb",
// target_host="c" would canonicalize identically. `append_field` writes
// each field as `<byte-length>:<bytes>`, so the boundary is determined by
// the length prefix, never by scanning for a byte that could also appear
// inside the field — the standard netstring/bencode technique. With a
// FIXED field count per row (9, exactly what's written below), this makes
// the whole encoding injective: two different (row-content) tuples can
// never produce the same byte stream.
void append_field(std::string& out, std::string_view field) {
    out += std::to_string(field.size());
    out += ':';
    out += field;
}

std::string canonicalize_legacy_jobs(const std::vector<DeploymentJob>& jobs) {
    std::vector<std::string> rows;
    rows.reserve(jobs.size());
    for (const auto& j : jobs) {
        std::string r;
        append_field(r, j.id);
        append_field(r, j.target_host);
        append_field(r, j.os);
        append_field(r, j.method);
        append_field(r, j.status);
        append_field(r, std::to_string(j.created_at));
        append_field(r, std::to_string(j.started_at));
        append_field(r, std::to_string(j.completed_at));
        append_field(r, j.error);
        rows.push_back(std::move(r));
    }
    std::sort(rows.begin(), rows.end());
    std::string canon = "deployment-legacy-fingerprint-v2\n";
    for (const auto& r : rows)
        canon += r;
    return canon;
}

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE deployment_jobs ("
         "  id            TEXT PRIMARY KEY,"
         "  target_host   TEXT NOT NULL,"
         "  os            TEXT NOT NULL DEFAULT 'linux',"
         "  method        TEXT NOT NULL DEFAULT 'manual',"
         "  status        TEXT NOT NULL DEFAULT 'pending',"
         "  created_at    BIGINT NOT NULL DEFAULT 0,"
         "  started_at    BIGINT NOT NULL DEFAULT 0,"
         "  completed_at  BIGINT NOT NULL DEFAULT 0,"
         "  error         TEXT NOT NULL DEFAULT '');"
         "CREATE INDEX idx_deployment_status ON deployment_jobs(status);"
         "CREATE INDEX idx_deployment_created ON deployment_jobs(created_at);"
         // ADR-0009 backfill idempotency — content-fingerprinted, not a
         // single completion flag (adversarial-review hardening round,
         // 2026-08-12; see the file header and migrate_from_sqlite's doc
         // comment for why a single-row marker is unsafe and what this
         // table does instead). One row per DISTINCT legacy-file content
         // (or the sourceless sentinel) ever observed by any replica.
         "CREATE TABLE sqlite_backfill_source ("
         "  fingerprint  TEXT PRIMARY KEY,"
         "  completed_at BIGINT NOT NULL);"},
    };
    return kMigrations;
}

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

// Only used against legacy SQLite text columns (may be nullptr).
const char* safe(const char* p) {
    return p ? p : "";
}

bool is_valid_hostname_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '.' || c == '_' || c == '-';
}

DeploymentJob read_job(PGresult* res, int i) {
    DeploymentJob j;
    int col = 0;
    j.id = PQgetvalue(res, i, col++);
    j.target_host = PQgetvalue(res, i, col++);
    j.os = PQgetvalue(res, i, col++);
    j.method = PQgetvalue(res, i, col++);
    j.status = PQgetvalue(res, i, col++);
    j.created_at = to_i64(PQgetvalue(res, i, col++));
    j.started_at = to_i64(PQgetvalue(res, i, col++));
    j.completed_at = to_i64(PQgetvalue(res, i, col++));
    j.error = PQgetvalue(res, i, col++);
    return j;
}

constexpr const char* kJobCols =
    "id, target_host, os, method, status, created_at, started_at, completed_at, error";

} // namespace

// ── ID generation ────────────────────────────────────────────────────────────

// Mirrors AccessReviewStore::generate_campaign_id — a 64-bit mt19937_64 value
// formatted as 16 hex chars. NOT a cryptographic random source: `id` is a
// non-security surrogate key (uniqueness, not unguessability, is what
// matters — nothing is authorized by knowing a deployment job id). Preserves
// the pre-migration SQLite store's exact ID format.
std::string DeploymentStore::generate_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::uint64_t> dist;
    char buf[17]{};
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(dist(rng)));
    return std::string{buf};
}

// ── Construction ─────────────────────────────────────────────────────────────

DeploymentStore::DeploymentStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("DeploymentStore: no database connection at construction ({}) — "
                      "deployment persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("DeploymentStore: schema migration failed — deployment persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

// ── Backfill (ADR-0043) ───────────────────────────────────────────────────
//
// Content-fingerprinted, not a single fleet-wide completion flag: completion
// is tracked PER DISTINCT LEGACY-FILE CONTENT, so a fileless replica's
// "nothing to backfill" stamp can never satisfy a holder replica's real data
// (docs/postgres-store-playbook.md "Local source absence never creates
// terminal migration state on its own"). A fileless (or schema-less/empty)
// replica computes and stamps the sourceless sentinel; a replica holding
// real rows computes a SHA-256 fingerprint of its own content (length-
// prefixed field encoding — see canonicalize_legacy_jobs below, chosen for
// provable injectivity over raw-delimiter encoding) and checks/stamps that
// specific value.
//
// Per-row conflict handling on `id` (`ON CONFLICT (id) DO NOTHING`)
// partitions the compared columns into two classes, because they behave
// differently after a row is first migrated:
//
//   - IDENTITY (target_host, os, method, created_at): set once at INSERT
//     and never mutated afterward — update_status/cancel_job (below) touch
//     only the lifecycle columns. A conflicting row whose identity differs
//     is therefore provably outside this store's model (corruption, a
//     hand-edited legacy file, or an astronomical collision on the random
//     64-bit generate_id() surrogate key) and fails the boot closed, naming
//     the offending id.
//   - LIFECYCLE (status, started_at, completed_at, error): legitimately
//     changes post-migration via live traffic on whichever replica migrated
//     the row first. A legacy snapshot showing an earlier lifecycle state
//     for the SAME identity is the ordinary shape of that progress, not a
//     conflict — Postgres already holds the live, authoritative value for
//     that id, so this is a benign no-op. The drift is WARNING-logged
//     (naming both values) rather than silently swallowed, so it stays
//     visible to an operator; it never blocks the boot.
//
// Deliberately simpler than RbacStore's post-#2703 reference shape (refuse
// on ANY column mismatch, docs/ops-runbooks/rbac-store-backfill-recovery.md):
// RBAC identifiers are small and human-chosen, so two independently-
// authored grants can legitimately collide on name and both need operator
// adjudication. DeploymentStore's id is random and machine-generated, so a
// shared id is always the SAME logical job observed twice (via cloned or
// restored legacy files sharing a common origin, or a replica re-reading
// its own already-migrated file) — never two independently-valuable rows
// that happen to collide — which is what makes "identity fixed, lifecycle
// may have moved on" the correct comparison instead of a byte-for-byte one.
//
// SQL shape note: this uses plain `DO NOTHING` plus a separate read-back
// `SELECT` and an application-level comparison, which deliberately diverges
// from docs/postgres-store-playbook.md's `DO UPDATE ... WHERE <condition>
// RETURNING` recipe for "two writers can legitimately agree on identical
// content." Backfill-vs-backfill is lock-safe (Postgres blocks the
// conflicting INSERT until the winner commits), so the only live race
// window is against an already-serving sibling's normal traffic on that
// exact row between the failed insert and the read-back — worst case a
// spurious fail-closed boot on a genuine identity mismatch, never silent
// data loss, so the simpler two-statement shape was kept over the atomic
// recipe.
//
// Trade-off accepted: this reads the local legacy file (if present) on
// EVERY boot rather than short-circuiting on a single marker, because
// "already migrated" is now a content-addressed question that can only be
// answered by hashing the content. Acceptable here — the file is small (ad
// hoc deployment jobs, not a high-volume table) and boots are infrequent.
// RbacStore avoids this cost by MOVING its legacy file aside after a
// successful migration; this store deliberately does not (matches
// ResultSetStore's retained-for-rollback-window choice, ADR-0009's
// one-release retention — moving the file would also complicate that
// cleanup story for no correctness benefit here).

bool DeploymentStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("DeploymentStore::migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        return false;
    }

    std::string fingerprint;
    std::vector<DeploymentJob> legacy_jobs;
    if (!legacy_exists) {
        fingerprint = kSourcelessFingerprint;
    } else {
        // Read the legacy SQLite file READ-ONLY. It is retained by the
        // caller (never deleted/moved here) for the ADR-0009 one-release
        // rollback window. SqliteDb/SqliteStmt (gov cpp-safety): close/
        // finalize on every path — including an exception thrown mid
        // read-loop — so no early return here can leak the connection or a
        // prepared statement.
        SqliteDb legacy;
        if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                            nullptr) != SQLITE_OK) {
            spdlog::error("DeploymentStore::migrate_from_sqlite: failed to open legacy {}: {}",
                          legacy_db_path.string(),
                          legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
            return false;
        }

        bool has_table = false;
        {
            SqliteStmt probe;
            if (sqlite3_prepare_v2(legacy.get(),
                                   "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
                                   "name='deployment_jobs'",
                                   -1, probe.addr(), nullptr) != SQLITE_OK) {
                spdlog::error("DeploymentStore::migrate_from_sqlite: schema probe failed on "
                              "legacy {}: {}",
                              legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
                return false;
            }
            if (sqlite3_step(probe.get()) != SQLITE_ROW) {
                spdlog::error("DeploymentStore::migrate_from_sqlite: schema probe step failed "
                              "on legacy {}: {}",
                              legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
                return false;
            }
            has_table = sqlite3_column_int64(probe.get(), 0) > 0;
        }

        if (!has_table) {
            // A present-but-schema-less file (e.g. a stray empty SQLite
            // file) has nothing to protect — same "nothing to lose" class
            // as no file at all.
            fingerprint = kSourcelessFingerprint;
        } else {
            SqliteStmt s;
            const char* sql =
                "SELECT id, target_host, os, method, status, created_at, started_at, "
                "completed_at, error FROM deployment_jobs ORDER BY created_at ASC, id ASC;";
            if (sqlite3_prepare_v2(legacy.get(), sql, -1, s.addr(), nullptr) != SQLITE_OK) {
                spdlog::error("DeploymentStore::migrate_from_sqlite: legacy deployment_jobs "
                              "query failed: {}",
                              sqlite3_errmsg(legacy.get()));
                return false;
            }
            int step_rc = SQLITE_OK;
            while ((step_rc = sqlite3_step(s.get())) == SQLITE_ROW) {
                DeploymentJob j;
                j.id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 0)));
                j.target_host =
                    safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 1)));
                j.os = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 2)));
                j.method = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 3)));
                j.status = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 4)));
                j.created_at = sqlite3_column_int64(s.get(), 5);
                j.started_at = sqlite3_column_int64(s.get(), 6);
                j.completed_at = sqlite3_column_int64(s.get(), 7);
                j.error = safe(reinterpret_cast<const char*>(sqlite3_column_text(s.get(), 8)));
                legacy_jobs.push_back(std::move(j));
            }
            // H2 (governance): require the terminal code to be SQLITE_DONE —
            // a corrupt page or I/O error mid-scan otherwise truncates the
            // legacy set silently, and a fingerprint computed over a
            // partial read would stamp completion over a partial copy,
            // permanently. ADR-0009: fail closed on ANY error, including
            // read-side ones — this now happens BEFORE any Postgres round
            // trip at all, so a corrupt file can never even reach the
            // fingerprint-lookup step below.
            if (step_rc != SQLITE_DONE) {
                spdlog::error("DeploymentStore::migrate_from_sqlite: legacy deployment_jobs "
                              "scan aborted mid-read (rc={} {}): refusing to stamp a partial "
                              "backfill",
                              step_rc, sqlite3_errmsg(legacy.get()));
                return false;
            }
            if (legacy_jobs.empty()) {
                fingerprint = kSourcelessFingerprint;
            } else {
                fingerprint = sha256_hex(canonicalize_legacy_jobs(legacy_jobs));
                if (fingerprint.empty()) {
                    spdlog::error("DeploymentStore::migrate_from_sqlite: SHA-256 hashing failed "
                                  "for legacy content at {} — refusing (fail-closed)",
                                  legacy_db_path.string());
                    return false;
                }
            }
        }
    }
    // `legacy` (if opened) closed here via SqliteDb's destructor.

    // Has THIS specific fingerprint already been processed — by this
    // replica's own prior boot, or (for the sourceless sentinel) any
    // replica's? Unbounded acquire() here is construction-time discipline
    // (ADR-0012 §2(a)) — this runs once at boot, before serving.
    {
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("DeploymentStore::migrate_from_sqlite: no database connection");
            return false;
        }
        pg::PgResult marker = pg::exec_params(
            lease.get(), "SELECT 1 FROM deployment_store.sqlite_backfill_source WHERE fingerprint=$1",
            std::vector<std::string>{fingerprint});
        if (marker.status() != PGRES_TUPLES_OK) {
            spdlog::error("DeploymentStore::migrate_from_sqlite: backfill-marker check failed: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        if (PQntuples(marker.get()) > 0) {
            spdlog::debug("DeploymentStore::migrate_from_sqlite: fingerprint already processed, "
                          "skipping");
            return true;
        }
    }

    if (fingerprint == kSourcelessFingerprint) {
        // Nothing to copy — stamp the sourceless sentinel so this (fileless
        // or schema-less) replica short-circuits on future boots. Scoped to
        // itself: a DIFFERENT, holder replica's real fingerprint is a
        // different primary-key value and is never satisfied by this row
        // (the invariant this whole redesign exists to guarantee).
        auto lease = pool_.acquire();
        if (!lease) {
            spdlog::error("DeploymentStore::migrate_from_sqlite: no connection to stamp marker");
            return false;
        }
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO deployment_store.sqlite_backfill_source (fingerprint, completed_at) "
            "VALUES ($1, $2::bigint) ON CONFLICT (fingerprint) DO NOTHING",
            std::vector<std::string>{fingerprint, std::to_string(now_epoch())});
        if (r.status() != PGRES_COMMAND_OK) {
            spdlog::error("DeploymentStore::migrate_from_sqlite: failed to stamp marker: {}",
                          PQerrorMessage(lease.get()));
            return false;
        }
        spdlog::info("DeploymentStore::migrate_from_sqlite: no legacy deployment jobs at {} — "
                     "nothing to backfill",
                     legacy_db_path.string());
        return true;
    }

    spdlog::info("DeploymentStore::migrate_from_sqlite: backfilling {} deployment job(s) from {}",
                 legacy_jobs.size(), legacy_db_path.string());

    // ONE transaction: fail closed on any error, nothing partially committed
    // (ADR-0009). Unbounded with_txn (not with_txn_for): startup is serial,
    // same discipline as the ctor's unbounded acquire() (ADR-0012 §2(a)).
    std::string failure_detail;
    bool ok = pool_.with_txn([&](PGconn* conn) -> bool {
        for (const auto& j : legacy_jobs) {
            // RETURNING id + PQntuples() (never a bare PGRES_COMMAND_OK check on
            // an ON CONFLICT DO NOTHING insert, gov fjarvis BLOCKING /
            // docs/postgres-store-playbook.md's own "Anti-patterns reviewers
            // reject"): PGRES_COMMAND_OK only proves the STATEMENT executed,
            // never that THIS row won the conflict — a same-id row already
            // present (e.g. from a second legacy file with overlapping ids,
            // such as a cloned/restored data directory) silently no-ops, and
            // the fingerprint stamped at the end of this transaction would
            // make that permanent: the file is never reconsidered.
            pg::PgResult res = pg::exec_params(
                conn,
                "INSERT INTO deployment_store.deployment_jobs "
                "(id, target_host, os, method, status, created_at, started_at, completed_at, "
                " error) VALUES ($1,$2,$3,$4,$5,$6::bigint,$7::bigint,$8::bigint,$9) "
                "ON CONFLICT (id) DO NOTHING RETURNING id",
                std::vector<std::string>{j.id, j.target_host, j.os, j.method, j.status,
                                         std::to_string(j.created_at),
                                         std::to_string(j.started_at),
                                         std::to_string(j.completed_at), j.error});
            if (res.status() != PGRES_TUPLES_OK) {
                failure_detail = std::string("legacy deployment_jobs row id='") + j.id +
                                 "' (target_host='" + j.target_host + "'): " +
                                 PQerrorMessage(conn);
                spdlog::error("DeploymentStore::migrate_from_sqlite: insert of {} failed: {}",
                              j.id, PQerrorMessage(conn));
                return false;
            }
            if (PQntuples(res.get()) > 0)
                continue; // inserted cleanly — no conflict, nothing further to check

            // Conflict: a row with this id already exists. An `ON CONFLICT`
            // match is on id ALONE — Postgres never compares the other
            // columns — so this does NOT by itself mean the content differs.
            // Read the existing row back and compare it in two classes (see
            // the design note above migrate_from_sqlite): an IDENTITY
            // mismatch (target_host/os/method/created_at) is provably
            // outside this store's model and fails closed; a LIFECYCLE-only
            // difference (status/started_at/completed_at/error) is the
            // ordinary shape of post-migration progress and is a benign
            // no-op — Postgres's live value is kept, and the drift is
            // WARNING-logged rather than silently swallowed.
            std::string existing_sql = std::string("SELECT ") + kJobCols +
                                       " FROM deployment_store.deployment_jobs WHERE id=$1";
            pg::PgResult existing =
                pg::exec_params(conn, existing_sql.c_str(), std::vector<std::string>{j.id});
            if (existing.status() != PGRES_TUPLES_OK || PQntuples(existing.get()) == 0) {
                failure_detail = std::string("legacy deployment_jobs row id='") + j.id +
                                 "': conflicted on insert but the existing row could not be "
                                 "read back for comparison: " +
                                 PQerrorMessage(conn);
                spdlog::error("DeploymentStore::migrate_from_sqlite: row {} conflicted but "
                              "the existing row read-back failed: {}",
                              j.id, PQerrorMessage(conn));
                return false;
            }
            const DeploymentJob stored = read_job(existing.get(), 0);
            const bool identity_matches =
                stored.target_host == j.target_host && stored.os == j.os &&
                stored.method == j.method && stored.created_at == j.created_at;
            if (!identity_matches) {
                failure_detail =
                    std::string("legacy deployment_jobs row id='") + j.id +
                    "' already exists with DIFFERENT identity (stored: target_host='" +
                    stored.target_host + "' os='" + stored.os + "' method='" + stored.method +
                    "' created_at=" + std::to_string(stored.created_at) +
                    "; legacy: target_host='" + j.target_host + "' os='" + j.os +
                    "' method='" + j.method + "' created_at=" + std::to_string(j.created_at) +
                    ") — refusing to silently discard it";
                spdlog::error("DeploymentStore::migrate_from_sqlite: row {} conflicts with "
                              "different IDENTITY — refusing to stamp a backfill that would "
                              "silently discard it",
                              j.id);
                return false;
            }
            const bool lifecycle_matches =
                stored.status == j.status && stored.started_at == j.started_at &&
                stored.completed_at == j.completed_at && stored.error == j.error;
            if (lifecycle_matches) {
                spdlog::debug("DeploymentStore::migrate_from_sqlite: row {} already present "
                              "with identical content, skipping (benign no-op)",
                              j.id);
            } else {
                spdlog::warn(
                    "DeploymentStore::migrate_from_sqlite: row {} already migrated with "
                    "lifecycle progress since this legacy snapshot was taken (legacy "
                    "status='{}' vs current status='{}') — keeping the current Postgres "
                    "value; this is expected on a replica whose legacy file predates that "
                    "progress, not a conflict",
                    j.id, j.status, stored.status);
            }
            continue;
        }
        pg::PgResult marker = pg::exec_params(
            conn,
            "INSERT INTO deployment_store.sqlite_backfill_source (fingerprint, completed_at) "
            "VALUES ($1, $2::bigint) ON CONFLICT (fingerprint) DO NOTHING",
            std::vector<std::string>{fingerprint, std::to_string(now_epoch())});
        if (marker.status() != PGRES_COMMAND_OK) {
            failure_detail = std::string("backfill marker stamp: ") + PQerrorMessage(conn);
            spdlog::error("DeploymentStore::migrate_from_sqlite: failed to stamp backfill "
                          "marker: {}",
                          PQerrorMessage(conn));
            return false;
        }
        return true;
    });
    if (!ok) {
        spdlog::error(
            "DeploymentStore::migrate_from_sqlite: backfill transaction failed and was rolled "
            "back — deployment job data NOT migrated. Offending: {}. Remediation: inspect/fix "
            "the referenced row in the retained read-only legacy file ({}) — e.g. `sqlite3 {} "
            "\"SELECT * FROM deployment_jobs WHERE id='<id>'\"` — then restart the server; the "
            "backfill marker was NOT stamped, so the next boot retries the whole backfill.",
            failure_detail.empty() ? "unknown (see the specific-row error above)" : failure_detail,
            legacy_db_path.string(), legacy_db_path.string());
        return false;
    }
    spdlog::info("DeploymentStore::migrate_from_sqlite: backfill complete");
    return true;
}

// ── Operations ───────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
DeploymentStore::create_job(const std::string& target_host, const std::string& os,
                            const std::string& method) {
    if (!open_)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database not open");

    if (target_host.empty())
        return std::unexpected("target_host is required");

    // Validate hostname: must match DNS rules — [a-zA-Z0-9._-] only, max 253
    // chars. The REST layer's manual-deployment install command
    // (discovery_routes.cpp) is a fixed per-OS string that does NOT
    // interpolate target_host today — this allowlist is defense-in-depth
    // against a future caller (e.g. an "ssh" method executor) templating a
    // shell/SSH command from this field without its own validation, not a
    // guard against an injection this store's current callers can reach.
    if (target_host.size() > 253)
        return std::unexpected("target_host exceeds DNS limit of 253 characters");
    if (!std::all_of(target_host.begin(), target_host.end(), is_valid_hostname_char))
        return std::unexpected(
            "target_host contains invalid characters (only [a-zA-Z0-9._-] allowed)");
    // A leading '-' is a valid DNS-allowlist character sequence but never a
    // valid DNS label (RFC 1123: a label starts/ends alphanumeric) — it is
    // also exactly the SSH-option-injection shape ("-oProxyCommand=...",
    // "-Jjump.host", "-Ffile") the allowlist's own doc comment names as the
    // future risk it defends against (gov fjarvis MEDIUM — empirically
    // verified: "-Jjump.evil.com"/"-Ffile" passed the allowlist above before
    // this check existed). Reject it now, while it is still free.
    if (target_host.front() == '-' || target_host.back() == '-')
        return std::unexpected("target_host must not start or end with '-'");

    if (os != "windows" && os != "linux" && os != "darwin")
        return std::unexpected("os must be windows, linux, or darwin");

    if (method != "ssh" && method != "group_policy" && method != "manual")
        return std::unexpected("method must be ssh, group_policy, or manual");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database unavailable — try again");

    const std::string id = generate_id();
    const std::int64_t now = now_epoch();
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO deployment_store.deployment_jobs "
        "(id, target_host, os, method, status, created_at) "
        "VALUES ($1,$2,$3,$4,'pending',$5::bigint) RETURNING id",
        std::vector<std::string>{id, target_host, os, method, std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "create_job failed: " +
                               PQerrorMessage(lease.get()));

    spdlog::info("DeploymentStore: created job {} for {} ({})", id, target_host, method);
    return id;
}

std::expected<std::vector<DeploymentJob>, std::string> DeploymentStore::list_jobs() {
    if (!open_)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kJobCols +
                      " FROM deployment_store.deployment_jobs ORDER BY created_at DESC LIMIT $1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{std::to_string(kListRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "list_jobs failed: " +
                               PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<DeploymentJob> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_job(res.get(), i));
    return out;
}

std::expected<std::optional<DeploymentJob>, std::string>
DeploymentStore::get_job(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database unavailable — try again");

    std::string sql =
        std::string("SELECT ") + kJobCols + " FROM deployment_store.deployment_jobs WHERE id=$1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "get_job failed: " +
                               PQerrorMessage(lease.get()));

    if (PQntuples(res.get()) == 0)
        return std::optional<DeploymentJob>{std::nullopt};
    return std::optional<DeploymentJob>{read_job(res.get(), 0)};
}

std::expected<void, std::string>
DeploymentStore::update_status(const std::string& id, const std::string& status,
                               const std::string& error) {
    if (!open_)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database not open");

    if (status != "pending" && status != "running" && status != "completed" &&
        status != "failed" && status != "cancelled")
        return std::unexpected("invalid status");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database unavailable — try again");

    const std::int64_t now = now_epoch();
    pg::PgResult res;
    if (status == "running") {
        res = pg::exec_params(
            lease.get(),
            "UPDATE deployment_store.deployment_jobs SET status=$1, started_at=$2::bigint, "
            "error=$3 WHERE id=$4 RETURNING id",
            std::vector<std::string>{status, std::to_string(now), error, id});
    } else if (status == "completed" || status == "failed") {
        res = pg::exec_params(
            lease.get(),
            "UPDATE deployment_store.deployment_jobs SET status=$1, completed_at=$2::bigint, "
            "error=$3 WHERE id=$4 RETURNING id",
            std::vector<std::string>{status, std::to_string(now), error, id});
    } else {
        res = pg::exec_params(
            lease.get(),
            "UPDATE deployment_store.deployment_jobs SET status=$1, error=$2 WHERE id=$3 "
            "RETURNING id",
            std::vector<std::string>{status, error, id});
    }
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "update_status failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("job not found");
    return {};
}

std::expected<void, std::string> DeploymentStore::cancel_job(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "database unavailable — try again");

    // Single guarded UPDATE — no separate check-then-write round trip, so a
    // concurrent second cancel or status update can never race this into an
    // inconsistent state (the mutation itself is race-safe regardless of
    // what follows below).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE deployment_store.deployment_jobs SET status='cancelled', "
        "error='cancelled by operator' WHERE id=$1 AND status IN ('pending','running') "
        "RETURNING id",
        std::vector<std::string>{id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) + "cancel_job failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) > 0)
        return {};

    // Zero rows matched — distinguish not-found from wrong-state for the
    // caller's error message. Best-effort ONLY with respect to a concurrent
    // writer racing the UPDATE above (that can change which of the two
    // business-error cases applies, never the guarded UPDATE's own
    // correctness) — a genuine READ FAILURE on this disambiguation query is
    // NOT folded into "job not found" (gov consistency-auditor finding,
    // hardening round): that would misreport a DB outage as a business
    // error and lose the kDeploymentDbErrorPrefix the route classifier
    // depends on, exactly the defect class this commit closes elsewhere.
    pg::PgResult check = pg::exec_params(
        lease.get(), "SELECT status FROM deployment_store.deployment_jobs WHERE id=$1",
        std::vector<std::string>{id});
    if (check.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeploymentDbErrorPrefix) +
                               "cancel_job disambiguation read failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(check.get()) > 0)
        return std::unexpected("only pending or running jobs can be cancelled");
    return std::unexpected("job not found");
}

} // namespace yuzu::server
