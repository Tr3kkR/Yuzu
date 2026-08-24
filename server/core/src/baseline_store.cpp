#include "baseline_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"
#include "store_errors.hpp"
#include "utf8_sanitize.hpp"

#include <libpq-fe.h>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <format>
#include <random>
#include <unordered_map>
#include <unordered_set>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "baseline_store";

// Bounded acquires (ADR-0012 §2(a)). Reads back the push fan-out / heartbeat
// reconcile catastrophic-read path and the Guardian dashboard; writes come
// from the operator dashboard/REST only (no gRPC hot path touches this
// store). Mirrors GuaranteedStateStore's rule/meta budget (its closest
// Guardian-domain sibling, ADR-0038) rather than its tighter ingest budget —
// this store has no ingest path.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
constexpr std::chrono::milliseconds kBackfillTxnTimeout{60000};

constexpr const char* kSourcelessFingerprint = "sourceless";

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

std::string format_conflict(std::string_view detail) {
    return std::string(kConflictPrefix) + " " + std::string(detail);
}

// Same treatment as CustomPropertiesStore/RbacStore/TagStore (ADR-0041/0045/0050):
// scrub invalid UTF-8 to U+FFFD, then replace any embedded NUL the scrub leaves
// behind — PostgreSQL TEXT can't store NUL and libpq's text-format bind
// C-string-truncates at the first one (pg_exec.hpp binds via `.c_str()`, no
// explicit length). Applied to every free-text value on every write path,
// including the backfill (a bad byte at-rest in a legacy guardian-baselines.db
// must not brick the MANDATORY backfill) and read-path id/name lookups
// (consistency: a lookup must transform its argument identically to how the
// matching row's id was transformed when written, or a NUL-bearing id could
// silently miss the very row it was meant to address).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

std::optional<std::string> sha256_hex(std::string_view in) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return std::nullopt;
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0F]);
    }
    return out;
}

std::string legacy_text(sqlite3_stmt* s, int col) {
    const auto* v = sqlite3_column_text(s, col);
    return v ? std::string(reinterpret_cast<const char*>(v),
                           static_cast<std::size_t>(sqlite3_column_bytes(s, col)))
             : std::string{};
}

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

// ── Postgres schema (ADR-0055): the FINAL column set of the legacy SQLite
// store's single migration, collapsed into one v1. Unqualified DDL — the
// migration runner sets search_path to `baseline_store` for the migration
// transaction. Runtime statements below schema-qualify explicitly.
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE baselines (
                baseline_id       TEXT PRIMARY KEY,
                name              TEXT NOT NULL UNIQUE,
                description       TEXT NOT NULL DEFAULT '',
                lifecycle         TEXT NOT NULL DEFAULT 'draft',
                -- Members captured at the last deploy (JSON array of rule_ids).
                -- This is the ENFORCED set: deployed_member_rule_ids() reads it,
                -- and the detail renderer diffs it against live members. See
                -- baseline_store.hpp.
                deployed_snapshot TEXT NOT NULL DEFAULT '',
                created_by        TEXT NOT NULL DEFAULT '',
                updated_by        TEXT NOT NULL DEFAULT '',
                deployed_by       TEXT NOT NULL DEFAULT '',
                created_at        BIGINT NOT NULL DEFAULT 0,
                updated_at        BIGINT NOT NULL DEFAULT 0,
                deployed_at       BIGINT NOT NULL DEFAULT 0
            );

            -- Member Guards (M:N). rule_id references a Guard in a DIFFERENT
            -- schema (guaranteed_state_store) so there is no FK on it; a
            -- dangling member is harmless at deploy (the push builder skips
            -- it). The FK to baselines (same schema) gives delete_baseline
            -- its cascade and rejects a member row for a non-existent
            -- baseline.
            CREATE TABLE baseline_rules (
                baseline_id TEXT NOT NULL REFERENCES baselines(baseline_id) ON DELETE CASCADE,
                rule_id     TEXT NOT NULL,
                PRIMARY KEY (baseline_id, rule_id)
            );

            -- Assignment: included − excluded management groups. group_id also
            -- references a different schema (management_group_store), so no
            -- FK on it. PK on (baseline_id, group_id) makes a group's disposition
            -- unambiguous — it cannot be both included and excluded.
            CREATE TABLE baseline_groups (
                baseline_id TEXT NOT NULL REFERENCES baselines(baseline_id) ON DELETE CASCADE,
                group_id    TEXT NOT NULL,
                disposition TEXT NOT NULL,   -- 'include' | 'exclude'
                PRIMARY KEY (baseline_id, group_id)
            );

            -- Reverse-lookup indexes: which baselines reference a given guard /
            -- group (deploy slice's affected-set recompute + cross-store cleanup).
            CREATE INDEX idx_baseline_rules_rule ON baseline_rules(rule_id);
            CREATE INDEX idx_baseline_groups_group ON baseline_groups(group_id);

            -- Backfill idempotency marker (ADR-0009/0055 — RbacStore/TagStore
            -- post-#2703 fingerprint shape). A dedicated k/v row pair — NEVER
            -- inferred from any table being empty.
            CREATE TABLE baseline_store_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        )"},
    };
    return kMigrations;
}

constexpr const char* kBaselineCols =
    "baseline_id, name, description, lifecycle, deployed_snapshot, created_by, updated_by, "
    "deployed_by, created_at, updated_at, deployed_at";

Baseline read_baseline_row(PGresult* res, int i) {
    Baseline b;
    int c = 0;
    b.baseline_id = text_col(res, i, c++);
    b.name = text_col(res, i, c++);
    b.description = text_col(res, i, c++);
    b.lifecycle = text_col(res, i, c++);
    b.deployed_snapshot = text_col(res, i, c++);
    b.created_by = text_col(res, i, c++);
    b.updated_by = text_col(res, i, c++);
    b.deployed_by = text_col(res, i, c++);
    b.created_at = to_i64(PQgetvalue(res, i, c++));
    b.updated_at = to_i64(PQgetvalue(res, i, c++));
    b.deployed_at = to_i64(PQgetvalue(res, i, c++));
    return b;
}

// ── Backfill (ADR-0009/0055) ─────────────────────────────────────────────────
// Mirrors TagStore/RbacStore's post-#2703 fingerprint-verified marker shape
// (docs/postgres-store-playbook.md "Local source absence never creates
// terminal migration state on its own"), scaled to THREE tables with FKs:
// parent rows (`baselines`) are migrated per-row, direction-aware on
// `updated_at` (the DeploymentStore/TagStore shape); a baseline's member +
// assignment children are copied ONLY when its parent row was freshly
// inserted from legacy THIS pass — see the header doc comment for why a
// baseline that already existed live does not need its children re-merged.

struct LegacyBaselineRow {
    std::string baseline_id, name, description, lifecycle, deployed_snapshot, created_by,
        updated_by, deployed_by;
    std::int64_t created_at{0}, updated_at{0}, deployed_at{0};
};
struct LegacyMemberRow {
    std::string baseline_id, rule_id;
};
struct LegacyGroupRow {
    std::string baseline_id, group_id, disposition;
};
struct LegacySnapshot {
    std::vector<LegacyBaselineRow> baselines;
    std::vector<LegacyMemberRow> members;
    std::vector<LegacyGroupRow> groups;
};

void append_field(std::string& out, std::string_view v) {
    out += std::to_string(v.size());
    out += ':';
    out += v;
}
void append_field(std::string& out, std::int64_t v) { append_field(out, std::to_string(v)); }

// Deterministic canonical serialization for the content fingerprint — field
// order and delimiter matter (mirrors TagStore's canonicalize_legacy_snapshot).
// Fingerprints RAW legacy bytes, pre-any-transform: the fingerprint answers
// "is this the same FILE content", not "would it insert the same rows".
std::string canonicalize_legacy_snapshot(const LegacySnapshot& snap) {
    std::vector<std::string> brows;
    brows.reserve(snap.baselines.size());
    for (const auto& b : snap.baselines) {
        std::string r;
        append_field(r, "baseline");
        append_field(r, b.baseline_id);
        append_field(r, b.name);
        append_field(r, b.description);
        append_field(r, b.lifecycle);
        append_field(r, b.deployed_snapshot);
        append_field(r, b.created_by);
        append_field(r, b.updated_by);
        append_field(r, b.deployed_by);
        append_field(r, b.created_at);
        append_field(r, b.updated_at);
        append_field(r, b.deployed_at);
        brows.push_back(std::move(r));
    }
    std::sort(brows.begin(), brows.end());

    std::vector<std::string> mrows;
    mrows.reserve(snap.members.size());
    for (const auto& m : snap.members) {
        std::string r;
        append_field(r, "member");
        append_field(r, m.baseline_id);
        append_field(r, m.rule_id);
        mrows.push_back(std::move(r));
    }
    std::sort(mrows.begin(), mrows.end());

    std::vector<std::string> grows;
    grows.reserve(snap.groups.size());
    for (const auto& g : snap.groups) {
        std::string r;
        append_field(r, "group");
        append_field(r, g.baseline_id);
        append_field(r, g.group_id);
        append_field(r, g.disposition);
        grows.push_back(std::move(r));
    }
    std::sort(grows.begin(), grows.end());

    std::string canon = "baseline-store-legacy-fingerprint-v1\n";
    for (const auto& r : brows)
        canon += r;
    for (const auto& r : mrows)
        canon += r;
    for (const auto& r : grows)
        canon += r;
    return canon;
}

std::optional<std::string> fingerprint_legacy_snapshot(const LegacySnapshot& snap) {
    const auto hash = sha256_hex(canonicalize_legacy_snapshot(snap));
    if (!hash)
        return std::nullopt;
    return "v1:" + *hash;
}

// nullopt == a genuine read error (fail-closed); an empty snapshot with no
// error is a legitimate zero-row legacy database. All three legacy tables are
// read inside ONE deferred transaction (RAII-guarded SqliteTxn) so a legacy
// file still being written by a stale pre-migration binary yields one
// consistent cross-table snapshot — load-bearing here (unlike TagStore's
// single-table case) because a torn read across `guaranteed_state_baselines`
// and its two child tables could fingerprint/migrate a parent whose children
// were captured from a different instant.
std::optional<LegacySnapshot> read_legacy_snapshot(sqlite3* db) {
    if (sqlite3_exec(db, "BEGIN", nullptr, nullptr, nullptr) != SQLITE_OK)
        return std::nullopt;
    SqliteTxn txn(db);
    LegacySnapshot snap;
    bool ok = true;
    {
        SqliteStmt s;
        const char* sql =
            "SELECT baseline_id, name, description, lifecycle, deployed_snapshot, created_by, "
            "updated_by, deployed_by, created_at, updated_at, deployed_at FROM "
            "guaranteed_state_baselines";
        if (sqlite3_prepare_v2(db, sql, -1, s.addr(), nullptr) != SQLITE_OK) {
            ok = false;
        } else {
            int rc;
            while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
                LegacyBaselineRow b;
                b.baseline_id = legacy_text(s.get(), 0);
                b.name = legacy_text(s.get(), 1);
                b.description = legacy_text(s.get(), 2);
                b.lifecycle = legacy_text(s.get(), 3);
                b.deployed_snapshot = legacy_text(s.get(), 4);
                b.created_by = legacy_text(s.get(), 5);
                b.updated_by = legacy_text(s.get(), 6);
                b.deployed_by = legacy_text(s.get(), 7);
                b.created_at = sqlite3_column_int64(s.get(), 8);
                b.updated_at = sqlite3_column_int64(s.get(), 9);
                b.deployed_at = sqlite3_column_int64(s.get(), 10);
                snap.baselines.push_back(std::move(b));
            }
            if (rc != SQLITE_DONE)
                ok = false;
        }
    }
    if (ok) {
        SqliteStmt s;
        const char* sql = "SELECT baseline_id, rule_id FROM guaranteed_state_baseline_rules";
        if (sqlite3_prepare_v2(db, sql, -1, s.addr(), nullptr) != SQLITE_OK) {
            ok = false;
        } else {
            int rc;
            while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
                LegacyMemberRow m;
                m.baseline_id = legacy_text(s.get(), 0);
                m.rule_id = legacy_text(s.get(), 1);
                snap.members.push_back(std::move(m));
            }
            if (rc != SQLITE_DONE)
                ok = false;
        }
    }
    if (ok) {
        SqliteStmt s;
        const char* sql =
            "SELECT baseline_id, group_id, disposition FROM guaranteed_state_baseline_groups";
        if (sqlite3_prepare_v2(db, sql, -1, s.addr(), nullptr) != SQLITE_OK) {
            ok = false;
        } else {
            int rc;
            while ((rc = sqlite3_step(s.get())) == SQLITE_ROW) {
                LegacyGroupRow g;
                g.baseline_id = legacy_text(s.get(), 0);
                g.group_id = legacy_text(s.get(), 1);
                g.disposition = legacy_text(s.get(), 2);
                snap.groups.push_back(std::move(g));
            }
            if (rc != SQLITE_DONE)
                ok = false;
        }
    }
    if (ok && txn.commit() != SQLITE_OK)
        spdlog::warn("BaselineStore: read_legacy_snapshot: COMMIT failed: {}", sqlite3_errmsg(db));
    if (!ok)
        return std::nullopt;
    return snap;
}

// Path-based convenience for the holder-side verification call site: opens
// read-only, probes for corruption, and either returns the sourceless
// sentinel (no `guaranteed_state_baselines` table — same "nothing to
// protect" class as no local file at all) or fingerprints a full snapshot.
// Returns nullopt ONLY on a corrupt/unreadable file or a snapshot read
// failure — the caller MUST fail closed on that, never treat it as
// sourceless-equivalent.
std::optional<std::string> legacy_fingerprint(const std::filesystem::path& legacy_db_path) {
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
    const auto has_table = legacy_has_table(legacy.get(), "guaranteed_state_baselines");
    if (!has_table)
        return std::nullopt; // genuine read error, NOT "no table"
    if (!*has_table)
        return std::string(kSourcelessFingerprint);
    const auto snap = read_legacy_snapshot(legacy.get());
    if (!snap)
        return std::nullopt;
    return fingerprint_legacy_snapshot(*snap);
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

BaselineStore::BaselineStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("BaselineStore: no database connection at construction ({}) — Guardian "
                      "Baseline persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("BaselineStore: schema migration failed — Guardian Baseline persistence "
                      "disabled");
        return;
    }
    open_ = true;
    spdlog::info("BaselineStore initialized (schema {})", kStoreName);
}

std::string BaselineStore::generate_id() const {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr char chars[] = "0123456789abcdef";
    std::string id;
    id.reserve(12);
    std::uniform_int_distribution<int> dist(0, 15);
    for (int i = 0; i < 12; ++i)
        id += chars[dist(rng)];
    return id;
}

// ── Backfill ─────────────────────────────────────────────────────────────────

bool BaselineStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    // The marker and its source fingerprint are ALWAYS stamped together, in
    // the SAME transaction. The fingerprint write is a MONOTONIC PROMOTION
    // (never a plain ON CONFLICT DO NOTHING), ported unmodified from
    // RbacStore/TagStore: "sourceless" carries no evidence worth protecting,
    // so a real fingerprint may promote a stored "sourceless" value; a stored
    // REAL value is never overwritten; a writer whose value already equals
    // what's stored counts as success. RETURNING + PQntuples() is the correct
    // read of "did MY value end up stored" — 0 rows means a DIFFERENT real
    // value already won.
    const auto stamp_complete = [this](std::string_view source_fingerprint) -> bool {
        return pool_.with_txn_for(kBackfillTxnTimeout, [source_fingerprint](PGconn* c) -> bool {
            pg::PgResult mk = pg::exec_params(
                c,
                "INSERT INTO baseline_store.baseline_store_meta (key, value) VALUES "
                "('backfill_complete', $1) ON CONFLICT (key) DO NOTHING",
                std::vector<std::string>{std::to_string(now_epoch())});
            if (mk.status() != PGRES_COMMAND_OK) {
                spdlog::error("BaselineStore: migrate_from_sqlite: marker stamp failed: {}",
                              PQerrorMessage(c));
                return false;
            }
            pg::PgResult fp = pg::exec_params(
                c,
                "INSERT INTO baseline_store.baseline_store_meta (key, value) VALUES "
                "('backfill_source_fingerprint', $1) ON CONFLICT (key) DO UPDATE SET "
                "value = EXCLUDED.value WHERE "
                "baseline_store.baseline_store_meta.value = 'sourceless' OR "
                "baseline_store.baseline_store_meta.value = EXCLUDED.value RETURNING value",
                std::vector<std::string>{std::string(source_fingerprint)});
            if (fp.status() != PGRES_TUPLES_OK) {
                spdlog::error(
                    "BaselineStore: migrate_from_sqlite: source-fingerprint stamp failed: {}",
                    PQerrorMessage(c));
                return false;
            }
            if (PQntuples(fp.get()) == 0 && source_fingerprint != kSourcelessFingerprint) {
                spdlog::error(
                    "BaselineStore: migrate_from_sqlite: lost the race to record this backfill's "
                    "own source fingerprint — a DIFFERENT real fingerprint already stamped "
                    "backfill_source_fingerprint between this pass's marker-absent check and "
                    "this commit. Manual reconciliation required (see "
                    "docs/postgres-store-playbook.md).");
                return false;
            }
            // A sourceless stamp losing this same race is NOT an error:
            // whichever writer's "sourceless" value won is the same value
            // this call would have written.
            return true;
        });
    };

    const auto move_legacy_aside = [](const std::filesystem::path& path) {
        std::filesystem::path aside;
        for (int suffix = 0;; ++suffix) {
            aside = path;
            aside += ".migrated-" + std::to_string(now_epoch());
            if (suffix > 0)
                aside += "-" + std::to_string(suffix);
            std::error_code exists_ec;
            if (!std::filesystem::exists(aside, exists_ec))
                break;
        }
        std::error_code mv_ec;
        std::filesystem::rename(path, aside, mv_ec);
        if (mv_ec)
            spdlog::warn("BaselineStore: migrate_from_sqlite: could not move legacy {} aside "
                         "({}); it is safe to archive/remove manually",
                         path.string(), mv_ec.message());
        else
            spdlog::info("BaselineStore: migrate_from_sqlite: moved legacy db to {}",
                         aside.string());
    };

    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("BaselineStore: migrate_from_sqlite: cannot stat legacy path {}: {}",
                      legacy_db_path.string(), ec.message());
        return false;
    }

    bool marker_present = false;
    std::optional<std::string> stored_fingerprint;
    {
        auto lease = pool_.acquire(); // one-shot pre-serve boot step (ADR-0012 §2(a))
        if (!lease) {
            spdlog::error("BaselineStore: migrate_from_sqlite: no database connection ({})",
                          pool_.last_error());
            return false;
        }
        pg::PgResult mk = pg::exec_params(
            lease.get(),
            "SELECT key, value FROM baseline_store.baseline_store_meta WHERE key IN "
            "('backfill_complete', 'backfill_source_fingerprint')",
            std::vector<std::string>{});
        if (mk.status() != PGRES_TUPLES_OK) {
            spdlog::error("BaselineStore: migrate_from_sqlite: marker lookup failed: {}",
                          PQerrorMessage(lease.get()));
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
            spdlog::debug("BaselineStore: migrate_from_sqlite already completed, skipping");
            return true;
        }
        // This replica still holds a local legacy file even though the
        // marker is already set — verify it was actually the file that got
        // migrated before trusting the marker (holder-side verification).
        const auto verify_fp = legacy_fingerprint(legacy_db_path);
        if (!verify_fp) {
            spdlog::error("BaselineStore: migrate_from_sqlite: backfill_complete is already set, "
                          "and this replica's own legacy db {} exists but is unreadable/corrupt "
                          "while being fingerprint-verified — refusing (fail-closed; never "
                          "silently trust a marker over an unverifiable local file)",
                          legacy_db_path.string());
            return false;
        }
        if (*verify_fp == kSourcelessFingerprint) {
            spdlog::debug("BaselineStore: migrate_from_sqlite already completed; this replica's "
                          "own legacy db has no guaranteed_state_baselines table (nothing to "
                          "lose), skipping");
            return true;
        }
        if (!stored_fingerprint || *stored_fingerprint != *verify_fp) {
            spdlog::error(
                "BaselineStore: migrate_from_sqlite: HOLDER-SIDE VERIFICATION FAILED — "
                "backfill_complete is already set with fingerprint '{}' but this replica's own "
                "legacy db {} fingerprints as '{}' — some other replica's legacy data was "
                "migrated, not this one's (docs/postgres-store-playbook.md anti-pattern 'Local "
                "source absence never creates terminal migration state on its own'). Refusing to "
                "silently accept a completion this replica's Baselines were never part of.",
                stored_fingerprint.value_or("<none recorded>"), legacy_db_path.string(),
                *verify_fp);
            return false;
        }
        spdlog::debug("BaselineStore: migrate_from_sqlite already completed (fingerprint "
                      "verified), skipping");
        move_legacy_aside(legacy_db_path);
        return true;
    }

    if (!legacy_exists) {
        if (!stamp_complete(kSourcelessFingerprint))
            return false;
        spdlog::info("BaselineStore: migrate_from_sqlite: no legacy db at {}; marking backfill "
                     "complete (fresh install)",
                     legacy_db_path.string());
        return true;
    }

    SqliteDb legacy;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK) {
        spdlog::error("BaselineStore: migrate_from_sqlite: failed to open legacy db {}: {}",
                      legacy_db_path.string(),
                      legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
        return false;
    }
    sqlite3_exec(legacy.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    {
        SqliteStmt probe;
        if (sqlite3_prepare_v2(legacy.get(), "SELECT count(*) FROM sqlite_master", -1, probe.addr(),
                               nullptr) != SQLITE_OK ||
            sqlite3_step(probe.get()) != SQLITE_ROW) {
            spdlog::error("BaselineStore: migrate_from_sqlite: legacy db {} is unreadable/corrupt "
                          "({}); refusing backfill (fail-closed — never silently drop Guardian "
                          "Baseline enforcement config)",
                          legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
            return false;
        }
    }
    const auto has_table = legacy_has_table(legacy.get(), "guaranteed_state_baselines");
    if (!has_table) {
        spdlog::error("BaselineStore: migrate_from_sqlite: legacy db {} could not be probed for "
                      "a guaranteed_state_baselines table ({}); refusing backfill (fail-closed)",
                      legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
        return false;
    }
    if (!*has_table) {
        if (!stamp_complete(kSourcelessFingerprint))
            return false;
        spdlog::warn("BaselineStore: migrate_from_sqlite: legacy db {} has no "
                     "guaranteed_state_baselines table; marking backfill complete",
                     legacy_db_path.string());
        return true;
    }

    // Read every legacy row ONCE into a shared snapshot — both the real
    // migration below and this run's own stamp_complete fingerprint derive
    // from it (no TOCTOU window between what got migrated and what got
    // fingerprinted).
    const auto snap_opt = read_legacy_snapshot(legacy.get());
    if (!snap_opt) {
        spdlog::error("BaselineStore: migrate_from_sqlite: legacy read failed: {}",
                      sqlite3_errmsg(legacy.get()));
        return false;
    }
    const LegacySnapshot& snap = *snap_opt;
    const auto fingerprint = fingerprint_legacy_snapshot(snap);
    if (!fingerprint) {
        spdlog::error("BaselineStore: migrate_from_sqlite: failed to fingerprint legacy content "
                      "(SHA-256 digest failure) — refusing backfill (fail-closed)");
        return false;
    }

    std::vector<std::string> freshly_inserted;
    std::string failure_detail;
    const bool ok = pool_.with_txn_for(kBackfillTxnTimeout, [&](PGconn* c) -> bool {
        // Parent rows first (FK parent-before-child), sorted by baseline_id
        // for deterministic cross-replica lock-acquisition order
        // (LicenseStore precedent — avoids a deadlock between two racing
        // replicas migrating overlapping content).
        std::vector<LegacyBaselineRow> sorted_baselines = snap.baselines;
        std::sort(sorted_baselines.begin(), sorted_baselines.end(),
                  [](const auto& a, const auto& b) { return a.baseline_id < b.baseline_id; });

        for (const auto& lb : sorted_baselines) {
            // Sanitize once per row (embedded NUL / invalid UTF-8 — see
            // sanitize_pg_text's doc comment) and compare/insert using these
            // values throughout, never the raw legacy fields: a prior partial
            // backfill pass would have stored SANITIZED bytes, so a raw-vs-
            // stored compare would false-mismatch on exactly the rows
            // sanitization touched (TagStore precedent).
            const std::string lb_id = sanitize_pg_text(lb.baseline_id);
            const std::string lb_name = sanitize_pg_text(lb.name);
            const std::string lb_desc = sanitize_pg_text(lb.description);
            const std::string lb_snap = sanitize_pg_text(lb.deployed_snapshot);
            const std::string lb_created_by = sanitize_pg_text(lb.created_by);
            const std::string lb_updated_by = sanitize_pg_text(lb.updated_by);
            const std::string lb_deployed_by = sanitize_pg_text(lb.deployed_by);

            // `lifecycle` is a controlled enum on every live write path
            // (create_baseline/update_baseline never accept caller-supplied
            // free text for it) but the legacy row is unvalidated at-rest —
            // refuse a corrupt value rather than let it reach
            // deployed_member_rule_ids()'s `WHERE lifecycle = 'deployed'`
            // filter as neither draft nor deployed (silently excluded from
            // both, indistinguishable from "successfully migrated").
            if (lb.lifecycle != kBaselineDraft && lb.lifecycle != kBaselineDeployed) {
                failure_detail = std::format(
                    "legacy baseline '{}' has an invalid lifecycle '{}' (expected '{}' or '{}') "
                    "— refusing to stamp a backfill containing it",
                    lb_id, lb.lifecycle, kBaselineDraft, kBaselineDeployed);
                return false;
            }

            pg::PgResult stored = pg::exec_params(
                c,
                "SELECT name, description, lifecycle, deployed_snapshot, created_by, "
                "updated_by, deployed_by, created_at, updated_at, deployed_at FROM "
                "baseline_store.baselines WHERE baseline_id = $1",
                std::vector<std::string>{lb_id});
            if (stored.status() != PGRES_TUPLES_OK) {
                failure_detail = std::format("stored-row lookup failed for baseline '{}': {}",
                                             lb_id, PQerrorMessage(c));
                return false;
            }
            if (PQntuples(stored.get()) == 0) {
                pg::PgResult ins = pg::exec_params(
                    c,
                    "INSERT INTO baseline_store.baselines (baseline_id, name, description, "
                    "lifecycle, deployed_snapshot, created_by, updated_by, deployed_by, "
                    "created_at, updated_at, deployed_at) VALUES "
                    "($1,$2,$3,$4,$5,$6,$7,$8,$9::bigint,$10::bigint,$11::bigint) "
                    "ON CONFLICT (baseline_id) DO NOTHING",
                    std::vector<std::string>{lb_id, lb_name, lb_desc, lb.lifecycle, lb_snap,
                                             lb_created_by, lb_updated_by, lb_deployed_by,
                                             std::to_string(lb.created_at),
                                             std::to_string(lb.updated_at),
                                             std::to_string(lb.deployed_at)});
                if (ins.status() != PGRES_COMMAND_OK) {
                    const char* sqlstate_p = PQresultErrorField(ins.get(), PG_DIAG_SQLSTATE);
                    const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
                    if (sqlstate == "23505") {
                        failure_detail = std::format(
                            "legacy baseline '{}' (name '{}') collides on the UNIQUE(name) "
                            "constraint with a DIFFERENT already-live baseline_id — a name "
                            "conflict between this replica's legacy data and live Postgres data "
                            "cannot be auto-resolved (refusing; rename one side and re-run)",
                            lb_id, lb_name);
                    } else {
                        failure_detail = std::format("insert failed for baseline '{}': {}",
                                                     lb_id, PQerrorMessage(c));
                    }
                    return false;
                }
                // PQcmdTuples "0" == a concurrent writer landed this exact
                // row between our lookup and this insert — refuse rather
                // than silently mix two writers' rows mid-backfill (the
                // playbook's ON-CONFLICT-DO-NOTHING silent-discard trap).
                if (std::string_view(PQcmdTuples(ins.get())) == "0") {
                    failure_detail = std::format(
                        "concurrent writer inserted baseline '{}' mid-backfill — refusing "
                        "(re-run will compare directions cleanly)",
                        lb_id);
                    return false;
                }
                freshly_inserted.push_back(lb_id);
                continue;
            }

            // Existing row — direction-aware compare on updated_at. IDENTITY
            // is baseline_id (already matched by the PK lookup above);
            // every other column is LIFECYCLE.
            const std::string st_name = text_col(stored.get(), 0, 0);
            const std::string st_desc = text_col(stored.get(), 0, 1);
            const std::string st_life = text_col(stored.get(), 0, 2);
            const std::string st_snap = text_col(stored.get(), 0, 3);
            const std::string st_created_by = text_col(stored.get(), 0, 4);
            const std::string st_updated_by = text_col(stored.get(), 0, 5);
            const std::string st_deployed_by = text_col(stored.get(), 0, 6);
            const std::int64_t st_created_at = to_i64(PQgetvalue(stored.get(), 0, 7));
            const std::int64_t st_updated_at = to_i64(PQgetvalue(stored.get(), 0, 8));
            const std::int64_t st_deployed_at = to_i64(PQgetvalue(stored.get(), 0, 9));

            const bool identical =
                st_name == lb_name && st_desc == lb_desc && st_life == lb.lifecycle &&
                st_snap == lb_snap && st_created_by == lb_created_by &&
                st_updated_by == lb_updated_by && st_deployed_by == lb_deployed_by &&
                st_created_at == lb.created_at && st_updated_at == lb.updated_at &&
                st_deployed_at == lb.deployed_at;
            if (identical)
                continue; // benign no-op; children already match by construction
            if (st_updated_at > lb.updated_at) {
                spdlog::warn(
                    "BaselineStore: migrate_from_sqlite: Postgres baseline '{}' is strictly "
                    "ahead of the legacy row (stored updated_at={} > legacy {}) — keeping "
                    "Postgres's value (benign; this replica's legacy snapshot predates live "
                    "progress); its live members/assignment are already complete and "
                    "authoritative, legacy children for this baseline are NOT copied",
                    lb_id, st_updated_at, lb.updated_at);
                continue;
            }
            failure_detail = std::format(
                "legacy baseline '{}' {} Postgres's current value (stored updated_at={}; legacy "
                "updated_at={}) — refusing to silently discard live Guardian enforcement "
                "config; reconcile which side is authoritative before restarting",
                lb_id,
                lb.updated_at > st_updated_at ? "shows MORE progress than"
                                              : "contradicts (tied updated_at, differing content)",
                st_updated_at, lb.updated_at);
            return false;
        }

        // Children — ONLY for parents freshly inserted THIS pass (see the
        // header doc comment: a baseline that already existed live already
        // has complete, authoritative children via
        // set_members/set_assignment's atomic full-replace semantics). No
        // concurrent-writer race is possible here: the parent row is
        // uncommitted-and-invisible to every other transaction until this
        // one commits, so nothing else could have written a member/
        // assignment row against it yet.
        const std::unordered_set<std::string> fresh_set(freshly_inserted.begin(),
                                                         freshly_inserted.end());
        for (const auto& m : snap.members) {
            const std::string m_baseline_id = sanitize_pg_text(m.baseline_id);
            if (!fresh_set.contains(m_baseline_id))
                continue;
            const std::string m_rule_id = sanitize_pg_text(m.rule_id);
            pg::PgResult ins = pg::exec_params(
                c, "INSERT INTO baseline_store.baseline_rules (baseline_id, rule_id) VALUES ($1, $2)",
                std::vector<std::string>{m_baseline_id, m_rule_id});
            if (ins.status() != PGRES_COMMAND_OK) {
                failure_detail = std::format("member insert failed for ({}, {}): {}",
                                             m_baseline_id, m_rule_id, PQerrorMessage(c));
                return false;
            }
        }
        for (const auto& g : snap.groups) {
            const std::string g_baseline_id = sanitize_pg_text(g.baseline_id);
            if (!fresh_set.contains(g_baseline_id))
                continue;
            // The legacy row's disposition is unvalidated at-rest (unlike
            // set_assignment's live-write path, which rejects anything but
            // kAssignInclude/kAssignExclude before it can be persisted) —
            // refuse a corrupt value rather than silently insert a third
            // disposition string the read paths (get_assignment's include-
            // before-exclude sort, any future include/exclude-only consumer)
            // were never designed to handle.
            if (g.disposition != kAssignInclude && g.disposition != kAssignExclude) {
                failure_detail = std::format(
                    "legacy assignment row ({}, {}) has an invalid disposition '{}' (expected "
                    "'{}' or '{}') — refusing to stamp a backfill containing it",
                    g_baseline_id, g.group_id, g.disposition, kAssignInclude, kAssignExclude);
                return false;
            }
            const std::string g_group_id = sanitize_pg_text(g.group_id);
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO baseline_store.baseline_groups (baseline_id, group_id, disposition) "
                "VALUES ($1, $2, $3)",
                std::vector<std::string>{g_baseline_id, g_group_id, g.disposition});
            if (ins.status() != PGRES_COMMAND_OK) {
                failure_detail = std::format("assignment insert failed for ({}, {}): {}",
                                             g_baseline_id, g_group_id, PQerrorMessage(c));
                return false;
            }
        }
        return true;
    });

    if (!ok) {
        spdlog::error(
            "BaselineStore: migrate_from_sqlite: backfill transaction failed and was rolled "
            "back — Guardian Baseline data NOT migrated. Offending: {}. Remediation: "
            "inspect/fix the referenced row in the retained read-only legacy file ({}), then "
            "restart the server; the backfill marker was NOT stamped, so the next boot retries "
            "the whole backfill.",
            failure_detail.empty() ? "unknown (see the specific-row error above)" : failure_detail,
            legacy_db_path.string());
        return false;
    }
    if (!stamp_complete(*fingerprint))
        return false;

    spdlog::info("BaselineStore: migrate_from_sqlite: backfilled {} baseline(s) ({} fresh, {} "
                 "already-live), {} member row(s), {} assignment row(s) from {}",
                 snap.baselines.size(), freshly_inserted.size(),
                 snap.baselines.size() - freshly_inserted.size(), snap.members.size(),
                 snap.groups.size(), legacy_db_path.string());
    // Close the legacy read-only handle FIRST: Windows refuses to rename a
    // file with an open handle (ERROR_SHARING_VIOLATION) — POSIX allows it,
    // so leaving `legacy` open passes Linux/macOS CI and fails only on the
    // Windows leg (same fix as RbacStore/CustomPropertiesStore/TagStore).
    legacy.close();
    move_legacy_aside(legacy_db_path);
    return true;
}

// ── Baseline CRUD ──────────────────────────────────────────────────────────

std::expected<std::string, std::string> BaselineStore::create_baseline(const Baseline& b) {
    if (!open_)
        return std::unexpected("database not open");
    if (b.name.empty())
        return std::unexpected("baseline name cannot be empty");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    PGconn* conn = lease.get();

    const std::string id = sanitize_pg_text(b.baseline_id.empty() ? generate_id() : b.baseline_id);
    const int64_t now = now_epoch();
    const std::string lifecycle = b.lifecycle.empty() ? kBaselineDraft : b.lifecycle;
    if (lifecycle != kBaselineDraft && lifecycle != kBaselineDeployed)
        return std::unexpected("invalid lifecycle '" + lifecycle + "': must be '" +
                                std::string(kBaselineDraft) + "' or '" +
                                std::string(kBaselineDeployed) + "'");

    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO baseline_store.baselines "
        "(baseline_id, name, description, lifecycle, deployed_snapshot, created_by, updated_by, "
        " deployed_by, created_at, updated_at, deployed_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::bigint,$10::bigint,$11::bigint)",
        std::vector<std::string>{id, sanitize_pg_text(b.name), sanitize_pg_text(b.description),
                                 lifecycle, sanitize_pg_text(b.deployed_snapshot),
                                 sanitize_pg_text(b.created_by), sanitize_pg_text(b.updated_by),
                                 sanitize_pg_text(b.deployed_by), std::to_string(now),
                                 std::to_string(now), std::to_string(b.deployed_at)});
    if (res.status() != PGRES_COMMAND_OK) {
        const char* sqlstate_p = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
        if (sqlstate == "23505") {
            const char* constraint_p = PQresultErrorField(res.get(), PG_DIAG_CONSTRAINT_NAME);
            const std::string constraint = constraint_p ? constraint_p : "";
            const bool name_collision = constraint.find("_name_key") != std::string::npos;
            return std::unexpected(format_conflict(
                name_collision ? ("baseline name '" + b.name + "' already exists")
                                : ("baseline_id '" + id + "' already exists")));
        }
        return std::unexpected("insert failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    return id;
}

std::optional<Baseline> BaselineStore::get_baseline(const std::string& baseline_id,
                                                     bool* store_ok) const {
    // Optimistic, same contract as get_baseline_by_name: only a store FAULT
    // clears this; a genuine not-found leaves it true.
    if (store_ok)
        *store_ok = true;
    if (!open_) {
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    const std::string sql =
        std::string("SELECT ") + kBaselineCols + " FROM baseline_store.baselines WHERE baseline_id = $1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{sanitize_pg_text(baseline_id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("BaselineStore::get_baseline: query failed: {}",
                      PQresultErrorMessage(res.get()));
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    if (PQntuples(res.get()) == 0)
        return std::nullopt;
    return read_baseline_row(res.get(), 0);
}

std::optional<Baseline> BaselineStore::get_baseline_by_name(const std::string& name,
                                                            bool* store_ok) const {
    // Optimistic: only a store FAULT (not-open / lease-timeout / query-error)
    // clears this; a genuine not-found leaves it true so the caller 404s
    // rather than 503s (UP-13/sre-2).
    if (store_ok)
        *store_ok = true;
    if (!open_) {
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    // Names are unique (create_baseline rejects a dup); LIMIT 1 is belt-and-braces.
    const std::string sql = std::string("SELECT ") + kBaselineCols +
                            " FROM baseline_store.baselines WHERE name = $1 LIMIT 1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{sanitize_pg_text(name)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("BaselineStore::get_baseline_by_name: query failed: {}",
                      PQresultErrorMessage(res.get()));
        if (store_ok)
            *store_ok = false; // fault, not a miss → caller 503s (retryable)
        return std::nullopt;
    }
    if (PQntuples(res.get()) == 0)
        return std::nullopt;
    return read_baseline_row(res.get(), 0);
}

std::vector<Baseline> BaselineStore::list_baselines() const {
    std::vector<Baseline> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    const std::string sql =
        std::string("SELECT ") + kBaselineCols + " FROM baseline_store.baselines ORDER BY name";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("BaselineStore::list_baselines: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return out;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        out.push_back(read_baseline_row(res.get(), i));
    return out;
}

std::expected<void, std::string> BaselineStore::update_baseline(const Baseline& b) {
    if (!open_)
        return std::unexpected("database not open");
    if (b.name.empty())
        return std::unexpected("baseline name cannot be empty");
    if (b.lifecycle != kBaselineDraft && b.lifecycle != kBaselineDeployed)
        return std::unexpected("invalid lifecycle '" + b.lifecycle + "': must be '" +
                                std::string(kBaselineDraft) + "' or '" +
                                std::string(kBaselineDeployed) + "'");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    PGconn* conn = lease.get();
    const int64_t now = now_epoch();

    // RETURNING (not sqlite3_changes()-style count) so the affected-row test
    // rides in the query result — CLAUDE.md #1033.
    const std::string id = sanitize_pg_text(b.baseline_id);
    pg::PgResult res = pg::exec_params(
        conn,
        "UPDATE baseline_store.baselines SET name = $1, description = $2, lifecycle = $3, "
        "deployed_snapshot = $4, updated_by = $5, deployed_by = $6, deployed_at = $7::bigint, "
        "updated_at = $8::bigint WHERE baseline_id = $9 RETURNING baseline_id",
        std::vector<std::string>{sanitize_pg_text(b.name), sanitize_pg_text(b.description),
                                 b.lifecycle, sanitize_pg_text(b.deployed_snapshot),
                                 sanitize_pg_text(b.updated_by), sanitize_pg_text(b.deployed_by),
                                 std::to_string(b.deployed_at), std::to_string(now), id});
    if (res.status() != PGRES_TUPLES_OK) {
        const char* sqlstate_p = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
        if (sqlstate == "23505")
            return std::unexpected(format_conflict("baseline name '" + b.name + "' already exists"));
        return std::unexpected("update failed: " + std::string(PQresultErrorMessage(res.get())));
    }
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not found: baseline_id '" + b.baseline_id + "'");
    return {};
}

std::expected<void, std::string> BaselineStore::delete_baseline(const std::string& baseline_id) {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    // ON DELETE CASCADE clears the member + assignment rows. RETURNING
    // reports whether the baseline existed without a separate row-count read.
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM baseline_store.baselines WHERE baseline_id = $1 RETURNING baseline_id",
        std::vector<std::string>{sanitize_pg_text(baseline_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("delete failed: " + std::string(PQresultErrorMessage(res.get())));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not found: baseline_id '" + baseline_id + "'");
    return {};
}

// ── Member Guards (M:N) ──────────────────────────────────────────────────────

std::expected<void, std::string>
BaselineStore::set_members(const std::string& baseline_id_in,
                           const std::vector<std::string>& rule_ids) {
    if (!open_)
        return std::unexpected("database not open");
    const std::string baseline_id = sanitize_pg_text(baseline_id_in);

    std::string error;
    bool not_found = false;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // Touch-and-lock FIRST, in the SAME transaction as the replace: an
        // INSERT enforces the FK against a concurrent delete, but an EMPTY
        // member set inserts nothing, so without this the existence check
        // and the replace were racing as two separate acquisitions — a
        // delete_baseline landing between them let an empty clear() report
        // success against a since-deleted baseline (governance TOCTOU
        // finding, three independent reviewers). The row lock this UPDATE
        // takes is held for the rest of the transaction, so a concurrent
        // delete_baseline either blocks behind it (this txn's 0-row result
        // then correctly reports not-found) or has already committed (0
        // rows here, same result) — no window remains.
        pg::PgResult touch = pg::exec_params(
            c,
            "UPDATE baseline_store.baselines SET updated_at = $1::bigint "
            "WHERE baseline_id = $2 RETURNING baseline_id",
            std::vector<std::string>{std::to_string(now_epoch()), baseline_id});
        if (touch.status() != PGRES_TUPLES_OK) {
            error = "touch updated_at failed: " + std::string(PQerrorMessage(c));
            return false;
        }
        if (PQntuples(touch.get()) == 0) {
            not_found = true;
            return false;
        }
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM baseline_store.baseline_rules WHERE baseline_id = $1",
            std::vector<std::string>{baseline_id});
        if (del.status() != PGRES_COMMAND_OK) {
            error = "delete failed: " + std::string(PQerrorMessage(c));
            return false;
        }
        // Sanitize BEFORE de-duping: two distinct raw values that sanitize to
        // the same string must collapse to one insert, not a mid-transaction
        // PK violation on the second.
        std::unordered_set<std::string> seen;
        for (const auto& raw_rule_id : rule_ids) {
            const std::string rule_id = sanitize_pg_text(raw_rule_id);
            if (rule_id.empty() || !seen.insert(rule_id).second)
                continue; // skip blanks + de-dup
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO baseline_store.baseline_rules (baseline_id, rule_id) VALUES ($1, $2)",
                std::vector<std::string>{baseline_id, rule_id});
            if (ins.status() != PGRES_COMMAND_OK) {
                error = "insert member failed: " + std::string(PQerrorMessage(c));
                return false;
            }
        }
        return true;
    });
    if (not_found)
        return std::unexpected("not found: baseline_id '" + baseline_id + "'");
    if (!ok)
        return std::unexpected(error.empty() ? "transaction failed" : error);
    return {};
}

std::vector<std::string> BaselineStore::get_members(const std::string& baseline_id) const {
    return get_members_checked(baseline_id).value_or(std::vector<std::string>{});
}

std::expected<std::vector<std::string>, std::string>
BaselineStore::get_members_checked(const std::string& baseline_id) const {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT rule_id FROM baseline_store.baseline_rules WHERE baseline_id = $1 ORDER BY rule_id",
        std::vector<std::string>{sanitize_pg_text(baseline_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    std::vector<std::string> out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        out.push_back(text_col(res.get(), i, 0));
    return out;
}

std::vector<std::string>
BaselineStore::baselines_containing_rule(const std::string& rule_id) const {
    std::vector<std::string> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT baseline_id FROM baseline_store.baseline_rules WHERE rule_id = $1 ORDER BY baseline_id",
        std::vector<std::string>{sanitize_pg_text(rule_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        out.push_back(text_col(res.get(), i, 0));
    return out;
}

std::size_t BaselineStore::remove_rule_everywhere(const std::string& rule_id) {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return 0;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM baseline_store.baseline_rules WHERE rule_id = $1 RETURNING baseline_id",
        std::vector<std::string>{sanitize_pg_text(rule_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return 0;
    return static_cast<std::size_t>(PQntuples(res.get()));
}

// ── Assignment (included − excluded management groups) ───────────────────────

std::expected<void, std::string>
BaselineStore::set_assignment(const std::string& baseline_id_in,
                              const std::vector<BaselineGroupAssignment>& groups) {
    if (!open_)
        return std::unexpected("database not open");
    const std::string baseline_id = sanitize_pg_text(baseline_id_in);

    // Validate + collapse duplicates (last disposition wins) BEFORE any write,
    // so an invalid disposition aborts with nothing persisted. Insertion order
    // is irrelevant — the PK is (baseline_id, group_id). Sanitize BEFORE
    // keying the map, same reasoning as set_members: two raw group_ids that
    // sanitize identically must collapse to one map entry, not two INSERTs
    // colliding mid-transaction.
    std::unordered_map<std::string, std::string> resolved;
    for (const auto& g : groups) {
        if (g.group_id.empty())
            continue;
        if (g.disposition != kAssignInclude && g.disposition != kAssignExclude)
            return std::unexpected("invalid disposition '" + g.disposition +
                                   "' (expected 'include' or 'exclude')");
        resolved[sanitize_pg_text(g.group_id)] = g.disposition;
    }

    std::string error;
    bool not_found = false;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // Touch-and-lock FIRST, in the SAME transaction as the replace — see
        // the identical comment in set_members for why (governance TOCTOU
        // finding, three independent reviewers): the old separate existence
        // check raced the replace transaction, letting an empty assignment
        // clear() report success against a since-deleted baseline.
        pg::PgResult touch = pg::exec_params(
            c,
            "UPDATE baseline_store.baselines SET updated_at = $1::bigint "
            "WHERE baseline_id = $2 RETURNING baseline_id",
            std::vector<std::string>{std::to_string(now_epoch()), baseline_id});
        if (touch.status() != PGRES_TUPLES_OK) {
            error = "touch updated_at failed: " + std::string(PQerrorMessage(c));
            return false;
        }
        if (PQntuples(touch.get()) == 0) {
            not_found = true;
            return false;
        }
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM baseline_store.baseline_groups WHERE baseline_id = $1",
            std::vector<std::string>{baseline_id});
        if (del.status() != PGRES_COMMAND_OK) {
            error = "delete failed: " + std::string(PQerrorMessage(c));
            return false;
        }
        for (const auto& [group_id, disposition] : resolved) {
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO baseline_store.baseline_groups (baseline_id, group_id, disposition) "
                "VALUES ($1, $2, $3)",
                std::vector<std::string>{baseline_id, group_id, disposition});
            if (ins.status() != PGRES_COMMAND_OK) {
                error = "insert assignment failed: " + std::string(PQerrorMessage(c));
                return false;
            }
        }
        return true;
    });
    if (not_found)
        return std::unexpected("not found: baseline_id '" + baseline_id + "'");
    if (!ok)
        return std::unexpected(error.empty() ? "transaction failed" : error);
    return {};
}

std::vector<BaselineGroupAssignment>
BaselineStore::get_assignment(const std::string& baseline_id) const {
    std::vector<BaselineGroupAssignment> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    // Sort include-before-exclude then by group_id for a stable UI order.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT group_id, disposition FROM baseline_store.baseline_groups WHERE baseline_id = $1 "
        "ORDER BY disposition, group_id",
        std::vector<std::string>{sanitize_pg_text(baseline_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return out;
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        BaselineGroupAssignment a;
        a.group_id = text_col(res.get(), i, 0);
        a.disposition = text_col(res.get(), i, 1);
        out.push_back(std::move(a));
    }
    return out;
}

std::size_t BaselineStore::remove_group_everywhere(const std::string& group_id) {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return 0;
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM baseline_store.baseline_groups WHERE group_id = $1 RETURNING baseline_id",
        std::vector<std::string>{sanitize_pg_text(group_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return 0;
    return static_cast<std::size_t>(PQntuples(res.get()));
}

// ── Reverse lookups / counting ───────────────────────────────────────────────

std::vector<Baseline> BaselineStore::list_deployed_baselines() const {
    std::vector<Baseline> out;
    if (!open_)
        return out;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return out;
    const std::string sql = std::string("SELECT ") + kBaselineCols +
                            " FROM baseline_store.baselines WHERE lifecycle = $1 ORDER BY name";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{kBaselineDeployed});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("BaselineStore::list_deployed_baselines: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return out;
    }
    const int n = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i)
        out.push_back(read_baseline_row(res.get(), i));
    return out;
}

std::expected<std::unordered_set<std::string>, std::string>
BaselineStore::deployed_member_rule_ids() const {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    // Read only the snapshot column of every deployed Baseline in one pass
    // (one lease, no per-Baseline round-trip). The snapshot is what was
    // deployed; see the deployed_snapshot field doc + deploy_baseline().
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT baseline_id, deployed_snapshot FROM baseline_store.baselines WHERE lifecycle = $1",
        std::vector<std::string>{kBaselineDeployed});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    std::unordered_set<std::string> ids;
    const int n = PQntuples(res.get());
    for (int i = 0; i < n; ++i) {
        const std::string row_baseline_id = text_col(res.get(), i, 0);
        const std::string snap = text_col(res.get(), i, 1);
        if (snap.empty())
            continue; // never-deployed / empty snapshot contributes nothing (fail-closed)
        // allow_exceptions=false: a malformed snapshot is skipped, not thrown on.
        const auto parsed = nlohmann::json::parse(snap, nullptr, /*allow_exceptions=*/false);
        if (!parsed.is_array()) {
            // Not a corruption this store can repair — deploy_baseline only
            // ever writes an array — but silently zeroing a deployed
            // Baseline's enforced set is a coverage-shrink an operator has
            // no other signal for (governance UP-4 finding); at least log it.
            // baseline_id included (governance Gate-8 compliance-officer
            // finding — an unidentified row ordinal undercuts the log's own
            // diagnostic value on this catastrophic-read chokepoint).
            spdlog::warn("BaselineStore::deployed_member_rule_ids: baseline '{}' deployed_snapshot "
                         "is not a JSON array — contributing 0 rule_ids for this baseline",
                         row_baseline_id);
            continue;
        }
        std::size_t dropped = 0;
        for (const auto& rid : parsed) {
            if (rid.is_string())
                ids.insert(rid.get<std::string>());
            else
                ++dropped;
        }
        if (dropped > 0)
            spdlog::warn("BaselineStore::deployed_member_rule_ids: baseline '{}' deployed_snapshot "
                         "array had {} non-string element(s) — dropped, not enforced",
                         row_baseline_id, dropped);
    }
    return ids;
}

std::expected<std::vector<std::string>, std::string>
BaselineStore::deployed_member_rule_ids(const std::string& baseline_id) const {
    if (!open_)
        return std::unexpected("database not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("no database connection: " + pool_.last_error());
    // The deployed snapshot (the ENFORCED set captured at last deploy) of ONE
    // Baseline — the per-Baseline analog of the fleet-union overload above,
    // for the baseline-anchored per-device REST view. The `lifecycle =
    // deployed` filter mirrors the union overload so the two share ONE
    // definition of "what is deployed": a draft / never-deployed Baseline
    // yields {} (the "deployed:false ⟹ no guards" contract is self-enforcing
    // here, not only via the externally-empty snapshot).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT deployed_snapshot FROM baseline_store.baselines WHERE baseline_id = $1 AND "
        "lifecycle = $2",
        std::vector<std::string>{sanitize_pg_text(baseline_id), kBaselineDeployed});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected("query failed: " + std::string(PQresultErrorMessage(res.get())));
    std::vector<std::string> ids;
    if (PQntuples(res.get()) > 0) {
        const std::string snap = text_col(res.get(), 0, 0);
        if (!snap.empty()) {
            // allow_exceptions=false: a malformed snapshot is skipped, not thrown on.
            const auto parsed = nlohmann::json::parse(snap, nullptr, /*allow_exceptions=*/false);
            if (!parsed.is_array()) {
                // See the fleet-wide overload's identical note (governance UP-4).
                spdlog::warn("BaselineStore::deployed_member_rule_ids({}): deployed_snapshot is "
                             "not a JSON array — contributing 0 rule_ids",
                             baseline_id);
            } else {
                std::size_t dropped = 0;
                for (const auto& rid : parsed) {
                    if (rid.is_string())
                        ids.push_back(rid.get<std::string>());
                    else
                        ++dropped;
                }
                if (dropped > 0)
                    spdlog::warn("BaselineStore::deployed_member_rule_ids({}): deployed_snapshot "
                                 "array had {} non-string element(s) — dropped, not enforced",
                                 baseline_id, dropped);
            }
        }
    }
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    return ids;
}

std::size_t BaselineStore::baseline_count() const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    pg::PgResult res = pg::exec_params(lease.get(), "SELECT COUNT(*) FROM baseline_store.baselines",
                                       std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return 0;
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

std::size_t BaselineStore::member_count(const std::string& baseline_id) const {
    if (!open_)
        return 0;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return 0;
    pg::PgResult res = pg::exec_params(
        lease.get(), "SELECT COUNT(*) FROM baseline_store.baseline_rules WHERE baseline_id = $1",
        std::vector<std::string>{sanitize_pg_text(baseline_id)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return 0;
    return static_cast<std::size_t>(to_i64(PQgetvalue(res.get(), 0, 0)));
}

} // namespace yuzu::server
