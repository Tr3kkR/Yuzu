#include "rbac_store.hpp"

#include "management_group_store.hpp"
#include "migration_runner.hpp"
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rbac_generation_rules.hpp"
#include "sqlite_raii.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <functional>
#include <optional>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "rbac_store";

// Bounded acquires (ADR-0012 §2(a)). Reads back interactive REST/dashboard/MCP
// callers; writes get a slightly wider budget. Backfill runs single-threaded at
// construction before serving, so a wide deadline is fine.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
// Availability hardening (governance re-review, #2703 Gate 7 — Fable-reviewed
// merge slice, item 1 commit A). The hot authz path (`maybe_refresh_generation`,
// `check_permission`'s own acquire, and `resolve_perm_groups`'s two acquires via
// `user_rbac_group_names`/`role_effects_for`) is on the request-serving critical
// path for EVERY confined operator action, so it uses this short acquire budget
// instead of `kReadTimeout` — under a saturated pool a wave of concurrent authz
// checks pins each HTTP worker for at most ~250ms instead of ~2s, bounding how
// much of the shared `http_worker` pool a Postgres degrade can exhaust before
// the item-1-commit-B breaker (next commit) trips. CRUD/admin RbacStore calls
// (`assign_role`, `set_permission`, catalogue listings, etc.) are operator-driven,
// not per-request, and keep the wider `kReadTimeout` — matches
// `docs/postgres-store-playbook.md`'s hot-path-vs-admin acquire-budget split.
constexpr std::chrono::milliseconds kAuthzAcquireTimeout{250};
// sre (Gate 6, #2703): bounds `with_txn_for`'s connection ACQUIRE only
// (`try_acquire_for`) — not the transaction's own duration once a connection
// is held. The advisory lock this backfill now takes first (kRevokeCoordLockSql)
// can block for longer than this if contended; that block is inside the held
// connection and is not counted against this deadline.
constexpr std::chrono::milliseconds kBackfillTxnTimeout{60000};

// chaos-injector (Gate 5, #2703, HIGH — CHAOS-1, verified against live PG):
// serializes every writer of the seed/revoke pair — seed_defaults()'s
// grant(), remove_permission(), and migrate_from_sqlite()'s F1 revoke block —
// against each other. Without this, grant()'s `INSERT ... SELECT ... WHERE
// NOT EXISTS (marker) ... ON CONFLICT DO NOTHING` can resurrect an
// already-revoked permission: if grant()'s statement snapshot is taken
// BEFORE a concurrent revoke's marker-insert+DELETE commits, but grant()
// then blocks on the ON-CONFLICT arbiter waiting for that same uncommitted
// DELETE, Postgres only re-checks the CONFLICT TARGET after the wait — it
// does NOT re-evaluate the WHERE NOT EXISTS subquery, which is fixed at the
// original (pre-revoke) snapshot. Once the revoke's DELETE commits, the
// conflict is gone and grant()'s already-computed INSERT lands anyway,
// leaving the marker AND the resurrected row both present, permanently
// (nothing ever re-syncs role_permissions against revoked_seed_defaults).
// The LOCK must be acquired in its OWN statement, in an explicit
// transaction, strictly BEFORE the statement that checks-and-mutates —
// embedding the lock in the same statement via a CTE does NOT work: a
// single statement's READ COMMITTED snapshot is fixed at that statement's
// start, before any of its own function calls (including a blocking
// pg_advisory_xact_lock) run, so blocking mid-statement never refreshes it.
// Verified empirically both ways. Coarse-grained (one fixed key, not
// per-triple): RBAC writes are boot-time seeding + rare admin actions, never
// a hot path, so cluster-wide serialization across all triples is cheap and
// avoids needing per-triple lock keys for the backfill's bulk (multi-row,
// array-parameterized) F1 statement. Two-int32 form + the "yuzu" namespace
// constant matches house convention (pg_migration_runner.cpp, auth_db.cpp,
// secret_codec.cpp, kek_op_lock.hpp) — 2037545589 is "yuzu" as big-endian
// ASCII, hashtext() of a descriptive string differentiates the feature.
constexpr const char* kRevokeCoordLockSql =
    "SELECT pg_advisory_xact_lock(2037545589, hashtext('rbac_store:revoke_coordination'))";

// Cross-replica permission-cache coherence (ADR-0041): re-validate the durable
// generation token at most this often on the read hot path.
constexpr std::int64_t kRbacGenerationRefreshMs = 1000;

// Bounded stale-serve (governance re-review, #2703 Gate 7 — operator-adjudicated
// design decision, availability-vs-strictness tradeoff): when a generation
// refresh FAILS (pool timeout, query error — distinct from the gated/in-flight
// case above, which never touches this), keep serving the last-known-good
// cache/enabled-state for up to this long past the last successful refresh
// before dropping trust in it. A refresh failure shorter than this window no
// longer forces perm_cache_ to empty (avoiding a fleet-wide cache-miss storm on
// a short Postgres blip) and no longer flips rbac_enforcement_in_effect() to
// "enforce" for an RBAC-disabled fleet (avoiding a spurious deny-all on a
// fleet that never turned RBAC on). Deliberately several multiples of
// kRbacGenerationRefreshMs: it bounds how stale a cross-replica revocation can
// observably be UNDER DEGRADE ONLY (the ~1s target above is for the healthy
// case), not the routine steady-state latency.
constexpr std::int64_t kRbacStaleServeBoundMs = 5000;

// Fail-fast breaker (#2703 Gate 7 merge-slice item 1 commit B, operator-
// adjudicated: trip fast). 2 consecutive failed pool touches on the authz
// hot path (acquire timeout OR a query error once acquired — e.g. a
// statement cancelled by PgPool's injected lock_timeout, the measured
// table-lock scenario, where the ACQUIRE succeeds and the query itself
// blocks) opens the breaker: every subsequent authz call is denied WITHOUT
// touching the pool until one probe per cooldown succeeds. Deliberately
// small (2, not e.g. 5) — the goal is bounding the FIRST wave's exposure,
// not waiting for a confident failure signal; kAuthzAcquireTimeout above
// already keeps a single failed attempt cheap (~250ms), so trip-fast costs
// little even on a false-positive (one genuinely-slow-but-healthy query).
constexpr int kBreakerTripThreshold = 2;

// Read-degrade reason labels (ADR-0037 convention). A !open_ store fails boot
// closed (never serves), so only the pool-timeout / query-error hot-path
// degrades are counted here.
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
// DENYING: fires only once a failed refresh is past kRbacStaleServeBoundMs
// and the cache is actually cleared (see maybe_refresh_generation). Must
// stay denial-only — YuzuRbacReadDegraded (docs/prometheus/yuzu-alerts.yml)
// is a severity:critical alert whose own design rationale is "never fold in
// a reason that can fire without denying anyone"; that rationale is exactly
// why kReasonRefreshFailedWithinBound below exists as a separate value
// rather than sharing this one (#2703 Gate 7 merge-slice, found during doc
// cross-check: the pre-split single reason violated that same rationale the
// moment the bounded stale-serve window shipped).
constexpr const char* kReasonRefreshFailed = "generation_refresh_failed";
// fjarvis F2 (#2703): the durable rbac_enabled row read back as neither
// exactly "true" nor "false" — see parse_canonical_bool.
constexpr const char* kReasonNonCanonicalFlag = "rbac_enabled_non_canonical";
// fjarvis F3 (#2703): a reader observed the cache past the accepted
// kRbacGenerationRefreshMs bound while a refresh was already in flight — see
// RbacStore::maybe_refresh_generation.
constexpr const char* kReasonStaleBeyondBound = "stale_beyond_accepted_bound";
// OBSERVE-ONLY: a refresh failed but the bounded stale-serve window
// (kRbacStaleServeBoundMs) has not yet elapsed, so the existing cache keeps
// serving unchanged and nothing is denied — early warning only. See
// kReasonRefreshFailed's comment above for why this cannot share that
// reason value.
constexpr const char* kReasonRefreshFailedWithinBound = "generation_refresh_failed_within_bound";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

// ── IdP / engine namespace guards (ported verbatim from the SQLite store) ────

constexpr std::array<std::string_view, 3> kRecognizedIdpSources = {"entra", "saml", "ad"};
constexpr std::string_view kLocalPrefix = "local:";
constexpr std::string_view kEnginePrefix = "engine:";

bool has_reserved_idp_prefix(std::string_view name) {
    if (name.size() >= kLocalPrefix.size() && name.compare(0, kLocalPrefix.size(), kLocalPrefix) == 0)
        return true;
    if (name.size() >= kEnginePrefix.size() &&
        name.compare(0, kEnginePrefix.size(), kEnginePrefix) == 0)
        return true;
    for (auto source : kRecognizedIdpSources) {
        if (name.size() > source.size() && name[source.size()] == ':' &&
            name.compare(0, source.size(), source) == 0)
            return true;
    }
    return false;
}

bool is_blank(std::string_view s) {
    for (unsigned char c : s) {
        if (!std::isspace(c))
            return false;
    }
    return true;
}

constexpr size_t kMaxExternalIdLength = 512;

/// Built-in role names an engine-principal assignment must never receive —
/// `RbacStore::validate_assignment`'s "no admin, ever" bar (design §4.2).
/// EXTEND this set — never fork a second bar elsewhere.
constexpr std::array<std::string_view, 2> kEngineDisallowedRoles = {"admin", "Administrator"};

std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
std::uint64_t to_u64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::uint64_t>(std::strtoull(s, nullptr, 10));
}
bool to_bool(const char* s) { return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1'); }

/// Strict canonical-boolean parser for `rbac_meta.value` (rbac_enabled):
/// unlike `to_bool` above (the loose native-PG-boolean-text convention —
/// 't'/'T'/'1'), this column is application-level TEXT storing the EXACT
/// literal "true"/"false" this store itself writes. fjarvis F2 (#2703): a
/// loose `== "true"` comparison silently treats ANY other value ("TRUE",
/// "1", corruption, a hand-edit) as false with no error — the RBAC-disabled
/// fail-open direction. `nullopt` means the value is neither canonical
/// string; every call site must treat that identically to an
/// unreadable/missing flag (fail closed), never coerce it to false.
std::optional<bool> parse_canonical_bool(std::string_view s) {
    if (s == "true")
        return true;
    if (s == "false")
        return false;
    return std::nullopt;
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

// sanitize_utf8_strict scrubs invalid UTF-8 to U+FFFD but keeps embedded NUL (a
// valid ASCII byte). PostgreSQL TEXT cannot store a NUL and libpq's text-format
// bind C-string-truncates at the first one. So after the UTF-8 scrub, replace
// every NUL with U+FFFD too. Ported verbatim from audit_store.cpp (ADR-0040) —
// applied to every free-text column, INCLUDING the backfill path (a bad byte
// at-rest in a legacy rbac.db must not brick the MANDATORY backfill).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

// ── Read-degrade observability (mirrors AuditStore/InventoryStore) ───────────
struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};

bool note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason, DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_server_rbac_read_degrade_total", {{"reason", reason}}).increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return new_episode || (n % kReadDegradeLogSample) == 0;
}

// #2703 Gate 7 merge-slice item 1 commit C: observes on EVERY exit from its
// enclosing scope (regardless of which return statement fires), so a single
// instance at the top of check_permission covers every outcome — cache hit,
// breaker-denied, pool timeout, query error, and success — without touching
// each return site individually. The observe() call runs in the destructor,
// which fires after every `{ std::lock_guard ... }` block in the caller has
// already released, so this never holds cache_mtx_/breaker_mtx_ while
// touching the Histogram's own lock (the same hazard note_read_degrade's
// call sites are already careful about, above).
//
// #2703 Gate 7 item Commit B (cpp-expert + performance, Gate 3 — 2 independent
// reporters): takes a pre-resolved `Histogram*` rather than a
// `MetricsRegistry*` + name pair, so a cache HIT — the common case — no
// longer takes the registry's family-map lock or heap-allocates a
// `std::string` from `metric_name` on every single call. The pointer is
// resolved once by `RbacStore::set_metrics()` (see its doc comment) and
// stays valid for the registry's lifetime; passing null (unwired metrics, the
// default in unit tests) disables observation exactly as before.
class ScopedLatencyObserver {
public:
    explicit ScopedLatencyObserver(yuzu::Histogram* hist)
        : hist_(hist), start_(std::chrono::steady_clock::now()) {}
    ~ScopedLatencyObserver() {
        if (!hist_)
            return;
        const auto elapsed = std::chrono::steady_clock::now() - start_;
        hist_->observe(std::chrono::duration<double>(elapsed).count());
    }
    ScopedLatencyObserver(const ScopedLatencyObserver&) = delete;
    ScopedLatencyObserver& operator=(const ScopedLatencyObserver&) = delete;

private:
    yuzu::Histogram* hist_;
    std::chrono::steady_clock::time_point start_;
};

// ── PostgreSQL schema (ADR-0041): the final column set of the SQLite store's
// four migrations, collapsed into one v1. Migrations v3/v4 were data cleanups
// against a live rbac.db — a fresh PG database needs neither (nothing to clean),
// and backfill copies an already-cleaned legacy DB, so they are not replayed.
// Unqualified DDL — the runner sets search_path to `rbac_store`; runtime
// statements below schema-qualify explicitly. `is_system` is BOOLEAN in PG.
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE securable_types (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   BOOLEAN NOT NULL DEFAULT FALSE
            );

            CREATE TABLE operations (
                id          TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   BOOLEAN NOT NULL DEFAULT FALSE
            );

            CREATE TABLE roles (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                is_system   BOOLEAN NOT NULL DEFAULT FALSE,
                created_at  BIGINT NOT NULL DEFAULT 0
            );

            CREATE TABLE role_permissions (
                role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                securable_type  TEXT NOT NULL REFERENCES securable_types(name),
                operation       TEXT NOT NULL REFERENCES operations(id),
                effect          TEXT NOT NULL DEFAULT 'allow',
                PRIMARY KEY (role_name, securable_type, operation)
            );

            CREATE TABLE principal_roles (
                principal_type  TEXT NOT NULL,
                principal_id    TEXT NOT NULL,
                role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                PRIMARY KEY (principal_type, principal_id, role_name)
            );
            CREATE INDEX idx_principal_roles_lookup
                ON principal_roles(principal_type, principal_id);

            CREATE TABLE groups (
                name        TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                source      TEXT NOT NULL DEFAULT 'local',
                external_id TEXT,
                created_at  BIGINT NOT NULL DEFAULT 0
            );
            CREATE INDEX idx_groups_source ON groups(source);

            CREATE TABLE group_members (
                group_name  TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
                username    TEXT NOT NULL,
                PRIMARY KEY (group_name, username)
            );
            CREATE INDEX idx_group_members_username ON group_members(username);

            -- Durable k/v (ADR-0041): the global `rbac_enabled` flag AND the
            -- cross-replica `write_generation` counter (bumped in the same txn
            -- as every mutation), plus the one-time `backfill_complete` marker.
            CREATE TABLE rbac_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        )"},
        // NOTE (#2376 task A, and any future securable addition): adding the
        // `EnginePrincipal` securable deliberately did NOT get a migration
        // here. `seed_defaults()` runs unconditionally on every construction
        // and its `types[]` / Viewer-read-loop / Administrator-CRUD inserts
        // are all ON CONFLICT DO NOTHING, so an EXISTING deployment picks up
        // the new securable and its grants on the next boot with no
        // migration at all — the same idempotent-additive-reseed path
        // `AccessReview` and `SoftwareLicensing` used. A migration is needed
        // only when a change cannot be expressed as an idempotent additive
        // re-seed (e.g. deleting rows).
        // fjarvis F2 (#2703): guard rbac_enabled at the schema level too — a
        // hand-edit or a future bug could otherwise write a non-canonical
        // value that the C++-side `parse_canonical_bool()` strict parser
        // would then correctly refuse to trust, but only at READ time
        // (refusing boot / dropping the cache). A CHECK constraint rejects
        // the bad value at WRITE time instead, which is strictly better: the
        // write itself fails loudly rather than silently landing and waiting
        // to be discovered on the next boot or refresh. Scoped to the one
        // key this applies to — every other `rbac_meta` value
        // (`write_generation`, `backfill_complete`) is not a boolean and
        // must not be constrained.
        {2, R"(
            ALTER TABLE rbac_meta ADD CONSTRAINT rbac_meta_enabled_canonical
                CHECK (key <> 'rbac_enabled' OR value IN ('true', 'false'));
        )"},
        // fable (Gate 4, #2703): a revoked BUILT-IN DEFAULT permission needs to
        // suppress seed_defaults()'s next reseed WITHOUT ever appearing as a
        // real `role_permissions` row — an earlier round of this fix used an
        // explicit `effect='deny'` tombstone instead, which is a real
        // authorization fact and inherits check_permission()/
        // check_scoped_permission()/authorize_list_read()'s pre-existing
        // "deny overrides everything, across ALL of a principal's held
        // roles" semantics. That silently changed the authorization OUTCOME
        // for any principal holding a second role that independently grants
        // the same (securable_type, operation) — legacy's plain DELETE never
        // created a deny row, so legacy computed ALLOW there; the tombstone
        // computes DENY. This table separates "reseed bookkeeping" from
        // "operator-authored authorization fact": it is consulted ONLY by
        // seed_defaults()'s grant() and by remove_permission()/the backfill's
        // equivalent cleanup, and is NEVER read by any authorization-decision
        // code path (check_permission, check_scoped_permission,
        // get_effective_permissions, role_effects_for, authorize_list_read,
        // holds_permission_via_any_group) — role_permissions absence goes
        // back to meaning exactly what it meant in the legacy store: this
        // role grants nothing for this (type, op), full stop, and other
        // roles' independent grants are untouched.
        // Same FK shape as role_permissions (deliberately — an unrecognized
        // role/type/op must still fail remove_permission() outright, and a
        // deleted CUSTOM role's stray markers should not linger forever;
        // system roles, the only ones seed_defaults() ever consults this
        // table for, can never be deleted).
        {3, R"(
            CREATE TABLE revoked_seed_defaults (
                role_name       TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
                securable_type  TEXT NOT NULL REFERENCES securable_types(name),
                operation       TEXT NOT NULL REFERENCES operations(id),
                PRIMARY KEY (role_name, securable_type, operation)
            );
        )"},
    };
    return kMigrations;
}

// ── Legacy (SQLite) introspection for the backfill ───────────────────────────
// nullopt means "could not determine" (a genuine prepare/step error), distinct
// from `false` ("determined the table is absent") — every caller MUST treat
// nullopt as a read failure, never coerce it to "absent" (governance
// re-review, PR #2703 round 2, cpp-expert HIGH: the pre-fix bool return
// conflated the two, and one caller — rbac_config.enabled below — had no
// accounting at all for the error case, silently keeping the "false" default
// on a transient SQLite error).
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

// Bind the SQL boolean literal for a legacy INTEGER is_system value.
const char* bool_lit(std::int64_t v) { return v != 0 ? "true" : "false"; }

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

// adversarial-review (PR #2703, BLOCKER — verified against the code and the
// documented anti-pattern before fixing): `docs/postgres-store-playbook.md`
// "Local source absence never creates terminal migration state on its own"
// (ADR-0040 round 3, Sol's diagnosis, #2697). A process finding no local
// legacy file cannot tell "genuine fresh install" from "a sibling replica
// holds the real one" — stamping the SHARED `backfill_complete` marker from
// that observation alone let a fileless replica permanently foreclose
// migration for a sibling that boots later with the real `rbac.db` still on
// disk. `AuditStore::migrate_from_sqlite` is the fixed reference (fingerprint
// stamped alongside the marker; a later holder verifies its own file against
// it before trusting the marker) — this is the same pattern, right-sized for
// RbacStore's small, single-shot (non-resumable) legacy dataset.
constexpr const char* kSourcelessFingerprint = "sourceless";

// governance re-review (PR #2703, BLOCKING — canonicalization collision,
// confirmed independently by 3 reviewers, one with an empirical repro): the
// original encoding joined fields with an unescaped '|' and rows with '\n'.
// SQLite TEXT columns carry arbitrary bytes (sqlite3_column_bytes, not a
// C string) and NOTHING in RbacStore restricts role/group/principal free
// text to a printable-safe charset (create_role only rejects an empty
// name) — so two genuinely different legacy datasets could canonicalize to
// the identical preimage and hash identically, silently defeating the
// verification this whole mechanism exists to provide. A different
// delimiter byte (e.g. the device/software-inventory stores' \x1f/\x1e
// convention) does not fix this: it is still just some other byte a TEXT
// column can legally contain. Every field below is therefore
// LENGTH-PREFIXED ("<byte-length>:<bytes>") rather than delimited — two
// different field sequences can never encode to the same preimage
// regardless of what bytes they contain, because the length prefix is
// unambiguous about where each field ends.
void append_field(std::string& out, std::string_view f) {
    out += std::to_string(f.size());
    out += ':';
    out.append(f.data(), f.size());
}
void append_field(std::string& out, std::int64_t v) { append_field(out, std::to_string(v)); }

struct LType {
    std::string name, description;
    std::int64_t is_system{0};
};
struct LRole {
    std::string name, description;
    std::int64_t is_system{0}, created_at{0};
};
struct LPerm {
    std::string role_name, securable_type, operation, effect;
};
struct LPrincipal {
    std::string principal_type, principal_id, role_name;
};
struct LGroup {
    std::string name, description, source;
    std::optional<std::string> external_id;
    std::int64_t created_at{0};
};
struct LMember {
    std::string group_name, username;
};

// Every row category this backfill reads from a legacy rbac.db, read ONCE
// and shared by the real migration (INSERT loop) and both fingerprint call
// sites (holder-side verification, and the post-migration trust-anchor
// stamp) — there is deliberately no second file read anywhere in this
// mechanism (governance re-review, MEDIUM->closed: a second independent
// read pass was previously the trust anchor's own TOCTOU window: a legacy
// file mutated between the migrated read and the re-derived fingerprint
// read, e.g. by an old server binary still live during a rolling upgrade,
// would stamp a fingerprint that never matched what was actually migrated,
// and every future verification would then wrongly validate against it).
struct LegacySnapshot {
    std::string enabled = "false";
    std::vector<LType> types;
    std::vector<std::pair<std::string, std::string>> ops;
    std::vector<LRole> roles;
    std::vector<LPerm> perms;
    std::vector<LPrincipal> principals;
    std::vector<LGroup> groups;
    std::vector<LMember> members;
};

// Reads every row this backfill cares about from an ALREADY-OPEN legacy
// connection already known to have a `roles` table (the sourceless case is
// the caller's responsibility, same as before). Fails closed (nullopt) on
// any partial/corrupt read — matches the pre-refactor read_all contract.
std::optional<LegacySnapshot> read_legacy_snapshot(sqlite3* legacy) {
    LegacySnapshot snap;
    bool ok = true;
    const auto has_table = [&](const char* table) -> bool {
        const auto present = legacy_has_table(legacy, table);
        if (!present) {
            ok = false;
            return false;
        }
        return *present;
    };

    if (has_table("rbac_config")) {
        SqliteStmt s;
        if (sqlite3_prepare_v2(legacy, "SELECT value FROM rbac_config WHERE key='enabled'", -1,
                               s.addr(), nullptr) != SQLITE_OK) {
            ok = false;
        } else {
            const int rc = sqlite3_step(s.get());
            if (rc == SQLITE_ROW) {
                // Raw text, not the strict canonical-bool parse the caller
                // applies to this same value for the actual rbac_enabled
                // write: this snapshot only needs to detect a CONTENT
                // difference for fingerprinting purposes, not validate
                // canonicality (fjarvis F2 stays the sole owner of that
                // check, applied by the caller).
                snap.enabled = sqlite_text(s.get(), 0);
            } else if (rc != SQLITE_DONE) {
                // A genuine read error, not "table exists but has no
                // 'enabled' row" (SQLITE_DONE — the "false" default is
                // correct there). Governance re-review round 2, cpp-expert
                // HIGH: this block previously had no failure accounting at
                // all, so a transient error here silently kept the "false"
                // default and could migrate an RBAC-enabled fleet to
                // RBAC-disabled with nothing downstream able to catch it —
                // the read-back verify and the fingerprint both derive from
                // this same already-poisoned snapshot.
                ok = false;
            }
        }
    }

    const auto read_all = [&](const char* sql,
                              const std::function<void(sqlite3_stmt*)>& row) -> bool {
        SqliteStmt s;
        if (sqlite3_prepare_v2(legacy, sql, -1, s.addr(), nullptr) != SQLITE_OK)
            return false;
        int rc;
        while ((rc = sqlite3_step(s.get())) == SQLITE_ROW)
            row(s.get());
        return rc == SQLITE_DONE;
    };

    if (has_table("securable_types"))
        ok &= read_all("SELECT name, description, is_system FROM securable_types",
                       [&](sqlite3_stmt* s) {
                           snap.types.push_back(
                               {sqlite_text(s, 0), sqlite_text(s, 1), sqlite3_column_int64(s, 2)});
                       });
    if (has_table("operations"))
        ok &= read_all("SELECT id, description FROM operations", [&](sqlite3_stmt* s) {
            snap.ops.emplace_back(sqlite_text(s, 0), sqlite_text(s, 1));
        });
    ok &= read_all("SELECT name, description, is_system, created_at FROM roles",
                   [&](sqlite3_stmt* s) {
                       snap.roles.push_back({sqlite_text(s, 0), sqlite_text(s, 1),
                                             sqlite3_column_int64(s, 2),
                                             sqlite3_column_int64(s, 3)});
                   });
    ok &= read_all("SELECT role_name, securable_type, operation, effect FROM role_permissions",
                   [&](sqlite3_stmt* s) {
                       snap.perms.push_back({sqlite_text(s, 0), sqlite_text(s, 1),
                                             sqlite_text(s, 2), sqlite_text(s, 3)});
                   });
    ok &= read_all("SELECT principal_type, principal_id, role_name FROM principal_roles",
                   [&](sqlite3_stmt* s) {
                       snap.principals.push_back(
                           {sqlite_text(s, 0), sqlite_text(s, 1), sqlite_text(s, 2)});
                   });
    if (has_table("groups"))
        ok &= read_all(
            "SELECT name, description, source, external_id, created_at FROM groups",
            [&](sqlite3_stmt* s) {
                LGroup g{sqlite_text(s, 0), sqlite_text(s, 1), sqlite_text(s, 2), std::nullopt,
                        sqlite3_column_int64(s, 4)};
                if (sqlite3_column_type(s, 3) != SQLITE_NULL)
                    g.external_id = sqlite_text(s, 3);
                snap.groups.push_back(std::move(g));
            });
    if (has_table("group_members"))
        ok &= read_all("SELECT group_name, username FROM group_members", [&](sqlite3_stmt* s) {
            snap.members.push_back({sqlite_text(s, 0), sqlite_text(s, 1)});
        });
    if (!ok)
        return std::nullopt;

    // Doomgoose (PR #2703 review, blocking item 2): this snapshot is read
    // directly off the legacy file via raw SELECTs -- MigrationRunner::run()
    // (the legacy SQLite migration path, v1-v4) never executes against a
    // file destined for this Postgres cutover, so a legacy rbac.db that
    // never itself booted a release carrying migrations v3/v4 still holds
    // exactly the data those migrations exist to remove. v3 purges
    // group_members rows for any IdP-sourced (non-local) group -- left in
    // place, a row keyed on an old, mutable IdP display name becomes a
    // resurrected confused-deputy hazard: a LOCAL user who later happens to
    // share that display name silently inherits the group's roles. v4
    // retires three specific role_permissions tuples (superseded Periodic
    // Access Review grants). docs/user-manual/upgrading.md documents direct
    // multi-version upgrades, so refusing outright on an old legacy file
    // would break that promise for RBAC specifically -- apply the same
    // predicates those migrations would have applied, inline, to this same
    // snapshot instead. Both the real backfill and the holder-side
    // fingerprint (canonicalize_legacy_snapshot, below) derive from THIS
    // returned snapshot, so neither can see different content than what was
    // actually decided here.
    // cpp-safety (#2703 Gate 8, scoped re-review): on a genuinely pre-#339
    // legacy file (no schema_meta table), current_version()'s internal
    // ensure_meta_table() logs an spdlog::error ("attempt to write a
    // readonly database") for what is, at THIS call site, an EXPECTED and
    // correctly-handled fallback (see the -1 handling immediately below) --
    // not a real infrastructure fault. That ERROR line is shared
    // MigrationRunner behavior (server/core/src/migration_runner.cpp), not
    // specific to this call site, so it's left as-is rather than touched
    // for every other caller; noted here so an on-call engineer correlating
    // logs for a direct-from-a-very-old-release upgrade knows this
    // particular ERROR line is benign in this one context.
    const int legacy_version = MigrationRunner::current_version(legacy, kStoreName);
    // -1 means the version read itself failed -- no schema_meta table at all
    // (a file that predates MigrationRunner's adoption in this store, #339,
    // entirely) or a genuine I/O error. Treat as version 0 (before
    // everything): the maximally safe assumption, since over-applying either
    // filter below is bounded-cost (v3's drop re-populates on the affected
    // user's next SSO login via reconcile_idp_memberships; v4's drop only
    // risks silently re-removing a grant an operator deliberately restored
    // after v4 originally ran, on this one-time cutover, a narrow edge case
    // next to the confused-deputy hazard under-filtering risks).
    const int effective_version = legacy_version < 0 ? 0 : legacy_version;
    std::size_t members_dropped = 0, perms_dropped = 0;
    if (effective_version < 3) {
        std::unordered_set<std::string> idp_groups;
        for (const auto& g : snap.groups)
            if (g.source != "local")
                idp_groups.insert(g.name);
        const auto before = snap.members.size();
        std::erase_if(snap.members,
                      [&](const LMember& m) { return idp_groups.contains(m.group_name); });
        members_dropped = before - snap.members.size();
    }
    if (effective_version < 4) {
        struct RetiredTuple {
            std::string_view role, securable_type, operation;
        };
        static constexpr std::array<RetiredTuple, 3> kRetired{{
            {"Administrator", "AuditLog", "Attest"},
            {"Reviewer", "AuditLog", "Read"},
            {"Reviewer", "AuditLog", "Attest"},
        }};
        const auto before = snap.perms.size();
        std::erase_if(snap.perms, [&](const LPerm& p) {
            return std::any_of(kRetired.begin(), kRetired.end(), [&](const RetiredTuple& t) {
                return p.role_name == t.role && p.securable_type == t.securable_type &&
                       p.operation == t.operation;
            });
        });
        perms_dropped = before - snap.perms.size();
    }
    if (members_dropped || perms_dropped) {
        spdlog::warn(
            "RbacStore: migrate_from_sqlite: legacy db is at schema_meta version {} (< 4) -- "
            "applied v3/v4 cleanup predicates inline before backfill: dropped {} stale IdP "
            "group-membership row(s), {} retired role_permissions tuple(s)",
            legacy_version, members_dropped, perms_dropped);
    }
    return snap;
}

// Injective preimage: every field length-prefixed (see append_field above),
// every row tagged by category, the row set sorted so on-disk order
// (WAL/vacuum state can reorder identical rows without changing their
// meaning) never changes the result. `groups.external_id`'s NULL-vs-empty-
// string distinction is preserved via an explicit presence tag ahead of the
// value field — collapsing the two (as the pre-fix encoding did) would
// fingerprint a NULL and an empty string identically even though the real
// migration (step 5's INSERT) does not treat them the same. A leading
// version/domain tag is hashed as part of the preimage (standard hash
// domain-separation hygiene) independent of the "v2:" prefix the caller
// puts on the STORED value — that prefix is for an operator/log reading the
// stored value directly, this one is for the hash itself.
//
// security-guardian (governance re-review round 2, LOW-MEDIUM, fail-closed
// direction only): this hashes the RAW sqlite_text() bytes, while the real
// migration (step 5) applies sanitize_pg_text()/bool_lit() normalization
// first. A legacy value that differs only in a way sanitize_pg_text()
// strips (e.g. a stray NUL) can therefore fingerprint-mismatch even though
// the migrated PG rows would be byte-identical — a spurious holder-side
// refusal, never a false accept, so left as-is rather than fixed in this
// round.
std::string canonicalize_legacy_snapshot(const LegacySnapshot& snap) {
    std::vector<std::string> rows;
    rows.reserve(snap.types.size() + snap.ops.size() + snap.roles.size() + snap.perms.size() +
                 snap.principals.size() + snap.groups.size() + snap.members.size());
    for (const auto& t : snap.types) {
        std::string r;
        append_field(r, "type");
        append_field(r, t.name);
        append_field(r, t.description);
        append_field(r, t.is_system);
        rows.push_back(std::move(r));
    }
    for (const auto& o : snap.ops) {
        std::string r;
        append_field(r, "op");
        append_field(r, o.first);
        append_field(r, o.second);
        rows.push_back(std::move(r));
    }
    for (const auto& role : snap.roles) {
        std::string r;
        append_field(r, "role");
        append_field(r, role.name);
        append_field(r, role.description);
        append_field(r, role.is_system);
        append_field(r, role.created_at);
        rows.push_back(std::move(r));
    }
    for (const auto& p : snap.perms) {
        std::string r;
        append_field(r, "perm");
        append_field(r, p.role_name);
        append_field(r, p.securable_type);
        append_field(r, p.operation);
        append_field(r, p.effect);
        rows.push_back(std::move(r));
    }
    for (const auto& p : snap.principals) {
        std::string r;
        append_field(r, "principal");
        append_field(r, p.principal_type);
        append_field(r, p.principal_id);
        append_field(r, p.role_name);
        rows.push_back(std::move(r));
    }
    for (const auto& g : snap.groups) {
        std::string r;
        append_field(r, "group");
        append_field(r, g.name);
        append_field(r, g.description);
        append_field(r, g.source);
        append_field(r, g.external_id ? "1" : "0"); // presence tag, disambiguates NULL vs ""
        append_field(r, g.external_id.value_or(""));
        append_field(r, g.created_at);
        rows.push_back(std::move(r));
    }
    for (const auto& m : snap.members) {
        std::string r;
        append_field(r, "member");
        append_field(r, m.group_name);
        append_field(r, m.username);
        rows.push_back(std::move(r));
    }
    std::sort(rows.begin(), rows.end());

    std::string canon = "rbac-legacy-fingerprint-v2\n";
    append_field(canon, snap.enabled);
    for (const auto& r : rows)
        canon += r;
    return canon;
}

// "v2:"-prefixed so a stored value's scheme is legible directly (to an
// operator reading rbac_meta, or in a log line) without decoding the hash —
// a future encoding change becomes a diagnosable "scheme changed" instead of
// reproducing the collision/TOCTOU class of defect this encoding closes as
// an unexplainable holder-side verification failure. Returns nullopt only on
// an EVP_Digest failure (essentially unreachable for SHA-256, but the
// contract stays fail-closed: a caller MUST NOT trust an empty-string
// fingerprint as valid, unlike the pre-fix version of this function).
std::optional<std::string> fingerprint_legacy_snapshot(const LegacySnapshot& snap) {
    const auto hash = sha256_hex(canonicalize_legacy_snapshot(snap));
    if (!hash)
        return std::nullopt;
    return "v2:" + *hash;
}

// Path-based convenience for the holder-side verification call site (which
// has no already-open connection to reuse): opens read-only, probes for
// corruption, and either returns the sourceless sentinel (no `roles` table —
// same "nothing to protect" class as no local file at all) or reads a full
// snapshot and fingerprints it via the exact same function the real
// migration path uses from its in-memory snapshot. Returns nullopt only on a
// corrupt/unreadable file or a snapshot read failure — the caller MUST fail
// closed on that, never treat it as sourceless-equivalent.
std::optional<std::string> legacy_rbac_fingerprint(const std::filesystem::path& legacy_db_path) {
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
    const auto has_roles = legacy_has_table(legacy.get(), "roles");
    if (!has_roles)
        return std::nullopt; // genuine read error, NOT "no roles table"
    if (!*has_roles)
        return std::string(kSourcelessFingerprint);

    const auto snap = read_legacy_snapshot(legacy.get());
    if (!snap)
        return std::nullopt;
    return fingerprint_legacy_snapshot(*snap);
}

} // namespace

std::string namespaced_group_name(const std::string& source, const std::string& external_id) {
    if (source == "local")
        return external_id;
    return source + ":" + external_id;
}

// ── Construction / teardown ──────────────────────────────────────────────────

RbacStore::RbacStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("RbacStore: no database connection at construction ({}) — authorization "
                      "substrate disabled (fail-closed: every authz read will DENY)",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("RbacStore: schema migration failed — authorization substrate disabled "
                      "(fail-closed)");
        return;
    }
    lease.reset(); // seed_defaults/load_enabled_flag re-acquire their own leases
    open_ = true;
    seed_defaults();
    // load_enabled_flag() is now fail-closed: if the durable rbac_enabled /
    // write_generation rows can't be read (lease/query error or absent — a
    // failed seed also lands here), it returns false and we refuse to serve
    // rather than boot RBAC-off on a fleet that enabled it (Gate 2 CRITICAL /
    // Gate 4 R1). is_open()==false → server sets startup_failed_ and refuses boot.
    if (!load_enabled_flag()) {
        open_ = false;
        return;
    }
    spdlog::info("RbacStore initialized (schema {})", kStoreName);
}

RbacStore::~RbacStore() = default;

void RbacStore::set_metrics(yuzu::MetricsRegistry* m) noexcept {
    metrics_ = m;
    // See the doc comment on the declaration for why this is resolved once
    // here rather than cached as a function-local static. The buckets
    // overload is idempotent with server.cpp's own zero-seed call — whichever
    // runs first fixes the series' boundaries (Prometheus semantics), and
    // both request the same extended buckets, so call order doesn't matter.
    authz_check_seconds_hist_ =
        m ? &m->histogram("yuzu_server_rbac_authz_check_seconds", yuzu::Histogram::seconds_buckets_60s())
          : nullptr;
}

// ── Seed data (idempotent — ON CONFLICT DO NOTHING) ──────────────────────────

void RbacStore::seed_defaults() {
    if (!open_)
        return;
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("RbacStore: seed_defaults: no connection ({})", pool_.last_error());
        return;
    }
    PGconn* c = lease.get();

    const auto exec = [&](const char* sql,
                          const std::vector<std::string>& params = {}) -> bool {
        pg::PgResult r = pg::exec_params(c, sql, params);
        if (!r.ok()) {
            spdlog::error("RbacStore: seed_defaults statement failed: {}", PQerrorMessage(c));
            return false;
        }
        return true;
    };

    // Durable meta defaults — never clobber a migrated value (DO NOTHING).
    exec("INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('rbac_enabled','false') "
         "ON CONFLICT (key) DO NOTHING");
    exec("INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('write_generation','0') "
         "ON CONFLICT (key) DO NOTHING");

    // Securable types.
    const std::array<std::string_view, 23> types = {
        "Infrastructure",  "UserManagement",  "InstructionDefinition",
        "InstructionSet",  "Execution",       "Schedule",
        "Approval",        "Tag",             "AuditLog",
        "Response",        "ManagementGroup", "ApiToken",
        "Security",        "Policy",          "DeviceToken",
        "SoftwareDeployment", "License",      "FileRetrieval",
        "GuaranteedState", "Inventory",       "AccessReview",
        // #2376 (task A) — engine-principal INVENTORY + grant-graph reads
        // (list/get engine principals, list their fleet-wide roles) cut away
        // from the over-broad Security:Read, which also gates unrelated
        // operational reads (quarantine visibility, CA issued-certs, KEK
        // status) that a follow-up change floors to admin-only when RBAC is
        // disabled — flooring all of Security:Read would sweep those in too.
        // Seeded to Administrator (CRUD via the loop below) + Viewer (Read,
        // below) — the same two roles that reached the migrated routes via
        // Security:Read before this cut.
        "SoftwareLicensing", "EnginePrincipal"};
    for (auto t : types)
        exec("INSERT INTO rbac_store.securable_types (name, is_system) VALUES ($1, TRUE) "
             "ON CONFLICT (name) DO NOTHING",
             {std::string(t)});
    // R18 (ADR-0024 Decision 9): defuse the SoftwareLicensing name (does NOT
    // gate the /inventory catalog). Set only when empty — never clobber an
    // operator-set value.
    exec("UPDATE rbac_store.securable_types SET description = "
         "'gates the /api/v1/sle/* detected-licence reads and the agent-decommission erasure; "
         "the /inventory software catalog remains under Inventory:Read' "
         "WHERE name = 'SoftwareLicensing' AND description = ''");

    // Operations. "Rotate" (dev P2 #11, SOC 2 CC6.3, merged from origin/dev):
    // ApiToken-specific self-service rotation
    // (ApiTokenStore::rotate_token/confirm_token_rotation). Same treatment as
    // Push/Attest below — a first-class operation, deliberately EXCLUDED from
    // crud_ops so no cross-type loop ever widens it onto an unrelated
    // securable, and deliberately distinct from ApiToken's own "Write": a
    // security-critical round on dev found that reusing Write to admit the
    // MCP rotation tools at the operator tier silently widened every OTHER
    // ApiToken:Write route/tool too (mcp_policy.hpp's tier_allows()
    // operator-tier comment is the narrative home for that finding). Granted
    // below to Administrator and ApiTokenManager only — the SAME population
    // that already holds ApiToken:Write.
    const std::array<std::string_view, 8> ops = {"Read",  "Write", "Execute", "Delete",
                                                 "Approve", "Push", "Attest",  "Rotate"};
    for (auto o : ops)
        exec("INSERT INTO rbac_store.operations (id, is_system) VALUES ($1, TRUE) "
             "ON CONFLICT (id) DO NOTHING",
             {std::string(o)});
    const std::array<std::string_view, 5> crud_ops = {"Read", "Write", "Execute", "Delete",
                                                      "Approve"};

    const std::int64_t now = now_secs();

    struct RoleSeed {
        std::string_view name;
        std::string_view desc;
    };
    const std::array<RoleSeed, 7> roles = {
        RoleSeed{"Administrator", "Full access to all operations"},
        {"PlatformEngineer", "Author and manage YAML instruction definitions, sets, and schemas"},
        {"Operator", "Execute and manage instructions, schedules, and tags"},
        {"ApiTokenManager", "Create, revoke, and manage API tokens for programmatic access"},
        {"ITServiceOwner", "Admin control over devices tagged with the same IT Service"},
        {"Viewer", "Read-only access to operational data"},
        {"Reviewer", "Read audit evidence and attest/flag access-review grants (SOC 2 CC6.2)"}};
    for (const auto& r : roles)
        exec("INSERT INTO rbac_store.roles (name, description, is_system, created_at) "
             "VALUES ($1, $2, TRUE, $3::bigint) ON CONFLICT (name) DO NOTHING",
             {std::string(r.name), std::string(r.desc), std::to_string(now)});

    // fable (Gate 4, #2703): skip a triple an operator explicitly revoked via
    // remove_permission() — revoked_seed_defaults is bookkeeping-only (never
    // read by any authorization decision), so this is the ONLY place its
    // absence-suppression takes effect. A re-grant via set_permission()
    // recreates the role_permissions row directly and does not touch this
    // table; the (now-redundant, harmless) marker just means a future
    // seed_defaults() no-ops against an already-restored row either way.
    // chaos-injector (Gate 5, #2703, HIGH — CHAOS-1): the lock MUST be its own
    // statement, in its own explicit transaction, strictly before the
    // check-and-insert — see kRevokeCoordLockSql's comment for why a CTE in
    // the same statement does not work. Each grant() call gets its own
    // mini-transaction rather than wrapping the whole seed_defaults() pass:
    // every other statement here stays a fire-and-forget auto-commit
    // (existing, deliberate — a single failed seed statement must not abort
    // the rest of the reseed), and this preserves that for grant() too.
    const auto grant = [&](std::string_view role, std::string_view type, std::string_view op) {
        if (!exec("BEGIN"))
            return;
        pg::PgTxn txn(c);
        if (!exec(kRevokeCoordLockSql))
            return; // txn destructor rolls back
        // security-guardian (Gate 8, #2703): check the INSERT's result before
        // committing, matching the UP-3 discipline PgPool::run_in_txn enforces
        // centrally for every OTHER write path in this store — a failed
        // statement must not be followed by commit() (PgTxn::commit() on an
        // aborted transaction still returns PGRES_COMMAND_OK while silently
        // performing a rollback; calling it unconditionally would have been
        // correct-by-accident, not by contract).
        if (!exec("INSERT INTO rbac_store.role_permissions (role_name, securable_type, "
                  "operation, effect) SELECT $1, $2, $3, 'allow' WHERE NOT EXISTS ("
                  "  SELECT 1 FROM rbac_store.revoked_seed_defaults "
                  "  WHERE role_name = $1 AND securable_type = $2 AND operation = $3"
                  ") ON CONFLICT DO NOTHING",
                  {std::string(role), std::string(type), std::string(op)}))
            return; // txn destructor rolls back
        txn.commit();
    };

    // Administrator: CRUD on everything + targeted Push + Attest + Rotate
    // (Rotate merged from origin/dev, P2 #11 — same targeted-grant treatment
    // as Push/Attest, see the "Rotate" catalogue comment above).
    for (auto t : types)
        for (auto o : crud_ops)
            grant("Administrator", t, o);
    grant("Administrator", "GuaranteedState", "Push");
    grant("Administrator", "AccessReview", "Attest");
    grant("Administrator", "ApiToken", "Rotate");

    // PlatformEngineer.
    for (std::string_view t : {"InstructionDefinition", "InstructionSet"})
        for (std::string_view o : {"Read", "Write", "Execute", "Delete"})
            grant("PlatformEngineer", t, o);
    for (std::string_view t : {"Execution", "Schedule", "Approval", "Tag", "AuditLog", "Response",
                               "SoftwareLicensing", "Inventory"})
        grant("PlatformEngineer", t, "Read");
    for (std::string_view o : {"Read", "Write", "Delete"})
        grant("PlatformEngineer", "Policy", o);
    for (std::string_view o : {"Read", "Write", "Delete", "Push"})
        grant("PlatformEngineer", "GuaranteedState", o);

    // Operator.
    for (std::string_view t : {"InstructionDefinition", "InstructionSet", "Execution", "Schedule",
                               "Tag"}) {
        for (std::string_view o : {"Read", "Write", "Execute", "Delete"})
            grant("Operator", t, o);
    }
    grant("Operator", "Approval", "Read");
    grant("Operator", "Approval", "Approve");
    grant("Operator", "AuditLog", "Read");
    grant("Operator", "Response", "Read");
    grant("Operator", "Policy", "Read");
    grant("Operator", "Policy", "Execute");
    grant("Operator", "SoftwareDeployment", "Read");
    grant("Operator", "SoftwareDeployment", "Execute");
    grant("Operator", "DeviceToken", "Read");
    grant("Operator", "License", "Read");
    grant("Operator", "Inventory", "Read");
    grant("Operator", "SoftwareLicensing", "Read");
    grant("Operator", "SoftwareLicensing", "Write");
    grant("Operator", "FileRetrieval", "Read");
    grant("Operator", "FileRetrieval", "Write");
    grant("Operator", "GuaranteedState", "Read");
    grant("Operator", "GuaranteedState", "Push");

    // ApiTokenManager. "Rotate" merged from origin/dev (P2 #11, SOC 2 CC6.3
    // — self-service human token rotation; same population that already
    // holds Write).
    for (std::string_view o : {"Read", "Write", "Delete", "Rotate"})
        grant("ApiTokenManager", "ApiToken", o);

    // ITServiceOwner.
    for (std::string_view t : {"Infrastructure", "InstructionDefinition", "InstructionSet",
                               "Execution", "Schedule", "Approval", "Tag", "AuditLog", "Response",
                               "ManagementGroup", "Policy", "DeviceToken", "SoftwareDeployment",
                               "License", "FileRetrieval", "GuaranteedState", "Inventory",
                               "SoftwareLicensing"}) {
        for (auto o : crud_ops)
            grant("ITServiceOwner", t, o);
    }
    grant("ITServiceOwner", "GuaranteedState", "Push");

    // Viewer: read on all except Infrastructure.
    // #2376 (task A) — Viewer held Security:Read (the only non-Administrator
    // role that did), so it keeps equivalent access on the new
    // EnginePrincipal securable.
    for (std::string_view t : {"UserManagement", "InstructionDefinition", "InstructionSet",
                               "Execution", "Schedule", "Approval", "Tag", "AuditLog", "Response",
                               "ManagementGroup", "ApiToken", "Security", "Policy", "DeviceToken",
                               "SoftwareDeployment", "License", "FileRetrieval", "GuaranteedState",
                               "Inventory", "SoftwareLicensing", "EnginePrincipal"})
        grant("Viewer", t, "Read");

    // Reviewer.
    grant("Reviewer", "AccessReview", "Read");
    grant("Reviewer", "AccessReview", "Attest");
}

bool RbacStore::load_enabled_flag() {
    if (!open_)
        return false;
    auto lease = pool_.acquire();
    if (!lease) {
        // CRITICAL fail-closed (Gate 2 security / Gate 4 R1): we could NOT read
        // the durable rbac_enabled flag. Leaving `rbac_enabled_` at its ctor
        // default (false) while `open_` stays true would serve a fleet that had
        // ENABLED RBAC with RBAC OFF — authorize_list_read → AdmitAll, a
        // fleet-wide confined-operator bypass. Refuse boot instead; the next
        // start retries. NEVER default-to-enabled either (that would break the
        // legitimate RBAC-off fresh install) — refuse-boot is the only safe
        // posture when the authoritative flag is unreadable.
        spdlog::error("RbacStore: could not acquire a connection to read the durable rbac_enabled "
                      "flag ({}) — refusing to start rather than risk serving RBAC-off on a fleet "
                      "that enabled it (fail-closed)",
                      pool_.last_error());
        return false;
    }
    pg::PgResult r = pg::exec_params(
        lease.get(), "SELECT value FROM rbac_store.rbac_meta WHERE key='rbac_enabled'",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1) {
        // The row is seeded by the migration/seed_defaults (and read-back-verified
        // by the backfill), so a query error OR a missing row means the durable
        // flag is unreadable/absent — fail closed, same reasoning as above.
        spdlog::error("RbacStore: durable rbac_enabled flag is unreadable/absent (status={}) — "
                      "refusing to start (fail-closed)",
                      static_cast<int>(r.status()));
        return false;
    }
    // fjarvis F2 (#2703): the row EXISTS and the query succeeded, so the
    // branch above doesn't fire — but a value that isn't exactly "true" or
    // "false" (a hand-edit, corruption, a future writer using a different
    // convention) previously coerced silently to false via `== "true"`. That
    // is boot-succeeds-RBAC-off on a fleet that enabled it — the same
    // fail-open class the branch above exists to close, one level down.
    // Treat a non-canonical value identically: refuse to start.
    const auto enabled_parsed = parse_canonical_bool(text_col(r.get(), 0, 0));
    if (!enabled_parsed) {
        spdlog::error("RbacStore: durable rbac_enabled flag holds a non-canonical value "
                      "(expected exactly \"true\" or \"false\") — refusing to start "
                      "(fail-closed; coercing an unrecognised value to false would silently "
                      "disable RBAC on a fleet that enabled it)");
        return false;
    }
    rbac_enabled_.store(*enabled_parsed, std::memory_order_relaxed);
    // Anchor the generation cache from the durable counter so the first read
    // does not immediately re-query. This row is likewise init-guaranteed.
    pg::PgResult g = pg::exec_params(
        lease.get(), "SELECT value FROM rbac_store.rbac_meta WHERE key='write_generation'",
        std::vector<std::string>{});
    if (g.status() != PGRES_TUPLES_OK || PQntuples(g.get()) != 1) {
        spdlog::error("RbacStore: durable write_generation is unreadable/absent — refusing to "
                      "start (fail-closed)");
        return false;
    }
    std::lock_guard lock(cache_mtx_);
    cached_generation_ = to_u64(PQgetvalue(g.get(), 0, 0));
    generation_valid_ = true;
    // Boot-time load is itself a genuine completed refresh — both timestamps
    // are honestly "now" (fjarvis F3, #2703 — see the member comments).
    refresh_started_ms_ = last_successful_refresh_ms_ = now_ms();
    return true;
}

// ── Durable generation token (ADR-0041 cross-replica coherence) ──────────────

void RbacStore::maybe_refresh_generation() const {
    if (!open_)
        return;
    bool gated = false;
    bool beyond_bound = false;
    {
        std::lock_guard lock(cache_mtx_);
        gated = (now_ms() - refresh_started_ms_) < kRbacGenerationRefreshMs;
        if (gated) {
            // fjarvis F3 (#2703): a refresh recently started (or is still in
            // flight) elsewhere, so THIS thread must not also fire a query —
            // that's the stampede this gate exists to prevent. But "someone
            // recently started a refresh" is not the same claim as "the cache
            // is fresh as of now" — the in-flight query may still be running.
            // Measure against `last_successful_refresh_ms_` (bumped only on
            // actual completion, never pre-emptively) so a slow in-flight
            // refresh under load is COUNTED rather than silently trusted: the
            // accepted ~kRbacGenerationRefreshMs bound stays honest instead of
            // being falsified by whichever thread happens to check first.
            // Computed here (still under the lock, a plain read of another
            // `mutable` member) but the degrade FIRES after the lock is
            // released — see below.
            beyond_bound = rbac_generation::is_stale_beyond_bound(
                now_ms(), last_successful_refresh_ms_, kRbacGenerationRefreshMs);
        } else {
            // Claim the refresh for THIS thread by advancing refresh_started_ms_
            // ATOMICALLY under the SAME lock as the gate check above (Gate 3
            // perf — this is what makes exactly one thread win per interval).
            // Otherwise every concurrent authz thread that crosses the interval
            // boundary at once fires the SELECT + grabs a pool lease — an N-way
            // refresh stampede once per interval under load, competing with
            // real permission queries. NOT last_successful_refresh_ms_ — that
            // one earns its update on actual completion, below.
            refresh_started_ms_ = now_ms();
        }
    }
    if (gated) {
        // performance (Gate 3, #2703): note_read_degrade()'s metrics-counter
        // call acquires MetricsRegistry's own multi-level lock chain and can
        // block for the duration of a Prometheus scrape (`serialize()` holds
        // the same registry lock). This branch is reachable by EVERY losing
        // thread on the fast/early-return path, not just the one thread per
        // interval that wins the refresh — so it must NOT run while holding
        // `cache_mtx_`, the sole authz-check serialization point, or a scrape
        // colliding with a degraded window could stall every check_permission
        // fleet-wide. Matches the existing pattern at check_permission's
        // pool-timeout branch (note_read_degrade called outside any lock).
        if (beyond_bound) {
            static DegradeSampler sampler;
            if (note_read_degrade(metrics_, kReasonStaleBeyondBound, sampler))
                spdlog::warn(
                    "RbacStore: cache read while a generation refresh is in flight AND "
                    "already past the accepted {}ms staleness bound — serving the "
                    "pre-refresh cache regardless (no cache to fail over to); this "
                    "replica's rbac view may be stale beyond the accepted bound",
                    kRbacGenerationRefreshMs);
        }
        return;
    }
    // Read the durable generation + enabled flag WITHOUT holding cache_mtx_.
    std::optional<std::uint64_t> durable_gen;
    std::optional<bool> durable_enabled;
    bool saw_non_canonical_enabled = false;
    // Breaker-gated (#2703 Gate 7 item 1 commit B): a denied attempt here
    // leaves durable_gen at nullopt WITHOUT touching the pool, which the
    // existing `!durable_gen` handling below already treats identically to
    // a real failed refresh — the stale-serve bound composes for free.
    if (breaker_admit()) {
        if (auto lease = pool_.try_acquire_for(kAuthzAcquireTimeout)) {
            pg::PgResult r = pg::exec_params(
                lease.get(),
                "SELECT key, value FROM rbac_store.rbac_meta WHERE key IN "
                "('write_generation','rbac_enabled')",
                std::vector<std::string>{});
            if (r.status() == PGRES_TUPLES_OK) {
                for (int i = 0; i < PQntuples(r.get()); ++i) {
                    const std::string k = text_col(r.get(), i, 0);
                    if (k == "write_generation")
                        durable_gen = to_u64(PQgetvalue(r.get(), i, 1));
                    else if (k == "rbac_enabled") {
                        // fjarvis F2 (#2703): parse strictly. A non-canonical
                        // value leaves durable_enabled at nullopt, and the
                        // existing "if (durable_enabled)" below already does the
                        // right thing (leave rbac_enabled_ untouched) — the loose
                        // `== "true"` this replaces silently coerced anything
                        // non-canonical to false instead.
                        durable_enabled = parse_canonical_bool(text_col(r.get(), i, 1));
                        saw_non_canonical_enabled = !durable_enabled;
                    }
                }
                breaker_note_result(true);
            } else {
                breaker_note_result(false);
            }
        } else {
            breaker_note_result(false);
        }
    }
    // consistency-auditor (Gate 4, #2703): the Gate 3 fix moved the
    // stale-beyond-bound degrade outside cache_mtx_ specifically because
    // note_read_degrade()'s metrics-registry lock chain can block for a
    // whole Prometheus scrape, and cache_mtx_ is the sole authz-check
    // serialization point — every concurrent check_permission() call (even
    // a cache HIT) needs it too. That same reasoning applies to these two
    // sibling branches; only the STATE MUTATIONS stay under the lock, and
    // which degrade(s) to fire is decided as plain bools first — except the
    // row-absent case below, which sets this same flag from INSIDE the
    // lock's durable_gen-confirmed branch, deliberately: it must only fire
    // when durable_gen was ALSO confirmed this round (see the fjarvis
    // MEDIUM comment there), a condition not yet known at this point.
    bool fire_non_canonical_degrade = saw_non_canonical_enabled;
    bool fire_refresh_failed_degrade = false;
    bool refresh_failed_cache_dropped = false;
    {
        std::lock_guard lock(cache_mtx_);
        if (!durable_gen) {
            // Bounded stale-serve (#2703 Gate 7): a refresh failure inside
            // kRbacStaleServeBoundMs of the last confirmed-good refresh keeps
            // serving what we already trusted — perm_cache_ stays populated
            // and generation_valid_/rbac_enabled_ stay as last observed,
            // instead of unconditionally dropping trust on every transient
            // blip. Still fires the degrade metric either way (below) so
            // on-call sees the refresh is failing before the bound is
            // actually exceeded. Do NOT touch rbac_enabled_ in EITHER branch
            // — flipping it to disabled would be fail-open.
            // Security-guardian (#2703 Gate 8, second re-review): this was a
            // hand-written third copy of generation_view_stale_locked()'s
            // exact formula (De Morgan's-equivalent to its negation) — the
            // same drift risk the chokepoint exists to eliminate, sitting
            // right next to a doc comment claiming there wasn't one.
            // cache_mtx_ is already held here (line 1241), so the lock-free
            // helper is safe to call.
            const bool within_stale_serve_bound = !generation_view_stale_locked();
            fire_refresh_failed_degrade = true;
            refresh_failed_cache_dropped = !within_stale_serve_bound;
            if (!within_stale_serve_bound) {
                // Fail toward "assume changed": drop the cache and stop
                // trusting it — the bound is exceeded, or we never had a
                // confirmed-good refresh to begin with (generation_valid_
                // false, e.g. right after construction on a broken pool).
                perm_cache_.clear();
                generation_valid_ = false;
            }
        } else {
            // fjarvis (PR #2703 re-review, MEDIUM, residual in the F2 fix):
            // last_successful_refresh_ms_ used to bump here whenever
            // write_generation alone was read, regardless of whether
            // rbac_enabled was ALSO confirmed this round -- durable_enabled
            // is nullopt both when the value was non-canonical (counted via
            // saw_non_canonical_enabled below) AND when the row was simply
            // absent from the result set (never counted at all, since the
            // per-row loop above only sets saw_non_canonical_enabled inside
            // its `k == "rbac_enabled"` branch). Either way, the freshness
            // clock this store's OWN staleness check relies on
            // (generation_view_stale_locked(), consulted by both perm_cache_
            // trust and rbac_enabled_view_degraded()) was advancing on a
            // round that never actually confirmed rbac_enabled -- a replica
            // cached at rbac_enabled_=false could then keep
            // rbac_enforcement_in_effect() returning false (legacy-open)
            // indefinitely instead of degrading after kRbacStaleServeBoundMs,
            // the asymmetric-with-write_generation direction that matters.
            // Only advance the freshness clock, and adopt the enabled value,
            // when BOTH rows were confirmed this round.
            const bool row_absent = !durable_enabled && !saw_non_canonical_enabled;
            if (row_absent)
                fire_non_canonical_degrade = true; // same degrade class: rbac_enabled unconfirmed
            if (durable_enabled) {
                last_successful_refresh_ms_ = now_ms();
                rbac_enabled_.store(*durable_enabled, std::memory_order_relaxed);
            }
            // Adopt the durable generation only when it moves FORWARD (Gate 3
            // cpp-safety): the SELECT above ran lock-free, so a concurrent
            // local apply_local_generation may have advanced cached_generation_
            // past what we read — never regress it (that would wrongly clear a
            // just-populated cache and re-anchor to a stale value). Generations
            // are monotonic, so `>` is the correct adopt test. This half is
            // independent of rbac_enabled's own confirmation above — a
            // successfully-read write_generation still anchors perm_cache_
            // validity even on a round where rbac_enabled specifically
            // couldn't be confirmed.
            if (!generation_valid_ || *durable_gen > cached_generation_) {
                perm_cache_.clear();
                cached_generation_ = *durable_gen;
                generation_valid_ = true;
            }
        }
    }
    if (fire_non_canonical_degrade) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonNonCanonicalFlag, sampler))
            spdlog::warn("RbacStore: durable rbac_enabled refresh could not confirm this round "
                         "(row read as non-canonical, or absent entirely) — leaving the cached "
                         "enabled-state unchanged (never coercing to false)");
    }
    if (fire_refresh_failed_degrade) {
        // Count the degrade so on-call can see that the cross-replica
        // generation + enabled-flag refresh is failing (Gate 3 architect /
        // Gate 6 sre): a persistent refresh failure means this replica's
        // rbac_enabled view can go stale, the more-sensitive fail-open
        // dimension. Two DISTINCT reasons (own sampler each, matching this
        // file's one-sampler-per-call-site convention — see check_permission's
        // pool-timeout/query-error sites): kReasonRefreshFailed fires ONLY
        // when the cache was actually dropped (denying, alert-eligible);
        // kReasonRefreshFailedWithinBound fires while the bounded stale-serve
        // window still protects the cache (observe-only, nobody denied). See
        // the reason constants' comments above for why they must not merge.
        if (refresh_failed_cache_dropped) {
            static DegradeSampler sampler;
            if (note_read_degrade(metrics_, kReasonRefreshFailed, sampler))
                spdlog::warn(
                    "RbacStore: durable generation/enabled-flag refresh failed — cache "
                    "dropped (assume-changed); rbac_enabled view may be stale on this replica");
        } else {
            static DegradeSampler sampler;
            if (note_read_degrade(metrics_, kReasonRefreshFailedWithinBound, sampler))
                spdlog::warn(
                    "RbacStore: durable generation/enabled-flag refresh failed — still within "
                    "the {}ms bounded stale-serve window, serving the existing cache "
                    "unchanged; rbac_enabled view may be stale on this replica",
                    kRbacStaleServeBoundMs);
        }
    }
}

void RbacStore::apply_local_generation(std::uint64_t new_gen) const {
    std::lock_guard lock(cache_mtx_);
    perm_cache_.clear();
    cached_generation_ = new_gen;
    generation_valid_ = true;
    // A locally-committed write is genuinely fresh data as of now — both
    // timestamps earn the update (fjarvis F3, #2703).
    refresh_started_ms_ = last_successful_refresh_ms_ = now_ms();
}

bool RbacStore::breaker_admit() const {
    std::lock_guard lock(breaker_mtx_);
    if (breaker_consecutive_failures_ < kBreakerTripThreshold) {
        // Closed. Still stamp the timestamp on every ADMITTED attempt (not
        // only the half-open probe below) — otherwise the very first
        // cooldown check right after a trip measures against whatever
        // `breaker_last_probe_started_ms_` last held (0 at construction, or
        // a stale value from a prior open episode), which is not "how long
        // since we last actually tried" and can let the cooldown gate fail
        // open on its very first evaluation.
        breaker_last_probe_started_ms_ = now_ms();
        return true; // closed — proceed normally
    }
    // Open. Allow exactly one probe per kRbacGenerationRefreshMs (half-open),
    // claimed the same way maybe_refresh_generation claims its refresh slot:
    // advance the gate timestamp BEFORE the attempt so a concurrent caller
    // sees the claim immediately, not after the probe completes — otherwise
    // every authz call arriving in the same instant as the winning probe
    // would also read "not gated yet" and each fire its own pool attempt.
    const bool gated =
        (now_ms() - breaker_last_probe_started_ms_) < kRbacGenerationRefreshMs;
    if (gated)
        return false; // still cooling down — deny without touching the pool
    breaker_last_probe_started_ms_ = now_ms();
    return true; // this call wins the probe
}

void RbacStore::breaker_note_result(bool success) const {
    // #2703 Gate 7 item 1 commit C: compute the closed<->open TRANSITION as a
    // plain optional<bool> under the lock (mirrors maybe_refresh_generation's
    // existing fire_refresh_failed_degrade split, above) and fire the gauge
    // only after releasing it — breaker_mtx_ sits on every authz call's
    // gated paths, so it must never be held while touching MetricsRegistry's
    // own lock (the same hazard note_read_degrade's call sites already
    // avoid). Firing only on a TRANSITION (not on every call) also means
    // this never adds registry-lock contention to the common closed/healthy
    // path — a gauge doesn't need refreshing on every success once it is
    // already known to be 0.
    std::optional<bool> new_open_state;
    {
        std::lock_guard lock(breaker_mtx_);
        const bool was_open = breaker_consecutive_failures_ >= kBreakerTripThreshold;
        if (success)
            breaker_consecutive_failures_ = 0;
        else
            ++breaker_consecutive_failures_;
        const bool is_open = breaker_consecutive_failures_ >= kBreakerTripThreshold;
        if (was_open != is_open)
            new_open_state = is_open;
    }
    if (new_open_state && metrics_)
        metrics_->gauge("yuzu_server_rbac_breaker_open").set(*new_open_state ? 1.0 : 0.0);
}

namespace {
// Bump `write_generation` inside an already-open txn on `c`; return the new
// value, or nullopt on any error. The mutation and this bump commit atomically
// (ADR-0041: the durable counter advances in the SAME txn as the write).
std::optional<std::uint64_t> bump_generation_in_txn(PGconn* c) {
    pg::PgResult r = pg::exec_params(
        c,
        "INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('write_generation','1') "
        "ON CONFLICT (key) DO UPDATE SET value = "
        "(rbac_store.rbac_meta.value::bigint + 1)::text RETURNING value::bigint",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
        return std::nullopt;
    return to_u64(PQgetvalue(r.get(), 0, 0));
}
} // namespace

// ── Global toggle ────────────────────────────────────────────────────────────

bool RbacStore::is_rbac_enabled() const {
    maybe_refresh_generation();
    return rbac_enabled_.load(std::memory_order_relaxed);
}

bool RbacStore::generation_view_stale_locked() const {
    // G11-CPPEXPERT-B2 (#2703 Gate 8): `generation_valid_` alone is not a
    // sufficient staleness signal. It only flips false once SOME thread's
    // maybe_refresh_generation() call actually completes a failed attempt
    // past kRbacStaleServeBoundMs -- but a query stuck on PG-side lock
    // contention (#3016, up to lock_timeout ~10s) can leave generation_valid_
    // TRUE, stale, and untouched for the whole stall: every OTHER caller in
    // that window either takes the gated fast-return path (no state change)
    // or is itself still blocked inside its own query. Checking elapsed time
    // here directly (matching rbac_enabled_view_degraded()'s own doc comment,
    // which already promised this bound) closes the gap without depending on
    // any in-flight refresh attempt ever completing. This is the ONE
    // chokepoint for that decision -- originally added only inside
    // rbac_enabled_view_degraded(), then found (architect, Gate 3 re-review
    // of this same fix) to have a sibling raw read of generation_valid_ in
    // check_permission()'s perm-cache trust decision that bypassed it
    // entirely, serving a stale cached ALLOW/DENY through the identical
    // stuck-refresh window. Extracted here so both readers share one
    // definition of "stale" rather than risking a second copy drifting.
    if (!generation_valid_)
        return true;
    return rbac_generation::is_stale_beyond_bound(now_ms(), last_successful_refresh_ms_,
                                                   kRbacStaleServeBoundMs);
}

bool RbacStore::rbac_enabled_view_degraded() const {
    std::lock_guard lock(cache_mtx_);
    return generation_view_stale_locked();
}

void RbacStore::set_rbac_enabled(bool enabled) {
    if (!open_)
        return;
    std::optional<std::uint64_t> new_gen;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('rbac_enabled', $1) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            std::vector<std::string>{enabled ? "true" : "false"});
        if (r.status() != PGRES_COMMAND_OK) {
            spdlog::error("RbacStore::set_rbac_enabled: write failed: {}", PQerrorMessage(c));
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok) {
        spdlog::error("RbacStore::set_rbac_enabled: transaction failed; flag unchanged");
        return;
    }
    rbac_enabled_.store(enabled, std::memory_order_relaxed);
    apply_local_generation(*new_gen);
}

bool rbac_enforcement_in_effect(const RbacStore* store) noexcept {
    // Permit the full-fleet fallback (return false) ONLY for a store that is
    // loaded, explicitly disabled, AND whose disabled view is currently
    // FRESH. Null / load-failed (!is_open()) fail CLOSED — see the header
    // for the #1498 rationale.
    if (!store || !store->is_open())
        return true;
    if (store->is_rbac_enabled())
        return true;
    // adversarial-review round (#2703): is_rbac_enabled()==false is not, on
    // its own, proof RBAC is genuinely disabled — maybe_refresh_generation()
    // (just invoked by the call above) deliberately never touches a stale
    // cached rbac_enabled_ on a failed refresh, so a replica that has never
    // itself observed a remote enable stays cached false indefinitely
    // through an outage. Treat a degraded view (the refresh did not land)
    // the same as "enabled" here — the one place this distinction is
    // security-relevant, unlike the raw is_rbac_enabled() accessor other
    // (non-confinement) callers use.
    return store->rbac_enabled_view_degraded();
}

// ── Roles CRUD ───────────────────────────────────────────────────────────────

std::vector<RbacRole> RbacStore::list_roles() const {
    std::vector<RbacRole> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name, description, is_system, created_at FROM rbac_store.roles "
        "ORDER BY is_system DESC, name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        RbacRole role;
        role.name = text_col(r.get(), i, 0);
        role.description = text_col(r.get(), i, 1);
        role.is_system = to_bool(PQgetvalue(r.get(), i, 2));
        role.created_at = to_i64(PQgetvalue(r.get(), i, 3));
        result.push_back(std::move(role));
    }
    return result;
}

std::optional<RbacRole> RbacStore::get_role(const std::string& name) const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name, description, is_system, created_at FROM rbac_store.roles WHERE name = $1",
        std::vector<std::string>{name});
    if (r.status() != PGRES_TUPLES_OK || PQntuples(r.get()) != 1)
        return std::nullopt;
    RbacRole role;
    role.name = text_col(r.get(), 0, 0);
    role.description = text_col(r.get(), 0, 1);
    role.is_system = to_bool(PQgetvalue(r.get(), 0, 2));
    role.created_at = to_i64(PQgetvalue(r.get(), 0, 3));
    return role;
}

std::expected<void, std::string> RbacStore::create_role(const RbacRole& role) {
    if (!open_)
        return std::unexpected("database not open");
    if (role.name.empty())
        return std::unexpected("role name cannot be empty");
    const std::int64_t now = now_secs();
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.roles (name, description, is_system, created_at) "
            "VALUES ($1, $2, FALSE, $3::bigint)",
            std::vector<std::string>{sanitize_pg_text(role.name),
                                     sanitize_pg_text(role.description), std::to_string(now)});
        if (r.status() != PGRES_COMMAND_OK) {
            err = std::string("role already exists or DB error: ") + PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "role create failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::update_role(const std::string& name,
                                                        const std::string& description) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    bool not_found = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c, "UPDATE rbac_store.roles SET description = $1 WHERE name = $2 RETURNING name",
            std::vector<std::string>{sanitize_pg_text(description), name});
        if (r.status() != PGRES_TUPLES_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        if (PQntuples(r.get()) == 0) {
            not_found = true;
            return false; // roll back — nothing changed, no generation bump
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (not_found)
        return std::unexpected("role not found");
    if (!ok)
        return std::unexpected(err.empty() ? "role update failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::delete_role(const std::string& name) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    bool not_found = false;
    bool is_system = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult chk = pg::exec_params(
            c, "SELECT is_system FROM rbac_store.roles WHERE name = $1",
            std::vector<std::string>{name});
        if (chk.status() != PGRES_TUPLES_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        if (PQntuples(chk.get()) == 0) {
            not_found = true;
            return false;
        }
        if (to_bool(PQgetvalue(chk.get(), 0, 0))) {
            is_system = true;
            return false;
        }
        pg::PgResult del = pg::exec_params(
            c, "DELETE FROM rbac_store.roles WHERE name = $1 AND is_system = FALSE",
            std::vector<std::string>{name});
        if (del.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (not_found)
        return std::unexpected("role not found");
    if (is_system)
        return std::unexpected("cannot delete system role");
    if (!ok)
        return std::unexpected(err.empty() ? "role delete failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

// ── Permissions CRUD ─────────────────────────────────────────────────────────

namespace {
Permission read_perm(PGresult* r, int i) {
    Permission p;
    p.role_name = text_col(r, i, 0);
    p.securable_type = text_col(r, i, 1);
    p.operation = text_col(r, i, 2);
    p.effect = text_col(r, i, 3);
    return p;
}
} // namespace

std::vector<Permission> RbacStore::get_role_permissions(const std::string& role_name) const {
    std::vector<Permission> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT role_name, securable_type, operation, effect FROM rbac_store.role_permissions "
        "WHERE role_name = $1 ORDER BY securable_type, operation",
        std::vector<std::string>{role_name});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_perm(r.get(), i));
    return result;
}

std::expected<std::vector<Permission>, std::string>
RbacStore::get_role_permissions_checked(const std::string& role_name) const {
    if (!open_)
        return std::unexpected("rbac store not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("pool acquire timeout");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT role_name, securable_type, operation, effect FROM rbac_store.role_permissions "
        "WHERE role_name = $1 ORDER BY securable_type, operation",
        std::vector<std::string>{role_name});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    std::vector<Permission> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_perm(r.get(), i));
    return result;
}

std::expected<std::vector<Permission>, std::string>
RbacStore::list_all_role_permissions_checked() const {
    if (!open_)
        return std::unexpected("rbac store not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("pool acquire timeout");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT role_name, securable_type, operation, effect FROM rbac_store.role_permissions "
        "ORDER BY role_name, securable_type, operation",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    std::vector<Permission> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_perm(r.get(), i));
    return result;
}

std::expected<void, std::string> RbacStore::set_permission(const Permission& perm) {
    if (perm.effect != "allow" && perm.effect != "deny")
        return std::unexpected("effect must be 'allow' or 'deny'");
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.role_permissions (role_name, securable_type, operation, effect) "
            "VALUES ($1, $2, $3, $4) ON CONFLICT (role_name, securable_type, operation) "
            "DO UPDATE SET effect = EXCLUDED.effect",
            std::vector<std::string>{sanitize_pg_text(perm.role_name),
                                     sanitize_pg_text(perm.securable_type),
                                     sanitize_pg_text(perm.operation), perm.effect});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "set_permission failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::remove_permission(const std::string& role_name,
                                                              const std::string& securable_type,
                                                              const std::string& operation) {
    if (!open_)
        return std::unexpected("database not open");
    // security-guardian (#2703, HIGH — the F1 disease recurring outside the
    // one-time backfill): a hard DELETE here does not stick against a
    // built-in default. seed_defaults() runs UNCONDITIONALLY on every
    // RbacStore construction (every server boot/restart — that is the
    // documented mechanism new securables rely on to reseed with no
    // migration) and its grant() calls are `ON CONFLICT DO NOTHING`. A
    // deleted row leaves nothing to conflict with, so the very next restart
    // silently re-inserts the seeded 'allow' — the operator's revocation is
    // undone forever, on ordinary restart/redeploy, no attacker required.
    //
    // fable (Gate 4, #2703, HIGH — this round's fix REVISED again): an
    // earlier fix upserted an explicit 'deny' row instead of deleting, on
    // the theory that "the authorization OUTCOME is identical either way
    // (no matching allow row -> deny)". That theory is false. 'deny' is a
    // REAL, operator-authored authorization fact, and check_permission() /
    // check_scoped_permission() / authorize_list_read() all apply "deny
    // overrides everything, across ALL of a principal's held roles" — a
    // pre-existing, deliberate invariant, identical in the legacy SQLite
    // store. A deny row from THIS role therefore vetoes an allow this same
    // principal holds via a DIFFERENT role — legacy never hit this, because
    // its DELETE left nothing to veto with; the tombstone does. Fix:
    // restore the plain DELETE, and record the revocation SEPARATELY, as
    // pure reseed-suppression bookkeeping in revoked_seed_defaults — a
    // table seed_defaults()'s grant() consults and no authorization-decision
    // code path ever reads. Both statements share one transaction (and the
    // same generation bump) so a crash between them can never leave the
    // row deleted with no marker to stop it resurrecting on the next boot.
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // chaos-injector (Gate 5, #2703, HIGH — CHAOS-1): must be the FIRST
        // statement in this transaction — see kRevokeCoordLockSql's comment.
        // Serializes against seed_defaults()'s grant() and the backfill's F1
        // revoke block for the same coordination window.
        pg::PgResult lk = pg::exec_params(c, kRevokeCoordLockSql, std::vector<std::string>{});
        if (lk.status() != PGRES_TUPLES_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        pg::PgResult marker = pg::exec_params(
            c,
            "INSERT INTO rbac_store.revoked_seed_defaults (role_name, securable_type, "
            "operation) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            std::vector<std::string>{sanitize_pg_text(role_name), sanitize_pg_text(securable_type),
                                     sanitize_pg_text(operation)});
        if (marker.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        pg::PgResult del = pg::exec_params(
            c,
            "DELETE FROM rbac_store.role_permissions WHERE role_name = $1 AND "
            "securable_type = $2 AND operation = $3",
            std::vector<std::string>{sanitize_pg_text(role_name), sanitize_pg_text(securable_type),
                                     sanitize_pg_text(operation)});
        if (del.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "remove_permission failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

// ── Principal-role assignments ───────────────────────────────────────────────

namespace {
PrincipalRole read_pr(PGresult* r, int i) {
    PrincipalRole pr;
    pr.principal_type = text_col(r, i, 0);
    pr.principal_id = text_col(r, i, 1);
    pr.role_name = text_col(r, i, 2);
    return pr;
}
} // namespace

std::vector<PrincipalRole> RbacStore::get_principal_roles(const std::string& principal_type,
                                                          const std::string& principal_id) const {
    std::vector<PrincipalRole> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT principal_type, principal_id, role_name FROM rbac_store.principal_roles "
        "WHERE principal_type = $1 AND principal_id = $2 ORDER BY role_name",
        std::vector<std::string>{principal_type, principal_id});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_pr(r.get(), i));
    return result;
}

std::expected<std::vector<PrincipalRole>, std::string>
RbacStore::get_principal_roles_checked(const std::string& principal_type,
                                       const std::string& principal_id) const {
    if (!open_)
        return std::unexpected("rbac store not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("pool acquire timeout");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT principal_type, principal_id, role_name FROM rbac_store.principal_roles "
        "WHERE principal_type = $1 AND principal_id = $2 ORDER BY role_name",
        std::vector<std::string>{principal_type, principal_id});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    std::vector<PrincipalRole> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_pr(r.get(), i));
    return result;
}

std::expected<std::vector<PrincipalRole>, std::string>
RbacStore::list_all_principal_roles_checked() const {
    if (!open_)
        return std::unexpected("rbac store not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("pool acquire timeout");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT principal_type, principal_id, role_name FROM rbac_store.principal_roles "
        "ORDER BY principal_type, principal_id, role_name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    std::vector<PrincipalRole> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_pr(r.get(), i));
    return result;
}

std::vector<PrincipalRole> RbacStore::get_role_members(const std::string& role_name) const {
    std::vector<PrincipalRole> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT principal_type, principal_id, role_name FROM rbac_store.principal_roles "
        "WHERE role_name = $1 ORDER BY principal_type, principal_id",
        std::vector<std::string>{role_name});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_pr(r.get(), i));
    return result;
}

std::expected<void, std::string> RbacStore::validate_assignment(const std::string& principal_type,
                                                                const std::string& principal_id,
                                                                const std::string& role_name) {
    // F2: an `engine:`-prefixed principal_id must ONLY be assigned under
    // principal_type=="engine" (else a shadow ('user','engine:x',role) row
    // would attribute an engine identity's perms to a user lookup).
    if (principal_type != "engine" && principal_id.starts_with(kEnginePrefix))
        return std::unexpected(
            "principal_id in the reserved 'engine:' namespace may only be assigned under "
            "principal_type=\"engine\"");

    if (principal_type != "user" && principal_type != "group" && principal_type != "engine")
        return std::unexpected("unrecognized principal_type '" + principal_type + "'");

    if (principal_type != "engine")
        return {};

    if (!principal_id.starts_with(kEnginePrefix) || principal_id.size() == kEnginePrefix.size())
        return std::unexpected(
            "engine principal_id must be in the reserved 'engine:<slug>' namespace with a "
            "non-empty slug");

    for (auto disallowed : kEngineDisallowedRoles) {
        if (role_name == disallowed)
            return std::unexpected("engine principals cannot be granted the admin/full-access "
                                   "role '" +
                                   role_name + "' — no admin, ever (design §4.2)");
    }
    return {};
}

std::expected<void, std::string> RbacStore::assign_role(const PrincipalRole& pr) {
    if (!open_)
        return std::unexpected("database not open");
    if (auto v = validate_assignment(pr.principal_type, pr.principal_id, pr.role_name); !v)
        return std::unexpected(v.error());

    std::optional<std::uint64_t> new_gen;
    bool builtin_reject = false;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // F1: for an engine principal, reject ANY built-in (is_system) role via
        // its own `is_system` flag — generalizes the static "no admin, ever"
        // bar to "no built-in role, ever" for the fleet-wide path.
        if (pr.principal_type == "engine") {
            pg::PgResult chk = pg::exec_params(
                c, "SELECT is_system FROM rbac_store.roles WHERE name = $1",
                std::vector<std::string>{pr.role_name});
            if (chk.status() != PGRES_TUPLES_OK) {
                err = PQerrorMessage(c);
                return false;
            }
            if (PQntuples(chk.get()) == 1 && to_bool(PQgetvalue(chk.get(), 0, 0))) {
                builtin_reject = true;
                return false;
            }
        }
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.principal_roles (principal_type, principal_id, role_name) "
            "VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            std::vector<std::string>{sanitize_pg_text(pr.principal_type),
                                     sanitize_pg_text(pr.principal_id),
                                     sanitize_pg_text(pr.role_name)});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (builtin_reject)
        return std::unexpected("engine principals cannot be granted a built-in system role '" +
                               pr.role_name + "' — no built-in role, ever (design §4.2)");
    if (!ok)
        return std::unexpected(err.empty() ? "assign_role failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::unassign_role(const std::string& principal_type,
                                                          const std::string& principal_id,
                                                          const std::string& role_name) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "DELETE FROM rbac_store.principal_roles WHERE principal_type = $1 AND principal_id = $2 "
            "AND role_name = $3",
            std::vector<std::string>{principal_type, principal_id, role_name});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "unassign_role failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

// ── Groups CRUD ──────────────────────────────────────────────────────────────

std::vector<RbacGroup> RbacStore::list_groups() const {
    std::vector<RbacGroup> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name, description, source, external_id, created_at FROM rbac_store.groups "
        "ORDER BY name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        RbacGroup g;
        g.name = text_col(r.get(), i, 0);
        g.description = text_col(r.get(), i, 1);
        g.source = text_col(r.get(), i, 2);
        g.external_id = text_col(r.get(), i, 3); // NULL → ""
        g.created_at = to_i64(PQgetvalue(r.get(), i, 4));
        result.push_back(std::move(g));
    }
    return result;
}

std::expected<std::vector<RbacGroup>, std::string> RbacStore::list_groups_checked() const {
    if (!open_)
        return std::unexpected("rbac store not open");
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("pool acquire timeout");
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name, description, source, external_id, created_at FROM rbac_store.groups "
        "ORDER BY name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    std::vector<RbacGroup> result;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        RbacGroup g;
        g.name = text_col(r.get(), i, 0);
        g.description = text_col(r.get(), i, 1);
        g.source = text_col(r.get(), i, 2);
        g.external_id = text_col(r.get(), i, 3);
        g.created_at = to_i64(PQgetvalue(r.get(), i, 4));
        result.push_back(std::move(g));
    }
    return result;
}

std::optional<std::vector<std::string>>
RbacStore::find_local_groups_with_prefix(const std::string& prefix) const {
    // A closed/unopened store, a pool timeout, or a query error is a scan
    // FAILURE, not "nothing to match" — signal it distinctly (nullopt) so the T8
    // preflight fails closed instead of trusting an engaged-but-empty result.
    if (!open_)
        return std::nullopt;
    // `prefix` is code-controlled — fail closed (empty result) if it ever
    // carries a LIKE metacharacter.
    if (prefix.empty() || prefix.find_first_of("%_\\") != std::string::npos)
        return std::vector<std::string>{};
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT name FROM rbac_store.groups WHERE source = 'local' AND name LIKE $1",
        std::vector<std::string>{prefix + "%"});
    if (r.status() != PGRES_TUPLES_OK) {
        spdlog::error("find_local_groups_with_prefix: scan of prefix '{}' failed: {}", prefix,
                      PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    std::vector<std::string> result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

std::expected<void, std::string> RbacStore::create_group(const RbacGroup& group) {
    if (!open_)
        return std::unexpected("database not open");
    if (group.name.empty())
        return std::unexpected("group name cannot be empty");
    if (group.source == "local" && has_reserved_idp_prefix(group.name))
        return std::unexpected(
            "group name uses a reserved identity-provider or engine-principal namespace prefix "
            "(local:/entra:/saml:/ad:/engine:)");
    const std::int64_t now = now_secs();
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.groups (name, description, source, external_id, created_at) "
            "VALUES ($1, $2, $3, $4, $5::bigint)",
            std::vector<std::string>{sanitize_pg_text(group.name),
                                     sanitize_pg_text(group.description),
                                     sanitize_pg_text(group.source),
                                     sanitize_pg_text(group.external_id), std::to_string(now)});
        if (r.status() != PGRES_COMMAND_OK) {
            err = std::string("group already exists or DB error: ") + PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "create_group failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::delete_group(const std::string& name) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r =
            pg::exec_params(c, "DELETE FROM rbac_store.groups WHERE name = $1",
                            std::vector<std::string>{name});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "delete_group failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::vector<std::string> RbacStore::get_group_members(const std::string& group_name) const {
    std::vector<std::string> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT username FROM rbac_store.group_members WHERE group_name = $1 ORDER BY username",
        std::vector<std::string>{group_name});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

std::expected<void, std::string> RbacStore::add_group_member(const std::string& group_name,
                                                             const std::string& username) {
    if (!open_)
        return std::unexpected("database not open");
    // G5: reject an `engine:`-prefixed username at this write surface too
    // (the group-resolution arm would otherwise hand it the group's roles).
    if (username.starts_with(kEnginePrefix))
        return std::unexpected(
            "principal_id in the reserved 'engine:' namespace cannot be added as a group member");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c,
            "INSERT INTO rbac_store.group_members (group_name, username) VALUES ($1, $2) "
            "ON CONFLICT DO NOTHING",
            std::vector<std::string>{sanitize_pg_text(group_name), sanitize_pg_text(username)});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "add_group_member failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<void, std::string> RbacStore::remove_group_member(const std::string& group_name,
                                                                const std::string& username) {
    if (!open_)
        return std::unexpected("database not open");
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        pg::PgResult r = pg::exec_params(
            c, "DELETE FROM rbac_store.group_members WHERE group_name = $1 AND username = $2",
            std::vector<std::string>{group_name, username});
        if (r.status() != PGRES_COMMAND_OK) {
            err = PQerrorMessage(c);
            return false;
        }
        new_gen = bump_generation_in_txn(c);
        return new_gen.has_value();
    });
    if (!ok)
        return std::unexpected(err.empty() ? "remove_group_member failed" : err);
    apply_local_generation(*new_gen);
    return {};
}

std::expected<ReconcileResult, std::string> RbacStore::reconcile_idp_memberships(
    const std::string& username, const std::string& source,
    const std::vector<std::pair<std::string, std::string>>& asserted) {
    if (asserted.size() > kMaxIdpGroupsPerLogin)
        return std::unexpected("group_count_exceeded");

    bool recognized_source = false;
    for (auto s : kRecognizedIdpSources) {
        if (source == s) {
            recognized_source = true;
            break;
        }
    }
    if (!recognized_source)
        return std::unexpected("invalid_source");

    // UP-9: drop asserted entries whose external_id can't produce a sane group
    // name — blank/whitespace-only or implausibly long.
    std::vector<std::pair<std::string, std::string>> valid;
    valid.reserve(asserted.size());
    for (const auto& a : asserted) {
        if (is_blank(a.first)) {
            spdlog::warn("reconcile_idp_memberships: skipping asserted entry with blank "
                         "external_id (user='{}', source='{}')",
                         username, source);
            continue;
        }
        if (a.first.size() > kMaxExternalIdLength) {
            spdlog::warn("reconcile_idp_memberships: skipping asserted external_id exceeding {} "
                         "bytes (user='{}', source='{}')",
                         kMaxExternalIdLength, username, source);
            continue;
        }
        valid.push_back(a);
    }

    if (!open_)
        return std::unexpected("database not open");

    const std::int64_t now = now_secs();

    // Namespaced names computed once: reused for the upsert loop AND the
    // stale-membership DELETE's NOT IN list.
    std::vector<std::string> namespaced;
    namespaced.reserve(valid.size());
    for (const auto& a : valid)
        namespaced.push_back(namespaced_group_name(source, a.first));

    ReconcileResult result;
    std::optional<std::uint64_t> new_gen;
    std::string err;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        for (size_t i = 0; i < valid.size(); ++i) {
            const auto& external_id = valid[i].first;
            const auto& display = valid[i].second;
            const auto& name = namespaced[i];
            const auto description = std::string("IdP-provisioned group (") + source + "): " +
                                     (display.empty() ? external_id : display);

            pg::PgResult ins_group = pg::exec_params(
                c,
                "INSERT INTO rbac_store.groups (name, description, source, external_id, created_at) "
                "VALUES ($1, $2, $3, $4, $5::bigint) ON CONFLICT (name) DO NOTHING",
                std::vector<std::string>{sanitize_pg_text(name), sanitize_pg_text(description),
                                         sanitize_pg_text(source), sanitize_pg_text(external_id),
                                         std::to_string(now)});
            if (ins_group.status() != PGRES_COMMAND_OK) {
                err = std::string("group upsert failed: ") + PQerrorMessage(c);
                return false;
            }

            // sec-L1: verify the (possibly pre-existing) row's source before
            // joining a membership — never leak a different-source group's roles.
            pg::PgResult chk = pg::exec_params(
                c, "SELECT source FROM rbac_store.groups WHERE name = $1",
                std::vector<std::string>{sanitize_pg_text(name)});
            if (chk.status() != PGRES_TUPLES_OK) {
                err = std::string("group source check failed: ") + PQerrorMessage(c);
                return false;
            }
            bool source_mismatch = false;
            if (PQntuples(chk.get()) == 1) {
                const std::string existing = text_col(chk.get(), 0, 0);
                if (source != existing)
                    source_mismatch = true;
            }
            if (source_mismatch) {
                spdlog::warn("reconcile_idp_memberships: NOT joining '{}' to pre-existing group "
                             "'{}' — row source differs from reconcile source '{}' "
                             "(confused-deputy guard)",
                             username, name, source);
                continue;
            }

            pg::PgResult ins_member = pg::exec_params(
                c,
                "INSERT INTO rbac_store.group_members (group_name, username) VALUES ($1, $2) "
                "ON CONFLICT DO NOTHING RETURNING 1",
                std::vector<std::string>{sanitize_pg_text(name), sanitize_pg_text(username)});
            if (ins_member.status() != PGRES_TUPLES_OK) {
                err = std::string("membership upsert failed: ") + PQerrorMessage(c);
                return false;
            }
            if (PQntuples(ins_member.get()) == 1)
                ++result.added;
        }

        // Remove stale IdP memberships: any group_members row for this user
        // whose group is owned by THIS source and was NOT re-asserted.
        std::string sql = "DELETE FROM rbac_store.group_members WHERE username = $1 "
                          "AND group_name IN (SELECT name FROM rbac_store.groups WHERE source = $2)";
        std::vector<std::string> params{username, source};
        if (!namespaced.empty()) {
            sql += " AND group_name NOT IN (";
            for (size_t i = 0; i < namespaced.size(); ++i) {
                sql += (i == 0 ? "$" : ",$") + std::to_string(3 + i);
                params.push_back(sanitize_pg_text(namespaced[i]));
            }
            sql += ")";
        }
        sql += " RETURNING group_name";
        pg::PgResult del = pg::exec_params(c, sql.c_str(), params);
        if (del.status() != PGRES_TUPLES_OK) {
            err = std::string("stale-membership delete failed: ") + PQerrorMessage(c);
            return false;
        }
        result.removed = static_cast<size_t>(PQntuples(del.get()));

        // Bump the durable generation ONLY when membership actually changed
        // (Gate 4 consistency SHOULD-1). A no-op reconcile runs on EVERY IdP
        // login re-asserting unchanged groups; an unconditional bump would clear
        // the perm cache fleet-wide on every login, defeating the very cache the
        // generation-token compromise was chosen to preserve.
        if (result.added || result.removed) {
            new_gen = bump_generation_in_txn(c);
            return new_gen.has_value();
        }
        return true; // no-op reconcile: commit, no generation churn
    });
    if (!ok)
        return std::unexpected(err.empty() ? "reconcile transaction failed" : err);
    if (new_gen)
        apply_local_generation(*new_gen);
    return result;
}

// ── Authorization check ──────────────────────────────────────────────────────

std::vector<std::string> RbacStore::collect_roles(void* conn, const std::string& username) const {
    std::vector<std::string> roles;
    auto* c = static_cast<PGconn*>(conn);
    // Three-way UNION: direct user grant, group-membership grant, and (§4.1)
    // direct engine-principal grant. $1 reused for all three arms.
    pg::PgResult r = pg::exec_params(
        c,
        "SELECT role_name FROM rbac_store.principal_roles "
        "WHERE principal_type = 'user' AND principal_id = $1 "
        "UNION "
        "SELECT pr.role_name FROM rbac_store.principal_roles pr "
        "JOIN rbac_store.group_members gm ON pr.principal_type = 'group' AND "
        "pr.principal_id = gm.group_name WHERE gm.username = $1 "
        "UNION "
        "SELECT role_name FROM rbac_store.principal_roles "
        "WHERE principal_type = 'engine' AND principal_id = $1",
        std::vector<std::string>{username});
    if (r.status() != PGRES_TUPLES_OK)
        return roles; // fail-closed: empty role set → deny
    for (int i = 0; i < PQntuples(r.get()); ++i)
        roles.push_back(text_col(r.get(), i, 0));
    return roles;
}

std::string RbacStore::perm_cache_key(const std::string& user, const std::string& type,
                                      const std::string& op) const {
    return user + ":" + type + ":" + op;
}

bool RbacStore::check_permission(const std::string& username, const std::string& securable_type,
                                 const std::string& operation) const {
    if (!open_)
        return false; // fail-closed

    // #2703 Gate 7 item 1 commit C: observes on every exit below, whichever
    // return statement fires — excludes the trivial !open_ short-circuit
    // above (a structural/administrative state, not a real check attempt).
    ScopedLatencyObserver latency_obs(authz_check_seconds_hist_);

    maybe_refresh_generation();

    const auto key = perm_cache_key(username, securable_type, operation);
    std::uint64_t gen_at_check = 0;
    bool gen_ok = false;
    {
        std::lock_guard lock(cache_mtx_);
        // G11-CPPEXPERT-B2 (#2703 Gate 8): route through the same
        // staleness check rbac_enabled_view_degraded() uses, not the raw
        // generation_valid_ flag directly -- a stuck-in-flight refresh
        // (PG-side lock contention, #3016) can leave generation_valid_ true
        // and stale for the whole stall, and a raw read here would keep
        // serving a stale cached ALLOW/DENY verdict through that window
        // exactly like the already-fixed rbac_enabled path did.
        gen_ok = !generation_view_stale_locked();
        gen_at_check = cached_generation_;
        if (gen_ok) {
            auto it = perm_cache_.find(key);
            if (it != perm_cache_.end())
                return it->second;
        }
    }

    // Breaker-gated (#2703 Gate 7 item 1 commit B): an open breaker denies
    // this pool fallback without an acquire attempt — the cache lookup above
    // ran regardless (never breaker-gated), so this line is reached only on
    // a genuine cache miss.
    if (!breaker_admit()) {
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn(
                "RbacStore::check_permission: circuit breaker open — DENY without pool touch");
        return false; // fail-closed
    }

    auto lease = pool_.try_acquire_for(kAuthzAcquireTimeout);
    if (!lease) {
        breaker_note_result(false);
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("RbacStore::check_permission: pool acquire timed out — DENY");
        return false; // fail-closed
    }
    PGconn* conn = lease.get();

    const auto roles = collect_roles(conn, username);
    if (roles.empty()) {
        // collect_roles() cannot distinguish "genuinely no roles" (the
        // common case for any least-privilege user) from "the query
        // failed" — both return empty. Recording this as a breaker SUCCESS
        // is the deliberate, safer default: treating it as a failure would
        // trip the breaker on ordinary confined-user traffic while Postgres
        // is perfectly healthy, which is worse than under-counting the
        // narrower same-shape connection-failure case this leaves uncovered.
        breaker_note_result(true);
        return false;
    }

    std::string sql = "SELECT effect FROM rbac_store.role_permissions "
                      "WHERE securable_type = $1 AND operation = $2 AND role_name IN (";
    std::vector<std::string> params{securable_type, operation};
    for (size_t i = 0; i < roles.size(); ++i) {
        sql += (i == 0 ? "$" : ",$") + std::to_string(3 + i);
        params.push_back(roles[i]);
    }
    sql += ")";

    pg::PgResult r = pg::exec_params(conn, sql.c_str(), params);
    if (r.status() != PGRES_TUPLES_OK) {
        breaker_note_result(false);
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("RbacStore::check_permission: query failed: {} — DENY",
                         PQerrorMessage(conn));
        return false; // fail-closed
    }
    breaker_note_result(true);
    bool has_allow = false;
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        const std::string effect = text_col(r.get(), i, 0);
        if (effect == "deny")
            return false; // deny overrides everything
        if (effect == "allow")
            has_allow = true;
    }

    // Store only if the generation we validated against is still current — a
    // mutation racing this read (local or cross-replica) must not persist a
    // stale verdict under the new generation.
    {
        std::lock_guard lock(cache_mtx_);
        if (generation_valid_ && gen_ok && cached_generation_ == gen_at_check)
            perm_cache_[key] = has_allow;
    }
    return has_allow;
}

std::vector<Permission> RbacStore::get_effective_permissions(const std::string& username) const {
    std::vector<Permission> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    PGconn* conn = lease.get();

    const auto roles = collect_roles(conn, username);
    if (roles.empty())
        return result;

    std::string sql =
        "SELECT role_name, securable_type, operation, effect FROM rbac_store.role_permissions "
        "WHERE role_name IN (";
    std::vector<std::string> params;
    for (size_t i = 0; i < roles.size(); ++i) {
        sql += (i == 0 ? "$" : ",$") + std::to_string(1 + i);
        params.push_back(roles[i]);
    }
    sql += ") ORDER BY securable_type, operation";

    pg::PgResult r = pg::exec_params(conn, sql.c_str(), params);
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(read_perm(r.get(), i));
    return result;
}

// ── Reference data ───────────────────────────────────────────────────────────

std::vector<std::string> RbacStore::list_securable_types() const {
    std::vector<std::string> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(
        lease.get(), "SELECT name FROM rbac_store.securable_types ORDER BY name",
        std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

std::vector<std::string> RbacStore::list_operations() const {
    std::vector<std::string> result;
    if (!open_)
        return result;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;
    pg::PgResult r = pg::exec_params(lease.get(), "SELECT id FROM rbac_store.operations ORDER BY id",
                                     std::vector<std::string>{});
    if (r.status() != PGRES_TUPLES_OK)
        return result;
    for (int i = 0; i < PQntuples(r.get()); ++i)
        result.push_back(text_col(r.get(), i, 0));
    return result;
}

// ── Scoped permission check ──────────────────────────────────────────────────

bool RbacStore::check_scoped_permission(const std::string& username,
                                        const std::string& securable_type,
                                        const std::string& operation, const std::string& agent_id,
                                        const ManagementGroupStore* mgmt_store) const {
    // 1. Global permission first (a global ALLOW short-circuits, #1715(b)).
    if (check_permission(username, securable_type, operation))
        return true;

    // 2. No mgmt store or agent → cannot do the scoped check.
    if (!mgmt_store || agent_id.empty())
        return false;

    // 3. Resolve allow/deny groups via the shared INV-7 resolver, intersect
    //    with the agent's reachable groups. Deny wins within the scoped set.
    //    Fail-closed: any store error → false.
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg)
        return false;

    // CONFINEMENT reads are now degrade-distinguishable (ADR-0042): a `nullopt`
    // means the mgmt-store degraded (store-not-open / pool-acquire timeout /
    // query error), NOT a genuine empty. Treat it as DenyAll (fail-closed) — a
    // silent empty here would drop the agent's reachable groups and could admit
    // a scoped grant that a DENY assignment should have blocked (fail-open).
    auto groups = mgmt_store->get_agent_groups(agent_id);
    if (!groups)
        return false; // mgmt-store degrade → deny
    std::unordered_set<std::string> reachable;
    for (const auto& gid : *groups) {
        reachable.insert(gid);
        auto ancestors = mgmt_store->get_ancestor_ids(gid);
        if (!ancestors)
            return false; // mgmt-store degrade → deny
        for (const auto& aid : *ancestors)
            reachable.insert(aid);
    }
    if (reachable.empty())
        return false;

    for (const auto& g : pg->deny_groups)
        if (reachable.contains(g))
            return false;
    for (const auto& g : pg->allow_groups)
        if (reachable.contains(g))
            return true;
    return false;
}

// ── ADR-0017 admit-then-filter list gate ─────────────────────────────────────

std::expected<std::vector<std::string>, std::string>
RbacStore::user_rbac_group_names(const std::string& username) const {
    std::vector<std::string> groups;
    if (!open_)
        return std::unexpected("rbac store not open");
    // Breaker-gated (#2703 Gate 7 item 1 commit B) — see check_permission's
    // pool-fallback gate for the shared rationale.
    if (!breaker_admit()) {
        // #2703 Gate 7 item 3: this is the ADR-0017 admit-then-filter
        // chokepoint (authorize_list_read) — a degrade here is invisible to
        // yuzu_server_rbac_read_degrade_total / YuzuRbacReadDegraded without
        // this call. Reuses check_permission's reason label so the alert's
        // existing regex needs no change.
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn(
                "RbacStore::user_rbac_group_names: circuit breaker open — DENY without pool touch");
        return std::unexpected("circuit breaker open");
    }
    auto lease = pool_.try_acquire_for(kAuthzAcquireTimeout);
    if (!lease) {
        breaker_note_result(false);
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("RbacStore::user_rbac_group_names: pool acquire timed out — DENY");
        return std::unexpected("pool acquire timeout");
    }
    pg::PgResult r = pg::exec_params(
        lease.get(), "SELECT group_name FROM rbac_store.group_members WHERE username = $1",
        std::vector<std::string>{username});
    if (r.status() != PGRES_TUPLES_OK) {
        breaker_note_result(false);
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("RbacStore::user_rbac_group_names: query failed: {} — DENY",
                         PQerrorMessage(lease.get()));
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    }
    breaker_note_result(true);
    for (int i = 0; i < PQntuples(r.get()); ++i)
        groups.push_back(text_col(r.get(), i, 0));
    return groups;
}

std::expected<std::unordered_map<std::string, int>, std::string>
RbacStore::role_effects_for(const std::string& securable_type, const std::string& operation) const {
    std::unordered_map<std::string, int> role_effect; // -1 deny (wins), 1 allow, 0 none
    if (!open_)
        return std::unexpected("rbac store not open");
    // Breaker-gated (#2703 Gate 7 item 1 commit B) — see check_permission's
    // pool-fallback gate for the shared rationale.
    if (!breaker_admit()) {
        // #2703 Gate 7 item 3 — see user_rbac_group_names' matching call for
        // the ADR-0017 chokepoint-visibility rationale; same reason labels.
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn(
                "RbacStore::role_effects_for: circuit breaker open — DENY without pool touch");
        return std::unexpected("circuit breaker open");
    }
    auto lease = pool_.try_acquire_for(kAuthzAcquireTimeout);
    if (!lease) {
        breaker_note_result(false);
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonPoolTimeout, sampler))
            spdlog::warn("RbacStore::role_effects_for: pool acquire timed out — DENY");
        return std::unexpected("pool acquire timeout");
    }
    pg::PgResult r = pg::exec_params(
        lease.get(),
        "SELECT role_name, effect FROM rbac_store.role_permissions "
        "WHERE securable_type = $1 AND operation = $2",
        std::vector<std::string>{securable_type, operation});
    if (r.status() != PGRES_TUPLES_OK) {
        breaker_note_result(false);
        static DegradeSampler sampler;
        if (note_read_degrade(metrics_, kReasonQueryError, sampler))
            spdlog::warn("RbacStore::role_effects_for: query failed: {} — DENY",
                         PQerrorMessage(lease.get()));
        return std::unexpected(std::string("query failed: ") + PQerrorMessage(lease.get()));
    }
    breaker_note_result(true);
    for (int i = 0; i < PQntuples(r.get()); ++i) {
        const std::string role = text_col(r.get(), i, 0);
        const std::string effect = text_col(r.get(), i, 1);
        if (role.empty())
            continue;
        int& e = role_effect[role];
        if (effect == "deny")
            e = -1;
        else if (effect == "allow" && e == 0)
            e = 1;
    }
    return role_effect;
}

std::expected<RbacStore::PermGroups, std::string>
RbacStore::resolve_perm_groups(const std::string& username, const std::string& securable_type,
                               const std::string& operation,
                               const ManagementGroupStore* mgmt_store) const {
    if (!mgmt_store)
        return std::unexpected("management group store unavailable");

    auto rbac_groups = user_rbac_group_names(username);
    if (!rbac_groups)
        return std::unexpected(rbac_groups.error());

    auto assignments = mgmt_store->get_assignments_for_principal(username, *rbac_groups);
    if (!assignments)
        return std::unexpected(assignments.error());

    auto role_effect_r = role_effects_for(securable_type, operation);
    if (!role_effect_r)
        return std::unexpected(role_effect_r.error());
    const auto& role_effect = *role_effect_r;

    PermGroups pg;
    std::unordered_set<std::string> allow_seen, deny_seen;
    for (const auto& a : *assignments) {
        auto it = role_effect.find(a.role_name);
        if (it == role_effect.end() || it->second == 0)
            continue;
        if (it->second == -1) {
            if (deny_seen.insert(a.group_id).second)
                pg.deny_groups.push_back(a.group_id);
        } else if (allow_seen.insert(a.group_id).second) {
            pg.allow_groups.push_back(a.group_id);
        }
    }
    return pg;
}

std::expected<std::vector<std::string>, std::string>
RbacStore::expand_visible_set(const PermGroups& pg, const ManagementGroupStore* mgmt_store) const {
    if (!mgmt_store)
        return std::unexpected("management group store unavailable");
    if (pg.allow_groups.empty())
        return std::vector<std::string>{}; // holds nothing via groups → empty (INV-2)

    auto allow_agents = mgmt_store->get_member_agents_in_subtrees(pg.allow_groups);
    if (!allow_agents)
        return std::unexpected(allow_agents.error());

    if (!pg.deny_groups.empty()) {
        auto deny_agents = mgmt_store->get_member_agents_in_subtrees(pg.deny_groups);
        if (!deny_agents)
            return std::unexpected(deny_agents.error());
        std::unordered_set<std::string> denied(deny_agents->begin(), deny_agents->end());
        std::vector<std::string> visible;
        visible.reserve(allow_agents->size());
        for (auto& a : *allow_agents)
            if (!denied.contains(a))
                visible.push_back(std::move(a));
        allow_agents = std::move(visible);
    }
    std::sort(allow_agents->begin(), allow_agents->end());
    allow_agents->erase(std::unique(allow_agents->begin(), allow_agents->end()),
                        allow_agents->end());
    return allow_agents;
}

bool RbacStore::holds_permission_via_any_group(const std::string& username,
                                               const std::string& securable_type,
                                               const std::string& operation,
                                               const ManagementGroupStore* mgmt_store) const {
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg)
        return false; // fail-closed on any store error
    return !pg->allow_groups.empty();
}

std::expected<std::vector<std::string>, std::string>
RbacStore::visible_agents_for_permission(const std::string& username,
                                         const std::string& securable_type,
                                         const std::string& operation,
                                         const ManagementGroupStore* mgmt_store) const {
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg)
        return std::unexpected(pg.error());
    return expand_visible_set(*pg, mgmt_store);
}

ListReadAuthorization RbacStore::authorize_list_read(const std::string& username,
                                                     const std::string& securable_type,
                                                     const std::string& operation,
                                                     const ManagementGroupStore* mgmt_store) const {
    ListReadAuthorization out; // DenyAll by default — the INV-1 fail-closed default.

    // Legacy-open: RBAC loaded AND explicitly disabled → full-fleet read. A
    // null / load-failed store returns true from rbac_enforcement_in_effect and
    // falls through to the RBAC path, which denies (INV-1).
    if (!rbac_enforcement_in_effect(this)) {
        out.decision = ListReadDecision::AdmitAll;
        return out;
    }

    // #1715(b): a global ALLOW overrides any group deny → unfiltered read.
    if (check_permission(username, securable_type, operation)) {
        out.decision = ListReadDecision::AdmitAll;
        return out;
    }

    // #1715(a): additive — a group allow admits even against a global deny/absent.
    auto pg = resolve_perm_groups(username, securable_type, operation, mgmt_store);
    if (!pg || pg->allow_groups.empty()) {
        out.decision = ListReadDecision::DenyAll; // INV-1/INV-5: error or no grant → deny
        return out;
    }
    auto visible = expand_visible_set(*pg, mgmt_store);
    if (!visible) {
        out.decision = ListReadDecision::DenyAll; // fail-closed on a subtree-read error
        return out;
    }
    out.decision = ListReadDecision::AdmitScoped;
    out.visible_agents = std::move(*visible);
    return out;
}

bool RbacStore::check_role_has_permission(const std::string& role_name,
                                          const std::string& securable_type,
                                          const std::string& operation) const {
    // Uses the fail-closed authoritative read: on a store error the checked
    // variant returns unexpected → DENY (never a false allow).
    auto perms = get_role_permissions_checked(role_name);
    if (!perms)
        return false;
    for (const auto& p : *perms) {
        if (p.securable_type == securable_type && p.operation == operation) {
            if (p.effect == "deny")
                return false;
            if (p.effect == "allow")
                return true;
        }
    }
    return false;
}

// ── Backfill (ADR-0009 MANDATORY class / ADR-0041) ───────────────────────────

bool RbacStore::migrate_from_sqlite(const std::filesystem::path& legacy_db_path) {
    if (!open_)
        return false;

    const auto backfill_metric = [this](const char* result) {
        if (metrics_)
            metrics_->counter("yuzu_server_rbac_backfill_total", {{"result", result}}).increment();
    };

    // adversarial-review (PR #2703, BLOCKER — sourceless-marker anti-pattern,
    // docs/postgres-store-playbook.md "Local source absence never creates
    // terminal migration state on its own", #2697): the marker and its
    // source fingerprint are ALWAYS stamped together, in the SAME
    // transaction, matching AuditStore's fixed reference.
    //
    // governance re-review (Sol, verified empirically against real Postgres
    // before shipping — see the promotion table this SQL was checked
    // against): the fingerprint write is a MONOTONIC PROMOTION, not a plain
    // first-writer-wins race, because "sourceless" carries no evidence worth
    // protecting. A real fingerprint may promote a stored "sourceless"
    // value (a fileless sibling stamped first, then this replica's real
    // migration lands); a stored REAL value is never overwritten by anyone,
    // sourceless or real-but-different; a writer whose value already equals
    // what's stored counts as success, not a lost race (closes a same-
    // fingerprint lockout the WHERE-less DO NOTHING version had: two
    // replicas sharing storage, both migrating the identical real file,
    // simultaneous boot — the loser used to fail even though the values
    // matched). RETURNING + PQntuples() (not PQcmdTuples on a DO NOTHING) is
    // the correct read of "did this call's value end up as the stored one":
    // 1 row means it did (fresh insert, promotion, or already-equal); 0 rows
    // means a DIFFERENT real value already won and this call's write was
    // rejected by the WHERE clause.
    const auto stamp_complete = [&](std::string_view source_fingerprint) -> bool {
        return pool_.with_txn_for(
            kBackfillTxnTimeout, [source_fingerprint](PGconn* c) -> bool {
                pg::PgResult mk = pg::exec_params(
                    c,
                    "INSERT INTO rbac_store.rbac_meta (key, value) VALUES "
                    "('backfill_complete', $1) ON CONFLICT (key) DO NOTHING",
                    std::vector<std::string>{std::to_string(now_secs())});
                if (mk.status() != PGRES_COMMAND_OK) {
                    spdlog::error("RbacStore: migrate_from_sqlite: marker stamp failed: {}",
                                  PQerrorMessage(c));
                    return false;
                }
                pg::PgResult fp = pg::exec_params(
                    c,
                    "INSERT INTO rbac_store.rbac_meta (key, value) VALUES "
                    "('backfill_source_fingerprint', $1) ON CONFLICT (key) DO UPDATE SET "
                    "value = EXCLUDED.value WHERE rbac_store.rbac_meta.value = 'sourceless' OR "
                    "rbac_store.rbac_meta.value = EXCLUDED.value RETURNING value",
                    std::vector<std::string>{std::string(source_fingerprint)});
                if (fp.status() != PGRES_TUPLES_OK) {
                    spdlog::error(
                        "RbacStore: migrate_from_sqlite: source-fingerprint stamp failed: {}",
                        PQerrorMessage(c));
                    return false;
                }
                if (PQntuples(fp.get()) == 0 && source_fingerprint != kSourcelessFingerprint) {
                    // unhappy-path (round 2, C2): this replica's own steps
                    // 4-6 already committed real writes to Postgres before
                    // losing this race — they are not rolled back, and a
                    // retry does NOT recover cleanly. The next boot will
                    // find the marker present with a DIFFERENT real
                    // fingerprint and permanently refuse (HOLDER-SIDE
                    // VERIFICATION FAILED) until an operator reconciles
                    // which replica's config is authoritative — see the
                    // runbook. Say that plainly rather than implying a
                    // clean automatic recovery exists.
                    spdlog::error(
                        "RbacStore: migrate_from_sqlite: lost the race to record this backfill's "
                        "own source fingerprint — a DIFFERENT real fingerprint already stamped "
                        "backfill_source_fingerprint between this pass's marker-absent check and "
                        "this commit. This replica's own migration steps already committed to "
                        "Postgres; a retry will find the marker present, fail holder-side "
                        "fingerprint verification against the winning replica's value, and "
                        "require manual reconciliation — see "
                        "docs/ops-runbooks/rbac-store-backfill-recovery.md.");
                    return false;
                }
                // A sourceless stamp losing this same race is NOT an error (matches
                // AuditStore's stamp_complete, audit_store.cpp): whichever writer's
                // "sourceless" value won is the same value this call would have
                // written, so there is nothing this replica's boot needs to refuse
                // over — refusing here would fail an ordinary simultaneous
                // multi-replica fresh install for no security benefit.
                return true;
            });
    };

    // Shared by step 8 (fresh successful migration) AND the verified-match
    // branch of step 2 (this replica's OWN already-migrated file is still
    // present, e.g. an earlier move-aside attempt failed) — non-fatal on
    // failure either way, logged for an operator to clean up manually.
    // governance re-review (Fable): RbacStore's verified-match path used to
    // just skip without retrying the rename, unlike AuditStore's equivalent
    // (audit_store.cpp) — a once-failed move-aside then re-fingerprinted the
    // same file on every future boot forever, never converging on the
    // playbook's one-release retention policy.
    const auto move_legacy_aside = [](const std::filesystem::path& path) {
        // cpp-safety (governance re-review, #2703, LOW — empirically
        // confirmed in this round's own test run): a bare now_secs() suffix
        // collides within the same wall-clock second (a fresh migration's
        // move immediately followed by a later verified-match retry against
        // a recreated file at the same path, both within one second), and
        // std::filesystem::rename SILENTLY REPLACES an existing destination
        // on both POSIX and Windows — the first archive is overwritten, not
        // preserved alongside the second. Probe for an unused destination
        // rather than trusting the clock alone to be unique.
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
            spdlog::warn("RbacStore: migrate_from_sqlite: could not move legacy {} aside ({}); "
                         "it is safe to archive/remove manually",
                         path.string(), mv_ec.message());
        else
            spdlog::info("RbacStore: migrate_from_sqlite: moved legacy rbac db to {}",
                         aside.string());
    };

    // 1. Local legacy-file presence (cheap stat) — checked BEFORE the marker
    // lookup so step 2 knows whether THIS replica has something to verify a
    // pre-existing marker against.
    std::error_code ec;
    const bool legacy_exists = std::filesystem::exists(legacy_db_path, ec);
    if (ec) {
        spdlog::error("RbacStore: migrate_from_sqlite: cannot stat legacy path {}: {}",
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
            spdlog::error("RbacStore: migrate_from_sqlite: no database connection ({})",
                          pool_.last_error());
            backfill_metric("failed");
            return false;
        }
        pg::PgResult mk = pg::exec_params(
            lease.get(),
            "SELECT key, value FROM rbac_store.rbac_meta WHERE key IN "
            "('backfill_complete', 'backfill_source_fingerprint')",
            std::vector<std::string>{});
        if (mk.status() != PGRES_TUPLES_OK) {
            spdlog::error("RbacStore: migrate_from_sqlite: marker lookup failed: {}",
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
        // lease released HERE (end of scope) — governance re-review
        // (cpp-safety, MEDIUM): the verification work below is a SQLite file
        // read + SHA-256 hash, which used to run with this Postgres lease
        // still checked out, contradicting the very comment this step
        // carries. legacy_exists is already hoisted above this block for the
        // same reason (step 1's comment); marker_present/stored_fingerprint
        // now get the same treatment.
    }
    if (marker_present) {
        if (!legacy_exists) {
            spdlog::debug("RbacStore: migrate_from_sqlite already completed, skipping");
            return true;
        }
        // This replica still holds a local legacy file even though the
        // fleet marker is already set — verify it was actually the file
        // that got migrated before trusting the marker. A sourceless
        // writer's placeholder can never match a real file's fingerprint,
        // which is exactly what catches the anti-pattern this fix closes.
        const auto verify_fp = legacy_rbac_fingerprint(legacy_db_path);
        if (!verify_fp) {
            spdlog::error(
                "RbacStore: migrate_from_sqlite: backfill_complete is already set, and this "
                "replica's own legacy db {} exists but is unreadable/corrupt while being "
                "fingerprint-verified against it — refusing (fail-closed; never silently "
                "trust a marker over an unverifiable local file)",
                legacy_db_path.string());
            backfill_metric("failed");
            return false;
        }
        if (*verify_fp == kSourcelessFingerprint) {
            // This replica's own local file has no `roles` table — nothing
            // to lose regardless of who stamped the marker or why (matches
            // AuditStore's `legacy_fp->count == 0` short-circuit,
            // audit_store.cpp). Refusing here would penalize a replica for
            // holding a schema-less file it never had operator content in,
            // with no data at risk to justify the boot failure.
            spdlog::debug("RbacStore: migrate_from_sqlite already completed; this replica's "
                         "own legacy db has no roles table (nothing to lose), skipping");
            return true;
        }
        if (!stored_fingerprint) {
            // governance re-review (PR #2703, HIGH — chaos-injector/
            // unhappy-path, unhappy-path's finding EMPIRICALLY reproduced):
            // no `backfill_source_fingerprint` row at all means this marker
            // predates the fingerprint mechanism (31273f288) — it could be
            // THIS replica's own genuine prior migration (in which case
            // this file is redundant and safe to move aside), or a
            // different replica's completion this file was never proven
            // part of. Unlike the sourceless case below, this is NOT safe
            // to auto-retry: a real migration DID happen under the old
            // marker-only scheme, and this replica may have accepted live
            // operator changes since (new roles, revoked grants) that a
            // fresh re-migration would clobber (see the destructive-under-
            // live-mutation reasoning on step 4/5's DO UPDATE + revoke
            // CTE). Sol/Fable: the message must not assert more than this
            // is actually known, and must not copy AuditStore's wording
            // verbatim (their pre-fingerprint-upgrade population differs).
            spdlog::error(
                "RbacStore: migrate_from_sqlite: backfill_complete is already set with NO "
                "recorded source fingerprint (this marker predates the fingerprint-"
                "verification mechanism), and this replica's own legacy db {} still holds "
                "real content (fingerprint '{}'). This marker's provenance was never "
                "recorded, so it cannot be told apart from this replica's OWN completed "
                "migration before fingerprints existed (redundant, safe to move aside) vs. a "
                "different replica's completion this file was never proven part of. "
                "Refusing to guess either way — see "
                "docs/ops-runbooks/rbac-store-backfill-recovery.md.",
                legacy_db_path.string(), *verify_fp);
            backfill_metric("failed");
            return false;
        }
        if (*stored_fingerprint == kSourcelessFingerprint) {
            // governance re-review (PR #2703 round 2 — REVERTED from a
            // fall-through this same round's own re-review round found
            // unsafe; see Fable's original Q2 answer this branch had gone
            // beyond). Promotion is safe AT STAMP TIME (commit 2's
            // monotonic-promotion upsert in stamp_complete, above): by step
            // 7 the writer has already durably committed its OWN migration,
            // so correcting the trust anchor cannot clobber anything. This
            // is a DIFFERENT moment — a LATER boot that finds the marker
            // ALREADY sourceless, where this replica has done no migration
            // work of its own yet — and here the mechanism cannot bound
            // what post-cutover mutations a fresh auto-migration would
            // clobber. Concretely (unhappy-path, round 2): a fileless
            // sibling's sourceless stamp makes rbac_store operational with
            // only seeded defaults, and a live IdP login in the interim can
            // run reconcile_idp_memberships (auth_routes.cpp), which
            // DELETEs a stale group_members row a legacy rbac.db snapshot
            // still records — this file's own group_members INSERT (ON
            // CONFLICT DO NOTHING) would silently resurrect exactly that
            // row, restoring a role grant to a user correctly de-
            // provisioned from an IdP group. Refuse; let the operator
            // confirm no live post-cutover state exists before moving the
            // file aside by hand.
            spdlog::error(
                "RbacStore: migrate_from_sqlite: backfill_complete is already set with a "
                "sourceless source fingerprint (no legacy rbac.db has been migrated for this "
                "fleet yet), and this replica's own legacy db {} still holds real content "
                "(fingerprint '{}'). Refusing to auto-migrate on this later boot: rbac_store "
                "may already have accepted live post-cutover state (e.g. IdP group "
                "reconciliation) this file's stale content would silently clobber — see "
                "docs/ops-runbooks/rbac-store-backfill-recovery.md.",
                legacy_db_path.string(), *verify_fp);
            backfill_metric("failed");
            return false;
        } else if (*stored_fingerprint != *verify_fp) {
            spdlog::error(
                "RbacStore: migrate_from_sqlite: HOLDER-SIDE VERIFICATION FAILED — "
                "backfill_complete is already set with a DIFFERENT recorded source "
                "fingerprint ('{}') than this replica's own legacy db {} ('{}') — some "
                "other replica's legacy data was migrated, not this one's "
                "(docs/postgres-store-playbook.md anti-pattern 'Local source absence never "
                "creates terminal migration state on its own', #2697). Refusing to silently "
                "accept a completion this replica's roles/grants/groups were never part of "
                "— see docs/ops-runbooks/rbac-store-backfill-recovery.md.",
                *stored_fingerprint, legacy_db_path.string(), *verify_fp);
            backfill_metric("failed");
            return false;
        } else {
            spdlog::debug("RbacStore: migrate_from_sqlite already completed (fingerprint "
                         "verified), skipping");
            // governance re-review (Fable): retry the move-aside here too,
            // not only on the fresh-migration path — a verified match
            // means this IS the file a prior boot on this replica already
            // migrated, and a once-failed move-aside (the only way it
            // could still be here) deserves the same retry, or it re-
            // verifies against this same file forever and never converges
            // on the playbook's one-release retention policy.
            // legacy_rbac_fingerprint() above opened and closed its own
            // connection, so nothing holds this path open.
            move_legacy_aside(legacy_db_path);
            return true;
        }
    }

    if (!legacy_exists) {
        // Fresh install — the seeded default rbac_enabled='false' is correct.
        // Fingerprint is the sourceless sentinel, not skipped: a later
        // process that DOES hold a legacy file must be able to tell this
        // marker was never derived from any real content.
        if (!stamp_complete(kSourcelessFingerprint)) {
            backfill_metric("failed");
            return false;
        }
        spdlog::info("RbacStore: migrate_from_sqlite: no legacy rbac.db at {}; marking backfill "
                     "complete (fresh install)",
                     legacy_db_path.string());
        backfill_metric("fresh");
        return true;
    }

    // 3. Open legacy read-only.
    SqliteDb legacy;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), legacy.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK) {
        spdlog::error("RbacStore: migrate_from_sqlite: failed to open legacy db {}: {}",
                      legacy_db_path.string(),
                      legacy ? sqlite3_errmsg(legacy.get()) : "open failed");
        backfill_metric("failed");
        return false;
    }
    sqlite3_exec(legacy.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    // Corruption probe: a non-empty, non-SQLite file opens lazily under
    // READONLY, then the first real query fails with SQLITE_NOTADB. Distinguish
    // that (fail CLOSED — an unreadable legacy DB must NOT be silently skipped,
    // which would drop every operator-authored grant) from a genuine fresh/other
    // DB where the query succeeds and merely finds no `roles` table.
    {
        SqliteStmt probe;
        if (sqlite3_prepare_v2(legacy.get(), "SELECT count(*) FROM sqlite_master", -1, probe.addr(),
                               nullptr) != SQLITE_OK ||
            sqlite3_step(probe.get()) != SQLITE_ROW) {
            spdlog::error("RbacStore: migrate_from_sqlite: legacy db {} is unreadable/corrupt ({}); "
                          "refusing backfill (fail-closed — never silently drop operator RBAC "
                          "config)",
                          legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
            backfill_metric("failed");
            return false;
        }
    }
    const auto has_roles = legacy_has_table(legacy.get(), "roles");
    if (!has_roles) {
        // A genuine read error, NOT "no roles table" — must NOT be treated
        // as sourceless (governance re-review round 2, cpp-expert): stamping
        // the marker on a read failure would permanently foreclose this
        // replica's real migration on every future boot.
        spdlog::error("RbacStore: migrate_from_sqlite: legacy db {} could not be probed for a "
                      "roles table ({}); refusing backfill (fail-closed)",
                      legacy_db_path.string(), sqlite3_errmsg(legacy.get()));
        backfill_metric("failed");
        return false;
    }
    if (!*has_roles) {
        // No operator content here either — same "nothing to protect" class
        // as no local file at all (kSourcelessFingerprint, not skipped).
        if (!stamp_complete(kSourcelessFingerprint)) {
            backfill_metric("failed");
            return false;
        }
        spdlog::warn("RbacStore: migrate_from_sqlite: legacy db {} has no roles table; marking "
                     "backfill complete",
                     legacy_db_path.string());
        backfill_metric("fresh");
        return true;
    }

    // 3b. Read every legacy row ONCE (config tables are small) into the shared
    // snapshot — the single source both the real migration (below) and this
    // stamp's own trust-anchor fingerprint (step 7) derive from. No second
    // file read anywhere in this function (governance re-review, MEDIUM ->
    // closed: a second independent read at step 7 was previously a TOCTOU
    // window between what actually got migrated and what got fingerprinted).
    const auto snap_opt = read_legacy_snapshot(legacy.get());
    if (!snap_opt) {
        spdlog::error("RbacStore: migrate_from_sqlite: legacy read failed: {}",
                      sqlite3_errmsg(legacy.get()));
        backfill_metric("failed");
        return false;
    }
    const LegacySnapshot& snap = *snap_opt;
    const auto& types = snap.types;
    const auto& ops = snap.ops;
    const auto& roles = snap.roles;
    const auto& perms = snap.perms;
    const auto& principals = snap.principals;
    const auto& groups = snap.groups;
    const auto& members = snap.members;

    // 4. CRITICAL — the rbac_enabled flag FIRST, read-back-verified. Losing it
    // silently reverts the fleet to RBAC-off (catastrophic fail-open). The
    // seeded default 'false' is a placeholder legacy intent must OVERRIDE, so
    // this is DO UPDATE (not DO NOTHING).
    std::string legacy_enabled = "false";
    {
        // fjarvis F2 (#2703): parse strictly rather than coercing any
        // non-canonical value to "false" — the same fail-open class as the
        // PG-side read this row is about to feed, one hop earlier. snap.enabled
        // defaults to "false" itself when legacy has no rbac_config row, which
        // parses canonically, so this still runs unconditionally.
        const auto parsed = parse_canonical_bool(snap.enabled);
        if (!parsed) {
            spdlog::error(
                "RbacStore: migrate_from_sqlite: legacy rbac_config.enabled holds a "
                "non-canonical value (expected exactly \"true\" or \"false\") — refusing "
                "backfill (fail-closed; coercing it to false would silently disable RBAC "
                "on a fleet that enabled it)");
            backfill_metric("failed");
            return false;
        }
        legacy_enabled = *parsed ? "true" : "false";
    }
    {
        const bool ok = pool_.with_txn_for(kBackfillTxnTimeout, [&](PGconn* c) -> bool {
            pg::PgResult up = pg::exec_params(
                c,
                "INSERT INTO rbac_store.rbac_meta (key, value) VALUES ('rbac_enabled', $1) "
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                std::vector<std::string>{legacy_enabled});
            if (up.status() != PGRES_COMMAND_OK) {
                spdlog::error("RbacStore: migrate_from_sqlite: rbac_enabled write failed: {}",
                              PQerrorMessage(c));
                return false;
            }
            // Read-back-after-write verification IN THE SAME TXN.
            pg::PgResult rb = pg::exec_params(
                c, "SELECT value FROM rbac_store.rbac_meta WHERE key='rbac_enabled'",
                std::vector<std::string>{});
            if (rb.status() != PGRES_TUPLES_OK || PQntuples(rb.get()) != 1 ||
                text_col(rb.get(), 0, 0) != legacy_enabled) {
                spdlog::error("RbacStore: migrate_from_sqlite: rbac_enabled read-back verification "
                              "FAILED — refusing backfill (fail-closed; losing this flag is "
                              "catastrophic fail-open)");
                return false;
            }
            return true;
        });
        if (!ok) {
            backfill_metric("failed");
            return false;
        }
        rbac_enabled_.store(legacy_enabled == "true", std::memory_order_relaxed);
        spdlog::info("RbacStore: migrate_from_sqlite: rbac_enabled migrated + verified as '{}'",
                     legacy_enabled);
    }

    // 5. Backfill config tables from the snapshot already read at step 3b —
    // one transaction, ON CONFLICT DO NOTHING (idempotent + crash-resumable by
    // re-run). securable_types/operations are backfilled too (defensive:
    // keeps role_permissions FKs satisfiable even for a hypothetical custom
    // type). Doomgoose (PR #2703 review, blocking item 2) disproved the
    // premise this comment used to assert ("legacy is already migration-
    // cleaned, so v3/v4 cleanups are not replayed") -- nothing ever enforced
    // that. v3/v4's predicates ARE now replayed, just earlier in the
    // pipeline than this point: read_legacy_snapshot() (called at step 3b,
    // feeding `roles`/`perms`/`groups`/`members` below) applies them inline
    // against the legacy file's own schema_meta version before returning.
    // Reconciliation counts below are the snapshot's own (already-filtered)
    // row counts — a genuinely partial read already failed closed at step 3b
    // (read_all's rc == SQLITE_DONE contract), so re-counting via a second
    // query would be redundant, not an independent check.
    struct TableCounts {
        std::int64_t roles{0}, perms{0}, principals{0}, groups{0}, members{0};
    };
    const TableCounts legacy_counts{static_cast<std::int64_t>(roles.size()),
                                    static_cast<std::int64_t>(perms.size()),
                                    static_cast<std::int64_t>(principals.size()),
                                    static_cast<std::int64_t>(groups.size()),
                                    static_cast<std::int64_t>(members.size())};
    // Doomgoose (PR #2703 review, blocking item 3): declared here (not inside
    // the transaction lambda below) so step 6's reconciliation check can
    // account for it -- an intentionally-skipped orphaned row is not the
    // silent data loss that check exists to catch.
    std::size_t skipped_orphan_members = 0;

    const bool insert_ok = pool_.with_txn_for(kBackfillTxnTimeout, [&](PGconn* c) -> bool {
        const auto run = [&](const char* sql, const std::vector<std::string>& p) -> bool {
            pg::PgResult r = pg::exec_params(c, sql, p);
            if (r.status() != PGRES_COMMAND_OK) {
                spdlog::error("RbacStore: migrate_from_sqlite: insert failed: {}", PQerrorMessage(c));
                return false;
            }
            return true;
        };
        // sre (Gate 6, #2703, MEDIUM — lock-ordering inversion): must be the
        // FIRST statement in this transaction, before this loop's R2 upsert
        // below ever touches a role_permissions row. grant() and
        // remove_permission() both acquire this SAME lock before touching
        // role_permissions; acquiring it here only at the F1 block further
        // down (after the R2 upsert already holds row locks) would let this
        // transaction hold row locks while WANTING the advisory lock, at the
        // same time a concurrent grant()/remove_permission() holds the
        // advisory lock while WANTING one of those row locks — a genuine
        // wait-for cycle. Postgres's deadlock detector resolves that (never
        // hangs), but consistent "lock strictly first, everywhere" avoids
        // manufacturing an avoidable deadlock at all.
        {
            pg::PgResult lk = pg::exec_params(c, kRevokeCoordLockSql, std::vector<std::string>{});
            if (lk.status() != PGRES_TUPLES_OK) {
                spdlog::error("RbacStore: migrate_from_sqlite: revoke-coordination lock failed: {}",
                             PQerrorMessage(c));
                return false;
            }
        }
        for (const auto& t : types)
            if (!run("INSERT INTO rbac_store.securable_types (name, description, is_system) "
                     "VALUES ($1, $2, $3::boolean) ON CONFLICT (name) DO NOTHING",
                     {sanitize_pg_text(t.name), sanitize_pg_text(t.description),
                      bool_lit(t.is_system)}))
                return false;
        for (const auto& o : ops)
            if (!run("INSERT INTO rbac_store.operations (id, description, is_system) "
                     "VALUES ($1, $2, TRUE) ON CONFLICT (id) DO NOTHING",
                     {sanitize_pg_text(o.first), sanitize_pg_text(o.second)}))
                return false;
        for (const auto& r : roles)
            if (!run("INSERT INTO rbac_store.roles (name, description, is_system, created_at) "
                     "VALUES ($1, $2, $3::boolean, $4::bigint) ON CONFLICT (name) DO NOTHING",
                     {sanitize_pg_text(r.name), sanitize_pg_text(r.description),
                      bool_lit(r.is_system), std::to_string(r.created_at)}))
                return false;
        for (const auto& p : perms)
            // DO UPDATE, not DO NOTHING (Gate 4 R2, CONFIRMED fail-open): the
            // legacy rbac.db is the AUTHORITATIVE pre-cutover state. If an
            // operator edited a SEEDED system-role permission (e.g. flipped an
            // 'allow' default to 'deny'), that row collides on the (role,type,op)
            // key with the seed we just inserted; DO NOTHING would silently drop
            // the operator's deny and the row-count reconcile can't see it —
            // resurrecting a revoked permission (fail-open). DO UPDATE makes the
            // legacy effect win, preserving the operator's authorization intent.
            if (!run("INSERT INTO rbac_store.role_permissions (role_name, securable_type, "
                     "operation, effect) VALUES ($1, $2, $3, $4) "
                     "ON CONFLICT (role_name, securable_type, operation) DO UPDATE SET "
                     "effect = EXCLUDED.effect",
                     {sanitize_pg_text(p.role_name), sanitize_pg_text(p.securable_type),
                      sanitize_pg_text(p.operation), sanitize_pg_text(p.effect)}))
                return false;
        // fjarvis F1 — seed_defaults() (constructor, runs before this backfill)
        // unconditionally re-inserts every built-in default permission
        // (ON CONFLICT DO NOTHING). If an operator called remove_permission()
        // to revoke a built-in default in the legacy store, that revocation
        // has no positive row to upsert against — the seeded row silently
        // survives, and the row-count reconciliation below can't see it (PG
        // always holds >= legacy counts by design; a missing-in-legacy row
        // is invisible to a count check).
        //
        // fable (Gate 4, #2703, HIGH — this block's fix REVISED again): an
        // earlier fix here UPDATEd the row to an explicit 'deny' tombstone
        // instead of deleting it, matching remove_permission()'s own fix at
        // the time. That silently changes the authorization OUTCOME for any
        // principal who holds a SECOND role that independently grants the
        // same (type,op): check_permission() / check_scoped_permission() /
        // authorize_list_read() all apply "deny overrides everything,
        // across ALL of a principal's held roles" — a pre-existing,
        // deliberate invariant, identical in the legacy SQLite store. A
        // deny row from the revoked role therefore vetoes an allow the same
        // principal holds via a different role; legacy never hit this
        // (its DELETE left nothing to veto with). Fix (matching
        // remove_permission()'s own revised fix): DELETE the row, and
        // record the revocation SEPARATELY as pure reseed-suppression
        // bookkeeping in revoked_seed_defaults — never read by any
        // authorization-decision code path, only by seed_defaults()'s
        // grant(). Both statements run as one CTE (DELETE ... RETURNING
        // feeding the INSERT) so they commit or roll back together within
        // this backfill's existing transaction — no window where the row
        // is gone but the marker isn't there yet to suppress the reseed.
        //
        // Delete any PG role_permissions row whose role, securable_type, AND
        // operation were ALL known to legacy (so legacy could have had an
        // opinion about it) but whose exact (role,type,op) triple is absent
        // from legacy's own role_permissions — i.e. explicitly revoked, not
        // merely never-seeded. Scoping to legacy's own catalogues (all
        // three: roles, securable_types, AND operations) is what protects a
        // securable/operation a LATER seed_defaults() adds — a brand-new
        // securable_type (EnginePrincipal, #2376) is never in legacy's
        // securable_types; a brand-new OPERATION on an EXISTING role+type
        // pair (ApiToken:Rotate, P2 #11 — fjarvis re-review, blocking C1,
        // reproduced against live Postgres: the original two-dimension
        // scoping deleted and PERMANENTLY suppressed exactly this grant on
        // every upgrade from a legacy catalogue that predates Rotate) is
        // never in legacy's operations. Either filter excludes the row and
        // the newly-seeded grant survives untouched. An empty
        // legacy_role_names/legacy_type_names/legacy_op_names (a
        // pre-securable_types/operations-table legacy schema) makes every
        // `= ANY` filter match nothing — degrades to "touch nothing" rather
        // than guessing. Comparison values are sanitize_pg_text()'d
        // identically to the INSERT above so a legacy string with invalid
        // UTF-8/embedded NUL matches its own already-stored (equally
        // sanitized) row instead of spuriously mismatching and revoking a
        // row legacy still has.
        //
        // fjarvis (PR #2703 re-review, blocking C1, reproduced against live
        // Postgres): the invariant above was falsified by this same PR's own
        // dev merge — ApiToken:Rotate (P2 #11) is a new OPERATION on the
        // pre-existing (Administrator, ApiToken) / (ApiTokenManager,
        // ApiToken) pairs, so every upgrade from a legacy catalogue that
        // predates Rotate had it silently deleted and permanently
        // suppressed via revoked_seed_defaults, logged as an "operator-
        // revoked default" it never was. Fixed by adding legacy's own
        // operations catalogue as a third filter dimension — an operation
        // legacy never knew about is one legacy could not have had an
        // opinion about, the same reasoning already applied to role and
        // type. A genuine operator revocation of an operation legacy DID
        // know about is still caught (that row is present in legacy_op_names
        // but absent from perm_ops for this role+type+op triple).
        //
        // INVARIANT (security-guardian, #2703 re-review): this generalizes
        // the original two-dimension gap rather than closing the risk
        // class it warned about. A brand-new TRIPLE — a default grant whose
        // role, securable_type, AND operation are each individually already
        // known to legacy, but never before as this exact combination (e.g.
        // a role gaining a grant for an operation legacy only ever saw
        // associated with a DIFFERENT role) — is still indistinguishable
        // from a genuine operator revocation under this filter, for the
        // same structural reason the original two-dimension case was:
        // legacy has an opinion about all three catalogues individually but
        // holds no row for the triple. As before, the failure direction is
        // a lockout (access denial), not an escalation — but it is
        // narrowed, not eliminated. Revisit this scoping if a future
        // default grant ever ships onto a triple whose role, type, and
        // operation legacy could each plausibly have known but never in
        // that combination (ApiToken:Rotate was the type+operation
        // instance of this; role+operation and role+type instances remain
        // theoretically possible).
        {
            std::vector<std::string> legacy_role_names, legacy_type_names, legacy_op_names,
                perm_roles, perm_types, perm_ops;
            legacy_role_names.reserve(roles.size());
            for (const auto& r : roles)
                legacy_role_names.push_back(sanitize_pg_text(r.name));
            legacy_type_names.reserve(types.size());
            for (const auto& t : types)
                legacy_type_names.push_back(sanitize_pg_text(t.name));
            legacy_op_names.reserve(ops.size());
            for (const auto& o : ops)
                legacy_op_names.push_back(sanitize_pg_text(o.first));
            perm_roles.reserve(perms.size());
            perm_types.reserve(perms.size());
            perm_ops.reserve(perms.size());
            for (const auto& p : perms) {
                perm_roles.push_back(sanitize_pg_text(p.role_name));
                perm_types.push_back(sanitize_pg_text(p.securable_type));
                perm_ops.push_back(sanitize_pg_text(p.operation));
            }
            const auto to_views = [](const std::vector<std::string>& v) {
                std::vector<std::string_view> out;
                out.reserve(v.size());
                for (const auto& s : v)
                    out.push_back(s);
                return out;
            };
            // chaos-injector (Gate 5, #2703, HIGH — CHAOS-1) + sre (Gate 6,
            // MEDIUM — lock ordering): kRevokeCoordLockSql is already held,
            // acquired as the FIRST statement of this transaction (see the
            // top of this with_txn_for callback) — strictly before the R2
            // upsert above ever touches a role_permissions row, so this
            // transaction never holds a row lock while wanting the advisory
            // lock (the exact shape that could deadlock against a concurrent
            // grant()/remove_permission()). No re-acquisition needed here.
            pg::PgResult revoked = pg::exec_params(
                c,
                "WITH revoked AS ("
                "  DELETE FROM rbac_store.role_permissions rp "
                "  WHERE rp.role_name = ANY($1::text[]) "
                "  AND rp.securable_type = ANY($2::text[]) "
                "  AND rp.operation = ANY($6::text[]) "
                "  AND NOT EXISTS ("
                "    SELECT 1 FROM unnest($3::text[], $4::text[], $5::text[]) "
                "      AS legacy(role_name, securable_type, operation) "
                "    WHERE legacy.role_name = rp.role_name "
                "      AND legacy.securable_type = rp.securable_type "
                "      AND legacy.operation = rp.operation"
                "  ) "
                "  RETURNING role_name, securable_type, operation"
                ") "
                "INSERT INTO rbac_store.revoked_seed_defaults (role_name, securable_type, "
                "operation) SELECT role_name, securable_type, operation FROM revoked "
                "ON CONFLICT DO NOTHING",
                std::vector<std::string>{pg::to_text_array(to_views(legacy_role_names)),
                                         pg::to_text_array(to_views(legacy_type_names)),
                                         pg::to_text_array(to_views(perm_roles)),
                                         pg::to_text_array(to_views(perm_types)),
                                         pg::to_text_array(to_views(perm_ops)),
                                         pg::to_text_array(to_views(legacy_op_names))});
            if (revoked.status() != PGRES_COMMAND_OK) {
                spdlog::error(
                    "RbacStore: migrate_from_sqlite: revoked-permission cleanup failed: {}",
                    PQerrorMessage(c));
                return false;
            }
            const char* removed = PQcmdTuples(revoked.get());
            if (removed != nullptr && removed[0] != '\0' && std::strcmp(removed, "0") != 0)
                spdlog::info(
                    "RbacStore: migrate_from_sqlite: removed {} seeded permission(s) absent "
                    "from legacy (operator-revoked defaults; recorded in revoked_seed_defaults "
                    "so a future reseed cannot resurrect them)",
                    removed);
        }
        for (const auto& p : principals)
            if (!run("INSERT INTO rbac_store.principal_roles (principal_type, principal_id, "
                     "role_name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                     {sanitize_pg_text(p.principal_type), sanitize_pg_text(p.principal_id),
                      sanitize_pg_text(p.role_name)}))
                return false;
        for (const auto& g : groups) {
            pg::PgResult r = pg::exec_params(
                c,
                "INSERT INTO rbac_store.groups (name, description, source, external_id, created_at) "
                "VALUES ($1, $2, $3, $4, $5::bigint) ON CONFLICT (name) DO NOTHING",
                std::vector<std::optional<std::string>>{
                    sanitize_pg_text(g.name), sanitize_pg_text(g.description),
                    sanitize_pg_text(g.source),
                    g.external_id ? std::optional<std::string>(sanitize_pg_text(*g.external_id))
                                  : std::nullopt,
                    std::to_string(g.created_at)});
            if (r.status() != PGRES_COMMAND_OK) {
                spdlog::error("RbacStore: migrate_from_sqlite: group insert failed: {}",
                              PQerrorMessage(c));
                return false;
            }
        }
        // Doomgoose (PR #2703 review, blocking item 3): group_members.group_name
        // is a real FK (REFERENCES groups(name) ON DELETE CASCADE) that SQLite
        // never enforced by default, so an operator who deleted a group via a
        // raw sqlite3 UPDATE/DELETE (foreign_keys=OFF, the SQLite default) could
        // leave an orphaned group_members row in the legacy file with nothing
        // ever catching it there. Unlike roles/perms/principals/groups
        // themselves (irreducible operator intent -- this store's standing
        // "never silently drop operator RBAC config" contract), a single
        // group-membership pairing is the narrow exception: it's the one row
        // class here an admin can trivially recreate (re-add the user to the
        // group) and, same as InventoryStore's own established precedent
        // (inventory_store.cpp, IB2/UP-1 -- SAVEPOINT per row, skip ONLY a
        // genuine row-data-class SQLSTATE, fail closed on anything
        // infra-shaped), one bad row must not be a permanent boot loop for
        // every OTHER legitimate membership, role, and grant in this same
        // transaction. Scoped to group_members ONLY -- roles/perms/principals/
        // groups above keep the existing any-error-aborts-everything contract.
        // (skipped_orphan_members is declared in the OUTER function scope --
        // see the comment there -- so step 6's reconciliation can see it.)
        for (const auto& m : members) {
            pg::PgResult sp =
                pg::exec_params(c, "SAVEPOINT legacy_group_member_backfill", std::vector<std::string>{});
            if (sp.status() != PGRES_COMMAND_OK) {
                spdlog::error("RbacStore: migrate_from_sqlite: SAVEPOINT failed (infra error, "
                              "aborting backfill): {}",
                              PQerrorMessage(c));
                return false;
            }
            pg::PgResult ins = pg::exec_params(
                c,
                "INSERT INTO rbac_store.group_members (group_name, username) VALUES ($1, $2) "
                "ON CONFLICT DO NOTHING",
                std::vector<std::string>{sanitize_pg_text(m.group_name),
                                         sanitize_pg_text(m.username)});
            if (ins.status() == PGRES_COMMAND_OK) {
                pg::PgResult rel = pg::exec_params(c, "RELEASE SAVEPOINT legacy_group_member_backfill",
                                                   std::vector<std::string>{});
                if (rel.status() != PGRES_COMMAND_OK) {
                    spdlog::error("RbacStore: migrate_from_sqlite: RELEASE SAVEPOINT failed "
                                  "(infra error, aborting backfill): {}",
                                  PQerrorMessage(c));
                    return false;
                }
                continue;
            }
            // Explicit ins.get() guard for exact parity with the
            // InventoryStore precedent this mirrors (inventory_store.cpp)
            // -- PQresultErrorField/PQresultErrorMessage already null-check
            // internally (verified against vendored libpq's fe-exec.c), so
            // this is belt-and-suspenders, not a functional fix.
            const char* sqlstate_p =
                ins.get() ? PQresultErrorField(ins.get(), PG_DIAG_SQLSTATE) : nullptr;
            const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
            const bool row_data_error =
                sqlstate.size() == 5 && (sqlstate.starts_with("22") || sqlstate.starts_with("23") ||
                                         sqlstate.starts_with("54"));
            pg::PgResult back = pg::exec_params(c, "ROLLBACK TO SAVEPOINT legacy_group_member_backfill",
                                                std::vector<std::string>{});
            if (back.status() != PGRES_COMMAND_OK) {
                spdlog::error("RbacStore: migrate_from_sqlite: ROLLBACK TO SAVEPOINT failed "
                              "after a bad row (infra error, aborting backfill): {}",
                              PQerrorMessage(c));
                return false;
            }
            if (!row_data_error) {
                spdlog::error(
                    "RbacStore: migrate_from_sqlite: group_members insert failed with "
                    "non-row-data SQLSTATE '{}' (group_name={} username={}): {} -- treating as "
                    "an infrastructure error and aborting the backfill unstamped; the next boot "
                    "retries",
                    sqlstate.empty() ? "<none>" : sqlstate, m.group_name, m.username,
                    PQresultErrorMessage(ins.get()));
                return false;
            }
            pg::PgResult rel = pg::exec_params(c, "RELEASE SAVEPOINT legacy_group_member_backfill",
                                               std::vector<std::string>{});
            if (rel.status() != PGRES_COMMAND_OK) {
                spdlog::error("RbacStore: migrate_from_sqlite: RELEASE SAVEPOINT failed (infra "
                              "error, aborting backfill): {}",
                              PQerrorMessage(c));
                return false;
            }
            ++skipped_orphan_members;
            spdlog::warn("RbacStore: migrate_from_sqlite: skipping orphaned legacy "
                        "group_members row (SQLSTATE {}, likely a group deleted via raw SQL "
                        "without FK enforcement): group_name={} username={}",
                        sqlstate, m.group_name, m.username);
        }
        if (skipped_orphan_members > 0)
            spdlog::warn(
                "RbacStore: migrate_from_sqlite: skipped {} orphaned group_members row(s) "
                "during backfill -- affected users may need to be re-added to their group(s) "
                "manually",
                skipped_orphan_members);
        return true;
    });
    if (!insert_ok) {
        backfill_metric("failed");
        return false;
    }

    // 6. Row-count reconciliation — PG must hold at least the legacy counts
    // (PG also holds seeded system rows; DO NOTHING never drops a legacy row).
    {
        auto lease = pool_.acquire();
        if (!lease) {
            backfill_metric("failed");
            return false;
        }
        const auto pg_count = [&](const char* table) -> std::int64_t {
            pg::PgResult r = pg::exec_params(
                lease.get(), (std::string("SELECT COUNT(*) FROM rbac_store.") + table).c_str(),
                std::vector<std::string>{});
            if (r.status() != PGRES_TUPLES_OK)
                return -1;
            return to_i64(PQgetvalue(r.get(), 0, 0));
        };
        const std::int64_t pr = pg_count("roles"), pp = pg_count("role_permissions"),
                           ppr = pg_count("principal_roles"), pg_ = pg_count("groups"),
                           pm = pg_count("group_members");
        if (pr < 0 || pp < 0 || ppr < 0 || pg_ < 0 || pm < 0) {
            spdlog::error("RbacStore: migrate_from_sqlite: reconciliation count failed");
            backfill_metric("failed");
            return false;
        }
        // Doomgoose (PR #2703 review, blocking item 3): the members floor
        // excludes rows this backfill deliberately, loggedly skipped as
        // orphaned (no corresponding groups row) -- that is not the silent
        // data loss this check exists to catch. Every other floor is
        // unchanged: roles/perms/principals/groups still have zero tolerated
        // skip path, matching their standing "never silently drop operator
        // RBAC config" contract.
        const std::int64_t expected_members =
            legacy_counts.members - static_cast<std::int64_t>(skipped_orphan_members);
        if (pr < legacy_counts.roles || pp < legacy_counts.perms ||
            ppr < legacy_counts.principals || pg_ < legacy_counts.groups ||
            pm < expected_members) {
            spdlog::error("RbacStore: migrate_from_sqlite: reconciliation FAILED — legacy "
                          "(roles={},perms={},principals={},groups={},members={}, {} orphaned "
                          "member row(s) intentionally skipped) vs PG "
                          "(roles={},perms={},principals={},groups={},members={}); refusing marker",
                          legacy_counts.roles, legacy_counts.perms, legacy_counts.principals,
                          legacy_counts.groups, legacy_counts.members, skipped_orphan_members, pr,
                          pp, ppr, pg_, pm);
            backfill_metric("failed");
            return false;
        }
        spdlog::info("RbacStore: migrate_from_sqlite: reconciled — legacy "
                     "(roles={},perms={},principals={},groups={},members={}), PG "
                     "(roles={},perms={},principals={},groups={},members={})",
                     legacy_counts.roles, legacy_counts.perms, legacy_counts.principals,
                     legacy_counts.groups, legacy_counts.members, pr, pp, ppr, pg_, pm);
    }

    // 7. Stamp the one-time marker with THIS file's real fingerprint — derived
    // from the SAME snapshot already read at step 3b, not a second file read
    // (governance re-review: a second independent read here was previously
    // the trust anchor's own TOCTOU window — see the comment on
    // read_legacy_snapshot's declaration).
    const auto source_fp = fingerprint_legacy_snapshot(snap);
    if (!source_fp) {
        spdlog::error("RbacStore: migrate_from_sqlite: could not derive this file's own "
                      "fingerprint immediately after successfully backfilling it; refusing to "
                      "stamp complete without a trust anchor");
        backfill_metric("failed");
        return false;
    }
    if (!stamp_complete(*source_fp)) {
        backfill_metric("failed");
        return false;
    }

    // 8. Move the verified legacy file aside (non-fatal on failure).
    // Close the legacy read-only handle FIRST: Windows refuses to rename a file
    // with an open handle (ERROR_SHARING_VIOLATION), so leaving `legacy` open
    // silently defeated the move-aside on the Wee Tam MSVC leg (POSIX allows
    // rename-with-open-handle, so it passed on Linux/macOS). All legacy reads
    // are already materialised in memory above.
    legacy.close();
    move_legacy_aside(legacy_db_path);

    backfill_metric("completed");
    return true;
}

} // namespace yuzu::server
