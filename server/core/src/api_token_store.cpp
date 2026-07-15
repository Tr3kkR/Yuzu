#include "api_token_store.hpp"
#include "mcp_policy.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "secure_random.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <span>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <windows.h>  // must precede bcrypt.h (defines NTSTATUS)
// clang-format on
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/sha.h>
#endif

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "api_token_store";

// Bounded acquires (ADR-0012 §2). Token validation sits on the request hot
// path (every Bearer-authed call falls through here on a cache miss) so it
// gets the shorter budget; mutations (create/revoke/delete) are user-facing
// but rarer, so they get a little more room. Neither is unbounded.
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE api_tokens ("
         "  token_id      TEXT PRIMARY KEY,"
         "  token_hash    TEXT NOT NULL UNIQUE,"
         "  name          TEXT NOT NULL,"
         "  principal_id  TEXT NOT NULL DEFAULT '',"
         "  scope_service TEXT NOT NULL DEFAULT '',"
         "  mcp_tier      TEXT NOT NULL DEFAULT '',"
         "  principal_kind TEXT NOT NULL DEFAULT 'human' "
         "    CHECK (principal_kind IN ('human','engine')),"
         "  created_at    BIGINT NOT NULL DEFAULT 0,"
         "  expires_at    BIGINT NOT NULL DEFAULT 0,"
         "  last_used_at  BIGINT NOT NULL DEFAULT 0,"
         "  revoked       BOOLEAN NOT NULL DEFAULT FALSE);"
         "CREATE INDEX api_tokens_principal_idx ON api_tokens (principal_id);"},
    };
    return kMigrations;
}

// Epoch SECONDS (unchanged from the SQLite store — do not drift to ms).
int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<int64_t>(std::strtoll(s, nullptr, 10));
}

bool to_bool(const char* s) {
    return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1');
}

// Null-safe column read: every column in the v1 projection is NOT NULL, so
// PQgetvalue never returns a NULL cell today. This gate keeps read_token
// robust if a future migration relaxes a NOT NULL constraint or the
// projection drifts from kTokenColsTail — a NULL cell degrades to "" rather
// than dereferencing a nullptr into std::string.
const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}

// `token_hash` (column 1) is always present in the projection — either the
// real hash (validate_token) or a literal '' mask (list_tokens/get_token,
// which never expose the hash — see kTokenColsTail's callers).
ApiToken read_token(PGresult* res, int row) {
    ApiToken t;
    int c = 0;
    t.token_id = col(res, row, c++);
    t.token_hash = col(res, row, c++);
    t.name = col(res, row, c++);
    t.principal_id = col(res, row, c++);
    t.scope_service = col(res, row, c++);
    t.created_at = to_i64(col(res, row, c++));
    t.expires_at = to_i64(col(res, row, c++));
    t.last_used_at = to_i64(col(res, row, c++));
    t.revoked = to_bool(col(res, row, c++));
    t.mcp_tier = col(res, row, c++);
    t.principal_kind = col(res, row, c++);
    return t;
}

// Column order shared by validate_token / get_token / list_tokens; the
// token_hash slot is either the real column (validate_token) or a literal
// '' (list_tokens masks it — never expose the hash in a listing).
constexpr const char* kTokenColsTail =
    "name, principal_id, scope_service, created_at, expires_at, last_used_at, revoked, "
    "mcp_tier, principal_kind";

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

ApiTokenStore::ApiTokenStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("ApiTokenStore: no database connection at construction ({}) — API token "
                      "store disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("ApiTokenStore: schema migration failed — API token store disabled");
        return;
    }
    open_ = true;
    spdlog::info("ApiTokenStore: opened (schema {})", kStoreName);
}

bool ApiTokenStore::is_open() const {
    return open_;
}

// ── Token generation and hashing ─────────────────────────────────────────────

std::expected<std::string, std::string> ApiTokenStore::generate_raw_token() const {
    // Cryptographic PRNG required — pre-#801 this swallowed CSPRNG failures
    // and produced a token derived from zero-initialised bytes (all 'A'
    // chars). secure_random surfaces entropy exhaustion as a hard error so
    // the request becomes a 503 instead of issuing a known-weak token.
    std::uint8_t buf[32]{};
    auto rc = fill_random(std::span{buf, sizeof(buf)});
    if (!rc.has_value())
        return std::unexpected(std::string{"CSPRNG unavailable (entropy exhausted)"});

    static constexpr char chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string token = "yuzu_";
    token.reserve(37);
    for (std::uint8_t b : buf)
        token += chars[b % 62];
    return token;
}

std::string ApiTokenStore::sha256_hex(const std::string& input) const {
    unsigned char hash[32]{};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (alg) {
        BCRYPT_HASH_HANDLE h = nullptr;
        BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0);
        if (h) {
            BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                           static_cast<ULONG>(input.size()), 0);
            BCryptFinishHash(h, hash, 32, 0);
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
#else
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
#endif

    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (unsigned char c : hash) {
        result += hex[c >> 4];
        result += hex[c & 0x0f];
    }
    return result;
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
ApiTokenStore::create_token(const std::string& name, const std::string& principal_id,
                            int64_t expires_at, const std::string& scope_service,
                            const std::string& mcp_tier) {
    if (!open_)
        return std::unexpected("database not open");
    if (name.empty())
        return std::unexpected("token name cannot be empty");
    if (!scope_service.empty() && expires_at <= 0)
        return std::unexpected("service-scoped tokens must have an expiration time");
    if (!mcp_tier.empty() && !mcp::is_valid_tier(mcp_tier))
        return std::unexpected(
            "invalid MCP tier — must be 'readonly', 'operator', or 'supervised'");
    if (!mcp_tier.empty() && expires_at <= 0)
        return std::unexpected("MCP tokens must have an expiration time (max 90 days)");
    if (!mcp_tier.empty() && expires_at > 0) {
        auto now = now_epoch();
        constexpr int64_t k90Days = 90 * 24 * 3600;
        if (expires_at - now > k90Days)
            return std::unexpected("MCP token TTL cannot exceed 90 days");
    }

    auto raw_result = generate_raw_token();
    if (!raw_result.has_value())
        return std::unexpected(raw_result.error());
    auto raw = std::move(*raw_result);
    auto hash = sha256_hex(raw);
    auto token_id = hash.substr(0, 24); // Display ID — 24 hex chars (96 bits, collision-resistant)
    auto now = now_epoch();

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    // principal_kind is bound as the SQL literal 'human' — PR 4.1 has no
    // engine write path (the caller-supplied kind + its C++-side allowlist
    // land in PR 4.2, design doc §§6-8/11). The column still exists (the seam
    // the rest of Phase 4 stacks on) and its CHECK bounds it to the allowlist.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO api_token_store.api_tokens "
        "(token_id, token_hash, name, principal_id, scope_service, mcp_tier, principal_kind, "
        " created_at, expires_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,'human',$7::bigint,$8::bigint) RETURNING token_id",
        std::vector<std::string>{token_id, hash, name, principal_id, scope_service, mcp_tier,
                                 std::to_string(now), std::to_string(expires_at)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::unexpected(std::string("failed to create token: ") +
                               PQerrorMessage(lease.get()));
    return raw; // Return the raw token (shown once to user)
}

std::optional<ApiToken> ApiTokenStore::validate_token(const std::string& raw_token) {
    if (!open_ || raw_token.empty())
        return std::nullopt;

    auto hash = sha256_hex(raw_token);

    // Snapshot the revoke generation BEFORE the cache lookup so that any
    // revoke that races with our DB read is observable at the cache-write
    // step below, where we skip caching a stale entry. This guards cache
    // POISONING only — it does NOT serialize this validate against a
    // concurrent revoke the way sqlite's db_mtx_ used to. A token revoked
    // during this call's own execution may still be returned once (bounded;
    // the next uncached validate SELECTs revoked=true). See the
    // revoke_generation_ field comment in the hpp for the two residual
    // windows and the tracked follow-up for a proper close.
    const auto gen_before = revoke_generation_.load(std::memory_order_acquire);

    // Check cache first (avoids the Postgres round-trip on a hit).
    {
        std::lock_guard cache_lock(cache_mtx_);
        auto it = token_cache_.find(hash);
        if (it != token_cache_.end()) {
            auto age = std::chrono::steady_clock::now() - it->second.cached_at;
            if (age < kTokenCacheTtl) {
                const auto& cached = it->second.token;
                auto now = now_epoch();
                if (cached.revoked || (cached.expires_at > 0 && now > cached.expires_at)) {
                    token_cache_.erase(it);
                    cache_misses_.fetch_add(1, std::memory_order_relaxed);
                    return std::nullopt;
                }
                cache_hits_.fetch_add(1, std::memory_order_relaxed);
                return cached;
            }
            // Expired cache entry — remove and fall through to DB lookup
            token_cache_.erase(it);
        }
    }

    cache_misses_.fetch_add(1, std::memory_order_relaxed);

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    const std::string sql = std::string("SELECT token_id, token_hash, ") + kTokenColsTail +
                            " FROM api_token_store.api_tokens WHERE token_hash = $1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{hash});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return std::nullopt;

    ApiToken t = read_token(res.get(), 0);

    if (t.revoked)
        return std::nullopt;
    auto now = now_epoch();
    if (t.expires_at > 0 && now > t.expires_at)
        return std::nullopt;

    // Update last_used_at (best-effort — do not fail validation on this).
    pg::exec_params(lease.get(),
                    "UPDATE api_token_store.api_tokens SET last_used_at = $1::bigint "
                    "WHERE token_hash = $2",
                    std::vector<std::string>{std::to_string(now), hash});

    // Store in cache, but skip the write if a revoke raced our SELECT — this
    // prevents a stale revoked=false entry surviving the cache TTL. It does
    // NOT retract the value already being returned below; that bounded
    // single-request window is documented on revoke_generation_ in the hpp.
    //
    // The generation re-check MUST be taken UNDER cache_mtx_, not before it.
    // invalidate_cache() acquires the same mutex, and revoke_token bumps the
    // generation BEFORE it locks, so a check-then-lock ordering left a real
    // window: a revoke's erase could run between our check and our insert
    // (erasing nothing, since we hadn't inserted yet), after which we inserted a
    // revoked=false entry that re-authenticated the token for up to
    // kTokenCacheTtl. Holding the lock across the re-check AND the insert makes
    // the two operations serialize against the erase: either we observe the
    // bumped generation and skip, or the revoke's erase runs strictly after our
    // insert and removes it. Neither leaves a stale entry.
    if (test_hook_after_validate_select_)
        test_hook_after_validate_select_();

    {
        std::lock_guard cache_lock(cache_mtx_);
        if (revoke_generation_.load(std::memory_order_acquire) == gen_before) {
            token_cache_[hash] = CachedToken{t, std::chrono::steady_clock::now()};
        }
    }

    return t;
}

void ApiTokenStore::invalidate_cache(const std::string& token_hash) {
    std::lock_guard cache_lock(cache_mtx_);
    token_cache_.erase(token_hash);
}

std::size_t ApiTokenStore::cache_size() const {
    std::lock_guard cache_lock(cache_mtx_);
    return token_cache_.size();
}

std::expected<std::vector<ApiToken>, std::string>
ApiTokenStore::list_tokens(const std::string& principal_id) const {
    // Authoritative store (ADR-0012 §1): a runtime read error is SURFACED, never
    // papered over as an empty result — a silent empty read here would show an
    // operator "no tokens" during a Postgres outage and could hide a live
    // credential. Only a genuine zero-row read returns an empty vector.
    if (!open_)
        return std::unexpected("database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    std::string sql = std::string("SELECT token_id, '' AS token_hash, ") + kTokenColsTail +
                      " FROM api_token_store.api_tokens";
    std::vector<std::string> params;
    if (!principal_id.empty()) {
        sql += " WHERE principal_id = $1";
        params.push_back(principal_id);
    }
    sql += " ORDER BY created_at DESC";

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("list_tokens read failed: ") +
                               PQerrorMessage(lease.get()));

    std::vector<ApiToken> result;
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        result.push_back(read_token(res.get(), i)); // token_hash is the literal '' column above
    }
    return result;
}

std::expected<std::optional<ApiToken>, std::string>
ApiTokenStore::get_token(const std::string& token_id) const {
    // Authoritative store (ADR-0012 §1): distinguish a runtime read error
    // (surfaced → caller 503s) from a genuine no-such-row (value == nullopt →
    // caller 404s). The old nullopt-on-DB-error made an ownership pre-check 404
    // during an outage while the token stayed live (#2188 review).
    if (!open_)
        return std::unexpected("database not open");
    if (token_id.empty())
        return std::optional<ApiToken>{std::nullopt}; // argument guard, not a DB error

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected("database unavailable — try again");

    const std::string sql = std::string("SELECT token_id, '' AS token_hash, ") + kTokenColsTail +
                            " FROM api_token_store.api_tokens WHERE token_id = $1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{token_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("get_token read failed: ") + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::optional<ApiToken>{std::nullopt}; // genuine not-found

    return std::optional<ApiToken>{read_token(res.get(), 0)};
}

std::expected<bool, std::string> ApiTokenStore::revoke_token(const std::string& token_id) {
    if (!open_)
        return std::unexpected("database not open");

    // Bump the revoke generation BEFORE the UPDATE so any concurrent
    // validate_token whose SELECT outraces this UPDATE will observe the
    // generation move at its cache-write step and skip the stale write.
    revoke_generation_.fetch_add(1, std::memory_order_release);

    if (test_hook_after_first_revoke_bump_)
        test_hook_after_first_revoke_bump_();

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        // authoritative: a lease timeout is a WRITE FAILURE — never a silent
        // success and never a false "not found". The caller must 503/retry.
        return std::unexpected("database unavailable — try again");

    // RETURNING token_hash — never sqlite3_changes()-style mutate-then-count
    // (#1033). PQntuples > 0 IS the changed check, and the returned hash is
    // exactly what we need to invalidate the cache (no pre-SELECT needed).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE api_token_store.api_tokens SET revoked = TRUE WHERE token_id = $1 "
        "RETURNING token_hash",
        std::vector<std::string>{token_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("revoke did not persist: ") +
                               PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    if (rows == 0)
        return false; // DB write succeeded; no such token (already gone / unknown id)

    // Second generation bump — AFTER the UPDATE has committed, BEFORE we
    // invalidate. The pre-UPDATE bump alone only catches a validate_token that
    // snapshotted revoke_generation_ *before* it. A validate that started AFTER
    // that first bump captured the already-incremented value as its baseline,
    // and under Postgres READ COMMITTED its SELECT can still read this row's
    // pre-commit revoked=false; its post-SELECT re-check would then match its
    // own snapshot and cache the stale row for the full TTL (PR #2188 round-3
    // review). This second transition moves the generation past that snapshot,
    // so the racing validate skips its cache write; invalidate_cache below then
    // clears any entry that still beat us (both serialize on cache_mtx_).
    revoke_generation_.fetch_add(1, std::memory_order_release);
    invalidate_cache(PQgetvalue(res.get(), 0, 0));
    return true;
}

std::expected<std::size_t, std::string>
ApiTokenStore::revoke_for_principal(const std::string& principal_id) {
    if (!open_)
        return std::unexpected("database not open");
    if (principal_id.empty())
        return std::size_t{0}; // argument guard: nothing to revoke, DB untouched

    // Bump revoke generation BEFORE the UPDATE — same contract as
    // `revoke_token`.
    revoke_generation_.fetch_add(1, std::memory_order_release);

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        // authoritative: never report a count (even 0) when we could not reach
        // the DB — that is indistinguishable from "the principal had no tokens"
        // and would let "Sign out everywhere" lie during an outage.
        return std::unexpected("database unavailable — try again");

    // ONE statement yields both the count (PQntuples) and every hash to
    // invalidate (RETURNING token_hash) — no separate pre-SELECT snapshot
    // needed; the UPDATE's own WHERE clause is the authoritative "what
    // changed" answer (#1033).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE api_token_store.api_tokens SET revoked = TRUE "
        "WHERE principal_id = $1 AND revoked = FALSE RETURNING token_hash",
        std::vector<std::string>{principal_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("revoke_for_principal did not persist: ") +
                               PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    // Second generation bump after the UPDATE commits, before invalidating —
    // see revoke_token for the full rationale (closes the post-first-bump /
    // pre-commit READ COMMITTED cache-poisoning window).
    if (rows > 0)
        revoke_generation_.fetch_add(1, std::memory_order_release);
    for (int i = 0; i < rows; ++i)
        invalidate_cache(PQgetvalue(res.get(), i, 0));
    return static_cast<std::size_t>(rows);
}

std::expected<bool, std::string> ApiTokenStore::delete_token(const std::string& token_id) {
    if (!open_)
        return std::unexpected("database not open");

    // Bump revoke generation BEFORE the DELETE — a delete is a stronger
    // form of revoke from the cache's perspective, so the same TOCTOU
    // applies.
    revoke_generation_.fetch_add(1, std::memory_order_release);

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        // authoritative (ADR-0030 §Posture names delete_token alongside
        // revoke_*): a lease timeout is a WRITE FAILURE, never a silent success
        // and never a false "not found".
        return std::unexpected("database unavailable — try again");

    // RETURNING token_hash — same #1033 idiom as revoke_token: PQntuples is
    // the changed-check, the returned hash is the cache-invalidation key.
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM api_token_store.api_tokens WHERE token_id = $1 RETURNING token_hash",
        std::vector<std::string>{token_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("delete did not persist: ") + PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    if (rows == 0)
        return false; // DB write succeeded; no such token (already gone / unknown id)

    // Second generation bump after the DELETE commits, before invalidating —
    // see revoke_token for the full rationale.
    revoke_generation_.fetch_add(1, std::memory_order_release);
    invalidate_cache(PQgetvalue(res.get(), 0, 0));
    return true;
}

} // namespace yuzu::server
