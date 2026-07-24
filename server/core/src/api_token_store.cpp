#include "api_token_store.hpp"
#include "engine_principal_store.hpp"
#include "mcp_policy.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "rotation_confirm_state.hpp"
#include "secure_random.hpp"

#include <yuzu/secure_zero.hpp>

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
        // v2 (design doc §7, plan PR 4.3): overlap-pair credential rotation.
        // Additive only — every existing row defaults cleanly to "not
        // rotating" (empty group/predecessor, 0 overlap/confirm instants).
        {2,
         "ALTER TABLE api_tokens ADD COLUMN rotation_group TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE api_tokens ADD COLUMN supersedes_token_id TEXT NOT NULL DEFAULT '';"
         "ALTER TABLE api_tokens ADD COLUMN overlap_expires_at BIGINT NOT NULL DEFAULT 0;"
         "ALTER TABLE api_tokens ADD COLUMN confirmed_at BIGINT NOT NULL DEFAULT 0;"},
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
    t.rotation_group = col(res, row, c++);
    t.supersedes_token_id = col(res, row, c++);
    t.overlap_expires_at = to_i64(col(res, row, c++));
    t.confirmed_at = to_i64(col(res, row, c++));
    return t;
}

// Column order shared by validate_token / get_token / list_tokens /
// list_active_for_principal; the token_hash slot is either the real column
// (validate_token) or a literal '' (the others mask it — never expose the
// hash outside a validate).
constexpr const char* kTokenColsTail =
    "name, principal_id, scope_service, created_at, expires_at, last_used_at, revoked, "
    "mcp_tier, principal_kind, rotation_group, supersedes_token_id, overlap_expires_at, "
    "confirmed_at";

// Same query `list_active_for_principal` runs, but against a caller-supplied
// `conn` (no lease acquisition) and a caller-supplied `now` — used by
// `rotate_engine_credential`/`confirm_rotation` to re-read the active set
// INSIDE their advisory-locked transaction (Hermes F1/F5): the count/rows
// this returns are what the ≤2-active branch decision and the pairing
// checks are based on, never a pre-lock snapshot.
std::vector<ApiToken> read_active_for_principal_on_conn(PGconn* conn, const std::string& principal_id,
                                                         int64_t now) {
    std::vector<ApiToken> result;
    const std::string sql = std::string("SELECT token_id, '' AS token_hash, ") + kTokenColsTail +
                            " FROM api_token_store.api_tokens "
                            "WHERE principal_id = $1 AND revoked = FALSE "
                            "AND (expires_at = 0 OR expires_at > $2::bigint) "
                            "ORDER BY created_at ASC";
    pg::PgResult res = pg::exec_params(
        conn, sql.c_str(), std::vector<std::string>{principal_id, std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK)
        return result;
    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.push_back(read_token(res.get(), i));
    return result;
}

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
                            const std::string& mcp_tier, std::string principal_kind) {
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

    // ── Engine principal block (design doc §6/§7/§8) ───────────────────────
    // C++-side allowlist ahead of the DB CHECK (principal_kind IN
    // ('human','engine')) — defense-in-depth per governance PR-4.2 prereq:
    // never let an unrecognized value reach Postgres and rely solely on the
    // constraint to reject it.
    if (principal_kind != "human" && principal_kind != "engine")
        return std::unexpected("invalid principal_kind");

    // G2 (governance hardening, security LOW / UP-1): symmetric namespace
    // guard. Without this, the `engine:`-namespace guarantee is only as
    // strong as every call site remembering to pass principal_kind=="engine"
    // whenever principal_id starts with "engine:" — a human-kind token could
    // otherwise carry an engine: id that RbacStore's engine-resolution arm
    // would happily match at role-resolution time. Make the guarantee
    // structural here, ahead of PR 4.3's engine-minting routes.
    if (principal_id.starts_with("engine:") && principal_kind != "engine")
        return std::unexpected("engine:-namespaced principal_id requires principal_kind=engine");

    if (principal_kind == "engine") {
        // §6/§7/§8: scope/tier/TTL + referential-integrity validation,
        // shared verbatim with `rotate_engine_credential`'s candidate-
        // successor prep (Hermes F2) so the two mint paths can never drift.
        auto validation = validate_engine_mint(principal_id, scope_service, mcp_tier, expires_at,
                                               now_epoch());
        if (!validation.has_value())
            return std::unexpected(validation.error());
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

    // principal_kind is bound as a parameter ($7): "human" by default, or
    // "engine" once the engine block above has validated the mint (design doc
    // §§6-8). The DB CHECK (principal_kind IN ('human','engine')) is the
    // schema-level backstop behind the C++-side allowlist checked earlier.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO api_token_store.api_tokens "
        "(token_id, token_hash, name, principal_id, scope_service, mcp_tier, principal_kind, "
        " created_at, expires_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8::bigint,$9::bigint) RETURNING token_id",
        std::vector<std::string>{token_id, hash, name, principal_id, scope_service, mcp_tier,
                                 principal_kind, std::to_string(now), std::to_string(expires_at)});
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

ApiTokenStore::CheckedToken ApiTokenStore::validate_token_checked(const std::string& raw_token) {
    if (raw_token.empty())
        return {TokenCheck::kInvalid, std::nullopt};  // definitive: no credential is no credential
    if (!open_)
        return {TokenCheck::kUnavailable, std::nullopt};  // store closed → we cannot know

    // This does its OWN status-aware lookup rather than calling validate_token and
    // inferring from its nullopt. An earlier version did exactly that, then probed
    // the store with a *different* trivial statement to decide whether the negative
    // answer was real — and that is wrong in the precise case this function exists
    // for: `validate_token` folds "could not acquire a connection" and "the query
    // errored" into the same nullopt as "no such row", while the probe statement can
    // still succeed on a merely-contended store. The result was a healthy stream
    // being killed as `credential_revoked` because the backend was busy — the 60 s
    // grace window (Decision 15(i)) unreachable for the most likely auth-store fault.
    // Only the status of the actual lookup can distinguish the two. (The reasoning
    // was written against SQLite's BUSY/IOERR rc and survives the Postgres port
    // unchanged: a failed lease and a non-TUPLES_OK result are the same class of
    // "we asked and did not get an answer", and zero rows is the same definitive no.)
    const auto hash = sha256_hex(raw_token);
    const auto gen_before = revoke_generation_.load(std::memory_order_acquire);

    {
        std::lock_guard cache_lock(cache_mtx_);
        auto it = token_cache_.find(hash);
        if (it != token_cache_.end()) {
            if (std::chrono::steady_clock::now() - it->second.cached_at < kTokenCacheTtl) {
                const auto& cached = it->second.token;
                const auto now = now_epoch();
                if (cached.revoked || (cached.expires_at > 0 && now > cached.expires_at)) {
                    token_cache_.erase(it);
                    cache_misses_.fetch_add(1, std::memory_order_relaxed);
                    return {TokenCheck::kInvalid, std::nullopt}; // definitive
                }
                cache_hits_.fetch_add(1, std::memory_order_relaxed);
                return {TokenCheck::kValid, cached};
            }
            token_cache_.erase(it);
        }
    }
    cache_misses_.fetch_add(1, std::memory_order_relaxed);

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        // No connection inside the timeout: we could not even ask. NOT evidence of
        // revocation — the caller rides out its bounded grace window instead.
        return {TokenCheck::kUnavailable, std::nullopt};
    }

    const std::string sql = std::string("SELECT token_id, token_hash, ") + kTokenColsTail +
                            " FROM api_token_store.api_tokens WHERE token_hash = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{hash});
    if (res.status() != PGRES_TUPLES_OK) {
        // We asked and did not get an answer (backend error, connection dropped
        // mid-query, ...). Fail-safe: indeterminate never GRANTS access, it only
        // defers the decision to cut an already-authenticated stream.
        return {TokenCheck::kUnavailable, std::nullopt};
    }
    if (PQntuples(res.get()) == 0)
        return {TokenCheck::kInvalid, std::nullopt}; // the row genuinely is not there

    ApiToken t = read_token(res.get(), 0);

    if (t.revoked || (t.expires_at > 0 && now_epoch() > t.expires_at))
        return {TokenCheck::kInvalid, std::nullopt}; // definitive

    // Deliberately NO `UPDATE last_used_at` here. This runs on every heartbeat tick of
    // every live stream: writing would (a) make last_used_at track heartbeats rather
    // than actual calls, and (b) put a write on a pooled connection every time a
    // stream's cache entry expires — with streams' TTLs aligned by attach time, that is
    // a thundering herd of writes that every token-authenticated request on the server
    // then queues behind. Re-validation is a READ.
    //
    // The generation re-check is taken UNDER cache_mtx_, matching validate_token: a
    // check-then-lock ordering leaves a window where a racing revoke's erase runs
    // between the check and the insert, leaving a revoked=false entry alive for a full
    // kTokenCacheTtl — which on this path would keep a revoked credential's stream up.
    {
        std::lock_guard cache_lock(cache_mtx_);
        if (revoke_generation_.load(std::memory_order_acquire) == gen_before) {
            token_cache_[hash] = CachedToken{t, std::chrono::steady_clock::now()};
        }
    }
    return {TokenCheck::kValid, std::move(t)};
}

void ApiTokenStore::invalidate_cache(const std::string& token_hash) {
    std::lock_guard cache_lock(cache_mtx_);
    token_cache_.erase(token_hash);
}

std::size_t ApiTokenStore::cache_size() const {
    std::lock_guard cache_lock(cache_mtx_);
    return token_cache_.size();
}

void ApiTokenStore::set_engine_referent_check(
    std::function<EngineLookupStatus(const std::string&)> fn) {
    engine_referent_check_ = std::move(fn);
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

std::vector<ApiToken>
ApiTokenStore::list_active_for_principal(const std::string& principal_id) const {
    std::vector<ApiToken> result;
    if (!open_ || principal_id.empty())
        return result;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;

    const auto now = now_epoch();
    const std::string sql = std::string("SELECT token_id, '' AS token_hash, ") + kTokenColsTail +
                            " FROM api_token_store.api_tokens "
                            "WHERE principal_id = $1 AND revoked = FALSE "
                            "AND (expires_at = 0 OR expires_at > $2::bigint) "
                            "ORDER BY created_at ASC";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(), std::vector<std::string>{principal_id, std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK)
        return result;

    const int rows = PQntuples(res.get());
    result.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        result.push_back(read_token(res.get(), i)); // token_hash is the literal '' column above
    return result;
}

// ── Overlap-pair rotation (design doc §7) ───────────────────────────────────

std::expected<void, std::string>
ApiTokenStore::validate_engine_mint(const std::string& principal_id,
                                    const std::string& scope_service, const std::string& mcp_tier,
                                    int64_t expires_at, int64_t now) const {
    // F6 (Hermes pass-2 MEDIUM M3): engine principals are fleet-wide only
    // (§4.3) — a service-scoped engine token is not a valid combination.
    if (!scope_service.empty())
        return std::unexpected("engine principal tokens cannot be service-scoped");

    // §8: mcp_tier readonly hard-lock. Unlike the human path (which permits
    // an empty mcp_tier for a non-MCP token), an engine token MUST be
    // readonly — empty or any other tier is rejected outright.
    if (mcp_tier != "readonly")
        return std::unexpected("engine principal tokens must use mcp_tier=readonly");

    // §7: non-perpetual / 90-day ceiling.
    if (expires_at == 0)
        return std::unexpected("engine principal tokens cannot be perpetual (90-day max)");
    constexpr int64_t k90Days = 90 * 24 * 3600;
    if (expires_at - now > k90Days)
        return std::unexpected("engine principal token TTL cannot exceed 90 days");

    // §6: creation-time referential integrity. Fail-closed if the resolver
    // isn't wired yet — never mint an engine token without this check.
    if (!engine_referent_check_)
        return std::unexpected("engine referent check unavailable");
    switch (engine_referent_check_(principal_id)) {
    case EngineLookupStatus::Active:
        return {};
    case EngineLookupStatus::MissingOrRevoked:
        // Terminal (401-class) per engine_principal_store.hpp's three-state
        // contract — the referenced principal doesn't exist or was revoked.
        return std::unexpected("engine principal not found or revoked");
    case EngineLookupStatus::StoreUnreachable:
        // Retryable (503-class), distinct from the terminal case above — see
        // the EngineLookupStatus doc comment / design doc §3.1.
        return std::unexpected("engine principal store unavailable — try again");
    }
    return std::unexpected("engine referent check returned an unrecognized status");
}

bool ApiTokenStore::try_reserve(const std::string& rotation_group, std::string& out_raw,
                                std::string& out_requesting_user) const {
    std::lock_guard cache_lock(rotation_cache_mtx_);
    auto it = rotation_grace_cache_.find(rotation_group);
    if (it == rotation_grace_cache_.end())
        return false;
    out_requesting_user = it->second.requesting_user;
    if (std::chrono::steady_clock::now() - it->second.minted > kRotationGraceSecs) {
        // Raw-secret reveal is time-bounded (§7) — the entry itself stays
        // resident so `confirm_rotation`/`grace_entry_owner` can still
        // resolve `requesting_user` for the rest of the (much longer)
        // overlap window. See the RotationGraceEntry doc comment.
        return false;
    }
    out_raw = it->second.raw;
    return true;
}

bool ApiTokenStore::grace_entry_owner(const std::string& rotation_group,
                                      std::string& out_requesting_user) const {
    std::lock_guard cache_lock(rotation_cache_mtx_);
    auto it = rotation_grace_cache_.find(rotation_group);
    if (it == rotation_grace_cache_.end())
        return false;
    out_requesting_user = it->second.requesting_user;
    return true;
}

void ApiTokenStore::evict_rotation_raw(const std::string& rotation_group) {
    std::lock_guard cache_lock(rotation_cache_mtx_);
    auto it = rotation_grace_cache_.find(rotation_group);
    if (it != rotation_grace_cache_.end())
        yuzu::secure_zero(it->second.raw); // scrub before the erase frees it
    rotation_grace_cache_.erase(rotation_group);
}

void ApiTokenStore::resolve_rotation_pair_after_revoke(const std::string& principal_id,
                                                      const std::string& rotation_group,
                                                      const std::string& revoked_token_id) {
    if (!open_ || principal_id.empty() || rotation_group.empty())
        return; // the common non-rotation revoke — nothing to resolve

    // Clear the surviving partner's rotation state under the same principal
    // advisory lock rotate/confirm/sweep take, so this can't race them. The
    // partner is simply the OTHER live row sharing this rotation_group — the
    // clear is identical whether it is the predecessor or the successor: it
    // becomes a plain standalone credential and (crucially) drops out of the
    // sweep's predecessor scan (overlap_expires_at -> 0).
    (void)pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult lock_res =
            pg::exec_params(conn, "SELECT pg_advisory_xact_lock(hashtext($1))",
                            std::vector<std::string>{principal_id});
        if (lock_res.status() != PGRES_TUPLES_OK)
            return false;
        pg::PgResult r = pg::exec_params(
            conn,
            "UPDATE api_token_store.api_tokens "
            "SET rotation_group = '', supersedes_token_id = '', overlap_expires_at = 0 "
            "WHERE rotation_group = $1 AND token_id <> $2 AND revoked = FALSE",
            std::vector<std::string>{rotation_group, revoked_token_id});
        // Zero rows is fine (partner already resolved/gone); no RETURNING, so a
        // successful zero-row match is PGRES_COMMAND_OK. Only a genuine
        // execution failure rolls back.
        return r.status() == PGRES_COMMAND_OK;
    });
    evict_rotation_raw(rotation_group);
}

void ApiTokenStore::store_rotation_raw(const std::string& rotation_group, const std::string& raw,
                                       const std::string& requesting_user) {
    std::lock_guard cache_lock(rotation_cache_mtx_);
    auto it = rotation_grace_cache_.find(rotation_group);
    if (it != rotation_grace_cache_.end())
        yuzu::secure_zero(it->second.raw); // scrub the entry being overwritten
    rotation_grace_cache_[rotation_group] =
        RotationGraceEntry{raw, requesting_user, std::chrono::steady_clock::now()};
}

void ApiTokenStore::scrub_elapsed_grace_secrets() {
    std::lock_guard cache_lock(rotation_cache_mtx_);
    const auto now = std::chrono::steady_clock::now();
    for (auto& [group, entry] : rotation_grace_cache_) {
        // Mirrors try_reserve's own staleness check — once the raw-reveal
        // grace window has elapsed, no caller can read `raw` back out
        // anyway, so its plaintext no longer needs to sit in RAM. The
        // entry itself (notably `requesting_user`) stays resident; only
        // scrub once, so an already-empty `raw` is a cheap no-op.
        if (!entry.raw.empty() && now - entry.minted > kRotationGraceSecs)
            yuzu::secure_zero(entry.raw);
    }
}

std::expected<std::string, std::string>
ApiTokenStore::rotate_engine_credential(const std::string& principal_id, int64_t overlap_secs,
                                        int64_t now, const std::string& requesting_user) {
    if (!open_)
        return std::unexpected("database not open");
    if (principal_id.empty())
        return std::unexpected("principal_id required");
    if (requesting_user.empty())
        return std::unexpected("requesting_user required");

    // §7: reject an under-floor window outright rather than truncating it —
    // a window the module never gets a chance to act within is a worse
    // failure than a rejected rotate call. Pure-math check; no DB round trip
    // needed to evaluate it.
    if (overlap_secs < kOverlapFloorSecs)
        return std::unexpected("overlap window below 24h floor");

    // Reject an absurdly large window outright too — `overlap_secs` is
    // floored above but was never ceilinged, so an unbounded caller value
    // fed into the `now + overlap_secs` adds below would be an unchecked
    // signed int64 overflow (UB), and a wrapped-negative `window_end` could
    // slip past the expiry guards those adds feed. Evaluated here, before
    // any arithmetic touches `overlap_secs`.
    if (overlap_secs > kOverlapCeilSecs)
        return std::unexpected("overlap window exceeds the maximum (10 years)");

    // Candidate successor, prepared BEFORE the locked transaction below
    // (Hermes F2 — see this function's .hpp doc comment for why: both
    // `validate_engine_mint`'s referential-integrity call and CSPRNG
    // generation must not run from inside `with_txn_for`'s callback). Used
    // only if the lock-held re-read below actually lands on the 1-active
    // mint branch; discarded otherwise.
    constexpr int64_t k90Days = 90 * 24 * 3600;
    const int64_t candidate_expires_at = now + k90Days;
    auto candidate_validation =
        validate_engine_mint(principal_id, /*scope_service=*/{}, "readonly", candidate_expires_at,
                             now);
    std::string candidate_raw, candidate_hash, candidate_token_id, candidate_error;
    if (candidate_validation.has_value()) {
        auto raw_result = generate_raw_token();
        if (raw_result.has_value()) {
            candidate_raw = std::move(*raw_result);
            candidate_hash = sha256_hex(candidate_raw);
            candidate_token_id = candidate_hash.substr(0, 24);
        } else {
            candidate_error = raw_result.error();
        }
    } else {
        candidate_error = candidate_validation.error();
    }

    std::string error_msg;
    std::string raw_out;
    // Populated only by the 1-active mint branch, applied to the RAM grace
    // cache AFTER the transaction below commits successfully.
    std::string grace_group_out, grace_raw_out;

    // Hermes F1: the ENTIRE check -> mint -> stamp sequence commits inside
    // ONE transaction, opened with a principal-scoped Postgres advisory
    // lock — a concurrent rotate_engine_credential/confirm_rotation call
    // for the SAME principal_id blocks on the lock until this transaction
    // resolves, so its own re-read always observes this call's committed
    // effect (or its absence), never an interleaved half-state. The ≤2
    // ceiling therefore holds under concurrency.
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult lock_res =
            pg::exec_params(conn, "SELECT pg_advisory_xact_lock(hashtext($1))",
                            std::vector<std::string>{principal_id});
        if (lock_res.status() != PGRES_TUPLES_OK) {
            error_msg = "failed to acquire rotation lock";
            return false;
        }

        auto active = read_active_for_principal_on_conn(conn, principal_id, now);

        // Belt-and-braces (mirrors the G2 namespace guard in create_token):
        // rotate_engine_credential only ever operates on engine credentials
        // — never silently mix a human-kind row into the rotation state
        // machine.
        for (const auto& t : active) {
            if (t.principal_kind != "engine") {
                error_msg = "principal has a non-engine active credential";
                return false;
            }
        }

        if (active.empty()) {
            error_msg = "no active credential to rotate — mint one first";
            return false;
        }

        if (active.size() == 1) {
            const ApiToken& predecessor = active.front();
            const int64_t window_end = now + overlap_secs;

            // Reject, never truncate, if the requested overlap would
            // outlive either credential's own expiry.
            if (predecessor.expires_at != 0 && window_end > predecessor.expires_at) {
                error_msg = "overlap window would exceed the predecessor credential's expiry";
                return false;
            }
            if (window_end > candidate_expires_at) {
                error_msg = "overlap window would exceed the successor credential's expiry";
                return false;
            }
            if (!candidate_error.empty()) {
                error_msg = candidate_error;
                return false;
            }

            // Hermes F2: mint (INSERT) and pair-stamp (both UPDATEs) commit
            // in this SAME transaction — a crash here rolls back the whole
            // thing, so a successful rotate always leaves both rows linked;
            // there is no window where an orphan successor (empty
            // rotation_group) can exist.
            pg::PgResult ins = pg::exec_params(
                conn,
                "INSERT INTO api_token_store.api_tokens "
                "(token_id, token_hash, name, principal_id, scope_service, mcp_tier, "
                " principal_kind, created_at, expires_at, rotation_group, supersedes_token_id) "
                "VALUES ($1,$2,$3,$4,'', 'readonly', 'engine', $5::bigint, $6::bigint, $7, $8) "
                "RETURNING token_id",
                std::vector<std::string>{candidate_token_id, candidate_hash, predecessor.name,
                                         principal_id, std::to_string(now),
                                         std::to_string(candidate_expires_at), candidate_token_id,
                                         predecessor.token_id});
            if (ins.status() != PGRES_TUPLES_OK || PQntuples(ins.get()) == 0) {
                error_msg = "failed to mint successor credential";
                return false;
            }

            pg::PgResult r2 = pg::exec_params(
                conn,
                "UPDATE api_token_store.api_tokens "
                "SET rotation_group = $1, overlap_expires_at = $2::bigint "
                "WHERE token_id = $3 AND revoked = FALSE RETURNING token_id",
                std::vector<std::string>{candidate_token_id, std::to_string(now + overlap_secs),
                                         predecessor.token_id});
            if (r2.status() != PGRES_TUPLES_OK || PQntuples(r2.get()) == 0) {
                error_msg = "failed to stamp predecessor overlap window";
                return false;
            }

            raw_out = candidate_raw;
            grace_group_out = candidate_token_id;
            grace_raw_out = candidate_raw;
            return true;
        }

        if (active.size() == 2) {
            const ApiToken* predecessor = nullptr;
            const ApiToken* successor = nullptr;
            for (const auto& t : active) {
                if (!t.supersedes_token_id.empty())
                    successor = &t;
                else
                    predecessor = &t;
            }
            if (predecessor == nullptr || successor == nullptr ||
                successor->rotation_group.empty() ||
                successor->rotation_group != predecessor->rotation_group ||
                successor->supersedes_token_id != predecessor->token_id) {
                error_msg = "two active credentials not in a recognized rotation pair — "
                           "resolve via revoke, not rotate";
                return false;
            }

            // Idempotency window, epoch side: a retry more than
            // kRotationGraceSecs after the successor's own mint is out of
            // bounds regardless of whether the in-memory cache entry
            // happens to still be present.
            if (now - successor->created_at > kRotationGraceSecs.count()) {
                error_msg = "rotation grace window elapsed; confirm or revoke";
                return false;
            }

            // Idempotency window, cache side: the raw secret itself must
            // still be resident and unexpired.
            std::string cached_raw, cached_user;
            if (!try_reserve(successor->rotation_group, cached_raw, cached_user)) {
                error_msg = "rotation grace window elapsed; confirm or revoke";
                return false;
            }

            // Hermes F4: only the SAME operator who initiated this rotation
            // may re-serve its raw secret — never a different admin, even
            // within the grace window.
            if (cached_user != requesting_user) {
                error_msg = "rotation in progress by a different operator";
                return false;
            }

            // Re-serve the SAME raw value. The per-reveal audit and the
            // step-up re-validation this replay still owes (§7) are the
            // route layer's responsibility, not this store's.
            raw_out = cached_raw;
            return true;
        }

        // Defensive: this function's own 1-active arm is the only mint path
        // it drives, so >2 active means a credential was minted outside
        // rotate_engine_credential (e.g. a direct create_token call) — never
        // silently arbitrate which one to treat as authoritative.
        error_msg = "more than two active credentials for this principal — "
                    "resolve manually before rotating";
        return false;
    });

    if (!ok)
        return std::unexpected(error_msg.empty() ? "rotation failed" : error_msg);

    // Cache the raw secret + initiating operator for the grace window AFTER
    // the mint committed — the one-time-reveal contract's "once" means once
    // per grace-bounded rotation attempt (§7), so a bounded retry BY THE
    // SAME OPERATOR can re-serve this exact value.
    if (!grace_group_out.empty())
        store_rotation_raw(grace_group_out, grace_raw_out, requesting_user);

    return raw_out;
}

std::expected<void, std::string>
ApiTokenStore::confirm_rotation(const std::string& principal_id, const std::string& token_id,
                                const std::string& requesting_user) {
    if (!open_)
        return std::unexpected("database not open");
    if (principal_id.empty())
        return std::unexpected("principal_id required");
    if (token_id.empty())
        return std::unexpected("token_id required");
    if (requesting_user.empty())
        return std::unexpected("requesting_user required");

    const int64_t now = now_epoch();
    std::string error_msg;
    std::string revoked_hash;
    std::string confirmed_group;

    // Advisory-locked exactly like rotate_engine_credential (Hermes F5) —
    // the confirm + predecessor-revoke + successor-clear triple commits
    // atomically in this same transaction, and can't race a concurrent
    // rotate/confirm/sweep for the same principal.
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult lock_res =
            pg::exec_params(conn, "SELECT pg_advisory_xact_lock(hashtext($1))",
                            std::vector<std::string>{principal_id});
        if (lock_res.status() != PGRES_TUPLES_OK) {
            error_msg = "failed to acquire rotation lock";
            return false;
        }

        auto active = read_active_for_principal_on_conn(conn, principal_id, now);
        for (const auto& t : active) {
            if (t.principal_kind != "engine") {
                error_msg = "principal has a non-engine active credential";
                return false;
            }
        }

        // #2404: discriminate the states a confirm can find so a replay after
        // the rotation already resolved gets a TERMINAL answer (the caller's
        // classifier maps these strings to a 409/kInvalidParams conflict),
        // instead of the old blanket "no in-flight rotation" that classified
        // 503-retryable and made an idempotent-hint-honouring agent retry a
        // permanently-failing call forever. The state machine is factored into
        // a pure classifier (rotation_confirm_state.hpp) so a future
        // pre-consume recheck seam (#2443) can reuse the same taxonomy; the
        // recheck HERE, under the advisory lock, stays authoritative.
        switch (detail::classify_confirm_state(active, token_id)) {
        case detail::RotationConfirmState::kNoneActive:
            // Ambiguous with a swallowed read failure (empty-on-error read
            // contract) -> stays retryable, never a terminal client error.
            error_msg = "no in-flight rotation to confirm";
            return false;
        case detail::RotationConfirmState::kOverfull:
            error_msg = "more than two active credentials for this principal - "
                        "resolve manually before confirming";
            return false;
        case detail::RotationConfirmState::kUnresolvedSole:
            // A best-effort pair-resolve failed (or the partner expired before
            // cleanup), leaving one row still stamped mid-rotation. Rotating
            // from here would strand a malformed pair, so the remediation is
            // revoke/inspect, NEVER rotate (#2404 F1).
            error_msg = "one active credential with unresolved rotation metadata - "
                        "do not rotate; revoke or inspect the credential state";
            return false;
        case detail::RotationConfirmState::kSoleConfirmed:
            error_msg = "rotation already confirmed - the supplied token_id is the "
                        "sole active credential; nothing to confirm";
            return false;
        case detail::RotationConfirmState::kSoleResolved:
            error_msg = "no rotation in flight - the supplied token_id is already the "
                        "sole active credential; nothing to confirm";
            return false;
        case detail::RotationConfirmState::kSoleOtherToken:
            error_msg = "no rotation in flight for the supplied token_id - the rotation "
                        "was resolved (confirmed, revoked, or cut over); rotate again if "
                        "a new rotation is needed";
            return false;
        case detail::RotationConfirmState::kPair:
            break; // exactly two active -> fall through to pair processing below
        }

        const ApiToken* predecessor = nullptr;
        const ApiToken* successor = nullptr;
        for (const auto& t : active) {
            if (!t.supersedes_token_id.empty())
                successor = &t;
            else
                predecessor = &t;
        }
        if (predecessor == nullptr || successor == nullptr || successor->rotation_group.empty() ||
            successor->rotation_group != predecessor->rotation_group ||
            successor->supersedes_token_id != predecessor->token_id) {
            error_msg = "no in-flight rotation to confirm";
            return false;
        }

        // #2384: the caller must pin the exact rotation being confirmed by
        // supplying the successor's token_id (the value rotate returned).
        // A stale id from an earlier rotation — the blind-retry hazard —
        // mismatches here and rejects before any write. Checked before the
        // initiator binding: structural mismatch is the harder failure.
        if (token_id != successor->token_id) {
            error_msg = "token_id does not match the pending rotation successor; "
                        "pass the token_id returned by rotate";
            return false;
        }

        // Hermes F4/F5: only the operator who initiated the rotation may
        // confirm it — same binding as the grace-window re-serve, but NOT
        // time-bounded to kRotationGraceSecs (see grace_entry_owner's doc
        // comment).
        std::string initiator;
        if (!grace_entry_owner(successor->rotation_group, initiator)) {
            error_msg = "rotation confirmation unavailable — retry via rotate or fall back to "
                       "revoke";
            return false;
        }
        if (initiator != requesting_user) {
            error_msg = "rotation in progress by a different operator";
            return false;
        }

        confirmed_group = successor->rotation_group;

        pg::PgResult confirm_res = pg::exec_params(
            conn,
            "UPDATE api_token_store.api_tokens SET confirmed_at = $1::bigint "
            "WHERE token_id = $2 AND revoked = FALSE RETURNING token_id",
            std::vector<std::string>{std::to_string(now), successor->token_id});
        if (confirm_res.status() != PGRES_TUPLES_OK || PQntuples(confirm_res.get()) == 0) {
            error_msg = "failed to confirm rotation";
            return false;
        }

        // Bump the revoke generation BEFORE the predecessor's revoke UPDATE
        // — same TOCTOU contract revoke_token/sweep_expired_rotations use.
        revoke_generation_.fetch_add(1, std::memory_order_release);

        pg::PgResult revoke_res = pg::exec_params(
            conn,
            "UPDATE api_token_store.api_tokens SET revoked = TRUE "
            "WHERE token_id = $1 AND revoked = FALSE RETURNING token_hash",
            std::vector<std::string>{predecessor->token_id});
        if (revoke_res.status() != PGRES_TUPLES_OK || PQntuples(revoke_res.get()) == 0) {
            error_msg = "failed to revoke predecessor on confirm";
            return false;
        }
        revoked_hash = PQgetvalue(revoke_res.get(), 0, 0);

        pg::PgResult clear_res = pg::exec_params(
            conn,
            "UPDATE api_token_store.api_tokens "
            "SET rotation_group = '', supersedes_token_id = '', overlap_expires_at = 0 "
            "WHERE token_id = $1 AND revoked = FALSE RETURNING token_id",
            std::vector<std::string>{successor->token_id});
        if (clear_res.status() != PGRES_TUPLES_OK || PQntuples(clear_res.get()) == 0) {
            error_msg = "failed to clear successor rotation state on confirm";
            return false;
        }

        return true;
    });

    if (!ok)
        return std::unexpected(error_msg.empty() ? "confirm failed" : error_msg);

    // Second generation bump AFTER the txn commits, before invalidating the
    // cache — the double-bump TOCTOU contract revoke_token/revoke_for_principal
    // use (#2188). Without it, a validate_token whose SELECT read the
    // pre-commit revoked=FALSE predecessor could re-populate the cache with the
    // stale row AFTER invalidate_cache ran, letting the revoked predecessor
    // validate from cache for up to kTokenCacheTtl (60s) past confirm — exactly
    // the immediate-cutover guarantee this call exists to provide.
    revoke_generation_.fetch_add(1, std::memory_order_release);
    invalidate_cache(revoked_hash);
    evict_rotation_raw(confirmed_group);
    return {};
}

// ── T12: rotation maintenance sweep (design doc §7) ─────────────────────────

std::vector<ApiToken> ApiTokenStore::sweep_expired_rotations(int64_t now, bool* tick_failed) {
    std::vector<ApiToken> revoked;
    if (tick_failed)
        *tick_failed = false;
    if (!open_)
        return revoked;

    // Secret-hygiene half, RAM-only (no DB round trip): scrub any
    // grace-cache `raw` past its raw-reveal window before the DB-side
    // auto-revoke half below. Runs every tick regardless of whether this
    // tick finds any expired predecessors.
    scrub_elapsed_grace_secrets();

    // Half 1's read: every non-revoked predecessor whose overlap window has
    // elapsed. Scoped to its own block so the read lease is released before
    // the per-row write transaction below (a size-1 test pool would
    // otherwise self-deadlock trying to acquire a second connection).
    std::vector<ApiToken> expired_predecessors;
    {
        auto lease = pool_.try_acquire_for(kReadTimeout);
        if (!lease) {
            if (tick_failed)
                *tick_failed = true; // pool contention — the tick did not run
            return revoked;
        }
        const std::string sql = std::string("SELECT token_id, '' AS token_hash, ") +
                                kTokenColsTail +
                                " FROM api_token_store.api_tokens "
                                "WHERE revoked = FALSE AND overlap_expires_at > 0 "
                                "AND overlap_expires_at <= $1::bigint AND supersedes_token_id = '' "
                                // Only auto-revoke a predecessor that still has a
                                // LIVE successor to cut over to (design §7). If the
                                // successor was manually revoked/deleted, the
                                // predecessor is now the principal's ONLY credential
                                // — auto-revoking it here would leave zero. This
                                // races-closes the window before
                                // resolve_rotation_pair_after_revoke clears the
                                // predecessor's overlap_expires_at.
                                "AND EXISTS (SELECT 1 FROM api_token_store.api_tokens s "
                                "WHERE s.rotation_group = api_token_store.api_tokens.rotation_group "
                                "AND s.supersedes_token_id = api_token_store.api_tokens.token_id "
                                "AND s.revoked = FALSE)";
        pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                           std::vector<std::string>{std::to_string(now)});
        if (res.status() != PGRES_TUPLES_OK) {
            if (tick_failed)
                *tick_failed = true; // predecessor scan failed — the tick did not run
            return revoked;
        }
        const int rows = PQntuples(res.get());
        expired_predecessors.reserve(static_cast<std::size_t>(rows));
        for (int i = 0; i < rows; ++i)
            expired_predecessors.push_back(read_token(res.get(), i));
    }

    for (const auto& predecessor : expired_predecessors) {
        // Bump revoke generation BEFORE the UPDATE — same TOCTOU contract as
        // revoke_token/revoke_for_principal (a concurrent validate_token's
        // SELECT racing this UPDATE observes the generation move at its
        // cache-write step and skips the stale write).
        revoke_generation_.fetch_add(1, std::memory_order_release);

        std::string revoked_hash;
        // Atomic pair-resolve: revoke the predecessor AND clear the
        // surviving successor's rotation state together, or neither —
        // never leave a revoked predecessor with a successor still stamped
        // mid-rotation (design doc §7: "revocation during overlap ...
        // resolves the rotation state"). Hermes F3: the clear UPDATE's
        // result is checked (a genuine execution failure — not merely
        // "matched zero rows", the expected idempotent case when the
        // successor is already gone/resolved — rolls back the WHOLE
        // transaction, including the predecessor's revoke, so "or neither"
        // is a real guarantee). Also advisory-locked on the same
        // principal_id key rotate_engine_credential/confirm_rotation use,
        // so this sweep can't race a concurrent manual rotate/confirm for
        // the same principal.
        const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) {
            pg::PgResult lock_res =
                pg::exec_params(conn, "SELECT pg_advisory_xact_lock(hashtext($1))",
                                std::vector<std::string>{predecessor.principal_id});
            if (lock_res.status() != PGRES_TUPLES_OK)
                return false;

            // Re-assert the scan's preconditions UNDER THE LOCK (the scan at the
            // top of this function is unlocked, so a manual successor-revoke
            // could have run between it and this locked revoke): only revoke if
            // the predecessor still has a live overlap window AND a live
            // successor to cut over to. Without this, a successor manually
            // revoked in that window — whose resolve_rotation_pair_after_revoke
            // cleared this predecessor's overlap_expires_at — would still be
            // revoked here, dropping the principal to ZERO credentials (the
            // exact §7 invariant). The `overlap_expires_at > 0` check makes
            // resolve's clear authoritative under the lock; the EXISTS is the
            // belt to its suspenders.
            pg::PgResult r1 = pg::exec_params(
                conn,
                "UPDATE api_token_store.api_tokens SET revoked = TRUE "
                "WHERE token_id = $1 AND revoked = FALSE AND overlap_expires_at > 0 "
                "AND EXISTS (SELECT 1 FROM api_token_store.api_tokens s "
                "WHERE s.rotation_group = api_token_store.api_tokens.rotation_group "
                "AND s.supersedes_token_id = api_token_store.api_tokens.token_id "
                "AND s.revoked = FALSE) "
                "RETURNING token_hash",
                std::vector<std::string>{predecessor.token_id});
            if (r1.status() != PGRES_TUPLES_OK || PQntuples(r1.get()) == 0)
                return false; // already revoked, or resolved under the lock — idempotent no-op
            revoked_hash = PQgetvalue(r1.get(), 0, 0);

            // A successor already revoked/gone simply matches zero rows,
            // which is fine (nothing survives to clear) — but a genuine
            // execution failure (status != PGRES_TUPLES_OK) must roll back
            // the predecessor's revoke above too, never commit half the
            // pair-resolve.
            pg::PgResult r2 = pg::exec_params(
                conn,
                "UPDATE api_token_store.api_tokens "
                "SET rotation_group = '', supersedes_token_id = '', overlap_expires_at = 0 "
                "WHERE rotation_group = $1 AND supersedes_token_id = $2 AND revoked = FALSE",
                std::vector<std::string>{predecessor.rotation_group, predecessor.token_id});
            // Zero rows is the expected idempotent case (successor already
            // gone/resolved) and still reports PGRES_COMMAND_OK — this
            // UPDATE has no RETURNING clause, so a successful zero-row match
            // is PGRES_COMMAND_OK, never PGRES_TUPLES_OK; only a genuine
            // execution failure returns anything else.
            if (r2.status() != PGRES_COMMAND_OK)
                return false;
            return true;
        });

        if (ok) {
            // Second generation bump AFTER the txn commits, before invalidating
            // — the double-bump TOCTOU contract revoke_token/confirm_rotation
            // use (#2188): closes the window where a validate_token that read
            // the pre-commit predecessor could re-populate the cache after
            // invalidate_cache, re-serving the revoked credential for the 60s TTL.
            revoke_generation_.fetch_add(1, std::memory_order_release);
            invalidate_cache(revoked_hash);
            evict_rotation_raw(predecessor.rotation_group);
            revoked.push_back(predecessor);
        }
    }
    return revoked;
}

std::vector<ApiTokenStore::RotationPair>
ApiTokenStore::list_rotations_nearing_expiry_unused(int64_t now, int64_t warn_within_secs) const {
    std::vector<RotationPair> result;
    if (!open_)
        return result;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return result;

    // Not-yet-elapsed predecessors whose overlap window ends within the
    // warn lead time. An already-elapsed window is sweep_expired_rotations's
    // job, not this half's — the `> $1::bigint` (strictly in the future)
    // keeps the two halves from double-handling the same row on one tick.
    const std::string sql =
        std::string("SELECT token_id, '' AS token_hash, ") + kTokenColsTail +
        " FROM api_token_store.api_tokens "
        "WHERE revoked = FALSE AND overlap_expires_at > $1::bigint "
        "AND overlap_expires_at <= $2::bigint AND supersedes_token_id = ''";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{std::to_string(now), std::to_string(now + warn_within_secs)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::warn("[{}] list_rotations_nearing_expiry_unused: predecessor scan failed",
                    kStoreName);
        return result;
    }

    const int rows = PQntuples(res.get());
    for (int i = 0; i < rows; ++i) {
        ApiToken predecessor = read_token(res.get(), i);

        const std::string succ_sql = std::string("SELECT token_id, '' AS token_hash, ") +
                                     kTokenColsTail +
                                     " FROM api_token_store.api_tokens "
                                     "WHERE revoked = FALSE AND rotation_group = $1 "
                                     "AND supersedes_token_id = $2 AND last_used_at = 0 LIMIT 1";
        pg::PgResult sres = pg::exec_params(
            lease.get(), succ_sql.c_str(),
            std::vector<std::string>{predecessor.rotation_group, predecessor.token_id});
        if (sres.status() != PGRES_TUPLES_OK || PQntuples(sres.get()) == 0)
            continue; // successor gone, already used, or already revoked — nothing to warn about

        ApiToken successor = read_token(sres.get(), 0);
        result.push_back(RotationPair{std::move(predecessor), std::move(successor)});
    }
    return result;
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
        "RETURNING token_hash, principal_id, rotation_group",
        std::vector<std::string>{token_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("revoke did not persist: ") +
                               PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    if (rows == 0)
        return false; // DB write succeeded; no such token (already gone / unknown id)
    const std::string revoked_principal_id = PQgetvalue(res.get(), 0, 1);
    const std::string revoked_rotation_group = PQgetvalue(res.get(), 0, 2);

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
    // Design §7: if this credential was part of an in-flight rotation pair,
    // resolve the surviving partner. Release our write lease FIRST — the helper
    // opens its own advisory-locked txn, and holding two leases would
    // self-starve a size-1 pool.
    lease.reset();
    resolve_rotation_pair_after_revoke(revoked_principal_id, revoked_rotation_group, token_id);
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
        lease.get(),
        "DELETE FROM api_token_store.api_tokens WHERE token_id = $1 "
        "RETURNING token_hash, principal_id, rotation_group",
        std::vector<std::string>{token_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string("delete did not persist: ") + PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    if (rows == 0)
        return false; // DB write succeeded; no such token (already gone / unknown id)
    const std::string deleted_principal_id = PQgetvalue(res.get(), 0, 1);
    const std::string deleted_rotation_group = PQgetvalue(res.get(), 0, 2);

    // Second generation bump after the DELETE commits, before invalidating —
    // see revoke_token for the full rationale.
    revoke_generation_.fetch_add(1, std::memory_order_release);
    invalidate_cache(PQgetvalue(res.get(), 0, 0));
    // Design §7: resolve the rotation pair if this credential was part of one
    // (release our lease first — see revoke_token).
    lease.reset();
    resolve_rotation_pair_after_revoke(deleted_principal_id, deleted_rotation_group, token_id);
    return true;
}

} // namespace yuzu::server
