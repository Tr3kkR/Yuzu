#pragma once

#include <sqlite3.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

struct ApiToken {
    std::string token_id;      // Short display ID (prefix of hash)
    std::string token_hash;    // SHA-256 hash of raw token (stored, never the raw token)
    std::string name;          // Human-readable label
    std::string principal_id;  // Username who created it
    std::string scope_service; // Non-empty = scoped to this IT service (change window token)
    std::string mcp_tier;      // "readonly", "operator", "supervised", or "" (not MCP)
    int64_t created_at{0};
    int64_t expires_at{0}; // 0 = never
    int64_t last_used_at{0};
    bool revoked{false};
};

class ApiTokenStore {
public:
    explicit ApiTokenStore(const std::filesystem::path& db_path);
    ~ApiTokenStore();

    ApiTokenStore(const ApiTokenStore&) = delete;
    ApiTokenStore& operator=(const ApiTokenStore&) = delete;

    bool is_open() const;

    /// Create a new API token. Returns the raw token string (shown to user once).
    /// If scope_service is non-empty, the token is scoped to that IT service.
    /// If mcp_tier is non-empty, the token is an MCP token with the given tier.
    std::expected<std::string, std::string>
    create_token(const std::string& name, const std::string& principal_id, int64_t expires_at = 0,
                 const std::string& scope_service = {}, const std::string& mcp_tier = {});

    /// Validate a raw Bearer token. Returns the ApiToken if valid and not expired/revoked.
    std::optional<ApiToken> validate_token(const std::string& raw_token);

    /// List all tokens (for admin UI). Raw token values are never returned.
    std::vector<ApiToken> list_tokens(const std::string& principal_id = {}) const;

    /// Look up a single token by its short display ID. The raw token and
    /// `token_hash` are NOT populated — only metadata. Used by the REST API
    /// to verify ownership before revoke so a caller with `ApiToken:Delete`
    /// cannot revoke another user's token by guessing its ID.
    std::optional<ApiToken> get_token(const std::string& token_id) const;

    /// Revoke a token by ID.
    bool revoke_token(const std::string& token_id);

    /// Revoke every non-revoked token belonging to a principal. Returns
    /// the number of tokens marked revoked. Used by the session-revocation
    /// REST surface so "Sign out everywhere" actually revokes everywhere
    /// (cookie sessions + API tokens), not just browser cookies. Without
    /// this, a stolen-laptop incident leaves the on-laptop API token
    /// fully functional and the operator UX silently lies.
    std::size_t revoke_for_principal(const std::string& principal_id);

    /// Delete a token permanently.
    bool delete_token(const std::string& token_id);

    /// Cumulative count of validate_token calls served from the in-memory cache.
    /// Exposed for Prometheus scraping; set via gauge in server.cpp's periodic loop.
    uint64_t cache_hits() const noexcept { return cache_hits_.load(std::memory_order_relaxed); }

    /// Cumulative count of validate_token calls that fell through to SQLite.
    uint64_t cache_misses() const noexcept { return cache_misses_.load(std::memory_order_relaxed); }

    /// Current number of distinct tokens cached in memory.
    std::size_t cache_size() const;

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex db_mtx_; // protects all db_ access (G2-SEC-A2-002)

    // LRU cache for validated tokens: token_hash -> (ApiToken, expiry_time)
    struct CachedToken {
        ApiToken token;
        std::chrono::steady_clock::time_point cached_at;
    };
    mutable std::mutex cache_mtx_;
    mutable std::unordered_map<std::string, CachedToken> token_cache_;
    static constexpr auto kTokenCacheTtl = std::chrono::seconds(60);

    // Cache hit/miss counters (atomic, lock-free read for Prometheus scraping).
    mutable std::atomic<uint64_t> cache_hits_{0};
    mutable std::atomic<uint64_t> cache_misses_{0};

    // Defense-in-depth against a cache TOCTOU on revocation. Incremented
    // before every UPDATE in `revoke_token`, `revoke_for_principal`, and
    // `delete_token`. `validate_token` snapshots the value before its DB
    // SELECT and re-reads before the cache write — if it moved, a revoke
    // raced with us and we MUST NOT populate the cache with a stale
    // (revoked=false) view that would survive for `kTokenCacheTtl` (60 s)
    // and silently lie about "Sign out everywhere" success.
    //
    // The current `validate_token` also holds `db_mtx_` exclusively
    // across the SELECT and the cache write, which on its own prevents
    // the interleave. The generation counter is belt-and-suspenders
    // against a future refactor that narrows the `db_mtx_` scope: the
    // explicit acquire/release pairs make the invariant locally
    // verifiable without lock-ordering analysis (HIGH-1 on PR #883).
    std::atomic<uint64_t> revoke_generation_{0};

    void create_tables();
    std::string generate_raw_token() const;
    std::string sha256_hex(const std::string& input) const;
    void invalidate_cache(const std::string& token_hash);
};

} // namespace yuzu::server
