#pragma once

// test_api_token_pg_helper.hpp — shared PG-backed ApiTokenStore construction
// helper for the auth-route test fixtures (test_auth_routes*.cpp,
// test_auth_sso_identity.cpp, test_auth_jit_elevation.cpp, test_saml_routes.cpp,
// test_oidc_routes.cpp, test_schedule_routes.cpp, test_rest_api_tokens.cpp,
// test_mcp_server.cpp).
//
// ApiTokenStore ported to Postgres (PR 4.1, docs/auth-engine-principals-design.md
// §6, schema `api_token_store`): every fixture that used to open it against a
// per-test SQLite temp file now needs a live database. ApiTokenStorePg bundles
// the ephemeral clone database (from a shared "apitoken" PgTestTemplate — one
// migration paid across the whole suite, not per test), the PgPool, and the
// store itself in destruction-safe order, so a fixture's constructor stays a
// one-liner:
//
//     yuzu::test::ApiTokenStorePg api_tokens;
//     ...
//     api_tokens->create_token(...);   // ApiTokenStore* via operator->
//
// Construction SKIPs the current TEST_CASE when YUZU_TEST_POSTGRES_DSN is
// unset, and REQUIREs a working database when it is set but broken — the same
// skip-vs-fail posture as every other [pg] test (see test_helpers.hpp).

#include "api_token_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

namespace yuzu::test {

namespace detail {
inline void setup_api_token_store_pg_template(const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::ApiTokenStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("apitoken template: store failed to migrate");
}
} // namespace detail

/// Process-wide template (one migration run, cloned per fixture) shared by
/// every TU that includes this header — the same "declare a shared key"
/// pattern PgTestTemplate documents (mirrors test_mcp_server.cpp's "swinv"
/// key). An `inline` namespace-scope variable is guaranteed one definition
/// across every including TU (C++17), and PgTestTemplate's own registry is
/// additionally keyed by name — either alone would be enough for dedup.
inline PgTestTemplate apitoken_pg_template{"apitoken",
                                           &detail::setup_api_token_store_pg_template};

/// RAII bundle: ephemeral database + pool + ApiTokenStore, in destruction-safe
/// member order (store closes before the pool, the pool closes before the
/// database is dropped). Behaves like a `std::unique_ptr<ApiTokenStore>` at
/// call sites (`get()`/`operator->`/`operator*`) so existing
/// `api_tokens.get()` / `api_tokens->method()` fixture call sites port
/// unchanged; `reset()` tears down early for fixtures that sequence teardown
/// explicitly before removing their scratch directory.
class ApiTokenStorePg {
public:
    ApiTokenStorePg() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        db_.emplace(apitoken_pg_template);
        INFO("[ApiTokenStorePg] fixture status (blank == database came up OK): " << db_->error());
        REQUIRE(db_->available());
        pool_.emplace(yuzu::server::pg::PgPool::Options{.conninfo = db_->dsn(), .size = 4});
        REQUIRE(pool_->valid());
        store_ = std::make_unique<yuzu::server::ApiTokenStore>(*pool_);
        REQUIRE(store_->is_open());
    }

    ApiTokenStorePg(const ApiTokenStorePg&) = delete;
    ApiTokenStorePg& operator=(const ApiTokenStorePg&) = delete;
    ApiTokenStorePg(ApiTokenStorePg&&) = delete;
    ApiTokenStorePg& operator=(ApiTokenStorePg&&) = delete;

    /// Connection string of the ephemeral database backing this store. Needed by
    /// tests that must act on the store's data from a SECOND connection — e.g.
    /// breaking the schema underneath a live store to exercise the "could not
    /// read" branch, which has no test-only hook on the production store.
    [[nodiscard]] std::string dsn() const { return db_->dsn(); }

    [[nodiscard]] yuzu::server::ApiTokenStore* get() const noexcept { return store_.get(); }
    yuzu::server::ApiTokenStore* operator->() const noexcept { return store_.get(); }
    yuzu::server::ApiTokenStore& operator*() const noexcept { return *store_; }
    explicit operator bool() const noexcept { return store_ != nullptr; }

    /// Tear down early (store, then pool, then database) — mirrors
    /// `std::unique_ptr::reset()` for fixtures that sequence teardown
    /// explicitly.
    void reset() noexcept {
        store_.reset();
        pool_.reset();
        db_.reset();
    }

private:
    std::optional<PostgresTestDb> db_;
    std::optional<yuzu::server::pg::PgPool> pool_;
    std::unique_ptr<yuzu::server::ApiTokenStore> store_;
};

} // namespace yuzu::test
