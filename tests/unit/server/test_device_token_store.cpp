/**
 * test_device_token_store.cpp — `DeviceTokenStore` (device authorization tokens, capability
 * 18.8, ADR-0052).
 *
 * **This store is deliberately DORMANT on `dev`** — nothing in `server.cpp` constructs a
 * `DeviceTokenStore` (see device_token_store.hpp's file header). These tests exercise the
 * store's public API directly, exactly as `test_rest_api_t2.cpp`'s/`test_rest_api_tokens.cpp`'s
 * device-token cases and a future re-wiring do.
 *
 * Covers:
 *  - fail-closed construction, both the migration-drift case (a live but unmigratable database)
 *    and the unreachable-pool case (mirrors test_license_store.cpp's two fail-closed cases).
 *  - create_token validation (empty principal_id) and CSPRNG-shaped errors.
 *  - create/validate round-trip, token shape, CSPRNG uniqueness (256 consecutive tokens).
 *  - validate_token's full rejection ordering: not_found -> revoked -> expired ->
 *    unbound_legacy -> binding_mismatch, and the #1053 rich-rejection context per variant.
 *  - list_tokens (typed reads — ADR-0036), revoke_token, revoke_by_principal (#823).
 *  - migrate_from_sqlite backfill contract (ADR-0009/0052): sourceless-then-holder anti-pattern
 *    regression, IDENTITY-mismatch fail-closed, LIFECYCLE-benign-no-op, the security-relevant
 *    `revoked` asymmetry (legacy-revoked-but-Postgres-active fails closed; the reverse is
 *    benign), malformed token_id/token_hash fail-closed, mid-scan corruption.
 *
 * Migrated-to-Postgres store (ADR-0012 §1, authoritative/fail-hard). PG-gated: skips when
 * YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken (test_helpers.hpp skip-vs-fail
 * contract). Store-behaviour cases use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the two fail-closed cases use YUZU_REQUIRE_PG_DB / no
 * gate at all, per the plain-migration-test carve-out documented on that macro.
 */

#include "device_token_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::DeviceAuthToken;
using yuzu::server::DeviceTokenStore;
using yuzu::server::DeviceTokenValidateError;
using yuzu::server::SqliteDb;
using yuzu::server::SqliteStmt;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// RAII log capture (mirrors test_deployment_store.cpp/test_license_store.cpp) — swaps in an
// ostream-backed logger for its lifetime, restored on scope exit including on an exception. Used
// to assert WHICH branch a production code path took, not just that it failed.
class LogCapture {
public:
    LogCapture() {
        auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(oss_);
        auto logger = std::make_shared<spdlog::logger>("test_device_token_store_capture", sink);
        logger->set_level(spdlog::level::trace);
        prev_logger_ = spdlog::default_logger();
        prev_level_ = spdlog::get_level();
        spdlog::set_default_logger(logger);
        spdlog::set_level(spdlog::level::trace);
    }
    ~LogCapture() {
        spdlog::set_default_logger(prev_logger_);
        spdlog::set_level(prev_level_);
    }
    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;

    [[nodiscard]] std::string str() const { return oss_.str(); }

private:
    std::ostringstream oss_;
    std::shared_ptr<spdlog::logger> prev_logger_;
    spdlog::level::level_enum prev_level_{spdlog::level::info};
};

// Shares the "devicetokenstore" key with test_rest_api_t2.cpp's and test_rest_api_tokens.cpp's
// own templates (identical setup, replay-verified per docs/postgres-store-playbook.md step 7).
yuzu::test::PgTestTemplate device_token_store_tpl{
    "devicetokenstore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        DeviceTokenStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("device_token_store template: store failed to migrate");
    }};

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Legacy-fixture row shape carrying every pre-migration SQLite column, including token_hash
// (the public DeviceAuthToken struct deliberately omits it — it is never re-exposed).
struct LegacyTokenFixture {
    std::string token_id;
    std::string token_hash;
    std::string name;
    std::string principal_id;
    std::string device_id;
    std::string definition_id{};
    int64_t created_at{0};
    int64_t expires_at{0};
    int64_t last_used_at{0};
    bool revoked{false};
};

// 32/64-lowercase-hex fixture ids — deterministic, not CSPRNG-derived (these are TEST fixtures
// standing in for what the pre-migration store's real generate_token_id()/hash_token() would
// have produced). Every byte of a human-readable seed is mapped to a hex digit (rather than
// passed through verbatim) so a seed containing non-hex letters (the 'h'/'s'/etc. in something
// like "holderhash1") still produces valid lowercase-hex output — is_valid_lowercase_hex rejects
// anything else.
std::string to_hex_digits(std::string_view seed) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(seed.size());
    for (unsigned char c : seed)
        out.push_back(kHex[c % 16]);
    return out;
}

std::string hex_id(std::string_view seed) {
    std::string out = to_hex_digits(seed);
    while (out.size() < 32)
        out.push_back('0');
    return out.substr(0, 32);
}

std::string hex_hash(std::string_view seed) {
    std::string out = to_hex_digits(seed);
    while (out.size() < 64)
        out.push_back('1');
    return out.substr(0, 64);
}

void write_legacy_sqlite_db(const std::filesystem::path& path,
                            const std::vector<LegacyTokenFixture>& rows) {
    // SqliteDb (gov cpp-safety BLOCKING, policy floor): a raw sqlite3* with a trailing
    // sqlite3_close(db) leaks on any REQUIRE() failure between open and close.
    SqliteDb db;
    REQUIRE(sqlite3_open(path.string().c_str(), db.addr()) == SQLITE_OK);
    const char* ddl = "CREATE TABLE device_auth_tokens ("
                      "  token_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,"
                      "  name TEXT NOT NULL DEFAULT '', principal_id TEXT NOT NULL,"
                      "  device_id TEXT NOT NULL DEFAULT '', definition_id TEXT NOT NULL "
                      "DEFAULT '',"
                      "  created_at INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL "
                      "DEFAULT 0,"
                      "  last_used_at INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL "
                      "DEFAULT 0);";
    REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, nullptr) == SQLITE_OK);
    for (const auto& r : rows) {
        SqliteStmt s;
        const char* sql =
            "INSERT INTO device_auth_tokens (token_id, token_hash, name, principal_id, "
            "device_id, definition_id, created_at, expires_at, last_used_at, revoked) "
            "VALUES (?,?,?,?,?,?,?,?,?,?);";
        REQUIRE(sqlite3_prepare_v2(db.get(), sql, -1, s.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(s.get(), 1, r.token_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 2, r.token_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 3, r.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 4, r.principal_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 5, r.device_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 6, r.definition_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(s.get(), 7, r.created_at);
        sqlite3_bind_int64(s.get(), 8, r.expires_at);
        sqlite3_bind_int64(s.get(), 9, r.last_used_at);
        sqlite3_bind_int64(s.get(), 10, r.revoked ? 1 : 0);
        REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
    }
}

// `n` deterministic, token_id-ascending fixture rows — %032x/%064x of 1..n, so the caller gets
// rows already in the backfill's own ORDER BY token_id ASC scan order. Extracted from the
// mid-scan-corruption test's original inline 3000-row builder (#3399) so other tests exercising
// multi-batch/large-table behavior can reuse the same shape.
std::vector<LegacyTokenFixture> make_bulk_fixture(int n, std::string_view name_prefix = "bulk-token-") {
    std::vector<LegacyTokenFixture> bulk;
    bulk.reserve(static_cast<std::size_t>(n));
    for (int i = 0; i < n; ++i) {
        LegacyTokenFixture r;
        r.token_id = std::format("{:032x}", i + 1);
        r.token_hash = std::format("{:064x}", i + 1);
        r.name = std::string(name_prefix) + std::to_string(i) +
                "-padding-for-size-xxxxxxxxxxxxxxxxxxxxxx";
        r.principal_id = "admin";
        r.device_id = "device-bulk";
        r.created_at = 1000 + i;
        bulk.push_back(std::move(r));
    }
    return bulk;
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("DeviceTokenStore reports !is_open on a migration failure", "[device_token][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA device_token_store")};
        REQUIRE(s.ok());
        PgResult t{
            PQexec(conn.get(), "CREATE TABLE device_token_store.device_auth_tokens (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    DeviceTokenStore store{pool};
    CHECK_FALSE(store.is_open());
}

TEST_CASE(
    "DeviceTokenStore reports !is_open on an unreachable pool, and every method fails closed",
    "[device_token]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    DeviceTokenStore store{pool};
    CHECK_FALSE(store.is_open());

    auto create_res = store.create_token("n", "admin", "d", "", 0);
    CHECK_FALSE(create_res.has_value());
    CHECK(create_res.error().starts_with(yuzu::server::kDeviceTokenDbErrorPrefix));

    // A closed store collapses to invalid_input, same as an empty raw token — preserved
    // unchanged from the pre-migration store's contract (device_token_store.hpp: "Empty /
    // malformed raw token, or store closed").
    auto validate_res = store.validate_token("ydt_whatever", "d");
    CHECK_FALSE(validate_res.has_value());
    CHECK(validate_res.error().error == DeviceTokenValidateError::invalid_input);

    auto list_res = store.list_tokens();
    CHECK_FALSE(list_res.has_value());
    CHECK(list_res.error().starts_with(yuzu::server::kDeviceTokenDbErrorPrefix));

    auto revoke_res = store.revoke_token("x");
    CHECK_FALSE(revoke_res.has_value());
    CHECK(revoke_res.error().starts_with(yuzu::server::kDeviceTokenDbErrorPrefix));

    auto revoke_by_res = store.revoke_by_principal("alice");
    CHECK_FALSE(revoke_by_res.has_value());
    CHECK(revoke_by_res.error().starts_with(yuzu::server::kDeviceTokenDbErrorPrefix));

    CHECK_FALSE(store.migrate_from_sqlite("/nonexistent/does/not/matter"));
}

// ── Create and Validate ──────────────────────────────────────────────────────

TEST_CASE("create_token rejects an empty principal_id", "[device_token][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_token("n", "", "d", "", 0);
    REQUIRE_FALSE(r.has_value());
    CHECK_FALSE(r.error().starts_with(yuzu::server::kDeviceTokenDbErrorPrefix));
}

TEST_CASE("DeviceTokenStore: create and validate round-trip", "[device_token][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Test Token", "admin", "device-RT", "", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-RT");
    REQUIRE(validated.has_value());
    CHECK(validated->name == "Test Token");
    CHECK(validated->principal_id == "admin");
    CHECK(validated->created_at > 0);
    CHECK(!validated->revoked);
}

TEST_CASE("DeviceTokenStore: token starts with ydt_ prefix", "[device_token][format][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Prefixed Token", "admin", "", "", 0);
    REQUIRE(result.has_value());
    CHECK(result->starts_with("ydt_"));
    CHECK(result->size() == 68); // "ydt_" (4) + 64 hex chars
}

TEST_CASE("DeviceTokenStore: invalid token rejected", "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto validated = store.validate_token("ydt_this_is_not_a_valid_token_abcdef0123456789", "");
    REQUIRE(!validated.has_value());
    CHECK(validated.error().error == DeviceTokenValidateError::not_found);
    CHECK(validated.error().token_id.empty());
    CHECK(validated.error().bound_device_id.empty());
    CHECK(validated.error().bound_principal_id.empty());
}

TEST_CASE("DeviceTokenStore: empty token rejected", "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto validated = store.validate_token("", "");
    REQUIRE(!validated.has_value());
    CHECK(validated.error().error == DeviceTokenValidateError::invalid_input);
    CHECK(validated.error().token_id.empty());
}

TEST_CASE("DeviceTokenStore: expired token rejected", "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Expired Token", "admin", "device-X", "", 1);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-X");
    REQUIRE(!validated.has_value());
    CHECK(validated.error().error == DeviceTokenValidateError::expired);
    CHECK(!validated.error().token_id.empty());
    CHECK(validated.error().bound_device_id == "device-X");
    CHECK(validated.error().bound_principal_id == "admin");
}

TEST_CASE("DeviceTokenStore: revoked token rejected", "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("Revocable", "admin", "device-R", "", 0);
    REQUIRE(raw.has_value());

    auto valid1 = store.validate_token(*raw, "device-R");
    REQUIRE(valid1.has_value());

    auto revoked = store.revoke_token(valid1->token_id);
    CHECK(revoked.has_value());

    auto valid2 = store.validate_token(*raw, "device-R");
    REQUIRE(!valid2.has_value());
    CHECK(valid2.error().error == DeviceTokenValidateError::revoked);
    CHECK(valid2.error().bound_device_id == "device-R");
    CHECK(valid2.error().bound_principal_id == "admin");
}

// ── List ──────────────────────────────────────────────────────────────────────

TEST_CASE("DeviceTokenStore: list tokens", "[device_token][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create_token("Token A", "alice", "", "", 0).has_value());
    REQUIRE(store.create_token("Token B", "alice", "", "", 0).has_value());
    REQUIRE(store.create_token("Token C", "bob", "", "", 0).has_value());

    auto all = store.list_tokens();
    REQUIRE(all.has_value());
    CHECK(all->size() == 3);
}

TEST_CASE("DeviceTokenStore: list tokens with principal_id filter", "[device_token][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create_token("Token A", "alice", "", "", 0).has_value());
    REQUIRE(store.create_token("Token B", "alice", "", "", 0).has_value());
    REQUIRE(store.create_token("Token C", "bob", "", "", 0).has_value());

    auto alice_tokens = store.list_tokens("alice");
    REQUIRE(alice_tokens.has_value());
    CHECK(alice_tokens->size() == 2);
    for (const auto& t : *alice_tokens)
        CHECK(t.principal_id == "alice");

    auto bob_tokens = store.list_tokens("bob");
    REQUIRE(bob_tokens.has_value());
    CHECK(bob_tokens->size() == 1);
    CHECK((*bob_tokens)[0].principal_id == "bob");
}

// ── Revoke edge cases ─────────────────────────────────────────────────────────

TEST_CASE("DeviceTokenStore: revoke non-existent is not_found", "[device_token][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto revoked = store.revoke_token("nonexistent-token-id");
    REQUIRE_FALSE(revoked.has_value());
    CHECK(revoked.error().starts_with("not_found:"));
}

// ── W1.5 / #823 — revoke_by_principal ────────────────────────────────────────

TEST_CASE("DeviceTokenStore: revoke_by_principal revokes every still-valid token for the "
          "principal",
          "[device_token][823][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto a1 = store.create_token("alice-1", "alice", "device-A1", "", 0);
    auto a2 = store.create_token("alice-2", "alice", "device-A2", "", 0);
    auto b1 = store.create_token("bob-1", "bob", "device-B1", "", 0);
    REQUIRE(a1.has_value());
    REQUIRE(a2.has_value());
    REQUIRE(b1.has_value());

    REQUIRE(store.validate_token(*a1, "device-A1").has_value());
    REQUIRE(store.validate_token(*a2, "device-A2").has_value());
    REQUIRE(store.validate_token(*b1, "device-B1").has_value());

    auto revoked = store.revoke_by_principal("alice");
    REQUIRE(revoked.has_value());
    CHECK(*revoked == 2);

    auto v1 = store.validate_token(*a1, "device-A1");
    REQUIRE(!v1.has_value());
    CHECK(v1.error().error == DeviceTokenValidateError::revoked);

    auto v2 = store.validate_token(*a2, "device-A2");
    REQUIRE(!v2.has_value());
    CHECK(v2.error().error == DeviceTokenValidateError::revoked);

    auto v3 = store.validate_token(*b1, "device-B1");
    REQUIRE(v3.has_value());
}

TEST_CASE("DeviceTokenStore: revoke_by_principal is idempotent and skips already-revoked rows",
          "[device_token][823][crud][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto t = store.create_token("only", "alice", "device-A", "", 0);
    REQUIRE(t.has_value());

    auto first = store.revoke_by_principal("alice");
    REQUIRE(first.has_value());
    CHECK(*first == 1);
    auto second = store.revoke_by_principal("alice");
    REQUIRE(second.has_value());
    CHECK(*second == 0);

    auto nobody = store.revoke_by_principal("nobody");
    REQUIRE(nobody.has_value());
    CHECK(*nobody == 0);

    // Empty principal is rejected at the wrapper — must not match historical rows that happen to
    // have an empty principal_id.
    auto empty = store.revoke_by_principal("");
    REQUIRE(empty.has_value());
    CHECK(*empty == 0);
}

// ── Validate updates last_used_at ────────────────────────────────────────────

TEST_CASE("DeviceTokenStore: validate updates last_used_at", "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("Usage Token", "admin", "device-U", "", 0);
    REQUIRE(raw.has_value());

    auto before = store.list_tokens();
    REQUIRE(before.has_value());
    REQUIRE(before->size() == 1);
    CHECK((*before)[0].last_used_at == 0);

    auto validated = store.validate_token(*raw, "device-U");
    REQUIRE(validated.has_value());

    auto after = store.list_tokens();
    REQUIRE(after.has_value());
    REQUIRE(after->size() == 1);
    CHECK((*after)[0].last_used_at > 0);
}

// ── Scope fields ──────────────────────────────────────────────────────────────

TEST_CASE("DeviceTokenStore: device scope stored correctly", "[device_token][scope][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Scoped Token", "admin", "device-42", "", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-42");
    REQUIRE(validated.has_value());
    CHECK(validated->device_id == "device-42");
    CHECK(validated->definition_id.empty());
}

TEST_CASE("DeviceTokenStore: definition scope stored correctly", "[device_token][scope][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Def Scoped Token", "admin", "device-D", "get-os-info", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-D");
    REQUIRE(validated.has_value());
    CHECK(validated->device_id == "device-D");
    CHECK(validated->definition_id == "get-os-info");
}

TEST_CASE("DeviceTokenStore: both scopes stored correctly", "[device_token][scope][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result =
        store.create_token("Dual Scoped Token", "admin", "device-99", "restart-service", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-99");
    REQUIRE(validated.has_value());
    CHECK(validated->device_id == "device-99");
    CHECK(validated->definition_id == "restart-service");
}

// ── Expiration edge cases ────────────────────────────────────────────────────

TEST_CASE("DeviceTokenStore: non-expiring token (expires_at=0) is valid",
          "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Perpetual Token", "admin", "device-P", "", 0);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-P");
    REQUIRE(validated.has_value());
    CHECK(validated->expires_at == 0);
}

TEST_CASE("DeviceTokenStore: future expiry token is valid", "[device_token][auth][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto future = now_epoch() + 86400 * 365; // 1 year from now
    auto result = store.create_token("Future Token", "admin", "device-F", "", future);
    REQUIRE(result.has_value());

    auto validated = store.validate_token(*result, "device-F");
    REQUIRE(validated.has_value());
    CHECK(validated->expires_at == future);
}

// ── Binding enforcement (#824) — token presenter MUST equal token subject ──────

TEST_CASE("DeviceTokenStore: device-bound token accepted from matching presenter",
          "[device_token][binding][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("Bound", "admin", "device-A", "", 0);
    REQUIRE(raw.has_value());

    auto ok = store.validate_token(*raw, "device-A");
    REQUIRE(ok.has_value());
    CHECK(ok->device_id == "device-A");
}

TEST_CASE("DeviceTokenStore: device-bound token rejected from different presenter",
          "[device_token][binding][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("Bound", "admin", "device-A", "", 0);
    REQUIRE(raw.has_value());

    auto bad = store.validate_token(*raw, "device-B");
    REQUIRE(!bad.has_value());
    CHECK(bad.error().error == DeviceTokenValidateError::binding_mismatch);
    CHECK(bad.error().bound_device_id == "device-A");
    CHECK(bad.error().bound_principal_id == "admin");
    CHECK(!bad.error().token_id.empty());
}

TEST_CASE("DeviceTokenStore: device-bound token rejected when presenter empty",
          "[device_token][binding][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("Bound", "admin", "device-A", "", 0);
    REQUIRE(raw.has_value());

    auto bad = store.validate_token(*raw, "");
    REQUIRE(!bad.has_value());
    CHECK(bad.error().error == DeviceTokenValidateError::binding_mismatch);
    CHECK(bad.error().bound_device_id == "device-A");
    CHECK(bad.error().bound_principal_id == "admin");
}

TEST_CASE(
    "DeviceTokenStore: validate_token rejects unbound legacy token with unbound_legacy variant",
    "[device_token][binding][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("LegacyAny", "admin", "", "", 0);
    REQUIRE(raw.has_value());

    auto e = store.validate_token(*raw, "");
    REQUIRE(!e.has_value());
    CHECK(e.error().error == DeviceTokenValidateError::unbound_legacy);
    CHECK(e.error().bound_device_id.empty());
    CHECK(e.error().bound_principal_id == "admin");
    CHECK(!e.error().token_id.empty());

    auto a = store.validate_token(*raw, "device-A");
    REQUIRE(!a.has_value());
    CHECK(a.error().error == DeviceTokenValidateError::unbound_legacy);

    auto b = store.validate_token(*raw, "device-B");
    REQUIRE(!b.has_value());
    CHECK(b.error().error == DeviceTokenValidateError::unbound_legacy);
}

TEST_CASE("DeviceTokenStore: validate_token unbound_legacy precedes binding_mismatch and follows "
          "expired",
          "[device_token][binding][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto expired_raw = store.create_token("ExpiredLegacy", "admin", "", "", 1);
    REQUIRE(expired_raw.has_value());
    auto exp = store.validate_token(*expired_raw, "anything");
    REQUIRE(!exp.has_value());
    CHECK(exp.error().error == DeviceTokenValidateError::expired);

    auto legacy_raw = store.create_token("Legacy", "admin", "", "", 0);
    REQUIRE(legacy_raw.has_value());
    auto leg = store.validate_token(*legacy_raw, "device-X");
    REQUIRE(!leg.has_value());
    CHECK(leg.error().error == DeviceTokenValidateError::unbound_legacy);
}

TEST_CASE("DeviceTokenStore: binding_mismatch precedes neither expired nor revoked",
          "[device_token][binding][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("ExpiredBound", "admin", "device-A", "", 1);
    REQUIRE(raw.has_value());

    auto exp_ok = store.validate_token(*raw, "device-A");
    REQUIRE(!exp_ok.has_value());
    CHECK(exp_ok.error().error == DeviceTokenValidateError::expired);
    auto exp_bad = store.validate_token(*raw, "device-B");
    REQUIRE(!exp_bad.has_value());
    CHECK(exp_bad.error().error == DeviceTokenValidateError::expired);
}

// ── CSPRNG contract (#801) ────────────────────────────────────────────────────

TEST_CASE("DeviceTokenStore: consecutive tokens differ", "[device_token][csprng][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto a = store.create_token("A", "admin", "", "", 0);
    auto b = store.create_token("B", "admin", "", "", 0);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    CHECK(*a != *b);
}

TEST_CASE("DeviceTokenStore: 256 consecutive tokens are all unique", "[device_token][csprng][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    std::set<std::string> seen;
    for (int i = 0; i < 256; ++i) {
        auto r = store.create_token("bulk", "admin", "", "", 0);
        REQUIRE(r.has_value());
        CHECK(seen.insert(*r).second);
    }
    CHECK(seen.size() == 256);
}

TEST_CASE("DeviceTokenStore: token shape — 'ydt_' + 64 lowercase hex chars",
          "[device_token][csprng][format][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_token("Shape", "admin", "", "", 0);
    REQUIRE(r.has_value());
    REQUIRE(r->size() == 68);
    CHECK(r->starts_with("ydt_"));
    for (std::size_t i = 4; i < r->size(); ++i) {
        char c = (*r)[i];
        CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
    }
}

// ── Backfill (ADR-0009/0052) ─────────────────────────────────────────────────

TEST_CASE("migrate_from_sqlite: no legacy file stamps the sourceless marker, idempotently",
          "[device_token][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto missing =
        yuzu::test::unique_temp_path("yuzu_test_devtoken_missing") / "device-tokens.db";
    CHECK(store.migrate_from_sqlite(missing));
    CHECK(store.migrate_from_sqlite(missing)); // second call is a no-op success
}

// Regression test for the anti-pattern docs/postgres-store-playbook.md's "Local source absence
// never creates terminal migration state on its own" documents: a fileless replica's boot must
// never permanently block a later, DIFFERENT holder replica's real legacy data.
TEST_CASE("migrate_from_sqlite: a sourceless boot never blocks a later boot's real legacy data",
          "[device_token][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto missing_path =
        yuzu::test::unique_temp_path("yuzu_test_devtoken_sourceless") / "device-tokens.db";
    REQUIRE(store.migrate_from_sqlite(missing_path));

    LegacyTokenFixture legacy;
    legacy.token_id = hex_id("holder1");
    legacy.token_hash = hex_hash("holderhash1");
    legacy.name = "holder-token";
    legacy.principal_id = "admin";
    legacy.device_id = "holder-device";
    legacy.created_at = 5000;
    auto holder_path =
        yuzu::test::unique_temp_path("yuzu_test_devtoken_holder") / "device-tokens.db";
    std::filesystem::create_directories(holder_path.parent_path());
    write_legacy_sqlite_db(holder_path, {legacy});

    REQUIRE(store.migrate_from_sqlite(holder_path));

    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    CHECK(tokens->size() == 1);
    CHECK((*tokens)[0].name == "holder-token");

    // A third boot against the SAME holder file is a no-op — its fingerprint is now recorded —
    // but does not duplicate the row.
    REQUIRE(store.migrate_from_sqlite(holder_path));
    auto tokens2 = store.list_tokens();
    REQUIRE(tokens2.has_value());
    CHECK(tokens2->size() == 1);
}

TEST_CASE("migrate_from_sqlite copies a populated legacy file exactly once",
          "[device_token][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    LegacyTokenFixture t1;
    t1.token_id = hex_id("aaa1");
    t1.token_hash = hex_hash("aaahash1");
    t1.name = "first";
    t1.principal_id = "alice";
    t1.device_id = "device-A";
    t1.created_at = 100;
    t1.expires_at = 0;

    LegacyTokenFixture t2;
    t2.token_id = hex_id("bbb2");
    t2.token_hash = hex_hash("bbbhash2");
    t2.name = "second";
    t2.principal_id = "bob";
    t2.device_id = "";
    t2.definition_id = "get-os-info";
    t2.created_at = 200;
    t2.revoked = true;
    t2.last_used_at = 250;

    auto path = yuzu::test::unique_temp_path("yuzu_test_devtoken_populated") / "device-tokens.db";
    std::filesystem::create_directories(path.parent_path());
    write_legacy_sqlite_db(path, {t1, t2});

    REQUIRE(store.migrate_from_sqlite(path));
    REQUIRE(store.migrate_from_sqlite(path)); // idempotent, same fingerprint

    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    CHECK(tokens->size() == 2);

    for (const auto& t : *tokens) {
        if (t.token_id == t1.token_id) {
            CHECK(t.name == "first");
            CHECK(t.principal_id == "alice");
            CHECK(t.device_id == "device-A");
            CHECK_FALSE(t.revoked);
        } else if (t.token_id == t2.token_id) {
            CHECK(t.name == "second");
            CHECK(t.definition_id == "get-os-info");
            CHECK(t.revoked);
            CHECK(t.last_used_at == 250);
        } else {
            FAIL("unexpected token_id in backfilled result: " << t.token_id);
        }
    }
}

TEST_CASE("migrate_from_sqlite fails closed when a legacy row's token_id already exists with "
          "DIFFERENT identity",
          "[device_token][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    const std::string shared_id = hex_id("shared1");

    LegacyTokenFixture first;
    first.token_id = shared_id;
    first.token_hash = hex_hash("firsthash");
    first.name = "first-name";
    first.principal_id = "alice";
    first.device_id = "device-A";
    first.created_at = 100;

    auto path1 = yuzu::test::unique_temp_path("yuzu_test_devtoken_conflict1") / "device-tokens.db";
    std::filesystem::create_directories(path1.parent_path());
    write_legacy_sqlite_db(path1, {first});
    REQUIRE(store.migrate_from_sqlite(path1));

    // Same token_id, DIFFERENT identity column (name) — a different legacy snapshot sharing an
    // id by construction (e.g. a cloned data directory independently mutated).
    LegacyTokenFixture conflicting = first;
    conflicting.name = "different-name";

    auto path2 = yuzu::test::unique_temp_path("yuzu_test_devtoken_conflict2") / "device-tokens.db";
    std::filesystem::create_directories(path2.parent_path());
    write_legacy_sqlite_db(path2, {conflicting});

    CHECK_FALSE(store.migrate_from_sqlite(path2));

    // The original row is untouched — no partial/incorrect overwrite.
    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    REQUIRE(tokens->size() == 1);
    CHECK((*tokens)[0].name == "first-name");
}

TEST_CASE("migrate_from_sqlite treats an identical-content token_id conflict as a benign no-op",
          "[device_token][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    LegacyTokenFixture shared;
    shared.token_id = hex_id("ident1");
    shared.token_hash = hex_hash("identhash1");
    shared.name = "same";
    shared.principal_id = "alice";
    shared.device_id = "device-A";
    shared.created_at = 100;

    auto path1 = yuzu::test::unique_temp_path("yuzu_test_devtoken_ident1") / "device-tokens.db";
    std::filesystem::create_directories(path1.parent_path());
    write_legacy_sqlite_db(path1, {shared});
    REQUIRE(store.migrate_from_sqlite(path1));

    // A SECOND, larger legacy file: the SAME shared row (byte-identical) plus one genuinely NEW
    // row. Different overall file content means a different fingerprint, so this is not
    // short-circuited by the marker check — it must reach the per-row conflict path for `shared`
    // and correctly treat it as benign (mirrors test_deployment_store.cpp's identical precedent).
    LegacyTokenFixture new_row;
    new_row.token_id = hex_id("ident2new");
    new_row.token_hash = hex_hash("identhash2new");
    new_row.name = "sibling";
    new_row.principal_id = "alice";
    new_row.device_id = "device-B";
    new_row.created_at = 101;

    auto path2 = yuzu::test::unique_temp_path("yuzu_test_devtoken_ident2") / "device-tokens.db";
    std::filesystem::create_directories(path2.parent_path());
    write_legacy_sqlite_db(path2, {shared, new_row});

    CHECK(store.migrate_from_sqlite(path2));

    // Both rows present: the identical-content conflict did not abort the pass, and the
    // genuinely new sibling row landed too.
    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    CHECK(tokens->size() == 2);
}

TEST_CASE("migrate_from_sqlite treats a last_used_at-only LIFECYCLE difference as a benign "
          "no-op regardless of direction",
          "[device_token][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    LegacyTokenFixture row;
    row.token_id = hex_id("lc1");
    row.token_hash = hex_hash("lchash1");
    row.name = "usage-drift";
    row.principal_id = "alice";
    row.device_id = "device-A";
    row.created_at = 100;
    row.last_used_at = 500; // "ahead" of what Postgres will hold after the first backfill

    auto path1 = yuzu::test::unique_temp_path("yuzu_test_devtoken_lc1") / "device-tokens.db";
    std::filesystem::create_directories(path1.parent_path());
    write_legacy_sqlite_db(path1, {row});
    REQUIRE(store.migrate_from_sqlite(path1));

    // A second legacy snapshot reporting a HIGHER last_used_at is still benign — bookkeeping,
    // not authorization state — and must not fail the backfill closed.
    LegacyTokenFixture ahead = row;
    ahead.last_used_at = 9999;
    auto path2 = yuzu::test::unique_temp_path("yuzu_test_devtoken_lc2") / "device-tokens.db";
    std::filesystem::create_directories(path2.parent_path());
    write_legacy_sqlite_db(path2, {ahead});

    CHECK(store.migrate_from_sqlite(path2));

    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    REQUIRE(tokens->size() == 1);
    // Postgres's value is kept — the backfill never updates an existing row.
    CHECK((*tokens)[0].last_used_at == 500);
}

// ── ADR-0052 security-relevant asymmetry: `revoked` ──────────────────────────

TEST_CASE("migrate_from_sqlite fails closed when a legacy row was REVOKED but Postgres's "
          "current row is still active",
          "[device_token][pg][backfill][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    LegacyTokenFixture row;
    row.token_id = hex_id("rev1");
    row.token_hash = hex_hash("revhash1");
    row.name = "will-be-revoked";
    row.principal_id = "alice";
    row.device_id = "device-A";
    row.created_at = 100;
    row.revoked = false;

    auto path1 = yuzu::test::unique_temp_path("yuzu_test_devtoken_rev1") / "device-tokens.db";
    std::filesystem::create_directories(path1.parent_path());
    write_legacy_sqlite_db(path1, {row});
    REQUIRE(store.migrate_from_sqlite(path1));

    // A second legacy snapshot shows the SAME token now revoked — evidence Postgres does not
    // have. Silently keeping Postgres's stale "still active" value would resurrect a credential
    // the operator explicitly killed (ADR-0052) — this MUST fail the backfill closed, never a
    // benign warn-and-keep.
    LegacyTokenFixture revoked_snapshot = row;
    revoked_snapshot.revoked = true;
    revoked_snapshot.last_used_at = 900;
    auto path2 = yuzu::test::unique_temp_path("yuzu_test_devtoken_rev2") / "device-tokens.db";
    std::filesystem::create_directories(path2.parent_path());
    write_legacy_sqlite_db(path2, {revoked_snapshot});

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(path2));
        captured = capture.str();
    }
    CHECK(captured.find("was REVOKED in the legacy snapshot but Postgres's current row is "
                        "still active") != std::string::npos);

    // Postgres's row is untouched — still active, not silently flipped either way.
    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    REQUIRE(tokens->size() == 1);
    CHECK_FALSE((*tokens)[0].revoked);
}

TEST_CASE("migrate_from_sqlite treats Postgres-already-revoked-but-legacy-still-active as a "
          "benign no-op (the safe LIFECYCLE direction)",
          "[device_token][pg][backfill][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    LegacyTokenFixture row;
    row.token_id = hex_id("rev3");
    row.token_hash = hex_hash("revhash3");
    row.name = "revoked-in-pg";
    row.principal_id = "alice";
    row.device_id = "device-A";
    row.created_at = 100;
    row.revoked = false;

    auto path1 = yuzu::test::unique_temp_path("yuzu_test_devtoken_rev3") / "device-tokens.db";
    std::filesystem::create_directories(path1.parent_path());
    write_legacy_sqlite_db(path1, {row});
    REQUIRE(store.migrate_from_sqlite(path1));

    // Operator revokes the token directly against Postgres (simulating a live operator action
    // between two backfill passes on this same replica).
    auto tokens_before = store.list_tokens();
    REQUIRE(tokens_before.has_value());
    REQUIRE(tokens_before->size() == 1);
    auto revoke_res = store.revoke_token((*tokens_before)[0].token_id);
    REQUIRE(revoke_res.has_value());

    // A second, older legacy snapshot still shows the token active — Postgres is strictly ahead
    // (monotone: revoked never regresses to active), so this is safe and must be a benign no-op.
    auto path2 = yuzu::test::unique_temp_path("yuzu_test_devtoken_rev4") / "device-tokens.db";
    std::filesystem::create_directories(path2.parent_path());
    write_legacy_sqlite_db(path2, {row});

    CHECK(store.migrate_from_sqlite(path2));

    auto tokens_after = store.list_tokens();
    REQUIRE(tokens_after.has_value());
    REQUIRE(tokens_after->size() == 1);
    CHECK((*tokens_after)[0].revoked); // still revoked — never silently un-revoked
}

TEST_CASE("migrate_from_sqlite fails closed on a legacy row with a malformed token_id or "
          "token_hash",
          "[device_token][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    SECTION("token_id wrong length") {
        LegacyTokenFixture row;
        row.token_id = "not-32-hex-chars";
        row.token_hash = hex_hash("validhash");
        row.name = "bad";
        row.principal_id = "alice";
        row.device_id = "device-A";
        auto path = yuzu::test::unique_temp_path("yuzu_test_devtoken_badid") / "device-tokens.db";
        std::filesystem::create_directories(path.parent_path());
        write_legacy_sqlite_db(path, {row});
        CHECK_FALSE(store.migrate_from_sqlite(path));
    }

    SECTION("token_hash contains an uppercase/non-hex character") {
        LegacyTokenFixture row;
        row.token_id = hex_id("badhash1");
        row.token_hash = "ZZ" + hex_hash("mostlyvalid").substr(2);
        row.name = "bad";
        row.principal_id = "alice";
        row.device_id = "device-A";
        auto path =
            yuzu::test::unique_temp_path("yuzu_test_devtoken_badhash") / "device-tokens.db";
        std::filesystem::create_directories(path.parent_path());
        write_legacy_sqlite_db(path, {row});
        CHECK_FALSE(store.migrate_from_sqlite(path));
    }

    // Neither malformed row was stamped complete or partially inserted.
    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    CHECK(tokens->empty());
}

TEST_CASE("migrate_from_sqlite aborts unstamped on a mid-scan legacy read failure",
          "[device_token][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_devtoken_truncated") / "device-tokens.db";
    std::filesystem::create_directories(legacy_path.parent_path());

    std::vector<LegacyTokenFixture> bulk = make_bulk_fixture(3000);
    write_legacy_sqlite_db(legacy_path, bulk);

    auto full_size = std::filesystem::file_size(legacy_path);
    REQUIRE(full_size > 65536); // sanity: spans many SQLite pages

    // Corrupt a LATER region IN PLACE (same file length — no truncation), same technique as
    // test_deployment_store.cpp's mid-scan corruption test: lets prepare/schema-probe succeed
    // and several rows land via SQLITE_ROW before the cursor reaches the corrupted page.
    {
        std::fstream f(legacy_path, std::ios::in | std::ios::out | std::ios::binary);
        REQUIRE(f.is_open());
        const auto corrupt_at = static_cast<std::streamoff>(full_size * 3 / 4);
        f.seekp(corrupt_at);
        std::vector<char> garbage(4096, '\xff');
        f.write(garbage.data(), static_cast<std::streamsize>(garbage.size()));
        REQUIRE(f.good());
    }

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(legacy_path));
        captured = capture.str();
    }
    CHECK(captured.find("scan aborted mid-read") != std::string::npos);
    CHECK(captured.find("legacy device_auth_tokens query failed") == std::string::npos);

    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    CHECK(tokens->empty());

    // A subsequent migrate_from_sqlite against a freshly-written, INTACT file succeeds — proving
    // the aborted pass never stamped the marker.
    auto intact_path =
        yuzu::test::unique_temp_path("yuzu_test_devtoken_intact") / "device-tokens.db";
    std::filesystem::create_directories(intact_path.parent_path());
    write_legacy_sqlite_db(intact_path, {bulk.front()});
    REQUIRE(store.migrate_from_sqlite(intact_path));

    auto tokens2 = store.list_tokens();
    REQUIRE(tokens2.has_value());
    CHECK(tokens2->size() == 1);
}

// ── #3399: v1 fingerprint stability (golden pin) ─────────────────────────────
//
// Pins the v1 canonical-fingerprint algorithm (sha256_hex(canonicalize_legacy_tokens(...)))
// against a hardcoded digest, computed independently in Python from the same
// length-prefixed-field / sorted-encoded-rows / "device-token-legacy-fingerprint-v1\n"-prefixed
// scheme documented above migrate_from_sqlite. Exists so a future streaming rewrite of the
// fingerprint computation (#3399) can be proven byte-identical to this value rather than merely
// "still self-consistent" — a regression that silently changed the algorithm would still pass
// every other backfill test (they never compare against an external oracle) but would orphan
// every already-stamped marker in the field. Row order is deliberately NOT sorted-by-token_id in
// the fixture, to prove the fingerprint does not depend on legacy scan/insertion order (the
// canonicalizer's own std::sort — or an equivalent streaming digest fed in a different order,
// since sorted-encoded order equals token_id-ASC scan order — is what makes that true).
TEST_CASE("migrate_from_sqlite: v1 fingerprint is stable and independent of legacy row order",
          "[device_token][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    // token_id/token_hash are hand-written %032x/%064x of 1..3 (NOT the seed-mapped hex_id()/
    // hex_hash() helpers) so the fixture matches the independently-computed Python oracle exactly.
    LegacyTokenFixture c;
    c.token_id = "00000000000000000000000000000003";
    c.token_hash = "0000000000000000000000000000000000000000000000000000000000000003";
    c.name = "fp-c";
    c.principal_id = "alice";
    c.device_id = "dev-c";
    c.created_at = 300;

    LegacyTokenFixture a;
    a.token_id = "00000000000000000000000000000001";
    a.token_hash = "0000000000000000000000000000000000000000000000000000000000000001";
    a.name = "fp-a";
    a.principal_id = "alice";
    a.device_id = "dev-a";
    a.created_at = 100;

    LegacyTokenFixture b;
    b.token_id = "00000000000000000000000000000002";
    b.token_hash = "0000000000000000000000000000000000000000000000000000000000000002";
    b.name = "fp-b";
    b.principal_id = "bob";
    b.device_id = "dev-b";
    b.definition_id = "def-b";
    b.created_at = 200;
    b.expires_at = 999;
    b.last_used_at = 150;
    b.revoked = true;

    constexpr const char* kExpectedFingerprint =
        "98e611043d8a361bd017c3e00abec456b16986229e9830c159d9ee7aea01df6f";

    // Written in insertion order [c, a, b] — deliberately not token_id-ascending.
    auto path1 = yuzu::test::unique_temp_path("yuzu_test_devtoken_fpgolden1") / "device-tokens.db";
    std::filesystem::create_directories(path1.parent_path());
    write_legacy_sqlite_db(path1, {c, a, b});
    REQUIRE(store.migrate_from_sqlite(path1));

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(),
                          "SELECT fingerprint FROM device_token_store.sqlite_backfill_source")};
        REQUIRE(r.ok());
        REQUIRE(PQntuples(r.get()) == 1);
        CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == kExpectedFingerprint);
    }

    // A second file holding the SAME three rows in a DIFFERENT insertion order [b, c, a] produces
    // the SAME fingerprint, so this second call is a marker-skip, not a re-insert.
    auto path2 = yuzu::test::unique_temp_path("yuzu_test_devtoken_fpgolden2") / "device-tokens.db";
    std::filesystem::create_directories(path2.parent_path());
    write_legacy_sqlite_db(path2, {b, c, a});

    std::string captured;
    {
        LogCapture capture;
        REQUIRE(store.migrate_from_sqlite(path2));
        captured = capture.str();
    }
    CHECK(captured.find("fingerprint already processed, skipping") != std::string::npos);

    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    CHECK(tokens->size() == 3);
}

// ── #3399: multi-batch rollback fault injection ──────────────────────────────
//
// The "N rows committed within the transaction, row N+1 fails, ALL N must roll back" path was
// untested before #3399: every existing fail-closed fixture above is either single-row or aborts
// during the SQLITE SCAN itself, before the Postgres transaction is ever entered. This test
// poisons the LAST row of a 3000-row fixture (well over kBackfillBatchRows, an anon-namespace
// constant this test file cannot name directly) via a Postgres trigger, so several batch INSERT
// statements succeed inside the (still-open) transaction before the poisoned final batch raises —
// proving the whole transaction rolls back to zero rows and zero markers, not merely that one
// statement fails.
TEST_CASE("migrate_from_sqlite rolls back every batch when a later row fails, leaves no marker, "
          "and the same file retries cleanly",
          "[device_token][pg][backfill]") {
    // DDL fault injection is deliberately isolated (own PgTestTemplate clone, not the shared
    // fixture): the trigger is dropped at the end of this test, but a randomized/filtered run
    // that skipped the drop would otherwise leak it onto a shared database.
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    auto bulk = make_bulk_fixture(3000, "rollback-");
    const std::string poison_id = bulk.back().token_id;

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        // Predicate on the RAW token_id (never sanitize_pg_text'd) — matches what the batch
        // INSERT actually binds for that column.
        const std::string create_fn =
            "CREATE FUNCTION device_token_store.yuzu_test_fault() RETURNS trigger "
            "LANGUAGE plpgsql AS $fn$ BEGIN IF NEW.token_id = '" +
            poison_id +
            "' THEN RAISE EXCEPTION 'injected fault'; END IF; RETURN NEW; END $fn$";
        PgResult fn{PQexec(conn.get(), create_fn.c_str())};
        REQUIRE(fn.ok());
        PgResult trg{PQexec(conn.get(),
                            "CREATE TRIGGER yuzu_test_fault_trg BEFORE INSERT ON "
                            "device_token_store.device_auth_tokens FOR EACH ROW EXECUTE "
                            "FUNCTION device_token_store.yuzu_test_fault()")};
        REQUIRE(trg.ok());
    }

    auto path = yuzu::test::unique_temp_path("yuzu_test_devtoken_rollback") / "device-tokens.db";
    std::filesystem::create_directories(path.parent_path());
    write_legacy_sqlite_db(path, bulk);

    std::string captured;
    {
        LogCapture capture;
        CHECK_FALSE(store.migrate_from_sqlite(path));
        captured = capture.str();
    }
    CHECK(captured.find("batch insert of") != std::string::npos);
    CHECK(captured.find("rolled back") != std::string::npos);
    CHECK(captured.find("marker was NOT stamped") != std::string::npos);

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult counts{PQexec(
            conn.get(), "SELECT (SELECT COUNT(*) FROM device_token_store.device_auth_tokens), "
                       "(SELECT COUNT(*) FROM device_token_store.sqlite_backfill_source)")};
        REQUIRE(counts.ok());
        REQUIRE(PQntuples(counts.get()) == 1);
        CHECK(std::string(PQgetvalue(counts.get(), 0, 0)) == "0");
        CHECK(std::string(PQgetvalue(counts.get(), 0, 1)) == "0");

        PgResult drop_trg{PQexec(conn.get(), "DROP TRIGGER yuzu_test_fault_trg ON "
                                             "device_token_store.device_auth_tokens")};
        REQUIRE(drop_trg.ok());
        PgResult drop_fn{
            PQexec(conn.get(), "DROP FUNCTION device_token_store.yuzu_test_fault()")};
        REQUIRE(drop_fn.ok());
    }

    // Same file, same fingerprint — the marker was never stamped, so this retries the whole
    // backfill and now succeeds (the trigger is gone).
    REQUIRE(store.migrate_from_sqlite(path));
    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    CHECK(tokens->size() == 3000);
}

// ── #3399: batched restructuring regression guard (lambda-false path) ───────
//
// Distinct from the trigger-based test above (a STATEMENT-level Postgres error): here the batch
// INSERT statement itself SUCCEEDS — `ON CONFLICT (token_id) DO NOTHING` silently skips the
// conflicting row within that one statement, so the genuinely-new sibling row in the SAME batch
// is inserted cleanly — and the failure is detected AFTERWARD, when flush_batch's post-statement
// loop calls check_conflict() on the row `unnest`'s RETURNING didn't cover. Proves the
// batch->conflict-set->read-back restructuring still rolls back a row that was, moment to moment,
// successfully inserted within the (still-open) transaction.
TEST_CASE("migrate_from_sqlite rolls back a same-batch sibling row when another row in the batch "
          "conflicts with different IDENTITY",
          "[device_token][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    LegacyTokenFixture first;
    first.token_id = hex_id("batchconflict1");
    first.token_hash = hex_hash("batchconflict1hash");
    first.name = "first-name";
    first.principal_id = "alice";
    first.device_id = "device-A";
    first.created_at = 100;

    auto path1 =
        yuzu::test::unique_temp_path("yuzu_test_devtoken_batchconflict1") / "device-tokens.db";
    std::filesystem::create_directories(path1.parent_path());
    write_legacy_sqlite_db(path1, {first});
    REQUIRE(store.migrate_from_sqlite(path1));

    LegacyTokenFixture new_row;
    new_row.token_id = hex_id("batchconflictnew");
    new_row.token_hash = hex_hash("batchconflictnewhash");
    new_row.name = "sibling";
    new_row.principal_id = "alice";
    new_row.device_id = "device-B";
    new_row.created_at = 101;

    LegacyTokenFixture conflicting = first;
    conflicting.name = "different-name";

    auto path2 =
        yuzu::test::unique_temp_path("yuzu_test_devtoken_batchconflict2") / "device-tokens.db";
    std::filesystem::create_directories(path2.parent_path());
    write_legacy_sqlite_db(path2, {new_row, conflicting});

    CHECK_FALSE(store.migrate_from_sqlite(path2));

    // Only `first` (from path1) survives — the new sibling row did NOT persist even though its
    // own row landed cleanly within the batch statement that also skipped `conflicting`.
    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    REQUIRE(tokens->size() == 1);
    CHECK((*tokens)[0].name == "first-name");

    // Corrected file (identity conflict removed) now succeeds — the marker was never stamped.
    auto path3 =
        yuzu::test::unique_temp_path("yuzu_test_devtoken_batchconflict3") / "device-tokens.db";
    std::filesystem::create_directories(path3.parent_path());
    write_legacy_sqlite_db(path3, {new_row, first});
    REQUIRE(store.migrate_from_sqlite(path3));

    auto tokens2 = store.list_tokens();
    REQUIRE(tokens2.has_value());
    CHECK(tokens2->size() == 2);
}

// ── #3399: batch boundary + idempotency ───────────────────────────────────────
TEST_CASE("migrate_from_sqlite copies a legacy table spanning multiple batches, including a "
          "partial final batch, and counts it in the success log",
          "[device_token][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    // 1201 = 2 full 500-row batches + one 201-row partial final flush (kBackfillBatchRows == 500,
    // an anon-namespace constant this test file cannot name directly).
    auto bulk = make_bulk_fixture(1201, "batchboundary-");
    auto path =
        yuzu::test::unique_temp_path("yuzu_test_devtoken_batchboundary") / "device-tokens.db";
    std::filesystem::create_directories(path.parent_path());
    write_legacy_sqlite_db(path, bulk);

    std::string captured;
    {
        LogCapture capture;
        REQUIRE(store.migrate_from_sqlite(path));
        captured = capture.str();
    }
    CHECK(captured.find("backfill complete: 1201 inserted, 0 already present") !=
          std::string::npos);

    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    CHECK(tokens->size() == 1201);

    std::string captured2;
    {
        LogCapture capture;
        REQUIRE(store.migrate_from_sqlite(path));
        captured2 = capture.str();
    }
    CHECK(captured2.find("fingerprint already processed, skipping") != std::string::npos);

    auto tokens2 = store.list_tokens();
    REQUIRE(tokens2.has_value());
    CHECK(tokens2->size() == 1201);
}

// ── #3398: busy_timeout behavioral proof ─────────────────────────────────────
//
// A regression here would be silent: nothing else in this file proves the pragma actually
// changes behavior (as opposed to merely being present in the source) — every other backfill
// test runs against an uncontended legacy file. Deliberately timing-coupled (the
// std::thread/std::atomic pattern mirrors test_software_deployment_store.cpp's torn-read test —
// Catch2 assertions are unsupported off the main thread, so the holder records failure via
// atomic and the main thread REQUIREs it after join()); the 300ms hold vs. the pragma's 5000ms
// budget is a >15x margin. Uses the DEFAULT rollback-journal mode (write_legacy_sqlite_db does
// not enable WAL) so BEGIN EXCLUSIVE unconditionally blocks every other connection's first read —
// the simplest, most deterministic proof that the pragma changes behavior at all.
TEST_CASE("migrate_from_sqlite waits out a briefly-held exclusive lock instead of failing closed",
          "[device_token][pg][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, device_token_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DeviceTokenStore store{pool};
    REQUIRE(store.is_open());

    LegacyTokenFixture row;
    row.token_id = hex_id("busytimeout1");
    row.token_hash = hex_hash("busytimeout1hash");
    row.name = "contended";
    row.principal_id = "alice";
    row.device_id = "device-A";
    row.created_at = 100;

    auto path =
        yuzu::test::unique_temp_path("yuzu_test_devtoken_busytimeout") / "device-tokens.db";
    std::filesystem::create_directories(path.parent_path());
    write_legacy_sqlite_db(path, {row});

    std::atomic<bool> lock_held{false};
    std::atomic<bool> holder_open_failed{false};
    std::atomic<bool> holder_begin_failed{false};
    std::thread holder([&] {
        SqliteDb h;
        if (sqlite3_open(path.string().c_str(), h.addr()) != SQLITE_OK) {
            holder_open_failed = true;
            return;
        }
        if (sqlite3_exec(h.get(), "BEGIN EXCLUSIVE", nullptr, nullptr, nullptr) != SQLITE_OK) {
            holder_begin_failed = true;
            return;
        }
        lock_held.store(true, std::memory_order_release);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        sqlite3_exec(h.get(), "COMMIT", nullptr, nullptr, nullptr);
    });

    // Bounded wait, not an unconditional spin: if the holder thread fails before ever setting
    // lock_held (sqlite3_open/BEGIN EXCLUSIVE failing), an unconditional spin here would hang to
    // the CI/meson timeout with zero diagnostic. Watch the failure flags too, and give up with an
    // actionable FAIL well inside Catch2's own per-test timeout.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!lock_held.load(std::memory_order_acquire)) {
        if (holder_open_failed.load() || holder_begin_failed.load()) {
            holder.join();
            FAIL("holder thread failed to open/lock the legacy file before signalling — see "
                 "holder_open_failed/holder_begin_failed");
        }
        if (std::chrono::steady_clock::now() > deadline) {
            holder.join();
            FAIL("holder thread did not acquire the lock within 10s");
        }
        std::this_thread::yield();
    }

    std::string captured;
    bool migrated = false;
    {
        LogCapture capture;
        migrated = store.migrate_from_sqlite(path);
        captured = capture.str();
    }
    holder.join();
    REQUIRE_FALSE(holder_open_failed.load());
    REQUIRE_FALSE(holder_begin_failed.load());

    REQUIRE(migrated);
    CHECK(captured.find("scan aborted mid-read") == std::string::npos);
    CHECK(captured.find("schema probe failed") == std::string::npos);

    auto tokens = store.list_tokens();
    REQUIRE(tokens.has_value());
    CHECK(tokens->size() == 1);
}
