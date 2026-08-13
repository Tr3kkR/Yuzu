/**
 * test_custom_properties_store.cpp -- Unit tests for CustomPropertiesStore
 * (ADR-0006/ADR-0044, migrated Postgres store, schema `custom_properties_store`)
 *
 * Covers: property CRUD, schema CRUD, schema validation (type checking,
 * regex), key/value validation, agent isolation, property map, the bulk
 * get_values_for_keys preload (props.<key> scope-DSL resolution), the
 * typed-error authoritative-read posture (kDegraded on a degrade, never a
 * silent empty), and the legacy-SQLite backfill (ADR-0009).
 */

#include <catch2/catch_test_macros.hpp>

#include "custom_properties_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>
#include <sqlite3.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

using yuzu::server::CustomProperty;
using yuzu::server::CustomPropertiesReadError;
using yuzu::server::CustomPropertiesStore;
using yuzu::server::CustomPropertySchema;
using yuzu::server::SqliteDb;
using yuzu::server::SqliteErrMsg;
using yuzu::server::SqliteStmt;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

// ── Shared pre-migrated fixture (playbook "high-volume store-behaviour
// files" pattern) — one migrated clone + one persistent pool for the whole
// FILE, TRUNCATE-reset between tests instead of a fresh CREATE DATABASE +
// new pool per test (mirrors test_product_registry_store.cpp / the
// test_software_inventory_store.cpp rationale it cites). At testRunEnded the
// pool is drained before the clone is dropped, leaving static destruction
// inert. Backfill tests below deliberately construct their OWN store against
// their OWN per-test database (YUZU_REQUIRE_PG_DB) — they exercise
// fresh/empty-database behaviour the template's already-migrated clone
// can't.
yuzu::test::PgTestTemplate props_tpl{"customprops", [](const std::string& dsn) {
                                         PgPool pool{{.conninfo = dsn, .size = 1}};
                                         CustomPropertiesStore store{pool};
                                         if (!store.is_open())
                                             throw std::runtime_error(
                                                 "customprops template: store failed to migrate");
                                     }};

struct PropsShared {
    yuzu::test::PostgresTestDb db{props_tpl};
    std::optional<PgPool> pool;
    PropsShared() {
        REQUIRE(db.available());
        pool.emplace(PgPool::Options{.conninfo = db.dsn(), .size = 4});
        REQUIRE(pool->valid());
        db.keep_until_run_end([this]() noexcept { pool.reset(); });
    }
};
PropsShared& props_shared() {
    static PropsShared s;
    return s;
}

// TRUNCATE all three tables (custom_properties_meta included so a stray
// backfill-marker test run doesn't leak into a later CRUD test's fixture —
// none of the CRUD/schema tests below touch it, but the reset should not
// assume that stays true forever).
void props_reset() {
    auto lease = props_shared().pool->acquire();
    REQUIRE(lease);
    auto trunc =
        pg::exec_params(lease.get(),
                        "TRUNCATE custom_properties_store.custom_properties, "
                        "custom_properties_store.custom_property_schemas, "
                        "custom_properties_store.custom_properties_meta RESTART IDENTITY CASCADE",
                        std::vector<std::string>{});
    REQUIRE(trunc.status() == PGRES_COMMAND_OK);
}

#define PROPS_SHARED(store, pool)                                                                 \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                              \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                           \
    }                                                                                              \
    props_reset();                                                                                 \
    [[maybe_unused]] PgPool& pool = *props_shared().pool;                                          \
    CustomPropertiesStore store{pool};                                                             \
    REQUIRE(store.is_open())

// Unwraps a get_property/get_properties/get_value/get_property_map
// std::expected result in tests, asserting it's NOT a degrade (the common
// case for well-formed CRUD tests below) and returning the success payload.
template <typename T>
T require_ok(const std::expected<T, CustomPropertiesReadError>& r) {
    REQUIRE(r.has_value());
    return *r;
}

} // namespace

// ============================================================================
// Lifecycle
// ============================================================================

TEST_CASE("CustomPropertiesStore: migrates at construction and reopens idempotently",
          "[pg][custom_props][db]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    {
        CustomPropertiesStore s1{pool};
        REQUIRE(s1.is_open());
    }
    // A second construction against the already-migrated schema is a no-op
    // (versioned runner) — not a DDL re-run failure.
    CustomPropertiesStore s2{pool};
    CHECK(s2.is_open());
    auto props = s2.get_properties("agent-1");
    REQUIRE(props.has_value());
    CHECK(props->empty());
}

// ============================================================================
// Key/value validation (static methods, pure C++, unaffected by the substrate)
// ============================================================================

TEST_CASE("CustomPropertiesStore: validate_key accepts valid keys",
          "[custom_props][validation]") {
    CHECK(CustomPropertiesStore::validate_key("env") == true);
    CHECK(CustomPropertiesStore::validate_key("os.version") == true);
    CHECK(CustomPropertiesStore::validate_key("my-tag") == true);
    CHECK(CustomPropertiesStore::validate_key("tag:sub") == true);
    CHECK(CustomPropertiesStore::validate_key("a_b_c") == true);
    CHECK(CustomPropertiesStore::validate_key("ABC123") == true);
    CHECK(CustomPropertiesStore::validate_key("x") == true); // single char
}

TEST_CASE("CustomPropertiesStore: validate_key rejects invalid keys",
          "[custom_props][validation]") {
    CHECK(CustomPropertiesStore::validate_key("") == false);
    CHECK(CustomPropertiesStore::validate_key(std::string(65, 'a')) == false); // too long
    CHECK(CustomPropertiesStore::validate_key("has space") == false);
    CHECK(CustomPropertiesStore::validate_key("has/slash") == false);
    CHECK(CustomPropertiesStore::validate_key("has@at") == false);
    CHECK(CustomPropertiesStore::validate_key("has#hash") == false);
}

TEST_CASE("CustomPropertiesStore: validate_key allows max 64 chars",
          "[custom_props][validation]") {
    CHECK(CustomPropertiesStore::validate_key(std::string(64, 'a')) == true);
    CHECK(CustomPropertiesStore::validate_key(std::string(65, 'a')) == false);
}

TEST_CASE("CustomPropertiesStore: validate_value", "[custom_props][validation]") {
    CHECK(CustomPropertiesStore::validate_value("") == true);
    CHECK(CustomPropertiesStore::validate_value("hello") == true);
    CHECK(CustomPropertiesStore::validate_value(std::string(1024, 'x')) == true);
    CHECK(CustomPropertiesStore::validate_value(std::string(1025, 'x')) == false);
}

// ============================================================================
// Property CRUD
// ============================================================================

TEST_CASE("CustomPropertiesStore: set and get property", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    auto result = store.set_property("agent-1", "env", "production");
    REQUIRE(result.has_value());

    auto prop = require_ok(store.get_property("agent-1", "env"));
    REQUIRE(prop.has_value());
    CHECK(prop->agent_id == "agent-1");
    CHECK(prop->key == "env");
    CHECK(prop->value == "production");
    CHECK(prop->type == "string");
    CHECK(prop->updated_at > 0);
}

TEST_CASE("CustomPropertiesStore: get_value shortcut", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    store.set_property("agent-1", "region", "us-east-1");
    CHECK(require_ok(store.get_value("agent-1", "region")) == "us-east-1");
}

TEST_CASE("CustomPropertiesStore: get_value nonexistent returns nullopt (not degraded)",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);
    auto v = store.get_value("agent-1", "nonexistent");
    REQUIRE(v.has_value()); // read succeeded
    CHECK_FALSE(v->has_value()); // genuinely not found
}

TEST_CASE("CustomPropertiesStore: get_property nonexistent returns nullopt (not degraded)",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);
    auto p = store.get_property("agent-1", "nonexistent");
    REQUIRE(p.has_value());
    CHECK(*p == std::nullopt);
}

TEST_CASE("CustomPropertiesStore: set overwrites existing", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    store.set_property("agent-1", "env", "staging");
    store.set_property("agent-1", "env", "production");
    CHECK(require_ok(store.get_value("agent-1", "env")) == "production");
}

TEST_CASE("CustomPropertiesStore: set with custom type", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    store.set_property("agent-1", "port", "8080", "int");
    auto prop = require_ok(store.get_property("agent-1", "port"));
    REQUIRE(prop.has_value());
    CHECK(prop->type == "int");
}

TEST_CASE("CustomPropertiesStore: set with invalid key rejected", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    auto result = store.set_property("agent-1", "bad key", "value");
    REQUIRE(!result.has_value());
    CHECK(result.error().find("invalid property key") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: set with overlength value rejected",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    auto result = store.set_property("agent-1", "env", std::string(1025, 'x'));
    REQUIRE(!result.has_value());
    CHECK(result.error().find("maximum length") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: delete property", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    store.set_property("agent-1", "env", "prod");
    CHECK(store.delete_property("agent-1", "env") == true);
    CHECK(*store.get_property("agent-1", "env") == std::nullopt);

    // Second delete returns false
    CHECK(store.delete_property("agent-1", "env") == false);
}

TEST_CASE("CustomPropertiesStore: delete nonexistent returns false",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);
    CHECK(store.delete_property("agent-1", "nonexistent") == false);
}

TEST_CASE("CustomPropertiesStore: delete all properties for agent",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    store.set_property("agent-1", "env", "prod");
    store.set_property("agent-1", "region", "us-east");
    store.set_property("agent-1", "role", "web");

    store.delete_all_properties("agent-1");

    auto props = require_ok(store.get_properties("agent-1"));
    CHECK(props.empty());
}

TEST_CASE("CustomPropertiesStore: get_properties lists all for agent",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    store.set_property("agent-1", "env", "prod");
    store.set_property("agent-1", "region", "us-east");
    store.set_property("agent-1", "role", "web");

    auto props = require_ok(store.get_properties("agent-1"));
    REQUIRE(props.size() == 3);

    // Ordered by key
    CHECK(props[0].key == "env");
    CHECK(props[1].key == "region");
    CHECK(props[2].key == "role");
}

TEST_CASE("CustomPropertiesStore: get_properties for empty agent", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    auto props = require_ok(store.get_properties("agent-99"));
    CHECK(props.empty());
}

TEST_CASE("CustomPropertiesStore: get_property_map", "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);

    store.set_property("agent-1", "env", "prod");
    store.set_property("agent-1", "region", "eu-west");

    auto map = require_ok(store.get_property_map("agent-1"));
    REQUIRE(map.size() == 2);
    CHECK(map["env"] == "prod");
    CHECK(map["region"] == "eu-west");
}

TEST_CASE("CustomPropertiesStore: get_property_map for empty agent",
          "[pg][custom_props][crud]") {
    PROPS_SHARED(store, pool);
    auto map = require_ok(store.get_property_map("agent-99"));
    CHECK(map.empty());
}

// ============================================================================
// Bulk preload (get_values_for_keys — props.<key> scope-DSL resolution)
// ============================================================================

TEST_CASE("CustomPropertiesStore: get_values_for_keys bulk-preloads across agents",
          "[pg][custom_props][bulk]") {
    PROPS_SHARED(store, pool);

    store.set_property("agent-1", "env", "prod");
    store.set_property("agent-1", "region", "us-east");
    store.set_property("agent-2", "env", "staging");
    store.set_property("agent-3", "role", "web"); // not one of the requested keys' agents only

    auto result = require_ok(store.get_values_for_keys({"env", "region"}));
    REQUIRE(result.size() == 2); // agent-1, agent-2 (agent-3 has no env/region)
    REQUIRE(result.contains("agent-1"));
    CHECK(result["agent-1"]["env"] == "prod");
    CHECK(result["agent-1"]["region"] == "us-east");
    REQUIRE(result.contains("agent-2"));
    CHECK(result["agent-2"]["env"] == "staging");
    CHECK_FALSE(result["agent-2"].contains("region"));
}

TEST_CASE("CustomPropertiesStore: get_values_for_keys with empty keys returns empty map, no query",
          "[pg][custom_props][bulk]") {
    PROPS_SHARED(store, pool);
    store.set_property("agent-1", "env", "prod");
    auto result = require_ok(store.get_values_for_keys({}));
    CHECK(result.empty());
}

TEST_CASE("CustomPropertiesStore: get_values_for_keys with no matching properties",
          "[pg][custom_props][bulk]") {
    PROPS_SHARED(store, pool);
    store.set_property("agent-1", "env", "prod");
    auto result = require_ok(store.get_values_for_keys({"nonexistent"}));
    CHECK(result.empty());
}

// ============================================================================
// Authoritative-read posture (kDegraded on a store/pool/query failure)
// ============================================================================

TEST_CASE("CustomPropertiesStore: reads degrade to kDegraded on a closed store",
          "[custom_props][degrade]") {
    // A default-constructed PgPool pointed at an unreachable DSN never opens
    // — is_open() stays false, exercising the "store not open" degrade path
    // without needing a live Postgres instance (this case runs unconditionally).
    PgPool pool{{.conninfo = "postgresql://nonexistent-host-for-test:1/nope", .size = 1}};
    CustomPropertiesStore store{pool};
    REQUIRE_FALSE(store.is_open());

    CHECK(store.get_properties("agent-1").error() == CustomPropertiesReadError::kDegraded);
    CHECK(store.get_property("agent-1", "k").error() == CustomPropertiesReadError::kDegraded);
    CHECK(store.get_value("agent-1", "k").error() == CustomPropertiesReadError::kDegraded);
    CHECK(store.get_property_map("agent-1").error() == CustomPropertiesReadError::kDegraded);
    CHECK(store.get_values_for_keys({"k"}).error() == CustomPropertiesReadError::kDegraded);

    // set_property on a closed store is also an error (not silently
    // accepted) — same posture, string-error channel (unchanged contract).
    auto set_result = store.set_property("agent-1", "k", "v");
    REQUIRE(!set_result.has_value());
    CHECK(set_result.error() == "store not open");
}

// ============================================================================
// Agent isolation
// ============================================================================

TEST_CASE("CustomPropertiesStore: properties isolated per agent",
          "[pg][custom_props][isolation]") {
    PROPS_SHARED(store, pool);

    store.set_property("agent-1", "env", "production");
    store.set_property("agent-2", "env", "staging");

    CHECK(require_ok(store.get_value("agent-1", "env")) == "production");
    CHECK(require_ok(store.get_value("agent-2", "env")) == "staging");

    auto props1 = require_ok(store.get_properties("agent-1"));
    REQUIRE(props1.size() == 1);
    CHECK(props1[0].value == "production");

    auto props2 = require_ok(store.get_properties("agent-2"));
    REQUIRE(props2.size() == 1);
    CHECK(props2[0].value == "staging");
}

TEST_CASE("CustomPropertiesStore: delete one agent does not affect another",
          "[pg][custom_props][isolation]") {
    PROPS_SHARED(store, pool);

    store.set_property("agent-1", "env", "prod");
    store.set_property("agent-2", "env", "staging");

    store.delete_all_properties("agent-1");

    CHECK(require_ok(store.get_properties("agent-1")).empty());
    CHECK(require_ok(store.get_value("agent-2", "env")) == "staging");
}

TEST_CASE("CustomPropertiesStore: same key different agents", "[pg][custom_props][isolation]") {
    PROPS_SHARED(store, pool);

    store.set_property("agent-1", "role", "web");
    store.set_property("agent-2", "role", "db");
    store.set_property("agent-3", "role", "cache");

    CHECK(require_ok(store.get_value("agent-1", "role")) == "web");
    CHECK(require_ok(store.get_value("agent-2", "role")) == "db");
    CHECK(require_ok(store.get_value("agent-3", "role")) == "cache");

    // Delete from agent-2 only
    CHECK(store.delete_property("agent-2", "role"));
    CHECK(require_ok(store.get_value("agent-1", "role")) == "web");
    CHECK_FALSE(require_ok(store.get_value("agent-2", "role")).has_value());
    CHECK(require_ok(store.get_value("agent-3", "role")) == "cache");
}

// ============================================================================
// Schema CRUD
// ============================================================================

TEST_CASE("CustomPropertiesStore: create and get schema", "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema schema;
    schema.key = "environment";
    schema.display_name = "Environment";
    schema.type = "string";
    schema.description = "Deployment environment";
    schema.validation_regex = "^(dev|staging|production)$";

    auto result = store.upsert_schema(schema);
    REQUIRE(result.has_value());

    auto retrieved = store.get_schema("environment");
    REQUIRE(retrieved.has_value());
    CHECK(retrieved->key == "environment");
    CHECK(retrieved->display_name == "Environment");
    CHECK(retrieved->type == "string");
    CHECK(retrieved->description == "Deployment environment");
    CHECK(retrieved->validation_regex == "^(dev|staging|production)$");
}

TEST_CASE("CustomPropertiesStore: list schemas", "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s1{.key = "env", .display_name = "Env", .type = "string"};
    CustomPropertySchema s2{.key = "port", .display_name = "Port", .type = "int"};
    CustomPropertySchema s3{.key = "active", .display_name = "Active", .type = "bool"};

    store.upsert_schema(s1);
    store.upsert_schema(s2);
    store.upsert_schema(s3);

    auto schemas = store.list_schemas();
    REQUIRE(schemas.size() == 3);
    // Sorted by key
    CHECK(schemas[0].key == "active");
    CHECK(schemas[1].key == "env");
    CHECK(schemas[2].key == "port");
}

TEST_CASE("CustomPropertiesStore: update schema via upsert", "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s1{.key = "env", .display_name = "Env", .type = "string"};
    store.upsert_schema(s1);

    // Update display name
    CustomPropertySchema s2{.key = "env", .display_name = "Environment", .type = "string",
                             .description = "Updated"};
    store.upsert_schema(s2);

    auto schema = store.get_schema("env");
    REQUIRE(schema.has_value());
    CHECK(schema->display_name == "Environment");
    CHECK(schema->description == "Updated");

    // Still only one schema
    auto all = store.list_schemas();
    CHECK(all.size() == 1);
}

TEST_CASE("CustomPropertiesStore: delete schema", "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "env", .display_name = "Env", .type = "string"};
    store.upsert_schema(s);

    CHECK(store.delete_schema("env") == true);
    CHECK(store.get_schema("env") == std::nullopt);
    CHECK(store.delete_schema("env") == false);
}

TEST_CASE("CustomPropertiesStore: delete nonexistent schema", "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);
    CHECK(store.delete_schema("nonexistent") == false);
}

TEST_CASE("CustomPropertiesStore: get nonexistent schema returns nullopt",
          "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);
    CHECK(store.get_schema("nonexistent") == std::nullopt);
}

TEST_CASE("CustomPropertiesStore: schema with invalid key rejected",
          "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "bad key", .display_name = "Bad", .type = "string"};
    auto result = store.upsert_schema(s);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("invalid schema key") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema with invalid type rejected",
          "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "env", .display_name = "Env", .type = "float"};
    auto result = store.upsert_schema(s);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("type must be one of") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema with invalid regex rejected",
          "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "env", .display_name = "Env", .type = "string",
                            .validation_regex = "[invalid("};
    auto result = store.upsert_schema(s);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("invalid validation regex") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema regex exceeding max length rejected",
          "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "env", .display_name = "Env", .type = "string",
                            .validation_regex = std::string(257, 'a')};
    auto result = store.upsert_schema(s);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("maximum length of 256") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema valid types accepted", "[pg][custom_props][schema]") {
    PROPS_SHARED(store, pool);

    for (const auto& type : {"string", "int", "bool", "datetime"}) {
        CustomPropertySchema s{.key = std::string("k_") + type,
                                .display_name = type,
                                .type = type};
        auto result = store.upsert_schema(s);
        REQUIRE(result.has_value());
    }

    auto schemas = store.list_schemas();
    CHECK(schemas.size() == 4);
}

// ============================================================================
// Schema validation on set
// ============================================================================

TEST_CASE("CustomPropertiesStore: schema type validation -- int",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "port", .display_name = "Port", .type = "int"};
    store.upsert_schema(s);

    // Valid int
    auto r1 = store.set_property("agent-1", "port", "8080");
    REQUIRE(r1.has_value());

    // Invalid int
    auto r2 = store.set_property("agent-1", "port", "not-a-number");
    REQUIRE(!r2.has_value());
    CHECK(r2.error().find("valid integer") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema type validation -- bool",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "active", .display_name = "Active", .type = "bool"};
    store.upsert_schema(s);

    auto r1 = store.set_property("agent-1", "active", "true");
    REQUIRE(r1.has_value());

    auto r2 = store.set_property("agent-1", "active", "false");
    REQUIRE(r2.has_value());

    auto r3 = store.set_property("agent-1", "active", "yes");
    REQUIRE(!r3.has_value());
    CHECK(r3.error().find("'true' or 'false'") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema type validation -- string accepts anything",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "desc", .display_name = "Description", .type = "string"};
    store.upsert_schema(s);

    auto r = store.set_property("agent-1", "desc", "anything goes here 123!@#");
    REQUIRE(r.has_value());
}

TEST_CASE("CustomPropertiesStore: schema type validation -- datetime accepts any string",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "enrolled_at", .display_name = "Enrolled At",
                            .type = "datetime"};
    store.upsert_schema(s);

    auto r = store.set_property("agent-1", "enrolled_at", "2025-01-15T12:00:00Z");
    REQUIRE(r.has_value());
}

TEST_CASE("CustomPropertiesStore: schema regex validation", "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "env",
                            .display_name = "Environment",
                            .type = "string",
                            .validation_regex = "^(dev|staging|production)$"};
    store.upsert_schema(s);

    // Matching values
    auto r1 = store.set_property("agent-1", "env", "production");
    REQUIRE(r1.has_value());

    auto r2 = store.set_property("agent-1", "env", "dev");
    REQUIRE(r2.has_value());

    // Non-matching value
    auto r3 = store.set_property("agent-1", "env", "testing");
    REQUIRE(!r3.has_value());
    CHECK(r3.error().find("validation pattern") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: no schema means no validation",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    // No schema for "freeform" key -- anything should be accepted
    auto r = store.set_property("agent-1", "freeform", "any value");
    REQUIRE(r.has_value());
    CHECK(require_ok(store.get_value("agent-1", "freeform")) == "any value");
}

TEST_CASE("CustomPropertiesStore: schema type overrides provided type",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    // Define schema with type "int"
    CustomPropertySchema s{.key = "port", .display_name = "Port", .type = "int"};
    store.upsert_schema(s);

    // Set with type "string" -- schema type should win
    auto r = store.set_property("agent-1", "port", "8080", "string");
    REQUIRE(r.has_value());

    auto prop = require_ok(store.get_property("agent-1", "port"));
    REQUIRE(prop.has_value());
    CHECK(prop->type == "int");
}

TEST_CASE("CustomPropertiesStore: schema regex with int type",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    // Int schema with regex for port range
    CustomPropertySchema s{.key = "port",
                            .display_name = "Port",
                            .type = "int",
                            .validation_regex = "^[0-9]{1,5}$"};
    store.upsert_schema(s);

    // Valid: integer that matches regex
    auto r1 = store.set_property("agent-1", "port", "8080");
    REQUIRE(r1.has_value());

    // Invalid: not an integer
    auto r2 = store.set_property("agent-1", "port", "abc");
    REQUIRE(!r2.has_value());

    // Invalid: integer but doesn't match regex (negative)
    auto r3 = store.set_property("agent-1", "port", "-1");
    REQUIRE(!r3.has_value());
}

TEST_CASE("CustomPropertiesStore: delete schema removes validation",
          "[pg][custom_props][schema_val]") {
    PROPS_SHARED(store, pool);

    CustomPropertySchema s{.key = "env",
                            .display_name = "Env",
                            .type = "string",
                            .validation_regex = "^(dev|prod)$"};
    store.upsert_schema(s);

    // Rejected with schema
    auto r1 = store.set_property("agent-1", "env", "testing");
    REQUIRE(!r1.has_value());

    // Delete schema
    store.delete_schema("env");

    // Accepted without schema
    auto r2 = store.set_property("agent-1", "env", "testing");
    REQUIRE(r2.has_value());
}

// ============================================================================
// Backfill (ADR-0009) — each case constructs its OWN store against its OWN
// per-test database (YUZU_REQUIRE_PG_DB), since these exercise fresh/empty-
// database behaviour the shared template's already-migrated clone can't.
// ============================================================================

namespace {

// RAII temp SQLite file — the legacy `custom-properties.db` a backfill reads.
// A successful migrate_from_sqlite() moves `path` aside to `path.migrated-*`
// (ADR-0009 rollback window); the destructor sweeps the parent directory for
// any such sibling so a passing backfill test doesn't leak files into the
// scratch dir.
struct TempSqliteFile {
    std::filesystem::path path;
    explicit TempSqliteFile(const std::string& prefix)
        : path(yuzu::test::unique_temp_path(prefix)) {}
    ~TempSqliteFile() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        const std::string stem = path.filename().string() + ".migrated-";
        std::error_code dir_ec;
        for (const auto& entry :
             std::filesystem::directory_iterator(path.parent_path(), dir_ec)) {
            if (entry.path().filename().string().starts_with(stem))
                std::filesystem::remove(entry.path(), ec);
        }
    }
    TempSqliteFile(const TempSqliteFile&) = delete;
    TempSqliteFile& operator=(const TempSqliteFile&) = delete;
};

} // namespace

TEST_CASE("CustomPropertiesStore: backfill with no legacy file marks complete (fresh install)",
          "[pg][custom_props][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    CustomPropertiesStore store{pool};
    REQUIRE(store.is_open());

    TempSqliteFile legacy("yuzu_test_customprops_nofile_");
    // Do not create the file — exercise the "no legacy db" branch.
    CHECK(store.migrate_from_sqlite(legacy.path));

    // Idempotent: a second call against the now-set marker is a no-op skip.
    CHECK(store.migrate_from_sqlite(legacy.path));
}

TEST_CASE("CustomPropertiesStore: backfill copies properties and schemas from legacy SQLite",
          "[pg][custom_props][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    CustomPropertiesStore store{pool};
    REQUIRE(store.is_open());

    TempSqliteFile legacy("yuzu_test_customprops_backfill_");
    {
        SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        REQUIRE(raw.get() != nullptr);
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(),
                             "CREATE TABLE custom_properties (agent_id TEXT NOT NULL, key TEXT "
                             "NOT NULL, value TEXT NOT NULL, type TEXT NOT NULL DEFAULT "
                             "'string', updated_at INTEGER NOT NULL, PRIMARY KEY (agent_id, "
                             "key));"
                             "CREATE TABLE custom_property_schemas (key TEXT PRIMARY KEY, "
                             "display_name TEXT, type TEXT NOT NULL DEFAULT 'string', "
                             "description TEXT, validation_regex TEXT);"
                             "INSERT INTO custom_properties VALUES ('agent-legacy-1', 'env', "
                             "'production', 'string', 1700000000);"
                             "INSERT INTO custom_properties VALUES ('agent-legacy-2', 'role', "
                             "'db', 'string', 1700000001);"
                             "INSERT INTO custom_property_schemas VALUES ('env', 'Environment', "
                             "'string', 'Deployment env', '^(dev|staging|production)$');",
                             nullptr, nullptr, err.addr()) == SQLITE_OK);
    }

    REQUIRE(store.migrate_from_sqlite(legacy.path));

    auto p1 = store.get_property("agent-legacy-1", "env");
    REQUIRE(p1.has_value());
    REQUIRE(p1->has_value());
    CHECK((*p1)->value == "production");
    CHECK((*p1)->updated_at == 1700000000);

    auto p2 = store.get_property("agent-legacy-2", "role");
    REQUIRE(p2.has_value());
    REQUIRE(p2->has_value());
    CHECK((*p2)->value == "db");

    auto schema = store.get_schema("env");
    REQUIRE(schema.has_value());
    CHECK(schema->display_name == "Environment");
    CHECK(schema->validation_regex == "^(dev|staging|production)$");

    // Legacy file was moved aside (one-release rollback window, ADR-0009).
    CHECK_FALSE(std::filesystem::exists(legacy.path));

    // Idempotent re-run (legacy file gone, marker set) is a clean skip.
    CHECK(store.migrate_from_sqlite(legacy.path));
}

TEST_CASE("CustomPropertiesStore: backfill refuses on a corrupt legacy file (fail-closed)",
          "[pg][custom_props][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    CustomPropertiesStore store{pool};
    REQUIRE(store.is_open());

    TempSqliteFile legacy("yuzu_test_customprops_corrupt_");
    {
        // Not a valid SQLite file at all.
        FILE* f = std::fopen(legacy.path.string().c_str(), "wb");
        REQUIRE(f != nullptr);
        const char junk[] = "this is not a sqlite database";
        std::fwrite(junk, 1, sizeof(junk), f);
        std::fclose(f);
    }

    CHECK_FALSE(store.migrate_from_sqlite(legacy.path));
    // The legacy file must NOT have been consumed/moved on a failed backfill.
    CHECK(std::filesystem::exists(legacy.path));
}

TEST_CASE("CustomPropertiesStore: backfill with legacy db missing custom_properties table "
          "marks complete",
          "[pg][custom_props][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    CustomPropertiesStore store{pool};
    REQUIRE(store.is_open());

    TempSqliteFile legacy("yuzu_test_customprops_notable_");
    {
        SqliteDb raw;
        REQUIRE(sqlite3_open(legacy.path.string().c_str(), raw.addr()) == SQLITE_OK);
        // A valid, empty SQLite db with no custom_properties table (e.g. a
        // stray file, or a DB some other subsystem created).
        SqliteErrMsg err;
        REQUIRE(sqlite3_exec(raw.get(), "CREATE TABLE unrelated (x INTEGER);", nullptr, nullptr,
                             err.addr()) == SQLITE_OK);
    }

    CHECK(store.migrate_from_sqlite(legacy.path));
    auto props = store.get_properties("any-agent");
    REQUIRE(props.has_value());
    CHECK(props->empty());
}

// ============================================================================
// Backfill: holder-side fingerprint verification (marker already set, this
// replica still holds a legacy file) — the novel logic this store's backfill
// was specifically built to add over the SQLite original, per ADR-0044 and
// the RbacStore post-#2703 reference shape it ports unmodified. Governance
// Gate 3 quality-engineer flagged these branches as having zero coverage.
// ============================================================================

namespace {

void write_legacy_props_db(const std::filesystem::path& path, const std::string& agent_id,
                           const std::string& key, const std::string& value) {
    SqliteDb raw;
    REQUIRE(sqlite3_open(path.string().c_str(), raw.addr()) == SQLITE_OK);
    SqliteErrMsg err;
    REQUIRE(sqlite3_exec(raw.get(),
                         "CREATE TABLE custom_properties (agent_id TEXT NOT NULL, key TEXT NOT "
                         "NULL, value TEXT NOT NULL, type TEXT NOT NULL DEFAULT 'string', "
                         "updated_at INTEGER NOT NULL, PRIMARY KEY (agent_id, key));"
                         "CREATE TABLE custom_property_schemas (key TEXT PRIMARY KEY, "
                         "display_name TEXT, type TEXT NOT NULL DEFAULT 'string', description "
                         "TEXT, validation_regex TEXT);",
                         nullptr, nullptr, err.addr()) == SQLITE_OK);
    SqliteStmt stmt;
    REQUIRE(sqlite3_prepare_v2(raw.get(),
                               "INSERT INTO custom_properties (agent_id, key, value, type, "
                               "updated_at) VALUES (?, ?, ?, 'string', 1700000000)",
                               -1, stmt.addr(), nullptr) == SQLITE_OK);
    sqlite3_bind_text(stmt.get(), 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, value.c_str(), -1, SQLITE_TRANSIENT);
    REQUIRE(sqlite3_step(stmt.get()) == SQLITE_DONE);
}

} // namespace

TEST_CASE("CustomPropertiesStore: migrate_from_sqlite verifies a matching fingerprint when "
          "this replica's own already-migrated legacy file is still present",
          "[pg][custom_props][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    CustomPropertiesStore store{pool};
    REQUIRE(store.is_open());

    TempSqliteFile legacy("yuzu_test_customprops_fpmatch_");
    write_legacy_props_db(legacy.path, "agent-1", "env", "prod");
    REQUIRE(store.migrate_from_sqlite(legacy.path));
    CHECK_FALSE(std::filesystem::exists(legacy.path)); // moved aside as usual

    // Recreate a file with IDENTICAL logical content at the same path —
    // simulating a failed move-aside on a real restart (the RbacStore
    // reference case, test_rbac_store.cpp).
    write_legacy_props_db(legacy.path, "agent-1", "env", "prod");
    CustomPropertiesStore reopened{pool};
    REQUIRE(reopened.is_open());
    CHECK(reopened.migrate_from_sqlite(legacy.path));

    // Verified, not re-migrated: no duplicate/conflicting row, and the
    // matched-fingerprint branch retries move_legacy_aside — machine-check
    // that it actually ran, not just that migrate_from_sqlite returned true.
    auto prop = reopened.get_property("agent-1", "env");
    REQUIRE(prop.has_value());
    REQUIRE(prop->has_value());
    CHECK((*prop)->value == "prod");
    CHECK_FALSE(std::filesystem::exists(legacy.path));
}

TEST_CASE("CustomPropertiesStore: migrate_from_sqlite refuses a sourceless sibling's marker on "
          "a later boot even though this replica genuinely holds the legacy file",
          "[pg][custom_props][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    // "Replica A" — no local legacy file, stamps the shared marker with the
    // sourceless sentinel fingerprint.
    CustomPropertiesStore replica_a{pool};
    REQUIRE(replica_a.is_open());
    CHECK(replica_a.migrate_from_sqlite("/nonexistent/path/custom-properties.db"));

    // "Replica B" — same shared Postgres, but this one genuinely holds a
    // legacy file with real, non-empty operator content, and boots AFTER
    // the marker was already stamped sourceless.
    CustomPropertiesStore replica_b{pool};
    REQUIRE(replica_b.is_open());
    TempSqliteFile legacy("yuzu_test_customprops_sourcelessrace_");
    write_legacy_props_db(legacy.path, "agent-1", "env", "prod");

    // Refused, not silently accepted OR silently re-migrated — the file must
    // survive untouched, and no operator data it holds must land in PG.
    CHECK_FALSE(replica_b.migrate_from_sqlite(legacy.path));
    CHECK(std::filesystem::exists(legacy.path));
    auto prop = replica_b.get_property("agent-1", "env");
    REQUIRE(prop.has_value());
    CHECK_FALSE(prop->has_value());
}

TEST_CASE("CustomPropertiesStore: migrate_from_sqlite HOLDER-SIDE VERIFICATION FAILED on a "
          "different replica's real fingerprint",
          "[pg][custom_props][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    // "Replica A" migrates its own real content and stamps the shared marker.
    CustomPropertiesStore replica_a{pool};
    REQUIRE(replica_a.is_open());
    TempSqliteFile legacy_a("yuzu_test_customprops_holderA_");
    write_legacy_props_db(legacy_a.path, "agent-a", "env", "staging");
    REQUIRE(replica_a.migrate_from_sqlite(legacy_a.path));

    // "Replica B" boots later, holding a DIFFERENT real legacy file (its own,
    // divergent content) — must refuse rather than silently accept the
    // marker or clobber the already-migrated data.
    CustomPropertiesStore replica_b{pool};
    REQUIRE(replica_b.is_open());
    TempSqliteFile legacy_b("yuzu_test_customprops_holderB_");
    write_legacy_props_db(legacy_b.path, "agent-b", "role", "db");

    CHECK_FALSE(replica_b.migrate_from_sqlite(legacy_b.path));
    // Replica B's file must NOT have been consumed/moved.
    CHECK(std::filesystem::exists(legacy_b.path));
    // Replica B's data must NOT have landed in Postgres.
    auto prop_b = replica_b.get_property("agent-b", "role");
    REQUIRE(prop_b.has_value());
    CHECK_FALSE(prop_b->has_value());
    // Replica A's data is untouched (the promotion upsert never overwrites a
    // stored real value with a different real value).
    auto prop_a = replica_b.get_property("agent-a", "env");
    REQUIRE(prop_a.has_value());
    REQUIRE(prop_a->has_value());
    CHECK((*prop_a)->value == "staging");
}

TEST_CASE("CustomPropertiesStore: migrate_from_sqlite refuses on this replica's own legacy "
          "file being unreadable while the marker is already set",
          "[pg][custom_props][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());

    CustomPropertiesStore replica_a{pool};
    REQUIRE(replica_a.is_open());
    REQUIRE(replica_a.migrate_from_sqlite("/nonexistent/path/custom-properties.db"));

    CustomPropertiesStore replica_b{pool};
    REQUIRE(replica_b.is_open());
    TempSqliteFile legacy("yuzu_test_customprops_holdercorrupt_");
    {
        std::ofstream f(legacy.path, std::ios::binary);
        REQUIRE(f.is_open());
        f << "not a sqlite database";
    }

    // A corrupt/unreadable file while the marker is set must fail closed —
    // never silently trust the (sourceless) marker over an unverifiable
    // local file that might hold real, never-migrated data.
    CHECK_FALSE(replica_b.migrate_from_sqlite(legacy.path));
    CHECK(std::filesystem::exists(legacy.path));
}

// governance Gate 8 (security-guardian, MEDIUM): the 4 holder-side tests
// above are all SEQUENTIAL — replica A's migrate_from_sqlite fully commits
// (marker present) before replica B's ever runs, so replica B always takes
// the pre-existing `marker_present` verify branch and never re-enters
// stamp_complete itself. None of them would fail if stamp_complete's SQL
// were reverted to the pre-fix plain `ON CONFLICT DO NOTHING`. A genuine
// concurrent-collision repro needs two real racing callers, which (mirrors
// RbacStore's own documented limitation, test_rbac_store.cpp) the public
// API's own step-2 idempotency check makes impossible to force
// deterministically without a test-only pause hook. Verify the upsert's SQL
// semantics directly against Postgres instead — a COPY of stamp_complete's
// fingerprint query, not a call into stamp_complete itself (a private
// lambda with no external call site). DISCLOSED LIMITATION: this copy is
// NOT auto-synced — if stamp_complete's fingerprint UPSERT in
// custom_properties_store.cpp ever changes, this copy must be updated to
// match or this test silently stops covering the real code.
TEST_CASE("CustomPropertiesStore: backfill_source_fingerprint upsert promotes sourceless, "
          "protects a real value, and accepts a matching value",
          "[pg][custom_props][backfill]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    CustomPropertiesStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.migrate_from_sqlite("/nonexistent/path/custom-properties.db")); // seeds 'sourceless'

    const auto stamp = [&](const std::string& value) -> int {
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "INSERT INTO custom_properties_store.custom_properties_meta (key, value) VALUES "
            "('backfill_source_fingerprint', $1) ON CONFLICT (key) DO UPDATE SET "
            "value = EXCLUDED.value WHERE custom_properties_store.custom_properties_meta.value = "
            "'sourceless' OR custom_properties_store.custom_properties_meta.value = "
            "EXCLUDED.value RETURNING value",
            std::vector<std::string>{value});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        return PQntuples(r.get());
    };
    const auto stored_value = [&]() -> std::string {
        auto lease = pool.acquire();
        REQUIRE(lease);
        pg::PgResult r = pg::exec_params(
            lease.get(),
            "SELECT value FROM custom_properties_store.custom_properties_meta WHERE key = "
            "'backfill_source_fingerprint'",
            std::vector<std::string>{});
        REQUIRE(r.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(r.get()) == 1);
        return PQgetvalue(r.get(), 0, 0);
    };
    REQUIRE(stored_value() == "sourceless");

    // A real fingerprint promotes a stored sourceless placeholder — 1 row.
    CHECK(stamp("v1:real_A") == 1);
    CHECK(stored_value() == "v1:real_A");

    // A DIFFERENT real fingerprint may not overwrite the now-real value — 0
    // rows, and the stored value is untouched. This is the exact case the
    // security-guardian HIGH finding closed: pre-fix (plain ON CONFLICT DO
    // NOTHING), this same call would have silently no-opped without ever
    // reporting that a different value already won.
    CHECK(stamp("v1:real_B") == 0);
    CHECK(stored_value() == "v1:real_A");

    // The SAME real fingerprint writing again (two replicas sharing storage,
    // both migrating identical content, one loses only the INSERT race, not
    // the content race) counts as success, not a lost race — 1 row.
    CHECK(stamp("v1:real_A") == 1);
    CHECK(stored_value() == "v1:real_A");

    // A sourceless writer never overwrites an established real value — 0
    // rows (non-error for the sourceless caller per stamp_complete's own
    // exemption, exercised at the migrate_from_sqlite level in the tests
    // above).
    CHECK(stamp("sourceless") == 0);
    CHECK(stored_value() == "v1:real_A");
}
