/**
 * test_custom_properties_store.cpp -- Unit tests for CustomPropertiesStore
 *
 * Covers: property CRUD, schema CRUD, schema validation (type checking, regex),
 * key/value validation, agent isolation, property map.
 */

#include "custom_properties_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;

// ============================================================================
// Lifecycle
// ============================================================================

TEST_CASE("CustomPropertiesStore: open in-memory", "[custom_props][db]") {
    CustomPropertiesStore store(":memory:");
    REQUIRE(store.is_open());
}

// ============================================================================
// Key/value validation (static methods)
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

TEST_CASE("CustomPropertiesStore: set and get property", "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");

    auto result = store.set_property("agent-1", "env", "production");
    REQUIRE(result.has_value());

    auto prop = store.get_property("agent-1", "env");
    REQUIRE(prop.has_value());
    CHECK(prop->agent_id == "agent-1");
    CHECK(prop->key == "env");
    CHECK(prop->value == "production");
    CHECK(prop->type == "string");
    CHECK(prop->updated_at > 0);
}

TEST_CASE("CustomPropertiesStore: get_value shortcut", "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");

    store.set_property("agent-1", "region", "us-east-1");
    CHECK(store.get_value("agent-1", "region") == "us-east-1");
}

TEST_CASE("CustomPropertiesStore: get_value nonexistent returns empty",
          "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");
    CHECK(store.get_value("agent-1", "nonexistent").empty());
}

TEST_CASE("CustomPropertiesStore: get_property nonexistent returns nullopt",
          "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");
    CHECK(store.get_property("agent-1", "nonexistent") == std::nullopt);
}

TEST_CASE("CustomPropertiesStore: set overwrites existing", "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");

    store.set_property("agent-1", "env", "staging");
    store.set_property("agent-1", "env", "production");
    CHECK(store.get_value("agent-1", "env") == "production");
}

TEST_CASE("CustomPropertiesStore: set with custom type", "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");

    store.set_property("agent-1", "port", "8080", "int");
    auto prop = store.get_property("agent-1", "port");
    REQUIRE(prop.has_value());
    CHECK(prop->type == "int");
}

TEST_CASE("CustomPropertiesStore: set with invalid key rejected", "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");

    auto result = store.set_property("agent-1", "bad key", "value");
    REQUIRE(!result.has_value());
    CHECK(result.error().find("invalid property key") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: set with overlength value rejected",
          "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");

    auto result = store.set_property("agent-1", "env", std::string(1025, 'x'));
    REQUIRE(!result.has_value());
    CHECK(result.error().find("maximum length") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: delete property", "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");

    store.set_property("agent-1", "env", "prod");
    CHECK(store.delete_property("agent-1", "env") == true);
    CHECK(store.get_property("agent-1", "env") == std::nullopt);

    // Second delete returns false
    CHECK(store.delete_property("agent-1", "env") == false);
}

TEST_CASE("CustomPropertiesStore: delete nonexistent returns false",
          "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");
    CHECK(store.delete_property("agent-1", "nonexistent") == false);
}

TEST_CASE("CustomPropertiesStore: delete all properties for agent",
          "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");

    store.set_property("agent-1", "env", "prod");
    store.set_property("agent-1", "region", "us-east");
    store.set_property("agent-1", "role", "web");

    store.delete_all_properties("agent-1");

    auto props = store.get_properties("agent-1");
    CHECK(props.empty());
}

TEST_CASE("CustomPropertiesStore: get_properties lists all for agent",
          "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");

    store.set_property("agent-1", "env", "prod");
    store.set_property("agent-1", "region", "us-east");
    store.set_property("agent-1", "role", "web");

    auto props = store.get_properties("agent-1");
    REQUIRE(props.size() == 3);

    // Ordered by key
    CHECK(props[0].key == "env");
    CHECK(props[1].key == "region");
    CHECK(props[2].key == "role");
}

TEST_CASE("CustomPropertiesStore: get_properties for empty agent", "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");

    auto props = store.get_properties("agent-99");
    CHECK(props.empty());
}

TEST_CASE("CustomPropertiesStore: get_property_map", "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");

    store.set_property("agent-1", "env", "prod");
    store.set_property("agent-1", "region", "eu-west");

    auto map = store.get_property_map("agent-1");
    REQUIRE(map.size() == 2);
    CHECK(map["env"] == "prod");
    CHECK(map["region"] == "eu-west");
}

TEST_CASE("CustomPropertiesStore: get_property_map for empty agent",
          "[custom_props][crud]") {
    CustomPropertiesStore store(":memory:");
    auto map = store.get_property_map("agent-99");
    CHECK(map.empty());
}

// ============================================================================
// Agent isolation
// ============================================================================

TEST_CASE("CustomPropertiesStore: properties isolated per agent",
          "[custom_props][isolation]") {
    CustomPropertiesStore store(":memory:");

    store.set_property("agent-1", "env", "production");
    store.set_property("agent-2", "env", "staging");

    CHECK(store.get_value("agent-1", "env") == "production");
    CHECK(store.get_value("agent-2", "env") == "staging");

    auto props1 = store.get_properties("agent-1");
    REQUIRE(props1.size() == 1);
    CHECK(props1[0].value == "production");

    auto props2 = store.get_properties("agent-2");
    REQUIRE(props2.size() == 1);
    CHECK(props2[0].value == "staging");
}

TEST_CASE("CustomPropertiesStore: delete one agent does not affect another",
          "[custom_props][isolation]") {
    CustomPropertiesStore store(":memory:");

    store.set_property("agent-1", "env", "prod");
    store.set_property("agent-2", "env", "staging");

    store.delete_all_properties("agent-1");

    CHECK(store.get_properties("agent-1").empty());
    CHECK(store.get_value("agent-2", "env") == "staging");
}

TEST_CASE("CustomPropertiesStore: same key different agents", "[custom_props][isolation]") {
    CustomPropertiesStore store(":memory:");

    store.set_property("agent-1", "role", "web");
    store.set_property("agent-2", "role", "db");
    store.set_property("agent-3", "role", "cache");

    CHECK(store.get_value("agent-1", "role") == "web");
    CHECK(store.get_value("agent-2", "role") == "db");
    CHECK(store.get_value("agent-3", "role") == "cache");

    // Delete from agent-2 only
    store.delete_property("agent-2", "role");
    CHECK(store.get_value("agent-1", "role") == "web");
    CHECK(store.get_value("agent-2", "role").empty());
    CHECK(store.get_value("agent-3", "role") == "cache");
}

// ============================================================================
// Schema CRUD
// ============================================================================

TEST_CASE("CustomPropertiesStore: create and get schema", "[custom_props][schema]") {
    CustomPropertiesStore store(":memory:");

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

TEST_CASE("CustomPropertiesStore: list schemas", "[custom_props][schema]") {
    CustomPropertiesStore store(":memory:");

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

TEST_CASE("CustomPropertiesStore: update schema via upsert", "[custom_props][schema]") {
    CustomPropertiesStore store(":memory:");

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

TEST_CASE("CustomPropertiesStore: delete schema", "[custom_props][schema]") {
    CustomPropertiesStore store(":memory:");

    CustomPropertySchema s{.key = "env", .display_name = "Env", .type = "string"};
    store.upsert_schema(s);

    CHECK(store.delete_schema("env") == true);
    CHECK(store.get_schema("env") == std::nullopt);
    CHECK(store.delete_schema("env") == false);
}

TEST_CASE("CustomPropertiesStore: delete nonexistent schema", "[custom_props][schema]") {
    CustomPropertiesStore store(":memory:");
    CHECK(store.delete_schema("nonexistent") == false);
}

TEST_CASE("CustomPropertiesStore: get nonexistent schema returns nullopt",
          "[custom_props][schema]") {
    CustomPropertiesStore store(":memory:");
    CHECK(store.get_schema("nonexistent") == std::nullopt);
}

TEST_CASE("CustomPropertiesStore: schema with invalid key rejected",
          "[custom_props][schema]") {
    CustomPropertiesStore store(":memory:");

    CustomPropertySchema s{.key = "bad key", .display_name = "Bad", .type = "string"};
    auto result = store.upsert_schema(s);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("invalid schema key") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema with invalid type rejected",
          "[custom_props][schema]") {
    CustomPropertiesStore store(":memory:");

    CustomPropertySchema s{.key = "env", .display_name = "Env", .type = "float"};
    auto result = store.upsert_schema(s);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("type must be one of") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema with invalid regex rejected",
          "[custom_props][schema]") {
    CustomPropertiesStore store(":memory:");

    CustomPropertySchema s{.key = "env", .display_name = "Env", .type = "string",
                            .validation_regex = "[invalid("};
    auto result = store.upsert_schema(s);
    REQUIRE(!result.has_value());
    CHECK(result.error().find("invalid validation regex") != std::string::npos);
}

TEST_CASE("CustomPropertiesStore: schema valid types accepted", "[custom_props][schema]") {
    CustomPropertiesStore store(":memory:");

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

TEST_CASE("CustomPropertiesStore: schema type validation -- int", "[custom_props][schema_val]") {
    CustomPropertiesStore store(":memory:");

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

TEST_CASE("CustomPropertiesStore: schema type validation -- bool", "[custom_props][schema_val]") {
    CustomPropertiesStore store(":memory:");

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
          "[custom_props][schema_val]") {
    CustomPropertiesStore store(":memory:");

    CustomPropertySchema s{.key = "desc", .display_name = "Description", .type = "string"};
    store.upsert_schema(s);

    auto r = store.set_property("agent-1", "desc", "anything goes here 123!@#");
    REQUIRE(r.has_value());
}

TEST_CASE("CustomPropertiesStore: schema type validation -- datetime accepts any string",
          "[custom_props][schema_val]") {
    CustomPropertiesStore store(":memory:");

    CustomPropertySchema s{.key = "enrolled_at", .display_name = "Enrolled At",
                            .type = "datetime"};
    store.upsert_schema(s);

    auto r = store.set_property("agent-1", "enrolled_at", "2025-01-15T12:00:00Z");
    REQUIRE(r.has_value());
}

TEST_CASE("CustomPropertiesStore: schema regex validation", "[custom_props][schema_val]") {
    CustomPropertiesStore store(":memory:");

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
          "[custom_props][schema_val]") {
    CustomPropertiesStore store(":memory:");

    // No schema for "freeform" key -- anything should be accepted
    auto r = store.set_property("agent-1", "freeform", "any value");
    REQUIRE(r.has_value());
    CHECK(store.get_value("agent-1", "freeform") == "any value");
}

TEST_CASE("CustomPropertiesStore: schema type overrides provided type",
          "[custom_props][schema_val]") {
    CustomPropertiesStore store(":memory:");

    // Define schema with type "int"
    CustomPropertySchema s{.key = "port", .display_name = "Port", .type = "int"};
    store.upsert_schema(s);

    // Set with type "string" -- schema type should win
    auto r = store.set_property("agent-1", "port", "8080", "string");
    REQUIRE(r.has_value());

    auto prop = store.get_property("agent-1", "port");
    REQUIRE(prop.has_value());
    CHECK(prop->type == "int");
}

TEST_CASE("CustomPropertiesStore: schema regex with int type",
          "[custom_props][schema_val]") {
    CustomPropertiesStore store(":memory:");

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
          "[custom_props][schema_val]") {
    CustomPropertiesStore store(":memory:");

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
