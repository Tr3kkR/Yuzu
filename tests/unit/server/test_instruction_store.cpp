/**
 * test_instruction_store.cpp — Unit tests for InstructionStore
 *
 * Covers: CRUD definitions, uniqueness, filters, parameters, import/export,
 *         instruction sets.
 */

#include "instruction_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <unordered_map>

using namespace yuzu::server;

// ── Helpers ─────────────────────────────────────────────────────────────────

static InstructionDefinition make_question(
    const std::string& name,
    const std::string& version = "1.0",
    const std::string& plugin = "system_info")
{
    InstructionDefinition def;
    def.name = name;
    def.version = version;
    def.plugin = plugin;
    def.action = "query";
    def.type = "question";
    def.description = "Test question: " + name;
    def.enabled = true;
    return def;
}

static InstructionDefinition make_action(
    const std::string& name,
    const std::string& version = "1.0",
    const std::string& plugin = "remediation")
{
    InstructionDefinition def;
    def.name = name;
    def.version = version;
    def.plugin = plugin;
    def.action = "execute";
    def.type = "action";
    def.description = "Test action: " + name;
    def.enabled = true;
    return def;
}

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("InstructionStore: open in-memory", "[instruction_store][db]") {
    InstructionStore store(":memory:");
    REQUIRE(store.is_open());
}

// ── Create Definition ──────────────────────────────────────────────────────

TEST_CASE("InstructionStore: create question definition", "[instruction_store]") {
    InstructionStore store(":memory:");

    auto def = make_question("Get Hostname");
    auto result = store.create_definition(def);
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("InstructionStore: create action definition", "[instruction_store]") {
    InstructionStore store(":memory:");

    auto def = make_action("Restart Service");
    auto result = store.create_definition(def);
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("InstructionStore: create with invalid type fails", "[instruction_store]") {
    InstructionStore store(":memory:");

    InstructionDefinition def;
    def.name = "Bad";
    def.type = "invalid";
    def.plugin = "test";
    def.action = "test";
    auto result = store.create_definition(def);
    CHECK(!result.has_value());
}

// ── Name+Version Uniqueness ────────────────────────────────────────────────

TEST_CASE("InstructionStore: name+version uniqueness", "[instruction_store]") {
    InstructionStore store(":memory:");

    auto result1 = store.create_definition(make_question("Get Hostname", "1.0"));
    REQUIRE(result1.has_value());

    // Same name+version should fail
    auto result2 = store.create_definition(make_question("Get Hostname", "1.0"));
    CHECK(!result2.has_value());

    // Same name, different version should succeed
    auto result3 = store.create_definition(make_question("Get Hostname", "2.0"));
    CHECK(result3.has_value());
}

// ── Get By ID ──────────────────────────────────────────────────────────────

TEST_CASE("InstructionStore: get definition by ID", "[instruction_store]") {
    InstructionStore store(":memory:");

    auto def = make_question("Get Hostname");
    def.description = "Returns the machine hostname";
    auto result = store.create_definition(def);
    REQUIRE(result.has_value());

    auto fetched = store.get_definition(*result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->name == "Get Hostname");
    CHECK(fetched->version == "1.0");
    CHECK(fetched->plugin == "system_info");
    CHECK(fetched->type == "question");
    CHECK(fetched->description == "Returns the machine hostname");
    CHECK(fetched->enabled == true);
}

TEST_CASE("InstructionStore: get nonexistent returns empty", "[instruction_store]") {
    InstructionStore store(":memory:");
    auto result = store.get_definition("nonexistent-id");
    CHECK(!result.has_value());
}

// ── Query with Filters ─────────────────────────────────────────────────────

TEST_CASE("InstructionStore: query all definitions", "[instruction_store]") {
    InstructionStore store(":memory:");

    store.create_definition(make_question("Get Hostname"));
    store.create_definition(make_action("Restart Service"));
    store.create_definition(make_question("Get OS Version"));

    auto results = store.query_definitions();
    REQUIRE(results.size() == 3);
}

TEST_CASE("InstructionStore: query by name filter", "[instruction_store]") {
    InstructionStore store(":memory:");

    store.create_definition(make_question("Get Hostname"));
    store.create_definition(make_question("Get OS Version"));
    store.create_definition(make_action("Restart Service"));

    InstructionQuery q;
    q.name_filter = "Hostname";
    auto results = store.query_definitions(q);
    REQUIRE(results.size() == 1);
    CHECK(results[0].name == "Get Hostname");
}

TEST_CASE("InstructionStore: query by plugin filter", "[instruction_store]") {
    InstructionStore store(":memory:");

    store.create_definition(make_question("Get Hostname", "1.0", "system_info"));
    store.create_definition(make_action("Restart Service", "1.0", "remediation"));
    store.create_definition(make_question("Get CPU Info", "1.0", "system_info"));

    InstructionQuery q;
    q.plugin_filter = "system_info";
    auto results = store.query_definitions(q);
    REQUIRE(results.size() == 2);
}

TEST_CASE("InstructionStore: query by type filter", "[instruction_store]") {
    InstructionStore store(":memory:");

    store.create_definition(make_question("Get Hostname"));
    store.create_definition(make_action("Restart Service"));
    store.create_definition(make_action("Kill Process"));

    InstructionQuery q;
    q.type_filter = "action";
    auto results = store.query_definitions(q);
    REQUIRE(results.size() == 2);
}

TEST_CASE("InstructionStore: query enabled_only filter", "[instruction_store]") {
    InstructionStore store(":memory:");

    auto def1 = make_question("Get Hostname");
    def1.enabled = true;
    store.create_definition(def1);

    auto def2 = make_question("Get OS Version");
    def2.enabled = false;
    store.create_definition(def2);

    InstructionQuery q;
    q.enabled_only = true;
    auto results = store.query_definitions(q);
    REQUIRE(results.size() == 1);
    CHECK(results[0].name == "Get Hostname");
}

// ── Update Definition ──────────────────────────────────────────────────────

TEST_CASE("InstructionStore: update definition", "[instruction_store]") {
    InstructionStore store(":memory:");

    auto def = make_question("Get Hostname");
    auto id_result = store.create_definition(def);
    REQUIRE(id_result.has_value());

    auto fetched = store.get_definition(*id_result);
    REQUIRE(fetched.has_value());
    fetched->description = "Updated description";
    fetched->enabled = false;

    auto update_result = store.update_definition(*fetched);
    REQUIRE(update_result.has_value());

    auto refetched = store.get_definition(*id_result);
    REQUIRE(refetched.has_value());
    CHECK(refetched->description == "Updated description");
    CHECK(refetched->enabled == false);
}

TEST_CASE("InstructionStore: update nonexistent fails", "[instruction_store]") {
    InstructionStore store(":memory:");

    InstructionDefinition def;
    def.id = "nonexistent-id";
    def.name = "Ghost";
    def.version = "1.0";
    def.plugin = "test";
    def.action = "test";
    def.type = "question";

    auto result = store.update_definition(def);
    CHECK(!result.has_value());
}

// ── Delete Definition ──────────────────────────────────────────────────────

TEST_CASE("InstructionStore: delete definition", "[instruction_store]") {
    InstructionStore store(":memory:");

    auto id_result = store.create_definition(make_question("Get Hostname"));
    REQUIRE(id_result.has_value());

    bool deleted = store.delete_definition(*id_result);
    REQUIRE(deleted);

    auto result = store.get_definition(*id_result);
    CHECK(!result.has_value());
}

TEST_CASE("InstructionStore: delete nonexistent returns false", "[instruction_store]") {
    InstructionStore store(":memory:");
    bool deleted = store.delete_definition("nonexistent-id");
    CHECK(!deleted);
}

// ── Parameter Validation ───────────────────────────────────────────────────

TEST_CASE("InstructionStore: parameter validation — required", "[instruction_store][params]") {
    InstructionStore store(":memory:");

    auto def = make_action("Run Script");
    ParamDef param;
    param.name = "script_path";
    param.type = "string";
    param.required = true;
    def.parameter_schema.push_back(param);
    auto id_result = store.create_definition(def);
    REQUIRE(id_result.has_value());

    // Missing required parameter should fail validation
    std::unordered_map<std::string, std::string> args;
    auto errors = store.validate_parameters(*id_result, args);
    CHECK(!errors.has_value());

    // Providing the required parameter should pass
    args["script_path"] = "/usr/local/bin/cleanup.sh";
    auto errors2 = store.validate_parameters(*id_result, args);
    CHECK(errors2.has_value());
}

TEST_CASE("InstructionStore: parameter validation — choice", "[instruction_store][params]") {
    InstructionStore store(":memory:");

    auto def = make_action("Set Power Plan");
    ParamDef param;
    param.name = "plan";
    param.type = "choice";
    param.required = true;
    param.choices = {"balanced", "performance", "power_saver"};
    def.parameter_schema.push_back(param);
    auto id_result = store.create_definition(def);
    REQUIRE(id_result.has_value());

    // Valid choice
    std::unordered_map<std::string, std::string> args;
    args["plan"] = "balanced";
    auto result1 = store.validate_parameters(*id_result, args);
    CHECK(result1.has_value());

    // Invalid choice
    args["plan"] = "turbo";
    auto result2 = store.validate_parameters(*id_result, args);
    CHECK(!result2.has_value());
}

// ── Import/Export JSON ─────────────────────────────────────────────────────

TEST_CASE("InstructionStore: export and import round-trip", "[instruction_store][json]") {
    InstructionStore store(":memory:");

    auto id_result = store.create_definition(make_question("Get Hostname"));
    REQUIRE(id_result.has_value());

    auto json = store.export_definition_json(*id_result);
    REQUIRE(!json.empty());
    CHECK(json != "{}");

    // Import into same store with different name to avoid uniqueness violation
    // The import creates a new ID, but same name+version will fail
    InstructionStore store2(":memory:");
    auto import_result = store2.import_definition_json(json);
    CHECK(import_result.has_value());
}

TEST_CASE("InstructionStore: import invalid JSON fails", "[instruction_store][json]") {
    InstructionStore store(":memory:");
    auto result = store.import_definition_json("not valid json {{{");
    CHECK(!result.has_value());
}

// ── Instruction Sets ───────────────────────────────────────────────────────

TEST_CASE("InstructionStore: create instruction set", "[instruction_store][sets]") {
    InstructionStore store(":memory:");

    InstructionSet iset;
    iset.name = "Baseline Audit";
    iset.description = "Standard compliance checks";
    auto result = store.create_set(iset);
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("InstructionStore: list instruction sets", "[instruction_store][sets]") {
    InstructionStore store(":memory:");

    InstructionSet s1; s1.name = "Baseline Audit";
    store.create_set(s1);
    InstructionSet s2; s2.name = "Incident Response";
    store.create_set(s2);

    auto sets = store.list_sets();
    REQUIRE(sets.size() == 2);
}

TEST_CASE("InstructionStore: delete instruction set", "[instruction_store][sets]") {
    InstructionStore store(":memory:");

    InstructionSet iset;
    iset.name = "Temporary Set";
    auto result = store.create_set(iset);
    REQUIRE(result.has_value());

    bool deleted = store.delete_set(*result);
    REQUIRE(deleted);

    auto sets = store.list_sets();
    CHECK(sets.empty());
}

TEST_CASE("InstructionStore: definitions_in_set", "[instruction_store][sets]") {
    InstructionStore store(":memory:");

    InstructionSet iset;
    iset.name = "Fleet Overview";
    auto set_result = store.create_set(iset);
    REQUIRE(set_result.has_value());

    auto def1 = make_question("Get Hostname");
    def1.instruction_set_id = *set_result;
    store.create_definition(def1);

    auto def2 = make_question("Get OS Version");
    def2.instruction_set_id = *set_result;
    store.create_definition(def2);

    // Third definition not in set
    store.create_definition(make_question("Get CPU Info"));

    auto defs = store.definitions_in_set(*set_result);
    REQUIRE(defs.size() == 2);
}

TEST_CASE("InstructionStore: set name uniqueness", "[instruction_store][sets]") {
    InstructionStore store(":memory:");

    InstructionSet s1; s1.name = "Same Name";
    auto r1 = store.create_set(s1);
    REQUIRE(r1.has_value());

    InstructionSet s2; s2.name = "Same Name";
    auto r2 = store.create_set(s2);
    CHECK(!r2.has_value());
}
