/**
 * test_instruction_store.cpp — Unit tests for InstructionStore
 *
 * Covers: CRUD definitions, uniqueness, filters, import/export,
 *         instruction sets, extended fields, validation.
 */

#include "instruction_store.hpp"
#include "store_errors.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;

// ── Helpers ─────────────────────────────────────────────────────────────────

static InstructionDefinition make_question(const std::string& name,
                                           const std::string& version = "1.0",
                                           const std::string& plugin = "system_info") {
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

static InstructionDefinition make_action(const std::string& name,
                                         const std::string& version = "1.0",
                                         const std::string& plugin = "remediation") {
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

TEST_CASE("InstructionStore: create with empty name fails", "[instruction_store]") {
    InstructionStore store(":memory:");

    InstructionDefinition def;
    def.name = "";
    def.type = "question";
    def.plugin = "test";
    def.action = "test";
    def.version = "1.0";
    auto result = store.create_definition(def);
    CHECK(!result.has_value());
}

TEST_CASE("InstructionStore: create with invalid type fails", "[instruction_store]") {
    InstructionStore store(":memory:");

    InstructionDefinition def;
    def.name = "Bad";
    def.type = "invalid";
    def.plugin = "test";
    def.action = "test";
    def.version = "1.0";
    auto result = store.create_definition(def);
    CHECK(!result.has_value());
}

// ── ID Uniqueness ─────────────────────────────────────────────────────────

TEST_CASE("InstructionStore: auto-generated IDs are unique", "[instruction_store]") {
    InstructionStore store(":memory:");

    auto result1 = store.create_definition(make_question("Get Hostname", "1.0"));
    REQUIRE(result1.has_value());

    // Same name+version gets a different auto-generated ID
    auto result2 = store.create_definition(make_question("Get Hostname", "1.0"));
    REQUIRE(result2.has_value());
    CHECK(*result1 != *result2);

    // Explicit duplicate ID should fail
    auto def = make_question("Another", "1.0");
    def.id = *result1;
    auto result3 = store.create_definition(def);
    CHECK(!result3.has_value());
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

TEST_CASE("InstructionStore: query by set_id_filter", "[instruction_store]") {
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

    InstructionQuery q;
    q.set_id_filter = *set_result;
    auto results = store.query_definitions(q);
    REQUIRE(results.size() == 2);
}

TEST_CASE("InstructionStore: query with limit", "[instruction_store]") {
    InstructionStore store(":memory:");

    for (int i = 0; i < 10; ++i) {
        auto def = make_question("Def " + std::to_string(i), std::to_string(i) + ".0");
        store.create_definition(def);
    }

    InstructionQuery q;
    q.limit = 3;
    auto results = store.query_definitions(q);
    REQUIRE(results.size() == 3);
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

// ── Import/Export JSON ─────────────────────────────────────────────────────

TEST_CASE("InstructionStore: export and import round-trip", "[instruction_store][json]") {
    InstructionStore store(":memory:");

    auto def = make_question("Get Hostname");
    def.parameter_schema = R"({"type":"object","properties":{"timeout":{"type":"integer"}}})";
    def.result_schema = R"([{"name":"hostname","type":"string"}])";
    auto id_result = store.create_definition(def);
    REQUIRE(id_result.has_value());

    auto json = store.export_definition_json(*id_result);
    REQUIRE(!json.empty());
    CHECK(json != "{}");

    // Import into a fresh store (avoids name+version uniqueness collision)
    InstructionStore store2(":memory:");
    auto import_result = store2.import_definition_json(json);
    REQUIRE(import_result.has_value());

    // Verify the imported definition preserves fields
    auto imported = store2.get_definition(*import_result);
    REQUIRE(imported.has_value());
    CHECK(imported->name == "Get Hostname");
    CHECK(imported->plugin == "system_info");
}

TEST_CASE("InstructionStore: import invalid JSON fails", "[instruction_store][json]") {
    InstructionStore store(":memory:");
    auto result = store.import_definition_json("not valid json {{{");
    CHECK(!result.has_value());
}

TEST_CASE("InstructionStore: export nonexistent returns empty", "[instruction_store][json]") {
    InstructionStore store(":memory:");
    auto json = store.export_definition_json("nonexistent-id");
    CHECK((json.empty() || json == "{}"));
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

    InstructionSet s1;
    s1.name = "Baseline Audit";
    store.create_set(s1);
    InstructionSet s2;
    s2.name = "Incident Response";
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

TEST_CASE("InstructionStore: delete set unsets instruction_set_id on definitions",
          "[instruction_store][sets]") {
    InstructionStore store(":memory:");

    InstructionSet iset;
    iset.name = "Fleet Overview";
    auto set_result = store.create_set(iset);
    REQUIRE(set_result.has_value());

    auto def = make_question("Get Hostname");
    def.instruction_set_id = *set_result;
    auto def_result = store.create_definition(def);
    REQUIRE(def_result.has_value());

    // Delete the set
    bool deleted = store.delete_set(*set_result);
    REQUIRE(deleted);

    // The definition should still exist but with instruction_set_id cleared
    auto fetched = store.get_definition(*def_result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->instruction_set_id.empty());
}

TEST_CASE("InstructionStore: delete nonexistent set returns false", "[instruction_store][sets]") {
    InstructionStore store(":memory:");
    bool deleted = store.delete_set("nonexistent-set-id");
    CHECK(!deleted);
}

// ── Extended Fields ────────────────────────────────────────────────────────

TEST_CASE("InstructionStore: extended fields round-trip", "[instruction_store][extended]") {
    InstructionStore store(":memory:");

    auto def = make_action("Patch Windows");
    def.yaml_source = "name: Patch Windows\ntype: action\n";
    def.parameter_schema = R"({"type":"object","properties":{"kb":{"type":"string"}}})";
    def.result_schema = R"([{"name":"exit_code","type":"int32"},{"name":"reboot","type":"bool"}])";
    def.approval_mode = "role-gated";
    def.concurrency_mode = "per-device";
    def.platforms = "windows";
    def.min_agent_version = "2.1.0";
    def.required_plugins = "windows_update,remediation";
    def.readable_payload = "Install KB ${kb} on target";
    def.created_by = "admin";
    def.gather_ttl_seconds = 600;
    def.response_ttl_days = 180;

    auto id_result = store.create_definition(def);
    REQUIRE(id_result.has_value());

    auto fetched = store.get_definition(*id_result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->yaml_source == def.yaml_source);
    CHECK(fetched->parameter_schema == def.parameter_schema);
    CHECK(fetched->result_schema == def.result_schema);
    CHECK(fetched->approval_mode == "role-gated");
    CHECK(fetched->concurrency_mode == "per-device");
    CHECK(fetched->platforms == "windows");
    CHECK(fetched->min_agent_version == "2.1.0");
    CHECK(fetched->required_plugins == "windows_update,remediation");
    CHECK(fetched->readable_payload == "Install KB ${kb} on target");
    CHECK(fetched->created_by == "admin");
    CHECK(fetched->gather_ttl_seconds == 600);
    CHECK(fetched->response_ttl_days == 180);
}

TEST_CASE("InstructionStore: timestamps set on create", "[instruction_store][extended]") {
    InstructionStore store(":memory:");

    auto def = make_question("Get Hostname");
    auto id_result = store.create_definition(def);
    REQUIRE(id_result.has_value());

    auto fetched = store.get_definition(*id_result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->created_at > 0);
    CHECK(fetched->updated_at > 0);
}

// ── Duplicate-id guard (#402) ──────────────────────────────────────────────

TEST_CASE("InstructionStore: explicit duplicate id rejected with conflict prefix",
          "[instruction_store][duplicate]") {
    InstructionStore store(":memory:");

    auto first = make_question("First", "1.0");
    first.id = "test.os.info";
    auto first_result = store.create_definition(first);
    REQUIRE(first_result.has_value());
    CHECK(*first_result == "test.os.info");

    // Re-using the same explicit id must surface as "conflict:" so the route
    // layer can map it to HTTP 409 instead of the generic 400.
    auto second = make_question("Second", "1.0");
    second.id = "test.os.info";
    auto second_result = store.create_definition(second);
    REQUIRE_FALSE(second_result.has_value());
    CHECK(is_conflict_error(second_result.error()));

    // First definition is unchanged — no silent overwrite.
    auto fetched = store.get_definition("test.os.info");
    REQUIRE(fetched.has_value());
    CHECK(fetched->name == "First");
}

TEST_CASE("InstructionStore: empty id still gets generated UUID with no conflict",
          "[instruction_store][duplicate]") {
    InstructionStore store(":memory:");

    auto a = make_question("Alpha");
    auto b = make_question("Bravo");
    // Both with empty def.id — store generates UUIDs, no duplicate-id path.
    auto ra = store.create_definition(a);
    auto rb = store.create_definition(b);
    REQUIRE(ra.has_value());
    REQUIRE(rb.has_value());
    CHECK(*ra != *rb);
}
