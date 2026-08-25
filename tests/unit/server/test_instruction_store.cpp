/**
 * test_instruction_store.cpp — Unit tests for InstructionStore
 *
 * Migrated-to-Postgres store (ADR-0006/0009/0058, ADR-0012 §1 authoritative/fail-hard). PG-gated:
 * skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set but broken (test_helpers.hpp
 * skip-vs-fail contract). Store-behaviour cases use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7).
 *
 * Covers: CRUD definitions, uniqueness, filters, import/export,
 *         instruction sets, extended fields, validation.
 *
 * The `[instruction_store][seed]`-tagged cases at the end of this file (trusted reseed /
 * seed-vs-live, ADR-0058) are a SEPARATE concern from the rest of this file's mechanical
 * PG-harness conversion — they encode the deliberate Option B behaviour-inversion decision and
 * are maintained as their own section.
 */

#include "instruction_store.hpp"
#include "sqlite_raii.hpp"
#include "store_errors.hpp"

#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <sqlite3.h>

#include <algorithm>
#include <string>

using namespace yuzu::server;
namespace pg = yuzu::server::pg;
using yuzu::server::pg::PgPool;

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

namespace {
yuzu::test::PgTestTemplate instruction_store_tpl{
    "instructionstore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("instruction_store template: store failed to migrate");
    }};

void legacy_exec(sqlite3* db, const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    INFO((err ? err : "no error"));
    REQUIRE(rc == SQLITE_OK);
    if (err)
        sqlite3_free(err);
}

const char* kLegacyDefsSchema =
    "CREATE TABLE instruction_definitions ("
    " id TEXT PRIMARY KEY, name TEXT NOT NULL, version TEXT NOT NULL,"
    " type TEXT NOT NULL, plugin TEXT NOT NULL, action TEXT NOT NULL,"
    " description TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,"
    " instruction_set_id TEXT NOT NULL DEFAULT '', gather_ttl_seconds INTEGER NOT NULL DEFAULT 0,"
    " response_ttl_days INTEGER NOT NULL DEFAULT 0, created_by TEXT NOT NULL DEFAULT '',"
    " created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);";
const char* kLegacySetsSchema =
    "CREATE TABLE instruction_sets ("
    " id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',"
    " created_by TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT 0);";
} // namespace

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("InstructionStore: opens against Postgres", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
}

// ── Create Definition ──────────────────────────────────────────────────────

TEST_CASE("InstructionStore: create question definition", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto def = make_question("Get Hostname");
    auto result = store.create_definition(def);
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("InstructionStore: create action definition", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto def = make_action("Restart Service");
    auto result = store.create_definition(def);
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("InstructionStore: create with empty name fails", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionDefinition def;
    def.name = "";
    def.type = "question";
    def.plugin = "test";
    def.action = "test";
    def.version = "1.0";
    auto result = store.create_definition(def);
    CHECK(!result.has_value());
}

TEST_CASE("InstructionStore: create with invalid type fails", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionDefinition def;
    def.name = "Bad";
    def.type = "invalid";
    def.plugin = "test";
    def.action = "test";
    def.version = "1.0";
    auto result = store.create_definition(def);
    CHECK(!result.has_value());
}

TEST_CASE("InstructionStore: explicit id is bounded to a safe charset", "[instruction_store][pg]") {
    // Explicit ids are operator-controlled (JSON create #402, YAML Save
    // metadata.id #1993) and are interpolated into dashboard fragments,
    // route paths, and audit rows — the store is the single chokepoint that
    // bounds them (governance sec-M1).
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionDefinition def;
    def.name = "Charset Probe";
    def.type = "question";
    def.plugin = "test";
    def.action = "test";
    def.version = "1.0";

    SECTION("dotted canonical id is accepted") {
        def.id = "tutorial.service.inspect_v2-a";
        auto result = store.create_definition(def);
        REQUIRE(result.has_value());
        CHECK(*result == "tutorial.service.inspect_v2-a");
    }
    SECTION("quote/attribute-breakout characters are rejected") {
        def.id = "x' onmouseover='alert(1)";
        auto result = store.create_definition(def);
        REQUIRE(!result.has_value());
        CHECK(result.error() ==
              "definition id may only contain letters, digits, '.', '_', and '-'");
    }
    SECTION("path separators are rejected") {
        def.id = "a/b";
        CHECK(!store.create_definition(def).has_value());
    }
    SECTION("overlong id is rejected") {
        def.id = std::string(129, 'a');
        auto result = store.create_definition(def);
        REQUIRE(!result.has_value());
        CHECK(result.error() == "definition id too long (max 128 characters)");
    }
    SECTION("empty id still store-generates") {
        def.id = "";
        auto result = store.create_definition(def);
        REQUIRE(result.has_value());
        CHECK(!result->empty());
    }
}

TEST_CASE("InstructionStore: the mcp. definition-id namespace is reserved",
          "[instruction_store][security][pg]") {
    // #2442: the MCP approval gate mints tickets under `mcp.<tool>` and its
    // recall matches on (definition_id, scope_expression) without binding the
    // submitter. A definition authored under that prefix is what would let an
    // approval raised on the instruction surface line up with an MCP tool's
    // canonical arguments — so the prefix is refused at the authoring
    // chokepoint as well as at the mint.
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionDefinition def;
    def.name = "Namespace Probe";
    def.type = "question";
    def.plugin = "test";
    def.action = "test";
    def.version = "1.0";

    SECTION("an mcp.-prefixed id is rejected") {
        def.id = "mcp.quarantine_device";
        auto result = store.create_definition(def);
        REQUIRE(!result.has_value());
        CHECK(result.error().find("reserved") != std::string::npos);
    }
    SECTION("only the exact prefix is reserved") {
        def.id = "mcpx.thing"; // no dot boundary — not the MCP namespace
        CHECK(store.create_definition(def).has_value());
    }
}

TEST_CASE("InstructionStore: NUL in yaml_source is rejected at the store chokepoint",
          "[instruction_store][pg]") {
    // libpq's text-format binding is C-string-based, so a NUL-bearing source would silently
    // TRUNCATE the stored value at that point (persisting a blob that diverges from the
    // extracted columns and, on the signed-import path, from the signature-verified bytes).
    // The store rejects it for every surface, not just the dashboard validator (governance
    // UP-2 / Gate 8).
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionDefinition def;
    def.name = "Nul Probe";
    def.type = "question";
    def.plugin = "test";
    def.action = "test";
    def.version = "1.0";
    def.yaml_source = std::string("apiVersion: yuzu.io/v1alpha1\n") + '\0' + "kind: x\n";

    auto result = store.create_definition(def);
    REQUIRE(!result.has_value());
    CHECK(result.error() == "yaml_source contains a NUL byte");
}

// ── spec.scope (scope-walking DSL) validation (PR-E) ────────────────────────

namespace {
InstructionDefinition scoped_def(const std::string& scope_and_assignment) {
    InstructionDefinition def;
    def.name = "Scoped";
    def.type = "action";
    def.plugin = "system_info";
    def.action = "query";
    def.version = "1.0";
    def.yaml_source = "apiVersion: yuzu.io/v1alpha1\n"
                      "kind: InstructionDefinition\n"
                      "spec:\n" +
                      scope_and_assignment;
    return def;
}
} // namespace

TEST_CASE("InstructionStore: spec.scope.fromResultSet with static mode is accepted + round-trips",
          "[instruction_store][scope][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto def = scoped_def("  scope:\n"
                          "    fromResultSet: rs_abc\n"
                          "  assignment:\n"
                          "    mode: static\n");
    auto r = store.create_definition(def);
    REQUIRE(r.has_value());
    auto got = store.get_definition(r.value());
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->yaml_source.find("fromResultSet") != std::string::npos);
}

TEST_CASE("InstructionStore: spec.scope.fromResultSet with dynamic mode is rejected",
          "[instruction_store][scope][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_definition(scoped_def("  scope:\n"
                                                "    fromResultSet: rs_abc\n"
                                                "  assignment:\n"
                                                "    mode: dynamic\n"));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("requires assignment.mode: static") != std::string::npos);
}

TEST_CASE("InstructionStore: update_definition enforces the same scope validation (arch-B1)",
          "[instruction_store][scope][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    // Create a clean definition...
    auto def = scoped_def("  scope:\n    fromResultSet: rs_abc\n  assignment:\n    mode: static\n");
    auto created = store.create_definition(def);
    REQUIRE(created.has_value());
    // ...then try to edit in a forbidden dynamic-mode combo: must be rejected,
    // not silently stored (the bypass governance arch-B1/UP-4 closed).
    InstructionDefinition edit = def;
    edit.id = created.value();
    edit.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nspec:\n"
                       "  scope:\n    fromResultSet: rs_abc\n  assignment:\n    mode: dynamic\n";
    auto updated = store.update_definition(edit);
    REQUIRE_FALSE(updated.has_value());
    CHECK(updated.error().find("requires assignment.mode: static") != std::string::npos);
}

TEST_CASE("InstructionStore: inline flow-mapping scope is rejected (UP-6)",
          "[instruction_store][scope][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionDefinition def;
    def.name = "Inline";
    def.type = "action";
    def.plugin = "system_info";
    def.action = "query";
    def.version = "1.0";
    def.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nspec:\n"
                      "  scope: {fromResultSet: rs_abc}\n";
    auto r = store.create_definition(def);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("inline flow-mapping") != std::string::npos);
}

TEST_CASE("InstructionStore: spec.scope.fromResultSet + assignment.managementGroups is rejected",
          "[instruction_store][scope][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_definition(scoped_def("  scope:\n"
                                                "    fromResultSet: rs_abc\n"
                                                "  assignment:\n"
                                                "    managementGroups:\n"
                                                "      - all-devices\n"));
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().find("cannot be combined with assignment.managementGroups") !=
          std::string::npos);
}

TEST_CASE("InstructionStore: a scope-less definition is unaffected by PR-E validation",
          "[instruction_store][scope][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    CHECK(store.create_definition(make_question("Plain")).has_value());
}

// ── ID Uniqueness ─────────────────────────────────────────────────────────

TEST_CASE("InstructionStore: auto-generated IDs are unique", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

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

TEST_CASE("InstructionStore: get definition by ID", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto def = make_question("Get Hostname");
    def.description = "Returns the machine hostname";
    auto result = store.create_definition(def);
    REQUIRE(result.has_value());

    auto fetched = store.get_definition(*result);
    REQUIRE(fetched.has_value());
    REQUIRE(fetched->has_value());
    CHECK((*fetched)->name == "Get Hostname");
    CHECK((*fetched)->version == "1.0");
    CHECK((*fetched)->plugin == "system_info");
    CHECK((*fetched)->type == "question");
    CHECK((*fetched)->description == "Returns the machine hostname");
    CHECK((*fetched)->enabled == true);
}

TEST_CASE("InstructionStore: get nonexistent returns empty", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.get_definition("nonexistent-id");
    REQUIRE(result.has_value()); // successful read...
    CHECK_FALSE(result->has_value()); // ...that found nothing
}

// ── Query with Filters ─────────────────────────────────────────────────────

TEST_CASE("InstructionStore: query all definitions", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    store.create_definition(make_question("Get Hostname"));
    store.create_definition(make_action("Restart Service"));
    store.create_definition(make_question("Get OS Version"));

    auto results = store.query_definitions();
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 3);
}

TEST_CASE("InstructionStore: query by name filter", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    store.create_definition(make_question("Get Hostname"));
    store.create_definition(make_question("Get OS Version"));
    store.create_definition(make_action("Restart Service"));

    InstructionQuery q;
    q.name_filter = "Hostname";
    auto results = store.query_definitions(q);
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].name == "Get Hostname");
}

TEST_CASE("InstructionStore: query by plugin filter", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    store.create_definition(make_question("Get Hostname", "1.0", "system_info"));
    store.create_definition(make_action("Restart Service", "1.0", "remediation"));
    store.create_definition(make_question("Get CPU Info", "1.0", "system_info"));

    InstructionQuery q;
    q.plugin_filter = "system_info";
    auto results = store.query_definitions(q);
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 2);
}

TEST_CASE("InstructionStore: query by type filter", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    store.create_definition(make_question("Get Hostname"));
    store.create_definition(make_action("Restart Service"));
    store.create_definition(make_action("Kill Process"));

    InstructionQuery q;
    q.type_filter = "action";
    auto results = store.query_definitions(q);
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 2);
}

TEST_CASE("InstructionStore: query enabled_only filter", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto def1 = make_question("Get Hostname");
    def1.enabled = true;
    store.create_definition(def1);

    auto def2 = make_question("Get OS Version");
    def2.enabled = false;
    store.create_definition(def2);

    InstructionQuery q;
    q.enabled_only = true;
    auto results = store.query_definitions(q);
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].name == "Get Hostname");
}

TEST_CASE("InstructionStore: query by set_id_filter", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

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
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 2);
}

TEST_CASE("InstructionStore: query with limit", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    for (int i = 0; i < 10; ++i) {
        auto def = make_question("Def " + std::to_string(i), std::to_string(i) + ".0");
        store.create_definition(def);
    }

    InstructionQuery q;
    q.limit = 3;
    auto results = store.query_definitions(q);
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 3);
}

// ── Update Definition ──────────────────────────────────────────────────────

TEST_CASE("InstructionStore: update definition", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto def = make_question("Get Hostname");
    auto id_result = store.create_definition(def);
    REQUIRE(id_result.has_value());

    auto fetched = store.get_definition(*id_result);
    REQUIRE(fetched.has_value());
    REQUIRE(fetched->has_value());
    (*fetched)->description = "Updated description";
    (*fetched)->enabled = false;

    auto update_result = store.update_definition(**fetched);
    REQUIRE(update_result.has_value());

    auto refetched = store.get_definition(*id_result);
    REQUIRE(refetched.has_value());
    REQUIRE(refetched->has_value());
    CHECK((*refetched)->description == "Updated description");
    CHECK((*refetched)->enabled == false);
}

TEST_CASE("InstructionStore: update nonexistent fails", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

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

TEST_CASE("InstructionStore: delete definition", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto id_result = store.create_definition(make_question("Get Hostname"));
    REQUIRE(id_result.has_value());

    auto deleted = store.delete_definition(*id_result);
    REQUIRE(deleted.has_value());

    auto result = store.get_definition(*id_result);
    REQUIRE(result.has_value());
    CHECK_FALSE(result->has_value());
}

TEST_CASE("InstructionStore: delete nonexistent returns not_found", "[instruction_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto deleted = store.delete_definition("nonexistent-id");
    REQUIRE_FALSE(deleted.has_value());
    CHECK(deleted.error().starts_with("not_found:"));
}

// ── Import/Export JSON ─────────────────────────────────────────────────────

TEST_CASE("InstructionStore: export and import round-trip", "[instruction_store][json][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto def = make_question("Get Hostname");
    def.parameter_schema = R"({"type":"object","properties":{"timeout":{"type":"integer"}}})";
    def.result_schema = R"([{"name":"hostname","type":"string"}])";
    auto id_result = store.create_definition(def);
    REQUIRE(id_result.has_value());

    auto json = store.export_definition_json(*id_result);
    REQUIRE(json.has_value());
    REQUIRE(!json->empty());
    CHECK(*json != "{}");

    // Import into a fresh, separately-cloned store (avoids name+version uniqueness collision).
    YUZU_REQUIRE_PG_DB_TPL(db2, instruction_store_tpl);
    PgPool pool2{{.conninfo = db2.dsn(), .size = 2}};
    InstructionStore store2{pool2};
    REQUIRE(store2.is_open());
    // #1073: opt out of signature enforcement — this test exercises
    // import-round-trip, not the signature gate.
    store2.set_require_signed_definitions(false);
    auto import_result = store2.import_definition_json(*json);
    REQUIRE(import_result.has_value());

    // Verify the imported definition preserves fields
    auto imported = store2.get_definition(*import_result);
    REQUIRE(imported.has_value());
    REQUIRE(imported->has_value());
    CHECK((*imported)->name == "Get Hostname");
    CHECK((*imported)->plugin == "system_info");
}

TEST_CASE("InstructionStore: import invalid JSON fails", "[instruction_store][json][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.import_definition_json("not valid json {{{");
    CHECK(!result.has_value());
}

TEST_CASE("InstructionStore: export nonexistent returns empty", "[instruction_store][json][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto json = store.export_definition_json("nonexistent-id");
    REQUIRE(json.has_value()); // successful read finding nothing, not a DB error
    CHECK(*json == "{}");
}

// ── Instruction Sets ───────────────────────────────────────────────────────

TEST_CASE("InstructionStore: create instruction set", "[instruction_store][sets][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionSet iset;
    iset.name = "Baseline Audit";
    iset.description = "Standard compliance checks";
    auto result = store.create_set(iset);
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("InstructionStore: list instruction sets", "[instruction_store][sets][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionSet s1;
    s1.name = "Baseline Audit";
    store.create_set(s1);
    InstructionSet s2;
    s2.name = "Incident Response";
    store.create_set(s2);

    auto sets = store.list_sets();
    REQUIRE(sets.has_value());
    REQUIRE(sets->size() == 2);
}

TEST_CASE("InstructionStore: delete instruction set", "[instruction_store][sets][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionSet iset;
    iset.name = "Temporary Set";
    auto result = store.create_set(iset);
    REQUIRE(result.has_value());

    auto deleted = store.delete_set(*result);
    REQUIRE(deleted.has_value());

    auto sets = store.list_sets();
    REQUIRE(sets.has_value());
    CHECK(sets->empty());
}

TEST_CASE("InstructionStore: delete set unsets instruction_set_id on definitions",
          "[instruction_store][sets][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionSet iset;
    iset.name = "Fleet Overview";
    auto set_result = store.create_set(iset);
    REQUIRE(set_result.has_value());

    auto def = make_question("Get Hostname");
    def.instruction_set_id = *set_result;
    auto def_result = store.create_definition(def);
    REQUIRE(def_result.has_value());

    // Delete the set
    auto deleted = store.delete_set(*set_result);
    REQUIRE(deleted.has_value());

    // The definition should still exist but with instruction_set_id cleared
    auto fetched = store.get_definition(*def_result);
    REQUIRE(fetched.has_value());
    REQUIRE(fetched->has_value());
    CHECK((*fetched)->instruction_set_id.empty());
}

TEST_CASE("InstructionStore: delete nonexistent set returns not_found",
          "[instruction_store][sets][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto deleted = store.delete_set("nonexistent-set-id");
    REQUIRE_FALSE(deleted.has_value());
    CHECK(deleted.error().starts_with("not_found:"));
}

TEST_CASE("InstructionStore: delete nonexistent set must not mutate definitions that happen to "
          "reference that id (not_found must be a pure no-op)",
          "[instruction_store][sets][pg]") {
    // Regression pin for a data-integrity bug: delete_set used to unlink
    // instruction_set_id on referencing definitions BEFORE checking whether the
    // set actually existed, so a not-found delete (typo, stale id, or a
    // deliberate probe) could still silently commit the unlink.
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto def = make_question("Get Hostname");
    def.instruction_set_id = "typo-set-id-that-was-never-created";
    auto def_result = store.create_definition(def);
    REQUIRE(def_result.has_value());

    auto deleted = store.delete_set("typo-set-id-that-was-never-created");
    REQUIRE_FALSE(deleted.has_value());
    CHECK(deleted.error().starts_with("not_found:"));

    auto fetched = store.get_definition(*def_result);
    REQUIRE(fetched.has_value());
    REQUIRE(fetched->has_value());
    CHECK((*fetched)->instruction_set_id == "typo-set-id-that-was-never-created");
}

// ── Extended Fields ────────────────────────────────────────────────────────

TEST_CASE("InstructionStore: extended fields round-trip", "[instruction_store][extended][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

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
    REQUIRE(fetched->has_value());
    CHECK((*fetched)->yaml_source == def.yaml_source);
    CHECK((*fetched)->parameter_schema == def.parameter_schema);
    CHECK((*fetched)->result_schema == def.result_schema);
    CHECK((*fetched)->approval_mode == "role-gated");
    CHECK((*fetched)->concurrency_mode == "per-device");
    CHECK((*fetched)->platforms == "windows");
    CHECK((*fetched)->min_agent_version == "2.1.0");
    CHECK((*fetched)->required_plugins == "windows_update,remediation");
    CHECK((*fetched)->readable_payload == "Install KB ${kb} on target");
    CHECK((*fetched)->created_by == "admin");
    CHECK((*fetched)->gather_ttl_seconds == 600);
    CHECK((*fetched)->response_ttl_days == 180);
}

TEST_CASE("InstructionStore: timestamps set on create", "[instruction_store][extended][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto def = make_question("Get Hostname");
    auto id_result = store.create_definition(def);
    REQUIRE(id_result.has_value());

    auto fetched = store.get_definition(*id_result);
    REQUIRE(fetched.has_value());
    REQUIRE(fetched->has_value());
    CHECK((*fetched)->created_at > 0);
    CHECK((*fetched)->updated_at > 0);
}

// ── Duplicate-id guard (#402) ──────────────────────────────────────────────

TEST_CASE("InstructionStore: explicit duplicate id rejected with conflict prefix",
          "[instruction_store][duplicate][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

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
    REQUIRE(fetched->has_value());
    CHECK((*fetched)->name == "First");
}

TEST_CASE("InstructionStore: empty id still gets generated UUID with no conflict",
          "[instruction_store][duplicate][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_question("Alpha");
    auto b = make_question("Bravo");
    // Both with empty def.id — store generates UUIDs, no duplicate-id path.
    auto ra = store.create_definition(a);
    auto rb = store.create_definition(b);
    REQUIRE(ra.has_value());
    REQUIRE(rb.has_value());
    CHECK(*ra != *rb);
}

// Governance Gate 4 C-B1 / arch-B1 / QE-B2 regression — pin the contract
// the boot-time auto-import loop in server.cpp depends on. Both
// import_definition_json and create_set MUST return kConflictPrefix-
// prefixed errors on duplicate id; substring matches like "already exists"
// are NOT the contract.
TEST_CASE("InstructionStore: kConflictPrefix has the documented literal value",
          "[instruction_store][duplicate]") {
    // Pin the LITERAL VALUE, not just the identifier. Governance Gate 4
    // UP-11: a future refactor that "fixes" the constant from "conflict:"
    // to e.g. "already exists:" would move both the producer (store) and
    // every consumer-side find(kConflictPrefix) test in lock-step, leaving
    // no test failure — but the auto-import loop in server.cpp also uses
    // is_conflict_error() and would silently regress if a third consumer
    // used a substring match. Pinning the literal here is the only way to
    // detect a constant rename that drops the documented prefix shape.
    //
    // No PG dependency — pure constant check, no store construction.
    CHECK(std::string_view(kConflictPrefix) == "conflict:");
}

TEST_CASE("InstructionStore: import_definition_json duplicate uses kConflictPrefix",
          "[instruction_store][duplicate][import][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());
    // #1073: this test pins the duplicate-import error contract for the
    // boot-time auto-import flow; opt out of signature enforcement so the
    // unsigned envelope below isn't pre-emptively rejected.
    store.set_require_signed_definitions(false);

    const std::string envelope = R"({
        "id":"test.import.dup",
        "name":"Test Import Dup",
        "version":"1.0",
        "type":"question",
        "plugin":"os_info",
        "action":"os_name",
        "yaml_source":"---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  id: test.import.dup\n  displayName: Test Import Dup\n"
    })";

    auto first = store.import_definition_json(envelope);
    REQUIRE(first.has_value());

    auto second = store.import_definition_json(envelope);
    REQUIRE_FALSE(second.has_value());
    INFO("actual error: " << second.error()); // Catch2 prints only on failure
    CHECK(is_conflict_error(second.error())); // contract for boot-time auto-import
    CHECK(second.error().find(kConflictPrefix) == 0);
}

TEST_CASE("InstructionStore: create_set duplicate uses kConflictPrefix",
          "[instruction_store][duplicate][set][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionSet s;
    s.id = "test.set.dup";
    s.name = "Test Set Dup";
    s.created_by = "test";

    auto first = store.create_set(s);
    REQUIRE(first.has_value());
    CHECK(*first == "test.set.dup");

    auto second = store.create_set(s);
    REQUIRE_FALSE(second.has_value());
    // Pre-fix this returned "insert failed: UNIQUE constraint failed: ..."
    // — the boot-time auto-import substring-matched "already exists" and
    // miscounted every reboot's bundled sets as `errored`. Pin the
    // kConflictPrefix contract so a future refactor cannot regress it.
    INFO("actual error: " << second.error()); // Catch2 prints only on failure
    CHECK(is_conflict_error(second.error()));
    CHECK(second.error().find(kConflictPrefix) == 0);
}

// ── Trusted reseed / seed-vs-live (ADR-0058 pin) ────────────────────────────
//
// PostgreSQL migration prep (ADR-0058): these tests PIN the CURRENT SQLite
// boot-reseed contract exercised by server.cpp's kBundledDefinitions loop
// (each envelope re-imported via import_definition_json_trusted on every
// boot; id-existence conflict = silent skip, never a merge). The Postgres
// port must reproduce this EXACT behaviour under N concurrent replicas —
// see the kickoff doc's "seed-vs-live semantics preserved exactly"
// requirement. These tests assert what the store DOES today, not what it
// SHOULD do, so a behaviour change during the port is a deliberate,
// ADR-recorded decision rather than an accidental regression.
//
// Notably: the store's seed-vs-live signal for a LIVE row is id existence,
// preserving an operator's in-place EDIT (case 2 below). Deletion is
// DIFFERENT: ADR-0058 made it an intentional suppression (`deleted_seed_content`,
// consulted only by the trusted-reseed insert path and the backfill) rather
// than a plain DELETE the every-boot reseed loop could silently undo — this
// is a DELIBERATE BEHAVIOUR CHANGE from the pre-migration SQLite store, which
// resurrected an operator-deleted bundled definition on the very next boot
// (see docs/adr/0058-instruction-store-postgres-migration.md for the full
// reasoning and the independent-model consult that informed the decision).
// Case 3 below asserts the NEW behaviour, not the old one.

namespace {
yuzu::test::PgTestTemplate instruction_store_seed_tpl{
    "instrstoreseed", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("instruction_store_seed template: store failed to migrate");
    }};
} // namespace

TEST_CASE("InstructionStore: trusted reseed of an untouched bundled definition "
          "is a conflict-skip, not a re-import",
          "[instruction_store][seed][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_seed_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    const std::string envelope = R"({
        "id":"bundled.seed.probe",
        "name":"Bundled Seed Probe",
        "version":"1.0",
        "type":"question",
        "plugin":"os_info",
        "action":"os_name",
        "description":"original bundled description",
        "yaml_source":"---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  id: bundled.seed.probe\n"
    })";

    // First boot: bundled content imports as trusted, unsigned content.
    auto first = store.import_definition_json_trusted(envelope);
    REQUIRE(first.has_value());
    CHECK(*first == "bundled.seed.probe");

    // Second boot replays the SAME bundled envelope (server.cpp does this on
    // every startup, unconditionally, for every entry in kBundledDefinitions).
    auto second = store.import_definition_json_trusted(envelope);
    REQUIRE_FALSE(second.has_value());
    CHECK(is_conflict_error(second.error()));
}

TEST_CASE("InstructionStore: trusted reseed does not clobber an operator edit to a "
          "bundled definition",
          "[instruction_store][seed][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_seed_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    const std::string envelope = R"({
        "id":"bundled.seed.probe",
        "name":"Bundled Seed Probe",
        "version":"1.0",
        "type":"question",
        "plugin":"os_info",
        "action":"os_name",
        "description":"original bundled description",
        "yaml_source":"---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  id: bundled.seed.probe\n"
    })";
    auto seeded = store.import_definition_json_trusted(envelope);
    REQUIRE(seeded.has_value());

    // Operator edits the seeded definition in place (e.g. dashboard YAML Save).
    auto live = store.get_definition(*seeded);
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    InstructionDefinition edited = **live;
    edited.description = "operator-edited description";
    REQUIRE(store.update_definition(edited).has_value());

    // Next boot replays the SAME bundled envelope — must not clobber the edit.
    auto reseed = store.import_definition_json_trusted(envelope);
    REQUIRE_FALSE(reseed.has_value());
    CHECK(is_conflict_error(reseed.error()));

    auto after = store.get_definition(*seeded);
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->description == "operator-edited description");
}

TEST_CASE("InstructionStore: trusted reseed does NOT resurrect an operator-deleted "
          "bundled definition (ADR-0058 — deliberate behaviour change from the "
          "pre-migration SQLite store)",
          "[instruction_store][seed][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_seed_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    const std::string envelope = R"({
        "id":"bundled.seed.probe",
        "name":"Bundled Seed Probe",
        "version":"1.0",
        "type":"question",
        "plugin":"os_info",
        "action":"os_name",
        "description":"original bundled description",
        "yaml_source":"---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  id: bundled.seed.probe\n"
    })";
    auto seeded = store.import_definition_json_trusted(envelope);
    REQUIRE(seeded.has_value());

    // Operator deletes the seeded definition outright — this stamps
    // deleted_seed_content(kind='definition', id='bundled.seed.probe') in the
    // same transaction as the delete (ADR-0058).
    REQUIRE(store.delete_definition(*seeded).has_value());
    auto gone = store.get_definition(*seeded);
    REQUIRE(gone.has_value());
    CHECK_FALSE(gone->has_value());

    // Next boot replays the SAME bundled envelope against the now-vacant id.
    // Pre-migration this resurrected the row (id-existence-only check); the
    // tombstone now suppresses it — the reseed reports the SAME conflict-skip
    // shape as an untouched row, and the id stays deleted.
    auto reseed = store.import_definition_json_trusted(envelope);
    REQUIRE_FALSE(reseed.has_value());
    CHECK(is_conflict_error(reseed.error()));

    auto still_gone = store.get_definition("bundled.seed.probe");
    REQUIRE(still_gone.has_value());
    CHECK_FALSE(still_gone->has_value());
}

TEST_CASE("InstructionStore: trusted reseed of a CHANGED bundled envelope (release "
          "upgrade) never updates an existing row, operator-touched or not",
          "[instruction_store][seed][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_seed_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    const std::string v1_envelope = R"({
        "id":"bundled.seed.probe",
        "name":"Bundled Seed Probe",
        "version":"1.0",
        "type":"question",
        "plugin":"os_info",
        "action":"os_name",
        "description":"v1 bundled description",
        "yaml_source":"---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  id: bundled.seed.probe\n  version: v1\n"
    })";
    // A later release ships changed bundled content for the SAME id — this
    // is the upgrade path the kickoff doc calls out as part of the same
    // decision as seed-vs-live. Only description/yaml_source differ.
    const std::string v2_envelope = R"({
        "id":"bundled.seed.probe",
        "name":"Bundled Seed Probe",
        "version":"1.0",
        "type":"question",
        "plugin":"os_info",
        "action":"os_name",
        "description":"v2 bundled description, release upgrade",
        "yaml_source":"---\napiVersion: yuzu.io/v1alpha1\nkind: InstructionDefinition\nmetadata:\n  id: bundled.seed.probe\n  version: v2\n"
    })";

    auto seeded = store.import_definition_json_trusted(v1_envelope);
    REQUIRE(seeded.has_value());

    // Case (a): row untouched by any operator. A release upgrade replays the
    // CHANGED envelope on next boot — still a conflict-skip (id-only check),
    // so the untouched row stays frozen at v1 content.
    auto upgrade_untouched = store.import_definition_json_trusted(v2_envelope);
    REQUIRE_FALSE(upgrade_untouched.has_value());
    CHECK(is_conflict_error(upgrade_untouched.error()));
    auto after_untouched = store.get_definition(*seeded);
    REQUIRE(after_untouched.has_value());
    REQUIRE(after_untouched->has_value());
    CHECK((*after_untouched)->description == "v1 bundled description");

    // Case (b): operator has since edited the row. Same outcome — the
    // upgrade's changed content still cannot reach an existing id.
    auto live = store.get_definition(*seeded);
    REQUIRE(live.has_value());
    REQUIRE(live->has_value());
    InstructionDefinition edited = **live;
    edited.description = "operator-edited description";
    REQUIRE(store.update_definition(edited).has_value());

    auto upgrade_edited = store.import_definition_json_trusted(v2_envelope);
    REQUIRE_FALSE(upgrade_edited.has_value());
    CHECK(is_conflict_error(upgrade_edited.error()));
    auto after_edited = store.get_definition(*seeded);
    REQUIRE(after_edited.has_value());
    REQUIRE(after_edited->has_value());
    CHECK((*after_edited)->description == "operator-edited description");
}

// ── create_set_seed / delete_set tombstone (ADR-0058) ───────────────────────
//
// Mirrors the definitions coverage above for the set-side seed-aware entry
// point — a genuinely new code path (no pre-migration equivalent existed:
// the every-boot kBundledSets loop called plain create_set, which never
// resurrected a deleted set only because the pre-migration store never
// tombstoned deletes at all).

TEST_CASE("InstructionStore: create_set_seed of an untouched bundled set is a "
          "conflict-skip, not a re-create",
          "[instruction_store][seed][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_seed_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionSet s;
    s.id = "bundled.seed.set";
    s.name = "Bundled Seed Set";
    s.created_by = "system";

    auto first = store.create_set_seed(s);
    REQUIRE(first.has_value());
    CHECK(*first == "bundled.seed.set");

    auto second = store.create_set_seed(s);
    REQUIRE_FALSE(second.has_value());
    CHECK(is_conflict_error(second.error()));
}

TEST_CASE("InstructionStore: create_set_seed does NOT resurrect an operator-deleted "
          "bundled set (ADR-0058)",
          "[instruction_store][seed][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_seed_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionSet s;
    s.id = "bundled.seed.set.deleted";
    s.name = "Bundled Seed Set (deleted)";
    s.created_by = "system";

    auto seeded = store.create_set_seed(s);
    REQUIRE(seeded.has_value());

    // Operator deletes the seeded set outright — stamps
    // deleted_seed_content(kind='set', id=...) in the same transaction.
    REQUIRE(store.delete_set(*seeded).has_value());
    auto sets_after_delete = store.list_sets();
    REQUIRE(sets_after_delete.has_value());
    for (const auto& stored : *sets_after_delete)
        CHECK(stored.id != "bundled.seed.set.deleted");

    // Next boot replays the same bundled set — must stay suppressed.
    auto reseed = store.create_set_seed(s);
    REQUIRE_FALSE(reseed.has_value());
    CHECK(is_conflict_error(reseed.error()));

    auto sets_after_reseed = store.list_sets();
    REQUIRE(sets_after_reseed.has_value());
    for (const auto& stored : *sets_after_reseed)
        CHECK(stored.id != "bundled.seed.set.deleted");
}

TEST_CASE("InstructionStore: plain create_set (operator path) is unaffected by a "
          "bundled-set tombstone",
          "[instruction_store][seed][pg]") {
    // The tombstone is consulted ONLY by the seed-aware path — an operator
    // must be able to freely (re)create a set under any id, including one
    // that was previously bundled-and-deleted (ADR-0058 "Locking": plain
    // create_set never touches deleted_seed_content).
    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_seed_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    InstructionSet s;
    s.id = "bundled.seed.set.reclaimed";
    s.name = "Reclaimed Set";
    s.created_by = "system";

    REQUIRE(store.create_set_seed(s).has_value());
    REQUIRE(store.delete_set(s.id).has_value());

    // Operator (not the boot loop) recreates a set under the same, previously
    // bundled-and-deleted id — plain create_set must succeed normally.
    InstructionSet reclaimed;
    reclaimed.id = s.id;
    reclaimed.name = "Operator-Recreated Set";
    reclaimed.created_by = "operator";
    auto recreated = store.create_set(reclaimed);
    REQUIRE(recreated.has_value());
    CHECK(*recreated == s.id);
}

// ── Backfill (ADR-0009/0058) — multi-replica bundled-content divergence ─────
//
// Bundled (build-time-embedded) definitions/sets carry NO created_at in their source YAML —
// insert_definition_row/create_set_seed stamp it as "now" at whatever wall-clock moment THIS
// replica first seeds it into ITS OWN legacy instructions.db, pre-migration. Two independently
// -provisioned replicas' legacy files therefore legitimately hold DIFFERENT created_at (and, for
// sets, potentially different name/description across release vintages — pinned test 4 above)
// for the SAME bundled id. Treating created_at (or, for sets, the full row) as write-once IDENTITY
// during backfill made every replica after the first brick its boot on this entirely benign
// divergence. This is a regression pin for that fix — verified red against the pre-fix code.

TEST_CASE("InstructionStore::migrate_from_sqlite: two independently-provisioned replicas' legacy "
          "files with a shared bundled id and DIVERGENT created_at is a benign no-op, not a "
          "fail-closed error",
          "[instruction_store][backfill][pg]") {
    yuzu::test::TempDbFile legacy_a{std::string_view{"instr-legacy-conflict-a-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_a.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(), kLegacyDefsSchema);
        legacy_exec(db.get(), kLegacySetsSchema);
        // A bundled definition as replica A's own legacy file recorded it: no created_by
        // (matches real bundled content, which never specifies one), created_at = replica A's
        // own historical first-seed time.
        legacy_exec(db.get(),
                    "INSERT INTO instruction_definitions (id, name, version, type, plugin, "
                    "action, description, enabled, instruction_set_id, gather_ttl_seconds, "
                    "response_ttl_days, created_by, created_at, updated_at) VALUES "
                    "('bundled.shared.id', 'Shared Bundled Def', '1.0', 'question', 'sysinfo', "
                    "'query', 'desc', 1, '', 0, 0, '', 1700000000, 1700000000);");
    }
    yuzu::test::TempDbFile legacy_b{std::string_view{"instr-legacy-conflict-b-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_b.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(), kLegacyDefsSchema);
        legacy_exec(db.get(), kLegacySetsSchema);
        // Same id, same created_by (""), but a DIFFERENT created_at — replica B independently
        // seeded this same bundled definition at its own, later, first-boot time.
        legacy_exec(db.get(),
                    "INSERT INTO instruction_definitions (id, name, version, type, plugin, "
                    "action, description, enabled, instruction_set_id, gather_ttl_seconds, "
                    "response_ttl_days, created_by, created_at, updated_at) VALUES "
                    "('bundled.shared.id', 'Shared Bundled Def', '1.0', 'question', 'sysinfo', "
                    "'query', 'desc', 1, '', 0, 0, '', 1800000000, 1800000000);");
        // An unrelated row so this file's fingerprint differs from legacy_a's (otherwise
        // whole-file fingerprint dedup would skip legacy_b before ever reaching the per-row
        // conflict path this test targets).
        legacy_exec(db.get(),
                    "INSERT INTO instruction_definitions (id, name, version, type, plugin, "
                    "action, description, enabled, instruction_set_id, gather_ttl_seconds, "
                    "response_ttl_days, created_by, created_at, updated_at) VALUES "
                    "('b.only.def', 'B-Only Def', '1.0', 'question', 'sysinfo', 'query', 'desc', "
                    "1, '', 0, 0, '', 1800000000, 1800000000);");
    }

    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.migrate_from_sqlite(legacy_a.path));
    // Replica B's own backfill against its own, independently-diverged legacy file must NOT
    // brick its boot.
    REQUIRE(store.migrate_from_sqlite(legacy_b.path));

    // Postgres's already-committed row (from replica A, the first writer) wins — replica B's
    // backfill neither overwrites it nor fails.
    auto shared = store.get_definition("bundled.shared.id");
    REQUIRE(shared.has_value());
    REQUIRE(shared->has_value());
    CHECK((*shared)->created_at == 1700000000);

    auto b_only = store.get_definition("b.only.def");
    REQUIRE(b_only.has_value());
    REQUIRE(b_only->has_value());
}

TEST_CASE("InstructionStore::migrate_from_sqlite: two replicas' legacy files with a shared "
          "bundled set id and a DIFFERENT description (release-vintage content change) is a "
          "benign no-op, not a fail-closed error",
          "[instruction_store][backfill][pg]") {
    yuzu::test::TempDbFile legacy_a{std::string_view{"instr-legacy-set-conflict-a-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_a.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(), kLegacyDefsSchema);
        legacy_exec(db.get(), kLegacySetsSchema);
        legacy_exec(db.get(),
                    "INSERT INTO instruction_sets (id, name, description, created_by, "
                    "created_at) VALUES ('bundled.shared.set', 'Shared Set', 'v1 description', "
                    "'system', 1700000000);");
    }
    yuzu::test::TempDbFile legacy_b{std::string_view{"instr-legacy-set-conflict-b-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_b.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(), kLegacyDefsSchema);
        legacy_exec(db.get(), kLegacySetsSchema);
        // Same id, same created_by ("system", the bundled-set default), but the description
        // (and created_at) differ — replica B seeded this set under a later release vintage
        // whose shipped content had a different description (the same class pinned test 4
        // established for definitions).
        legacy_exec(db.get(),
                    "INSERT INTO instruction_sets (id, name, description, created_by, "
                    "created_at) VALUES ('bundled.shared.set', 'Shared Set', 'v2 description', "
                    "'system', 1800000000);");
        legacy_exec(db.get(),
                    "INSERT INTO instruction_sets (id, name, description, created_by, "
                    "created_at) VALUES ('b.only.set', 'B-Only Set', 'desc', 'system', "
                    "1800000000);");
    }

    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.migrate_from_sqlite(legacy_a.path));
    REQUIRE(store.migrate_from_sqlite(legacy_b.path));

    auto shared = store.list_sets();
    REQUIRE(shared.has_value());
    auto it = std::find_if(shared->begin(), shared->end(),
                           [](const InstructionSet& s) { return s.id == "bundled.shared.set"; });
    REQUIRE(it != shared->end());
    // Postgres's already-committed row (replica A's) wins.
    CHECK(it->description == "v1 description");
    CHECK(it->created_at == 1700000000);
}

TEST_CASE("InstructionStore::migrate_from_sqlite: two replicas' legacy files sharing an "
          "OPERATOR-authored (non-sentinel created_by) definition id with DRIFTED yaml_source "
          "fails closed — this is NOT bundle-vintage drift",
          "[instruction_store][backfill][pg]") {
    yuzu::test::TempDbFile legacy_a{std::string_view{"instr-legacy-op-conflict-a-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_a.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(), kLegacyDefsSchema);
        legacy_exec(db.get(), kLegacySetsSchema);
        legacy_exec(db.get(), "ALTER TABLE instruction_definitions ADD COLUMN yaml_source TEXT "
                              "NOT NULL DEFAULT '';");
        // A hand-authored definition, as replica A's legacy file recorded it: real operator
        // created_by, real yaml_source content.
        legacy_exec(db.get(),
                    "INSERT INTO instruction_definitions (id, name, version, type, plugin, "
                    "action, description, enabled, instruction_set_id, gather_ttl_seconds, "
                    "response_ttl_days, created_by, created_at, updated_at, yaml_source) VALUES "
                    "('operator.shared.id', 'Shared Operator Def', '1.0', 'question', 'sysinfo', "
                    "'query', 'desc', 1, '', 0, 0, 'admin', 1700000000, 1700000000, "
                    "'scope: {}\nversion: 1');");
    }
    yuzu::test::TempDbFile legacy_b{std::string_view{"instr-legacy-op-conflict-b-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_b.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(), kLegacyDefsSchema);
        legacy_exec(db.get(), kLegacySetsSchema);
        legacy_exec(db.get(), "ALTER TABLE instruction_definitions ADD COLUMN yaml_source TEXT "
                              "NOT NULL DEFAULT '';");
        // Same id, same created_by ('admin', NOT the bundled sentinel), but a DIFFERENT
        // yaml_source — two genuinely different authoring events sharing an id and a
        // created_by (e.g. a shared login used on two pre-Postgres replicas), not vintage
        // drift of the same bundled row. This must refuse to guess which is correct.
        legacy_exec(db.get(),
                    "INSERT INTO instruction_definitions (id, name, version, type, plugin, "
                    "action, description, enabled, instruction_set_id, gather_ttl_seconds, "
                    "response_ttl_days, created_by, created_at, updated_at, yaml_source) VALUES "
                    "('operator.shared.id', 'Shared Operator Def', '1.0', 'question', 'sysinfo', "
                    "'query', 'desc', 1, '', 0, 0, 'admin', 1800000000, 1800000000, "
                    "'scope: {}\nversion: 2');");
    }

    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.migrate_from_sqlite(legacy_a.path));
    // Replica B's backfill must fail closed rather than silently discarding either side's
    // real, divergent operator content.
    CHECK_FALSE(store.migrate_from_sqlite(legacy_b.path));
}

TEST_CASE("InstructionStore::migrate_from_sqlite: two replicas' legacy files sharing an "
          "OPERATOR-authored definition id with IDENTICAL yaml_source but divergent created_at "
          "is a benign no-op",
          "[instruction_store][backfill][pg]") {
    yuzu::test::TempDbFile legacy_a{std::string_view{"instr-legacy-op-clean-a-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_a.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(), kLegacyDefsSchema);
        legacy_exec(db.get(), kLegacySetsSchema);
        legacy_exec(db.get(), "ALTER TABLE instruction_definitions ADD COLUMN yaml_source TEXT "
                              "NOT NULL DEFAULT '';");
        legacy_exec(db.get(),
                    "INSERT INTO instruction_definitions (id, name, version, type, plugin, "
                    "action, description, enabled, instruction_set_id, gather_ttl_seconds, "
                    "response_ttl_days, created_by, created_at, updated_at, yaml_source) VALUES "
                    "('operator.clean.id', 'Hand-Synced Def', '1.0', 'question', 'sysinfo', "
                    "'query', 'desc', 1, '', 0, 0, 'admin', 1700000000, 1700000000, "
                    "'scope: {}\nversion: 1');");
    }
    yuzu::test::TempDbFile legacy_b{std::string_view{"instr-legacy-op-clean-b-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_b.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(), kLegacyDefsSchema);
        legacy_exec(db.get(), kLegacySetsSchema);
        legacy_exec(db.get(), "ALTER TABLE instruction_definitions ADD COLUMN yaml_source TEXT "
                              "NOT NULL DEFAULT '';");
        // Same id, same created_by, IDENTICAL yaml_source — this is the ordinary hand-synced
        // (pre-Postgres multi-server) case: the same file copied to every replica, imported at
        // different times so created_at legitimately differs. Comparing created_at here (the
        // OLD full-row-equality design) would fail closed on this clean case; comparing
        // content (the corrected design) must not.
        legacy_exec(db.get(),
                    "INSERT INTO instruction_definitions (id, name, version, type, plugin, "
                    "action, description, enabled, instruction_set_id, gather_ttl_seconds, "
                    "response_ttl_days, created_by, created_at, updated_at, yaml_source) VALUES "
                    "('operator.clean.id', 'Hand-Synced Def', '1.0', 'question', 'sysinfo', "
                    "'query', 'desc', 1, '', 0, 0, 'admin', 1800000000, 1800000000, "
                    "'scope: {}\nversion: 1');");
        legacy_exec(db.get(),
                    "INSERT INTO instruction_definitions (id, name, version, type, plugin, "
                    "action, description, enabled, instruction_set_id, gather_ttl_seconds, "
                    "response_ttl_days, created_by, created_at, updated_at, yaml_source) VALUES "
                    "('b.only.op.def', 'B-Only Op Def', '1.0', 'question', 'sysinfo', 'query', "
                    "'desc', 1, '', 0, 0, 'admin', 1800000000, 1800000000, 'x');");
    }

    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.migrate_from_sqlite(legacy_a.path));
    REQUIRE(store.migrate_from_sqlite(legacy_b.path));

    auto shared = store.get_definition("operator.clean.id");
    REQUIRE(shared.has_value());
    REQUIRE(shared->has_value());
    CHECK((*shared)->created_at == 1700000000); // replica A, the first writer, wins
}

TEST_CASE("InstructionStore::migrate_from_sqlite: two replicas' legacy files sharing an "
          "OPERATOR-authored (non-sentinel created_by) set id with DRIFTED description fails "
          "closed",
          "[instruction_store][backfill][pg]") {
    yuzu::test::TempDbFile legacy_a{std::string_view{"instr-legacy-op-set-conflict-a-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_a.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(), kLegacyDefsSchema);
        legacy_exec(db.get(), kLegacySetsSchema);
        legacy_exec(db.get(),
                    "INSERT INTO instruction_sets (id, name, description, created_by, "
                    "created_at) VALUES ('operator.shared.set', 'Shared Set', 'v1 description', "
                    "'alice', 1700000000);");
    }
    yuzu::test::TempDbFile legacy_b{std::string_view{"instr-legacy-op-set-conflict-b-"}};
    {
        SqliteDb db;
        REQUIRE(sqlite3_open_v2(legacy_b.path.string().c_str(), db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        legacy_exec(db.get(), kLegacyDefsSchema);
        legacy_exec(db.get(), kLegacySetsSchema);
        // Same id, same created_by ('alice', NOT the "system" bundled-set sentinel), different
        // description — two genuinely different authoring events, must fail closed.
        legacy_exec(db.get(),
                    "INSERT INTO instruction_sets (id, name, description, created_by, "
                    "created_at) VALUES ('operator.shared.set', 'Shared Set', 'v2 description', "
                    "'alice', 1800000000);");
    }

    YUZU_REQUIRE_PG_DB_TPL(db, instruction_store_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    InstructionStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.migrate_from_sqlite(legacy_a.path));
    CHECK_FALSE(store.migrate_from_sqlite(legacy_b.path));
}
