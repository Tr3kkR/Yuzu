/**
 * test_instruction_yaml.cpp — schema-aware InstructionDefinition YAML field
 * extraction (instruction_yaml.{hpp,cpp}), the shared contract behind
 * POST /api/instructions/yaml (Save) and POST /api/instructions/validate-yaml.
 *
 * Regression net for #1993: the Save path used raw whole-document substring
 * scanning against a flat schema (metadata.name / spec.plugin / spec.action),
 * so canonical nested YAML (metadata.id / spec.execution.plugin — the shape
 * used by the docs, validate-yaml, and every bundled definition) passed
 * validation but failed Save with "Missing required fields: name, plugin,
 * action". These cases pin both schemas plus the resolution/fallback order
 * mirrored from the build-time importer (embed_content.py::def_envelope).
 */

#include "instruction_yaml.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server::instruction_yaml;

namespace {

// The getting-started tutorial's first definition, verbatim (docs/
// getting-started.md "Define it in YAML") — the exact input #1993 reported
// as un-saveable.
const std::string kTutorialYaml = R"(apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: hello.system.info
  displayName: Get System Info
  version: 1.0.0
  description: Returns basic OS information from all targeted endpoints.
spec:
  type: question
  platforms: [windows, linux, darwin]
  execution:
    plugin: os_info
    action: os_name
)";

// The flat schema the New Definition panel's structured form generates
// (instruction_ui.cpp formToYaml) — must keep working unchanged.
const std::string kFlatPanelYaml = R"(apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  name: "tutorial.service.inspect"
  version: "1.0.0"
spec:
  plugin: "services"
  action: "list"
  type: question
  description: "Returns the current state of a named service."
  concurrency: unlimited
  approval: auto
  platforms: [windows, linux, darwin]
  parameters:
    type: object
    additionalProperties:
      type: string
  results:
    - name: output
      type: string
)";

// Shipped-definition shape: nested execution block with concurrency, an
// approval mapping, a parameters block whose `type: object` / properties'
// `name:`s must NOT shadow the definition's own type/name, and a folded
// description.
const std::string kShippedYaml = R"(apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: device.agent_actions.set_log_level
  displayName: Set Agent Log Level
  version: 1.0.0
  description: >
    Changes the agent's spdlog log level at runtime.
  tags: [agent, logging, management]

spec:
  type: action
  platforms: [windows, linux, darwin]

  execution:
    plugin: agent_actions
    action: Set_Log_Level
    concurrency: per-device

  parameters:
    type: object
    required: [level]
    properties:
      level:
        type: string
        displayName: Log Level

  result:
    columns:
      - name: status
        type: string

  approval:
    mode: role-gated
)";

} // namespace

TEST_CASE("instruction_yaml: canonical nested schema (tutorial YAML) parses",
          "[instruction_yaml]") {
    auto f = parse_definition_yaml(kTutorialYaml);
    CHECK(f.id == "hello.system.info");
    CHECK(f.name == "Get System Info"); // displayName wins over id
    CHECK(f.version == "1.0.0");
    CHECK(f.type == "question");
    CHECK(f.plugin == "os_info");
    CHECK(f.action == "os_name");
    CHECK(f.description == "Returns basic OS information from all targeted endpoints.");
    CHECK(f.has_api_version);
    CHECK(f.has_kind);
}

TEST_CASE("instruction_yaml: flat panel schema keeps working", "[instruction_yaml]") {
    auto f = parse_definition_yaml(kFlatPanelYaml);
    CHECK(f.id.empty()); // flat form has no metadata.id — store generates one
    CHECK(f.name == "tutorial.service.inspect");
    CHECK(f.version == "1.0.0");
    CHECK(f.type == "question");
    CHECK(f.plugin == "services");
    CHECK(f.action == "list");
    CHECK(f.description == "Returns the current state of a named service.");
    CHECK(f.concurrency == "unlimited");
    CHECK(f.approval == "auto");
}

TEST_CASE("instruction_yaml: shipped-definition shape — nested keys don't shadow",
          "[instruction_yaml]") {
    auto f = parse_definition_yaml(kShippedYaml);
    CHECK(f.id == "device.agent_actions.set_log_level");
    CHECK(f.name == "Set Agent Log Level");
    // parameters.type: object / result columns' type: string must not leak
    // into the definition's own type.
    CHECK(f.type == "action");
    CHECK(f.plugin == "agent_actions");
    CHECK(f.action == "set_log_level"); // lowercased for case-sensitive plugin match
    CHECK(f.concurrency == "per-device");
    CHECK(f.approval == "role-gated"); // spec.approval.mode form
    // Folded description isn't a plain scalar — extraction yields empty; the
    // verbatim yaml_source remains the source of truth for it.
    CHECK(f.description.empty());
}

TEST_CASE("instruction_yaml: metadata.name fallback when no displayName/id", "[instruction_yaml]") {
    auto f = parse_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                   "kind: InstructionDefinition\n"
                                   "metadata:\n"
                                   "  name: bare.name\n"
                                   "spec:\n"
                                   "  plugin: p\n"
                                   "  action: a\n");
    CHECK(f.name == "bare.name");
    CHECK(f.id.empty());
}

TEST_CASE("instruction_yaml: quoted values and inline comments", "[instruction_yaml]") {
    auto f = parse_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                   "kind: InstructionDefinition\n"
                                   "metadata:\n"
                                   "  id: \"quoted.id\" # trailing comment\n"
                                   "  description: \"tracks issue #5\"\n"
                                   "spec:\n"
                                   "  execution:\n"
                                   "    plugin: os_info # inline comment\n"
                                   "    action: os_name\n");
    CHECK(f.id == "quoted.id");
    // '#' inside a quoted scalar is content, not a comment.
    CHECK(f.description == "tracks issue #5");
    CHECK(f.plugin == "os_info");
}

TEST_CASE("instruction_yaml: validate accepts what save needs — both schemas",
          "[instruction_yaml]") {
    CHECK(validate_definition_yaml(kTutorialYaml).empty());
    CHECK(validate_definition_yaml(kFlatPanelYaml).empty());
    CHECK(validate_definition_yaml(kShippedYaml).empty());
}

TEST_CASE("instruction_yaml: validate names the specific missing field", "[instruction_yaml]") {
    SECTION("empty source") {
        auto errors = validate_definition_yaml("");
        REQUIRE(errors.size() == 1);
        CHECK(errors[0] == "YAML source is empty");
    }
    SECTION("no identifier") {
        auto errors = validate_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                               "kind: InstructionDefinition\n"
                                               "spec:\n"
                                               "  plugin: p\n"
                                               "  action: a\n");
        REQUIRE(errors.size() == 1);
        CHECK(errors[0] == "Missing metadata.id (or metadata.name) field");
    }
    SECTION("no plugin/action") {
        auto errors = validate_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                               "kind: InstructionDefinition\n"
                                               "metadata:\n"
                                               "  id: x\n");
        REQUIRE(errors.size() == 2);
        CHECK(errors[0] == "Missing spec.execution.plugin (or spec.plugin) field");
        CHECK(errors[1] == "Missing spec.execution.action (or spec.action) field");
    }
    SECTION("missing apiVersion and kind") {
        auto errors = validate_definition_yaml("metadata:\n"
                                               "  id: x\n"
                                               "spec:\n"
                                               "  plugin: p\n"
                                               "  action: a\n");
        REQUIRE(errors.size() == 2);
        CHECK(errors[0] == "Missing apiVersion field");
        CHECK(errors[1] == "Missing kind field");
    }
    SECTION("invalid approval mode is caught at validate time") {
        auto errors = validate_definition_yaml("apiVersion: yuzu.io/v1alpha1\n"
                                               "kind: InstructionDefinition\n"
                                               "metadata:\n"
                                               "  id: x\n"
                                               "spec:\n"
                                               "  plugin: p\n"
                                               "  action: a\n"
                                               "  approval: sometimes\n");
        REQUIRE(errors.size() == 1);
        CHECK(errors[0].find("Invalid approval mode") == 0);
    }
}
