/**
 * test_inventory_eval.cpp -- Unit tests for the inventory evaluation engine
 *
 * Covers: all operators (==, !=, >, >=, <, <=, contains, exists,
 * version_gte, version_lte), dot-path extraction, array index paths,
 * combine modes (all/any), edge cases, unknown operators, multiple agents.
 */

#include "inventory_eval.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

using Records = std::vector<std::pair<std::string, std::string>>;

// ============================================================================
// Operator: ==
// ============================================================================

TEST_CASE("InventoryEval: operator == exact string match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Windows", "version": "11"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "os", "==", "Windows"}};
    req.combine = "all";

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-1");
    CHECK(results[0].match == true);
    CHECK(results[0].matched_value == "Windows");
    CHECK(results[0].plugin == "hardware");
}

TEST_CASE("InventoryEval: operator == no match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "os", "==", "Windows"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: !=
// ============================================================================

TEST_CASE("InventoryEval: operator != not equal match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "os", "!=", "Windows"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "Linux");
}

TEST_CASE("InventoryEval: operator != no match when equal", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Windows"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "os", "!=", "Windows"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: > (numeric)
// ============================================================================

TEST_CASE("InventoryEval: operator > numeric match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"cpu_count": 8})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "cpu_count", ">", "4"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "8");
}

TEST_CASE("InventoryEval: operator > no match when equal", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"cpu_count": 4})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "cpu_count", ">", "4"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

TEST_CASE("InventoryEval: operator > no match when less", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"cpu_count": 2})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "cpu_count", ">", "4"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: >=
// ============================================================================

TEST_CASE("InventoryEval: operator >= match when greater", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"ram_gb": 16})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "ram_gb", ">=", "8"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "16");
}

TEST_CASE("InventoryEval: operator >= match when equal", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"ram_gb": 8})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "ram_gb", ">=", "8"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: operator >= no match when less", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"ram_gb": 4})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "ram_gb", ">=", "8"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: <
// ============================================================================

TEST_CASE("InventoryEval: operator < numeric match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"disk_free_gb": 10})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "disk_free_gb", "<", "50"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "10");
}

TEST_CASE("InventoryEval: operator < no match when equal", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"disk_free_gb": 50})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "disk_free_gb", "<", "50"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: <=
// ============================================================================

TEST_CASE("InventoryEval: operator <= match when less", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"temp_celsius": 60})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "temp_celsius", "<=", "80"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: operator <= match when equal", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"temp_celsius": 80})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "temp_celsius", "<=", "80"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: operator <= no match when greater", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|metrics", R"({"temp_celsius": 95})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"metrics", "temp_celsius", "<=", "80"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: contains
// ============================================================================

TEST_CASE("InventoryEval: operator contains substring match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|software", R"({"product": "Microsoft Office Professional"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "product", "contains", "Office"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "Microsoft Office Professional");
}

TEST_CASE("InventoryEval: operator contains no match", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|software", R"({"product": "Notepad"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "product", "contains", "Office"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: exists
// ============================================================================

TEST_CASE("InventoryEval: operator exists field present", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"serial": "ABC123", "model": "ThinkPad"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "serial", "exists", ""}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "ABC123");
}

TEST_CASE("InventoryEval: operator exists field missing", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"model": "ThinkPad"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "serial", "exists", ""}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

TEST_CASE("InventoryEval: operator exists field is null", "[inventory_eval][operators]") {
    Records records = {
        {"agent-1|hardware", R"({"serial": null})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hardware", "serial", "exists", ""}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Operator: version_gte
// ============================================================================

TEST_CASE("InventoryEval: version_gte match", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "1.2.3"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "1.2.0"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "1.2.3");
}

TEST_CASE("InventoryEval: version_gte no match", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "1.2.3"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "1.3.0"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

TEST_CASE("InventoryEval: version_gte equal versions match", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "2.0.0"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "2.0.0"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

// ============================================================================
// Operator: version_lte
// ============================================================================

TEST_CASE("InventoryEval: version_lte match", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "1.2.0"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_lte", "1.2.3"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "1.2.0");
}

TEST_CASE("InventoryEval: version_lte no match", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "2.0.0"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_lte", "1.9.9"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Version edge cases
// ============================================================================

TEST_CASE("InventoryEval: version padding with zeros", "[inventory_eval][version]") {
    // "1.0" should be treated as "1.0.0"
    Records records = {
        {"agent-1|software", R"({"version": "1.0"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "1.0.0"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);

    // Also verify the reverse: "1.0.0" >= "1.0"
    InventoryEvalRequest req2;
    req2.conditions = {{"software", "version", "version_gte", "1.0"}};

    Records records2 = {
        {"agent-1|software", R"({"version": "1.0.0"})"},
    };
    auto results2 = evaluate_inventory(req2, records2);
    REQUIRE(results2.size() == 1);
}

TEST_CASE("InventoryEval: version with non-numeric segments", "[inventory_eval][version]") {
    // "1.0.0-beta" -- the "-beta" part is non-numeric, parsed as 0
    Records records = {
        {"agent-1|software", R"({"version": "1.0.0-beta"})"},
    };

    // "1.0.0-beta" segments: [1, 0, 0] (the "0-beta" part parses as 0)
    // compared against "1.0.0" segments: [1, 0, 0] -- should be equal
    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "1.0.0"}};

    auto results = evaluate_inventory(req, records);
    // Non-numeric suffix gets parsed as 0 by from_chars, so 1.0.0 >= 1.0.0 is true
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: version single segment", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "3"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "2"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: version many segments", "[inventory_eval][version]") {
    Records records = {
        {"agent-1|software", R"({"version": "1.2.3.4.5"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_lte", "1.2.3.4.6"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

// ============================================================================
// Dot-path field extraction
// ============================================================================

TEST_CASE("InventoryEval: dot-path nested object", "[inventory_eval][dotpath]") {
    Records records = {
        {"agent-1|software", R"({"details": {"version": "1.0", "vendor": "Acme"}})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "details.version", "==", "1.0"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "1.0");
}

TEST_CASE("InventoryEval: dot-path deeply nested", "[inventory_eval][dotpath]") {
    Records records = {
        {"agent-1|config", R"({"system": {"network": {"dns": "8.8.8.8"}}})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"config", "system.network.dns", "==", "8.8.8.8"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "8.8.8.8");
}

TEST_CASE("InventoryEval: dot-path missing intermediate key", "[inventory_eval][dotpath]") {
    Records records = {
        {"agent-1|config", R"({"system": {"other": "value"}})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"config", "system.network.dns", "==", "8.8.8.8"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Array index in dot-path
// ============================================================================

TEST_CASE("InventoryEval: array index in dot-path", "[inventory_eval][dotpath]") {
    Records records = {
        {"agent-1|inventory", R"({"items": [{"name": "foo"}, {"name": "bar"}]})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"inventory", "items.0.name", "==", "foo"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "foo");
}

TEST_CASE("InventoryEval: array second element", "[inventory_eval][dotpath]") {
    Records records = {
        {"agent-1|inventory", R"({"items": [{"name": "foo"}, {"name": "bar"}]})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"inventory", "items.1.name", "==", "bar"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "bar");
}

TEST_CASE("InventoryEval: array index out of bounds", "[inventory_eval][dotpath]") {
    Records records = {
        {"agent-1|inventory", R"({"items": [{"name": "foo"}]})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"inventory", "items.5.name", "==", "foo"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Combine mode: "all" (AND)
// ============================================================================

TEST_CASE("InventoryEval: combine all -- all match", "[inventory_eval][combine]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Windows", "cpu_count": 8, "ram_gb": 16})"},
    };

    InventoryEvalRequest req;
    req.conditions = {
        {"hardware", "os", "==", "Windows"},
        {"hardware", "cpu_count", ">=", "4"},
        {"hardware", "ram_gb", ">=", "8"},
    };
    req.combine = "all";

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: combine all -- one fails", "[inventory_eval][combine]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Linux", "cpu_count": 8, "ram_gb": 16})"},
    };

    InventoryEvalRequest req;
    req.conditions = {
        {"hardware", "os", "==", "Windows"},
        {"hardware", "cpu_count", ">=", "4"},
    };
    req.combine = "all";

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Combine mode: "any" (OR)
// ============================================================================

TEST_CASE("InventoryEval: combine any -- one matches", "[inventory_eval][combine]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "Linux", "cpu_count": 2})"},
    };

    InventoryEvalRequest req;
    req.conditions = {
        {"hardware", "os", "==", "Windows"},
        {"hardware", "os", "==", "Linux"},
    };
    req.combine = "any";

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: combine any -- none match", "[inventory_eval][combine]") {
    Records records = {
        {"agent-1|hardware", R"({"os": "macOS"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {
        {"hardware", "os", "==", "Windows"},
        {"hardware", "os", "==", "Linux"},
    };
    req.combine = "any";

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Empty conditions
// ============================================================================

TEST_CASE("InventoryEval: empty conditions returns all records", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"os": "Windows"})"},
        {"agent-2|hw", R"({"os": "Linux"})"},
        {"agent-3|hw", R"({"os": "macOS"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {};
    req.combine = "all";

    // With combine=all and no conditions, overall_match starts as true for each record
    auto results = evaluate_inventory(req, records);
    CHECK(results.size() == 3);
}

// ============================================================================
// No matching records
// ============================================================================

TEST_CASE("InventoryEval: no matching records returns empty", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"os": "Windows"})"},
        {"agent-2|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "==", "FreeBSD"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Multiple agents -- results grouped correctly
// ============================================================================

TEST_CASE("InventoryEval: multiple agents results grouped", "[inventory_eval][multi]") {
    Records records = {
        {"agent-1|software", R"({"version": "2.0.0"})"},
        {"agent-2|software", R"({"version": "1.5.0"})"},
        {"agent-3|software", R"({"version": "3.0.0"})"},
        {"agent-4|software", R"({"version": "0.9.0"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"software", "version", "version_gte", "1.5.0"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 3);

    // Verify we got the right agents
    bool found_1 = false, found_2 = false, found_3 = false;
    for (const auto& r : results) {
        if (r.agent_id == "agent-1") found_1 = true;
        if (r.agent_id == "agent-2") found_2 = true;
        if (r.agent_id == "agent-3") found_3 = true;
        CHECK(r.plugin == "software");
        CHECK(r.match == true);
    }
    CHECK(found_1);
    CHECK(found_2);
    CHECK(found_3);
}

TEST_CASE("InventoryEval: filter by agent_id", "[inventory_eval][multi]") {
    Records records = {
        {"agent-1|software", R"({"version": "2.0.0"})"},
        {"agent-2|software", R"({"version": "3.0.0"})"},
    };

    InventoryEvalRequest req;
    req.agent_id = "agent-1";
    req.conditions = {{"software", "version", "version_gte", "1.0.0"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-1");
}

// ============================================================================
// Unknown operator
// ============================================================================

TEST_CASE("InventoryEval: unknown operator silently returns no match", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "matches_regex", "Lin.*"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

// ============================================================================
// Edge cases
// ============================================================================

TEST_CASE("InventoryEval: malformed JSON skipped", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", "not valid json {{{"},
        {"agent-2|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "==", "Linux"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-2");
}

TEST_CASE("InventoryEval: record key without separator skipped", "[inventory_eval][edge]") {
    Records records = {
        {"badkey_no_pipe", R"({"os": "Linux"})"},
        {"agent-1|hw", R"({"os": "Linux"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "==", "Linux"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].agent_id == "agent-1");
}

TEST_CASE("InventoryEval: collected_at is extracted", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"os": "Linux", "collected_at": 1711234567})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "==", "Linux"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].collected_at == 1711234567);
}

TEST_CASE("InventoryEval: condition plugin filter skips non-matching plugin", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|network", R"({"ip": "10.0.0.1"})"},
    };

    // Condition targets "hardware" plugin, record is "network" -- AND mode fails
    InventoryEvalRequest req;
    req.conditions = {{"hardware", "ip", "==", "10.0.0.1"}};
    req.combine = "all";

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}

TEST_CASE("InventoryEval: empty plugin in condition matches any plugin", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|network", R"({"ip": "10.0.0.1"})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"", "ip", "==", "10.0.0.1"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].plugin == "network");
}

TEST_CASE("InventoryEval: boolean JSON value converted to string", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"secure_boot": true})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "secure_boot", "==", "true"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
    CHECK(results[0].matched_value == "true");
}

TEST_CASE("InventoryEval: integer JSON value compared as number", "[inventory_eval][edge]") {
    Records records = {
        {"agent-1|hw", R"({"cores": 16})"},
    };

    InventoryEvalRequest req;
    req.conditions = {{"hw", "cores", ">", "10"}};

    auto results = evaluate_inventory(req, records);
    REQUIRE(results.size() == 1);
}

TEST_CASE("InventoryEval: empty records returns empty", "[inventory_eval][edge]") {
    Records records = {};

    InventoryEvalRequest req;
    req.conditions = {{"hw", "os", "==", "Linux"}};

    auto results = evaluate_inventory(req, records);
    CHECK(results.empty());
}
