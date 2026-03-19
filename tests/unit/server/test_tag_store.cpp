/**
 * test_tag_store.cpp — Unit tests for TagStore
 *
 * Covers: CRUD, validation, sync, agents_with_tag, get_tag_map.
 */

#include "tag_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("TagStore: open in-memory", "[tag_store][db]") {
    TagStore store(":memory:");
    REQUIRE(store.is_open());
}

TEST_CASE("TagStore: set and get", "[tag_store]") {
    TagStore store(":memory:");

    store.set_tag("agent-1", "env", "production");
    CHECK(store.get_tag("agent-1", "env") == "production");
}

TEST_CASE("TagStore: get nonexistent returns empty", "[tag_store]") {
    TagStore store(":memory:");
    CHECK(store.get_tag("agent-1", "nonexistent").empty());
}

TEST_CASE("TagStore: set overwrites", "[tag_store]") {
    TagStore store(":memory:");

    store.set_tag("agent-1", "env", "staging");
    store.set_tag("agent-1", "env", "production");
    CHECK(store.get_tag("agent-1", "env") == "production");
}

TEST_CASE("TagStore: delete_tag", "[tag_store]") {
    TagStore store(":memory:");

    store.set_tag("agent-1", "env", "prod");
    CHECK(store.delete_tag("agent-1", "env") == true);
    CHECK(store.get_tag("agent-1", "env").empty());
    CHECK(store.delete_tag("agent-1", "env") == false);
}

TEST_CASE("TagStore: get_all_tags", "[tag_store]") {
    TagStore store(":memory:");

    store.set_tag("agent-1", "env", "prod");
    store.set_tag("agent-1", "region", "us-east");
    store.set_tag("agent-2", "env", "staging");

    auto tags = store.get_all_tags("agent-1");
    REQUIRE(tags.size() == 2);

    auto tags2 = store.get_all_tags("agent-2");
    REQUIRE(tags2.size() == 1);
}

TEST_CASE("TagStore: get_tag_map", "[tag_store]") {
    TagStore store(":memory:");

    store.set_tag("agent-1", "env", "prod");
    store.set_tag("agent-1", "region", "eu-west");

    auto map = store.get_tag_map("agent-1");
    REQUIRE(map.size() == 2);
    CHECK(map["env"] == "prod");
    CHECK(map["region"] == "eu-west");
}

TEST_CASE("TagStore: sync_agent_tags", "[tag_store]") {
    TagStore store(":memory:");

    // Set a server tag
    store.set_tag("agent-1", "criticality", "high", "server");

    // Sync agent tags
    std::unordered_map<std::string, std::string> agent_tags = {{"os.version", "10.0.19045"},
                                                               {"hostname", "WORKSTATION-01"}};
    store.sync_agent_tags("agent-1", agent_tags);

    // Server tag should remain
    CHECK(store.get_tag("agent-1", "criticality") == "high");
    // Agent tags should be present
    CHECK(store.get_tag("agent-1", "os.version") == "10.0.19045");
    CHECK(store.get_tag("agent-1", "hostname") == "WORKSTATION-01");
}

TEST_CASE("TagStore: sync replaces old agent tags", "[tag_store]") {
    TagStore store(":memory:");

    std::unordered_map<std::string, std::string> tags1 = {{"k1", "v1"}, {"k2", "v2"}};
    store.sync_agent_tags("agent-1", tags1);
    CHECK(store.get_tag("agent-1", "k1") == "v1");

    // Second sync should remove k1 and k2
    std::unordered_map<std::string, std::string> tags2 = {{"k3", "v3"}};
    store.sync_agent_tags("agent-1", tags2);
    CHECK(store.get_tag("agent-1", "k1").empty());
    CHECK(store.get_tag("agent-1", "k3") == "v3");
}

TEST_CASE("TagStore: delete_all_tags", "[tag_store]") {
    TagStore store(":memory:");

    store.set_tag("agent-1", "env", "prod");
    store.set_tag("agent-1", "region", "us");
    store.delete_all_tags("agent-1");

    CHECK(store.get_all_tags("agent-1").empty());
}

TEST_CASE("TagStore: agents_with_tag", "[tag_store]") {
    TagStore store(":memory:");

    store.set_tag("agent-1", "env", "prod");
    store.set_tag("agent-2", "env", "staging");
    store.set_tag("agent-3", "env", "prod");

    auto agents = store.agents_with_tag("env", "prod");
    REQUIRE(agents.size() == 2);

    auto all_env = store.agents_with_tag("env");
    REQUIRE(all_env.size() == 3);
}

TEST_CASE("TagStore: validate_key", "[tag_store]") {
    CHECK(TagStore::validate_key("env") == true);
    CHECK(TagStore::validate_key("os.version") == true);
    CHECK(TagStore::validate_key("my-tag") == true);
    CHECK(TagStore::validate_key("tag:sub") == true);
    CHECK(TagStore::validate_key("") == false);
    CHECK(TagStore::validate_key(std::string(65, 'a')) == false);
    CHECK(TagStore::validate_key("has space") == false);
    CHECK(TagStore::validate_key("has/slash") == false);
}

TEST_CASE("TagStore: validate_value", "[tag_store]") {
    CHECK(TagStore::validate_value("") == true);
    CHECK(TagStore::validate_value("hello") == true);
    CHECK(TagStore::validate_value(std::string(448, 'x')) == true);
    CHECK(TagStore::validate_value(std::string(449, 'x')) == false);
}

TEST_CASE("TagStore: invalid key rejected", "[tag_store]") {
    TagStore store(":memory:");

    store.set_tag("agent-1", "has space", "value");
    CHECK(store.get_tag("agent-1", "has space").empty());
}

TEST_CASE("TagStore: source preserved", "[tag_store]") {
    TagStore store(":memory:");

    store.set_tag("agent-1", "env", "prod", "api");
    auto tags = store.get_all_tags("agent-1");
    REQUIRE(tags.size() == 1);
    CHECK(tags[0].source == "api");
}

// ── Tag categories ──────────────────────────────────────────────────────────

TEST_CASE("TagStore: get_tag_categories returns 4 categories", "[tag_store][categories]") {
    const auto& cats = get_tag_categories();
    REQUIRE(cats.size() == 4);
    CHECK(cats[0].key == "role");
    CHECK(cats[1].key == "environment");
    CHECK(cats[2].key == "location");
    CHECK(cats[3].key == "service");
}

TEST_CASE("TagStore: set_tag_checked accepts valid environment value", "[tag_store][categories]") {
    TagStore store(":memory:");
    auto result = store.set_tag_checked("agent-1", "environment", "Production");
    REQUIRE(result.has_value());
    CHECK(store.get_tag("agent-1", "environment") == "Production");
}

TEST_CASE("TagStore: set_tag_checked rejects invalid environment value",
          "[tag_store][categories]") {
    TagStore store(":memory:");
    auto result = store.set_tag_checked("agent-1", "environment", "Staging");
    REQUIRE(!result.has_value());
    CHECK(result.error().find("allowed values") != std::string::npos);
    CHECK(store.get_tag("agent-1", "environment").empty());
}

TEST_CASE("TagStore: set_tag_checked allows free-form category", "[tag_store][categories]") {
    TagStore store(":memory:");
    auto result = store.set_tag_checked("agent-1", "role", "Web Server");
    REQUIRE(result.has_value());
    CHECK(store.get_tag("agent-1", "role") == "Web Server");
}

TEST_CASE("TagStore: set_tag_checked passes non-category key", "[tag_store][categories]") {
    TagStore store(":memory:");
    auto result = store.set_tag_checked("agent-1", "custom-tag", "any value");
    REQUIRE(result.has_value());
    CHECK(store.get_tag("agent-1", "custom-tag") == "any value");
}

TEST_CASE("TagStore: get_compliance_gaps", "[tag_store][categories]") {
    TagStore store(":memory:");

    // Agent-1 has all 4 categories
    store.set_tag("agent-1", "role", "Web Server");
    store.set_tag("agent-1", "environment", "Production");
    store.set_tag("agent-1", "location", "US-East");
    store.set_tag("agent-1", "service", "CRM");

    // Agent-2 missing environment and service
    store.set_tag("agent-2", "role", "Database");
    store.set_tag("agent-2", "location", "EU-West");

    auto gaps = store.get_compliance_gaps();
    // Agent-1 should not be in the gaps, agent-2 should
    REQUIRE(gaps.size() == 1);
    CHECK(gaps[0].first == "agent-2");
    REQUIRE(gaps[0].second.size() == 2);
    // Missing keys should be environment and service
    bool has_env = false, has_svc = false;
    for (const auto& k : gaps[0].second) {
        if (k == "environment")
            has_env = true;
        if (k == "service")
            has_svc = true;
    }
    CHECK(has_env);
    CHECK(has_svc);
}

TEST_CASE("TagStore: get_distinct_values", "[tag_store][categories]") {
    TagStore store(":memory:");

    store.set_tag("agent-1", "service", "CRM");
    store.set_tag("agent-2", "service", "ERP");
    store.set_tag("agent-3", "service", "CRM");

    auto values = store.get_distinct_values("service");
    REQUIRE(values.size() == 2);
    // Sorted alphabetically
    CHECK(values[0] == "CRM");
    CHECK(values[1] == "ERP");
}
