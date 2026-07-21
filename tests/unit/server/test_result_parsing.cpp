/**
 * test_result_parsing.cpp — pins the `interaction` plugin's registration in
 * result_parsing.hpp's kKeyValuePlugins (macOS parity 1.3).
 *
 * Before this registration, `interaction` fell to the generic 2-name
 * {Agent, Output} default schema while its rows are key|value shaped
 * (`status|not_reachable`, `response|ok`, ...) — split_fields() still split
 * on every pipe, so a 2-field row landed under a 2-header table with an
 * extra unlabeled cell. Registering it routes rows through the bounded
 * key/value split (matching firewall/antivirus), so header and cell counts
 * agree and the new message_box `status` column actually renders correctly.
 */

#include "result_parsing.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::server;

TEST_CASE("interaction is registered as a key/value plugin", "[result_parsing]") {
    const auto& cols = columns_for_plugin("interaction");
    REQUIRE(cols.size() == 3);
    CHECK(cols == std::vector<std::string>{"Agent", "Key", "Value"});
}

TEST_CASE("interaction rows split into exactly key + value", "[result_parsing]") {
    CHECK(split_fields("interaction", "status|not_reachable") ==
          std::vector<std::string>{"status", "not_reachable"});
    CHECK(split_fields("interaction", "response|ok") ==
          std::vector<std::string>{"response", "ok"});
    // A free-text answer containing a literal pipe stays intact in Value —
    // the bounded (first-pipe-only) split, not the unbounded default.
    CHECK(split_fields("interaction", "response|yes | no maybe") ==
          std::vector<std::string>{"response", "yes | no maybe"});
}
