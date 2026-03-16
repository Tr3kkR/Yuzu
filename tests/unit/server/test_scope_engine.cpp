/**
 * test_scope_engine.cpp — Unit tests for the scope expression engine
 *
 * Covers: parser (16), evaluator (10), performance (2).
 */

#include "scope_engine.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <unordered_map>

using namespace yuzu::scope;

// ── Helper ─────────────────────────────────────────────────────────────────

static AttributeResolver make_resolver(
    const std::unordered_map<std::string, std::string>& attrs)
{
    return [&attrs](std::string_view key) -> std::string {
        auto it = attrs.find(std::string(key));
        return it != attrs.end() ? it->second : std::string{};
    };
}

// ── Parser tests ───────────────────────────────────────────────────────────

TEST_CASE("ScopeEngine: parse simple equality", "[scope][parser]") {
    auto result = parse(R"(ostype == "Windows")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse inequality", "[scope][parser]") {
    auto result = parse(R"(ostype != "Linux")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse AND", "[scope][parser]") {
    auto result = parse(R"(ostype == "Windows" AND arch == "x86_64")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse OR", "[scope][parser]") {
    auto result = parse(R"(ostype == "Windows" OR ostype == "Linux")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse NOT", "[scope][parser]") {
    auto result = parse(R"(NOT ostype == "Linux")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse parenthesized", "[scope][parser]") {
    auto result = parse(R"((ostype == "Windows" OR ostype == "Linux") AND arch == "x86_64")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse LIKE", "[scope][parser]") {
    auto result = parse(R"(hostname LIKE "web-*")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse IN", "[scope][parser]") {
    auto result = parse(R"(ostype IN ("Windows", "Linux", "Darwin"))");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse CONTAINS", "[scope][parser]") {
    auto result = parse(R"(hostname CONTAINS "prod")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse comparison operators", "[scope][parser]") {
    REQUIRE(parse(R"(version > "1.0")").has_value());
    REQUIRE(parse(R"(version < "2.0")").has_value());
    REQUIRE(parse(R"(version >= "1.0")").has_value());
    REQUIRE(parse(R"(version <= "2.0")").has_value());
}

TEST_CASE("ScopeEngine: parse tag attribute", "[scope][parser]") {
    auto result = parse(R"(tag:env == "prod")");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse complex nested", "[scope][parser]") {
    auto result = parse(
        R"((ostype == "Windows" AND arch == "x86_64") OR (tag:env == "staging" AND NOT tag:locked == "true"))");
    REQUIRE(result.has_value());
}

TEST_CASE("ScopeEngine: parse error on empty", "[scope][parser]") {
    auto result = parse("");
    REQUIRE(!result.has_value());
}

TEST_CASE("ScopeEngine: parse error on bad syntax", "[scope][parser]") {
    auto result = parse(R"(ostype ==)");
    REQUIRE(!result.has_value());
}

TEST_CASE("ScopeEngine: parse parenthesized expression", "[scope][parser]") {
    // Use string literal to avoid raw string delimiter collision with parens
    auto result = parse("(ostype == \"Windows\")");
    REQUIRE(result.has_value());

    // Extra whitespace inside parens
    auto spaced = parse("( ostype == \"Windows\" )");
    REQUIRE(spaced.has_value());
}

TEST_CASE("ScopeEngine: parse error on unmatched paren", "[scope][parser]") {
    auto unmatched = parse("(ostype == \"Windows\"");
    REQUIRE(!unmatched.has_value());
}

TEST_CASE("ScopeEngine: parse error on max depth", "[scope][parser]") {
    // Build deeply nested expression
    std::string expr;
    for (int i = 0; i < 12; ++i) expr += "(";
    expr += R"(ostype == "Windows")";
    for (int i = 0; i < 12; ++i) expr += ")";

    auto result = parse(expr);
    REQUIRE(!result.has_value());
}

// ── Evaluator tests ────────────────────────────────────────────────────────

TEST_CASE("ScopeEngine: eval equality match", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {
        {"ostype", "Windows"}, {"arch", "x86_64"}
    };
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(ostype == "Windows")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval equality mismatch", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {
        {"ostype", "Linux"}
    };
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(ostype == "Windows")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == false);
}

TEST_CASE("ScopeEngine: eval case insensitive", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {
        {"ostype", "windows"}
    };
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(ostype == "Windows")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval AND", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {
        {"ostype", "Windows"}, {"arch", "x86_64"}
    };
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(ostype == "Windows" AND arch == "x86_64")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);

    auto expr2 = parse(R"(ostype == "Windows" AND arch == "aarch64")");
    REQUIRE(expr2.has_value());
    CHECK(evaluate(*expr2, resolver) == false);
}

TEST_CASE("ScopeEngine: eval OR", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {
        {"ostype", "Linux"}
    };
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(ostype == "Windows" OR ostype == "Linux")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval NOT", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {
        {"ostype", "Windows"}
    };
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(NOT ostype == "Linux")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval LIKE wildcard", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {
        {"hostname", "web-prod-01"}
    };
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(hostname LIKE "web-*")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);

    auto expr2 = parse(R"(hostname LIKE "db-*")");
    REQUIRE(expr2.has_value());
    CHECK(evaluate(*expr2, resolver) == false);
}

TEST_CASE("ScopeEngine: eval IN", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {
        {"ostype", "Linux"}
    };
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(ostype IN ("Windows", "Linux", "Darwin"))");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);

    std::unordered_map<std::string, std::string> attrs2 = {
        {"ostype", "FreeBSD"}
    };
    auto resolver2 = make_resolver(attrs2);
    CHECK(evaluate(*expr, resolver2) == false);
}

TEST_CASE("ScopeEngine: eval CONTAINS", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {
        {"hostname", "web-prod-01"}
    };
    auto resolver = make_resolver(attrs);

    auto expr = parse(R"(hostname CONTAINS "prod")");
    REQUIRE(expr.has_value());
    CHECK(evaluate(*expr, resolver) == true);
}

TEST_CASE("ScopeEngine: eval numeric comparison", "[scope][eval]") {
    std::unordered_map<std::string, std::string> attrs = {
        {"version", "2.5"}
    };
    auto resolver = make_resolver(attrs);

    auto gt = parse(R"(version > "1.0")");
    REQUIRE(gt.has_value());
    CHECK(evaluate(*gt, resolver) == true);

    auto lt = parse(R"(version < "1.0")");
    REQUIRE(lt.has_value());
    CHECK(evaluate(*lt, resolver) == false);
}

// ── Performance tests ──────────────────────────────────────────────────────

TEST_CASE("ScopeEngine: parse performance", "[scope][perf]") {
    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < 10000; ++i) {
        auto result = parse(R"((ostype == "Windows" AND arch == "x86_64") OR tag:env == "prod")");
        REQUIRE(result.has_value());
    }
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    REQUIRE(ms < 5000);  // 10k parses should take less than 5s
}

TEST_CASE("ScopeEngine: eval performance", "[scope][perf]") {
    auto expr = parse(R"((ostype == "Windows" AND arch == "x86_64") OR (tag:env == "prod" AND NOT tag:locked == "true"))");
    REQUIRE(expr.has_value());

    std::unordered_map<std::string, std::string> attrs = {
        {"ostype", "Windows"}, {"arch", "x86_64"},
        {"tag:env", "prod"}, {"tag:locked", "false"}
    };
    auto resolver = make_resolver(attrs);

    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < 100000; ++i) {
        evaluate(*expr, resolver);
    }
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    REQUIRE(ms < 5000);  // 100k evals should take less than 5s
}
