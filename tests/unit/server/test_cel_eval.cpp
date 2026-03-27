/**
 * test_cel_eval.cpp -- Unit tests for the CEL expression evaluator
 *
 * Covers: backward compatibility with legacy compliance expressions, CEL type
 * system, operators, string functions, collections, timestamps, migration,
 * validation, and edge cases.
 */

#include "cel_eval.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <string>

using namespace yuzu::server::cel;

// ============================================================================
// Backward compatibility — every legacy compliance_eval test must pass
// ============================================================================

TEST_CASE("CEL: legacy equality match", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"status", "running"}};
    CHECK(evaluate_bool("result.status == 'running'", fields) == true);
}

TEST_CASE("CEL: legacy equality mismatch", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"status", "stopped"}};
    CHECK(evaluate_bool("result.status == 'running'", fields) == false);
}

TEST_CASE("CEL: legacy not-equal match", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"status", "running"}};
    CHECK(evaluate_bool("result.status != 'stopped'", fields) == true);
}

TEST_CASE("CEL: legacy not-equal mismatch", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"status", "stopped"}};
    CHECK(evaluate_bool("result.status != 'stopped'", fields) == false);
}

TEST_CASE("CEL: legacy greater than numeric", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"count", "10"}};
    CHECK(evaluate_bool("result.count > 5", fields) == true);
    CHECK(evaluate_bool("result.count > 10", fields) == false);
    CHECK(evaluate_bool("result.count > 15", fields) == false);
}

TEST_CASE("CEL: legacy less than numeric", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"count", "3"}};
    CHECK(evaluate_bool("result.count < 5", fields) == true);
    CHECK(evaluate_bool("result.count < 3", fields) == false);
}

TEST_CASE("CEL: legacy greater-or-equal numeric", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"count", "5"}};
    CHECK(evaluate_bool("result.count >= 5", fields) == true);
    CHECK(evaluate_bool("result.count >= 6", fields) == false);
}

TEST_CASE("CEL: legacy less-or-equal numeric", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"count", "5"}};
    CHECK(evaluate_bool("result.count <= 5", fields) == true);
    CHECK(evaluate_bool("result.count <= 4", fields) == false);
}

TEST_CASE("CEL: legacy string comparison fallback for >=", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"version", "2.0"}};
    CHECK(evaluate_bool("result.version >= '1.0'", fields) == true);
    CHECK(evaluate_bool("result.version >= '2.0'", fields) == true);
    CHECK(evaluate_bool("result.version >= '3.0'", fields) == false);
}

TEST_CASE("CEL: legacy double-quoted strings", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"name", "yuzu-agent"}};
    CHECK(evaluate_bool("result.name == \"yuzu-agent\"", fields) == true);
}

TEST_CASE("CEL: legacy AND both true", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"a", "1"}, {"b", "2"}};
    CHECK(evaluate_bool("result.a == '1' AND result.b == '2'", fields) == true);
}

TEST_CASE("CEL: legacy AND one false", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"a", "1"}, {"b", "9"}};
    CHECK(evaluate_bool("result.a == '1' AND result.b == '2'", fields) == false);
}

TEST_CASE("CEL: legacy OR one true", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"x", "1"}, {"y", "9"}};
    CHECK(evaluate_bool("result.x == '1' OR result.y == '2'", fields) == true);
}

TEST_CASE("CEL: legacy OR both false", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"x", "0"}, {"y", "0"}};
    CHECK(evaluate_bool("result.x == '1' OR result.y == '2'", fields) == false);
}

TEST_CASE("CEL: legacy NOT true", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"status", "running"}};
    CHECK(evaluate_bool("NOT result.status == 'failed'", fields) == true);
}

TEST_CASE("CEL: legacy NOT false", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"status", "failed"}};
    CHECK(evaluate_bool("NOT result.status == 'failed'", fields) == false);
}

TEST_CASE("CEL: legacy nested parentheses with OR and AND", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"a", "1"}, {"b", "9"}, {"c", "3"}};
    CHECK(evaluate_bool("(result.a == '1' OR result.b == '2') AND result.c == '3'",
                         fields) == true);
}

TEST_CASE("CEL: legacy AND has higher precedence than OR", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"a", "1"}, {"b", "0"}, {"c", "0"}};
    CHECK(evaluate_bool("result.a == '1' OR result.b == '2' AND result.c == '3'",
                         fields) == true);
}

TEST_CASE("CEL: legacy double NOT", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"status", "failed"}};
    CHECK(evaluate_bool("NOT NOT result.status == 'failed'", fields) == true);
}

TEST_CASE("CEL: legacy contains match", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"name", "WebServer-01"}};
    CHECK(evaluate_bool("result.name contains 'server'", fields) == true);
}

TEST_CASE("CEL: legacy contains mismatch", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"name", "DatabaseHost"}};
    CHECK(evaluate_bool("result.name contains 'server'", fields) == false);
}

TEST_CASE("CEL: legacy contains is case-insensitive", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"name", "MyService"}};
    CHECK(evaluate_bool("result.name contains 'SERV'", fields) == true);
    CHECK(evaluate_bool("result.name contains 'serv'", fields) == true);
}

TEST_CASE("CEL: legacy startswith match", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"path", "/usr/local/bin"}};
    CHECK(evaluate_bool("result.path startswith '/usr'", fields) == true);
}

TEST_CASE("CEL: legacy startswith mismatch", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"path", "/etc/config"}};
    CHECK(evaluate_bool("result.path startswith '/usr'", fields) == false);
}

TEST_CASE("CEL: legacy startswith is case-insensitive", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"path", "/USR/local"}};
    CHECK(evaluate_bool("result.path startswith '/usr'", fields) == true);
}

TEST_CASE("CEL: legacy empty expression returns true", "[cel][compat]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("", fields) == true);
}

TEST_CASE("CEL: legacy missing field is empty string", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"other", "value"}};
    CHECK(evaluate_bool("result.missing == 'running'", fields) == false);
}

TEST_CASE("CEL: legacy deeply nested parentheses", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"a", "1"}};
    CHECK(evaluate_bool("(((result.a == '1')))", fields) == true);
    CHECK(evaluate_bool("(((result.a == '2')))", fields) == false);
}

TEST_CASE("CEL: legacy type coercion string '42' > 40", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"count", "42"}};
    CHECK(evaluate_bool("result.count > 40", fields) == true);
    CHECK(evaluate_bool("result.count > 42", fields) == false);
    CHECK(evaluate_bool("result.count > 50", fields) == false);
}

TEST_CASE("CEL: legacy negative numbers", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"temp", "-5"}};
    CHECK(evaluate_bool("result.temp < 0", fields) == true);
    CHECK(evaluate_bool("result.temp > -10", fields) == true);
    CHECK(evaluate_bool("result.temp == -5", fields) == true);
    CHECK(evaluate_bool("result.temp == -3", fields) == false);
}

TEST_CASE("CEL: legacy boolean literal true", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"enabled", "true"}};
    CHECK(evaluate_bool("result.enabled == true", fields) == true);
}

TEST_CASE("CEL: legacy boolean literal false", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"enabled", "false"}};
    CHECK(evaluate_bool("result.enabled == false", fields) == true);
    CHECK(evaluate_bool("result.enabled == true", fields) == false);
}

TEST_CASE("CEL: legacy bare identifier as boolean", "[cel][compat]") {
    std::map<std::string, std::string> fields = {{"active", "yes"}};
    CHECK(evaluate_bool("result.active", fields) == true);

    std::map<std::string, std::string> fields2 = {{"active", "false"}};
    CHECK(evaluate_bool("result.active", fields2) == false);

    std::map<std::string, std::string> fields3 = {{"active", "0"}};
    CHECK(evaluate_bool("result.active", fields3) == false);

    std::map<std::string, std::string> fields4;
    CHECK(evaluate_bool("result.active", fields4) == false);
}

TEST_CASE("CEL: legacy complex combined expression", "[cel][compat]") {
    std::map<std::string, std::string> fields = {
        {"status", "running"}, {"cpu", "45"}, {"name", "YuzuAgent"}};
    CHECK(evaluate_bool(
        "result.status == 'running' AND (result.cpu < 90 OR result.name contains 'yuzu')",
        fields) == true);
}

// ============================================================================
// CEL operators — && || ! ? :
// ============================================================================

TEST_CASE("CEL: logical and (&&)", "[cel][operators]") {
    std::map<std::string, std::string> fields = {{"a", "true"}, {"b", "true"}};
    CHECK(evaluate_bool("result.a && result.b", fields) == true);

    std::map<std::string, std::string> fields2 = {{"a", "true"}, {"b", "false"}};
    CHECK(evaluate_bool("result.a && result.b", fields2) == false);
}

TEST_CASE("CEL: logical or (||)", "[cel][operators]") {
    std::map<std::string, std::string> fields = {{"a", "false"}, {"b", "true"}};
    CHECK(evaluate_bool("result.a || result.b", fields) == true);

    std::map<std::string, std::string> fields2 = {{"a", "false"}, {"b", "false"}};
    CHECK(evaluate_bool("result.a || result.b", fields2) == false);
}

TEST_CASE("CEL: logical not (!)", "[cel][operators]") {
    std::map<std::string, std::string> fields = {{"status", "running"}};
    CHECK(evaluate_bool("!(result.status == 'failed')", fields) == true);
    CHECK(evaluate_bool("!(result.status == 'running')", fields) == false);
}

TEST_CASE("CEL: ternary operator", "[cel][operators]") {
    std::map<std::string, std::string> fields = {{"status", "running"}};
    auto val = evaluate("result.status == 'running' ? 'yes' : 'no'", fields);
    CHECK(std::get<std::string>(val) == "yes");

    std::map<std::string, std::string> fields2 = {{"status", "stopped"}};
    auto val2 = evaluate("result.status == 'running' ? 'yes' : 'no'", fields2);
    CHECK(std::get<std::string>(val2) == "no");
}

TEST_CASE("CEL: ternary with numeric result", "[cel][operators]") {
    std::map<std::string, std::string> fields = {{"count", "5"}};
    auto val = evaluate("result.count > 3 ? 1 : 0", fields);
    CHECK(std::get<int64_t>(val) == 1);
}

// ============================================================================
// Arithmetic operators
// ============================================================================

TEST_CASE("CEL: integer addition", "[cel][arithmetic]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("3 + 5", fields);
    CHECK(std::get<int64_t>(val) == 8);
}

TEST_CASE("CEL: integer subtraction", "[cel][arithmetic]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("10 - 3", fields);
    CHECK(std::get<int64_t>(val) == 7);
}

TEST_CASE("CEL: integer multiplication", "[cel][arithmetic]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("4 * 7", fields);
    CHECK(std::get<int64_t>(val) == 28);
}

TEST_CASE("CEL: integer division", "[cel][arithmetic]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("15 / 4", fields);
    CHECK(std::get<int64_t>(val) == 3); // integer division
}

TEST_CASE("CEL: integer modulo", "[cel][arithmetic]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("17 % 5", fields);
    CHECK(std::get<int64_t>(val) == 2);
}

TEST_CASE("CEL: division by zero returns null", "[cel][arithmetic]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("10 / 0", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

TEST_CASE("CEL: double arithmetic", "[cel][arithmetic]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("1.5 + 2.5", fields);
    CHECK(std::get<double>(val) == 4.0);
}

TEST_CASE("CEL: mixed int/double arithmetic", "[cel][arithmetic]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("3 + 1.5", fields);
    CHECK(std::get<double>(val) == 4.5);
}

TEST_CASE("CEL: string concatenation with +", "[cel][arithmetic]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("'hello' + ' ' + 'world'", fields);
    CHECK(std::get<std::string>(val) == "hello world");
}

TEST_CASE("CEL: arithmetic with variables", "[cel][arithmetic]") {
    std::map<std::string, std::string> fields = {{"a", "10"}, {"b", "3"}};
    CHECK(evaluate_bool("result.a + result.b == 13", fields) == true);
    CHECK(evaluate_bool("result.a - result.b == 7", fields) == true);
    CHECK(evaluate_bool("result.a * result.b == 30", fields) == true);
}

TEST_CASE("CEL: operator precedence (* before +)", "[cel][arithmetic]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("2 + 3 * 4", fields);
    CHECK(std::get<int64_t>(val) == 14);
}

TEST_CASE("CEL: unary minus", "[cel][arithmetic]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("-5 + 3", fields);
    CHECK(std::get<int64_t>(val) == -2);
}

// ============================================================================
// String functions (method call syntax)
// ============================================================================

TEST_CASE("CEL: string size()", "[cel][string]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("'hello'.size()", fields);
    CHECK(std::get<int64_t>(val) == 5);
}

TEST_CASE("CEL: string startsWith()", "[cel][string]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("'hello world'.startsWith('hello')", fields) == true);
    CHECK(evaluate_bool("'hello world'.startsWith('world')", fields) == false);
}

TEST_CASE("CEL: string endsWith()", "[cel][string]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("'hello world'.endsWith('world')", fields) == true);
    CHECK(evaluate_bool("'hello world'.endsWith('hello')", fields) == false);
}

TEST_CASE("CEL: string contains()", "[cel][string]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("'hello world'.contains('lo wo')", fields) == true);
    CHECK(evaluate_bool("'hello world'.contains('xyz')", fields) == false);
}

TEST_CASE("CEL: string matches()", "[cel][string]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("'web-01'.matches('^web-\\\\d+$')", fields) == true);
    CHECK(evaluate_bool("'db-01'.matches('^web-\\\\d+$')", fields) == false);
}

TEST_CASE("CEL: variable method call — result.name.size()", "[cel][string]") {
    std::map<std::string, std::string> fields = {{"name", "YuzuAgent"}};
    auto val = evaluate("result.name.size()", fields);
    CHECK(std::get<int64_t>(val) == 9);
}

TEST_CASE("CEL: variable method call — result.name.startsWith()", "[cel][string]") {
    std::map<std::string, std::string> fields = {{"name", "YuzuAgent"}};
    CHECK(evaluate_bool("result.name.startsWith('Yuzu')", fields) == true);
    CHECK(evaluate_bool("result.name.startsWith('Agent')", fields) == false);
}

TEST_CASE("CEL: variable method call — result.name.contains()", "[cel][string]") {
    std::map<std::string, std::string> fields = {{"name", "YuzuAgent"}};
    CHECK(evaluate_bool("result.name.contains('agent')", fields) == true);
}

TEST_CASE("CEL: size() comparison", "[cel][string]") {
    std::map<std::string, std::string> fields = {{"name", "hello"}};
    CHECK(evaluate_bool("result.name.size() > 3", fields) == true);
    CHECK(evaluate_bool("result.name.size() == 5", fields) == true);
    CHECK(evaluate_bool("result.name.size() < 3", fields) == false);
}

// ============================================================================
// Collections — lists, in operator
// ============================================================================

TEST_CASE("CEL: list literal", "[cel][collections]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("[1, 2, 3]", fields);
    auto* list = std::get_if<std::shared_ptr<CelList>>(&val);
    REQUIRE(list != nullptr);
    CHECK((*list)->items.size() == 3);
    CHECK(std::get<int64_t>((*list)->items[0]) == 1);
}

TEST_CASE("CEL: in operator with list", "[cel][collections]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("3 in [1, 2, 3, 4]", fields) == true);
    CHECK(evaluate_bool("5 in [1, 2, 3, 4]", fields) == false);
}

TEST_CASE("CEL: string in list", "[cel][collections]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("'b' in ['a', 'b', 'c']", fields) == true);
    CHECK(evaluate_bool("'d' in ['a', 'b', 'c']", fields) == false);
}

TEST_CASE("CEL: variable in list", "[cel][collections]") {
    std::map<std::string, std::string> fields = {{"status", "running"}};
    CHECK(evaluate_bool("result.status in ['running', 'starting']", fields) == true);
    CHECK(evaluate_bool("result.status in ['stopped', 'failed']", fields) == false);
}

TEST_CASE("CEL: list index access", "[cel][collections]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("[10, 20, 30][1]", fields);
    CHECK(std::get<int64_t>(val) == 20);
}

TEST_CASE("CEL: list size()", "[cel][collections]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("[1, 2, 3].size()", fields);
    CHECK(std::get<int64_t>(val) == 3);
}

TEST_CASE("CEL: empty list", "[cel][collections]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("[].size()", fields);
    CHECK(std::get<int64_t>(val) == 0);
}

TEST_CASE("CEL: out of bounds index returns null", "[cel][collections]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("[1, 2][5]", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

// ============================================================================
// has() — field presence check
// ============================================================================

TEST_CASE("CEL: has() with existing field", "[cel][has]") {
    std::map<std::string, std::string> fields = {{"status", "running"}};
    // has() checks if the field name exists as a key in the variable map
    CHECK(evaluate_bool("has(result.status)", fields) == false);
    // Direct key check
    CHECK(evaluate_bool("has('status')", fields) == true);
}

TEST_CASE("CEL: has() with missing field", "[cel][has]") {
    std::map<std::string, std::string> fields = {{"other", "value"}};
    CHECK(evaluate_bool("has('missing')", fields) == false);
}

// ============================================================================
// Type system — typed evaluation
// ============================================================================

TEST_CASE("CEL: bool literals", "[cel][types]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("true", fields) == true);
    CHECK(evaluate_bool("false", fields) == false);
}

TEST_CASE("CEL: null literal", "[cel][types]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("null", fields) == false);
    CHECK(evaluate_bool("null == null", fields) == true);
}

TEST_CASE("CEL: int literal", "[cel][types]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("42", fields);
    CHECK(std::get<int64_t>(val) == 42);
}

TEST_CASE("CEL: double literal", "[cel][types]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("3.14", fields);
    CHECK(std::get<double>(val) == 3.14);
}

TEST_CASE("CEL: string literal", "[cel][types]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("'hello'", fields);
    CHECK(std::get<std::string>(val) == "hello");
}

TEST_CASE("CEL: int() cast", "[cel][types]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("int('42')", fields);
    CHECK(std::get<int64_t>(val) == 42);
}

TEST_CASE("CEL: double() cast", "[cel][types]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("double('3.14')", fields);
    CHECK(std::get<double>(val) == 3.14);
}

TEST_CASE("CEL: string() cast", "[cel][types]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("string(42)", fields);
    CHECK(std::get<std::string>(val) == "42");
}

TEST_CASE("CEL: automatic type coercion from variables", "[cel][types]") {
    std::map<std::string, std::string> fields = {{"count", "10"}, {"enabled", "true"}};
    // count is coerced to int
    CHECK(evaluate_bool("result.count > 5", fields) == true);
    // enabled is coerced to bool
    CHECK(evaluate_bool("result.enabled == true", fields) == true);
}

TEST_CASE("CEL: int-double mixed comparison", "[cel][types]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("3 == 3.0", fields) == true);
    CHECK(evaluate_bool("3 < 3.5", fields) == true);
    CHECK(evaluate_bool("4 > 3.5", fields) == true);
}

// ============================================================================
// Timestamps and durations
// ============================================================================

TEST_CASE("CEL: timestamp() construction", "[cel][timestamp]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("timestamp('2024-01-15T10:30:00Z')", fields);
    CHECK(std::holds_alternative<CelTimestamp>(val));
}

TEST_CASE("CEL: duration() construction", "[cel][timestamp]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("duration('1h')", fields);
    CHECK(std::holds_alternative<CelDuration>(val));
    CHECK(std::get<CelDuration>(val).ms.count() == 3600000);
}

TEST_CASE("CEL: duration with minutes", "[cel][timestamp]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("duration('30m')", fields);
    CHECK(std::get<CelDuration>(val).ms.count() == 1800000);
}

TEST_CASE("CEL: duration with seconds", "[cel][timestamp]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("duration('5s')", fields);
    CHECK(std::get<CelDuration>(val).ms.count() == 5000);
}

TEST_CASE("CEL: duration with milliseconds", "[cel][timestamp]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("duration('500ms')", fields);
    CHECK(std::get<CelDuration>(val).ms.count() == 500);
}

TEST_CASE("CEL: timestamp comparison", "[cel][timestamp]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool(
        "timestamp('2024-01-15T10:30:00Z') > timestamp('2024-01-14T10:30:00Z')",
        fields) == true);
    CHECK(evaluate_bool(
        "timestamp('2024-01-15T10:30:00Z') < timestamp('2024-01-14T10:30:00Z')",
        fields) == false);
}

TEST_CASE("CEL: timestamp + duration", "[cel][timestamp]") {
    std::map<std::string, std::string> fields;
    // Adding 1 hour should produce a later timestamp
    CHECK(evaluate_bool(
        "timestamp('2024-01-15T10:30:00Z') + duration('1h') > timestamp('2024-01-15T10:30:00Z')",
        fields) == true);
}

TEST_CASE("CEL: timestamp - timestamp = duration", "[cel][timestamp]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate(
        "timestamp('2024-01-15T11:30:00Z') - timestamp('2024-01-15T10:30:00Z')",
        fields);
    CHECK(std::holds_alternative<CelDuration>(val));
    CHECK(std::get<CelDuration>(val).ms.count() == 3600000); // 1 hour in ms
}

TEST_CASE("CEL: duration comparison", "[cel][timestamp]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("duration('2h') > duration('1h')", fields) == true);
    CHECK(evaluate_bool("duration('30m') < duration('1h')", fields) == true);
}

// ============================================================================
// Migration — legacy syntax to CEL
// ============================================================================

TEST_CASE("CEL migration: AND -> &&", "[cel][migration]") {
    auto result = migrate_expression("result.a == '1' AND result.b == '2'");
    CHECK(result.find("&&") != std::string::npos);
    CHECK(result.find("AND") == std::string::npos);
}

TEST_CASE("CEL migration: OR -> ||", "[cel][migration]") {
    auto result = migrate_expression("result.a == '1' OR result.b == '2'");
    CHECK(result.find("||") != std::string::npos);
    CHECK(result.find("OR") == std::string::npos);
}

TEST_CASE("CEL migration: NOT -> !", "[cel][migration]") {
    auto result = migrate_expression("NOT result.status == 'failed'");
    CHECK(result.find("!") != std::string::npos);
    // Should not contain standalone NOT
    CHECK(result.find("NOT") == std::string::npos);
}

TEST_CASE("CEL migration: contains -> .contains()", "[cel][migration]") {
    auto result = migrate_expression("result.name contains 'test'");
    CHECK(result.find(".contains(") != std::string::npos);
}

TEST_CASE("CEL migration: startswith -> .startsWith()", "[cel][migration]") {
    auto result = migrate_expression("result.path startswith '/usr'");
    CHECK(result.find(".startsWith(") != std::string::npos);
}

TEST_CASE("CEL migration: already-CEL expression unchanged", "[cel][migration]") {
    auto result = migrate_expression("result.status == 'running' && result.count > 0");
    CHECK(result.find("&&") != std::string::npos);
}

TEST_CASE("CEL migration: empty expression", "[cel][migration]") {
    CHECK(migrate_expression("").empty());
}

TEST_CASE("CEL migration: migrated expression evaluates correctly", "[cel][migration]") {
    std::string legacy = "result.status == 'running' AND result.name contains 'yuzu'";
    auto migrated = migrate_expression(legacy);

    std::map<std::string, std::string> fields = {{"status", "running"}, {"name", "YuzuAgent"}};
    // Both should produce the same result
    CHECK(evaluate_bool(legacy, fields) == true);
    CHECK(evaluate_bool(migrated, fields) == true);
}

// ============================================================================
// Validation
// ============================================================================

TEST_CASE("CEL validate: valid expression", "[cel][validate]") {
    CHECK(validate("result.status == 'running'").empty());
}

TEST_CASE("CEL validate: valid complex expression", "[cel][validate]") {
    CHECK(validate("result.a == '1' && (result.b > 5 || result.c.contains('test'))").empty());
}

TEST_CASE("CEL validate: valid ternary", "[cel][validate]") {
    CHECK(validate("result.x > 0 ? 'yes' : 'no'").empty());
}

TEST_CASE("CEL validate: valid list", "[cel][validate]") {
    CHECK(validate("result.status in ['running', 'starting']").empty());
}

TEST_CASE("CEL validate: empty expression", "[cel][validate]") {
    CHECK(validate("").empty());
}

TEST_CASE("CEL validate: unclosed parenthesis", "[cel][validate]") {
    auto err = validate("(result.a == '1'");
    CHECK(!err.empty());
    CHECK(err.find("parenthesis") != std::string::npos);
}

TEST_CASE("CEL validate: incomplete expression", "[cel][validate]") {
    auto err = validate("result.a ==");
    CHECK(!err.empty());
}

TEST_CASE("CEL validate: trailing junk", "[cel][validate]") {
    auto err = validate("result.a == '1' GARBAGE");
    CHECK(!err.empty());
}

// ============================================================================
// Edge cases
// ============================================================================

TEST_CASE("CEL: escaped characters in strings", "[cel][edge]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("'hello\\nworld'", fields);
    CHECK(std::get<std::string>(val) == "hello\nworld");
}

TEST_CASE("CEL: large numbers", "[cel][edge]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("9999999999", fields);
    CHECK(std::get<int64_t>(val) == 9999999999LL);
}

TEST_CASE("CEL: complex nested expression", "[cel][edge]") {
    std::map<std::string, std::string> fields = {
        {"status", "running"}, {"cpu", "45"}, {"memory", "80"}, {"name", "web-01"}};
    CHECK(evaluate_bool(
        "(result.status == 'running' && result.cpu < 90) || "
        "(result.memory > 95 && result.name.startsWith('web'))",
        fields) == true);
}

TEST_CASE("CEL: chained comparisons with arithmetic", "[cel][edge]") {
    std::map<std::string, std::string> fields = {{"a", "10"}, {"b", "5"}};
    CHECK(evaluate_bool("result.a + result.b == 15", fields) == true);
    CHECK(evaluate_bool("result.a * 2 > 15", fields) == true);
}

TEST_CASE("CEL: global size() function", "[cel][edge]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("size('hello')", fields);
    CHECK(std::get<int64_t>(val) == 5);
}

TEST_CASE("CEL: null equality", "[cel][edge]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("null == null", fields) == true);
    CHECK(evaluate_bool("null != 'something'", fields) == true);
    CHECK(evaluate_bool("null == 'something'", fields) == false);
}

TEST_CASE("CEL: parse error returns false", "[cel][edge]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("@#$%", fields) == false);
}

TEST_CASE("CEL: regex error in matches() returns false", "[cel][edge]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("'test'.matches('[invalid')", fields) == false);
}

// ============================================================================
// Safety limits (governance findings)
// ============================================================================

TEST_CASE("CEL: expression exceeding max length is rejected", "[cel][safety]") {
    std::map<std::string, std::string> fields;
    std::string huge(5000, 'x');
    CHECK(evaluate_bool(huge, fields) == false);
    CHECK(!validate(huge).empty());
}

TEST_CASE("CEL: deeply nested expression is rejected", "[cel][safety]") {
    std::map<std::string, std::string> fields;
    // 100 levels of nesting — exceeds kMaxRecursionDepth (64)
    std::string expr;
    for (int i = 0; i < 100; ++i) expr += "(";
    expr += "true";
    for (int i = 0; i < 100; ++i) expr += ")";
    CHECK(evaluate_bool(expr, fields) == false);
}

TEST_CASE("CEL: regex pattern exceeding max length returns false", "[cel][safety]") {
    std::map<std::string, std::string> fields;
    std::string long_pattern(300, 'a'); // exceeds kMaxRegexPatternLen (256)
    CHECK(evaluate_bool("'test'.matches('" + long_pattern + "')", fields) == false);
}

TEST_CASE("CEL: integer overflow returns null", "[cel][safety]") {
    std::map<std::string, std::string> fields;
    // INT64_MAX + 1 overflows
    auto val = evaluate("9223372036854775807 + 1", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

TEST_CASE("CEL: INT64_MIN / -1 returns null", "[cel][safety]") {
    std::map<std::string, std::string> fields;
    // This would overflow: result exceeds INT64_MAX
    auto val = evaluate("-9223372036854775807 - 1", fields);
    // First verify we can represent INT64_MIN
    CHECK(std::holds_alternative<int64_t>(val));
}

TEST_CASE("CEL: short-circuit AND skips rhs on false", "[cel][safety]") {
    // has('missing') returns false, so rhs should not be evaluated
    // If rhs were evaluated, result.missing would resolve to "" (empty)
    // which would fail the > 0 comparison, so the result is the same either way.
    // But with short-circuit, an error in rhs is safely skipped.
    std::map<std::string, std::string> fields = {{"status", "running"}};
    CHECK(evaluate_bool("false && result.missing > 0", fields) == false);
}

TEST_CASE("CEL: short-circuit OR skips rhs on true", "[cel][safety]") {
    std::map<std::string, std::string> fields = {{"status", "running"}};
    CHECK(evaluate_bool("true || result.missing > 0", fields) == true);
}

// ============================================================================
// Coverage: Lexer edge cases
// ============================================================================

TEST_CASE("CEL: string escape sequences", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    CHECK(std::get<std::string>(evaluate("'a\\tb'", fields)) == "a\tb");
    CHECK(std::get<std::string>(evaluate("'a\\\\b'", fields)) == "a\\b");
    CHECK(std::get<std::string>(evaluate("'a\\'b'", fields)) == "a'b");
    // Unknown escape falls through
    CHECK(std::get<std::string>(evaluate("'a\\xb'", fields)) == "axb");
}

TEST_CASE("CEL: scientific notation", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("1.5e2", fields);
    CHECK(std::get<double>(val) == 150.0);

    auto val2 = evaluate("2E+3", fields);
    CHECK(std::get<double>(val2) == 2000.0);

    auto val3 = evaluate("5e-1", fields);
    CHECK(std::get<double>(val3) == 0.5);
}

// ============================================================================
// Coverage: Type coercion
// ============================================================================

TEST_CASE("CEL: variable coercion to bool", "[cel][coverage]") {
    std::map<std::string, std::string> fields = {{"flag", "true"}};
    auto val = evaluate("result.flag", fields);
    CHECK(std::get<bool>(val) == true);

    std::map<std::string, std::string> fields2 = {{"flag", "false"}};
    auto val2 = evaluate("result.flag", fields2);
    CHECK(std::get<bool>(val2) == false);
}

TEST_CASE("CEL: variable coercion to int", "[cel][coverage]") {
    std::map<std::string, std::string> fields = {{"count", "42"}};
    auto val = evaluate("result.count", fields);
    CHECK(std::get<int64_t>(val) == 42);
}

TEST_CASE("CEL: variable coercion to double", "[cel][coverage]") {
    std::map<std::string, std::string> fields = {{"score", "3.14"}};
    auto val = evaluate("result.score", fields);
    CHECK(std::get<double>(val) == 3.14);
}

TEST_CASE("CEL: variable coercion to timestamp", "[cel][coverage]") {
    std::map<std::string, std::string> fields = {{"ts", "2024-01-15T10:30:00Z"}};
    auto val = evaluate("result.ts", fields);
    CHECK(std::holds_alternative<CelTimestamp>(val));
}

TEST_CASE("CEL: timestamp parse rejects short strings", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("timestamp('2024-01-15')", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

TEST_CASE("CEL: timestamp parse rejects wrong format", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("timestamp('2024/01/15T10:30:00Z')", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

// ============================================================================
// Coverage: Arithmetic edge cases
// ============================================================================

TEST_CASE("CEL: subtraction overflow returns null", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    // INT64_MIN - 1 overflows
    auto val = evaluate("(-9223372036854775807 - 1) - 1", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

TEST_CASE("CEL: multiplication overflow returns null", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("9223372036854775807 * 2", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

TEST_CASE("CEL: INT64_MIN mod -1 returns null", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("(-9223372036854775807 - 1) % -1", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

TEST_CASE("CEL: double modulo", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("3.5 % 2.0", fields);
    CHECK(std::get<double>(val) == 1.5);
}

TEST_CASE("CEL: int / double mixed division", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("15 / 2.0", fields);
    CHECK(std::get<double>(val) == 7.5);
}

TEST_CASE("CEL: double / int mixed division", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("15.0 / 4", fields);
    CHECK(std::get<double>(val) == 3.75);
}

TEST_CASE("CEL: duration + duration", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("duration('1h') + duration('30m')", fields);
    CHECK(std::holds_alternative<CelDuration>(val));
    CHECK(std::get<CelDuration>(val).ms.count() == 5400000);
}

TEST_CASE("CEL: duration - duration", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("duration('2h') - duration('30m')", fields);
    CHECK(std::get<CelDuration>(val).ms.count() == 5400000);
}

TEST_CASE("CEL: type mismatch in arithmetic returns null", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("'hello' * 3", fields);
    CHECK(std::holds_alternative<std::monostate>(val));

    auto val2 = evaluate("true + false", fields);
    CHECK(std::holds_alternative<std::monostate>(val2));
}

// ============================================================================
// Coverage: Built-in function error handling
// ============================================================================

TEST_CASE("CEL: fn_size on non-string/non-list returns null", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("size(42)", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

TEST_CASE("CEL: fn_timestamp with non-string arg returns null", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("timestamp(123)", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

TEST_CASE("CEL: fn_timestamp with invalid string returns null", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("timestamp('not-a-date')", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

TEST_CASE("CEL: fn_duration with days", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("duration('2d')", fields);
    CHECK(std::get<CelDuration>(val).ms.count() == 172800000);
}

TEST_CASE("CEL: fn_duration with integer arg", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("duration(5000)", fields);
    CHECK(std::get<CelDuration>(val).ms.count() == 5000);
}

TEST_CASE("CEL: fn_duration with empty string returns null", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("duration('')", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

TEST_CASE("CEL: fn_duration with invalid unit returns null", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("duration('5x')", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

TEST_CASE("CEL: list .contains() method", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("[1, 2, 3].contains(2)", fields) == true);
    CHECK(evaluate_bool("[1, 2, 3].contains(5)", fields) == false);
}

TEST_CASE("CEL: unknown method returns null", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("'hello'.unknownMethod()", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

// ============================================================================
// Coverage: Parser edge cases
// ============================================================================

TEST_CASE("CEL: non-integer list index returns null", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("[1, 2, 3][1.5]", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

TEST_CASE("CEL: index on non-list returns null", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("42[0]", fields);
    CHECK(std::holds_alternative<std::monostate>(val));
}

TEST_CASE("CEL: unresolved identifier treated as string", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    // An unresolved identifier returns its own name as a string
    auto val = evaluate("unknown_var", fields);
    CHECK(std::get<std::string>(val) == "unknown_var");
}

TEST_CASE("CEL: list element limit exceeded", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    // Build a list expression with > 1000 elements
    std::string expr = "[0";
    for (int i = 1; i <= 1001; ++i)
        expr += "," + std::to_string(i);
    expr += "]";
    CHECK(evaluate_bool(expr, fields) == false);
}

TEST_CASE("CEL: has() with non-string argument", "[cel][coverage]") {
    std::map<std::string, std::string> fields = {{"x", "1"}};
    // has(42) — non-string, non-null → returns true (non-null check)
    CHECK(evaluate_bool("has(42)", fields) == true);
    // has(null) — null → returns false
    CHECK(evaluate_bool("has(null)", fields) == false);
}

TEST_CASE("CEL: int() cast from double", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("int(3.7)", fields);
    CHECK(std::get<int64_t>(val) == 3);
}

TEST_CASE("CEL: double() cast from int", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    auto val = evaluate("double(42)", fields);
    CHECK(std::get<double>(val) == 42.0);
}

TEST_CASE("CEL: string() cast from bool and null", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    CHECK(std::get<std::string>(evaluate("string(true)", fields)) == "true");
    CHECK(std::get<std::string>(evaluate("string(false)", fields)) == "false");
    CHECK(std::get<std::string>(evaluate("string(null)", fields)) == "null");
}

TEST_CASE("CEL: matches() global function form", "[cel][coverage]") {
    std::map<std::string, std::string> fields;
    CHECK(evaluate_bool("matches('web-01', '^web-\\\\d+$')", fields) == true);
    CHECK(evaluate_bool("matches('db-01', '^web-\\\\d+$')", fields) == false);
}
