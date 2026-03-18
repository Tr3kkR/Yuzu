#include <yuzu/plugin.h>
#include <yuzu/sdk_utilities.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::sdk;
using namespace std::string_view_literals;

// ═══════════════════════════════════════════════════════════════════════════
// C++ API: split_lines
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("split_lines handles LF", "[sdk_utilities]") {
    auto lines = split_lines("a\nb\nc");
    REQUIRE(lines.size() == 3);
    CHECK(lines[0] == "a");
    CHECK(lines[1] == "b");
    CHECK(lines[2] == "c");
}

TEST_CASE("split_lines handles CRLF", "[sdk_utilities]") {
    auto lines = split_lines("a\r\nb\r\nc");
    REQUIRE(lines.size() == 3);
    CHECK(lines[0] == "a");
    CHECK(lines[1] == "b");
    CHECK(lines[2] == "c");
}

TEST_CASE("split_lines handles bare CR", "[sdk_utilities]") {
    auto lines = split_lines("a\rb\rc");
    REQUIRE(lines.size() == 3);
    CHECK(lines[0] == "a");
    CHECK(lines[1] == "b");
    CHECK(lines[2] == "c");
}

TEST_CASE("split_lines handles mixed line endings", "[sdk_utilities]") {
    auto lines = split_lines("a\nb\r\nc\rd");
    REQUIRE(lines.size() == 4);
    CHECK(lines[0] == "a");
    CHECK(lines[1] == "b");
    CHECK(lines[2] == "c");
    CHECK(lines[3] == "d");
}

TEST_CASE("split_lines empty input returns empty vector", "[sdk_utilities]") {
    auto lines = split_lines("");
    CHECK(lines.empty());
}

TEST_CASE("split_lines single line no newline", "[sdk_utilities]") {
    auto lines = split_lines("hello");
    REQUIRE(lines.size() == 1);
    CHECK(lines[0] == "hello");
}

TEST_CASE("split_lines trailing newline produces empty last line", "[sdk_utilities]") {
    auto lines = split_lines("a\nb\n");
    REQUIRE(lines.size() == 3);
    CHECK(lines[0] == "a");
    CHECK(lines[1] == "b");
    CHECK(lines[2] == "");
}

// ═══════════════════════════════════════════════════════════════════════════
// C++ API: table_to_json
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("table_to_json basic conversion", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"name", "role", "status"};
    auto result = table_to_json("alice|admin|active\nbob|user|inactive", cols);
    REQUIRE(result.has_value());

    auto json = nlohmann::json::parse(*result);
    REQUIRE(json.is_array());
    REQUIRE(json.size() == 2);
    CHECK(json[0]["name"] == "alice");
    CHECK(json[0]["role"] == "admin");
    CHECK(json[0]["status"] == "active");
    CHECK(json[1]["name"] == "bob");
    CHECK(json[1]["role"] == "user");
    CHECK(json[1]["status"] == "inactive");
}

TEST_CASE("table_to_json with escaped pipes", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"cmd", "output"};
    auto result = table_to_json("ls|file1\\|file2\\|file3", cols);
    REQUIRE(result.has_value());

    auto json = nlohmann::json::parse(*result);
    REQUIRE(json.size() == 1);
    CHECK(json[0]["cmd"] == "ls");
    CHECK(json[0]["output"] == "file1|file2|file3");
}

TEST_CASE("table_to_json empty fields preserved as empty strings", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"a", "b", "c"};
    auto result = table_to_json("x||z", cols);
    REQUIRE(result.has_value());

    auto json = nlohmann::json::parse(*result);
    REQUIRE(json.size() == 1);
    CHECK(json[0]["a"] == "x");
    CHECK(json[0]["b"] == "");
    CHECK(json[0]["c"] == "z");
}

TEST_CASE("table_to_json mismatched column count fills missing with empty", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"a", "b", "c"};
    auto result = table_to_json("only_one", cols);
    REQUIRE(result.has_value());

    auto json = nlohmann::json::parse(*result);
    REQUIRE(json.size() == 1);
    CHECK(json[0]["a"] == "only_one");
    CHECK(json[0]["b"] == "");
    CHECK(json[0]["c"] == "");
}

TEST_CASE("table_to_json with type hints", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"name", "count", "ratio", "active"};
    std::vector<ColumnType> types = {ColumnType::kString, ColumnType::kInt, ColumnType::kFloat,
                                     ColumnType::kBool};
    auto result = table_to_json("widget|42|3.14|true", cols, types);
    REQUIRE(result.has_value());

    auto json = nlohmann::json::parse(*result);
    REQUIRE(json.size() == 1);
    CHECK(json[0]["name"] == "widget");
    CHECK(json[0]["count"] == 42);
    CHECK(json[0]["ratio"] == 3.14);
    CHECK(json[0]["active"] == true);
}

TEST_CASE("table_to_json type hint fallback on bad value", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"val"};
    std::vector<ColumnType> types = {ColumnType::kInt};
    auto result = table_to_json("not_a_number", cols, types);
    REQUIRE(result.has_value());

    auto json = nlohmann::json::parse(*result);
    CHECK(json[0]["val"] == "not_a_number");
}

TEST_CASE("table_to_json skips empty lines", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"x"};
    auto result = table_to_json("a\n\nb", cols);
    REQUIRE(result.has_value());

    auto json = nlohmann::json::parse(*result);
    CHECK(json.size() == 2);
}

TEST_CASE("table_to_json empty column_names returns error", "[sdk_utilities]") {
    std::vector<std::string_view> cols;
    auto result = table_to_json("data", cols);
    CHECK(!result.has_value());
}

TEST_CASE("table_to_json with unicode", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"greeting", "emoji"};
    auto result = table_to_json("こんにちは|🎉", cols);
    REQUIRE(result.has_value());

    auto json = nlohmann::json::parse(*result);
    CHECK(json[0]["greeting"] == "こんにちは");
    CHECK(json[0]["emoji"] == "🎉");
}

// ═══════════════════════════════════════════════════════════════════════════
// C++ API: json_to_table
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("json_to_table basic conversion", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"name", "role"};
    auto result =
        json_to_table(R"([{"name":"alice","role":"admin"},{"name":"bob","role":"user"}])", cols);
    REQUIRE(result.has_value());
    CHECK(*result == "alice|admin\nbob|user");
}

TEST_CASE("json_to_table escapes pipe characters in values", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"cmd"};
    auto result = json_to_table(R"([{"cmd":"a|b"}])", cols);
    REQUIRE(result.has_value());
    CHECK(*result == "a\\|b");
}

TEST_CASE("json_to_table missing key produces empty field", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"a", "b"};
    auto result = json_to_table(R"([{"a":"val"}])", cols);
    REQUIRE(result.has_value());
    CHECK(*result == "val|");
}

TEST_CASE("json_to_table null value produces empty field", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"a"};
    auto result = json_to_table(R"([{"a":null}])", cols);
    REQUIRE(result.has_value());
    CHECK(*result == "");
}

TEST_CASE("json_to_table numeric values rendered as text", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"n", "f", "b"};
    auto result = json_to_table(R"([{"n":42,"f":3.14,"b":true}])", cols);
    REQUIRE(result.has_value());
    CHECK(*result == "42|3.14|true");
}

TEST_CASE("json_to_table invalid JSON returns error", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"a"};
    auto result = json_to_table("{bad json", cols);
    CHECK(!result.has_value());
    CHECK(result.error().code == 2);
}

TEST_CASE("json_to_table non-array returns error", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"a"};
    auto result = json_to_table(R"({"a":"b"})", cols);
    CHECK(!result.has_value());
    CHECK(result.error().code == 3);
}

TEST_CASE("json_to_table non-object element returns error", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"a"};
    auto result = json_to_table(R"([42])", cols);
    CHECK(!result.has_value());
    CHECK(result.error().code == 4);
}

TEST_CASE("json_to_table empty column_names returns error", "[sdk_utilities]") {
    std::vector<std::string_view> cols;
    auto result = json_to_table(R"([{"a":"b"}])", cols);
    CHECK(!result.has_value());
}

// ═══════════════════════════════════════════════════════════════════════════
// C++ API: generate_sequence
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("generate_sequence basic", "[sdk_utilities]") {
    auto result = generate_sequence(1, 3);
    CHECK(result == "1\n2\n3");
}

TEST_CASE("generate_sequence with prefix", "[sdk_utilities]") {
    auto result = generate_sequence(0, 3, "item-");
    CHECK(result == "item-0\nitem-1\nitem-2");
}

TEST_CASE("generate_sequence count zero returns empty", "[sdk_utilities]") {
    auto result = generate_sequence(1, 0);
    CHECK(result.empty());
}

TEST_CASE("generate_sequence count one returns single item", "[sdk_utilities]") {
    auto result = generate_sequence(42, 1, "id_");
    CHECK(result == "id_42");
}

TEST_CASE("generate_sequence negative start", "[sdk_utilities]") {
    auto result = generate_sequence(-2, 4);
    CHECK(result == "-2\n-1\n0\n1");
}

// ═══════════════════════════════════════════════════════════════════════════
// Roundtrip: table → JSON → table
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("roundtrip table->json->table", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"host", "os", "version"};
    std::string original = "srv01|linux|6.1\nsrv02|windows|10.0";

    auto json_result = table_to_json(original, cols);
    REQUIRE(json_result.has_value());

    auto table_result = json_to_table(*json_result, cols);
    REQUIRE(table_result.has_value());
    CHECK(*table_result == original);
}

TEST_CASE("roundtrip with escaped pipes", "[sdk_utilities]") {
    std::vector<std::string_view> cols = {"data"};
    std::string original = "a\\|b\\|c";

    auto json_result = table_to_json(original, cols);
    REQUIRE(json_result.has_value());

    auto json = nlohmann::json::parse(*json_result);
    CHECK(json[0]["data"] == "a|b|c");

    auto table_result = json_to_table(*json_result, cols);
    REQUIRE(table_result.has_value());
    CHECK(*table_result == original);
}

// ═══════════════════════════════════════════════════════════════════════════
// C ABI: yuzu_table_to_json
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("C ABI table_to_json basic", "[sdk_utilities][c_abi]") {
    const char* cols[] = {"name", "role"};
    char* result = yuzu_table_to_json("alice|admin", cols, 2);
    REQUIRE(result != nullptr);

    auto json = nlohmann::json::parse(result);
    CHECK(json[0]["name"] == "alice");
    CHECK(json[0]["role"] == "admin");

    yuzu_free_string(result);
}

TEST_CASE("C ABI table_to_json null input returns null", "[sdk_utilities][c_abi]") {
    const char* cols[] = {"a"};
    CHECK(yuzu_table_to_json(nullptr, cols, 1) == nullptr);
}

TEST_CASE("C ABI table_to_json null columns returns null", "[sdk_utilities][c_abi]") {
    CHECK(yuzu_table_to_json("data", nullptr, 1) == nullptr);
}

TEST_CASE("C ABI table_to_json zero columns returns null", "[sdk_utilities][c_abi]") {
    const char* cols[] = {"a"};
    CHECK(yuzu_table_to_json("data", cols, 0) == nullptr);
}

// ═══════════════════════════════════════════════════════════════════════════
// C ABI: yuzu_json_to_table
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("C ABI json_to_table basic", "[sdk_utilities][c_abi]") {
    const char* cols[] = {"x"};
    char* result = yuzu_json_to_table(R"([{"x":"hello"}])", cols, 1);
    REQUIRE(result != nullptr);
    CHECK(std::string(result) == "hello");
    yuzu_free_string(result);
}

TEST_CASE("C ABI json_to_table invalid json returns null", "[sdk_utilities][c_abi]") {
    const char* cols[] = {"x"};
    CHECK(yuzu_json_to_table("{bad", cols, 1) == nullptr);
}

// ═══════════════════════════════════════════════════════════════════════════
// C ABI: yuzu_split_lines
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("C ABI split_lines normalizes CRLF to LF", "[sdk_utilities][c_abi]") {
    char* result = yuzu_split_lines("a\r\nb\r\nc");
    REQUIRE(result != nullptr);
    CHECK(std::string(result) == "a\nb\nc");
    yuzu_free_string(result);
}

TEST_CASE("C ABI split_lines normalizes bare CR to LF", "[sdk_utilities][c_abi]") {
    char* result = yuzu_split_lines("a\rb\rc");
    REQUIRE(result != nullptr);
    CHECK(std::string(result) == "a\nb\nc");
    yuzu_free_string(result);
}

TEST_CASE("C ABI split_lines null input returns null", "[sdk_utilities][c_abi]") {
    CHECK(yuzu_split_lines(nullptr) == nullptr);
}

// ═══════════════════════════════════════════════════════════════════════════
// C ABI: yuzu_generate_sequence
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("C ABI generate_sequence basic", "[sdk_utilities][c_abi]") {
    char* result = yuzu_generate_sequence(1, 3, "host-");
    REQUIRE(result != nullptr);
    CHECK(std::string(result) == "host-1\nhost-2\nhost-3");
    yuzu_free_string(result);
}

TEST_CASE("C ABI generate_sequence null prefix treated as empty", "[sdk_utilities][c_abi]") {
    char* result = yuzu_generate_sequence(5, 2, nullptr);
    REQUIRE(result != nullptr);
    CHECK(std::string(result) == "5\n6");
    yuzu_free_string(result);
}

TEST_CASE("C ABI generate_sequence zero count returns null", "[sdk_utilities][c_abi]") {
    CHECK(yuzu_generate_sequence(1, 0, "x") == nullptr);
}

// ═══════════════════════════════════════════════════════════════════════════
// C ABI: yuzu_free_string
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("C ABI free_string accepts null safely", "[sdk_utilities][c_abi]") {
    yuzu_free_string(nullptr); // must not crash
}
