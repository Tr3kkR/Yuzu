// Pure (no-DB) unit tests for pg::to_text_array — the PostgreSQL text-array
// literal builder behind the batched `unnest($N::text[])` ingest (#1664). The
// escaping here is the one genuinely novel, silently-corruption-prone piece of
// the batch path, and its failure mode (a malformed array literal) only
// surfaces against a live PG. These tests pin the literal bytes directly so the
// contract is validated without a database, on every platform, in the default
// (non-PG-gated) test run.

#include <catch2/catch_test_macros.hpp>

#include "pg/pg_array.hpp"

#include <string>
#include <string_view>
#include <vector>

using yuzu::server::pg::to_text_array;

TEST_CASE("to_text_array: empty and trivial shapes", "[pg][array]") {
    REQUIRE(to_text_array({}) == "{}");
    REQUIRE(to_text_array({""}) == R"({""})");
    REQUIRE(to_text_array({"hello"}) == R"({"hello"})");
    REQUIRE(to_text_array({"a", "b", "c"}) == R"({"a","b","c"})");
}

TEST_CASE("to_text_array: every element is quoted so array metacharacters are inert",
          "[pg][array]") {
    // Comma, braces, and leading/trailing whitespace would all need quoting in
    // PG array syntax; unconditional quoting makes them ordinary content.
    REQUIRE(to_text_array({"a,b"}) == R"({"a,b"})");
    REQUIRE(to_text_array({"{x}"}) == R"({"{x}"})");
    REQUIRE(to_text_array({"  pad  "}) == R"({"  pad  "})");
    // The bareword NULL must stay the 4-char string, never bind SQL NULL.
    REQUIRE(to_text_array({"NULL"}) == R"({"NULL"})");
}

TEST_CASE("to_text_array: backslash and double-quote are escaped", "[pg][array]") {
    REQUIRE(to_text_array({R"(a"b)"}) == R"({"a\"b"})");
    REQUIRE(to_text_array({R"(a\b)"}) == R"({"a\\b"})");
    // Element containing both, adjacent (backslash then quote). Built from
    // explicit chars so the expected literal carries no escaping ambiguity:
    // input \"  ->  {"\\\""}
    const std::string both{'\\', '"'};
    const std::string both_out{'{', '"', '\\', '\\', '\\', '"', '"', '}'};
    REQUIRE(to_text_array({std::string_view(both)}) == both_out);
}

TEST_CASE("to_text_array: multibyte UTF-8 and the wire delimiters pass through verbatim",
          "[pg][array]") {
    // é = 0xC3 0xA9 — a valid 2-byte sequence; must not be altered.
    REQUIRE(to_text_array({"caf\xC3\xA9"}) == "{\"caf\xC3\xA9\"}");
    // 0x1F (unit) / 0x1E (record) are the agent's field/entry delimiters; they
    // are ordinary bytes to array syntax and must survive unchanged.
    REQUIRE(to_text_array({std::string_view("a\x1f"
                                            "b",
                                            3)}) == std::string("{\"a\x1f"
                                                                "b\"}"));
}

TEST_CASE("to_text_array: NUL is dropped, keeping the literal well-formed", "[pg][array]") {
    // A 0x00 cannot ride libpq's NUL-terminated text param; dropping it (rather
    // than truncating the whole literal) keeps the batch ingest non-erroring.
    const std::string with_nul("a\0b", 3);
    REQUIRE(to_text_array({std::string_view(with_nul)}) == R"({"ab"})");
    // NUL between otherwise-valid elements must not corrupt element framing.
    const std::string e0("x\0", 2);
    REQUIRE(to_text_array({std::string_view(e0), std::string_view("y")}) == R"({"x","y"})");
}
