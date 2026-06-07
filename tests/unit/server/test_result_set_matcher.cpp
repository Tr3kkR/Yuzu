/**
 * test_result_set_matcher.cpp — unit coverage for the async result-set
 * membership matcher (scope walking PR-D, design §3.3).
 *
 * The matcher is a pure function of (matcher_json, status, output), so it
 * needs no SQLite / dispatch / tracker fixtures — every per-producer rule
 * (SUCCESS default, tar_rows_ge, any_response, column/op/value over both the
 * tar pipe shape and a JSON array-of-objects) is asserted directly here. The
 * server maintenance thread is a thin caller; this is where the rule lives.
 */

#include "result_set_matcher.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server::rs_matcher;

namespace {
// A tar.sql response: `__schema__` header, `|`-joined rows, `__total__` trailer.
std::string tar_rows(int n, const std::string& col = "pid") {
    std::string out = "__schema__|" + col;
    for (int i = 0; i < n; ++i)
        out += "\n" + std::to_string(1000 + i);
    out += "\n__total__|" + std::to_string(n);
    return out;
}
constexpr int kOk = kStatusSuccess; // 1
constexpr int kFail = 2;            // any non-SUCCESS
} // namespace

TEST_CASE("matcher: non-success response never qualifies", "[result_set][matcher]") {
    // Even a matcher that would otherwise pass must reject a failed exec —
    // an errored plugin is not evidence of a hit.
    REQUIRE_FALSE(response_matches("", kFail, tar_rows(5)));
    REQUIRE_FALSE(response_matches(R"({"kind":"any_response"})", kFail, tar_rows(5)));
    REQUIRE_FALSE(response_matches(R"({"kind":"tar_rows_ge","n":1})", kFail, tar_rows(5)));
}

TEST_CASE("matcher: empty / blank matcher = SUCCESS default", "[result_set][matcher]") {
    REQUIRE(response_matches("", kOk, "anything"));
    REQUIRE(response_matches("{}", kOk, "anything"));
    // Unparseable JSON falls back to the SUCCESS default rather than emptying.
    REQUIRE(response_matches("not json", kOk, "anything"));
}

TEST_CASE("matcher: any_response includes every SUCCESS responder", "[result_set][matcher]") {
    REQUIRE(response_matches(R"({"kind":"any_response"})", kOk, tar_rows(0)));
    REQUIRE(response_matches(R"({"kind":"any_response"})", kOk, "error|whatever"));
    REQUIRE_FALSE(response_matches(R"({"kind":"any_response"})", kFail, tar_rows(3)));
}

TEST_CASE("matcher: tar_rows_ge thresholds on row count", "[result_set][matcher]") {
    REQUIRE(response_matches(R"({"kind":"tar_rows_ge","n":1})", kOk, tar_rows(1)));
    REQUIRE(response_matches(R"({"kind":"tar_rows_ge","n":1})", kOk, tar_rows(5)));
    REQUIRE_FALSE(response_matches(R"({"kind":"tar_rows_ge","n":1})", kOk, tar_rows(0)));
    REQUIRE(response_matches(R"({"kind":"tar_rows_ge","n":3})", kOk, tar_rows(3)));
    REQUIRE_FALSE(response_matches(R"({"kind":"tar_rows_ge","n":3})", kOk, tar_rows(2)));
    // n defaults to 1 when omitted.
    REQUIRE(response_matches(R"({"kind":"tar_rows_ge"})", kOk, tar_rows(1)));
    REQUIRE_FALSE(response_matches(R"({"kind":"tar_rows_ge"})", kOk, tar_rows(0)));
}

TEST_CASE("matcher: tar error output counts as 0 rows", "[result_set][matcher]") {
    REQUIRE(tar_row_count("error|missing required 'sql' parameter") == 0);
    REQUIRE_FALSE(response_matches(R"({"kind":"tar_rows_ge","n":1})", kOk, "error|nope"));
}

TEST_CASE("matcher: tar_row_count trailer + fallback", "[result_set][matcher]") {
    REQUIRE(tar_row_count(tar_rows(4)) == 4);
    REQUIRE(tar_row_count(tar_rows(0)) == 0);
    // No trailer → fall back to counting data lines (schema excluded).
    REQUIRE(tar_row_count("__schema__|a\nx\ny") == 2);
    REQUIRE(tar_row_count("") == 0);
}

TEST_CASE("matcher: unknown kind excludes conservatively", "[result_set][matcher]") {
    REQUIRE_FALSE(response_matches(R"({"kind":"does_not_exist"})", kOk, tar_rows(9)));
}

TEST_CASE("matcher: column op over tar pipe shape", "[result_set][matcher]") {
    std::string out = "__schema__|pid|sha256\n42|abc\n43|def\n__total__|2";
    REQUIRE(response_matches(R"({"column":"sha256","op":"eq","value":"abc"})", kOk, out));
    REQUIRE(response_matches(R"({"column":"sha256","op":"eq","value":"def"})", kOk, out));
    REQUIRE_FALSE(response_matches(R"({"column":"sha256","op":"eq","value":"zzz"})", kOk, out));
    // in / value_set
    REQUIRE(response_matches(R"({"column":"sha256","op":"in","value_set":["x","def"]})", kOk, out));
    REQUIRE_FALSE(
        response_matches(R"({"column":"sha256","op":"in","value_set":["x","y"]})", kOk, out));
    // contains
    REQUIRE(response_matches(R"({"column":"sha256","op":"contains","value":"e"})", kOk, out));
    // exists (non-empty cell)
    REQUIRE(response_matches(R"({"column":"pid","op":"exists"})", kOk, out));
    // unknown column never matches
    REQUIRE_FALSE(response_matches(R"({"column":"nope","op":"exists"})", kOk, out));
}

TEST_CASE("matcher: column op over JSON array-of-objects fallback", "[result_set][matcher]") {
    std::string out = R"([{"sha256":"bad1","path":"/a"},{"sha256":"good","path":"/b"}])";
    REQUIRE(response_matches(R"({"column":"sha256","op":"in","value_set":["bad1","bad2"]})", kOk,
                             out));
    REQUIRE_FALSE(
        response_matches(R"({"column":"sha256","op":"in","value_set":["nope"]})", kOk, out));
    // {"rows":[...]} envelope is also accepted.
    std::string env = R"({"rows":[{"n":7}]})";
    REQUIRE(response_matches(R"({"column":"n","op":"eq","value":"7"})", kOk, env));
}

TEST_CASE("matcher: malformed column matcher falls back to default", "[result_set][matcher]") {
    // Has neither value nor value_set for eq → row never satisfies, but the
    // matcher SHAPE is recognised, so it's not the "typo → default" path; it
    // simply finds no matching row. A SUCCESS responder with such a matcher
    // and no rows yields no membership.
    std::string out = "__schema__|c\nv\n__total__|1";
    REQUIRE_FALSE(response_matches(R"({"column":"c","op":"eq"})", kOk, out));
    // A matcher object with neither kind nor column is treated as default.
    REQUIRE(response_matches(R"({"foo":"bar"})", kOk, out));
}
