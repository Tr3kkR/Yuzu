// MCP progress bridge (track 2f PR 3) — the consumer-side projection of the
// ExecutionEventBus onto the MCP session's SSE surfaces.
//
// This rung (3a) exercises the pure JSON-RPC helpers the bridge projects through:
// _meta.progressToken extraction and the notifications/progress builder. The bridge
// class itself (records, mailbox, projector) lands in a later rung and grows its tests
// here.

#include <catch2/catch_test_macros.hpp>

#include "../../../server/core/src/mcp_jsonrpc.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace mcp = yuzu::server::mcp;
using nlohmann::json;

TEST_CASE("extract_progress_token — accepts string and integer tokens verbatim",
          "[mcp][bridge][2f]") {
    SECTION("string token") {
        auto p = json::parse(R"({"_meta":{"progressToken":"abc-123"}})");
        auto tok = mcp::extract_progress_token(p);
        REQUIRE(tok.has_value());
        CHECK(tok->is_string());
        CHECK(tok->get<std::string>() == "abc-123");
    }
    SECTION("integer token") {
        auto p = json::parse(R"({"_meta":{"progressToken":42}})");
        auto tok = mcp::extract_progress_token(p);
        REQUIRE(tok.has_value());
        CHECK(tok->is_number_integer());
        CHECK(tok->get<int>() == 42);
    }
    SECTION("negative integer token") {
        auto p = json::parse(R"({"_meta":{"progressToken":-7}})");
        auto tok = mcp::extract_progress_token(p);
        REQUIRE(tok.has_value());
        CHECK(tok->get<int>() == -7);
    }
}

TEST_CASE("extract_progress_token — anything not string|integer is ignored (no error)",
          "[mcp][bridge][2f]") {
    // The spec lets a server decline to emit progress, so an unusable or absent token is
    // simply "no progress requested" — never a parse failure.
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({})")).has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{}})")).has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":42})")).has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{"progressToken":3.14}})"))
                    .has_value()); // float rejected
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{"progressToken":true}})"))
                    .has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{"progressToken":null}})"))
                    .has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"({"_meta":{"progressToken":{}}})"))
                    .has_value());
    CHECK_FALSE(mcp::extract_progress_token(json::parse(R"([1,2,3])")).has_value()); // non-object
}

TEST_CASE("progress_notification — token echoed verbatim, shape is valid JSON-RPC",
          "[mcp][bridge][2f]") {
    SECTION("string token stays a string; execution_id in _meta") {
        auto tok = json("tok-abc");
        auto msg = mcp::progress_notification(tok, /*progress=*/3, /*total=*/5, "3/5 responded",
                                              "exec-xyz");
        auto parsed = json::parse(msg); // must be well-formed
        CHECK(parsed["jsonrpc"] == "2.0");
        CHECK(parsed["method"] == "notifications/progress");
        CHECK(parsed["params"]["progressToken"] == "tok-abc"); // string, not "\"tok-abc\""
        CHECK(parsed["params"]["progressToken"].is_string());
        CHECK(parsed["params"]["progress"] == 3);
        CHECK(parsed["params"]["total"] == 5);
        CHECK(parsed["params"]["message"] == "3/5 responded");
        CHECK(parsed["params"]["_meta"]["yuzu.execution_id"] == "exec-xyz");
        CHECK_FALSE(parsed.contains("id")); // a notification has no id
    }
    SECTION("integer token is emitted as a number, never stringified") {
        auto tok = json(99);
        auto parsed = json::parse(
            mcp::progress_notification(tok, 1, 1, "done", "exec-1"));
        CHECK(parsed["params"]["progressToken"].is_number_integer());
        CHECK(parsed["params"]["progressToken"] == 99);
    }
    SECTION("message with quotes/newlines is escaped into valid JSON") {
        auto tok = json("t");
        auto parsed = json::parse(
            mcp::progress_notification(tok, 0, 0, "line\"one\"\nline two", "exec-1"));
        CHECK(parsed["params"]["message"] == "line\"one\"\nline two");
    }
}
