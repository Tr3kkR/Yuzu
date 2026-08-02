#include <yuzu/contracts/adr31/b3_platform.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <string>

namespace contracts = yuzu::contracts::adr31;

TEST_CASE("ADR-0031 B3 platform request has a deterministic round trip", "[adr31][contract][b3]") {
    contracts::B3PlatformRequest request{
        .correlation_id = "req-contract-0001",
        .securable = "GuaranteedState",
        .operation = contracts::CoreOperation::Read,
        .scope = nlohmann::json{{"kind", "fleet"}},
    };

    const auto encoded = contracts::encode_b3_platform_request(request);
    REQUIRE(encoded.has_value());
    CHECK(
        *encoded ==
        R"({"contract":{"id":"yuzu.b3.platform.request","version":{"major":1,"minor":0}},"correlation_id":"req-contract-0001","operation":"Read","scope":{"kind":"fleet"},"securable":"GuaranteedState"})");

    const auto decoded = contracts::decode_b3_platform_request(*encoded);
    REQUIRE(decoded.has_value());
    CHECK(decoded->correlation_id == request.correlation_id);
    CHECK(decoded->securable == request.securable);
    CHECK(decoded->operation == request.operation);
    CHECK(decoded->scope == request.scope);

    const auto reencoded = contracts::encode_b3_platform_request(*decoded);
    REQUIRE(reencoded.has_value());
    CHECK(*reencoded == *encoded);
}

TEST_CASE("ADR-0031 B3 rejects an untyped operation", "[adr31][contract][b3][negative]") {
    const auto decoded = contracts::decode_b3_platform_request(
        R"({"contract":{"id":"yuzu.b3.platform.request","version":{"major":1,"minor":0}},"correlation_id":"req-contract-0001","operation":"Observe","scope":{"kind":"fleet"},"securable":"GuaranteedState"})");

    REQUIRE_FALSE(decoded.has_value());
    CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
    CHECK(decoded.error().path == "/operation");
}

TEST_CASE("ADR-0031 B3 decoder distinguishes absent, null, and mistyped fields",
          "[adr31][contract][b3][negative]") {
    SECTION("missing") {
        const auto decoded = contracts::decode_b3_platform_request(
            R"({"contract":{"id":"yuzu.b3.platform.request","version":{"major":1,"minor":0}},"operation":"Read","scope":{"kind":"fleet"},"securable":"GuaranteedState"})");

        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::MissingField);
        CHECK(decoded.error().path == "/correlation_id");
    }

    SECTION("null") {
        const auto decoded = contracts::decode_b3_platform_request(
            R"({"contract":{"id":"yuzu.b3.platform.request","version":{"major":1,"minor":0}},"correlation_id":null,"operation":"Read","scope":{"kind":"fleet"},"securable":"GuaranteedState"})");

        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::NullField);
        CHECK(decoded.error().path == "/correlation_id");
    }

    SECTION("wrong type") {
        const auto decoded = contracts::decode_b3_platform_request(
            R"({"contract":{"id":"yuzu.b3.platform.request","version":{"major":1,"minor":0}},"correlation_id":7,"operation":"Read","scope":{"kind":"fleet"},"securable":"GuaranteedState"})");

        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::WrongType);
        CHECK(decoded.error().path == "/correlation_id");
    }
}
