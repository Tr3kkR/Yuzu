#include <yuzu/contracts/adr31/b3_platform.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <string>
#include <string_view>

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

TEST_CASE("ADR-0031 B3 rejects caller-authored authority context",
          "[adr31][contract][b3][security]") {
    const auto base = nlohmann::json::parse(
        R"({"contract":{"id":"yuzu.b3.platform.request","version":{"major":1,"minor":0}},"correlation_id":"req-contract-0001","operation":"Read","scope":{"kind":"fleet"},"securable":"GuaranteedState"})");
    constexpr std::array<std::string_view, 15> forbidden{
        "principal_credential",
        "credential",
        "authorization",
        "access_token",
        "bearerToken",
        "actor_id",
        "principal",
        "operator_id",
        "represented_operator",
        "on_behalf_of",
        "On-Behalf-Of",
        "recipient",
        "audience",
        "scope_ceiling",
        "grant",
    };

    for (const auto field : forbidden) {
        auto wire = base;
        wire[std::string{field}] = "attacker-authored";
        const auto decoded = contracts::decode_b3_platform_request(wire.dump());
        CAPTURE(field);
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
    }
}

TEST_CASE("ADR-0031 B3 tolerates safe additive fields", "[adr31][contract][b3][compatibility]") {
    auto wire = nlohmann::json::parse(
        R"({"contract":{"id":"yuzu.b3.platform.request","version":{"major":1,"minor":0}},"correlation_id":"req-contract-0001","operation":"Read","scope":{"kind":"fleet"},"securable":"GuaranteedState"})");
    wire["future_envelope_hint"] = true;
    wire["contract"]["future_header_hint"] = 1;
    wire["contract"]["version"]["future_version_hint"] = 2;
    wire["scope"]["actor"] = "domain-value";

    const auto decoded = contracts::decode_b3_platform_request(wire.dump());
    REQUIRE(decoded.has_value());
    CHECK(decoded->scope == wire["scope"]);
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
