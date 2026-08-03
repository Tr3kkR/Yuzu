#include <yuzu/contracts/adr31/b3_platform.hpp>
#include <yuzu/contracts/adr31/contract_limits.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <expected>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

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

TEST_CASE("ADR-0031 B3 correlation is a bounded diagnostic token",
          "[adr31][contract][b3][security]") {
    contracts::B3PlatformRequest request{
        .correlation_id = "req-contract-0001",
        .securable = "GuaranteedState",
        .operation = contracts::CoreOperation::Read,
        .scope = nlohmann::json{{"kind", "fleet"}},
    };

    for (const std::string& invalid :
         {std::string{}, std::string{"contains space"}, std::string{"contains\nnewline"},
          std::string(contracts::kMaxCorrelationIdCharacters + 1, 'x')}) {
        request.correlation_id = invalid;
        const auto encoded = contracts::encode_b3_platform_request(request);
        CAPTURE(invalid.size());
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(encoded.error().path == "/correlation_id");
    }
}

TEST_CASE("ADR-0031 B3 rejects caller-authored authority context",
          "[adr31][contract][b3][security]") {
    const auto base = nlohmann::json::parse(
        R"({"contract":{"id":"yuzu.b3.platform.request","version":{"major":1,"minor":0}},"correlation_id":"req-contract-0001","operation":"Read","scope":{"kind":"fleet"},"securable":"GuaranteedState"})");
    constexpr std::array<std::string_view, 19> forbidden{
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
        "x-on-behalf-of",
        "x-yuzu-on-behalf-of",
        "delegationArtifact",
        "result_grant",
    };

    for (const auto field : forbidden) {
        auto wire = base;
        wire[std::string{field}] = "attacker-authored";
        const auto decoded = contracts::decode_b3_platform_request(wire.dump());
        CAPTURE(field);
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
        CHECK(decoded.error().path == "/" + std::string{field});
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

TEST_CASE("ADR-0031 B3 rejects ambiguous or unbounded JSON", "[adr31][contract][b3][security]") {
    SECTION("duplicate object key") {
        const auto decoded = contracts::decode_b3_platform_request(
            R"({"contract":{"id":"yuzu.b3.platform.request","version":{"major":1,"minor":0}},"correlation_id":"req-contract-0001","operation":"Read","operation":"Write","scope":{"kind":"fleet"},"securable":"GuaranteedState"})");
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::DuplicateKey);
        CHECK(decoded.error().path == "/operation");
    }

    SECTION("duplicate nested version key") {
        const auto decoded = contracts::decode_b3_platform_request(
            R"({"contract":{"id":"yuzu.b3.platform.request","version":{"major":1,"major":2,"minor":0}},"correlation_id":"req-contract-0001","operation":"Read","scope":{"kind":"fleet"},"securable":"GuaranteedState"})");
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::DuplicateKey);
        CHECK(decoded.error().path == "/contract/version/major");
    }

    SECTION("duplicate nested scope key") {
        const auto decoded = contracts::decode_b3_platform_request(
            R"({"contract":{"id":"yuzu.b3.platform.request","version":{"major":1,"minor":0}},"correlation_id":"req-contract-0001","operation":"Read","scope":{"kind":"fleet","kind":"group"},"securable":"GuaranteedState"})");
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::DuplicateKey);
        CHECK(decoded.error().path == "/scope/kind");
    }

    SECTION("excessive nesting") {
        auto scope = nlohmann::json::object();
        for (std::size_t depth = 0; depth < contracts::kMaxContractNestingDepth; ++depth) {
            scope = nlohmann::json{{"nested", std::move(scope)}};
        }
        auto wire = nlohmann::json{
            {"contract",
             {{"id", "yuzu.b3.platform.request"}, {"version", {{"major", 1}, {"minor", 0}}}}},
            {"correlation_id", "req-contract-0001"},
            {"operation", "Read"},
            {"scope", std::move(scope)},
            {"securable", "GuaranteedState"},
        };
        const auto decoded = contracts::decode_b3_platform_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::TooDeep);
    }

    SECTION("oversized decode") {
        const auto decoded = contracts::decode_b3_platform_request(
            std::string(contracts::kMaxContractWireBytes + 1, ' '));
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::TooLarge);
    }

    SECTION("exact nesting and wire-size limits remain valid") {
        auto scope = nlohmann::json::object();
        for (std::size_t depth = 0; depth < contracts::kMaxContractNestingDepth - 2; ++depth) {
            scope = nlohmann::json{{"nested", std::move(scope)}};
        }
        auto wire = nlohmann::json{
            {"contract",
             {{"id", "yuzu.b3.platform.request"}, {"version", {{"major", 1}, {"minor", 0}}}}},
            {"correlation_id", "req-contract-0001"},
            {"operation", "Read"},
            {"scope", std::move(scope)},
            {"securable", "GuaranteedState"},
            {"padding", ""},
        };
        const auto empty_size = wire.dump().size();
        REQUIRE(empty_size < contracts::kMaxContractWireBytes);
        wire["padding"] = std::string(contracts::kMaxContractWireBytes - empty_size, 'x');
        const auto encoded = wire.dump();
        REQUIRE(encoded.size() == contracts::kMaxContractWireBytes);

        const auto decoded = contracts::decode_b3_platform_request(encoded);
        REQUIRE(decoded.has_value());
    }
}

TEST_CASE("ADR-0031 B3 encoder owns validation failures", "[adr31][contract][b3][negative]") {
    contracts::B3PlatformRequest request{
        .correlation_id = "req-contract-0001",
        .securable = "GuaranteedState",
        .operation = contracts::CoreOperation::Read,
        .scope = nlohmann::json{{"kind", "fleet"}},
    };

    SECTION("oversized output") {
        request.scope["padding"] = std::string(contracts::kMaxContractWireBytes, 'x');
        const auto encoded = contracts::encode_b3_platform_request(request);
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::TooLarge);
    }

    SECTION("invalid UTF-8") {
        request.scope["invalid"] = std::string(1, static_cast<char>(0xff));
        std::expected<std::string, contracts::ContractError> encoded;
        REQUIRE_NOTHROW(encoded = contracts::encode_b3_platform_request(request));
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::InvalidValue);
    }

    SECTION("excessive nesting") {
        request.scope = nlohmann::json::object();
        for (std::size_t depth = 0; depth < contracts::kMaxContractNestingDepth; ++depth) {
            request.scope = nlohmann::json{{"nested", std::move(request.scope)}};
        }
        const auto encoded = contracts::encode_b3_platform_request(request);
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::TooDeep);
    }

    SECTION("non-finite numbers") {
        constexpr std::array invalid_numbers{
            std::numeric_limits<double>::quiet_NaN(),
            std::numeric_limits<double>::infinity(),
            -std::numeric_limits<double>::infinity(),
        };
        for (const auto invalid : invalid_numbers) {
            request.scope["invalid"] = invalid;
            const auto encoded = contracts::encode_b3_platform_request(request);
            REQUIRE_FALSE(encoded.has_value());
            CHECK(encoded.error().code == contracts::ContractErrorCode::InvalidValue);
        }
    }
}

TEST_CASE("ADR-0031 B3 encoding is independent of object insertion order",
          "[adr31][contract][b3][compatibility]") {
    const contracts::B3PlatformRequest first{
        .correlation_id = "req-contract-0001",
        .securable = "GuaranteedState",
        .operation = contracts::CoreOperation::Read,
        .scope = nlohmann::json{{"kind", "group"}, {"id", "engineering"}},
    };
    auto reversed_scope = nlohmann::json::object();
    reversed_scope["id"] = "engineering";
    reversed_scope["kind"] = "group";
    const contracts::B3PlatformRequest second{
        .correlation_id = first.correlation_id,
        .securable = first.securable,
        .operation = first.operation,
        .scope = std::move(reversed_scope),
    };

    const auto first_wire = contracts::encode_b3_platform_request(first);
    const auto second_wire = contracts::encode_b3_platform_request(second);
    REQUIRE(first_wire.has_value());
    REQUIRE(second_wire.has_value());
    CHECK(*first_wire == *second_wire);
}

TEST_CASE("ADR-0031 B3 rejects malformed documents and unknown versions",
          "[adr31][contract][b3][negative]") {
    const auto base = nlohmann::json::parse(
        R"({"contract":{"id":"yuzu.b3.platform.request","version":{"major":1,"minor":0}},"correlation_id":"req-contract-0001","operation":"Read","scope":{"kind":"fleet"},"securable":"GuaranteedState"})");

    SECTION("trailing data") {
        const auto decoded = contracts::decode_b3_platform_request(base.dump() + " trailing");
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::MalformedJson);
    }

    SECTION("invalid UTF-8") {
        auto wire = base.dump();
        wire.insert(wire.size() - 1,
                    std::string{",\"future\":\""} + static_cast<char>(0xff) + "\"");
        const auto decoded = contracts::decode_b3_platform_request(wire);
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::MalformedJson);
    }

    SECTION("non-object root") {
        const auto decoded = contracts::decode_b3_platform_request("[]");
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::RootNotObject);
    }

    SECTION("unsupported minor") {
        auto wire = base;
        wire["contract"]["version"]["minor"] = 1;
        const auto decoded = contracts::decode_b3_platform_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::UnsupportedVersion);
    }

    SECTION("unsupported major") {
        auto wire = base;
        wire["contract"]["version"]["major"] = 2;
        const auto decoded = contracts::decode_b3_platform_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::UnsupportedVersion);
    }

    SECTION("negative version") {
        auto wire = base;
        wire["contract"]["version"]["major"] = -1;
        const auto decoded = contracts::decode_b3_platform_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::WrongType);
        CHECK(decoded.error().path == "/contract/version/major");
    }
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
