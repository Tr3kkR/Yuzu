#include <yuzu/contracts/adr31/b3_platform.hpp>
#include <yuzu/contracts/adr31/contract_limits.hpp>
#include <yuzu/contracts/adr31/contract_version.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <expected>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

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

TEST_CASE("ADR-0031 B3 success response preserves the public REST envelope",
          "[adr31][contract][b3][result]") {
    const contracts::B3PlatformResponse response{contracts::B3PlatformResult{
        .correlation_id = "req-contract-0001",
        .data = nlohmann::json{{"rules", nlohmann::json::array({"baseline-a"})}},
    }};

    const auto encoded = contracts::encode_b3_platform_response(response);
    REQUIRE(encoded.has_value());
    CHECK(
        *encoded ==
        R"({"contract":{"id":"yuzu.b3.platform.result","version":{"major":1,"minor":0}},"correlation_id":"req-contract-0001","data":{"rules":["baseline-a"]},"meta":{"api_version":"v1"}})");

    const auto decoded = contracts::decode_b3_platform_response(*encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(std::holds_alternative<contracts::B3PlatformResult>(*decoded));
    CHECK(std::get<contracts::B3PlatformResult>(*decoded) ==
          std::get<contracts::B3PlatformResult>(response));

    const contracts::B3PlatformRequest request{
        .correlation_id = "req-contract-0001",
        .securable = "GuaranteedState",
        .operation = contracts::CoreOperation::Read,
        .scope = nlohmann::json{{"kind", "fleet"}},
    };
    CHECK(contracts::validate_b3_platform_exchange(request, *decoded).has_value());
}

TEST_CASE("ADR-0031 B3 failure response carries the A4 fields",
          "[adr31][contract][b3][result][a4]") {
    const contracts::B3PlatformResponse response{contracts::A4ErrorEnvelope{
        .code = 403,
        .message = "permission denied",
        .correlation_id = "req-contract-0001",
        .retry_after_ms = std::nullopt,
        .remediation = "request GuaranteedState:Read",
        .permission = "GuaranteedState:Read",
        .approval_id = std::nullopt,
        .status_url = std::nullopt,
    }};

    const auto encoded = contracts::encode_b3_platform_response(response);
    REQUIRE(encoded.has_value());
    CHECK(
        *encoded ==
        R"({"error":{"code":403,"correlation_id":"req-contract-0001","message":"permission denied","permission":"GuaranteedState:Read","remediation":"request GuaranteedState:Read","retry_after_ms":null},"meta":{"api_version":"v1"}})");
    CHECK(encoded->find("yuzu.b3.platform.result") == std::string::npos);

    const auto decoded = contracts::decode_b3_platform_response(*encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(std::holds_alternative<contracts::A4ErrorEnvelope>(*decoded));
    CHECK(std::get<contracts::A4ErrorEnvelope>(*decoded) ==
          std::get<contracts::A4ErrorEnvelope>(response));

    const contracts::B3PlatformRequest request{
        .correlation_id = "req-contract-0001",
        .securable = "GuaranteedState",
        .operation = contracts::CoreOperation::Read,
        .scope = nlohmann::json{{"kind", "fleet"}},
    };
    CHECK(contracts::validate_b3_platform_exchange(request, *decoded).has_value());
}

TEST_CASE("ADR-0031 B3 A4 approval and retry metadata is typed",
          "[adr31][contract][b3][result][a4]") {
    SECTION("approval required") {
        const contracts::B3PlatformResponse response{contracts::A4ErrorEnvelope{
            .code = 202,
            .message = "approval required",
            .correlation_id = "req-contract-0001",
            .retry_after_ms = std::nullopt,
            .remediation = "poll approval status",
            .permission = std::nullopt,
            .approval_id = "approval-0001",
            .status_url = "/api/v1/approvals/approval-0001",
        }};
        const auto encoded = contracts::encode_b3_platform_response(response);
        REQUIRE(encoded.has_value());
        const auto decoded = contracts::decode_b3_platform_response(*encoded);
        REQUIRE(decoded.has_value());
        CHECK(*decoded == response);
    }

    SECTION("retryable unavailable") {
        const contracts::B3PlatformResponse response{contracts::A4ErrorEnvelope{
            .code = 503,
            .message = "service unavailable",
            .correlation_id = "req-contract-0001",
            .retry_after_ms = 5000,
            .remediation = std::nullopt,
            .permission = std::nullopt,
            .approval_id = std::nullopt,
            .status_url = std::nullopt,
        }};
        const auto encoded = contracts::encode_b3_platform_response(response);
        REQUIRE(encoded.has_value());
        CHECK(encoded->find(R"("retry_after_ms":5000)") != std::string::npos);
    }
}

TEST_CASE("ADR-0031 B3 response rejects ambiguous and malformed outcomes",
          "[adr31][contract][b3][result][negative]") {
    const auto success = nlohmann::json::parse(
        R"({"contract":{"id":"yuzu.b3.platform.result","version":{"major":1,"minor":0}},"correlation_id":"req-contract-0001","data":{},"meta":{"api_version":"v1"}})");
    const auto failure = nlohmann::json::parse(
        R"({"error":{"code":503,"message":"service unavailable","correlation_id":"req-contract-0001","retry_after_ms":null},"meta":{"api_version":"v1"}})");

    SECTION("neither success nor error") {
        const auto decoded =
            contracts::decode_b3_platform_response(R"({"meta":{"api_version":"v1"}})");
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::MissingField);
    }

    SECTION("both success and error") {
        auto wire = success;
        wire["error"] = failure["error"];
        const auto decoded = contracts::decode_b3_platform_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
    }

    SECTION("ambiguous arm precedes an unsupported success version") {
        auto wire = success;
        wire["error"] = failure["error"];
        wire["contract"]["version"]["major"] = 2;
        const auto decoded = contracts::decode_b3_platform_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
    }

    SECTION("null success data") {
        auto wire = success;
        wire["data"] = nullptr;
        const auto decoded = contracts::decode_b3_platform_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::NullField);
        CHECK(decoded.error().path == "/data");
    }

    SECTION("unsupported result version") {
        auto wire = success;
        wire["contract"]["version"]["major"] = 2;
        const auto decoded = contracts::decode_b3_platform_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::UnsupportedVersion);
    }

    SECTION("A4 has no contract header") {
        auto wire = failure;
        wire["contract"] = success["contract"];
        const auto decoded = contracts::decode_b3_platform_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/contract");
    }

    SECTION("A4 retry field is required") {
        auto wire = failure;
        wire["error"].erase("retry_after_ms");
        const auto decoded = contracts::decode_b3_platform_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::MissingField);
        CHECK(decoded.error().path == "/error/retry_after_ms");
    }

    SECTION("A4 retry cannot be negative") {
        auto wire = failure;
        wire["error"]["retry_after_ms"] = -1;
        const auto decoded = contracts::decode_b3_platform_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/error/retry_after_ms");
    }

    SECTION("approval fields are atomic") {
        auto wire = failure;
        wire["error"]["code"] = 202;
        wire["error"]["approval_id"] = "approval-0001";
        const auto decoded = contracts::decode_b3_platform_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/error");
    }

    SECTION("REST API version is explicit") {
        auto wire = success;
        wire["meta"]["api_version"] = "v2";
        const auto decoded = contracts::decode_b3_platform_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::UnsupportedVersion);
        CHECK(decoded.error().path == "/meta/api_version");
    }
}

TEST_CASE("ADR-0031 B3 response tolerates domain additions without treating them as authority",
          "[adr31][contract][b3][result][compatibility][security]") {
    auto wire = nlohmann::json::parse(
        R"({"contract":{"id":"yuzu.b3.platform.result","version":{"major":1,"minor":0}},"correlation_id":"req-contract-0001","data":{"principal":{"id":"domain-result"}},"meta":{"api_version":"v1"}})");
    wire["future_envelope_hint"] = true;
    wire["contract"]["future_header_hint"] = 1;
    wire["meta"]["future_meta_hint"] = 2;

    const auto decoded = contracts::decode_b3_platform_response(wire.dump());
    REQUIRE(decoded.has_value());
    REQUIRE(std::holds_alternative<contracts::B3PlatformResult>(*decoded));
    CHECK(std::get<contracts::B3PlatformResult>(*decoded).data == wire["data"]);

    wire["credential"] = "attacker-authored";
    const auto unsafe = contracts::decode_b3_platform_response(wire.dump());
    REQUIRE_FALSE(unsafe.has_value());
    CHECK(unsafe.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);

    auto a4 = nlohmann::json::parse(
        R"({"error":{"code":503,"message":"service unavailable","correlation_id":"req-contract-0001","retry_after_ms":null},"meta":{"api_version":"v1"}})");
    a4["future_envelope_hint"] = true;
    a4["error"]["future_error_hint"] = "safe";
    a4["meta"]["future_meta_hint"] = 1;
    CHECK(contracts::decode_b3_platform_response(a4.dump()).has_value());

    a4["credential"] = "attacker-authored";
    const auto unsafe_a4 = contracts::decode_b3_platform_response(a4.dump());
    REQUIRE_FALSE(unsafe_a4.has_value());
    CHECK(unsafe_a4.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
}

TEST_CASE("ADR-0031 B3 consumer rejects mismatched correlation and permission",
          "[adr31][contract][b3][result][security]") {
    const contracts::B3PlatformRequest request{
        .correlation_id = "req-contract-0001",
        .securable = "GuaranteedState",
        .operation = contracts::CoreOperation::Read,
        .scope = nlohmann::json{{"kind", "fleet"}},
    };

    SECTION("correlation mismatch") {
        const contracts::B3PlatformResponse response{contracts::B3PlatformResult{
            .correlation_id = "req-contract-0002",
            .data = nlohmann::json::object(),
        }};
        const auto valid = contracts::validate_b3_platform_exchange(request, response);
        REQUIRE_FALSE(valid.has_value());
        CHECK(valid.error().path == "/correlation_id");
    }

    SECTION("denial correlation mismatch") {
        const contracts::B3PlatformResponse response{contracts::A4ErrorEnvelope{
            .code = 503,
            .message = "service unavailable",
            .correlation_id = "req-contract-0002",
            .retry_after_ms = std::nullopt,
            .remediation = std::nullopt,
            .permission = std::nullopt,
            .approval_id = std::nullopt,
            .status_url = std::nullopt,
        }};
        const auto valid = contracts::validate_b3_platform_exchange(request, response);
        REQUIRE_FALSE(valid.has_value());
        CHECK(valid.error().path == "/correlation_id");
    }

    SECTION("permission mismatch") {
        const contracts::B3PlatformResponse response{contracts::A4ErrorEnvelope{
            .code = 403,
            .message = "permission denied",
            .correlation_id = "req-contract-0001",
            .retry_after_ms = std::nullopt,
            .remediation = std::nullopt,
            .permission = "Tag:Write",
            .approval_id = std::nullopt,
            .status_url = std::nullopt,
        }};
        const auto valid = contracts::validate_b3_platform_exchange(request, response);
        REQUIRE_FALSE(valid.has_value());
        CHECK(valid.error().path == "/error/permission");
    }
}

TEST_CASE("ADR-0031 B3 publishes no fabricated previous result version",
          "[adr31][contract][b3][result][compatibility]") {
    REQUIRE(contracts::kB3PlatformResult.supported_versions.size() == 1);
    CHECK(contracts::kB3PlatformResult.supported_versions.front() == contracts::kVersion1_0);
}

TEST_CASE("ADR-0031 B3 rejects an unsupported version before request semantics",
          "[adr31][contract][b3][compatibility][security]") {
    auto wire = nlohmann::json::parse(
        R"({"contract":{"id":"yuzu.b3.platform.request","version":{"major":2,"minor":0}},"correlation_id":"req-contract-0001","operation":"Read","scope":{"kind":"fleet"},"securable":"GuaranteedState"})");
    wire["operator_id"] = "attacker-authored";

    const auto decoded = contracts::decode_b3_platform_request(wire.dump());
    REQUIRE_FALSE(decoded.has_value());
    CHECK(decoded.error().code == contracts::ContractErrorCode::UnsupportedVersion);
    CHECK(decoded.error().path == "/contract/version");
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
