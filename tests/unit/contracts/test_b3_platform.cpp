#include <yuzu/contracts/adr31/b3_platform.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <string>

namespace contracts = yuzu::contracts::adr31;

TEST_CASE("ADR-0031 B3 platform request has a deterministic round trip", "[adr31][contract][b3]") {
    contracts::B3PlatformRequest request{
        .correlation_id = "req-contract-0001",
        .securable = "GuaranteedState",
        .operation = "Read",
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
