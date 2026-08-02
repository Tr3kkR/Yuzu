#include <yuzu/contracts/adr31/b2_use_case.hpp>
#include <yuzu/contracts/adr31/transport_auth_slot.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <string>
#include <string_view>

namespace contracts = yuzu::contracts::adr31;

TEST_CASE("ADR-0031 B2 use-case request has a deterministic round trip", "[adr31][contract][b2]") {
    constexpr std::string_view grant_secret = "fixture-invocation-grant";
    auto grant = contracts::make_transport_auth_slot(contracts::TransportAuthKind::InvocationGrant,
                                                     std::string{grant_secret});
    REQUIRE(grant.has_value());

    const contracts::B2UseCaseRequest request{
        .request_id = "req-use-case-0001",
        .use_case_run_id = "run_7YVvW8ERpX5qx9Qm2LcT4A",
        .use_case = {.id = "vulnerability-prioritisation", .version = "1.2.0"},
        .module = {.id = "vulnerability-management", .version = "3.1.4"},
        .normalised_inputs =
            nlohmann::json{
                {"include_suppressed", false},
                {"severity", nlohmann::json::array({"critical", "high"})},
            },
    };

    const auto encoded = contracts::encode_b2_use_case_request(request);
    REQUIRE(encoded.has_value());
    CHECK(
        *encoded ==
        R"({"contract":{"id":"yuzu.b2.use_case.request","version":{"major":1,"minor":0}},"module":{"id":"vulnerability-management","version":"3.1.4"},"normalised_inputs":{"include_suppressed":false,"severity":["critical","high"]},"request_id":"req-use-case-0001","use_case":{"id":"vulnerability-prioritisation","version":"1.2.0"},"use_case_run_id":"run_7YVvW8ERpX5qx9Qm2LcT4A"})");
    CHECK(encoded->find(grant_secret) == std::string::npos);

    const auto decoded = contracts::decode_b2_use_case_request(*encoded);
    REQUIRE(decoded.has_value());
    CHECK(decoded->request_id == request.request_id);
    CHECK(decoded->use_case_run_id == request.use_case_run_id);
    CHECK(decoded->use_case == request.use_case);
    CHECK(decoded->module == request.module);
    CHECK(decoded->normalised_inputs == request.normalised_inputs);

    const auto reencoded = contracts::encode_b2_use_case_request(*decoded);
    REQUIRE(reencoded.has_value());
    CHECK(*reencoded == *encoded);
}
