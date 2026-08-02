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

TEST_CASE("ADR-0031 B2 canonical input bytes are stable", "[adr31][contract][b2][canonical]") {
    contracts::B2UseCaseRequest first{
        .request_id = "req-use-case-0001",
        .use_case_run_id = "run_7YVvW8ERpX5qx9Qm2LcT4A",
        .use_case = {.id = "vulnerability-prioritisation", .version = "1.2.0"},
        .module = {.id = "vulnerability-management", .version = "3.1.4"},
        .normalised_inputs = nlohmann::json{{"severity", "high"}, {"include_suppressed", false}},
    };
    auto second = first;
    second.normalised_inputs = nlohmann::json::object();
    second.normalised_inputs["include_suppressed"] = false;
    second.normalised_inputs["severity"] = "high";

    const auto first_bytes = contracts::canonical_b2_input_bytes(first);
    const auto second_bytes = contracts::canonical_b2_input_bytes(second);
    REQUIRE(first_bytes.has_value());
    REQUIRE(second_bytes.has_value());
    CHECK(*first_bytes == R"({"include_suppressed":false,"severity":"high"})");
    CHECK(*first_bytes == *second_bytes);
}

TEST_CASE("ADR-0031 B2 request rejects asserted authority and weak run selectors",
          "[adr31][contract][b2][security]") {
    auto wire = nlohmann::json::parse(
        R"({"contract":{"id":"yuzu.b2.use_case.request","version":{"major":1,"minor":0}},"module":{"id":"vulnerability-management","version":"3.1.4"},"normalised_inputs":{"actor":"domain-input"},"request_id":"req-use-case-0001","use_case":{"id":"vulnerability-prioritisation","version":"1.2.0"},"use_case_run_id":"run_7YVvW8ERpX5qx9Qm2LcT4A"})");

    SECTION("authority field") {
        for (const std::string_view field :
             {"operator_id", "on_behalf_of", "grant", "release_authorization"}) {
            auto unsafe = wire;
            unsafe[std::string{field}] = "attacker-authored";
            const auto decoded = contracts::decode_b2_use_case_request(unsafe.dump());
            CAPTURE(field);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
        }
    }

    SECTION("weak run selector") {
        wire["use_case_run_id"] = "42";
        const auto decoded = contracts::decode_b2_use_case_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/use_case_run_id");
    }

    SECTION("safe additive field") {
        wire["future_hint"] = true;
        const auto decoded = contracts::decode_b2_use_case_request(wire.dump());
        REQUIRE(decoded.has_value());
        CHECK(decoded->normalised_inputs["actor"] == "domain-input");
    }
}

TEST_CASE("ADR-0031 B2 request requires an explicitly supported contract version",
          "[adr31][contract][b2][compatibility]") {
    auto wire = nlohmann::json::parse(
        R"({"contract":{"id":"yuzu.b2.use_case.request","version":{"major":1,"minor":0}},"module":{"id":"vulnerability-management","version":"3.1.4"},"normalised_inputs":{},"request_id":"req-use-case-0001","use_case":{"id":"vulnerability-prioritisation","version":"1.2.0"},"use_case_run_id":"run_7YVvW8ERpX5qx9Qm2LcT4A"})");

    wire["contract"]["version"]["minor"] = 1;
    const auto future_minor = contracts::decode_b2_use_case_request(wire.dump());
    REQUIRE_FALSE(future_minor.has_value());
    CHECK(future_minor.error().code == contracts::ContractErrorCode::UnsupportedVersion);

    wire["contract"]["version"] = {{"major", 2}, {"minor", 0}};
    const auto future_major = contracts::decode_b2_use_case_request(wire.dump());
    REQUIRE_FALSE(future_major.has_value());
    CHECK(future_major.error().code == contracts::ContractErrorCode::UnsupportedVersion);
}
