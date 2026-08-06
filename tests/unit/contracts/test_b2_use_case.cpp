#include <yuzu/contracts/adr31/b2_use_case.hpp>
#include <yuzu/contracts/adr31/transport_auth_slot.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace contracts = yuzu::contracts::adr31;

namespace {

[[nodiscard]] contracts::B2UseCaseResult make_result() {
    return {
        .request_id = "req-use-case-0001",
        .use_case_run_id = "run_7YVvW8ERpX5qx9Qm2LcT4A",
        .result_schema_version = "vulnerability-prioritisation.result@1.0.0",
        .result =
            {
                .facts = nlohmann::json::array({{{"cve", "CVE-2026-0001"}, {"agent_id", "a-1"}}}),
                .coverage =
                    {
                        .intended = 2,
                        .contacted = 2,
                        .responded = 2,
                        .failed = 0,
                        .timed_out = 0,
                        .offline = 0,
                        .scope_basis = contracts::ScopeBasis::Global,
                        .completeness = contracts::Completeness::Complete,
                        .policy =
                            {
                                .minimum_response_percent = 100,
                                .blocks_next_step_when_incomplete = true,
                            },
                    },
                .provenance = nlohmann::json{{"journal_id", "journal-0001"}},
                .decisions = nlohmann::json::array({{{"action", "prioritise"}}}),
                .proposed_plan_reference = std::nullopt,
            },
        .finalisation_receipt = "receipt-core-0001",
    };
}

} // namespace

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

    const auto first_hash = contracts::canonical_b2_input_hash(first);
    const auto second_hash = contracts::canonical_b2_input_hash(second);
    REQUIRE(first_hash.has_value());
    REQUIRE(second_hash.has_value());
    CHECK(*first_hash == "sha256:193eb606cbfb424f8e95c0ed09a5a17c03ff5ea2a9591cda5b2581b553d371e8");
    CHECK(*first_hash == *second_hash);
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

    SECTION("nested authority field in domain inputs") {
        for (const std::string_view field :
             {"on_behalf_of", "operator_context", "acting_operator_id", "act_as",
              "engine_credential", "invocation_grant", "obo_context", "auth_context",
              "access_token_value", "oboContext", "authContext", "accessTokenValue",
              "representedoperatorclaim", "delegatedoperatorcontext", "grantcontext",
              "tokenvalue"}) {
            auto unsafe = wire;
            unsafe["normalised_inputs"]["nested"][field] = "attacker-authored";
            const auto decoded = contracts::decode_b2_use_case_request(unsafe.dump());
            CAPTURE(field);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
            CHECK(decoded.error().path == "/normalised_inputs/nested/" + std::string{field});
        }
    }

    SECTION("nested authority field in an additive control extension") {
        for (const std::string_view field :
             {"represented_operator_claim", "obo_context", "auth_context", "access_token_value"}) {
            auto unsafe = wire;
            unsafe["future"][field] = "attacker-authored";
            const auto decoded = contracts::decode_b2_use_case_request(unsafe.dump());
            CAPTURE(field);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
            CHECK(decoded.error().path == "/future/" + std::string{field});
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

    SECTION("ordinary domain identity words remain inputs, not authority") {
        wire["normalised_inputs"]["subject"] = "certificate";
        wire["normalised_inputs"]["identity"] = "package";
        wire["normalised_inputs"]["user"] = "local-account";
        wire["normalised_inputs"]["author"] = "package-maintainer";
        wire["normalised_inputs"]["fact_assertion"] = true;
        wire["normalised_inputs"]["id_tokenizer"] = "domain-parser";
        wire["normalised_inputs"]["tokenizer"] = "domain-parser";
        wire["normalised_inputs"]["token_count"] = 12;
        const auto decoded = contracts::decode_b2_use_case_request(wire.dump());
        REQUIRE(decoded.has_value());
        CHECK(decoded->normalised_inputs == wire["normalised_inputs"]);
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

TEST_CASE("ADR-0031 B2 result carries typed coverage and a finalisation receipt",
          "[adr31][contract][b2][result]") {
    const auto result = make_result();

    const auto encoded = contracts::encode_b2_use_case_result(result);
    REQUIRE(encoded.has_value());
    const auto decoded = contracts::decode_b2_use_case_result(*encoded);
    REQUIRE(decoded.has_value());
    CHECK(*decoded == result);

    const auto canonical = contracts::canonical_b2_result_bytes(result);
    REQUIRE(canonical.has_value());
    const auto before_receipt =
        contracts::canonical_b2_result_bytes(result.result_schema_version, result.result);
    REQUIRE(before_receipt.has_value());
    CHECK(*before_receipt == *canonical);
    CHECK(
        *canonical ==
        R"({"result":{"coverage":{"completeness":"complete","contacted":2,"failed":0,"intended":2,"offline":0,"policy":{"blocks_next_step_when_incomplete":true,"minimum_response_percent":100},"responded":2,"scope_basis":"global","timed_out":0},"decisions":[{"action":"prioritise"}],"facts":[{"agent_id":"a-1","cve":"CVE-2026-0001"}],"provenance":{"journal_id":"journal-0001"}},"result_schema_version":"vulnerability-prioritisation.result@1.0.0"})");

    auto different_receipt = result;
    different_receipt.finalisation_receipt = "receipt-core-0002";
    const auto same_hash_domain = contracts::canonical_b2_result_bytes(different_receipt);
    REQUIRE(same_hash_domain.has_value());
    CHECK(*same_hash_domain == *canonical);
}

TEST_CASE("ADR-0031 B2 result rejects contradictory coverage",
          "[adr31][contract][b2][result][negative]") {
    auto result = make_result();

    SECTION("complete requires every intended endpoint to respond") {
        result.result.coverage.intended = 10;
        result.result.coverage.contacted = 8;
        result.result.coverage.responded = 8;

        const auto encoded = contracts::encode_b2_use_case_result(result);
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(encoded.error().path == "/result/coverage/completeness");
    }

    SECTION("endpoint outcomes cannot be classified twice") {
        result.result.coverage.offline = 1;
        result.result.coverage.completeness = contracts::Completeness::Partial;

        const auto encoded = contracts::encode_b2_use_case_result(result);
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(encoded.error().path == "/result/coverage");
    }
}

TEST_CASE("ADR-0031 B2 result preserves compatible hash-domain extensions",
          "[adr31][contract][b2][result][compatibility]") {
    auto result = make_result();
    result.result.extensions["future_summary"] = nlohmann::json{{"format", "compact"}};
    result.result.coverage.extensions["future_outcome"] = "not_applicable";
    result.result.coverage.policy.extensions["future_rounding"] = "down";

    const auto encoded = contracts::encode_b2_use_case_result(result);
    REQUIRE(encoded.has_value());
    const auto decoded = contracts::decode_b2_use_case_result(*encoded);
    REQUIRE(decoded.has_value());
    CHECK(*decoded == result);

    const auto before = contracts::canonical_b2_result_bytes(result);
    const auto after = contracts::canonical_b2_result_bytes(*decoded);
    REQUIRE(before.has_value());
    REQUIRE(after.has_value());
    CHECK(*after == *before);
    CHECK(after->find("future_summary") != std::string::npos);
    CHECK(after->find("future_outcome") != std::string::npos);
    CHECK(after->find("future_rounding") != std::string::npos);

    const auto reencoded = contracts::encode_b2_use_case_result(*decoded);
    REQUIRE(reencoded.has_value());
    CHECK(*reencoded == *encoded);
}

TEST_CASE("ADR-0031 B2 result rejects authority assertions in control metadata",
          "[adr31][contract][b2][result][security]") {
    auto result = make_result();
    result.result.decisions[0]["subject"] = "device-a-1";
    const auto encoded = contracts::encode_b2_use_case_result(result);
    REQUIRE(encoded.has_value());

    auto wire = nlohmann::json::parse(*encoded);
    wire["result"]["provenance"]["nested"]["on_behalf_of"] = "attacker-authored";
    const auto decoded = contracts::decode_b2_use_case_result(wire.dump());
    REQUIRE_FALSE(decoded.has_value());
    CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
    CHECK(decoded.error().path == "/result/provenance/nested/on_behalf_of");
}

TEST_CASE("ADR-0031 B2 result distinguishes structural and version failures",
          "[adr31][contract][b2][result][compatibility][negative]") {
    const auto encoded = contracts::encode_b2_use_case_result(make_result());
    REQUIRE(encoded.has_value());
    const auto valid = nlohmann::json::parse(*encoded);

    SECTION("missing receipt") {
        auto wire = valid;
        wire.erase("finalisation_receipt");
        const auto decoded = contracts::decode_b2_use_case_result(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::MissingField);
        CHECK(decoded.error().path == "/finalisation_receipt");
    }

    SECTION("null receipt") {
        auto wire = valid;
        wire["finalisation_receipt"] = nullptr;
        const auto decoded = contracts::decode_b2_use_case_result(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::NullField);
        CHECK(decoded.error().path == "/finalisation_receipt");
    }

    SECTION("wrong policy field type") {
        auto wire = valid;
        wire["result"]["coverage"]["policy"]["minimum_response_percent"] = "100";
        const auto decoded = contracts::decode_b2_use_case_result(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::WrongType);
        CHECK(decoded.error().path == "/result/coverage/policy/minimum_response_percent");
    }

    SECTION("unsupported major") {
        auto wire = valid;
        wire["contract"]["version"] = {{"major", 2}, {"minor", 0}};
        const auto decoded = contracts::decode_b2_use_case_result(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::UnsupportedVersion);
    }
}

TEST_CASE("ADR-0031 B2 coverage does not pretend offline endpoints were contacted",
          "[adr31][contract][b2][result][coverage]") {
    auto result = make_result();
    result.result.coverage.intended = 10;
    result.result.coverage.contacted = 5;
    result.result.coverage.responded = 5;
    result.result.coverage.offline = 5;
    result.result.coverage.completeness = contracts::Completeness::Partial;

    const auto encoded = contracts::encode_b2_use_case_result(result);
    REQUIRE(encoded.has_value());
    const auto decoded = contracts::decode_b2_use_case_result(*encoded);
    REQUIRE(decoded.has_value());
    CHECK(decoded->result.coverage == result.result.coverage);
}
