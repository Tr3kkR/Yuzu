#include <yuzu/contracts/adr31/b4_finalisation.hpp>
#include <yuzu/contracts/adr31/contract_version.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

namespace contracts = yuzu::contracts::adr31;

namespace {

constexpr std::string_view kEngineSecret = "fixture-finalisation-engine-credential";
constexpr std::string_view kReleaseSecret = "fixture-finalisation-release-authorization";

contracts::B2UseCaseRequest make_b2_request() {
    return {
        .request_id = "req-use-case-0001",
        .use_case_run_id = "run_7YVvW8ERpX5qx9Qm2LcT4A",
        .use_case = {.id = "vulnerability-prioritisation", .version = "1.2.0"},
        .module = {.id = "vulnerability-management", .version = "3.1.4"},
        .normalised_inputs = nlohmann::json{{"include_suppressed", false}},
    };
}

contracts::B2UseCaseResultPayload make_payload() {
    return {
        .facts = nlohmann::json::array({{{"agent_id", "agent-a"}, {"cve", "CVE-2026-0001"}}}),
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
        .provenance = nlohmann::json{{"journal_id", "uce-journal-0001"}},
        .decisions = nlohmann::json::array({{{"action", "prioritise"}}}),
        .proposed_plan_reference = std::nullopt,
    };
}

contracts::B4FinalisationDraft make_draft() {
    return {
        .correlation_id = "req-contract-0001",
        .module_manifest_hash =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .result_schema_version = "vulnerability-prioritisation.result@1.0.0",
        .disclosure_summary = {.fact_refs = {"fact-read-0002", "fact-read-0001"}},
    };
}

contracts::TransportAuthSlot make_auth(contracts::TransportAuthKind kind, std::string_view secret) {
    auto slot = contracts::make_transport_auth_slot(kind, std::string{secret});
    if (!slot)
        throw std::logic_error("test transport credential must be valid");
    return std::move(*slot);
}

std::string make_request_wire(const contracts::B2UseCaseRequest& b2 = make_b2_request(),
                              const contracts::B2UseCaseResultPayload& payload = make_payload(),
                              contracts::B4FinalisationDraft draft = make_draft()) {
    auto call = contracts::make_b4_finalisation_call(
        std::move(draft), b2, payload,
        make_auth(contracts::TransportAuthKind::EngineCredential, kEngineSecret));
    if (!call)
        throw std::logic_error("valid finalisation fixture was rejected");
    std::string body;
    const auto applied = std::move(*call).apply_to_transport(
        [&](const contracts::B4FinalisationTransportInputs& inputs) {
            if (inputs.engine_credential().bytes() != kEngineSecret)
                throw std::logic_error("engine credential changed");
            body = inputs.body().bytes();
        });
    if (!applied)
        throw std::logic_error("fresh finalisation call was consumed");
    return body;
}

contracts::B4FinalisationRequest make_request() {
    auto decoded = contracts::decode_b4_finalisation_request(make_request_wire());
    if (!decoded)
        throw std::logic_error("valid finalisation wire was rejected");
    return std::move(*decoded);
}

contracts::B4FinalisationResult make_result(const contracts::B4FinalisationRequest& request) {
    return {
        .correlation_id = request.correlation_id,
        .use_case_run_id = request.use_case_run_id,
        .use_case = request.use_case,
        .module = request.module,
        .module_manifest_hash = request.module_manifest_hash,
        .result_schema_version = request.result_schema_version,
        .result_hash = request.result_hash,
        .coverage = request.coverage,
        .journal_id = request.provenance.at("journal_id").get<std::string>(),
        .finalisation_receipt = "receipt-core-0001",
    };
}

contracts::A4ErrorEnvelope make_a4(std::int32_t code = 503) {
    return {
        .code = code,
        .message = "finalisation unavailable",
        .correlation_id = "req-contract-0001",
        .retry_after_ms = code == 503 ? std::optional<std::int64_t>{5000} : std::nullopt,
        .remediation = std::nullopt,
        .permission = std::nullopt,
        .approval_id = code == 202 ? std::optional<std::string>{"approval-1"} : std::nullopt,
        .status_url = code == 202 ? std::optional<std::string>{"/approvals/1"} : std::nullopt,
    };
}

contracts::B4FinalisationBindingError
binding_error(const contracts::B4FinalisationReplyError& value) {
    return std::get<contracts::B4FinalisationBindingError>(value);
}

} // namespace

static_assert(!std::is_default_constructible_v<contracts::B4FinalisationCall>);
static_assert(!std::is_copy_constructible_v<contracts::B4FinalisationCall>);
static_assert(!std::is_move_assignable_v<contracts::B4FinalisationCall>);
static_assert(!std::is_default_constructible_v<contracts::B4FinalisationReply>);
static_assert(!std::is_copy_constructible_v<contracts::B4FinalisationReply>);
static_assert(!std::is_move_assignable_v<contracts::B4FinalisationReply>);
static_assert(!std::is_default_constructible_v<contracts::B4PendingRelease>);
static_assert(!std::is_copy_constructible_v<contracts::B4PendingRelease>);
static_assert(!std::is_move_assignable_v<contracts::B4PendingRelease>);

TEST_CASE("ADR-0031 B4 finalisation derives one deterministic request",
          "[adr31][contract][b4][finalisation]") {
    const auto first = make_request_wire();
    const auto second = make_request_wire();
    CHECK(first == second);
    CHECK(first.find(kEngineSecret) == std::string::npos);
    CHECK(first.find("release_authorization") == std::string::npos);
    CHECK(first.find("released_input_digest") == std::string::npos);
    CHECK(first.find("normalised_inputs") == std::string::npos);

    const auto request = contracts::decode_b4_finalisation_request(first);
    REQUIRE(request.has_value());
    CHECK(request->use_case_run_id == make_b2_request().use_case_run_id);
    CHECK(request->use_case == make_b2_request().use_case);
    CHECK(request->module == make_b2_request().module);
    CHECK(request->coverage == make_payload().coverage);
    CHECK(request->provenance == make_payload().provenance);
    CHECK(request->disclosure_summary.fact_refs ==
          std::vector<std::string>{"fact-read-0001", "fact-read-0002"});

    const auto expected_hash =
        contracts::canonical_b2_result_hash(request->result_schema_version, make_payload());
    REQUIRE(expected_hash.has_value());
    CHECK(request->result_hash == *expected_hash);
    CHECK(request->result_hash ==
          "sha256:9dde9a19e8608125ca283ea8f1abfbeb4a5762e655e632611d736bacaf186dfe");
    CHECK(request->result_hash.size() == 71);
    CHECK(request->result_hash.starts_with("sha256:"));
}

TEST_CASE("ADR-0031 B2 finalisation hash covers exact pre-receipt result bytes",
          "[adr31][contract][b4][finalisation][canonical]") {
    auto first = make_payload();
    auto reordered = first;
    reordered.provenance = nlohmann::json::object();
    reordered.provenance["journal_id"] = "uce-journal-0001";
    const auto first_hash = contracts::canonical_b2_result_hash("schema@1", first);
    const auto reordered_hash = contracts::canonical_b2_result_hash("schema@1", reordered);
    REQUIRE(first_hash.has_value());
    REQUIRE(reordered_hash.has_value());
    CHECK(*first_hash == *reordered_hash);

    auto changed = first;
    changed.decisions[0]["action"] = "defer";
    const auto changed_hash = contracts::canonical_b2_result_hash("schema@1", changed);
    REQUIRE(changed_hash.has_value());
    CHECK(*changed_hash != *first_hash);
    const auto changed_schema = contracts::canonical_b2_result_hash("schema@2", first);
    REQUIRE(changed_schema.has_value());
    CHECK(*changed_schema != *first_hash);

    contracts::B2UseCaseResult with_receipt{
        .request_id = "request-a",
        .use_case_run_id = "run_7YVvW8ERpX5qx9Qm2LcT4A",
        .result_schema_version = "schema@1",
        .result = first,
        .finalisation_receipt = "receipt-a",
    };
    const auto hash_a = contracts::canonical_b2_result_hash(with_receipt);
    with_receipt.finalisation_receipt = "receipt-b";
    const auto hash_b = contracts::canonical_b2_result_hash(with_receipt);
    REQUIRE(hash_a.has_value());
    REQUIRE(hash_b.has_value());
    CHECK(*hash_a == *hash_b);
}

TEST_CASE("ADR-0031 B4 finalisation request has one engine-credential handoff",
          "[adr31][contract][b4][finalisation][auth]") {
    SECTION("every wrong credential kind is rejected") {
        for (const auto kind : {contracts::TransportAuthKind::CallerCredential,
                                contracts::TransportAuthKind::InvocationGrant,
                                contracts::TransportAuthKind::ReleaseAuthorization}) {
            auto call = contracts::make_b4_finalisation_call(
                make_draft(), make_b2_request(), make_payload(), make_auth(kind, "wrong-kind"));
            REQUIRE_FALSE(call.has_value());
            CHECK(std::get<contracts::B4FinalisationBindingError>(call.error()) ==
                  contracts::B4FinalisationBindingError::WrongEngineCredentialKind);
        }
    }

    SECTION("success consumes before callback and cannot be replayed") {
        auto call = contracts::make_b4_finalisation_call(
            make_draft(), make_b2_request(), make_payload(),
            make_auth(contracts::TransportAuthKind::EngineCredential, kEngineSecret));
        REQUIRE(call.has_value());
        const auto first = std::move(*call).apply_to_transport(
            [](const contracts::B4FinalisationTransportInputs&) {});
        REQUIRE(first.has_value());
        const auto retry = std::move(*call).apply_to_transport(
            [](const contracts::B4FinalisationTransportInputs&) {});
        REQUIRE_FALSE(retry.has_value());
        CHECK(std::get<contracts::B4FinalisationBindingError>(retry.error()) ==
              contracts::B4FinalisationBindingError::Consumed);
    }

    SECTION("a throwing adapter still burns the lease") {
        auto call = contracts::make_b4_finalisation_call(
            make_draft(), make_b2_request(), make_payload(),
            make_auth(contracts::TransportAuthKind::EngineCredential, kEngineSecret));
        REQUIRE(call.has_value());
        REQUIRE_THROWS_AS(std::move(*call).apply_to_transport(
                              [](const contracts::B4FinalisationTransportInputs&) {
                                  throw std::runtime_error("transport failed");
                              }),
                          std::runtime_error);
        CHECK_FALSE(std::move(*call)
                        .apply_to_transport([](const contracts::B4FinalisationTransportInputs&) {})
                        .has_value());
    }
}

TEST_CASE("ADR-0031 B4 finalisation rejects authority and disclosure ambiguity",
          "[adr31][contract][b4][finalisation][security][negative]") {
    const auto valid = nlohmann::json::parse(make_request_wire());

    SECTION("unsupported version") {
        auto wire = valid;
        wire["contract"]["version"]["major"] = 2;
        const auto decoded = contracts::decode_b4_finalisation_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::UnsupportedVersion);
    }
    SECTION("result hash is exact lowercase SHA-256") {
        auto wire = valid;
        wire["result_hash"] =
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const auto decoded = contracts::decode_b4_finalisation_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().path == "/result_hash");
    }
    SECTION("fact references are a set") {
        auto wire = valid;
        wire["disclosure_summary"]["fact_refs"] = {"fact-a", "fact-a"};
        const auto decoded = contracts::decode_b4_finalisation_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().path == "/disclosure_summary/fact_refs/1");
    }
    SECTION("pure-input results retain an explicit empty set") {
        auto draft = make_draft();
        draft.disclosure_summary.fact_refs.clear();
        const auto decoded = contracts::decode_b4_finalisation_request(
            make_request_wire(make_b2_request(), make_payload(), std::move(draft)));
        REQUIRE(decoded.has_value());
        CHECK(decoded->disclosure_summary.fact_refs.empty());
    }
    SECTION("journal linkage is required") {
        auto wire = valid;
        wire["provenance"].erase("journal_id");
        const auto decoded = contracts::decode_b4_finalisation_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().path == "/provenance/journal_id");
    }
    SECTION("operator and release authority cannot be smuggled") {
        for (const std::string_view field :
             {"operator_id", "on_behalf_of", "release_authorization"}) {
            auto wire = valid;
            wire["future"][field] = "attacker-authored";
            const auto decoded = contracts::decode_b4_finalisation_request(wire.dump());
            CAPTURE(field);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
        }
    }
    SECTION("Core-internal digest and population oracles stay off wire") {
        for (const std::string_view field :
             {"released_input_digest", "matched_count", "withheld"}) {
            auto wire = valid;
            wire["future"][field] = "forbidden";
            const auto decoded = contracts::decode_b4_finalisation_request(wire.dump());
            CAPTURE(field);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        }
    }
}

TEST_CASE("ADR-0031 B4 finalisation request distinguishes structural failures",
          "[adr31][contract][b4][finalisation][compatibility][negative]") {
    const auto wire_text = make_request_wire();
    const auto valid = nlohmann::json::parse(wire_text);

    for (const std::string_view field :
         {"correlation_id", "use_case_run_id", "use_case", "module", "module_manifest_hash",
          "result_schema_version", "result_hash", "disclosure_summary", "coverage", "provenance"}) {
        CAPTURE(field);
        auto missing = valid;
        missing.erase(field);
        const auto missing_result = contracts::decode_b4_finalisation_request(missing.dump());
        REQUIRE_FALSE(missing_result.has_value());
        CHECK(missing_result.error().code == contracts::ContractErrorCode::MissingField);
        CHECK(missing_result.error().path == "/" + std::string{field});

        auto null_value = valid;
        null_value[field] = nullptr;
        const auto null_result = contracts::decode_b4_finalisation_request(null_value.dump());
        REQUIRE_FALSE(null_result.has_value());
        CHECK(null_result.error().code == contracts::ContractErrorCode::NullField);
        CHECK(null_result.error().path == "/" + std::string{field});

        auto wrong_type = valid;
        wrong_type[field] = nlohmann::json::array();
        const auto type_result = contracts::decode_b4_finalisation_request(wrong_type.dump());
        REQUIRE_FALSE(type_result.has_value());
        CHECK(type_result.error().code == contracts::ContractErrorCode::WrongType);
        CHECK(type_result.error().path == "/" + std::string{field});
    }

    SECTION("non-object and trailing input") {
        const auto non_object = contracts::decode_b4_finalisation_request("[]");
        REQUIRE_FALSE(non_object.has_value());
        CHECK(non_object.error().code == contracts::ContractErrorCode::RootNotObject);
        const auto trailing = contracts::decode_b4_finalisation_request(wire_text + " trailing");
        REQUIRE_FALSE(trailing.has_value());
        CHECK(trailing.error().code == contracts::ContractErrorCode::MalformedJson);
    }
    SECTION("duplicate member") {
        const auto insertion = wire_text.find("\"correlation_id\"");
        REQUIRE(insertion != std::string::npos);
        auto duplicate = wire_text;
        duplicate.insert(insertion, "\"correlation_id\":\"attacker\",");
        const auto decoded = contracts::decode_b4_finalisation_request(duplicate);
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::DuplicateKey);
    }
    SECTION("wrong contract and unsupported minor") {
        auto wrong_id = valid;
        wrong_id["contract"]["id"] = "yuzu.b4.redemption";
        const auto wrong_contract = contracts::decode_b4_finalisation_request(wrong_id.dump());
        REQUIRE_FALSE(wrong_contract.has_value());
        CHECK(wrong_contract.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(wrong_contract.error().path == "/contract/id");
        auto minor = valid;
        minor["contract"]["version"]["minor"] = 1;
        const auto decoded = contracts::decode_b4_finalisation_request(minor.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::UnsupportedVersion);
    }
    SECTION("safe additive member is retained") {
        auto additive = valid;
        additive["future_verifier_hint"] = nlohmann::json{{"format", "compact"}};
        const auto decoded = contracts::decode_b4_finalisation_request(additive.dump());
        REQUIRE(decoded.has_value());
        CHECK(decoded->extensions["future_verifier_hint"] == additive["future_verifier_hint"]);
    }
    SECTION("a request cannot contain a response error arm") {
        auto ambiguous = valid;
        ambiguous["error"] = {{"code", 503}, {"message", "ambiguous"}};
        const auto decoded = contracts::decode_b4_finalisation_request(ambiguous.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/error");
    }
}

TEST_CASE("ADR-0031 B4 finalisation receipt round trips and echo-binds",
          "[adr31][contract][b4][finalisation][result]") {
    const auto request = make_request();
    const contracts::B4FinalisationResponse response{make_result(request)};
    const auto encoded = contracts::encode_b4_finalisation_response(response);
    REQUIRE(encoded.has_value());
    CHECK(encoded->find(kReleaseSecret) == std::string::npos);
    CHECK(encoded->find("release_authorization") == std::string::npos);
    const auto decoded = contracts::decode_b4_finalisation_response(*encoded);
    REQUIRE(decoded.has_value());
    CHECK(*decoded == response);
    CHECK(contracts::validate_b4_finalisation_exchange(request, *decoded).has_value());

    const auto rejects = [&](auto mutate, std::string_view expected_path) {
        auto mismatched = make_result(request);
        mutate(mismatched);
        const auto checked = contracts::validate_b4_finalisation_exchange(
            request, contracts::B4FinalisationResponse{std::move(mismatched)});
        REQUIRE_FALSE(checked.has_value());
        CHECK(checked.error().path == expected_path);
    };
    SECTION("correlation") {
        rejects([](auto& value) { value.correlation_id = "req-contract-0002"; }, "/correlation_id");
    }
    SECTION("run") {
        rejects([](auto& value) { value.use_case_run_id = "run_4bK8F7mP2qR9sT6vW3xY5Z"; },
                "/use_case_run_id");
    }
    SECTION("use-case id") {
        rejects([](auto& value) { value.use_case.id = "other-use-case"; }, "/use_case/id");
    }
    SECTION("use-case version") {
        rejects([](auto& value) { value.use_case.version = "9.0.0"; }, "/use_case/version");
    }
    SECTION("module id") {
        rejects([](auto& value) { value.module.id = "other-module"; }, "/module/id");
    }
    SECTION("module version") {
        rejects([](auto& value) { value.module.version = "9.0.0"; }, "/module/version");
    }
    SECTION("manifest") {
        rejects([](auto& value) { value.module_manifest_hash = "sha256:other"; },
                "/module_manifest_hash");
    }
    SECTION("schema") {
        rejects([](auto& value) { value.result_schema_version = "result@2"; },
                "/result_schema_version");
    }
    SECTION("result hash") {
        rejects(
            [](auto& value) {
                value.result_hash =
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            },
            "/result_hash");
    }
    SECTION("coverage") {
        rejects(
            [](auto& value) {
                value.coverage.scope_basis = contracts::ScopeBasis::AuthorityScoped;
            },
            "/coverage");
    }
    SECTION("journal") {
        rejects([](auto& value) { value.journal_id = "uce-journal-0002"; },
                "/provenance/journal_id");
    }
}

TEST_CASE("ADR-0031 B4 finalisation result is additive but structurally strict",
          "[adr31][contract][b4][finalisation][result][compatibility]") {
    const auto request = make_request();
    auto result = make_result(request);
    result.extensions["future_verifier_hint"] = nlohmann::json{{"format", "compact"}};
    const auto encoded =
        contracts::encode_b4_finalisation_response(contracts::B4FinalisationResponse{result});
    REQUIRE(encoded.has_value());
    const auto decoded = contracts::decode_b4_finalisation_response(*encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(std::holds_alternative<contracts::B4FinalisationResult>(*decoded));
    CHECK(std::get<contracts::B4FinalisationResult>(*decoded).extensions == result.extensions);

    const auto valid = nlohmann::json::parse(*encoded);
    for (const std::string_view field :
         {"correlation_id", "use_case_run_id", "use_case", "module", "module_manifest_hash",
          "result_schema_version", "result_hash", "coverage", "provenance",
          "finalisation_receipt"}) {
        CAPTURE(field);
        auto missing = valid;
        missing.erase(field);
        const auto missing_result = contracts::decode_b4_finalisation_response(missing.dump());
        REQUIRE_FALSE(missing_result.has_value());
        CHECK(missing_result.error().code == contracts::ContractErrorCode::MissingField);
        CHECK(missing_result.error().path ==
              (field == "finalisation_receipt" ? "" : "/" + std::string{field}));

        auto null_value = valid;
        null_value[field] = nullptr;
        const auto null_result = contracts::decode_b4_finalisation_response(null_value.dump());
        REQUIRE_FALSE(null_result.has_value());
        CHECK(null_result.error().code == contracts::ContractErrorCode::NullField);
        CHECK(null_result.error().path == "/" + std::string{field});

        auto wrong_type = valid;
        wrong_type[field] = nlohmann::json::array();
        const auto type_result = contracts::decode_b4_finalisation_response(wrong_type.dump());
        REQUIRE_FALSE(type_result.has_value());
        CHECK(type_result.error().code == contracts::ContractErrorCode::WrongType);
        CHECK(type_result.error().path == "/" + std::string{field});
    }
    SECTION("missing coverage") {
        auto wire = valid;
        wire.erase("coverage");
        const auto rejected = contracts::decode_b4_finalisation_response(wire.dump());
        REQUIRE_FALSE(rejected.has_value());
        CHECK(rejected.error().code == contracts::ContractErrorCode::MissingField);
        CHECK(rejected.error().path == "/coverage");
    }
    SECTION("null coverage") {
        auto wire = valid;
        wire["coverage"] = nullptr;
        const auto rejected = contracts::decode_b4_finalisation_response(wire.dump());
        REQUIRE_FALSE(rejected.has_value());
        CHECK(rejected.error().code == contracts::ContractErrorCode::NullField);
        CHECK(rejected.error().path == "/coverage");
    }
    SECTION("unsupported minor") {
        auto wire = valid;
        wire["contract"]["version"]["minor"] = 1;
        const auto rejected = contracts::decode_b4_finalisation_response(wire.dump());
        REQUIRE_FALSE(rejected.has_value());
        CHECK(rejected.error().code == contracts::ContractErrorCode::UnsupportedVersion);
    }
}

TEST_CASE("ADR-0031 B4 finalisation reply pairs authority with success only",
          "[adr31][contract][b4][finalisation][result][auth]") {
    const auto request = make_request();
    const contracts::B4FinalisationResponse success{make_result(request)};

    SECTION("success requires the branded release authorization") {
        const auto missing = contracts::make_b4_finalisation_reply(success);
        REQUIRE_FALSE(missing.has_value());
        CHECK(binding_error(missing.error()) ==
              contracts::B4FinalisationBindingError::MissingReleaseAuthorization);

        auto wrong = contracts::make_b4_finalisation_reply(
            success, make_auth(contracts::TransportAuthKind::InvocationGrant, "wrong"));
        REQUIRE_FALSE(wrong.has_value());
        CHECK(binding_error(wrong.error()) ==
              contracts::B4FinalisationBindingError::WrongReleaseAuthorizationKind);
    }

    SECTION("success hands body and release authority to the adapter once") {
        auto reply = contracts::make_b4_finalisation_reply(
            success, make_auth(contracts::TransportAuthKind::ReleaseAuthorization, kReleaseSecret));
        REQUIRE(reply.has_value());
        std::string body;
        std::string release;
        const auto sent = std::move(*reply).apply_to_transport(
            [&](const contracts::B4FinalisationReplyInputs& inputs) {
                body = inputs.body().bytes();
                REQUIRE(inputs.release_authorization().has_value());
                release = inputs.release_authorization()->bytes();
            });
        REQUIRE(sent.has_value());
        CHECK(release == kReleaseSecret);
        CHECK(body.find(kReleaseSecret) == std::string::npos);
        CHECK_FALSE(std::move(*reply)
                        .apply_to_transport([](const contracts::B4FinalisationReplyInputs&) {})
                        .has_value());
    }

    SECTION("move transfers the only usable reply and burns the source") {
        auto reply = contracts::make_b4_finalisation_reply(
            success, make_auth(contracts::TransportAuthKind::ReleaseAuthorization, kReleaseSecret));
        REQUIRE(reply.has_value());
        auto destination = std::move(*reply);
        CHECK_FALSE(std::move(*reply)
                        .apply_to_transport([](const contracts::B4FinalisationReplyInputs&) {})
                        .has_value());
        CHECK(std::move(destination)
                  .apply_to_transport([](const contracts::B4FinalisationReplyInputs&) {})
                  .has_value());
    }

    SECTION("a throwing response adapter still burns the reply") {
        auto reply = contracts::make_b4_finalisation_reply(
            success, make_auth(contracts::TransportAuthKind::ReleaseAuthorization, kReleaseSecret));
        REQUIRE(reply.has_value());
        REQUIRE_THROWS_AS(
            std::move(*reply).apply_to_transport([](const contracts::B4FinalisationReplyInputs&) {
                throw std::runtime_error("transport failed");
            }),
            std::runtime_error);
        CHECK_FALSE(std::move(*reply)
                        .apply_to_transport([](const contracts::B4FinalisationReplyInputs&) {})
                        .has_value());
    }

    SECTION("A4 has neither a B4 header nor release authority and is one-shot") {
        const contracts::B4FinalisationResponse failure{make_a4()};
        auto forbidden = contracts::make_b4_finalisation_reply(
            failure, make_auth(contracts::TransportAuthKind::ReleaseAuthorization, kReleaseSecret));
        REQUIRE_FALSE(forbidden.has_value());
        CHECK(binding_error(forbidden.error()) ==
              contracts::B4FinalisationBindingError::UnexpectedReleaseAuthorization);

        auto reply = contracts::make_b4_finalisation_reply(failure);
        REQUIRE(reply.has_value());
        const auto sent = std::move(*reply).apply_to_transport(
            [](const contracts::B4FinalisationReplyInputs& inputs) {
                CHECK_FALSE(inputs.release_authorization().has_value());
                CHECK(inputs.body().bytes().find("yuzu.b4.finalisation") == std::string_view::npos);
            });
        REQUIRE(sent.has_value());
        CHECK_FALSE(std::move(*reply)
                        .apply_to_transport([](const contracts::B4FinalisationReplyInputs&) {})
                        .has_value());
    }

    SECTION("finalisation cannot create an approval flow") {
        const auto encoded = contracts::encode_b4_finalisation_response(
            contracts::B4FinalisationResponse{make_a4(202)});
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().path == "/error/code");
    }
}

TEST_CASE("ADR-0031 B4 finalisation binds a pending release, not a servable result",
          "[adr31][contract][b4][finalisation][binding][security]") {
    const auto request = make_request();
    const auto b2 = make_b2_request();
    const auto payload = make_payload();
    const contracts::B4FinalisationResponse success{make_result(request)};

    SECTION("success privately owns the exact payload and release lease") {
        auto bound = contracts::bind_b4_finalisation_exchange(
            request, b2, payload, success,
            make_auth(contracts::TransportAuthKind::ReleaseAuthorization, kReleaseSecret));
        REQUIRE(bound.has_value());
        REQUIRE(std::holds_alternative<contracts::B4PendingRelease>(*bound));
        CHECK(std::get<contracts::B4PendingRelease>(*bound).receipt().finalisation_receipt ==
              "receipt-core-0001");
    }
    SECTION("missing or wrong release authority fails closed") {
        const auto missing =
            contracts::bind_b4_finalisation_exchange(request, b2, payload, success);
        REQUIRE_FALSE(missing.has_value());
        CHECK(std::get<contracts::B4FinalisationBindingError>(missing.error()) ==
              contracts::B4FinalisationBindingError::MissingReleaseAuthorization);

        const auto wrong = contracts::bind_b4_finalisation_exchange(
            request, b2, payload, success,
            make_auth(contracts::TransportAuthKind::EngineCredential, "wrong"));
        REQUIRE_FALSE(wrong.has_value());
        CHECK(std::get<contracts::B4FinalisationBindingError>(wrong.error()) ==
              contracts::B4FinalisationBindingError::WrongReleaseAuthorizationKind);
    }
    SECTION("a swapped payload is rejected before a pending release exists") {
        auto changed = payload;
        changed.facts[0]["cve"] = "CVE-2026-9999";
        const auto bound = contracts::bind_b4_finalisation_exchange(
            request, b2, changed, success,
            make_auth(contracts::TransportAuthKind::ReleaseAuthorization, kReleaseSecret));
        REQUIRE_FALSE(bound.has_value());
        CHECK(std::get<contracts::ContractError>(bound.error()).path == "/result_hash");
    }
    SECTION("retained B2 identity must still match") {
        const auto rejects_b2 = [&](auto mutate, std::string_view expected_path) {
            auto changed = b2;
            mutate(changed);
            const auto bound = contracts::bind_b4_finalisation_exchange(
                request, changed, payload, success,
                make_auth(contracts::TransportAuthKind::ReleaseAuthorization, kReleaseSecret));
            REQUIRE_FALSE(bound.has_value());
            CHECK(std::get<contracts::ContractError>(bound.error()).path == expected_path);
        };
        SECTION("run") {
            rejects_b2([](auto& value) { value.use_case_run_id = "run_4bK8F7mP2qR9sT6vW3xY5Z"; },
                       "/use_case_run_id");
        }
        SECTION("use case") {
            rejects_b2([](auto& value) { value.use_case.version = "9.0.0"; }, "/use_case");
        }
        SECTION("module") {
            rejects_b2([](auto& value) { value.module.version = "9.0.0"; }, "/module");
        }
    }
    SECTION("A4 binds correlation only and forbids an accompanying lease") {
        const contracts::B4FinalisationResponse failure{make_a4()};
        auto bound = contracts::bind_b4_finalisation_exchange(request, b2, payload, failure);
        REQUIRE(bound.has_value());
        CHECK(std::holds_alternative<contracts::A4ErrorEnvelope>(*bound));

        auto forbidden = contracts::bind_b4_finalisation_exchange(
            request, b2, payload, failure,
            make_auth(contracts::TransportAuthKind::ReleaseAuthorization, kReleaseSecret));
        REQUIRE_FALSE(forbidden.has_value());
        CHECK(std::get<contracts::B4FinalisationBindingError>(forbidden.error()) ==
              contracts::B4FinalisationBindingError::UnexpectedReleaseAuthorization);
    }
}
