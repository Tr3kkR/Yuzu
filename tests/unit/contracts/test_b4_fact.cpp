#include <yuzu/contracts/adr31/b4_fact.hpp>
#include <yuzu/contracts/adr31/contract_limits.hpp>
#include <yuzu/contracts/adr31/contract_version.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace contracts = yuzu::contracts::adr31;

namespace {

constexpr std::string_view kEngineSecret = "fixture-b4-engine-credential";
constexpr std::string_view kGrantSecret = "fixture-b4-invocation-grant";
constexpr std::string_view kInputHash =
    "sha256:8d8e9aecfd69eb15ff3985c3b67b4a432e256bab4bb898d93843d053de7a382d";

struct LegacyPositionalB4Sink {
    void operator()(std::string_view, std::string_view, std::optional<std::string_view>) const {}
};

struct BodyConsumer {
    void operator()(contracts::B4FactRequestBodyView) const {}
};

struct EngineCredentialConsumer {
    void operator()(contracts::B4EngineCredentialView) const {}
};

struct InvocationGrantConsumer {
    void operator()(contracts::B4InvocationGrantView) const {}
};

struct FakeAsyncRequest {
    std::string body;
    std::string engine_credential;
    std::optional<std::string> invocation_grant;
};

contracts::B4FactRequest make_request() {
    return contracts::B4FactRequest{
        .correlation_id = "req-contract-0001",
        .use_case_run_id = "run_7YVvW8ERpX5qx9Qm2LcT4A",
        .module = {.id = "vulnerability-management", .version = "3.1.4"},
        .module_manifest_hash =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .capability = {.id = "inventory.software", .version = "1.0.0"},
        .parameters = nlohmann::json{{"include_suppressed", false}},
        .scope = nlohmann::json{{"kind", "fleet"}},
    };
}

contracts::B2UseCaseRequest make_b2_request() {
    return contracts::B2UseCaseRequest{
        .request_id = "req-use-case-0001",
        .use_case_run_id = "run_7YVvW8ERpX5qx9Qm2LcT4A",
        .use_case = {.id = "vulnerability-prioritisation", .version = "1.2.0"},
        .module = {.id = "vulnerability-management", .version = "3.1.4"},
        .normalised_inputs = nlohmann::json{{"include_suppressed", false}},
    };
}

contracts::B4FactTransportAuth make_authentication(bool include_grant = true) {
    auto engine = contracts::make_transport_auth_slot(
        contracts::TransportAuthKind::EngineCredential, std::string{kEngineSecret});
    if (!engine)
        throw std::logic_error("test engine credential must be valid");

    std::optional<contracts::B4FactInvocationStart> invocation_start;
    if (include_grant) {
        auto made_grant = contracts::make_transport_auth_slot(
            contracts::TransportAuthKind::InvocationGrant, std::string{kGrantSecret});
        if (!made_grant)
            throw std::logic_error("test invocation grant must be valid");
        invocation_start.emplace(contracts::B4FactInvocationStart{
            .received_b2_request = make_b2_request(),
            .invocation_grant = std::move(*made_grant),
        });
    }
    return contracts::B4FactTransportAuth{
        .engine_credential = std::move(*engine),
        .invocation_start = std::move(invocation_start),
    };
}

std::expected<std::string, contracts::ContractError>
encode_request_through_authenticated_carrier(contracts::B4FactRequest request) {
    auto call = contracts::make_b4_fact_call(std::move(request), make_authentication());
    if (!call) {
        if (const auto* contract_error = std::get_if<contracts::ContractError>(&call.error())) {
            return std::unexpected(*contract_error);
        }
        throw std::logic_error("valid test authentication was rejected");
    }

    std::string body;
    const auto applied =
        std::move(*call).apply_to_transport([&](const contracts::B4FactTransportInputs& input) {
            if (input.engine_credential().bytes() != kEngineSecret || !input.invocation_grant() ||
                input.invocation_grant()->bytes() != kGrantSecret) {
                throw std::logic_error("carrier changed test authentication");
            }
            body = input.body().bytes();
        });
    if (!applied)
        throw std::logic_error("fresh carrier was not consumable");
    return body;
}

nlohmann::json base_wire() {
    return nlohmann::json{
        {"contract", {{"id", "yuzu.b4.fact"}, {"version", {{"major", 1}, {"minor", 0}}}}},
        {"correlation_id", "req-contract-0001"},
        {"use_case_run_id", "run_7YVvW8ERpX5qx9Qm2LcT4A"},
        {"module", {{"id", "vulnerability-management"}, {"version", "3.1.4"}}},
        {"module_manifest_hash",
         "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
        {"capability", {{"id", "inventory.software"}, {"version", "1.0.0"}}},
        {"input_hash", kInputHash},
        {"parameters", {{"include_suppressed", false}}},
        {"scope", {{"kind", "fleet"}}},
    };
}

contracts::CoverageEnvelope make_coverage() {
    return contracts::CoverageEnvelope{
        .intended = 3,
        .contacted = 3,
        .responded = 3,
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
    };
}

contracts::B4FactResult make_result(bool include_coverage = true) {
    return contracts::B4FactResult{
        .correlation_id = "req-contract-0001",
        .use_case_run_id = "run_7YVvW8ERpX5qx9Qm2LcT4A",
        .module = {.id = "vulnerability-management", .version = "3.1.4"},
        .module_manifest_hash =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .capability = {.id = "inventory.software", .version = "1.0.0"},
        .facts = nlohmann::json::array(
            {{{"agent_id", "agent-a"}, {"package", "openssl"}, {"version", "3.4.1"}}}),
        .fact_refs = {"fact-read-0001"},
        .scope_basis = contracts::ScopeBasis::Global,
        .coverage = include_coverage ? std::optional{make_coverage()} : std::nullopt,
        .provenance =
            nlohmann::json{{"journal_id", "core-fact-journal-0001"}, {"source", "inventory-store"}},
    };
}

nlohmann::json base_result_wire(bool include_coverage = true) {
    const contracts::B4FactResponse response{make_result(include_coverage)};
    const auto encoded = contracts::encode_b4_fact_response(response);
    if (!encoded)
        throw std::logic_error("valid B4 fact result fixture was rejected");
    return nlohmann::json::parse(*encoded);
}

contracts::A4ErrorEnvelope make_a4_error(std::int32_t code = 503) {
    return contracts::A4ErrorEnvelope{
        .code = code,
        .message = code == 403 ? "permission denied" : "fact dependency unavailable",
        .correlation_id = "req-contract-0001",
        .retry_after_ms = code == 503 ? std::optional<std::int64_t>{5000} : std::nullopt,
        .remediation = std::nullopt,
        .permission =
            code == 403 ? std::optional<std::string>{"InventoryFact:Observe"} : std::nullopt,
        .approval_id = std::nullopt,
        .status_url = std::nullopt,
    };
}

} // namespace

static_assert(!std::is_default_constructible_v<contracts::B4FactCall>);
static_assert(!std::is_copy_constructible_v<contracts::B4FactCall>);
static_assert(!std::is_copy_assignable_v<contracts::B4FactCall>);
static_assert(std::is_nothrow_move_constructible_v<contracts::B4FactCall>);
static_assert(!std::is_move_assignable_v<contracts::B4FactCall>);
static_assert(!std::is_default_constructible_v<contracts::B4FactTransportInputs>);
static_assert(!std::is_copy_constructible_v<contracts::B4FactTransportInputs>);
static_assert(!std::is_move_constructible_v<contracts::B4FactTransportInputs>);
static_assert(!std::is_move_assignable_v<contracts::B4FactTransportInputs>);
static_assert(
    !std::is_invocable_v<LegacyPositionalB4Sink, const contracts::B4FactTransportInputs&>);
static_assert(!std::is_invocable_v<BodyConsumer, contracts::B4EngineCredentialView>);
static_assert(!std::is_invocable_v<EngineCredentialConsumer, contracts::B4InvocationGrantView>);
static_assert(!std::is_invocable_v<InvocationGrantConsumer, contracts::B4FactRequestBodyView>);

TEST_CASE("ADR-0031 B4 fact request has a deterministic authenticated round trip",
          "[adr31][contract][b4][fact]") {
    const auto request = make_request();
    const auto encoded = encode_request_through_authenticated_carrier(request);
    REQUIRE(encoded.has_value());
    CHECK(
        *encoded ==
        R"({"capability":{"id":"inventory.software","version":"1.0.0"},"contract":{"id":"yuzu.b4.fact","version":{"major":1,"minor":0}},"correlation_id":"req-contract-0001","input_hash":"sha256:8d8e9aecfd69eb15ff3985c3b67b4a432e256bab4bb898d93843d053de7a382d","module":{"id":"vulnerability-management","version":"3.1.4"},"module_manifest_hash":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","parameters":{"include_suppressed":false},"scope":{"kind":"fleet"},"use_case_run_id":"run_7YVvW8ERpX5qx9Qm2LcT4A"})");
    CHECK(encoded->find(kEngineSecret) == std::string::npos);
    CHECK(encoded->find(kGrantSecret) == std::string::npos);

    auto decoded = contracts::decode_b4_fact_request(*encoded);
    REQUIRE(decoded.has_value());
    CHECK(decoded->correlation_id == request.correlation_id);
    CHECK(decoded->use_case_run_id == request.use_case_run_id);
    CHECK(decoded->module == request.module);
    CHECK(decoded->module_manifest_hash == request.module_manifest_hash);
    CHECK(decoded->capability == request.capability);
    REQUIRE(decoded->input_hash.has_value());
    CHECK(*decoded->input_hash == kInputHash);
    CHECK(decoded->parameters == request.parameters);
    CHECK(decoded->scope == request.scope);

    decoded->input_hash.reset();
    const auto reencoded = encode_request_through_authenticated_carrier(*decoded);
    REQUIRE(reencoded.has_value());
    CHECK(*reencoded == *encoded);
}

TEST_CASE("ADR-0031 B4 fact carrier atomically applies all transport inputs",
          "[adr31][contract][b4][fact][auth]") {
    auto authentication = make_authentication();
    auto call = contracts::make_b4_fact_call(make_request(), std::move(authentication));
    REQUIRE(call.has_value());
    CHECK_FALSE(authentication.engine_credential.valid());
    REQUIRE(authentication.invocation_start.has_value());
    CHECK_FALSE(authentication.invocation_start->invocation_grant.valid());

    bool invoked = false;
    std::string body;
    std::string engine_secret;
    std::string grant_secret;
    const auto applied =
        std::move(*call).apply_to_transport([&](const contracts::B4FactTransportInputs& input) {
            invoked = true;
            body = input.body().bytes();
            engine_secret = input.engine_credential().bytes();
            REQUIRE(input.invocation_grant().has_value());
            grant_secret = input.invocation_grant()->bytes();
        });
    REQUIRE(applied.has_value());
    CHECK(invoked);
    CHECK(engine_secret == kEngineSecret);
    CHECK(grant_secret == kGrantSecret);
    CHECK(body.find(engine_secret) == std::string::npos);
    CHECK(body.find(grant_secret) == std::string::npos);

    bool repeated = false;
    const auto repeat = std::move(*call).apply_to_transport(
        [&](const contracts::B4FactTransportInputs&) { repeated = true; });
    REQUIRE_FALSE(repeat.has_value());
    REQUIRE(std::holds_alternative<contracts::B4FactAuthBindingError>(repeat.error()));
    CHECK(std::get<contracts::B4FactAuthBindingError>(repeat.error()) ==
          contracts::B4FactAuthBindingError::Consumed);
    CHECK_FALSE(repeated);
}

TEST_CASE("ADR-0031 B4 fact permits engine-authenticated mid-run calls without a grant",
          "[adr31][contract][b4][fact][auth]") {
    auto call = contracts::make_b4_fact_call(make_request(), make_authentication(false));
    REQUIRE(call.has_value());

    bool invoked = false;
    std::string body;
    const auto applied =
        std::move(*call).apply_to_transport([&](const contracts::B4FactTransportInputs& input) {
            invoked = true;
            body = input.body().bytes();
            CHECK(input.engine_credential().bytes() == kEngineSecret);
            CHECK_FALSE(input.invocation_grant().has_value());
        });
    REQUIRE(applied.has_value());
    CHECK(invoked);
    CHECK(body.find("input_hash") == std::string::npos);
    const auto decoded = contracts::decode_b4_fact_request(body);
    REQUIRE(decoded.has_value());
    CHECK_FALSE(decoded->input_hash.has_value());
}

TEST_CASE("ADR-0031 B4 fact adapter can retain only owned transport copies",
          "[adr31][contract][b4][fact][auth][safety]") {
    std::optional<FakeAsyncRequest> retained;
    {
        auto call = contracts::make_b4_fact_call(make_request(), make_authentication());
        REQUIRE(call.has_value());
        const auto applied =
            std::move(*call).apply_to_transport([&](const contracts::B4FactTransportInputs& input) {
                retained.emplace(FakeAsyncRequest{
                    .body = std::string{input.body().bytes()},
                    .engine_credential = std::string{input.engine_credential().bytes()},
                    .invocation_grant =
                        input.invocation_grant()
                            ? std::optional<std::string>{input.invocation_grant()->bytes()}
                            : std::nullopt,
                });
            });
        REQUIRE(applied.has_value());
    }

    REQUIRE(retained.has_value());
    CHECK(retained->engine_credential == kEngineSecret);
    REQUIRE(retained->invocation_grant.has_value());
    CHECK(*retained->invocation_grant == kGrantSecret);
    CHECK(contracts::decode_b4_fact_request(retained->body).has_value());
}

TEST_CASE("ADR-0031 B4 fact carrier fails closed across moves and exceptions",
          "[adr31][contract][b4][fact][auth][safety]") {
    SECTION("moving transfers the only usable lease") {
        auto call = contracts::make_b4_fact_call(make_request(), make_authentication());
        REQUIRE(call.has_value());
        auto moved = std::move(*call);

        bool source_invoked = false;
        const auto source = std::move(*call).apply_to_transport(
            [&](const contracts::B4FactTransportInputs&) { source_invoked = true; });
        REQUIRE_FALSE(source.has_value());
        CHECK_FALSE(source_invoked);
        CHECK(std::get<contracts::B4FactAuthBindingError>(source.error()) ==
              contracts::B4FactAuthBindingError::Consumed);

        bool destination_invoked = false;
        const auto destination = std::move(moved).apply_to_transport(
            [&](const contracts::B4FactTransportInputs&) { destination_invoked = true; });
        REQUIRE(destination.has_value());
        CHECK(destination_invoked);
    }

    SECTION("a throwing sink still consumes and scrubs the lease") {
        for (const bool include_grant : {false, true}) {
            auto call =
                contracts::make_b4_fact_call(make_request(), make_authentication(include_grant));
            REQUIRE(call.has_value());
            REQUIRE_THROWS_AS(
                std::move(*call).apply_to_transport([](const contracts::B4FactTransportInputs&) {
                    throw std::runtime_error("transport rejected request");
                }),
                std::runtime_error);

            bool retry_invoked = false;
            const auto retry = std::move(*call).apply_to_transport(
                [&](const contracts::B4FactTransportInputs&) { retry_invoked = true; });
            CAPTURE(include_grant);
            REQUIRE_FALSE(retry.has_value());
            CHECK_FALSE(retry_invoked);
            CHECK(std::get<contracts::B4FactAuthBindingError>(retry.error()) ==
                  contracts::B4FactAuthBindingError::Consumed);
        }
    }
}

TEST_CASE("ADR-0031 B4 fact factory rejects invalid transport authentication first",
          "[adr31][contract][b4][fact][auth][negative]") {
    auto invalid_request = make_request();
    invalid_request.parameters = nlohmann::json::array();

    SECTION("missing or moved engine credential") {
        auto engine = contracts::make_transport_auth_slot(
            contracts::TransportAuthKind::EngineCredential, "moved-engine-secret");
        REQUIRE(engine.has_value());
        auto owner = std::move(*engine);
        auto rejected = contracts::make_b4_fact_call(
            invalid_request,
            contracts::B4FactTransportAuth{.engine_credential = std::move(*engine)});
        REQUIRE_FALSE(rejected.has_value());
        CHECK(std::get<contracts::B4FactAuthBindingError>(rejected.error()) ==
              contracts::B4FactAuthBindingError::MissingEngineCredential);
        CHECK(owner.valid());
    }

    SECTION("every wrong engine credential kind") {
        for (const auto kind : {contracts::TransportAuthKind::CallerCredential,
                                contracts::TransportAuthKind::InvocationGrant,
                                contracts::TransportAuthKind::ReleaseAuthorization}) {
            auto engine = contracts::make_transport_auth_slot(kind, "wrong-engine-secret");
            REQUIRE(engine.has_value());
            auto rejected = contracts::make_b4_fact_call(
                invalid_request,
                contracts::B4FactTransportAuth{.engine_credential = std::move(*engine)});
            CAPTURE(static_cast<int>(kind));
            REQUIRE_FALSE(rejected.has_value());
            CHECK(std::get<contracts::B4FactAuthBindingError>(rejected.error()) ==
                  contracts::B4FactAuthBindingError::WrongEngineCredentialKind);
        }
    }

    SECTION("moved invocation grant") {
        auto auth = make_authentication(false);
        auto grant = contracts::make_transport_auth_slot(
            contracts::TransportAuthKind::InvocationGrant, "moved-grant-secret");
        REQUIRE(grant.has_value());
        auto owner = std::move(*grant);
        auth.invocation_start.emplace(contracts::B4FactInvocationStart{
            .received_b2_request = make_b2_request(),
            .invocation_grant = std::move(*grant),
        });
        auto rejected = contracts::make_b4_fact_call(invalid_request, std::move(auth));
        REQUIRE_FALSE(rejected.has_value());
        CHECK(std::get<contracts::B4FactAuthBindingError>(rejected.error()) ==
              contracts::B4FactAuthBindingError::InvalidInvocationGrant);
        CHECK(owner.valid());
    }

    SECTION("every wrong invocation grant kind") {
        for (const auto kind : {contracts::TransportAuthKind::CallerCredential,
                                contracts::TransportAuthKind::EngineCredential,
                                contracts::TransportAuthKind::ReleaseAuthorization}) {
            auto auth = make_authentication(false);
            auto grant = contracts::make_transport_auth_slot(kind, "wrong-grant-secret");
            REQUIRE(grant.has_value());
            auth.invocation_start.emplace(contracts::B4FactInvocationStart{
                .received_b2_request = make_b2_request(),
                .invocation_grant = std::move(*grant),
            });
            auto rejected = contracts::make_b4_fact_call(invalid_request, std::move(auth));
            CAPTURE(static_cast<int>(kind));
            REQUIRE_FALSE(rejected.has_value());
            CHECK(std::get<contracts::B4FactAuthBindingError>(rejected.error()) ==
                  contracts::B4FactAuthBindingError::WrongInvocationGrantKind);
        }
    }
}

TEST_CASE("ADR-0031 B4 fact derives the start hash from the received B2 request",
          "[adr31][contract][b4][fact][auth][security]") {
    SECTION("a caller-authored input hash cannot satisfy the binding") {
        auto request = make_request();
        request.input_hash =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        auto rejected = contracts::make_b4_fact_call(std::move(request), make_authentication());
        REQUIRE_FALSE(rejected.has_value());
        CHECK(std::get<contracts::B4FactAuthBindingError>(rejected.error()) ==
              contracts::B4FactAuthBindingError::CallerAuthoredInputHash);
    }

    SECTION("the received B2 run must match the B4 run") {
        auto auth = make_authentication();
        auth.invocation_start->received_b2_request.use_case_run_id = "run_4bK8F7mP2qR9sT6vW3xY5Z";
        auto rejected = contracts::make_b4_fact_call(make_request(), std::move(auth));
        REQUIRE_FALSE(rejected.has_value());
        CHECK(std::get<contracts::B4FactAuthBindingError>(rejected.error()) ==
              contracts::B4FactAuthBindingError::StartRunMismatch);
    }

    SECTION("the received B2 module must match the B4 module") {
        auto auth = make_authentication();
        auth.invocation_start->received_b2_request.module.version = "3.1.5";
        auto rejected = contracts::make_b4_fact_call(make_request(), std::move(auth));
        REQUIRE_FALSE(rejected.has_value());
        CHECK(std::get<contracts::B4FactAuthBindingError>(rejected.error()) ==
              contracts::B4FactAuthBindingError::StartModuleMismatch);
    }
}

TEST_CASE("ADR-0031 B4 fact encoder owns structural validation failures",
          "[adr31][contract][b4][fact][negative]") {
    auto request = make_request();

    SECTION("parameters must be an object") {
        request.parameters = nlohmann::json::array();
        const auto encoded = encode_request_through_authenticated_carrier(request);
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::WrongType);
        CHECK(encoded.error().path == "/parameters");
    }

    SECTION("authority metadata is forbidden inside scope") {
        request.scope["nested"] = {{"operator_id", "operator-7"}};
        const auto encoded = encode_request_through_authenticated_carrier(request);
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
        CHECK(encoded.error().path == "/scope/nested/operator_id");
    }

    SECTION("oversized output") {
        request.parameters["padding"] = std::string(contracts::kMaxContractWireBytes, 'x');
        const auto encoded = encode_request_through_authenticated_carrier(request);
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::TooLarge);
    }

    SECTION("excessive nesting") {
        request.parameters = nlohmann::json::object();
        for (std::size_t depth = 0; depth < contracts::kMaxContractNestingDepth; ++depth) {
            request.parameters = {{"nested", std::move(request.parameters)}};
        }
        const auto encoded = encode_request_through_authenticated_carrier(request);
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::TooDeep);
    }

    SECTION("non-finite numbers") {
        request.parameters["invalid"] = std::numeric_limits<double>::infinity();
        const auto encoded = encode_request_through_authenticated_carrier(request);
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::InvalidValue);
    }
}

TEST_CASE("ADR-0031 B4 fact rejects caller-authored authority and transport auth",
          "[adr31][contract][b4][fact][security]") {
    for (const std::string_view forbidden : {"operator_id", "on_behalf_of", "engine_credential",
                                             "invocation_grant", "grant", "scope_ceiling"}) {
        auto wire = base_wire();
        wire[forbidden] = "caller-authored";
        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        CAPTURE(forbidden);
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
        CHECK(decoded.error().path == "/" + std::string{forbidden});
    }

    SECTION("control objects reject nested authority claims") {
        auto wire = base_wire();
        wire["scope"]["items"] =
            nlohmann::json::array({{{"kind", "group"}, {"on_behalf_of", "operator-7"}}});
        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
        CHECK(decoded.error().path == "/scope/items/0/on_behalf_of");
    }

    SECTION("contract extensions reject nested authority claims") {
        auto wire = base_wire();
        wire["contract"]["future"] = {{"on_behalf_of", "operator-7"}};
        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
        CHECK(decoded.error().path == "/contract/future/on_behalf_of");
    }

    SECTION("additive control-envelope fields reject nested authority claims") {
        for (const std::string_view forbidden :
             {"on_behalf_of", "acting_operator_id", "operator_context",
              "represented_operator_claim", "act_as", "obo_context", "auth_context",
              "access_token_value", "oboContext", "authContext", "accessTokenValue"}) {
            auto wire = base_wire();
            wire["future"][forbidden] = "operator-7";
            const auto decoded = contracts::decode_b4_fact_request(wire.dump());
            CAPTURE(forbidden);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
            CHECK(decoded.error().path == "/future/" + std::string{forbidden});
        }
    }

    SECTION("opaque parameters still reject transport authority metadata") {
        for (const std::string_view forbidden : {"engine_credential",
                                                 "invocation_grant",
                                                 "authorization",
                                                 "operator_id",
                                                 "represented_operator",
                                                 "on_behalf_of",
                                                 "On-Behalf-Of",
                                                 "X-Yuzu-On-Behalf-Of",
                                                 "X-Yuzu-Delegated-Operator",
                                                 "X-Yuzu-Delegation-Artifact",
                                                 "acting_operator_id",
                                                 "operator_context",
                                                 "represented_operator_claim",
                                                 "act_as",
                                                 "obo_context",
                                                 "auth_context",
                                                 "access_token_value",
                                                 "representedoperatorclaim",
                                                 "delegatedoperatorcontext",
                                                 "grantcontext",
                                                 "tokenvalue"}) {
            auto wire = base_wire();
            wire["parameters"]["nested"][forbidden] = "caller-authored";
            const auto decoded = contracts::decode_b4_fact_request(wire.dump());
            CAPTURE(forbidden);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
            CHECK(decoded.error().path == "/parameters/nested/" + std::string{forbidden});
        }
    }

    SECTION("domain parameters may use domain-shaped identity fields") {
        auto wire = base_wire();
        wire["parameters"]["subject"] = {{"kind", "certificate"}, {"value", "CN=device"}};
        wire["parameters"]["identity"] = {{"kind", "package"}, {"value", "openssl"}};
        wire["parameters"]["user"] = "local-account-inventory";
        wire["parameters"]["author"] = "package-maintainer";
        wire["parameters"]["fact_assertion"] = true;
        wire["parameters"]["id_tokenizer"] = "domain-parser";
        wire["parameters"]["tokenizer"] = "domain-parser";
        wire["parameters"]["token_count"] = 12;
        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        REQUIRE(decoded.has_value());
        CHECK(decoded->parameters == wire["parameters"]);
    }

    SECTION("many-component domain keys stay bounded and remain valid") {
        auto wire = base_wire();
        std::string field;
        field.reserve(48 * 1024);
        while (field.size() + 7 < 48 * 1024)
            field += "a-";
        field += "metric";
        wire["parameters"][field] = true;

        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        REQUIRE(decoded.has_value());
        CHECK(decoded->parameters[field] == true);
    }
}

TEST_CASE("ADR-0031 B4 fact decoder distinguishes missing null and wrong-typed fields",
          "[adr31][contract][b4][fact][negative]") {
    for (const std::string_view field :
         {"correlation_id", "use_case_run_id", "module", "module_manifest_hash", "capability",
          "parameters", "scope"}) {
        SECTION(std::string{"missing "} + std::string{field}) {
            auto wire = base_wire();
            wire.erase(field);
            const auto decoded = contracts::decode_b4_fact_request(wire.dump());
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::MissingField);
            CHECK(decoded.error().path == "/" + std::string{field});
        }

        SECTION(std::string{"null "} + std::string{field}) {
            auto wire = base_wire();
            wire[field] = nullptr;
            const auto decoded = contracts::decode_b4_fact_request(wire.dump());
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::NullField);
            CHECK(decoded.error().path == "/" + std::string{field});
        }
    }

    SECTION("wrong object type") {
        auto wire = base_wire();
        wire["capability"] = "inventory.software@1.0.0";
        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::WrongType);
        CHECK(decoded.error().path == "/capability");
    }

    SECTION("nested reference member") {
        auto wire = base_wire();
        wire["module"].erase("version");
        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::MissingField);
        CHECK(decoded.error().path == "/module/version");
    }

    SECTION("optional input hash rejects explicit null") {
        auto wire = base_wire();
        wire["input_hash"] = nullptr;
        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::NullField);
        CHECK(decoded.error().path == "/input_hash");
    }

    SECTION("optional input hash rejects a non-string") {
        auto wire = base_wire();
        wire["input_hash"] = 7;
        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::WrongType);
        CHECK(decoded.error().path == "/input_hash");
    }

    SECTION("optional input hash rejects an empty string") {
        auto wire = base_wire();
        wire["input_hash"] = "";
        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/input_hash");
    }
}

TEST_CASE("ADR-0031 B4 fact decoder is additive but version strict",
          "[adr31][contract][b4][fact][compatibility]") {
    SECTION("safe future root members are ignored") {
        auto wire = base_wire();
        wire["future_diagnostic"] = {{"trace", "trace-7"}};
        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        REQUIRE(decoded.has_value());
        CHECK(decoded->correlation_id == "req-contract-0001");
    }

    SECTION("unsupported minor version is rejected") {
        auto wire = base_wire();
        wire["contract"]["version"]["minor"] = 1;
        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::UnsupportedVersion);
    }

    SECTION("unsupported major version is rejected") {
        auto wire = base_wire();
        wire["contract"]["version"]["major"] = 2;
        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::UnsupportedVersion);
    }

    SECTION("wrong contract identifier is rejected") {
        auto wire = base_wire();
        wire["contract"]["id"] = "yuzu.b4.finalisation";
        const auto decoded = contracts::decode_b4_fact_request(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/contract/id");
    }

    CHECK(contracts::kB4Fact.identifier == "yuzu.b4.fact");
    REQUIRE(contracts::kB4Fact.supported_versions.size() == 1);
    CHECK(contracts::kB4Fact.supported_versions.front() == contracts::kVersion1_0);
}

TEST_CASE("ADR-0031 B4 fact rejects malformed and ambiguous JSON",
          "[adr31][contract][b4][fact][negative]") {
    SECTION("trailing data") {
        const auto decoded = contracts::decode_b4_fact_request(base_wire().dump() + " trailing");
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::MalformedJson);
    }

    SECTION("non-object root") {
        const auto decoded = contracts::decode_b4_fact_request("[]");
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::RootNotObject);
    }

    SECTION("duplicate field") {
        const auto wire = base_wire().dump();
        const auto insertion = wire.find("\"correlation_id\"");
        REQUIRE(insertion != std::string::npos);
        auto duplicate = wire;
        duplicate.insert(insertion, "\"correlation_id\":\"attacker\",");
        const auto decoded = contracts::decode_b4_fact_request(duplicate);
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::DuplicateKey);
        CHECK(decoded.error().path == "/correlation_id");
    }

    SECTION("invalid UTF-8") {
        auto wire = base_wire().dump();
        wire.insert(wire.size() - 1,
                    std::string{",\"future\":\""} + static_cast<char>(0xff) + "\"");
        const auto decoded = contracts::decode_b4_fact_request(wire);
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::MalformedJson);
    }
}

TEST_CASE("ADR-0031 B4 fact encoding is independent of object insertion order",
          "[adr31][contract][b4][fact][compatibility]") {
    auto first = make_request();
    auto second = first;
    second.parameters = nlohmann::json::object();
    second.parameters["z_last"] = 7;
    second.parameters["include_suppressed"] = false;
    first.parameters["z_last"] = 7;
    second.scope = nlohmann::json::object();
    second.scope["value"] = "engineering";
    second.scope["kind"] = "group";
    first.scope = {{"kind", "group"}, {"value", "engineering"}};

    const auto first_wire = encode_request_through_authenticated_carrier(first);
    const auto second_wire = encode_request_through_authenticated_carrier(second);
    REQUIRE(first_wire.has_value());
    REQUIRE(second_wire.has_value());
    CHECK(*first_wire == *second_wire);
}

TEST_CASE("ADR-0031 B4 fact result has a deterministic bound round trip",
          "[adr31][contract][b4][fact][result]") {
    const contracts::B4FactResponse response{make_result()};
    const auto encoded = contracts::encode_b4_fact_response(response);
    REQUIRE(encoded.has_value());
    CHECK(
        *encoded ==
        R"({"capability":{"id":"inventory.software","version":"1.0.0"},"contract":{"id":"yuzu.b4.fact","version":{"major":1,"minor":0}},"correlation_id":"req-contract-0001","coverage":{"completeness":"complete","contacted":3,"failed":0,"intended":3,"offline":0,"policy":{"blocks_next_step_when_incomplete":true,"minimum_response_percent":100},"responded":3,"scope_basis":"global","timed_out":0},"fact_refs":["fact-read-0001"],"facts":[{"agent_id":"agent-a","package":"openssl","version":"3.4.1"}],"module":{"id":"vulnerability-management","version":"3.1.4"},"module_manifest_hash":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","provenance":{"journal_id":"core-fact-journal-0001","source":"inventory-store"},"scope_basis":"global","use_case_run_id":"run_7YVvW8ERpX5qx9Qm2LcT4A"})");

    const auto decoded = contracts::decode_b4_fact_response(*encoded);
    REQUIRE(decoded.has_value());
    CHECK(*decoded == response);
    CHECK(contracts::validate_b4_fact_exchange(make_request(), *decoded).has_value());
}

TEST_CASE("ADR-0031 B4 fact result keeps scope basis independent from request shape",
          "[adr31][contract][b4][fact][result][scope]") {
    SECTION("a confined fleet read may be complete within its authorised cohort") {
        auto result = make_result();
        result.scope_basis = contracts::ScopeBasis::AuthorityScoped;
        result.coverage->scope_basis = contracts::ScopeBasis::AuthorityScoped;
        const contracts::B4FactResponse response{result};
        CHECK(contracts::validate_b4_fact_exchange(make_request(), response).has_value());
        CHECK(contracts::encode_b4_fact_response(response).has_value());
    }

    SECTION("an intentionally narrow read may retain a global authority basis") {
        auto request = make_request();
        request.scope = {{"kind", "group"}, {"value", "engineering"}};
        const contracts::B4FactResponse response{make_result(false)};
        CHECK(contracts::validate_b4_fact_exchange(request, response).has_value());
    }

    SECTION("core-store result omits distributed coverage") {
        const contracts::B4FactResponse response{make_result(false)};
        const auto encoded = contracts::encode_b4_fact_response(response);
        REQUIRE(encoded.has_value());
        CHECK(encoded->find("coverage") == std::string::npos);
        const auto decoded = contracts::decode_b4_fact_response(*encoded);
        REQUIRE(decoded.has_value());
        CHECK(*decoded == response);
    }

    SECTION("coverage and result markers cannot contradict") {
        auto result = make_result();
        result.coverage->scope_basis = contracts::ScopeBasis::AuthorityScoped;
        const auto encoded =
            contracts::encode_b4_fact_response(contracts::B4FactResponse{std::move(result)});
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(encoded.error().path == "/coverage/scope_basis");
    }

    SECTION("zero intended targets can be an honest complete empty answer") {
        auto result = make_result();
        result.facts = nlohmann::json::array();
        result.coverage->intended = 0;
        result.coverage->contacted = 0;
        result.coverage->responded = 0;
        const auto encoded =
            contracts::encode_b4_fact_response(contracts::B4FactResponse{std::move(result)});
        REQUIRE(encoded.has_value());
    }
}

TEST_CASE("ADR-0031 B4 fact errors reuse A4 without creating an approval path",
          "[adr31][contract][b4][fact][result][a4]") {
    SECTION("permission denial round trips and binds only correlation") {
        const contracts::B4FactResponse response{make_a4_error(403)};
        const auto encoded = contracts::encode_b4_fact_response(response);
        REQUIRE(encoded.has_value());
        CHECK(encoded->find("yuzu.b4.fact") == std::string::npos);
        CHECK(encoded->find("InventoryFact:Observe") != std::string::npos);
        const auto decoded = contracts::decode_b4_fact_response(*encoded);
        REQUIRE(decoded.has_value());
        CHECK(*decoded == response);
        CHECK(contracts::validate_b4_fact_exchange(make_request(), *decoded).has_value());
    }

    SECTION("retryable dependency error round trips") {
        const contracts::B4FactResponse response{make_a4_error()};
        const auto encoded = contracts::encode_b4_fact_response(response);
        REQUIRE(encoded.has_value());
        const auto decoded = contracts::decode_b4_fact_response(*encoded);
        REQUIRE(decoded.has_value());
        CHECK(*decoded == response);
    }

    SECTION("fact reads cannot enter approval") {
        auto approval = make_a4_error(202);
        approval.message = "approval required";
        approval.approval_id = "approval-0001";
        approval.status_url = "/api/v1/approvals/approval-0001";
        const auto encoded =
            contracts::encode_b4_fact_response(contracts::B4FactResponse{std::move(approval)});
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().path == "/error/code");

        const auto wire =
            R"({"error":{"approval_id":"approval-0001","code":202,"correlation_id":"req-contract-0001","message":"approval required","retry_after_ms":null,"status_url":"/api/v1/approvals/approval-0001"},"meta":{"api_version":"v1"}})";
        const auto decoded = contracts::decode_b4_fact_response(wire);
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().path == "/error/code");
    }
}

TEST_CASE("ADR-0031 B4 fact exchange rejects every swapped success identity",
          "[adr31][contract][b4][fact][result][security]") {
    const auto request = make_request();

    const auto reject = [&](contracts::B4FactResult result, std::string_view expected_path) {
        const auto valid = contracts::validate_b4_fact_exchange(
            request, contracts::B4FactResponse{std::move(result)});
        REQUIRE_FALSE(valid.has_value());
        CHECK(valid.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(valid.error().path == expected_path);
    };

    auto correlation = make_result();
    correlation.correlation_id = "req-contract-0002";
    reject(std::move(correlation), "/correlation_id");

    auto run = make_result();
    run.use_case_run_id = "run_7YVvW8ERpX5qx9Qm2LcT4B";
    reject(std::move(run), "/use_case_run_id");

    auto module_id = make_result();
    module_id.module.id = "other-module";
    reject(std::move(module_id), "/module/id");

    auto module_version = make_result();
    module_version.module.version = "3.1.5";
    reject(std::move(module_version), "/module/version");

    auto manifest = make_result();
    manifest.module_manifest_hash =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    reject(std::move(manifest), "/module_manifest_hash");

    auto capability_id = make_result();
    capability_id.capability.id = "inventory.hardware";
    reject(std::move(capability_id), "/capability/id");

    auto capability_version = make_result();
    capability_version.capability.version = "2.0.0";
    reject(std::move(capability_version), "/capability/version");

    auto denial = make_a4_error();
    denial.correlation_id = "req-contract-0002";
    const auto denial_valid =
        contracts::validate_b4_fact_exchange(request, contracts::B4FactResponse{std::move(denial)});
    REQUIRE_FALSE(denial_valid.has_value());
    CHECK(denial_valid.error().path == "/correlation_id");
}

TEST_CASE("ADR-0031 B4 fact result requires typed facts and durable references",
          "[adr31][contract][b4][fact][result][negative]") {
    SECTION("empty facts remain an honest result") {
        auto result = make_result(false);
        result.facts = nlohmann::json::array();
        CHECK(contracts::encode_b4_fact_response(contracts::B4FactResponse{std::move(result)})
                  .has_value());
    }

    SECTION("facts must be structured") {
        const std::array invalid{nlohmann::json(nullptr), nlohmann::json(true), nlohmann::json(7),
                                 nlohmann::json("row")};
        for (const auto& value : invalid) {
            auto wire = base_result_wire(false);
            wire["facts"] = value;
            const auto decoded = contracts::decode_b4_fact_response(wire.dump());
            CAPTURE(value);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == (value.is_null()
                                               ? contracts::ContractErrorCode::NullField
                                               : contracts::ContractErrorCode::WrongType));
            CHECK(decoded.error().path == "/facts");
        }
    }

    SECTION("at least one fact reference is required") {
        auto wire = base_result_wire(false);
        wire["fact_refs"] = nlohmann::json::array();
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/fact_refs");
    }

    SECTION("fact references are nonempty strings") {
        const std::array invalid{nlohmann::json(nullptr), nlohmann::json(7), nlohmann::json("")};
        for (const auto& value : invalid) {
            auto wire = base_result_wire(false);
            wire["fact_refs"] = nlohmann::json::array({value});
            const auto decoded = contracts::decode_b4_fact_response(wire.dump());
            CAPTURE(value);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().path == "/fact_refs/0");
        }
    }

    SECTION("fact references are unique") {
        auto wire = base_result_wire(false);
        wire["fact_refs"] = nlohmann::json::array({"fact-read-0001", "fact-read-0001"});
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/fact_refs/1");
    }

    SECTION("fact_refs itself is an array") {
        auto wire = base_result_wire(false);
        wire["fact_refs"] = "fact-read-0001";
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::WrongType);
        CHECK(decoded.error().path == "/fact_refs");
    }
}

TEST_CASE("ADR-0031 B4 fact result enforces distributed coverage arithmetic",
          "[adr31][contract][b4][fact][result][coverage][negative]") {
    SECTION("coverage is optional but never nullable") {
        auto wire = base_result_wire();
        wire["coverage"] = nullptr;
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::NullField);
        CHECK(decoded.error().path == "/coverage");
    }

    SECTION("coverage must be an object") {
        auto wire = base_result_wire();
        wire["coverage"] = nlohmann::json::array();
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::WrongType);
        CHECK(decoded.error().path == "/coverage");
    }

    SECTION("contacted cannot exceed intended") {
        auto wire = base_result_wire();
        wire["coverage"]["contacted"] = 4;
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/coverage");
    }

    SECTION("classified outcomes cannot exceed contacted") {
        auto wire = base_result_wire();
        wire["coverage"]["responded"] = 2;
        wire["coverage"]["failed"] = 2;
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/coverage");
    }

    SECTION("complete cannot conceal a non-response") {
        auto wire = base_result_wire();
        wire["coverage"]["responded"] = 2;
        wire["coverage"]["timed_out"] = 1;
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/coverage/completeness");
    }

    SECTION("policy threshold is one through one hundred") {
        for (const int value : {0, 101}) {
            auto wire = base_result_wire();
            wire["coverage"]["policy"]["minimum_response_percent"] = value;
            const auto decoded = contracts::decode_b4_fact_response(wire.dump());
            CAPTURE(value);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
            CHECK(decoded.error().path == "/coverage/policy/minimum_response_percent");
        }
    }
}

TEST_CASE("ADR-0031 B4 fact result rejects malformed and ambiguous outcomes",
          "[adr31][contract][b4][fact][result][negative]") {
    SECTION("neither success nor error") {
        const auto decoded = contracts::decode_b4_fact_response(R"({"future":true})");
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::MissingField);
    }

    SECTION("both success and error") {
        auto wire = base_result_wire();
        wire["error"] = {{"code", 503},
                         {"correlation_id", "req-contract-0001"},
                         {"message", "unavailable"},
                         {"retry_after_ms", nullptr}};
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
    }

    SECTION("A4 error cannot carry the B4 contract header") {
        auto wire = nlohmann::json::parse(
            R"({"error":{"code":503,"correlation_id":"req-contract-0001","message":"unavailable","retry_after_ms":null},"meta":{"api_version":"v1"}})");
        wire["contract"] = base_result_wire()["contract"];
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/contract");
        CHECK(decoded.error().message == "A4 errors do not carry a B4 contract header");
    }

    SECTION("unsupported success version") {
        auto wire = base_result_wire();
        wire["contract"]["version"]["major"] = 2;
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::UnsupportedVersion);
    }

    SECTION("non-object root") {
        const auto decoded = contracts::decode_b4_fact_response("[]");
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::RootNotObject);
    }

    SECTION("trailing bytes") {
        const auto decoded =
            contracts::decode_b4_fact_response(base_result_wire().dump() + " trailing");
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::MalformedJson);
    }

    SECTION("duplicate nested success field") {
        const auto wire = base_result_wire().dump();
        const auto insertion = wire.find("\"module_manifest_hash\"");
        REQUIRE(insertion != std::string::npos);
        auto duplicate = wire;
        duplicate.insert(insertion, "\"module_manifest_hash\":\"attacker\",");
        const auto decoded = contracts::decode_b4_fact_response(duplicate);
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::DuplicateKey);
        CHECK(decoded.error().path == "/module_manifest_hash");
    }

    SECTION("invalid UTF-8") {
        auto wire = base_result_wire().dump();
        wire.insert(wire.size() - 1,
                    std::string{",\"future\":\""} + static_cast<char>(0xff) + "\"");
        const auto decoded = contracts::decode_b4_fact_response(wire);
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::MalformedJson);
    }

    SECTION("wire bound") {
        auto wire = base_result_wire(false);
        wire["facts"] = nlohmann::json::array({std::string(contracts::kMaxContractWireBytes, 'x')});
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::TooLarge);
    }

    SECTION("non-finite in-memory fact") {
        auto result = make_result(false);
        result.facts[0]["score"] = std::numeric_limits<double>::infinity();
        const auto encoded =
            contracts::encode_b4_fact_response(contracts::B4FactResponse{std::move(result)});
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::InvalidValue);
    }
}

TEST_CASE("ADR-0031 B4 fact result distinguishes missing null and wrong-typed fields",
          "[adr31][contract][b4][fact][result][negative]") {
    for (const std::string_view field :
         {"correlation_id", "use_case_run_id", "module_manifest_hash", "module", "capability",
          "fact_refs", "scope_basis", "provenance"}) {
        SECTION(std::string{"missing "} + std::string{field}) {
            auto wire = base_result_wire(false);
            wire.erase(field);
            const auto decoded = contracts::decode_b4_fact_response(wire.dump());
            CAPTURE(field);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::MissingField);
            CHECK(decoded.error().path == "/" + std::string{field});
        }

        SECTION(std::string{"null "} + std::string{field}) {
            auto wire = base_result_wire(false);
            wire[field] = nullptr;
            const auto decoded = contracts::decode_b4_fact_response(wire.dump());
            CAPTURE(field);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::NullField);
            CHECK(decoded.error().path == "/" + std::string{field});
        }
    }

    SECTION("unknown scope basis") {
        auto wire = base_result_wire(false);
        wire["scope_basis"] = "row_count_inferred";
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(decoded.error().path == "/scope_basis");
    }

    SECTION("provenance must be an object") {
        auto wire = base_result_wire(false);
        wire["provenance"] = nlohmann::json::array();
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::WrongType);
        CHECK(decoded.error().path == "/provenance");
    }
}

TEST_CASE("ADR-0031 B4 fact result excludes authority and confinement oracles",
          "[adr31][contract][b4][fact][result][security]") {
    SECTION("control additions cannot smuggle authority") {
        for (const std::string_view field :
             {"operator_context", "obo_context", "auth_context", "engine_credential",
              "invocation_grant", "release_authorization", "scope_ceiling"}) {
            auto wire = base_result_wire(false);
            wire["future"][field] = "attacker-authored";
            const auto decoded = contracts::decode_b4_fact_response(wire.dump());
            CAPTURE(field);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
            CHECK(decoded.error().path == "/future/" + std::string{field});
        }
    }

    SECTION("provenance cannot carry transport authority") {
        auto wire = base_result_wire(false);
        wire["provenance"]["nested"]["representedoperatorclaim"] = "operator-7";
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
        CHECK(decoded.error().path == "/provenance/nested/representedoperatorclaim");
    }

    SECTION("known control objects cannot hide authority extensions") {
        auto contract = base_result_wire(false);
        contract["contract"]["future"]["on_behalf_of"] = "operator-7";
        const auto contract_result = contracts::decode_b4_fact_response(contract.dump());
        REQUIRE_FALSE(contract_result.has_value());
        CHECK(contract_result.error().path == "/contract/future/on_behalf_of");

        auto module = base_result_wire(false);
        module["module"]["future"]["engine_credential"] = "transport-secret";
        const auto module_result = contracts::decode_b4_fact_response(module.dump());
        REQUIRE_FALSE(module_result.has_value());
        CHECK(module_result.error().path == "/module/future/engine_credential");

        auto coverage = base_result_wire();
        coverage["coverage"]["future"]["scope_ceiling"] = "fleet";
        const auto coverage_result = contracts::decode_b4_fact_response(coverage.dump());
        REQUIRE_FALSE(coverage_result.has_value());
        CHECK(coverage_result.error().path == "/coverage/future/scope_ceiling");
    }

    SECTION("facts preserve ordinary domain identity fields") {
        auto wire = base_result_wire(false);
        wire["facts"] = nlohmann::json::array({{{"actor", "package-installer"},
                                                {"identity", "CN=device"},
                                                {"subject", "certificate"},
                                                {"user", "local-account"},
                                                {"global_total", 1},
                                                {"matched", true}}});
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE(decoded.has_value());
        REQUIRE(std::holds_alternative<contracts::B4FactResult>(*decoded));
        CHECK(std::get<contracts::B4FactResult>(*decoded).facts == wire["facts"]);
    }

    SECTION("facts cannot masquerade transport authentication as domain data") {
        auto wire = base_result_wire(false);
        wire["facts"][0]["engine_credential"] = "transport-secret";
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
        CHECK(decoded.error().path == "/facts/0/engine_credential");
    }

    SECTION("control envelope exposes no matched or withheld oracle") {
        for (const std::string_view field :
             {"matched", "matched_count", "withheld", "withheld_count", "withheld_exists",
              "truncated", "was_truncated", "removed_count", "out_of_scope_count", "global_total",
              "fleet_total", "fleet_size", "unfiltered_count", "requested_before_confinement"}) {
            auto wire = base_result_wire(false);
            wire["future"][field] = 0;
            const auto decoded = contracts::decode_b4_fact_response(wire.dump());
            CAPTURE(field);
            REQUIRE_FALSE(decoded.has_value());
            CHECK(decoded.error().code == contracts::ContractErrorCode::InvalidValue);
            CHECK(decoded.error().path == "/future/" + std::string{field});
        }
    }

    SECTION("A4 details cannot echo transport authentication or an oracle") {
        auto wire = nlohmann::json::parse(
            R"({"error":{"code":503,"correlation_id":"req-contract-0001","message":"unavailable","retry_after_ms":null},"meta":{"api_version":"v1"}})");
        wire["error"]["details"]["engine_credential"] = "transport-secret";
        const auto credential = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(credential.has_value());
        CHECK(credential.error().path == "/error/details/engine_credential");

        wire["error"]["details"].erase("engine_credential");
        wire["error"]["details"]["withheld_count"] = 1;
        const auto oracle = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(oracle.has_value());
        CHECK(oracle.error().path == "/error/details/withheld_count");

        wire["error"]["details"].erase("withheld_count");
        wire["error"]["details"]["global_total"] = 500;
        const auto global_oracle = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(global_oracle.has_value());
        CHECK(global_oracle.error().path == "/error/details/global_total");
    }

    SECTION("A4 is control-only even when a field is ordinary inside facts") {
        auto wire = nlohmann::json::parse(
            R"({"error":{"code":503,"correlation_id":"req-contract-0001","message":"unavailable","retry_after_ms":null},"meta":{"api_version":"v1"}})");
        wire["error"]["details"]["actor"] = "domain-shaped-but-control";
        const auto decoded = contracts::decode_b4_fact_response(wire.dump());
        REQUIRE_FALSE(decoded.has_value());
        CHECK(decoded.error().code == contracts::ContractErrorCode::ForbiddenAuthorityField);
        CHECK(decoded.error().path == "/error/details/actor");
    }
}

TEST_CASE("ADR-0031 B4 fact result preserves safe additive fields deterministically",
          "[adr31][contract][b4][fact][result][compatibility]") {
    auto first = make_result();
    first.extensions["z_hint"] = 7;
    first.extensions["a_hint"] = true;
    first.provenance = nlohmann::json::object();
    first.provenance["source"] = "inventory-store";
    first.provenance["journal_id"] = "core-fact-journal-0001";

    auto second = make_result();
    second.extensions["a_hint"] = true;
    second.extensions["z_hint"] = 7;

    const auto first_encoded = contracts::encode_b4_fact_response(contracts::B4FactResponse{first});
    const auto second_encoded =
        contracts::encode_b4_fact_response(contracts::B4FactResponse{second});
    REQUIRE(first_encoded.has_value());
    REQUIRE(second_encoded.has_value());
    CHECK(*first_encoded == *second_encoded);

    const auto decoded = contracts::decode_b4_fact_response(*first_encoded);
    REQUIRE(decoded.has_value());
    REQUIRE(std::holds_alternative<contracts::B4FactResult>(*decoded));
    CHECK(std::get<contracts::B4FactResult>(*decoded).extensions == first.extensions);
}

TEST_CASE("ADR-0031 B4 fact result rejects invalid in-memory extension collisions",
          "[adr31][contract][b4][fact][result][negative]") {
    for (const std::string_view field : {"facts", "error"}) {
        auto result = make_result(false);
        result.extensions[field] = nlohmann::json::object();
        const auto encoded =
            contracts::encode_b4_fact_response(contracts::B4FactResponse{std::move(result)});
        CAPTURE(field);
        REQUIRE_FALSE(encoded.has_value());
        CHECK(encoded.error().code == contracts::ContractErrorCode::InvalidValue);
        CHECK(encoded.error().path == "/" + std::string{field});
    }
}

TEST_CASE("ADR-0031 B4 fact error validity precedes exchange correlation",
          "[adr31][contract][b4][fact][result][a4][security]") {
    auto invalid = make_a4_error(403);
    invalid.code = 404;
    invalid.correlation_id = "req-contract-0002";
    const auto checked = contracts::validate_b4_fact_exchange(
        make_request(), contracts::B4FactResponse{std::move(invalid)});
    REQUIRE_FALSE(checked.has_value());
    CHECK(checked.error().path == "/error/permission");
}
