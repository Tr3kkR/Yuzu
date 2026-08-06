#include <yuzu/contracts/adr31/b4_fact.hpp>
#include <yuzu/contracts/adr31/contract_limits.hpp>
#include <yuzu/contracts/adr31/contract_version.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <expected>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

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
