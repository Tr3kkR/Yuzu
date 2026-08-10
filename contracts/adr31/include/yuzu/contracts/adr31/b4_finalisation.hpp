#pragma once

#include "b2_use_case.hpp"
#include "contract_error.hpp"
#include "rest_a4_error.hpp"
#include "transport_auth_slot.hpp"
#include "use_case_types.hpp"

#include <nlohmann/json.hpp>

#include <concepts>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace yuzu::contracts::adr31 {

/// Complete set of Core-issued fact-read references disclosed by the run.
/// Presence is required on the wire; an empty set is valid for a pure-input
/// result. Core remains responsible for comparing it with the run release log.
struct B4DisclosureSummary {
    std::vector<std::string> fact_refs;
    nlohmann::json extensions = nlohmann::json::object();

    friend bool operator==(const B4DisclosureSummary&, const B4DisclosureSummary&) = default;
};

/// Outbound-only finalisation material. Identity and hash-bearing fields are
/// deliberately absent: make_b4_finalisation_call derives them from the B2
/// request and exact pre-receipt B2 result supplied by the engine.
struct B4FinalisationDraft {
    std::string correlation_id;
    std::string module_manifest_hash;
    std::string result_schema_version;
    B4DisclosureSummary disclosure_summary;
    nlohmann::json extensions = nlohmann::json::object();
};

/// Decoded B4 finalisation request. Every value is an untrusted wire claim at
/// the Core provider edge even when an outbound factory produced it.
struct B4FinalisationRequest {
    std::string correlation_id;
    std::string use_case_run_id;
    VersionedIdentity use_case;
    VersionedIdentity module;
    std::string module_manifest_hash;
    std::string result_schema_version;
    std::string result_hash;
    B4DisclosureSummary disclosure_summary;
    CoverageEnvelope coverage;
    nlohmann::json provenance;
    nlohmann::json extensions = nlohmann::json::object();

    friend bool operator==(const B4FinalisationRequest&, const B4FinalisationRequest&) = default;
};

enum class B4FinalisationBindingError : std::uint8_t {
    MissingEngineCredential,
    WrongEngineCredentialKind,
    MissingReleaseAuthorization,
    InvalidReleaseAuthorization,
    WrongReleaseAuthorizationKind,
    UnexpectedReleaseAuthorization,
    /// The process-local move-only carrier has already been consumed. Core's
    /// durable state machine, not this value, enforces protocol one-use.
    Consumed,
};

using B4FinalisationCallError = std::variant<ContractError, B4FinalisationBindingError>;
using B4FinalisationReplyError = std::variant<ContractError, B4FinalisationBindingError>;
using B4FinalisationExchangeError = std::variant<ContractError, B4FinalisationBindingError>;

class B4FinalisationRequestBodyView final {
public:
    [[nodiscard]] std::string_view bytes() const noexcept { return bytes_; }

private:
    explicit B4FinalisationRequestBodyView(std::string_view bytes) noexcept : bytes_(bytes) {}

    std::string_view bytes_;

    friend class B4FinalisationTransportInputs;
};

class B4FinalisationEngineCredentialView final {
public:
    [[nodiscard]] std::string_view bytes() const noexcept { return bytes_; }

private:
    explicit B4FinalisationEngineCredentialView(std::string_view bytes) noexcept : bytes_(bytes) {}

    std::string_view bytes_;

    friend class B4FinalisationTransportInputs;
};

/// Callback-scoped inputs for one authenticated B4 finalisation request.
class B4FinalisationTransportInputs final {
public:
    B4FinalisationTransportInputs(const B4FinalisationTransportInputs&) = delete;
    B4FinalisationTransportInputs& operator=(const B4FinalisationTransportInputs&) = delete;
    B4FinalisationTransportInputs(B4FinalisationTransportInputs&&) = delete;
    B4FinalisationTransportInputs& operator=(B4FinalisationTransportInputs&&) = delete;

    [[nodiscard]] B4FinalisationRequestBodyView body() const noexcept {
        return B4FinalisationRequestBodyView{body_};
    }
    [[nodiscard]] B4FinalisationEngineCredentialView engine_credential() const noexcept {
        return B4FinalisationEngineCredentialView{engine_credential_};
    }

private:
    B4FinalisationTransportInputs(std::string_view body,
                                  std::string_view engine_credential) noexcept
        : body_(body), engine_credential_(engine_credential) {}

    std::string_view body_;
    std::string_view engine_credential_;

    friend class B4FinalisationCall;
};

/// Move-only request carrier. The engine credential is never part of the JSON
/// document and is synchronously visible only while an adapter copies it.
class B4FinalisationCall final {
public:
    B4FinalisationCall(const B4FinalisationCall&) = delete;
    B4FinalisationCall& operator=(const B4FinalisationCall&) = delete;
    B4FinalisationCall(B4FinalisationCall&&) noexcept = default;
    B4FinalisationCall& operator=(B4FinalisationCall&&) = delete;

    template <typename Sink>
        requires std::invocable<Sink&&, const B4FinalisationTransportInputs&> &&
                 std::same_as<std::invoke_result_t<Sink&&, const B4FinalisationTransportInputs&>,
                              void>
    [[nodiscard]] std::expected<void, B4FinalisationCallError> apply_to_transport(Sink&& sink) && {
        if (!engine_credential_.valid()) {
            return std::unexpected(B4FinalisationCallError{B4FinalisationBindingError::Consumed});
        }

        auto engine_credential = std::move(engine_credential_);
        auto body = std::move(body_);
        const bool visited = engine_credential.visit_secret([&](std::string_view secret) {
            const B4FinalisationTransportInputs inputs{std::string_view{body}, secret};
            std::invoke(std::forward<Sink>(sink), inputs);
        });
        if (!visited) {
            return std::unexpected(B4FinalisationCallError{B4FinalisationBindingError::Consumed});
        }
        return {};
    }

private:
    B4FinalisationCall(std::string body, TransportAuthSlot engine_credential) noexcept;

    std::string body_;
    TransportAuthSlot engine_credential_;

    friend std::expected<B4FinalisationCall, B4FinalisationCallError> make_b4_finalisation_call(
        B4FinalisationDraft draft, const B2UseCaseRequest& received_b2_request,
        const B2UseCaseResultPayload& result, TransportAuthSlot engine_credential);
};

struct B4FinalisationResult {
    std::string correlation_id;
    std::string use_case_run_id;
    VersionedIdentity use_case;
    VersionedIdentity module;
    std::string module_manifest_hash;
    std::string result_schema_version;
    std::string result_hash;
    CoverageEnvelope coverage;
    std::string journal_id;
    /// Opaque public integrity evidence. It is not authority to release data.
    std::string finalisation_receipt;
    nlohmann::json extensions = nlohmann::json::object();

    friend bool operator==(const B4FinalisationResult&, const B4FinalisationResult&) = default;
};

using B4FinalisationResponse = std::variant<B4FinalisationResult, A4ErrorEnvelope>;

class B4FinalisationResponseBodyView final {
public:
    [[nodiscard]] std::string_view bytes() const noexcept { return bytes_; }

private:
    explicit B4FinalisationResponseBodyView(std::string_view bytes) noexcept : bytes_(bytes) {}

    std::string_view bytes_;

    friend class B4FinalisationReplyInputs;
};

class B4ReleaseAuthorizationView final {
public:
    [[nodiscard]] std::string_view bytes() const noexcept { return bytes_; }

private:
    explicit B4ReleaseAuthorizationView(std::string_view bytes) noexcept : bytes_(bytes) {}

    std::string_view bytes_;

    friend class B4FinalisationReplyInputs;
};

/// Callback-scoped provider response. A success always has a release
/// authorization; an A4 failure never does. The optional form exists only so
/// one transport adapter can handle both validated arms.
class B4FinalisationReplyInputs final {
public:
    B4FinalisationReplyInputs(const B4FinalisationReplyInputs&) = delete;
    B4FinalisationReplyInputs& operator=(const B4FinalisationReplyInputs&) = delete;
    B4FinalisationReplyInputs(B4FinalisationReplyInputs&&) = delete;
    B4FinalisationReplyInputs& operator=(B4FinalisationReplyInputs&&) = delete;

    [[nodiscard]] B4FinalisationResponseBodyView body() const noexcept {
        return B4FinalisationResponseBodyView{body_};
    }
    [[nodiscard]] std::optional<B4ReleaseAuthorizationView> release_authorization() const noexcept {
        if (!release_authorization_)
            return std::nullopt;
        return B4ReleaseAuthorizationView{*release_authorization_};
    }

private:
    B4FinalisationReplyInputs(std::string_view body,
                              std::optional<std::string_view> release_authorization) noexcept
        : body_(body), release_authorization_(release_authorization) {}

    std::string_view body_;
    std::optional<std::string_view> release_authorization_;

    friend class B4FinalisationReply;
};

/// Provider-side move-only response carrier. Creating it enforces the
/// success/authorization and A4/no-authorization pairing before an adapter can
/// write either value to a framework response.
class B4FinalisationReply final {
public:
    B4FinalisationReply(const B4FinalisationReply&) = delete;
    B4FinalisationReply& operator=(const B4FinalisationReply&) = delete;
    B4FinalisationReply(B4FinalisationReply&& other) noexcept
        : body_(std::move(other.body_)),
          release_authorization_(std::move(other.release_authorization_)),
          consumed_(std::exchange(other.consumed_, true)) {}
    B4FinalisationReply& operator=(B4FinalisationReply&&) = delete;

    template <typename Sink>
        requires std::invocable<Sink&&, const B4FinalisationReplyInputs&> &&
                 std::same_as<std::invoke_result_t<Sink&&, const B4FinalisationReplyInputs&>, void>
    [[nodiscard]] std::expected<void, B4FinalisationReplyError> apply_to_transport(Sink&& sink) && {
        if (std::exchange(consumed_, true)) {
            return std::unexpected(B4FinalisationReplyError{B4FinalisationBindingError::Consumed});
        }
        if (release_authorization_ && !release_authorization_->valid()) {
            return std::unexpected(B4FinalisationReplyError{B4FinalisationBindingError::Consumed});
        }

        auto release_authorization = std::move(release_authorization_);
        auto body = std::move(body_);
        if (!release_authorization) {
            const B4FinalisationReplyInputs inputs{std::string_view{body}, std::nullopt};
            std::invoke(std::forward<Sink>(sink), inputs);
            return {};
        }

        const bool visited = release_authorization->visit_secret([&](std::string_view secret) {
            const B4FinalisationReplyInputs inputs{std::string_view{body}, secret};
            std::invoke(std::forward<Sink>(sink), inputs);
        });
        if (!visited) {
            return std::unexpected(B4FinalisationReplyError{B4FinalisationBindingError::Consumed});
        }
        return {};
    }

private:
    B4FinalisationReply(std::string body,
                        std::optional<TransportAuthSlot> release_authorization) noexcept;

    std::string body_;
    std::optional<TransportAuthSlot> release_authorization_;
    bool consumed_ = false;

    friend std::expected<B4FinalisationReply, B4FinalisationReplyError>
    make_b4_finalisation_reply(B4FinalisationResponse response,
                               std::optional<TransportAuthSlot> release_authorization);
};

/// Consumer-side successful finalisation. Receipt evidence is inspectable;
/// release authority has no getter and can only be moved into the redemption
/// carrier added by the next B4 contract checkpoint.
class B4PendingRelease final {
public:
    B4PendingRelease(const B4PendingRelease&) = delete;
    B4PendingRelease& operator=(const B4PendingRelease&) = delete;
    B4PendingRelease(B4PendingRelease&&) noexcept = default;
    B4PendingRelease& operator=(B4PendingRelease&&) = delete;

    [[nodiscard]] const B4FinalisationResult& receipt() const noexcept { return receipt_; }

private:
    B4PendingRelease(std::string request_id, B2UseCaseResultPayload result,
                     B4FinalisationResult receipt,
                     TransportAuthSlot release_authorization) noexcept;

    std::string request_id_;
    B2UseCaseResultPayload result_;
    B4FinalisationResult receipt_;
    TransportAuthSlot release_authorization_;

    friend std::expected<std::variant<B4PendingRelease, A4ErrorEnvelope>,
                         B4FinalisationExchangeError>
    bind_b4_finalisation_exchange(const B4FinalisationRequest& request,
                                  const B2UseCaseRequest& received_b2_request,
                                  const B2UseCaseResultPayload& result,
                                  B4FinalisationResponse response,
                                  std::optional<TransportAuthSlot> release_authorization);
};

using B4BoundFinalisation = std::variant<B4PendingRelease, A4ErrorEnvelope>;

[[nodiscard]] std::expected<B4FinalisationCall, B4FinalisationCallError>
make_b4_finalisation_call(B4FinalisationDraft draft, const B2UseCaseRequest& received_b2_request,
                          const B2UseCaseResultPayload& result,
                          TransportAuthSlot engine_credential);

[[nodiscard]] std::expected<B4FinalisationRequest, ContractError>
decode_b4_finalisation_request(std::string_view wire_json);

/// Raw JSON codec for conformance fixtures. Providers should normally use
/// make_b4_finalisation_reply(), which additionally enforces the transport-only
/// release-authorization pairing.
[[nodiscard]] std::expected<std::string, ContractError>
encode_b4_finalisation_response(const B4FinalisationResponse& response);

[[nodiscard]] std::expected<B4FinalisationResponse, ContractError>
decode_b4_finalisation_response(std::string_view wire_json);

[[nodiscard]] std::expected<B4FinalisationReply, B4FinalisationReplyError>
make_b4_finalisation_reply(B4FinalisationResponse response,
                           std::optional<TransportAuthSlot> release_authorization = std::nullopt);

/// Checks every public request/result binding. This proves correlation and
/// integrity-shape agreement only; Core authentication, current authority,
/// exact release-log evidence and durable grant state remain authoritative.
[[nodiscard]] std::expected<void, ContractError>
validate_b4_finalisation_exchange(const B4FinalisationRequest& request,
                                  const B4FinalisationResponse& response);

/// Adds the transport-only release lease to a validated response. A success
/// requires exactly one ReleaseAuthorization; an A4 failure forbids one.
[[nodiscard]] std::expected<B4BoundFinalisation, B4FinalisationExchangeError>
bind_b4_finalisation_exchange(
    const B4FinalisationRequest& request, const B2UseCaseRequest& received_b2_request,
    const B2UseCaseResultPayload& result, B4FinalisationResponse response,
    std::optional<TransportAuthSlot> release_authorization = std::nullopt);

static_assert(!std::is_copy_constructible_v<B4FinalisationCall>);
static_assert(!std::is_copy_constructible_v<B4FinalisationReply>);
static_assert(!std::is_copy_constructible_v<B4PendingRelease>);
static_assert(std::is_nothrow_move_constructible_v<B4FinalisationCall>);
static_assert(std::is_nothrow_move_constructible_v<B4FinalisationReply>);
static_assert(std::is_nothrow_move_constructible_v<B4PendingRelease>);

} // namespace yuzu::contracts::adr31
