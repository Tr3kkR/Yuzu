#pragma once

#include "b2_use_case.hpp"
#include "contract_error.hpp"
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

namespace yuzu::contracts::adr31 {

struct B4FactRequest {
    std::string correlation_id;
    std::string use_case_run_id;
    VersionedIdentity module;
    std::string module_manifest_hash;
    VersionedIdentity capability;
    /// Untrusted wire claim decoded by Core. Outbound callers leave this
    /// empty: make_b4_fact_call derives it from the actual received B2 request
    /// carried by B4FactInvocationStart.
    std::optional<std::string> input_hash = std::nullopt;
    nlohmann::json parameters;
    nlohmann::json scope;
};

struct B4FactInvocationStart {
    B2UseCaseRequest received_b2_request;
    TransportAuthSlot invocation_grant;
};

/// Engine credentials authenticate every B4 call. Invocation start material
/// is present only for the first admitted-to-executing transition. The factory
/// derives the input hash from the same B2 request and carries the grant beside
/// the JSON. It is a start ticket, never authority over data.
struct B4FactTransportAuth {
    TransportAuthSlot engine_credential;
    std::optional<B4FactInvocationStart> invocation_start = std::nullopt;
};

enum class B4FactAuthBindingError : std::uint8_t {
    MissingEngineCredential,
    WrongEngineCredentialKind,
    InvalidInvocationGrant,
    WrongInvocationGrantKind,
    CallerAuthoredInputHash,
    StartRunMismatch,
    StartModuleMismatch,
    /// The local move-only lease was already consumed. Core's guarded run
    /// transition, not this process-local state, enforces protocol one-use.
    Consumed,
};

using B4FactCallError = std::variant<ContractError, B4FactAuthBindingError>;

class B4FactRequestBodyView final {
public:
    [[nodiscard]] std::string_view bytes() const noexcept { return bytes_; }

private:
    explicit B4FactRequestBodyView(std::string_view bytes) noexcept : bytes_(bytes) {}

    std::string_view bytes_;

    friend class B4FactTransportInputs;
};

class B4EngineCredentialView final {
public:
    [[nodiscard]] std::string_view bytes() const noexcept { return bytes_; }

private:
    explicit B4EngineCredentialView(std::string_view bytes) noexcept : bytes_(bytes) {}

    std::string_view bytes_;

    friend class B4FactTransportInputs;
};

class B4InvocationGrantView final {
public:
    [[nodiscard]] std::string_view bytes() const noexcept { return bytes_; }

private:
    explicit B4InvocationGrantView(std::string_view bytes) noexcept : bytes_(bytes) {}

    std::string_view bytes_;

    friend class B4FactTransportInputs;
};

/// Callback-scoped material for one B4 fact request. Adapters copy these
/// branded views into a framework-owned request before returning.
class B4FactTransportInputs final {
public:
    B4FactTransportInputs(const B4FactTransportInputs&) = delete;
    B4FactTransportInputs& operator=(const B4FactTransportInputs&) = delete;
    B4FactTransportInputs(B4FactTransportInputs&&) = delete;
    B4FactTransportInputs& operator=(B4FactTransportInputs&&) = delete;

    [[nodiscard]] B4FactRequestBodyView body() const noexcept {
        return B4FactRequestBodyView{body_};
    }
    [[nodiscard]] B4EngineCredentialView engine_credential() const noexcept {
        return B4EngineCredentialView{engine_credential_};
    }
    [[nodiscard]] std::optional<B4InvocationGrantView> invocation_grant() const noexcept {
        if (!invocation_grant_)
            return std::nullopt;
        return B4InvocationGrantView{*invocation_grant_};
    }

private:
    B4FactTransportInputs(std::string_view body, std::string_view engine_credential,
                          std::optional<std::string_view> invocation_grant) noexcept
        : body_(body), engine_credential_(engine_credential), invocation_grant_(invocation_grant) {}

    std::string_view body_;
    std::string_view engine_credential_;
    std::optional<std::string_view> invocation_grant_;

    friend class B4FactCall;
};

class B4FactCall final {
public:
    B4FactCall(const B4FactCall&) = delete;
    B4FactCall& operator=(const B4FactCall&) = delete;
    B4FactCall(B4FactCall&&) noexcept = default;
    B4FactCall& operator=(B4FactCall&&) = delete;

    template <typename Sink>
        requires std::invocable<Sink&&, const B4FactTransportInputs&> &&
                 std::same_as<std::invoke_result_t<Sink&&, const B4FactTransportInputs&>, void>
    [[nodiscard]] std::expected<void, B4FactCallError> apply_to_transport(Sink&& sink) && {
        if (!engine_credential_.valid() || (invocation_grant_ && !invocation_grant_->valid())) {
            return std::unexpected(B4FactCallError{B4FactAuthBindingError::Consumed});
        }

        auto engine_credential = std::move(engine_credential_);
        auto invocation_grant = std::move(invocation_grant_);
        auto body = std::move(body_);

        bool grant_visited = true;
        const bool engine_visited =
            engine_credential.visit_secret([&](std::string_view engine_secret) {
                if (invocation_grant) {
                    grant_visited =
                        invocation_grant->visit_secret([&](std::string_view grant_secret) {
                            const B4FactTransportInputs inputs{std::string_view{body},
                                                               engine_secret, grant_secret};
                            std::invoke(std::forward<Sink>(sink), inputs);
                        });
                    return;
                }
                const B4FactTransportInputs inputs{std::string_view{body}, engine_secret,
                                                   std::nullopt};
                std::invoke(std::forward<Sink>(sink), inputs);
            });
        if (!engine_visited || !grant_visited) {
            return std::unexpected(B4FactCallError{B4FactAuthBindingError::Consumed});
        }
        return {};
    }

private:
    B4FactCall(std::string body, B4FactTransportAuth authentication) noexcept;

    std::string body_;
    TransportAuthSlot engine_credential_;
    std::optional<TransportAuthSlot> invocation_grant_;

    friend std::expected<B4FactCall, B4FactCallError>
    make_b4_fact_call(B4FactRequest request, B4FactTransportAuth authentication);
};

[[nodiscard]] std::expected<B4FactRequest, ContractError>
decode_b4_fact_request(std::string_view wire_json);

[[nodiscard]] std::expected<B4FactCall, B4FactCallError>
make_b4_fact_call(B4FactRequest request, B4FactTransportAuth authentication);

} // namespace yuzu::contracts::adr31
