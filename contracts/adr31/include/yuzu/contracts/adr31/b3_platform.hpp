#pragma once

#include "contract_error.hpp"
#include "rest_a4_error.hpp"
#include "transport_auth_slot.hpp"

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

enum class CoreOperation : std::uint8_t {
    Read,
    Write,
    Execute,
    Delete,
    Approve,
    Push,
};

[[nodiscard]] constexpr std::string_view to_string(CoreOperation operation) noexcept {
    switch (operation) {
    case CoreOperation::Read: return "Read";
    case CoreOperation::Write: return "Write";
    case CoreOperation::Execute: return "Execute";
    case CoreOperation::Delete: return "Delete";
    case CoreOperation::Approve: return "Approve";
    case CoreOperation::Push: return "Push";
    }
    return {};
}

struct B3PlatformRequest {
    std::string correlation_id;
    std::string securable;
    CoreOperation operation;
    nlohmann::json scope;
};

enum class B3AuthBindingError : std::uint8_t {
    MissingAuthentication,
    WrongAuthenticationKind,
    Consumed,
};

using B3PlatformCallError = std::variant<ContractError, B3AuthBindingError>;

class B3RequestBodyView final {
  public:
    [[nodiscard]] std::string_view bytes() const noexcept { return bytes_; }

  private:
    explicit B3RequestBodyView(std::string_view bytes) noexcept : bytes_(bytes) {}

    std::string_view bytes_;

    friend class B3TransportInputs;
};

class B3CallerCredentialView final {
  public:
    [[nodiscard]] std::string_view bytes() const noexcept { return bytes_; }

  private:
    explicit B3CallerCredentialView(std::string_view bytes) noexcept : bytes_(bytes) {}

    std::string_view bytes_;

    friend class B3TransportInputs;
};

/// Ephemeral, named inputs for one B3 transport dispatch. The object cannot be
/// copied or moved; it and both branded views expire when apply_to_transport
/// returns.
class B3TransportInputs final {
  public:
    B3TransportInputs(const B3TransportInputs&) = delete;
    B3TransportInputs& operator=(const B3TransportInputs&) = delete;
    B3TransportInputs(B3TransportInputs&&) = delete;
    B3TransportInputs& operator=(B3TransportInputs&&) = delete;

    [[nodiscard]] B3RequestBodyView body() const noexcept { return B3RequestBodyView{body_}; }
    [[nodiscard]] B3CallerCredentialView caller_credential() const noexcept {
        return B3CallerCredentialView{caller_credential_};
    }

  private:
    B3TransportInputs(std::string_view body, std::string_view caller_credential) noexcept
        : body_(body), caller_credential_(caller_credential) {}

    std::string_view body_;
    std::string_view caller_credential_;

    friend class B3PlatformCall;
};

/// Move-only carrier consumed by a B3 adapter. Authentication remains beside
/// the JSON request and can only be inspected through TransportAuthSlot's
/// callback-scoped lease.
class B3PlatformCall final {
  public:
    B3PlatformCall(const B3PlatformCall&) = delete;
    B3PlatformCall& operator=(const B3PlatformCall&) = delete;
    B3PlatformCall(B3PlatformCall&&) noexcept = default;
    B3PlatformCall& operator=(B3PlatformCall&&) = delete;

    /// Synchronously copies both values into a framework-owned request. Views
    /// expire when the callback returns; async code must retain only its own
    /// copies. The carrier is consumed before the callback is invoked.
    template <typename Sink>
        requires std::invocable<Sink&&, const B3TransportInputs&> &&
                 std::same_as<std::invoke_result_t<Sink&&, const B3TransportInputs&>, void>
    [[nodiscard]] std::expected<void, B3PlatformCallError> apply_to_transport(Sink&& sink) && {
        if (!authentication_.valid()) {
            return std::unexpected(B3PlatformCallError{B3AuthBindingError::Consumed});
        }

        auto authentication = std::move(authentication_);
        auto body = std::move(body_);
        const bool visited = authentication.visit_secret([&](std::string_view secret) {
            const B3TransportInputs inputs{std::string_view{body}, secret};
            std::invoke(std::forward<Sink>(sink), inputs);
        });
        if (!visited) {
            return std::unexpected(B3PlatformCallError{B3AuthBindingError::Consumed});
        }
        return {};
    }

  private:
    B3PlatformCall(std::string body, TransportAuthSlot authentication) noexcept;

    std::string body_;
    TransportAuthSlot authentication_;

    friend std::expected<B3PlatformCall, B3PlatformCallError>
    make_b3_platform_call(B3PlatformRequest request, TransportAuthSlot authentication);
};

struct B3PlatformResult {
    std::string correlation_id;
    nlohmann::json data;

    friend bool operator==(const B3PlatformResult&, const B3PlatformResult&) = default;
};

using B3PlatformResponse = std::variant<B3PlatformResult, A4ErrorEnvelope>;

[[nodiscard]] std::expected<B3PlatformRequest, ContractError>
decode_b3_platform_request(std::string_view wire_json);

[[nodiscard]] std::expected<B3PlatformCall, B3PlatformCallError>
make_b3_platform_call(B3PlatformRequest request, TransportAuthSlot authentication);

// The failure arm carries the established A4 members and semantics. Object
// members use this package's deterministic sorted JSON order; legacy REST
// builder byte order is not part of the JSON contract.
[[nodiscard]] std::expected<std::string, ContractError>
encode_b3_platform_response(const B3PlatformResponse& response);

[[nodiscard]] std::expected<B3PlatformResponse, ContractError>
decode_b3_platform_response(std::string_view wire_json);

/// Consumer-side binding check. Correlation is diagnostic rather than
/// authority, but a mismatched response must never be delivered to a caller.
[[nodiscard]] std::expected<void, ContractError>
validate_b3_platform_exchange(const B3PlatformRequest& request,
                              const B3PlatformResponse& response);

} // namespace yuzu::contracts::adr31
