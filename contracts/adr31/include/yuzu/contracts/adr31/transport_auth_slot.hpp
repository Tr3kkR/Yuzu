#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace yuzu::contracts::adr31 {

inline constexpr std::size_t kMaxTransportAuthBytes = 16 * 1024;

enum class TransportAuthKind : std::uint8_t {
    CallerCredential,
    InvocationGrant,
    EngineCredential,
    ReleaseAuthorization,
};

enum class TransportAuthError : std::uint8_t {
    Empty,
    TooLarge,
    InvalidCharacter,
};

/// Move-only ownership lease for authentication material carried beside a
/// JSON contract. The value has no JSON conversion and always renders as a
/// redacted label. Adapters may inspect it only inside a synchronous callback;
/// the callback must copy it into the transport before returning.
class TransportAuthSlot {
  public:
    ~TransportAuthSlot();

    TransportAuthSlot(const TransportAuthSlot&) = delete;
    TransportAuthSlot& operator=(const TransportAuthSlot&) = delete;
    TransportAuthSlot(TransportAuthSlot&&) noexcept;
    TransportAuthSlot& operator=(TransportAuthSlot&&) noexcept;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] std::optional<TransportAuthKind> kind() const noexcept;

    template <typename Visitor>
        requires std::invocable<Visitor&&, std::string_view> &&
                 std::same_as<std::invoke_result_t<Visitor&&, std::string_view>, void>
    [[nodiscard]] bool visit_secret(Visitor&& visitor) const& {
        const auto secret = secret_view();
        if (!secret) return false;
        std::invoke(std::forward<Visitor>(visitor), *secret);
        return true;
    }

    template <typename Visitor>
    bool visit_secret(Visitor&&) const&& = delete;

    friend std::ostream& operator<<(std::ostream& output, const TransportAuthSlot& slot);

  private:
    struct SecretState;

    explicit TransportAuthSlot(std::unique_ptr<SecretState> state) noexcept;
    [[nodiscard]] std::optional<std::string_view> secret_view() const noexcept;

    std::unique_ptr<SecretState> state_;

    friend std::expected<TransportAuthSlot, TransportAuthError>
    make_transport_auth_slot(TransportAuthKind kind, std::string secret);
};

[[nodiscard]] std::expected<TransportAuthSlot, TransportAuthError>
make_transport_auth_slot(TransportAuthKind kind, std::string secret);

static_assert(!std::is_copy_constructible_v<TransportAuthSlot>);
static_assert(!std::is_copy_assignable_v<TransportAuthSlot>);
static_assert(std::is_nothrow_move_constructible_v<TransportAuthSlot>);
static_assert(std::is_nothrow_move_assignable_v<TransportAuthSlot>);

} // namespace yuzu::contracts::adr31
