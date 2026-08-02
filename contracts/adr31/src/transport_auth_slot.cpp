#include <yuzu/contracts/adr31/transport_auth_slot.hpp>

#include <yuzu/secure_zero.hpp>

#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::contracts::adr31 {
namespace {

[[nodiscard]] constexpr std::string_view redacted_label(TransportAuthKind kind) noexcept {
    switch (kind) {
    case TransportAuthKind::CallerCredential: return "<redacted:caller-credential>";
    case TransportAuthKind::InvocationGrant: return "<redacted:invocation-grant>";
    case TransportAuthKind::EngineCredential: return "<redacted:engine-credential>";
    case TransportAuthKind::ReleaseAuthorization: return "<redacted:release-authorization>";
    }
    return "<redacted:unknown>";
}

class SourceScrub {
  public:
    explicit SourceScrub(std::string& source) noexcept : source_(source) {}
    ~SourceScrub() { yuzu::secure_zero(source_); }

    SourceScrub(const SourceScrub&) = delete;
    SourceScrub& operator=(const SourceScrub&) = delete;

  private:
    std::string& source_;
};

} // namespace

struct TransportAuthSlot::SecretState {
    TransportAuthKind kind;
    std::string secret;

    SecretState(TransportAuthKind kind_value, const std::string& secret_value)
        : kind(kind_value), secret(secret_value) {}

    ~SecretState() { yuzu::secure_zero(secret); }
};

TransportAuthSlot::TransportAuthSlot(std::unique_ptr<SecretState> state) noexcept
    : state_(std::move(state)) {}

TransportAuthSlot::~TransportAuthSlot() = default;
TransportAuthSlot::TransportAuthSlot(TransportAuthSlot&&) noexcept = default;
TransportAuthSlot& TransportAuthSlot::operator=(TransportAuthSlot&&) noexcept = default;

bool TransportAuthSlot::valid() const noexcept { return state_ && !state_->secret.empty(); }

std::optional<TransportAuthKind> TransportAuthSlot::kind() const noexcept {
    if (!state_) return std::nullopt;
    return state_->kind;
}

std::optional<std::string_view> TransportAuthSlot::secret_view() const noexcept {
    if (!valid()) return std::nullopt;
    return std::string_view{state_->secret};
}

std::ostream& operator<<(std::ostream& output, const TransportAuthSlot& slot) {
    if (const auto kind = slot.kind()) return output << redacted_label(*kind);
    return output << "<redacted:empty>";
}

std::expected<TransportAuthSlot, TransportAuthError>
make_transport_auth_slot(TransportAuthKind kind, std::string secret) {
    SourceScrub scrub{secret};
    if (secret.empty()) return std::unexpected(TransportAuthError::Empty);
    if (secret.size() > kMaxTransportAuthBytes) {
        return std::unexpected(TransportAuthError::TooLarge);
    }
    for (const unsigned char byte : secret) {
        if (byte < 0x20 || byte == 0x7f) {
            return std::unexpected(TransportAuthError::InvalidCharacter);
        }
    }

    return TransportAuthSlot{std::make_unique<TransportAuthSlot::SecretState>(kind, secret)};
}

} // namespace yuzu::contracts::adr31
