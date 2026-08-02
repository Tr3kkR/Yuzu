#include "json_support.hpp"

#include <yuzu/contracts/adr31/contract_limits.hpp>

#include <nlohmann/json.hpp>

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::contracts::adr31::detail {
namespace {

constexpr std::array<std::string_view, 48> kForbiddenAuthorityNames{
    "accesstoken",
    "apitoken",
    "actor",
    "actorid",
    "actingprincipal",
    "actingprincipalid",
    "audience",
    "auth",
    "authenticatedactor",
    "authenticatedprincipal",
    "authentication",
    "authorization",
    "bearertoken",
    "caller",
    "callerid",
    "credential",
    "credentialid",
    "credentials",
    "delegatedoperator",
    "delegationartifact",
    "engineprincipal",
    "engineprincipalid",
    "grant",
    "identity",
    "invocationgrant",
    "onbehalfof",
    "operator",
    "operatorid",
    "principal",
    "principalcredential",
    "principalid",
    "recipient",
    "releaseauthorization",
    "representedoperator",
    "representedoperatorid",
    "resultgrant",
    "resultscopedgrant",
    "scopeceiling",
    "sessiontoken",
    "subject",
    "subjectid",
    "token",
    "user",
    "userid",
    "xonbehalfof",
    "xyuzudelegatedoperator",
    "xyuzudelegationartifact",
    "xyuzuonbehalfof",
};

[[nodiscard]] ContractError error(ContractErrorCode code, std::string path,
                                  std::string message) {
    return ContractError{code, std::move(path), std::move(message)};
}

[[nodiscard]] std::string escape_json_pointer(std::string_view token) {
    std::string escaped;
    escaped.reserve(token.size());
    for (const char byte : token) {
        if (byte == '~') {
            escaped += "~0";
        } else if (byte == '/') {
            escaped += "~1";
        } else {
            escaped.push_back(byte);
        }
    }
    return escaped;
}

class StructuralSax final : public nlohmann::json_sax<nlohmann::json> {
  public:
    using number_integer_t = nlohmann::json::number_integer_t;
    using number_unsigned_t = nlohmann::json::number_unsigned_t;
    using number_float_t = nlohmann::json::number_float_t;
    using string_t = nlohmann::json::string_t;
    using binary_t = nlohmann::json::binary_t;

    bool null() override { return scalar(); }
    bool boolean(bool) override { return scalar(); }
    bool number_integer(number_integer_t) override { return scalar(); }
    bool number_unsigned(number_unsigned_t) override { return scalar(); }
    bool number_float(number_float_t, const string_t&) override { return scalar(); }
    bool string(string_t&) override { return scalar(); }
    bool binary(binary_t&) override { return scalar(); }

    bool start_object(std::size_t) override { return start_container(FrameKind::Object); }

    bool key(string_t& value) override {
        if (frames_.empty() || frames_.back().kind != FrameKind::Object) return false;

        auto& frame = frames_.back();
        if (!frame.keys.emplace(value).second) {
            violation_ = error(ContractErrorCode::DuplicateKey,
                               frame.path + "/" + escape_json_pointer(value),
                               "contract JSON contains a duplicate object key");
            return false;
        }
        frame.pending_key = value;
        return true;
    }

    bool end_object() override { return end_container(FrameKind::Object); }
    bool start_array(std::size_t) override { return start_container(FrameKind::Array); }
    bool end_array() override { return end_container(FrameKind::Array); }

    bool parse_error(std::size_t, const std::string&,
                     const nlohmann::detail::exception&) override {
        return false;
    }

    [[nodiscard]] const std::optional<ContractError>& violation() const noexcept {
        return violation_;
    }

  private:
    enum class FrameKind : std::uint8_t { Object, Array };

    struct Frame {
        FrameKind kind;
        std::string path;
        std::set<std::string, std::less<>> keys;
        std::optional<std::string> pending_key;
        std::size_t next_index{0};
    };

    [[nodiscard]] std::string consume_value_path() {
        if (frames_.empty()) return {};

        auto& parent = frames_.back();
        if (parent.kind == FrameKind::Array) {
            return parent.path + "/" + std::to_string(parent.next_index++);
        }

        if (!parent.pending_key) return parent.path;
        auto path = parent.path + "/" + escape_json_pointer(*parent.pending_key);
        parent.pending_key.reset();
        return path;
    }

    bool scalar() {
        if (violation_) return false;
        static_cast<void>(consume_value_path());
        return true;
    }

    bool start_container(FrameKind kind) {
        if (violation_) return false;
        const auto path = consume_value_path();
        if (frames_.size() >= kMaxContractNestingDepth) {
            violation_ = error(ContractErrorCode::TooDeep, path,
                               "contract JSON exceeds the nesting limit");
            return false;
        }
        frames_.push_back(Frame{.kind = kind, .path = path});
        return true;
    }

    bool end_container(FrameKind kind) {
        if (violation_ || frames_.empty() || frames_.back().kind != kind) return false;
        frames_.pop_back();
        return true;
    }

    std::vector<Frame> frames_;
    std::optional<ContractError> violation_;
};

[[nodiscard]] std::string normalise_name(std::string_view name) {
    std::string result;
    result.reserve(name.size());
    for (const unsigned char byte : name) {
        if (byte >= 'A' && byte <= 'Z') {
            result.push_back(static_cast<char>(byte - 'A' + 'a'));
        } else if ((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9')) {
            result.push_back(static_cast<char>(byte));
        }
    }
    return result;
}

} // namespace

std::expected<nlohmann::json, ContractError> parse_contract_json(std::string_view wire_json) {
    if (wire_json.size() > kMaxContractWireBytes) {
        return std::unexpected(error(ContractErrorCode::TooLarge, "",
                                     "contract body exceeds the wire-size limit"));
    }

    StructuralSax structure;
    if (!nlohmann::json::sax_parse(wire_json, &structure)) {
        if (structure.violation()) return std::unexpected(*structure.violation());
        return std::unexpected(
            error(ContractErrorCode::MalformedJson, "", "contract body is not valid JSON"));
    }

    auto document = nlohmann::json::parse(wire_json, nullptr, false);
    if (document.is_discarded()) {
        return std::unexpected(
            error(ContractErrorCode::MalformedJson, "", "contract body is not valid JSON"));
    }
    return document;
}

std::expected<std::string, ContractError>
encode_contract_json(const nlohmann::json& document) {
    struct Pending {
        const nlohmann::json* value;
        std::size_t depth;
    };

    std::vector<Pending> pending{{&document, 1}};
    while (!pending.empty()) {
        const auto [value, depth] = pending.back();
        pending.pop_back();

        if (value->is_discarded() || value->is_binary()) {
            return std::unexpected(error(ContractErrorCode::InvalidValue, "",
                                         "contract contains a non-JSON value"));
        }
        if (value->is_number_float() &&
            !std::isfinite(value->get<nlohmann::json::number_float_t>())) {
            return std::unexpected(error(ContractErrorCode::InvalidValue, "",
                                         "contract contains a non-finite number"));
        }
        if (!value->is_structured()) continue;
        if (depth > kMaxContractNestingDepth) {
            return std::unexpected(error(ContractErrorCode::TooDeep, "",
                                         "contract JSON exceeds the nesting limit"));
        }
        for (auto it = value->begin(); it != value->end(); ++it) {
            pending.push_back(Pending{&*it, depth + 1});
        }
    }

    std::string wire;
    try {
        wire = document.dump(-1, ' ', false, nlohmann::json::error_handler_t::strict);
    } catch (const nlohmann::json::exception&) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "",
                                     "contract contains a value that cannot be encoded"));
    }
    if (wire.size() > kMaxContractWireBytes) {
        return std::unexpected(error(ContractErrorCode::TooLarge, "",
                                     "encoded contract exceeds the wire-size limit"));
    }
    return wire;
}

std::expected<void, ContractError>
reject_forbidden_authority_fields(const nlohmann::json& root) {
    for (auto it = root.begin(); it != root.end(); ++it) {
        const auto normalised = normalise_name(it.key());
        for (const auto forbidden : kForbiddenAuthorityNames) {
            if (normalised == forbidden) {
                return std::unexpected(ContractError{
                    ContractErrorCode::ForbiddenAuthorityField,
                    "/" + escape_json_pointer(it.key()),
                    "caller-authored identity or authentication context is forbidden",
                });
            }
        }
    }
    return {};
}

} // namespace yuzu::contracts::adr31::detail
