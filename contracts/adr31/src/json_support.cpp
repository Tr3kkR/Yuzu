#include "json_support.hpp"

#include <yuzu/contracts/adr31/contract_limits.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::contracts::adr31::detail {
namespace {

constexpr std::array<std::string_view, 49> kForbiddenAuthorityNames{
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
    "enginecredential",
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

constexpr auto kForbiddenTransportAuthorityNames = std::to_array<std::string_view>({
    "accesstoken",
    "apitoken",
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
    "enginecredential",
    "engineprincipal",
    "engineprincipalid",
    "grant",
    "invocationgrant",
    "onbehalfof",
    "operator",
    "operatorid",
    "principal",
    "principalcredential",
    "principalid",
    "releaseauthorization",
    "representedoperator",
    "representedoperatorid",
    "resultgrant",
    "resultscopedgrant",
    "scopeceiling",
    "sessiontoken",
    "token",
    "xonbehalfof",
    "xyuzudelegatedoperator",
    "xyuzudelegationartifact",
    "xyuzuonbehalfof",
});

// These security namespaces remain reserved as identifier components and when
// callers compose them with explicit qualifiers such as `_context`, `_claim`,
// or `_id`. They are never raw substring matches: `fact_assertion`, `tokenizer`,
// and `migrant` remain valid domain fields.
constexpr auto kForbiddenTransportAuthorityNamespaces = std::to_array<std::string_view>({
    "accesstoken",
    "actas",
    "actingprincipal",
    "apitoken",
    "audience",
    "auth",
    "authn",
    "authentication",
    "authorization",
    "authz",
    "bearertoken",
    "caller",
    "credential",
    "delegatedprincipal",
    "delegationartifact",
    "enginecredential",
    "engineprincipal",
    "idtoken",
    "invocationgrant",
    "oauth",
    "oauthtoken",
    "obo",
    "onbehalfof",
    "operator",
    "principalcredential",
    "releaseauthorization",
    "representedprincipal",
    "refreshtoken",
    "resultgrant",
    "resultscopedgrant",
    "scopeceiling",
    "sessiontoken",
});

constexpr std::array<std::string_view, 0> kNoForbiddenNamespaces{};

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

[[nodiscard]] bool is_ascii_upper(unsigned char byte) noexcept {
    return byte >= 'A' && byte <= 'Z';
}

[[nodiscard]] bool is_ascii_lower(unsigned char byte) noexcept {
    return byte >= 'a' && byte <= 'z';
}

[[nodiscard]] bool is_ascii_digit(unsigned char byte) noexcept {
    return byte >= '0' && byte <= '9';
}

[[nodiscard]] std::vector<std::string> authority_name_components(std::string_view name) {
    std::vector<std::string> components;
    std::string component;

    const auto flush = [&components, &component] {
        if (!component.empty()) {
            components.push_back(std::move(component));
            component.clear();
        }
    };

    for (std::size_t index = 0; index < name.size(); ++index) {
        const auto byte = static_cast<unsigned char>(name[index]);
        if (!is_ascii_upper(byte) && !is_ascii_lower(byte) && !is_ascii_digit(byte)) {
            flush();
            continue;
        }

        if (is_ascii_upper(byte) && !component.empty()) {
            const auto previous = static_cast<unsigned char>(name[index - 1]);
            const auto next = index + 1 < name.size() ? static_cast<unsigned char>(name[index + 1])
                                                      : static_cast<unsigned char>(0);
            if (is_ascii_lower(previous) || is_ascii_digit(previous) ||
                (is_ascii_upper(previous) && is_ascii_lower(next))) {
                flush();
            }
        }
        component.push_back(is_ascii_upper(byte) ? static_cast<char>(byte - 'A' + 'a')
                                                 : static_cast<char>(byte));
    }
    flush();
    return components;
}

[[nodiscard]] bool is_explicit_qualified_alias(std::string_view normalised,
                                               std::string_view authority_namespace) {
    if (!normalised.starts_with(authority_namespace))
        return false;

    constexpr auto qualifiers = std::to_array<std::string_view>(
        {"actor", "artifact", "blob", "claim", "claims", "context", "credential", "data", "hash",
         "header", "id", "info", "metadata", "principal", "scope", "secret", "subject", "token",
         "value"});
    const auto remainder = normalised.substr(authority_namespace.size());
    if (remainder.empty())
        return true;

    std::vector<bool> reachable(remainder.size() + 1);
    reachable.front() = true;
    for (std::size_t offset = 0; offset < remainder.size(); ++offset) {
        if (!reachable[offset])
            continue;
        const auto suffix = remainder.substr(offset);
        for (const auto qualifier : qualifiers) {
            if (suffix.starts_with(qualifier))
                reachable[offset + qualifier.size()] = true;
        }
    }
    return reachable.back();
}

template <std::size_t NamespaceSize>
[[nodiscard]] bool has_forbidden_authority_namespace(
    std::string_view name, std::string_view normalised,
    const std::array<std::string_view, NamespaceSize>& forbidden_namespaces) {
    constexpr auto token_prefixes = std::to_array<std::string_view>(
        {"access", "api", "auth", "bearer", "id", "identity", "oauth", "refresh", "session"});
    constexpr auto token_suffixes = std::to_array<std::string_view>(
        {"claim", "context", "credential", "hash", "header", "id", "secret", "value"});

    const auto components = authority_name_components(name);
    std::size_t max_namespace_size = 0;
    for (const auto authority_namespace : forbidden_namespaces)
        max_namespace_size = std::max(max_namespace_size, authority_namespace.size());

    std::string candidate;
    candidate.reserve(max_namespace_size);
    for (std::size_t start = 0; start < components.size(); ++start) {
        candidate.clear();
        for (std::size_t end = start; end < components.size(); ++end) {
            if (components[end].size() > max_namespace_size - candidate.size())
                break;
            candidate += components[end];
            for (const auto authority_namespace : forbidden_namespaces) {
                if (candidate == authority_namespace)
                    return true;
            }
        }

        const auto component = std::string_view{components[start]};
        if (component != "token")
            continue;

        if (start > 0) {
            for (const auto prefix : token_prefixes) {
                if (components[start - 1] == prefix)
                    return true;
            }
        }
        if (start + 1 < components.size()) {
            for (const auto suffix : token_suffixes) {
                if (components[start + 1] == suffix)
                    return true;
            }
        }
    }

    for (const auto authority_namespace : forbidden_namespaces) {
        if (is_explicit_qualified_alias(normalised, authority_namespace))
            return true;
    }
    return false;
}

template <std::size_t Size, std::size_t NamespaceSize>
std::expected<void, ContractError> reject_forbidden_fields_recursive(
    const nlohmann::json& value, std::string_view parent_path,
    const std::array<std::string_view, Size>& forbidden_names,
    const std::array<std::string_view, NamespaceSize>& forbidden_namespaces) {
    struct Pending {
        const nlohmann::json* value;
        std::string path;
    };

    std::vector<Pending> pending{{&value, std::string{parent_path}}};
    while (!pending.empty()) {
        auto current = std::move(pending.back());
        pending.pop_back();

        if (current.value->is_object()) {
            for (auto it = current.value->begin(); it != current.value->end(); ++it) {
                const auto path = current.path + "/" + escape_json_pointer(it.key());
                const auto normalised = normalise_name(it.key());
                bool forbidden_field = false;
                for (const auto forbidden : forbidden_names) {
                    if (normalised == forbidden) {
                        forbidden_field = true;
                        break;
                    }
                }
                if (!forbidden_field) {
                    for (const auto forbidden : forbidden_names) {
                        if (is_explicit_qualified_alias(normalised, forbidden)) {
                            forbidden_field = true;
                            break;
                        }
                    }
                }
                if (!forbidden_field && !forbidden_namespaces.empty()) {
                    forbidden_field = has_forbidden_authority_namespace(it.key(), normalised,
                                                                        forbidden_namespaces);
                }
                if (forbidden_field) {
                    return std::unexpected(ContractError{
                        ContractErrorCode::ForbiddenAuthorityField,
                        path,
                        "caller-authored identity or authentication context is forbidden",
                    });
                }
                pending.push_back(Pending{&*it, path});
            }
        } else if (current.value->is_array()) {
            for (std::size_t index = 0; index < current.value->size(); ++index) {
                pending.push_back(
                    Pending{&(*current.value)[index], current.path + "/" + std::to_string(index)});
            }
        }
    }
    return {};
}

} // namespace

std::expected<std::string, ContractError>
required_string(const nlohmann::json& object, std::string_view name,
                std::string_view parent_path) {
    const auto it = object.find(name);
    const auto path = std::string{parent_path} + "/" + std::string{name};
    if (it == object.end()) {
        return std::unexpected(error(ContractErrorCode::MissingField, path,
                                     std::string{name} + " is required"));
    }
    if (it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, path, std::string{name} + " must not be null"));
    }
    if (!it->is_string()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, path, std::string{name} + " must be a string"));
    }
    auto value = it->get<std::string>();
    if (value.empty()) {
        return std::unexpected(
            error(ContractErrorCode::InvalidValue, path, std::string{name} + " must not be empty"));
    }
    return value;
}

std::expected<ContractVersion, ContractError>
decode_contract_header(const nlohmann::json& root, const ContractDescriptor& descriptor) {
    const auto contract_it = root.find("contract");
    if (contract_it == root.end()) {
        return std::unexpected(
            error(ContractErrorCode::MissingField, "/contract", "contract is required"));
    }
    if (contract_it->is_null()) {
        return std::unexpected(
            error(ContractErrorCode::NullField, "/contract", "contract must not be null"));
    }
    if (!contract_it->is_object()) {
        return std::unexpected(
            error(ContractErrorCode::WrongType, "/contract", "contract must be an object"));
    }

    const auto id = required_string(*contract_it, "id", "/contract");
    if (!id) return std::unexpected(id.error());
    if (*id != descriptor.identifier) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, "/contract/id",
                                     "unexpected contract identifier"));
    }

    const auto version_it = contract_it->find("version");
    if (version_it == contract_it->end()) {
        return std::unexpected(error(ContractErrorCode::MissingField, "/contract/version",
                                     "version is required"));
    }
    if (version_it->is_null()) {
        return std::unexpected(error(ContractErrorCode::NullField, "/contract/version",
                                     "version must not be null"));
    }
    if (!version_it->is_object()) {
        return std::unexpected(error(ContractErrorCode::WrongType, "/contract/version",
                                     "version must be an object"));
    }

    const auto decode_part = [&](std::string_view name)
        -> std::expected<std::uint16_t, ContractError> {
        const auto it = version_it->find(name);
        const auto path = "/contract/version/" + std::string{name};
        if (it == version_it->end()) {
            return std::unexpected(error(ContractErrorCode::MissingField, path,
                                         std::string{name} + " is required"));
        }
        if (it->is_null()) {
            return std::unexpected(error(ContractErrorCode::NullField, path,
                                         std::string{name} + " must not be null"));
        }
        if (!it->is_number_unsigned()) {
            return std::unexpected(error(ContractErrorCode::WrongType, path,
                                         std::string{name} + " must be an unsigned integer"));
        }
        const auto value = it->get<std::uint64_t>();
        if (value > std::numeric_limits<std::uint16_t>::max()) {
            return std::unexpected(error(ContractErrorCode::InvalidValue, path,
                                         std::string{name} + " is outside the supported range"));
        }
        return static_cast<std::uint16_t>(value);
    };

    const auto major = decode_part("major");
    if (!major) return std::unexpected(major.error());
    const auto minor = decode_part("minor");
    if (!minor) return std::unexpected(minor.error());

    const ContractVersion version{*major, *minor};
    if (!supports(descriptor, version)) {
        return std::unexpected(error(ContractErrorCode::UnsupportedVersion, "/contract/version",
                                     "unsupported contract version"));
    }
    return version;
}

std::expected<void, ContractError> validate_opaque_run_id(std::string_view value,
                                                          std::string_view path) {
    if (value.size() < kMinOpaqueRunIdCharacters || value.size() > kMaxOpaqueRunIdCharacters) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, std::string{path},
                                     "run identifier length is outside the opaque-id contract"));
    }
    for (const unsigned char byte : value) {
        const bool allowed = (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
                             (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' ||
                             byte == '.' || byte == ':' || byte == '=';
        if (!allowed) {
            return std::unexpected(error(ContractErrorCode::InvalidValue, std::string{path},
                                         "run identifier is not an opaque ASCII token"));
        }
    }
    return {};
}

std::expected<void, ContractError> validate_correlation_id(std::string_view value,
                                                           std::string_view path) {
    if (value.empty() || value.size() > kMaxCorrelationIdCharacters) {
        return std::unexpected(error(ContractErrorCode::InvalidValue, std::string{path},
                                     "correlation identifier length is outside the contract"));
    }
    for (const unsigned char byte : value) {
        const bool allowed = (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
                             (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' ||
                             byte == '.' || byte == ':' || byte == '=';
        if (!allowed) {
            return std::unexpected(error(ContractErrorCode::InvalidValue, std::string{path},
                                         "correlation identifier is not an opaque ASCII token"));
        }
    }
    return {};
}

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

std::expected<void, ContractError>
reject_forbidden_authority_fields_recursive(const nlohmann::json& value,
                                             std::string_view parent_path) {
    return reject_forbidden_fields_recursive(value, parent_path, kForbiddenAuthorityNames,
                                             kNoForbiddenNamespaces);
}

std::expected<void, ContractError>
reject_forbidden_transport_authority_fields_recursive(const nlohmann::json& value,
                                                      std::string_view parent_path) {
    return reject_forbidden_fields_recursive(value, parent_path, kForbiddenTransportAuthorityNames,
                                             kForbiddenTransportAuthorityNamespaces);
}

} // namespace yuzu::contracts::adr31::detail
