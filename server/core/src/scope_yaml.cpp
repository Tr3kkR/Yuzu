#include "scope_yaml.hpp"

#include "result_set_store.hpp"
#include "yaml_scan.hpp"

#include <cctype>

namespace yuzu::server {

namespace {

std::string to_lower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Matches scope_engine.cpp read_ident's charset; governs where a
// from_result_set:<ref> atom ends.
bool is_scope_ident_char(char c) {
    unsigned char u = static_cast<unsigned char>(c);
    return std::isalnum(u) || c == '_' || c == '.' || c == ':' || c == '-' || c == '*';
}

} // namespace

ScopeBlock parse_scope_block(const std::string& yaml_source) {
    ScopeBlock sb;

    // Isolate the scope block. Prefer the precise spec.scope path; fall back to
    // a bare `scope:` for YAML without a spec wrapper (e.g. focused tests).
    std::string scope_block = yaml_scan::extract_yaml_section(yaml_source, "spec.scope");
    if (scope_block.empty())
        scope_block = yaml_scan::extract_yaml_section(yaml_source, "scope");
    if (scope_block.empty())
        return sb; // scalar `scope:` or no scope — empty block

    sb.has_from_result_set = yaml_scan::yaml_has_key(scope_block, "fromResultSet");
    if (sb.has_from_result_set)
        sb.from_result_set = yaml_scan::extract_yaml_value(scope_block, "fromResultSet");

    if (yaml_scan::yaml_has_key(scope_block, "selector")) {
        std::string selector_block = yaml_scan::extract_yaml_section(scope_block, "selector");
        sb.has_selector = true;
        sb.selector_platform = yaml_scan::extract_yaml_value(selector_block, "platform");
        sb.selector_tags = yaml_scan::extract_yaml_list(selector_block, "tags");
    }

    return sb;
}

std::optional<std::string> validate_scope_block(const ScopeBlock& sb,
                                                const std::string& assignment_mode,
                                                bool assignment_has_mgmt_groups) {
    // Rules 1+2 only constrain the fromResultSet form. A selector-only or empty
    // block is always valid (a scalar scope expression never reaches here).
    if (!sb.has_from_result_set)
        return std::nullopt;

    if (sb.from_result_set.empty())
        return "spec.scope.fromResultSet must not be empty: give a result-set id "
               "(rs_...) or a per-operator alias";
    if (sb.from_result_set.size() > 128)
        return "spec.scope.fromResultSet id or alias must be 1-128 chars";

    if (assignment_has_mgmt_groups)
        return "scope.fromResultSet cannot be combined with assignment.managementGroups: a "
               "result set already defines a fixed device set; remove managementGroups";

    if (assignment_mode == "dynamic")
        return "scope.fromResultSet requires assignment.mode: static (got 'dynamic'): a result "
               "set is a fixed target; dynamic re-evaluation would defeat it";

    return std::nullopt;
}

std::string lower_scope_block(const ScopeBlock& sb) {
    std::vector<std::string> parts;

    if (sb.has_from_result_set && !sb.from_result_set.empty())
        parts.push_back("from_result_set:" + sb.from_result_set);

    if (!sb.selector_platform.empty())
        parts.push_back("ostype == \"" + to_lower(sb.selector_platform) + "\"");

    for (const auto& tag : sb.selector_tags) {
        if (!tag.empty())
            parts.push_back("EXISTS tag:" + tag);
    }

    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0)
            out += " AND ";
        out += parts[i];
    }
    return out;
}

std::string resolve_scope_aliases(std::string_view expr, const std::string& owner,
                                  ResultSetStore* store) {
    static constexpr std::string_view kPrefix = "from_result_set:";
    if (owner.empty() || store == nullptr || expr.find(kPrefix) == std::string_view::npos)
        return std::string(expr);
    std::string out;
    out.reserve(expr.size());
    size_t i = 0;
    while (i < expr.size()) {
        char c = expr[i];
        if (c == '"' || c == '\'') { // copy quoted literal verbatim
            char quote = c;
            out += c;
            for (++i; i < expr.size(); ++i) {
                out += expr[i];
                if (expr[i] == quote) {
                    ++i;
                    break;
                }
            }
            continue;
        }
        bool at_boundary = (i == 0) || !is_scope_ident_char(expr[i - 1]);
        if (at_boundary && expr.substr(i).starts_with(kPrefix)) {
            size_t rs = i + kPrefix.size();
            size_t j = rs;
            while (j < expr.size() && is_scope_ident_char(expr[j]))
                ++j;
            std::string ref(expr.substr(rs, j - rs));
            if (!ref.empty() && !ref.starts_with("rs_")) {
                if (auto canon = store->resolve_alias(owner, ref))
                    ref = *canon;
            }
            out += kPrefix;
            out += ref;
            i = j;
            continue;
        }
        out += c;
        ++i;
    }
    return out;
}

std::vector<std::string> scope_refs_failing_owner_check(std::string_view expr,
                                                        const std::string& owner,
                                                        ResultSetStore* store) {
    std::vector<std::string> failing;
    static constexpr std::string_view kPrefix = "from_result_set:";
    if (owner.empty() || store == nullptr || expr.find(kPrefix) == std::string_view::npos)
        return failing;
    size_t i = 0;
    while (i < expr.size()) {
        char c = expr[i];
        if (c == '"' || c == '\'') {
            char quote = c;
            for (++i; i < expr.size(); ++i)
                if (expr[i] == quote) {
                    ++i;
                    break;
                }
            continue;
        }
        bool at_boundary = (i == 0) || !is_scope_ident_char(expr[i - 1]);
        if (at_boundary && expr.substr(i).starts_with(kPrefix)) {
            size_t rs = i + kPrefix.size();
            size_t j = rs;
            while (j < expr.size() && is_scope_ident_char(expr[j]))
                ++j;
            std::string ref(expr.substr(rs, j - rs));
            if (!ref.empty()) {
                auto set = store->get(ref);
                if (!set || set->owner_principal != owner)
                    failing.push_back(ref);
            }
            i = j;
            continue;
        }
        ++i;
    }
    return failing;
}

} // namespace yuzu::server
