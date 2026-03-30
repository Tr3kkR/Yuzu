/**
 * tar_sql_executor.cpp -- Safe SQL validation and $-name translation
 *
 * Three-layer defense:
 *  1. SELECT-only keyword check
 *  2. $-name whitelist translation
 *  3. Single-statement enforcement (reject trailing SQL)
 */

#include "tar_sql_executor.hpp"
#include "tar_schema_registry.hpp"

#include <algorithm>
#include <cctype>
#include <format>
#include <regex>
#include <string>
#include <string_view>

namespace yuzu::tar {

namespace {

/// Trim leading and trailing whitespace.
std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.remove_suffix(1);
    return s;
}

/// Case-insensitive check if the string starts with a keyword.
bool starts_with_ci(std::string_view s, std::string_view prefix) {
    if (s.size() < prefix.size())
        return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i])) !=
            std::tolower(static_cast<unsigned char>(prefix[i])))
            return false;
    }
    // Must be followed by whitespace or '(' to be a keyword boundary
    if (s.size() > prefix.size()) {
        char next = s[prefix.size()];
        if (std::isalnum(static_cast<unsigned char>(next)) || next == '_')
            return false;
    }
    return true;
}

/// Strip string literals (single-quoted) and SQL comments from input
/// so keyword matching doesn't produce false positives on data values. (H7)
std::string strip_literals_and_comments(const std::string& sql) {
    std::string out;
    out.reserve(sql.size());
    size_t i = 0;
    while (i < sql.size()) {
        // Single-quoted string literal
        if (sql[i] == '\'') {
            out += ' '; // replace literal with space
            ++i;
            while (i < sql.size()) {
                if (sql[i] == '\'' && i + 1 < sql.size() && sql[i + 1] == '\'') {
                    i += 2; // escaped quote
                } else if (sql[i] == '\'') {
                    ++i;
                    break;
                } else {
                    ++i;
                }
            }
        }
        // Block comment
        else if (sql[i] == '/' && i + 1 < sql.size() && sql[i + 1] == '*') {
            out += ' ';
            i += 2;
            while (i + 1 < sql.size() && !(sql[i] == '*' && sql[i + 1] == '/'))
                ++i;
            if (i + 1 < sql.size()) i += 2;
        }
        // Line comment
        else if (sql[i] == '-' && i + 1 < sql.size() && sql[i + 1] == '-') {
            out += ' ';
            i += 2;
            while (i < sql.size() && sql[i] != '\n')
                ++i;
        }
        else {
            out += sql[i];
            ++i;
        }
    }
    return out;
}

/// Check if the SQL contains a dangerous keyword (case-insensitive word match).
/// Operates on stripped input (no string literals or comments).
bool contains_dangerous_keyword(const std::string& stripped_sql) {
    std::string upper;
    upper.reserve(stripped_sql.size());
    for (char c : stripped_sql)
        upper += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    static const std::string_view dangerous[] = {
        "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
        "ATTACH", "DETACH", "PRAGMA", "REPLACE", "REINDEX", "VACUUM",
        "SAVEPOINT", "RELEASE", "ROLLBACK", "LOAD_EXTENSION",
    };

    for (auto kw : dangerous) {
        auto pos = upper.find(kw);
        while (pos != std::string::npos) {
            bool left_ok = (pos == 0) ||
                           !std::isalnum(static_cast<unsigned char>(upper[pos - 1])) &&
                           upper[pos - 1] != '_';
            bool right_ok = (pos + kw.size() >= upper.size()) ||
                            !std::isalnum(static_cast<unsigned char>(upper[pos + kw.size()])) &&
                            upper[pos + kw.size()] != '_';
            if (left_ok && right_ok)
                return true;
            pos = upper.find(kw, pos + 1);
        }
    }
    return false;
}

/// Check for multiple statements (semicolons followed by non-whitespace).
bool has_multiple_statements(std::string_view sql) {
    auto semi = sql.find(';');
    if (semi == std::string_view::npos)
        return false;
    // Check if there's meaningful content after the semicolon
    auto rest = trim(sql.substr(semi + 1));
    return !rest.empty();
}

} // namespace

std::expected<std::string, std::string> validate_and_translate_sql(const std::string& raw_sql) {
    // H12: Reject oversized input to prevent regex DoS
    if (raw_sql.size() > 4096)
        return std::unexpected("SQL query exceeds 4KB limit");

    auto trimmed = trim(raw_sql);
    if (trimmed.empty())
        return std::unexpected("empty SQL query");

    // Layer 1: Must start with SELECT
    if (!starts_with_ci(trimmed, "SELECT"))
        return std::unexpected("only SELECT queries are allowed");

    // Layer 1b: Must not contain dangerous keywords
    // H7: Strip string literals and comments first to avoid false positives
    std::string sql_str(trimmed);
    auto stripped = strip_literals_and_comments(sql_str);
    if (contains_dangerous_keyword(stripped))
        return std::unexpected("query contains forbidden keyword");

    // Layer 3: Single statement only
    if (has_multiple_statements(trimmed))
        return std::unexpected("only single-statement queries are allowed");

    // Layer 2: Translate $-prefixed table names
    // Match $Word_Word patterns
    static const std::regex dollar_re(R"(\$([A-Za-z]+_[A-Za-z]+))");
    std::string result;
    auto begin = std::sregex_iterator(sql_str.begin(), sql_str.end(), dollar_re);
    auto end = std::sregex_iterator();

    size_t last_pos = 0;
    for (auto it = begin; it != end; ++it) {
        auto& match = *it;
        auto dollar_name = "$" + match[1].str();
        auto translated = translate_dollar_name(dollar_name);
        if (!translated)
            return std::unexpected(std::format("unknown table: {}", dollar_name));

        result += sql_str.substr(last_pos, match.position() - last_pos);
        result += *translated;
        last_pos = match.position() + match.length();
    }
    result += sql_str.substr(last_pos);

    // Strip trailing semicolons
    while (!result.empty() && (result.back() == ';' ||
           std::isspace(static_cast<unsigned char>(result.back()))))
        result.pop_back();

    return result;
}

} // namespace yuzu::tar
