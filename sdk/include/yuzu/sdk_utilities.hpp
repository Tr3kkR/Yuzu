/**
 * yuzu/sdk_utilities.hpp — SDK utility functions for format conversion
 *
 * Pure, stateless, thread-safe transformations between pipe-delimited table
 * format and JSON. These are the C++23 interfaces; for the stable C ABI see
 * the corresponding functions in plugin.h.
 *
 * All functions live in namespace yuzu::sdk and are header-only so that both
 * plugins and the agent core can use them without additional link deps beyond
 * nlohmann/json.
 */

#pragma once

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "plugin.hpp"   // yuzu::PluginError, yuzu::Result

namespace yuzu::sdk {

// ── Column type hints for typed JSON output ──────────────────────────────

enum class ColumnType {
    kString,
    kInt,
    kFloat,
    kBool,
};

// ── split_lines ──────────────────────────────────────────────────────────

/**
 * Split a multi-line string into individual lines.
 * Handles \n, \r\n, and \r line endings.
 * Returns views into the original input — caller must keep input alive.
 */
inline std::vector<std::string_view> split_lines(std::string_view input) {
    std::vector<std::string_view> lines;
    if (input.empty()) return lines;

    size_t start = 0;
    while (start <= input.size()) {
        size_t end = input.find_first_of("\r\n", start);
        if (end == std::string_view::npos) {
            lines.push_back(input.substr(start));
            break;
        }
        lines.push_back(input.substr(start, end - start));
        if (input[end] == '\r' && end + 1 < input.size() && input[end + 1] == '\n') {
            start = end + 2;  // \r\n
        } else {
            start = end + 1;  // \r or \n
        }
    }
    return lines;
}

// ── Pipe-field parsing helpers (internal) ────────────────────────────────

namespace detail {

/** Parse one pipe-delimited field, handling \| escapes. Returns field end. */
inline size_t parse_field(std::string_view line, size_t start,
                          std::string& field_out) {
    field_out.clear();
    size_t pos = start;
    while (pos < line.size()) {
        if (line[pos] == '\\' && pos + 1 < line.size() && line[pos + 1] == '|') {
            field_out += '|';
            pos += 2;
        } else if (line[pos] == '|') {
            break;
        } else {
            field_out += line[pos];
            ++pos;
        }
    }
    return pos;  // points to '|' or end-of-line
}

/** Escape pipe characters in a field value for pipe-delimited output. */
inline void escape_field(std::string_view field, std::string& out) {
    for (char ch : field) {
        if (ch == '|') out += "\\|";
        else out += ch;
    }
}

/** Apply a type hint to convert a string field to a typed JSON value. */
inline nlohmann::json typed_value(const std::string& field, ColumnType type) {
    switch (type) {
        case ColumnType::kInt:
            try { return std::stoll(field); }
            catch (...) { return field; }
        case ColumnType::kFloat:
            try { return std::stod(field); }
            catch (...) { return field; }
        case ColumnType::kBool:
            return (field == "true" || field == "1");
        default:
            return field;
    }
}

}  // namespace detail

// ── table_to_json ────────────────────────────────────────────────────────

/**
 * Convert pipe-delimited rows into a JSON array of objects.
 *
 * @param input         Pipe-delimited text, one row per line.
 * @param column_names  Column names for the JSON keys.
 * @param column_types  Optional type hints (same length as column_names,
 *                      or empty to treat all fields as strings).
 * @return JSON string, or PluginError on failure.
 */
inline Result<std::string> table_to_json(
        std::string_view input,
        std::span<const std::string_view> column_names,
        std::span<const ColumnType> column_types = {})
{
    if (column_names.empty()) {
        return std::unexpected(PluginError{1, "column_names must not be empty"});
    }

    auto lines = split_lines(input);
    nlohmann::json arr = nlohmann::json::array();

    std::string field;
    for (const auto& line : lines) {
        if (line.empty()) continue;

        nlohmann::json obj = nlohmann::json::object();
        size_t col = 0;
        size_t pos = 0;

        while (pos <= line.size() && col < column_names.size()) {
            pos = detail::parse_field(line, pos, field);

            bool has_type = !column_types.empty() && col < column_types.size();
            std::string key{column_names[col]};
            obj[key] = has_type ? detail::typed_value(field, column_types[col])
                                : nlohmann::json(field);

            ++col;
            if (pos < line.size()) ++pos;  // skip '|'
        }

        // Fill missing columns with empty strings
        for (; col < column_names.size(); ++col) {
            obj[std::string{column_names[col]}] = "";
        }

        arr.push_back(std::move(obj));
    }

    return arr.dump();
}

// ── json_to_table ────────────────────────────────────────────────────────

/**
 * Convert a JSON array of objects into pipe-delimited rows.
 *
 * @param json_input   JSON string (must be an array of objects).
 * @param column_names Keys to extract from each object, in order.
 * @return Pipe-delimited text, or PluginError on failure.
 */
inline Result<std::string> json_to_table(
        std::string_view json_input,
        std::span<const std::string_view> column_names)
{
    if (column_names.empty()) {
        return std::unexpected(PluginError{1, "column_names must not be empty"});
    }

    nlohmann::json arr;
    try {
        arr = nlohmann::json::parse(json_input);
    } catch (const nlohmann::json::parse_error& e) {
        return std::unexpected(PluginError{2, std::string("JSON parse error: ") + e.what()});
    }

    if (!arr.is_array()) {
        return std::unexpected(PluginError{3, "Input must be a JSON array"});
    }

    std::string result;
    for (size_t i = 0; i < arr.size(); ++i) {
        const auto& obj = arr[i];
        if (!obj.is_object()) {
            return std::unexpected(PluginError{4,
                "Element " + std::to_string(i) + " is not an object"});
        }

        for (size_t c = 0; c < column_names.size(); ++c) {
            if (c > 0) result += '|';

            std::string key{column_names[c]};
            if (obj.contains(key)) {
                const auto& val = obj[key];
                if (val.is_string()) {
                    detail::escape_field(val.get<std::string>(), result);
                } else if (val.is_null()) {
                    // empty field
                } else {
                    detail::escape_field(val.dump(), result);
                }
            }
            // missing key → empty field
        }

        if (i + 1 < arr.size()) result += '\n';
    }

    return result;
}

// ── generate_sequence ────────────────────────────────────────────────────

/**
 * Generate a sequence of numbered identifiers.
 *
 * @param start   Starting number.
 * @param count   How many identifiers to generate.
 * @param prefix  Optional prefix prepended to each number.
 * @return Newline-separated identifiers.
 */
inline std::string generate_sequence(int start, int count,
                                     std::string_view prefix = {}) {
    std::string result;
    for (int i = 0; i < count; ++i) {
        if (i > 0) result += '\n';
        result += prefix;
        result += std::to_string(start + i);
    }
    return result;
}

}  // namespace yuzu::sdk
