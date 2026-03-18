#pragma once

#include <string>
#include <vector>

namespace yuzu::server::data_export {

// RFC 4180 CSV field escaping: quote fields containing commas, quotes, or newlines.
// Internal double-quotes are doubled.
inline std::string csv_escape(const std::string& field) {
    bool needs_quoting = false;
    for (char c : field) {
        if (c == ',' || c == '"' || c == '\n' || c == '\r') {
            needs_quoting = true;
            break;
        }
    }
    if (!needs_quoting) return field;

    std::string result;
    result.reserve(field.size() + 8);
    result += '"';
    for (char c : field) {
        if (c == '"') result += '"';
        result += c;
    }
    result += '"';
    return result;
}

// Convert a JSON array string to CSV.  Expects a JSON array of objects
// with uniform keys.  Returns CSV with header row.
std::string json_array_to_csv(const std::string& json_str);

}  // namespace yuzu::server::data_export
