#include "result_envelope.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <regex>
#include <string>
#include <string_view>

namespace yuzu::server {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

ColumnType parse_column_type(const std::string& type_str) {
    // Normalise to lowercase for comparison.
    std::string lower;
    lower.reserve(type_str.size());
    for (char c : type_str)
        lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (lower == "bool")
        return ColumnType::Bool;
    if (lower == "int32")
        return ColumnType::Int32;
    if (lower == "int64")
        return ColumnType::Int64;
    if (lower == "string")
        return ColumnType::String;
    if (lower == "datetime")
        return ColumnType::Datetime;
    if (lower == "guid")
        return ColumnType::Guid;
    if (lower == "clob")
        return ColumnType::Clob;

    // Unknown type — default to String so we never lose data.
    return ColumnType::String;
}

std::string column_type_to_string(ColumnType type) {
    switch (type) {
    case ColumnType::Bool:
        return "bool";
    case ColumnType::Int32:
        return "int32";
    case ColumnType::Int64:
        return "int64";
    case ColumnType::String:
        return "string";
    case ColumnType::Datetime:
        return "datetime";
    case ColumnType::Guid:
        return "guid";
    case ColumnType::Clob:
        return "clob";
    }
    return "string"; // unreachable, but silences warnings
}

// ---------------------------------------------------------------------------
// Type validation helpers
// ---------------------------------------------------------------------------

namespace {

bool is_valid_bool(std::string_view v) {
    return v == "true" || v == "false" || v == "1" || v == "0";
}

bool is_valid_int32(std::string_view v) {
    if (v.empty())
        return false;
    int32_t val{};
    auto [ptr, ec] = std::from_chars(v.data(), v.data() + v.size(), val);
    return ec == std::errc{} && ptr == v.data() + v.size();
}

bool is_valid_int64(std::string_view v) {
    if (v.empty())
        return false;
    int64_t val{};
    auto [ptr, ec] = std::from_chars(v.data(), v.data() + v.size(), val);
    return ec == std::errc{} && ptr == v.data() + v.size();
}

bool is_valid_datetime(std::string_view v) {
    if (v.empty())
        return false;

    // Accept a pure integer as epoch milliseconds.
    {
        int64_t epoch{};
        auto [ptr, ec] = std::from_chars(v.data(), v.data() + v.size(), epoch);
        if (ec == std::errc{} && ptr == v.data() + v.size())
            return true;
    }

    // Accept ISO 8601 variants:
    //   YYYY-MM-DD
    //   YYYY-MM-DDTHH:MM:SS
    //   YYYY-MM-DDTHH:MM:SSZ
    //   YYYY-MM-DDTHH:MM:SS+HH:MM / -HH:MM
    static const std::regex iso8601_re(
        R"(\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?)",
        std::regex::optimize);
    return std::regex_match(v.begin(), v.end(), iso8601_re);
}

// Build a column-name-to-type lookup from the result's column vector.
std::unordered_map<std::string, ColumnType>
build_type_map(const std::vector<ResultColumn>& columns) {
    std::unordered_map<std::string, ColumnType> m;
    m.reserve(columns.size());
    for (const auto& col : columns)
        m[col.name] = col.type;
    return m;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// validate_types
// ---------------------------------------------------------------------------

std::vector<std::string> validate_types(const InstructionResult& result) {
    std::vector<std::string> errors;
    auto type_map = build_type_map(result.columns);

    for (size_t row_idx = 0; row_idx < result.rows.size(); ++row_idx) {
        const auto& row = result.rows[row_idx];
        for (const auto& [col_name, value] : row.values) {
            auto it = type_map.find(col_name);
            if (it == type_map.end())
                continue; // extra column — not a type error

            bool valid = true;
            switch (it->second) {
            case ColumnType::Bool:
                valid = is_valid_bool(value);
                break;
            case ColumnType::Int32:
                valid = is_valid_int32(value);
                break;
            case ColumnType::Int64:
                valid = is_valid_int64(value);
                break;
            case ColumnType::Datetime:
                valid = is_valid_datetime(value);
                break;
            case ColumnType::String:
            case ColumnType::Guid:
            case ColumnType::Clob:
                // Always valid — any string is acceptable.
                break;
            }

            if (!valid) {
                errors.push_back("row " + std::to_string(row_idx) + ", column \"" + col_name +
                                 "\": value \"" + value + "\" is not a valid " +
                                 column_type_to_string(it->second));
            }
        }
    }
    return errors;
}

// ---------------------------------------------------------------------------
// parse_result
// ---------------------------------------------------------------------------

InstructionResult parse_result(const std::string& output, const std::string& result_schema_json) {
    InstructionResult result;

    // Build a name->type map from the schema if one was provided.
    std::unordered_map<std::string, std::string> schema_types;
    if (!result_schema_json.empty()) {
        try {
            auto schema = nlohmann::json::parse(result_schema_json);
            if (schema.is_array()) {
                for (const auto& col : schema) {
                    if (col.contains("name") && col.contains("type")) {
                        schema_types[col["name"].get<std::string>()] =
                            col["type"].get<std::string>();
                    }
                }
            }
        } catch (...) {
            // Malformed schema — fall through to raw-text wrapping.
        }
    }

    // Attempt to parse the output as JSON.
    nlohmann::json doc;
    bool parsed_json = false;
    try {
        doc = nlohmann::json::parse(output);
        parsed_json = true;
    } catch (...) {
        // Not JSON — handled below.
    }

    if (parsed_json && doc.is_object() && doc.contains("columns") && doc.contains("rows") &&
        doc["columns"].is_array() && doc["rows"].is_array()) {

        // ---- Structured result ----

        // Parse columns.
        for (const auto& col_json : doc["columns"]) {
            ResultColumn col;
            col.name = col_json.value("name", "");
            std::string type_str = col_json.value("type", "string");

            // Schema takes precedence if it defines a type for this column.
            if (auto it = schema_types.find(col.name); it != schema_types.end()) {
                type_str = it->second;
            }
            col.type = parse_column_type(type_str);
            result.columns.push_back(std::move(col));
        }

        // Parse rows.
        for (const auto& row_json : doc["rows"]) {
            ResultRow row;
            if (row_json.is_object()) {
                for (auto& [key, val] : row_json.items()) {
                    if (val.is_string())
                        row.values[key] = val.get<std::string>();
                    else
                        row.values[key] = val.dump();
                }
            }
            result.rows.push_back(std::move(row));
        }

        // Pull optional metadata from the JSON if present.
        if (doc.contains("execution_id"))
            result.execution_id = doc.value("execution_id", "");
        if (doc.contains("definition_id"))
            result.definition_id = doc.value("definition_id", "");
        if (doc.contains("agent_id"))
            result.agent_id = doc.value("agent_id", "");
        if (doc.contains("timestamp"))
            result.timestamp = doc.value("timestamp", int64_t{0});
        if (doc.contains("status"))
            result.status = doc.value("status", "");
        if (doc.contains("error_code"))
            result.error_code = doc.value("error_code", 0);
        if (doc.contains("duration_ms"))
            result.duration_ms = doc.value("duration_ms", int64_t{0});
        if (doc.contains("stdout"))
            result.stdout_text = doc.value("stdout", "");
        if (doc.contains("stderr"))
            result.stderr_text = doc.value("stderr", "");
        if (doc.contains("warnings") && doc["warnings"].is_array()) {
            for (const auto& w : doc["warnings"])
                result.warnings.push_back(w.get<std::string>());
        }

    } else {
        // ---- Raw text fallback ----
        result.columns.push_back(ResultColumn{"output", ColumnType::String});

        ResultRow row;
        row.values["output"] = output;
        result.rows.push_back(std::move(row));
    }

    return result;
}

// ---------------------------------------------------------------------------
// to_json
// ---------------------------------------------------------------------------

nlohmann::json to_json(const InstructionResult& result) {
    nlohmann::json j;

    // Metadata
    j["execution_id"] = result.execution_id;
    j["definition_id"] = result.definition_id;
    j["agent_id"] = result.agent_id;
    j["timestamp"] = result.timestamp;
    j["status"] = result.status;
    j["error_code"] = result.error_code;
    j["duration_ms"] = result.duration_ms;

    // Columns
    j["columns"] = nlohmann::json::array();
    for (const auto& col : result.columns) {
        j["columns"].push_back({{"name", col.name}, {"type", column_type_to_string(col.type)}});
    }

    // Rows
    j["rows"] = nlohmann::json::array();
    for (const auto& row : result.rows) {
        nlohmann::json row_obj = nlohmann::json::object();
        for (const auto& [key, val] : row.values)
            row_obj[key] = val;
        j["rows"].push_back(std::move(row_obj));
    }

    // Diagnostics
    j["stdout"] = result.stdout_text;
    j["stderr"] = result.stderr_text;
    j["warnings"] = result.warnings;

    return j;
}

} // namespace yuzu::server
