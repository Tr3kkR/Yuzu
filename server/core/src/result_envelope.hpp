#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

// Column types matching the instruction result schema spec.
// See docs/Instruction-Engine.md for the canonical type list.
enum class ColumnType { Bool, Int32, Int64, String, Datetime, Guid, Clob };

struct ResultColumn {
    std::string name;
    ColumnType type;
};

// Row values are stored as strings (wire format).  Typed validation is
// performed separately via validate_types().
struct ResultRow {
    std::unordered_map<std::string, std::string> values;
};

// Structured envelope for instruction execution results.  Carries metadata,
// typed columnar data, and optional diagnostic output.
struct InstructionResult {
    // -- Metadata --
    std::string execution_id;
    std::string definition_id;
    std::string agent_id;
    int64_t timestamp{0}; // epoch milliseconds
    std::string status;   // e.g. "success", "failure", "timeout"
    int error_code{0};
    int64_t duration_ms{0};

    // -- Data --
    std::vector<ResultColumn> columns;
    std::vector<ResultRow> rows;

    // -- Diagnostics --
    std::string stdout_text;
    std::string stderr_text;
    std::vector<std::string> warnings;
};

// Parse raw plugin output into a structured InstructionResult.
//
// If `output` is valid JSON containing "columns" and "rows" arrays the data is
// parsed into typed ResultColumns and ResultRows.  Otherwise the raw text is
// wrapped in a single column named "output" of type String.
//
// `result_schema_json` is the JSON result-schema from the InstructionDefinition
// (may be empty, in which case column types fall back to String).
InstructionResult parse_result(const std::string& output, const std::string& result_schema_json);

// Serialize an InstructionResult to a nlohmann::json object suitable for the
// REST API or persistent storage.
nlohmann::json to_json(const InstructionResult& result);

// Validate every row value against the declared column type.  Returns a
// (possibly empty) list of human-readable error strings describing mismatches.
std::vector<std::string> validate_types(const InstructionResult& result);

// Convert a type string ("bool", "int32", ...) to the ColumnType enum.
// Unrecognised strings map to ColumnType::String.
ColumnType parse_column_type(const std::string& type_str);

// Convert a ColumnType enum value back to its canonical lowercase string form.
std::string column_type_to_string(ColumnType type);

} // namespace yuzu::server
