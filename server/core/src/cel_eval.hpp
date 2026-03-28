#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace yuzu::server::cel {

// ── CEL type system ─────────────────────────────────────────────────────────

struct CelTimestamp {
    std::chrono::system_clock::time_point tp;
};

struct CelDuration {
    std::chrono::milliseconds ms;
};

struct CelList;  // forward declaration for recursive variant

/// CEL value: null | bool | int | double | string | timestamp | duration | list
using CelValue = std::variant<
    std::monostate,                  // null
    bool,                            // bool
    int64_t,                         // int
    double,                          // double
    std::string,                     // string
    CelTimestamp,                    // timestamp
    CelDuration,                    // duration
    std::shared_ptr<CelList>>;      // list (shared_ptr breaks recursive variant cycle)

struct CelList {
    std::vector<CelValue> items;
};

// ── Public API ──────────────────────────────────────────────────────────────

/// Evaluate a CEL expression against a variable map.
/// Variables are provided as string->string (matching existing wire format)
/// and coerced to typed CelValues based on content and expression context.
/// Returns the evaluated CelValue result.
CelValue evaluate(std::string_view expression,
                  const std::map<std::string, std::string>& variables);

/// Evaluate a CEL expression and coerce the result to bool.
/// Used for compliance checks and workflow step conditions.
/// Returns true if compliant, false if not (or on parse/evaluation error).
bool evaluate_bool(std::string_view expression,
                   const std::map<std::string, std::string>& variables);

/// Evaluate a CEL expression and return tri-state: true (compliant), false
/// (non-compliant), or nullopt (evaluation error — timeout, parse error,
/// missing variables producing monostate). Used by compliance_eval to
/// distinguish genuine non-compliance from evaluation failures (G4-UHP-POL-008).
std::optional<bool> evaluate_tri(std::string_view expression,
                                 const std::map<std::string, std::string>& variables);

/// Validate a CEL expression for syntax correctness without evaluation.
/// Returns empty string on success, or an error message describing the problem.
std::string validate(std::string_view expression);

/// Migrate a legacy compliance expression to CEL syntax.
/// Transforms: AND -> &&, OR -> ||, NOT -> !, contains -> .contains(),
/// startswith -> .startsWith(). Returns the CEL form, or the original
/// if it is already valid CEL.
std::string migrate_expression(std::string_view legacy_expression);

} // namespace yuzu::server::cel
