#pragma once

#include <map>
#include <string>
#include <string_view>

namespace yuzu::server {

/// Evaluates a simple compliance expression against a result map.
///
/// Supported operators: ==, !=, >, <, >=, <=, contains, startswith
/// Variables: result.<field> references fields from the result map
/// Combinators: AND, OR (with standard precedence)
/// Negation: NOT prefix
/// Literals: 'single-quoted', "double-quoted", true, false, integers
///
/// Examples:
///   result.status == 'running'
///   result.count > 0 AND result.enabled == true
///   result.name contains 'yuzu' OR result.name startswith 'Yuzu'
///   NOT result.status == 'error'
///
/// Returns true if compliant, false if not (or on parse error).
bool evaluate_compliance(std::string_view expression,
                         const std::map<std::string, std::string>& result_fields);

/// Validate a compliance expression for syntax correctness.
/// Returns empty string on success, or an error message describing the problem.
std::string validate_compliance_expression(std::string_view expression);

} // namespace yuzu::server
