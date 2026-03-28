#pragma once

#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server {

/// Result of compliance evaluation.
enum class ComplianceResult {
    compliant,      ///< Expression evaluated to true
    non_compliant,  ///< Expression evaluated to false
    eval_error      ///< Evaluation failed (timeout, missing variable, parse error)
};

/// Evaluates a compliance expression against a result map.
/// Returns compliant, non_compliant, or eval_error.
/// eval_error means the expression could not be evaluated — this is distinct
/// from non_compliant and should be surfaced differently on the dashboard
/// (G4-UHP-POL-008).
ComplianceResult evaluate_compliance(std::string_view expression,
                                     const std::map<std::string, std::string>& result_fields);

/// Legacy bool overload for backward compatibility with callers that don't
/// need to distinguish errors from non-compliance. Errors map to false.
bool evaluate_compliance_bool(std::string_view expression,
                              const std::map<std::string, std::string>& result_fields);

/// Validate a compliance expression for syntax correctness.
/// Returns empty string on success, or an error message describing the problem.
std::string validate_compliance_expression(std::string_view expression);

} // namespace yuzu::server
