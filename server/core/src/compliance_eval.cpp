#include "compliance_eval.hpp"

#include "cel_eval.hpp"

namespace yuzu::server {

bool evaluate_compliance(std::string_view expression,
                         const std::map<std::string, std::string>& result_fields) {
    if (expression.empty())
        return true; // empty expression = always compliant

    return cel::evaluate_bool(expression, result_fields);
}

std::string validate_compliance_expression(std::string_view expression) {
    if (expression.empty())
        return {};

    return cel::validate(expression);
}

} // namespace yuzu::server
