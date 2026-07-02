#pragma once

#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace yuzu::scope {

// -- Comparison operators ----------------------------------------------------

enum class CompOp { Eq, Neq, Like, Lt, Gt, Le, Ge, In, Contains, Matches, Exists };

// -- Expression AST ----------------------------------------------------------

struct Condition {
    std::string attribute;
    CompOp op;
    std::string value;
    std::vector<std::string> values; // for In operator
};

struct Combinator;

using Expression = std::variant<Condition, std::unique_ptr<Combinator>>;

enum class CombOp { And, Or, Not };

struct Combinator {
    CombOp op;
    std::vector<Expression> children;
};

// -- Parser ------------------------------------------------------------------

/// Parse a scope expression string into an AST.
/// Grammar:
///   expr     ::= or_expr
///   or_expr  ::= and_expr ('OR' and_expr)*
///   and_expr ::= not_expr ('AND' not_expr)*
///   not_expr ::= 'NOT' not_expr | primary
///   primary  ::= '(' expr ')' | condition
///   condition::= IDENT op value
///   op       ::= '==' | '!=' | 'LIKE' | 'MATCHES' | '<' | '>' | '<=' | '>=' | 'IN' | 'CONTAINS'
///   value    ::= QUOTED_STRING | '(' value_list ')' | IDENT
///   value_list ::= value (',' value)*
///
/// Extended operators:
///   condition::= 'EXISTS' IDENT                        (unary — checks non-empty)
///              | 'LEN' '(' IDENT ')' op value           (string length comparison)
///              | 'STARTSWITH' '(' IDENT ',' value ')'   (prefix check)
std::expected<Expression, std::string> parse(std::string_view input);

// -- Evaluator ---------------------------------------------------------------

/// Resolves an attribute name to a value.
using AttributeResolver = std::function<std::string(std::string_view)>;

/// Evaluate an expression against a resolver.
bool evaluate(const Expression& expr, const AttributeResolver& resolver);

/// Check if an expression is syntactically valid (convenience).
std::expected<void, std::string> validate(std::string_view input);

/// Canonical wire token for a comparison operator, e.g. `CompOp::Eq` -> `"=="`.
/// Single source for the `GET /api/v1/discover/scope-kinds` operator catalog
/// (`discover_routes.cpp`) so the published list can never silently diverge from
/// the evaluator. The switch backing this function (`scope_engine.cpp`) has NO
/// `default` case — mirroring `eval_condition`'s own exhaustive switch — so
/// adding a `CompOp` enumerator without updating both switches produces a
/// `-Wswitch` warning at build (warning_level=3 project-wide; see CLAUDE.md
/// Build). A CROSS-CHECK unit test (`test_discovery_routes.cpp`) also asserts
/// the discovery catalog covers every currently-declared value.
std::string_view operator_token(CompOp op);

} // namespace yuzu::scope
