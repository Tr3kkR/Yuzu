#pragma once

#include <cstddef>
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

// Single source of truth for "how many CompOp values exist". When you add a
// CompOp enumerator you MUST bump this AND add a `comp_op_catalog()` entry in
// discover_routes.cpp — a `static_assert` there binds the catalog size to this
// constant, so a mismatch is a portable BUILD failure on every compiler (the
// exhaustive-switch `-Wswitch` signal in operator_token/eval_condition is
// GCC/Clang-only and non-fatal, so it is not a sufficient guard on its own —
// governance arch-SHOULD-4 / cpp-expert). Not a `CompOp::_Count` sentinel on
// purpose: that would force a dummy case into every exhaustive CompOp switch.
inline constexpr std::size_t kCompOpCount = 11;

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
