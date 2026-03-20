#include "compliance_eval.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <optional>
#include <stdexcept>
#include <string>

namespace yuzu::server {

namespace {

// ── Token types ──────────────────────────────────────────────────────────────

enum class TokenType {
    Ident,       // result.foo, true, false
    StringLit,   // 'value' or "value"
    NumberLit,   // 123, -42
    OpEq,        // ==
    OpNeq,       // !=
    OpGt,        // >
    OpLt,        // <
    OpGe,        // >=
    OpLe,        // <=
    KwContains,  // contains
    KwStartswith,// startswith
    KwAnd,       // AND
    KwOr,        // OR
    KwNot,       // NOT
    LParen,      // (
    RParen,      // )
    End          // end of input
};

struct Token {
    TokenType type;
    std::string value;
};

// ── Lexer ────────────────────────────────────────────────────────────────────

class Lexer {
public:
    explicit Lexer(std::string_view input) : input_(input), pos_(0) {}

    Token next() {
        skip_whitespace();
        if (pos_ >= input_.size())
            return {TokenType::End, ""};

        char c = input_[pos_];

        // String literals
        if (c == '\'' || c == '"') {
            return read_string(c);
        }

        // Comparison operators
        if (c == '=' && peek(1) == '=') { pos_ += 2; return {TokenType::OpEq, "=="}; }
        if (c == '!' && peek(1) == '=') { pos_ += 2; return {TokenType::OpNeq, "!="}; }
        if (c == '>' && peek(1) == '=') { pos_ += 2; return {TokenType::OpGe, ">="}; }
        if (c == '<' && peek(1) == '=') { pos_ += 2; return {TokenType::OpLe, "<="}; }
        if (c == '>') { ++pos_; return {TokenType::OpGt, ">"}; }
        if (c == '<') { ++pos_; return {TokenType::OpLt, "<"}; }

        // Parentheses
        if (c == '(') { ++pos_; return {TokenType::LParen, "("}; }
        if (c == ')') { ++pos_; return {TokenType::RParen, ")"}; }

        // Number (possibly negative)
        if (std::isdigit(static_cast<unsigned char>(c)) ||
            (c == '-' && pos_ + 1 < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_ + 1])))) {
            return read_number();
        }

        // Identifier or keyword
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            return read_ident();
        }

        // Unknown character — skip
        ++pos_;
        return next();
    }

    size_t position() const { return pos_; }

private:
    std::string_view input_;
    size_t pos_;

    char peek(size_t offset) const {
        return (pos_ + offset < input_.size()) ? input_[pos_ + offset] : '\0';
    }

    void skip_whitespace() {
        while (pos_ < input_.size() && std::isspace(static_cast<unsigned char>(input_[pos_])))
            ++pos_;
    }

    Token read_string(char quote) {
        ++pos_; // skip opening quote
        std::string val;
        while (pos_ < input_.size() && input_[pos_] != quote) {
            if (input_[pos_] == '\\' && pos_ + 1 < input_.size()) {
                ++pos_;
                val += input_[pos_];
            } else {
                val += input_[pos_];
            }
            ++pos_;
        }
        if (pos_ < input_.size()) ++pos_; // skip closing quote
        return {TokenType::StringLit, val};
    }

    Token read_number() {
        size_t start = pos_;
        if (input_[pos_] == '-') ++pos_;
        while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_])))
            ++pos_;
        return {TokenType::NumberLit, std::string(input_.substr(start, pos_ - start))};
    }

    Token read_ident() {
        size_t start = pos_;
        while (pos_ < input_.size() &&
               (std::isalnum(static_cast<unsigned char>(input_[pos_])) || input_[pos_] == '_' || input_[pos_] == '.'))
            ++pos_;
        std::string val(input_.substr(start, pos_ - start));

        // Check for keywords (case-insensitive)
        std::string upper = val;
        std::transform(upper.begin(), upper.end(), upper.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

        if (upper == "AND")        return {TokenType::KwAnd, val};
        if (upper == "OR")         return {TokenType::KwOr, val};
        if (upper == "NOT")        return {TokenType::KwNot, val};
        if (upper == "CONTAINS")   return {TokenType::KwContains, val};
        if (upper == "STARTSWITH") return {TokenType::KwStartswith, val};

        return {TokenType::Ident, val};
    }
};

// ── Parser ───────────────────────────────────────────────────────────────────
//
// Grammar:
//   expr       ::= or_expr
//   or_expr    ::= and_expr ('OR' and_expr)*
//   and_expr   ::= not_expr ('AND' not_expr)*
//   not_expr   ::= 'NOT' not_expr | primary
//   primary    ::= '(' expr ')' | comparison
//   comparison ::= value (op value)?
//   op         ::= '==' | '!=' | '>' | '<' | '>=' | '<=' | 'contains' | 'startswith'
//   value      ::= IDENT | STRING_LIT | NUMBER_LIT

class Parser {
public:
    explicit Parser(std::string_view input, const std::map<std::string, std::string>& fields)
        : lexer_(input), fields_(fields) {
        advance();
    }

    bool evaluate() {
        bool result = parse_or();
        return result;
    }

    std::string validate_only() {
        try {
            parse_or_validate();
            if (current_.type != TokenType::End) {
                return "unexpected token: " + current_.value;
            }
            return {};
        } catch (const std::runtime_error& e) {
            return e.what();
        }
    }

private:
    Lexer lexer_;
    Token current_;
    const std::map<std::string, std::string>& fields_;

    void advance() { current_ = lexer_.next(); }

    // ── Evaluation methods ─────────────────────────────────────────────

    bool parse_or() {
        bool lhs = parse_and();
        while (current_.type == TokenType::KwOr) {
            advance();
            bool rhs = parse_and();
            lhs = lhs || rhs;
        }
        return lhs;
    }

    bool parse_and() {
        bool lhs = parse_not();
        while (current_.type == TokenType::KwAnd) {
            advance();
            bool rhs = parse_not();
            lhs = lhs && rhs;
        }
        return lhs;
    }

    bool parse_not() {
        if (current_.type == TokenType::KwNot) {
            advance();
            return !parse_not();
        }
        return parse_primary();
    }

    bool parse_primary() {
        if (current_.type == TokenType::LParen) {
            advance();
            bool result = parse_or();
            if (current_.type == TokenType::RParen)
                advance();
            return result;
        }
        return parse_comparison();
    }

    bool parse_comparison() {
        std::string lhs = resolve_value();

        // Check for comparison operator
        auto op = current_.type;
        if (op == TokenType::OpEq || op == TokenType::OpNeq ||
            op == TokenType::OpGt || op == TokenType::OpLt ||
            op == TokenType::OpGe || op == TokenType::OpLe ||
            op == TokenType::KwContains || op == TokenType::KwStartswith) {
            advance();
            std::string rhs = resolve_value();
            return compare(lhs, op, rhs);
        }

        // Bare identifier — treat as boolean (non-empty and not "false" = true)
        return !lhs.empty() && lhs != "false" && lhs != "0";
    }

    std::string resolve_value() {
        if (current_.type == TokenType::StringLit || current_.type == TokenType::NumberLit) {
            std::string val = current_.value;
            advance();
            return val;
        }
        if (current_.type == TokenType::Ident) {
            std::string name = current_.value;
            advance();

            // Handle boolean literals
            if (name == "true") return "true";
            if (name == "false") return "false";

            // Resolve result.field references
            if (name.starts_with("result.")) {
                auto field = name.substr(7); // skip "result."
                auto it = fields_.find(field);
                return (it != fields_.end()) ? it->second : "";
            }

            // Direct field lookup (without result. prefix)
            auto it = fields_.find(name);
            return (it != fields_.end()) ? it->second : name;
        }
        // Nothing to resolve
        return "";
    }

    bool compare(const std::string& lhs, TokenType op, const std::string& rhs) {
        switch (op) {
        case TokenType::OpEq:
            return lhs == rhs;
        case TokenType::OpNeq:
            return lhs != rhs;
        case TokenType::KwContains: {
            // Case-insensitive contains
            std::string l = lhs, r = rhs;
            std::transform(l.begin(), l.end(), l.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::transform(r.begin(), r.end(), r.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return l.find(r) != std::string::npos;
        }
        case TokenType::KwStartswith: {
            std::string l = lhs, r = rhs;
            std::transform(l.begin(), l.end(), l.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::transform(r.begin(), r.end(), r.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return l.starts_with(r);
        }
        default:
            break;
        }

        // Numeric comparisons
        auto to_int64 = [](const std::string& s) -> std::optional<int64_t> {
            int64_t val = 0;
            auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), val);
            if (ec == std::errc{} && ptr == s.data() + s.size())
                return val;
            return std::nullopt;
        };

        auto lnum = to_int64(lhs);
        auto rnum = to_int64(rhs);

        if (lnum && rnum) {
            switch (op) {
            case TokenType::OpGt: return *lnum > *rnum;
            case TokenType::OpLt: return *lnum < *rnum;
            case TokenType::OpGe: return *lnum >= *rnum;
            case TokenType::OpLe: return *lnum <= *rnum;
            default: break;
            }
        }

        // Fallback: lexicographic comparison for non-numeric values
        switch (op) {
        case TokenType::OpGt: return lhs > rhs;
        case TokenType::OpLt: return lhs < rhs;
        case TokenType::OpGe: return lhs >= rhs;
        case TokenType::OpLe: return lhs <= rhs;
        default: return false;
        }
    }

    // ── Validation-only methods (no field resolution) ──────────────────

    void parse_or_validate() {
        parse_and_validate();
        while (current_.type == TokenType::KwOr) {
            advance();
            parse_and_validate();
        }
    }

    void parse_and_validate() {
        parse_not_validate();
        while (current_.type == TokenType::KwAnd) {
            advance();
            parse_not_validate();
        }
    }

    void parse_not_validate() {
        if (current_.type == TokenType::KwNot) {
            advance();
            parse_not_validate();
            return;
        }
        parse_primary_validate();
    }

    void parse_primary_validate() {
        if (current_.type == TokenType::LParen) {
            advance();
            parse_or_validate();
            if (current_.type != TokenType::RParen)
                throw std::runtime_error("expected closing parenthesis");
            advance();
            return;
        }
        parse_comparison_validate();
    }

    void parse_comparison_validate() {
        consume_value_validate();

        auto op = current_.type;
        if (op == TokenType::OpEq || op == TokenType::OpNeq ||
            op == TokenType::OpGt || op == TokenType::OpLt ||
            op == TokenType::OpGe || op == TokenType::OpLe ||
            op == TokenType::KwContains || op == TokenType::KwStartswith) {
            advance();
            consume_value_validate();
        }
    }

    void consume_value_validate() {
        if (current_.type == TokenType::StringLit ||
            current_.type == TokenType::NumberLit ||
            current_.type == TokenType::Ident) {
            advance();
            return;
        }
        if (current_.type == TokenType::End) {
            throw std::runtime_error("unexpected end of expression");
        }
        throw std::runtime_error("expected value, got: " + current_.value);
    }
};

} // namespace

// ── Public API ───────────────────────────────────────────────────────────────

bool evaluate_compliance(std::string_view expression,
                         const std::map<std::string, std::string>& result_fields) {
    if (expression.empty())
        return true; // empty expression = always compliant

    try {
        Parser parser(expression, result_fields);
        return parser.evaluate();
    } catch (...) {
        return false; // parse error = non-compliant
    }
}

std::string validate_compliance_expression(std::string_view expression) {
    if (expression.empty())
        return {};

    try {
        static const std::map<std::string, std::string> empty_fields;
        Parser parser(expression, empty_fields);
        return parser.validate_only();
    } catch (const std::exception& e) {
        return e.what();
    }
}

} // namespace yuzu::server
