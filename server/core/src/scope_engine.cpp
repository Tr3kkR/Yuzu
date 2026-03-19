#include "scope_engine.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <format>
#include <regex>
#include <sstream>
#include <string>

namespace yuzu::scope {

namespace {

// -- Tokenizer ---------------------------------------------------------------

enum class TokenType {
    Ident,
    String,
    LParen,
    RParen,
    Comma,
    OpEq,
    OpNeq,
    OpLike,
    OpLt,
    OpGt,
    OpLe,
    OpGe,
    OpIn,
    OpContains,
    OpMatches,
    OpExists,
    KwLen,
    KwStartswith,
    KwAnd,
    KwOr,
    KwNot,
    Eof,
    Error
};

struct Token {
    TokenType type;
    std::string value;
    std::size_t pos{0};
};

class Tokenizer {
public:
    explicit Tokenizer(std::string_view input) : input_(input) {}

    Token next() {
        skip_whitespace();
        if (pos_ >= input_.size())
            return {TokenType::Eof, "", pos_};

        auto start = pos_;
        char c = input_[pos_];

        // Single-char tokens
        if (c == '(') {
            ++pos_;
            return {TokenType::LParen, "(", start};
        }
        if (c == ')') {
            ++pos_;
            return {TokenType::RParen, ")", start};
        }
        if (c == ',') {
            ++pos_;
            return {TokenType::Comma, ",", start};
        }

        // Operators
        if (c == '=' && pos_ + 1 < input_.size() && input_[pos_ + 1] == '=') {
            pos_ += 2;
            return {TokenType::OpEq, "==", start};
        }
        if (c == '!' && pos_ + 1 < input_.size() && input_[pos_ + 1] == '=') {
            pos_ += 2;
            return {TokenType::OpNeq, "!=", start};
        }
        if (c == '<' && pos_ + 1 < input_.size() && input_[pos_ + 1] == '=') {
            pos_ += 2;
            return {TokenType::OpLe, "<=", start};
        }
        if (c == '>' && pos_ + 1 < input_.size() && input_[pos_ + 1] == '=') {
            pos_ += 2;
            return {TokenType::OpGe, ">=", start};
        }
        if (c == '<') {
            ++pos_;
            return {TokenType::OpLt, "<", start};
        }
        if (c == '>') {
            ++pos_;
            return {TokenType::OpGt, ">", start};
        }

        // Quoted string
        if (c == '"' || c == '\'') {
            return read_string(c, start);
        }

        // Identifier or keyword
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_' || c == '*') {
            return read_ident(start);
        }

        // Number (for numeric comparisons)
        if (std::isdigit(static_cast<unsigned char>(c)) || c == '-') {
            return read_number(start);
        }

        return {TokenType::Error, std::string(1, c), start};
    }

    Token peek() {
        auto saved = pos_;
        auto tok = next();
        pos_ = saved;
        return tok;
    }

    std::size_t position() const { return pos_; }

private:
    std::string_view input_;
    std::size_t pos_{0};

    void skip_whitespace() {
        while (pos_ < input_.size() && std::isspace(static_cast<unsigned char>(input_[pos_])))
            ++pos_;
    }

    Token read_string(char quote, std::size_t start) {
        ++pos_; // skip opening quote
        std::string val;
        while (pos_ < input_.size() && input_[pos_] != quote) {
            if (input_[pos_] == '\\' && pos_ + 1 < input_.size()) {
                char ch = input_[pos_ + 1];
                if (ch == quote || ch == '\\') {
                    ++pos_; // only consume backslash for quote or backslash
                }
            }
            val += input_[pos_++];
        }
        if (pos_ >= input_.size()) {
            return {TokenType::Error, "unterminated string", start};
        }
        ++pos_; // skip closing quote
        return {TokenType::String, val, start};
    }

    Token read_ident(std::size_t start) {
        while (pos_ < input_.size()) {
            char ch = input_[pos_];
            if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' || ch == '.' ||
                ch == ':' || ch == '-' || ch == '*') {
                ++pos_;
            } else {
                break;
            }
        }
        auto val = std::string(input_.substr(start, pos_ - start));

        // Keywords (case-insensitive)
        auto upper = val;
        std::transform(upper.begin(), upper.end(), upper.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

        if (upper == "AND")
            return {TokenType::KwAnd, val, start};
        if (upper == "OR")
            return {TokenType::KwOr, val, start};
        if (upper == "NOT")
            return {TokenType::KwNot, val, start};
        if (upper == "LIKE")
            return {TokenType::OpLike, val, start};
        if (upper == "IN")
            return {TokenType::OpIn, val, start};
        if (upper == "CONTAINS")
            return {TokenType::OpContains, val, start};
        if (upper == "MATCHES")
            return {TokenType::OpMatches, val, start};
        if (upper == "EXISTS")
            return {TokenType::OpExists, val, start};
        if (upper == "LEN")
            return {TokenType::KwLen, val, start};
        if (upper == "STARTSWITH")
            return {TokenType::KwStartswith, val, start};

        return {TokenType::Ident, val, start};
    }

    Token read_number(std::size_t start) {
        if (input_[pos_] == '-')
            ++pos_;
        while (pos_ < input_.size() &&
               (std::isdigit(static_cast<unsigned char>(input_[pos_])) || input_[pos_] == '.')) {
            ++pos_;
        }
        return {TokenType::Ident, std::string(input_.substr(start, pos_ - start)), start};
    }
};

// -- Parser ------------------------------------------------------------------

class Parser {
public:
    explicit Parser(std::string_view input) : tokenizer_(input), input_(input) {}

    std::expected<Expression, std::string> parse_expression() {
        auto result = parse_or();
        if (!result)
            return result;

        auto tok = tokenizer_.peek();
        if (tok.type != TokenType::Eof) {
            return std::unexpected(
                std::format("unexpected token '{}' at position {}", tok.value, tok.pos));
        }
        return result;
    }

private:
    Tokenizer tokenizer_;
    std::string_view input_;
    int depth_{0};
    static constexpr int kMaxDepth = 10;

    std::expected<Expression, std::string> parse_or() {
        auto left = parse_and();
        if (!left)
            return left;

        while (tokenizer_.peek().type == TokenType::KwOr) {
            tokenizer_.next(); // consume OR
            auto right = parse_and();
            if (!right)
                return right;

            auto comb = std::make_unique<Combinator>();
            comb->op = CombOp::Or;
            comb->children.push_back(std::move(*left));
            comb->children.push_back(std::move(*right));
            left = Expression{std::move(comb)};
        }
        return left;
    }

    std::expected<Expression, std::string> parse_and() {
        auto left = parse_not();
        if (!left)
            return left;

        while (tokenizer_.peek().type == TokenType::KwAnd) {
            tokenizer_.next(); // consume AND
            auto right = parse_not();
            if (!right)
                return right;

            auto comb = std::make_unique<Combinator>();
            comb->op = CombOp::And;
            comb->children.push_back(std::move(*left));
            comb->children.push_back(std::move(*right));
            left = Expression{std::move(comb)};
        }
        return left;
    }

    std::expected<Expression, std::string> parse_not() {
        if (tokenizer_.peek().type == TokenType::KwNot) {
            tokenizer_.next(); // consume NOT
            auto child = parse_not();
            if (!child)
                return child;

            auto comb = std::make_unique<Combinator>();
            comb->op = CombOp::Not;
            comb->children.push_back(std::move(*child));
            return Expression{std::move(comb)};
        }
        return parse_primary();
    }

    std::expected<Expression, std::string> parse_primary() {
        auto tok = tokenizer_.peek();

        if (tok.type == TokenType::LParen) {
            tokenizer_.next(); // consume (
            if (++depth_ > kMaxDepth) {
                return std::unexpected("maximum nesting depth exceeded");
            }
            auto result = parse_or();
            --depth_;
            if (!result)
                return result;

            auto close = tokenizer_.next();
            if (close.type != TokenType::RParen) {
                return std::unexpected(
                    std::format("expected ')' at position {}, got '{}'", close.pos, close.value));
            }
            return result;
        }

        // EXISTS <attribute> — unary operator (checks non-empty)
        if (tok.type == TokenType::OpExists) {
            tokenizer_.next(); // consume EXISTS
            auto attr_tok = tokenizer_.next();
            if (attr_tok.type != TokenType::Ident) {
                return std::unexpected(std::format(
                    "expected attribute after EXISTS at position {}", attr_tok.pos));
            }
            Condition cond;
            cond.attribute = attr_tok.value;
            cond.op = CompOp::Exists;
            return Expression{std::move(cond)};
        }

        // LEN(<attribute>) <op> <value> — string length comparison
        if (tok.type == TokenType::KwLen) {
            tokenizer_.next(); // consume LEN
            auto lp = tokenizer_.next();
            if (lp.type != TokenType::LParen) {
                return std::unexpected(std::format(
                    "expected '(' after LEN at position {}", lp.pos));
            }
            auto attr_tok = tokenizer_.next();
            if (attr_tok.type != TokenType::Ident) {
                return std::unexpected(std::format(
                    "expected attribute inside LEN() at position {}", attr_tok.pos));
            }
            auto rp = tokenizer_.next();
            if (rp.type != TokenType::RParen) {
                return std::unexpected(std::format(
                    "expected ')' after LEN attribute at position {}", rp.pos));
            }
            // Now read comparison operator and value
            auto op_tok = tokenizer_.next();
            CompOp op;
            switch (op_tok.type) {
            case TokenType::OpEq:  op = CompOp::Eq;  break;
            case TokenType::OpNeq: op = CompOp::Neq; break;
            case TokenType::OpLt:  op = CompOp::Lt;  break;
            case TokenType::OpGt:  op = CompOp::Gt;  break;
            case TokenType::OpLe:  op = CompOp::Le;  break;
            case TokenType::OpGe:  op = CompOp::Ge;  break;
            default:
                return std::unexpected(std::format(
                    "expected comparison operator after LEN() at position {}", op_tok.pos));
            }
            auto val_tok = tokenizer_.next();
            if (val_tok.type != TokenType::Ident && val_tok.type != TokenType::String) {
                return std::unexpected(std::format(
                    "expected value after LEN() operator at position {}", val_tok.pos));
            }
            // Encode as synthetic attribute __len:<attr>
            Condition cond;
            cond.attribute = "__len:" + attr_tok.value;
            cond.op = op;
            cond.value = val_tok.value;
            return Expression{std::move(cond)};
        }

        // STARTSWITH(<attribute>, <prefix>) — prefix check
        if (tok.type == TokenType::KwStartswith) {
            tokenizer_.next(); // consume STARTSWITH
            auto lp = tokenizer_.next();
            if (lp.type != TokenType::LParen) {
                return std::unexpected(std::format(
                    "expected '(' after STARTSWITH at position {}", lp.pos));
            }
            auto attr_tok = tokenizer_.next();
            if (attr_tok.type != TokenType::Ident) {
                return std::unexpected(std::format(
                    "expected attribute inside STARTSWITH() at position {}", attr_tok.pos));
            }
            auto comma = tokenizer_.next();
            if (comma.type != TokenType::Comma) {
                return std::unexpected(std::format(
                    "expected ',' in STARTSWITH() at position {}", comma.pos));
            }
            auto val_tok = tokenizer_.next();
            if (val_tok.type != TokenType::Ident && val_tok.type != TokenType::String) {
                return std::unexpected(std::format(
                    "expected prefix value in STARTSWITH() at position {}", val_tok.pos));
            }
            auto rp = tokenizer_.next();
            if (rp.type != TokenType::RParen) {
                return std::unexpected(std::format(
                    "expected ')' after STARTSWITH() at position {}", rp.pos));
            }
            // Encode as synthetic attribute __startswith:<attr>
            Condition cond;
            cond.attribute = "__startswith:" + attr_tok.value;
            cond.op = CompOp::Eq;
            cond.value = val_tok.value;
            return Expression{std::move(cond)};
        }

        return parse_condition();
    }

    std::expected<Expression, std::string> parse_condition() {
        auto attr_tok = tokenizer_.next();
        if (attr_tok.type != TokenType::Ident) {
            return std::unexpected(std::format("expected attribute name at position {}, got '{}'",
                                               attr_tok.pos, attr_tok.value));
        }

        auto op_tok = tokenizer_.next();
        CompOp op;
        switch (op_tok.type) {
        case TokenType::OpEq:
            op = CompOp::Eq;
            break;
        case TokenType::OpNeq:
            op = CompOp::Neq;
            break;
        case TokenType::OpLike:
            op = CompOp::Like;
            break;
        case TokenType::OpLt:
            op = CompOp::Lt;
            break;
        case TokenType::OpGt:
            op = CompOp::Gt;
            break;
        case TokenType::OpLe:
            op = CompOp::Le;
            break;
        case TokenType::OpGe:
            op = CompOp::Ge;
            break;
        case TokenType::OpIn:
            op = CompOp::In;
            break;
        case TokenType::OpContains:
            op = CompOp::Contains;
            break;
        case TokenType::OpMatches:
            op = CompOp::Matches;
            break;
        default:
            return std::unexpected(std::format("expected operator at position {}, got '{}'",
                                               op_tok.pos, op_tok.value));
        }

        if (op == CompOp::In) {
            return parse_in_values(attr_tok.value);
        }

        auto val_tok = tokenizer_.next();
        if (val_tok.type != TokenType::Ident && val_tok.type != TokenType::String) {
            return std::unexpected(
                std::format("expected value at position {}, got '{}'", val_tok.pos, val_tok.value));
        }

        Condition cond;
        cond.attribute = attr_tok.value;
        cond.op = op;
        cond.value = val_tok.value;
        return Expression{std::move(cond)};
    }

    std::expected<Expression, std::string> parse_in_values(const std::string& attr) {
        auto lparen = tokenizer_.next();
        if (lparen.type != TokenType::LParen) {
            return std::unexpected(std::format("expected '(' after IN at position {}", lparen.pos));
        }

        std::vector<std::string> values;
        while (true) {
            auto val = tokenizer_.next();
            if (val.type != TokenType::Ident && val.type != TokenType::String) {
                return std::unexpected(
                    std::format("expected value in IN list at position {}", val.pos));
            }
            values.push_back(val.value);

            auto next = tokenizer_.peek();
            if (next.type == TokenType::Comma) {
                tokenizer_.next();
            } else {
                break;
            }
        }

        auto rparen = tokenizer_.next();
        if (rparen.type != TokenType::RParen) {
            return std::unexpected(std::format("expected ')' at position {}", rparen.pos));
        }

        Condition cond;
        cond.attribute = attr;
        cond.op = CompOp::In;
        cond.values = std::move(values);
        return Expression{std::move(cond)};
    }
};

// -- Helper: case-insensitive compare ----------------------------------------

bool ci_equal(std::string_view a, std::string_view b) {
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

// -- Helper: wildcard match (for LIKE) ----------------------------------------

bool wildcard_match(std::string_view pattern, std::string_view text) {
    std::size_t pi = 0, ti = 0;
    std::size_t star_p = std::string_view::npos, star_t = 0;

    while (ti < text.size()) {
        if (pi < pattern.size() && (std::tolower(static_cast<unsigned char>(pattern[pi])) ==
                                        std::tolower(static_cast<unsigned char>(text[ti])) ||
                                    pattern[pi] == '?')) {
            ++pi;
            ++ti;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
            star_p = pi++;
            star_t = ti;
        } else if (star_p != std::string_view::npos) {
            pi = star_p + 1;
            ti = ++star_t;
        } else {
            return false;
        }
    }
    while (pi < pattern.size() && pattern[pi] == '*')
        ++pi;
    return pi == pattern.size();
}

// -- Helper: try numeric comparison ------------------------------------------

bool try_numeric_compare(std::string_view a, std::string_view b, CompOp op) {
    double da = 0, db = 0;

#if defined(__cpp_lib_to_chars) && __cpp_lib_to_chars >= 201611L
    auto [pa, eca] = std::from_chars(a.data(), a.data() + a.size(), da);
    auto [pb, ecb] = std::from_chars(b.data(), b.data() + b.size(), db);
    if (eca != std::errc{} || ecb != std::errc{}) {
#else
    // Apple libc++ does not support std::from_chars for floating-point types,
    // so we fall back to std::stod on platforms that lack the feature.
    try {
        da = std::stod(std::string(a));
        db = std::stod(std::string(b));
    } catch (...) {
#endif
        // Fall back to string comparison
        int cmp = std::string(a).compare(std::string(b));
        switch (op) {
        case CompOp::Lt:
            return cmp < 0;
        case CompOp::Gt:
            return cmp > 0;
        case CompOp::Le:
            return cmp <= 0;
        case CompOp::Ge:
            return cmp >= 0;
        default:
            return false;
        }
    }

    switch (op) {
    case CompOp::Lt:
        return da < db;
    case CompOp::Gt:
        return da > db;
    case CompOp::Le:
        return da <= db;
    case CompOp::Ge:
        return da >= db;
    default:
        return false;
    }
}

// -- Helper: contains (case-insensitive substring) ----------------------------

bool ci_contains(std::string_view haystack, std::string_view needle) {
    if (needle.empty())
        return true;
    if (haystack.size() < needle.size())
        return false;
    for (std::size_t i = 0; i <= haystack.size() - needle.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (std::tolower(static_cast<unsigned char>(haystack[i + j])) !=
                std::tolower(static_cast<unsigned char>(needle[j]))) {
                match = false;
                break;
            }
        }
        if (match)
            return true;
    }
    return false;
}

// -- Evaluate a single condition ---------------------------------------------

// -- Helper: case-insensitive startswith ------------------------------------

bool ci_starts_with(std::string_view text, std::string_view prefix) {
    if (prefix.size() > text.size())
        return false;
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(text[i])) !=
            std::tolower(static_cast<unsigned char>(prefix[i]))) {
            return false;
        }
    }
    return true;
}

bool eval_condition(const Condition& cond, const AttributeResolver& resolver) {
    // Synthetic __startswith:<attr> — resolve real attribute then prefix-check
    if (cond.attribute.starts_with("__startswith:")) {
        auto real_attr = cond.attribute.substr(13);
        auto resolved = resolver(real_attr);
        return ci_starts_with(resolved, cond.value);
    }

    // Synthetic __len:<attr> — resolve real attribute then compare length
    if (cond.attribute.starts_with("__len:")) {
        auto real_attr = cond.attribute.substr(6);
        auto resolved = resolver(real_attr);
        auto len_str = std::to_string(resolved.size());
        // Eq/Neq: direct string compare (both are numeric strings)
        if (cond.op == CompOp::Eq) return len_str == cond.value;
        if (cond.op == CompOp::Neq) return len_str != cond.value;
        return try_numeric_compare(len_str, cond.value, cond.op);
    }

    auto resolved = resolver(cond.attribute);

    switch (cond.op) {
    case CompOp::Eq:
        return ci_equal(resolved, cond.value);
    case CompOp::Neq:
        return !ci_equal(resolved, cond.value);
    case CompOp::Like:
        return wildcard_match(cond.value, resolved);
    case CompOp::Matches: {
        try {
            std::regex re(cond.value, std::regex::ECMAScript | std::regex::icase);
            return std::regex_search(std::string(resolved), re);
        } catch (const std::regex_error&) {
            return false;
        }
    }
    case CompOp::Exists:
        return !resolved.empty();
    case CompOp::Lt:
    case CompOp::Gt:
    case CompOp::Le:
    case CompOp::Ge:
        return try_numeric_compare(resolved, cond.value, cond.op);
    case CompOp::In:
        for (const auto& v : cond.values) {
            if (ci_equal(resolved, v))
                return true;
        }
        return false;
    case CompOp::Contains:
        return ci_contains(resolved, cond.value);
    }
    return false;
}

} // anonymous namespace

// -- Public API --------------------------------------------------------------

std::expected<Expression, std::string> parse(std::string_view input) {
    if (input.empty()) {
        return std::unexpected("empty expression");
    }
    Parser parser(input);
    return parser.parse_expression();
}

bool evaluate(const Expression& expr, const AttributeResolver& resolver) {
    return std::visit(
        [&](const auto& node) -> bool {
            using T = std::decay_t<decltype(node)>;
            if constexpr (std::is_same_v<T, Condition>) {
                return eval_condition(node, resolver);
            } else {
                // std::unique_ptr<Combinator>
                const auto& comb = *node;
                switch (comb.op) {
                case CombOp::And:
                    for (const auto& child : comb.children) {
                        if (!evaluate(child, resolver))
                            return false;
                    }
                    return true;
                case CombOp::Or:
                    for (const auto& child : comb.children) {
                        if (evaluate(child, resolver))
                            return true;
                    }
                    return false;
                case CombOp::Not:
                    return !comb.children.empty() && !evaluate(comb.children[0], resolver);
                }
                return false;
            }
        },
        expr);
}

std::expected<void, std::string> validate(std::string_view input) {
    auto result = parse(input);
    if (result)
        return {};
    return std::unexpected(result.error());
}

} // namespace yuzu::scope
