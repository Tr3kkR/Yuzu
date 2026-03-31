#include "cel_eval.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <climits>
#include <cmath>
#include <ctime>
#include <functional>
#include <optional>
#include <re2/re2.h>
#include <stdexcept>
#include <string>

namespace yuzu::server::cel {

namespace {

// ── Safety limits ───────────────────────────────────────────────────────────

constexpr size_t kMaxExpressionLength  = 4096;
constexpr int    kMaxRecursionDepth    = 16;
constexpr size_t kMaxListElements      = 1000;
constexpr size_t kMaxRegexPatternLen   = 256;
constexpr size_t kMaxStringResultLen   = 65536; // 64 KiB cap on string concatenation results
constexpr auto   kEvalTimeout          = std::chrono::milliseconds(100);

// ── Token types ─────────────────────────────────────────────────────────────

enum class TokenType {
    // Literals
    Ident,       // result.foo, myVar
    StringLit,   // 'value' or "value"
    IntLit,      // 123, -42
    DoubleLit,   // 1.5, -3.14

    // Comparison operators
    OpEq,        // ==
    OpNeq,       // !=
    OpGt,        // >
    OpLt,        // <
    OpGe,        // >=
    OpLe,        // <=

    // Logical operators
    OpAnd,       // && (also AND for backward compat)
    OpOr,        // || (also OR for backward compat)
    OpNot,       // !  (also NOT for backward compat)

    // Arithmetic operators
    OpPlus,      // +
    OpMinus,     // -
    OpMul,       // *
    OpDiv,       // /
    OpMod,       // %

    // Punctuation
    LParen,      // (
    RParen,      // )
    LBracket,    // [
    RBracket,    // ]
    Dot,         // .
    Comma,       // ,
    Question,    // ?
    Colon,       // :

    // Keywords
    KwTrue,      // true
    KwFalse,     // false
    KwNull,      // null
    KwIn,        // in
    KwContains,  // contains  (legacy, maps to .contains())
    KwStartswith,// startswith (legacy, maps to .startsWith())

    Error,       // unrecognized character
    End          // end of input
};

struct Token {
    TokenType type;
    std::string value;
};

// ── Lexer ───────────────────────────────────────────────────────────────────

class Lexer {
public:
    explicit Lexer(std::string_view input) : input_(input), pos_(0) {}

    Token next() {
        skip_whitespace();
        if (pos_ >= input_.size())
            return {TokenType::End, ""};

        char c = input_[pos_];

        // String literals
        if (c == '\'' || c == '"')
            return read_string(c);

        // Two-character operators
        if (c == '=' && peek(1) == '=') { pos_ += 2; return {TokenType::OpEq, "=="}; }
        if (c == '!' && peek(1) == '=') { pos_ += 2; return {TokenType::OpNeq, "!="}; }
        if (c == '>' && peek(1) == '=') { pos_ += 2; return {TokenType::OpGe, ">="}; }
        if (c == '<' && peek(1) == '=') { pos_ += 2; return {TokenType::OpLe, "<="}; }
        if (c == '&' && peek(1) == '&') { pos_ += 2; return {TokenType::OpAnd, "&&"}; }
        if (c == '|' && peek(1) == '|') { pos_ += 2; return {TokenType::OpOr, "||"}; }

        // Single-character operators
        if (c == '>') { ++pos_; return {TokenType::OpGt, ">"}; }
        if (c == '<') { ++pos_; return {TokenType::OpLt, "<"}; }
        if (c == '!') { ++pos_; return {TokenType::OpNot, "!"}; }
        if (c == '+') { ++pos_; return {TokenType::OpPlus, "+"}; }
        if (c == '*') { ++pos_; return {TokenType::OpMul, "*"}; }
        if (c == '/') { ++pos_; return {TokenType::OpDiv, "/"}; }
        if (c == '%') { ++pos_; return {TokenType::OpMod, "%"}; }

        // Punctuation
        if (c == '(') { ++pos_; return {TokenType::LParen, "("}; }
        if (c == ')') { ++pos_; return {TokenType::RParen, ")"}; }
        if (c == '[') { ++pos_; return {TokenType::LBracket, "["}; }
        if (c == ']') { ++pos_; return {TokenType::RBracket, "]"}; }
        if (c == '.') { ++pos_; return {TokenType::Dot, "."}; }
        if (c == ',') { ++pos_; return {TokenType::Comma, ","}; }
        if (c == '?') { ++pos_; return {TokenType::Question, "?"}; }
        if (c == ':') { ++pos_; return {TokenType::Colon, ":"}; }

        // Number (possibly negative via unary minus handled in parser)
        // or standalone minus
        if (c == '-') {
            // Check if this looks like a negative number literal (digit follows)
            if (pos_ + 1 < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_ + 1]))) {
                return read_number();
            }
            ++pos_;
            return {TokenType::OpMinus, "-"};
        }

        if (std::isdigit(static_cast<unsigned char>(c)))
            return read_number();

        // Identifier or keyword
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_')
            return read_ident();

        // Unknown character — return error token instead of silently skipping
        ++pos_;
        return Token{TokenType::Error, std::string(1, c)};
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
                switch (input_[pos_]) {
                case 'n':  val += '\n'; break;
                case 't':  val += '\t'; break;
                case '\\': val += '\\'; break;
                case '\'': val += '\''; break;
                case '"':  val += '"';  break;
                default:   val += input_[pos_]; break;
                }
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

        bool is_double = false;
        if (pos_ < input_.size() && input_[pos_] == '.' &&
            pos_ + 1 < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_ + 1]))) {
            is_double = true;
            ++pos_; // skip '.'
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_])))
                ++pos_;
        }

        // Scientific notation
        if (pos_ < input_.size() && (input_[pos_] == 'e' || input_[pos_] == 'E')) {
            is_double = true;
            ++pos_;
            if (pos_ < input_.size() && (input_[pos_] == '+' || input_[pos_] == '-'))
                ++pos_;
            while (pos_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[pos_])))
                ++pos_;
        }

        std::string val(input_.substr(start, pos_ - start));
        return {is_double ? TokenType::DoubleLit : TokenType::IntLit, val};
    }

    Token read_ident() {
        size_t start = pos_;
        while (pos_ < input_.size() &&
               (std::isalnum(static_cast<unsigned char>(input_[pos_])) || input_[pos_] == '_'))
            ++pos_;
        std::string val(input_.substr(start, pos_ - start));

        // Check for keywords (case-insensitive for backward compat)
        std::string upper = val;
        std::transform(upper.begin(), upper.end(), upper.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

        if (val == "true")           return {TokenType::KwTrue, val};
        if (val == "false")          return {TokenType::KwFalse, val};
        if (val == "null")           return {TokenType::KwNull, val};
        if (upper == "IN")           return {TokenType::KwIn, val};
        if (upper == "AND")          return {TokenType::OpAnd, val};
        if (upper == "OR")           return {TokenType::OpOr, val};
        if (upper == "NOT")          return {TokenType::OpNot, val};
        if (upper == "CONTAINS")     return {TokenType::KwContains, val};
        if (upper == "STARTSWITH")   return {TokenType::KwStartswith, val};

        return {TokenType::Ident, val};
    }
};

// ── Type coercion helpers ───────────────────────────────────────────────────

std::optional<int64_t> try_parse_int(const std::string& s) {
    if (s.empty()) return std::nullopt;
    int64_t val = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), val);
    if (ec == std::errc{} && ptr == s.data() + s.size())
        return val;
    return std::nullopt;
}

std::optional<double> try_parse_double(const std::string& s) {
    if (s.empty()) return std::nullopt;
#if defined(__cpp_lib_to_chars) && __cpp_lib_to_chars >= 201611L
    double val = 0.0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), val);
    if (ec == std::errc{} && ptr == s.data() + s.size())
        return val;
#else
    // Apple Clang fallback (std::from_chars for double may not be available)
    try {
        size_t pos = 0;
        double val = std::stod(s, &pos);
        if (pos == s.size())
            return val;
    } catch (...) {}
#endif
    return std::nullopt;
}

// Parse ISO 8601 timestamp: YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DDTHH:MM:SS+00:00
std::optional<CelTimestamp> try_parse_timestamp(const std::string& s) {
    if (s.size() < 20) return std::nullopt;
    // Quick format check: YYYY-MM-DDTHH:MM:SS
    if (s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':')
        return std::nullopt;

    std::tm tm = {};
    tm.tm_year = std::atoi(s.substr(0, 4).c_str()) - 1900;
    tm.tm_mon  = std::atoi(s.substr(5, 2).c_str()) - 1;
    tm.tm_mday = std::atoi(s.substr(8, 2).c_str());
    tm.tm_hour = std::atoi(s.substr(11, 2).c_str());
    tm.tm_min  = std::atoi(s.substr(14, 2).c_str());
    tm.tm_sec  = std::atoi(s.substr(17, 2).c_str());

    // Use timegm (POSIX) or _mkgmtime (MSVC)
#ifdef _WIN32
    auto time = _mkgmtime(&tm);
#else
    auto time = timegm(&tm);
#endif
    if (time == -1) return std::nullopt;

    return CelTimestamp{std::chrono::system_clock::from_time_t(time)};
}

/// Coerce a string variable value to a typed CelValue.
CelValue coerce_string_value(const std::string& s) {
    if (s == "true")  return true;
    if (s == "false") return false;

    if (auto i = try_parse_int(s)) return *i;
    if (auto d = try_parse_double(s)) return *d;
    if (auto ts = try_parse_timestamp(s)) return *ts;

    return s;
}

// ── CelValue helpers ────────────────────────────────────────────────────────

bool is_null(const CelValue& v) { return std::holds_alternative<std::monostate>(v); }

/// Coerce CelValue to bool (CEL truthiness rules).
bool to_bool(const CelValue& v) {
    return std::visit([](const auto& val) -> bool {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, std::monostate>) return false;
        else if constexpr (std::is_same_v<T, bool>) return val;
        else if constexpr (std::is_same_v<T, int64_t>) return val != 0;
        else if constexpr (std::is_same_v<T, double>) return val != 0.0;
        else if constexpr (std::is_same_v<T, std::string>) return !val.empty() && val != "false" && val != "0";
        else if constexpr (std::is_same_v<T, CelTimestamp>) return true;
        else if constexpr (std::is_same_v<T, CelDuration>) return val.ms.count() != 0;
        else if constexpr (std::is_same_v<T, std::shared_ptr<CelList>>) return val && !val->items.empty();
        else return false;
    }, v);
}

/// Coerce CelValue to string.
std::string to_string_val(const CelValue& v) {
    return std::visit([](const auto& val) -> std::string {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, std::monostate>) return "null";
        else if constexpr (std::is_same_v<T, bool>) return val ? "true" : "false";
        else if constexpr (std::is_same_v<T, int64_t>) return std::to_string(val);
        else if constexpr (std::is_same_v<T, double>) return std::to_string(val);
        else if constexpr (std::is_same_v<T, std::string>) return val;
        else if constexpr (std::is_same_v<T, CelTimestamp>) {
            auto t = std::chrono::system_clock::to_time_t(val.tp);
            std::tm tm_buf{};
#ifdef _WIN32
            gmtime_s(&tm_buf, &t);
#else
            gmtime_r(&t, &tm_buf);
#endif
            char buf[32];
            std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
            return buf;
        }
        else if constexpr (std::is_same_v<T, CelDuration>) return std::to_string(val.ms.count()) + "ms";
        else if constexpr (std::is_same_v<T, std::shared_ptr<CelList>>) return "[list]";
        else return "";
    }, v);
}

/// Coerce CelValue to int64.
std::optional<int64_t> to_int(const CelValue& v) {
    if (auto* i = std::get_if<int64_t>(&v)) return *i;
    if (auto* d = std::get_if<double>(&v))   return static_cast<int64_t>(*d);
    if (auto* b = std::get_if<bool>(&v))     return *b ? 1 : 0;
    if (auto* s = std::get_if<std::string>(&v)) return try_parse_int(*s);
    return std::nullopt;
}

/// Coerce CelValue to double.
std::optional<double> to_double(const CelValue& v) {
    if (auto* d = std::get_if<double>(&v))   return *d;
    if (auto* i = std::get_if<int64_t>(&v))  return static_cast<double>(*i);
    if (auto* s = std::get_if<std::string>(&v)) return try_parse_double(*s);
    return std::nullopt;
}

// ── Comparison helpers ──────────────────────────────────────────────────────

int compare_values(const CelValue& lhs, const CelValue& rhs) {
    // Same-type comparisons
    if (auto* li = std::get_if<int64_t>(&lhs)) {
        if (auto* ri = std::get_if<int64_t>(&rhs))
            return (*li < *ri) ? -1 : (*li > *ri) ? 1 : 0;
        if (auto* rd = std::get_if<double>(&rhs)) {
            double ld = static_cast<double>(*li);
            return (ld < *rd) ? -1 : (ld > *rd) ? 1 : 0;
        }
    }
    if (auto* ld = std::get_if<double>(&lhs)) {
        if (auto* rd = std::get_if<double>(&rhs))
            return (*ld < *rd) ? -1 : (*ld > *rd) ? 1 : 0;
        if (auto* ri = std::get_if<int64_t>(&rhs)) {
            double rd = static_cast<double>(*ri);
            return (*ld < rd) ? -1 : (*ld > rd) ? 1 : 0;
        }
    }
    if (auto* ls = std::get_if<std::string>(&lhs)) {
        if (auto* rs = std::get_if<std::string>(&rhs)) {
            // Try numeric comparison first
            auto ln = try_parse_int(*ls);
            auto rn = try_parse_int(*rs);
            if (ln && rn)
                return (*ln < *rn) ? -1 : (*ln > *rn) ? 1 : 0;
            auto lf = try_parse_double(*ls);
            auto rf = try_parse_double(*rs);
            if (lf && rf)
                return (*lf < *rf) ? -1 : (*lf > *rf) ? 1 : 0;
            return ls->compare(*rs);
        }
    }
    if (auto* lb = std::get_if<bool>(&lhs)) {
        if (auto* rb = std::get_if<bool>(&rhs))
            return (*lb == *rb) ? 0 : (*lb < *rb) ? -1 : 1;
    }
    if (auto* lt = std::get_if<CelTimestamp>(&lhs)) {
        if (auto* rt = std::get_if<CelTimestamp>(&rhs))
            return (lt->tp < rt->tp) ? -1 : (lt->tp > rt->tp) ? 1 : 0;
    }
    if (auto* ld = std::get_if<CelDuration>(&lhs)) {
        if (auto* rd = std::get_if<CelDuration>(&rhs))
            return (ld->ms < rd->ms) ? -1 : (ld->ms > rd->ms) ? 1 : 0;
    }

    // Cross-type: coerce to string for comparison
    return to_string_val(lhs).compare(to_string_val(rhs));
}

bool values_equal(const CelValue& lhs, const CelValue& rhs) {
    // Null comparisons
    if (is_null(lhs) && is_null(rhs)) return true;
    if (is_null(lhs) || is_null(rhs)) return false;
    return compare_values(lhs, rhs) == 0;
}

// ── Arithmetic helpers ──────────────────────────────────────────────────────

// Checked integer arithmetic helpers — return null on overflow
CelValue checked_add(int64_t a, int64_t b) {
    int64_t r;
#if defined(__GNUC__) || defined(__clang__)
    if (__builtin_add_overflow(a, b, &r)) return std::monostate{};
#else
    if ((b > 0 && a > INT64_MAX - b) || (b < 0 && a < INT64_MIN - b)) return std::monostate{};
    r = a + b;
#endif
    return r;
}

CelValue checked_sub(int64_t a, int64_t b) {
    int64_t r;
#if defined(__GNUC__) || defined(__clang__)
    if (__builtin_sub_overflow(a, b, &r)) return std::monostate{};
#else
    if ((b < 0 && a > INT64_MAX + b) || (b > 0 && a < INT64_MIN + b)) return std::monostate{};
    r = a - b;
#endif
    return r;
}

CelValue checked_mul(int64_t a, int64_t b) {
    int64_t r;
#if defined(__GNUC__) || defined(__clang__)
    if (__builtin_mul_overflow(a, b, &r)) return std::monostate{};
#else
    if (a != 0 && ((b > 0 && b > INT64_MAX / a) || (b < 0 && b < INT64_MIN / a)))
        return std::monostate{};
    r = a * b;
#endif
    return r;
}

CelValue add_values(const CelValue& lhs, const CelValue& rhs) {
    // int + int (checked)
    if (auto* li = std::get_if<int64_t>(&lhs)) {
        if (auto* ri = std::get_if<int64_t>(&rhs)) return checked_add(*li, *ri);
        if (auto* rd = std::get_if<double>(&rhs))  return static_cast<double>(*li) + *rd;
    }
    // double + double/int
    if (auto* ld = std::get_if<double>(&lhs)) {
        if (auto* rd = std::get_if<double>(&rhs))  return *ld + *rd;
        if (auto* ri = std::get_if<int64_t>(&rhs)) return *ld + static_cast<double>(*ri);
    }
    // string + string (concatenation) — bounded to prevent memory exhaustion
    if (auto* ls = std::get_if<std::string>(&lhs)) {
        if (auto* rs = std::get_if<std::string>(&rhs)) {
            if (ls->size() + rs->size() > kMaxStringResultLen)
                throw std::runtime_error("string concatenation exceeds maximum length");
            return *ls + *rs;
        }
    }
    // timestamp + duration
    if (auto* lt = std::get_if<CelTimestamp>(&lhs)) {
        if (auto* rd = std::get_if<CelDuration>(&rhs))
            return CelTimestamp{lt->tp + rd->ms};
    }
    // duration + timestamp
    if (auto* ld = std::get_if<CelDuration>(&lhs)) {
        if (auto* rt = std::get_if<CelTimestamp>(&rhs))
            return CelTimestamp{rt->tp + ld->ms};
        if (auto* rd = std::get_if<CelDuration>(&rhs))
            return CelDuration{ld->ms + rd->ms};
    }
    return std::monostate{}; // type error
}

CelValue sub_values(const CelValue& lhs, const CelValue& rhs) {
    if (auto* li = std::get_if<int64_t>(&lhs)) {
        if (auto* ri = std::get_if<int64_t>(&rhs)) return checked_sub(*li, *ri);
        if (auto* rd = std::get_if<double>(&rhs))  return static_cast<double>(*li) - *rd;
    }
    if (auto* ld = std::get_if<double>(&lhs)) {
        if (auto* rd = std::get_if<double>(&rhs))  return *ld - *rd;
        if (auto* ri = std::get_if<int64_t>(&rhs)) return *ld - static_cast<double>(*ri);
    }
    // timestamp - timestamp = duration
    if (auto* lt = std::get_if<CelTimestamp>(&lhs)) {
        if (auto* rt = std::get_if<CelTimestamp>(&rhs))
            return CelDuration{std::chrono::duration_cast<std::chrono::milliseconds>(lt->tp - rt->tp)};
        if (auto* rd = std::get_if<CelDuration>(&rhs))
            return CelTimestamp{lt->tp - rd->ms};
    }
    // duration - duration
    if (auto* ld = std::get_if<CelDuration>(&lhs)) {
        if (auto* rd = std::get_if<CelDuration>(&rhs))
            return CelDuration{ld->ms - rd->ms};
    }
    return std::monostate{};
}

CelValue mul_values(const CelValue& lhs, const CelValue& rhs) {
    if (auto* li = std::get_if<int64_t>(&lhs)) {
        if (auto* ri = std::get_if<int64_t>(&rhs)) return checked_mul(*li, *ri);
        if (auto* rd = std::get_if<double>(&rhs))  return static_cast<double>(*li) * *rd;
    }
    if (auto* ld = std::get_if<double>(&lhs)) {
        if (auto* rd = std::get_if<double>(&rhs))  return *ld * *rd;
        if (auto* ri = std::get_if<int64_t>(&rhs)) return *ld * static_cast<double>(*ri);
    }
    return std::monostate{};
}

CelValue div_values(const CelValue& lhs, const CelValue& rhs) {
    if (auto* li = std::get_if<int64_t>(&lhs)) {
        if (auto* ri = std::get_if<int64_t>(&rhs)) {
            if (*ri == 0) return std::monostate{};
            if (*li == INT64_MIN && *ri == -1) return std::monostate{}; // overflow
            return *li / *ri;
        }
        if (auto* rd = std::get_if<double>(&rhs)) {
            if (*rd == 0.0) return std::monostate{};
            return static_cast<double>(*li) / *rd;
        }
    }
    if (auto* ld = std::get_if<double>(&lhs)) {
        if (auto* rd = std::get_if<double>(&rhs)) {
            if (*rd == 0.0) return std::monostate{};
            return *ld / *rd;
        }
        if (auto* ri = std::get_if<int64_t>(&rhs)) {
            if (*ri == 0) return std::monostate{};
            return *ld / static_cast<double>(*ri);
        }
    }
    return std::monostate{};
}

CelValue mod_values(const CelValue& lhs, const CelValue& rhs) {
    if (auto* li = std::get_if<int64_t>(&lhs)) {
        if (auto* ri = std::get_if<int64_t>(&rhs)) {
            if (*ri == 0) return std::monostate{};
            if (*li == INT64_MIN && *ri == -1) return std::monostate{}; // overflow
            return *li % *ri;
        }
    }
    if (auto* ld = std::get_if<double>(&lhs)) {
        if (auto* rd = std::get_if<double>(&rhs)) {
            if (*rd == 0.0) return std::monostate{};
            return std::fmod(*ld, *rd);
        }
    }
    return std::monostate{};
}

// ── Built-in functions ──────────────────────────────────────────────────────

// String methods (called on a string receiver)
CelValue fn_size(const CelValue& receiver) {
    if (auto* s = std::get_if<std::string>(&receiver))
        return static_cast<int64_t>(s->size());
    if (auto* l = std::get_if<std::shared_ptr<CelList>>(&receiver))
        return static_cast<int64_t>((*l)->items.size());
    return std::monostate{};
}

CelValue fn_starts_with(const CelValue& receiver, const CelValue& arg) {
    auto* s = std::get_if<std::string>(&receiver);
    auto* prefix = std::get_if<std::string>(&arg);
    if (s && prefix) return s->starts_with(*prefix);
    return std::monostate{};
}

CelValue fn_ends_with(const CelValue& receiver, const CelValue& arg) {
    auto* s = std::get_if<std::string>(&receiver);
    auto* suffix = std::get_if<std::string>(&arg);
    if (s && suffix) return s->ends_with(*suffix);
    return std::monostate{};
}

CelValue fn_contains(const CelValue& receiver, const CelValue& arg) {
    auto* s = std::get_if<std::string>(&receiver);
    auto* sub = std::get_if<std::string>(&arg);
    if (s && sub) {
        // Case-insensitive for backward compat with legacy compliance_eval
        std::string lhs = *s, rhs = *sub;
        std::transform(lhs.begin(), lhs.end(), lhs.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(rhs.begin(), rhs.end(), rhs.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return lhs.find(rhs) != std::string::npos;
    }
    // List contains
    if (auto* l = std::get_if<std::shared_ptr<CelList>>(&receiver)) {
        for (const auto& item : (*l)->items) {
            if (values_equal(item, arg)) return true;
        }
        return false;
    }
    return std::monostate{};
}

CelValue fn_matches(const CelValue& receiver, const CelValue& arg) {
    auto* s = std::get_if<std::string>(&receiver);
    auto* pattern = std::get_if<std::string>(&arg);
    if (s && pattern) {
        if (pattern->size() > kMaxRegexPatternLen) return false;
        // RE2 guarantees linear-time matching — immune to ReDoS (G2-SEC-D1-001)
        RE2 re(*pattern, RE2::Quiet);
        if (!re.ok()) return false;
        return RE2::PartialMatch(*s, re);
    }
    return std::monostate{};
}

// Global functions
CelValue fn_timestamp(const CelValue& arg) {
    if (auto* s = std::get_if<std::string>(&arg)) {
        if (auto ts = try_parse_timestamp(*s)) return *ts;
    }
    return std::monostate{};
}

CelValue fn_duration(const CelValue& arg) {
    if (auto* s = std::get_if<std::string>(&arg)) {
        // Parse duration strings like "1h", "30m", "5s", "500ms"
        const auto& ds = *s;
        if (ds.empty()) return std::monostate{};

        int64_t total_ms = 0;
        size_t pos = 0;

        while (pos < ds.size()) {
            // Skip whitespace
            while (pos < ds.size() && std::isspace(static_cast<unsigned char>(ds[pos]))) ++pos;
            if (pos >= ds.size()) break;

            // Parse number
            size_t num_start = pos;
            if (ds[pos] == '-') ++pos;
            while (pos < ds.size() && std::isdigit(static_cast<unsigned char>(ds[pos]))) ++pos;
            if (pos == num_start) return std::monostate{};

            int64_t num = 0;
            auto [p, ec] = std::from_chars(ds.data() + num_start, ds.data() + pos, num);
            if (ec != std::errc{}) return std::monostate{};

            // Parse unit
            std::string unit;
            while (pos < ds.size() && std::isalpha(static_cast<unsigned char>(ds[pos])))
                unit += ds[pos++];

            if (unit == "ms")      total_ms += num;
            else if (unit == "s")  total_ms += num * 1000;
            else if (unit == "m")  total_ms += num * 60 * 1000;
            else if (unit == "h")  total_ms += num * 3600 * 1000;
            else if (unit == "d")  total_ms += num * 86400 * 1000;
            else return std::monostate{};
        }

        return CelDuration{std::chrono::milliseconds(total_ms)};
    }
    if (auto* i = std::get_if<int64_t>(&arg))
        return CelDuration{std::chrono::milliseconds(*i)};
    return std::monostate{};
}

CelValue fn_int(const CelValue& arg) {
    if (auto i = to_int(arg)) return *i;
    if (auto* s = std::get_if<std::string>(&arg)) {
        if (auto i = try_parse_int(*s)) return *i;
    }
    return std::monostate{};
}

CelValue fn_double_cast(const CelValue& arg) {
    if (auto d = to_double(arg)) return *d;
    return std::monostate{};
}

CelValue fn_string(const CelValue& arg) {
    return to_string_val(arg);
}

// ── Parser ──────────────────────────────────────────────────────────────────

class Parser {
public:
    Parser(std::string_view input, const std::map<std::string, std::string>& vars,
           bool validate_only = false)
        : lexer_(input), vars_(vars), validate_only_(validate_only),
          deadline_(std::chrono::steady_clock::now() + kEvalTimeout) {
        advance();
    }

    // RAII depth guard for recursion limit + wall-clock timeout (G2-SEC-D1-002)
    struct DepthGuard {
        int& depth;
        const std::chrono::steady_clock::time_point& deadline;
        explicit DepthGuard(int& d, const std::chrono::steady_clock::time_point& dl)
            : depth(d), deadline(dl) {
            if (++depth > kMaxRecursionDepth)
                throw std::runtime_error("expression exceeds maximum nesting depth");
            if (std::chrono::steady_clock::now() > deadline)
                throw std::runtime_error("expression evaluation timeout exceeded");
        }
        ~DepthGuard() { --depth; }
    };

    CelValue evaluate() {
        auto result = parse_ternary();
        return result;
    }

    std::string validate() {
        try {
            parse_ternary();
            if (current_.type != TokenType::End)
                return "unexpected token: " + current_.value;
            return {};
        } catch (const std::runtime_error& e) {
            return e.what();
        }
    }

private:
    Lexer lexer_;
    Token current_;
    const std::map<std::string, std::string>& vars_;
    bool validate_only_;
    int depth_{0};
    std::chrono::steady_clock::time_point deadline_;

    void advance() { current_ = lexer_.next(); }

    void expect(TokenType t, const char* msg) {
        if (current_.type != t)
            throw std::runtime_error(msg);
        advance();
    }

    // ── Grammar productions ─────────────────────────────────────────────

    CelValue parse_ternary() {
        DepthGuard guard(depth_, deadline_);
        auto cond = parse_or();
        if (current_.type == TokenType::Question) {
            advance();
            auto then_val = parse_ternary();
            expect(TokenType::Colon, "expected ':' in ternary expression");
            auto else_val = parse_ternary();
            if (validate_only_) return std::monostate{};
            return to_bool(cond) ? then_val : else_val;
        }
        return cond;
    }

    CelValue parse_or() {
        auto lhs = parse_and();
        while (current_.type == TokenType::OpOr) {
            advance();
            // Short-circuit: if lhs is true, skip evaluation of rhs
            if (!validate_only_ && to_bool(lhs)) {
                parse_and(); // parse but discard for syntax validation
                // lhs stays true
            } else {
                auto rhs = parse_and();
                if (!validate_only_)
                    lhs = to_bool(lhs) || to_bool(rhs);
            }
        }
        return lhs;
    }

    CelValue parse_and() {
        auto lhs = parse_not_legacy();
        while (current_.type == TokenType::OpAnd) {
            advance();
            // Short-circuit: if lhs is false, skip evaluation of rhs
            if (!validate_only_ && !to_bool(lhs)) {
                parse_not_legacy(); // parse but discard for syntax validation
                // lhs stays false
            } else {
                auto rhs = parse_not_legacy();
                if (!validate_only_)
                    lhs = to_bool(lhs) && to_bool(rhs);
            }
        }
        return lhs;
    }

    // Handle legacy NOT keyword at lower precedence (between AND and rel_expr).
    // The CEL ! operator is handled in parse_unary() at higher precedence.
    CelValue parse_not_legacy() {
        if (current_.type == TokenType::OpNot && current_.value != "!") {
            // This is the keyword NOT (case-insensitive), which has lower
            // precedence than comparison operators for backward compat
            DepthGuard guard(depth_, deadline_);
            advance();
            auto val = parse_not_legacy();
            if (validate_only_) return std::monostate{};
            return !to_bool(val);
        }
        return parse_rel();
    }

    CelValue parse_rel() {
        auto lhs = parse_add();

        // 'in' operator
        if (current_.type == TokenType::KwIn) {
            advance();
            auto rhs = parse_add();
            if (validate_only_) return std::monostate{};
            // Check if lhs is in rhs (rhs should be a list)
            if (auto* l = std::get_if<std::shared_ptr<CelList>>(&rhs)) {
                for (const auto& item : (*l)->items) {
                    if (values_equal(lhs, item)) return true;
                }
                return false;
            }
            // Check string containment as fallback
            if (auto* rs = std::get_if<std::string>(&rhs)) {
                auto ls = to_string_val(lhs);
                return rs->find(ls) != std::string::npos;
            }
            return false;
        }

        // Legacy 'contains' keyword (x contains 'y')
        if (current_.type == TokenType::KwContains) {
            advance();
            auto rhs = parse_add();
            if (validate_only_) return std::monostate{};
            return fn_contains(lhs, rhs);
        }

        // Legacy 'startswith' keyword (x startswith 'y')
        if (current_.type == TokenType::KwStartswith) {
            advance();
            auto rhs = parse_add();
            if (validate_only_) return std::monostate{};
            // Case-insensitive for backward compat
            auto* ls = std::get_if<std::string>(&lhs);
            auto* rs = std::get_if<std::string>(&rhs);
            if (ls && rs) {
                std::string l = *ls, r = *rs;
                std::transform(l.begin(), l.end(), l.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                std::transform(r.begin(), r.end(), r.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                return l.starts_with(r);
            }
            return false;
        }

        // Comparison operators
        auto op = current_.type;
        if (op == TokenType::OpEq || op == TokenType::OpNeq ||
            op == TokenType::OpGt || op == TokenType::OpLt ||
            op == TokenType::OpGe || op == TokenType::OpLe) {
            advance();
            auto rhs = parse_add();
            if (validate_only_) return std::monostate{};

            int cmp = compare_values(lhs, rhs);
            switch (op) {
            case TokenType::OpEq:  return values_equal(lhs, rhs);
            case TokenType::OpNeq: return !values_equal(lhs, rhs);
            case TokenType::OpLt:  return cmp < 0;
            case TokenType::OpGt:  return cmp > 0;
            case TokenType::OpLe:  return cmp <= 0;
            case TokenType::OpGe:  return cmp >= 0;
            default: break;
            }
        }

        return lhs;
    }

    CelValue parse_add() {
        auto lhs = parse_mul();
        while (current_.type == TokenType::OpPlus || current_.type == TokenType::OpMinus) {
            auto op = current_.type;
            advance();
            auto rhs = parse_mul();
            if (!validate_only_) {
                lhs = (op == TokenType::OpPlus) ? add_values(lhs, rhs) : sub_values(lhs, rhs);
            }
        }
        return lhs;
    }

    CelValue parse_mul() {
        auto lhs = parse_unary();
        while (current_.type == TokenType::OpMul || current_.type == TokenType::OpDiv ||
               current_.type == TokenType::OpMod) {
            auto op = current_.type;
            advance();
            auto rhs = parse_unary();
            if (!validate_only_) {
                if (op == TokenType::OpMul)      lhs = mul_values(lhs, rhs);
                else if (op == TokenType::OpDiv)  lhs = div_values(lhs, rhs);
                else                              lhs = mod_values(lhs, rhs);
            }
        }
        return lhs;
    }

    CelValue parse_unary() {
        if (current_.type == TokenType::OpNot) {
            DepthGuard guard(depth_, deadline_);
            advance();
            auto val = parse_unary();
            if (validate_only_) return std::monostate{};
            return !to_bool(val);
        }
        if (current_.type == TokenType::OpMinus) {
            advance();
            auto val = parse_unary();
            if (validate_only_) return std::monostate{};
            if (auto* i = std::get_if<int64_t>(&val)) {
                if (*i == INT64_MIN) return std::monostate{}; // overflow
                return -(*i);
            }
            if (auto* d = std::get_if<double>(&val))  return -(*d);
            return std::monostate{};
        }
        return parse_member();
    }

    CelValue parse_member() {
        auto obj = parse_primary();

        while (true) {
            if (current_.type == TokenType::Dot) {
                advance();
                // Accept identifiers and keywords that can be method names
                // (contains/startswith are lexed as keywords but are also method names)
                if (current_.type != TokenType::Ident &&
                    current_.type != TokenType::KwContains &&
                    current_.type != TokenType::KwStartswith &&
                    current_.type != TokenType::KwIn)
                    throw std::runtime_error("expected identifier after '.'");
                std::string member = current_.value;
                advance();

                // Method call
                if (current_.type == TokenType::LParen) {
                    advance();
                    std::vector<CelValue> args;
                    if (current_.type != TokenType::RParen) {
                        args.push_back(parse_ternary());
                        while (current_.type == TokenType::Comma) {
                            advance();
                            args.push_back(parse_ternary());
                        }
                    }
                    expect(TokenType::RParen, "expected ')' after method arguments");

                    if (validate_only_) { obj = std::monostate{}; continue; }

                    // Dispatch method calls
                    if (member == "size" && args.empty())
                        obj = fn_size(obj);
                    else if (member == "startsWith" && args.size() == 1)
                        obj = fn_starts_with(obj, args[0]);
                    else if (member == "endsWith" && args.size() == 1)
                        obj = fn_ends_with(obj, args[0]);
                    else if (member == "contains" && args.size() == 1)
                        obj = fn_contains(obj, args[0]);
                    else if (member == "matches" && args.size() == 1)
                        obj = fn_matches(obj, args[0]);
                    else
                        obj = std::monostate{}; // unknown method
                } else {
                    // Property access — not needed for current use cases
                    // but we still handle it for forward compat
                    if (validate_only_) { obj = std::monostate{}; continue; }
                    obj = std::monostate{};
                }
            } else if (current_.type == TokenType::LBracket) {
                advance();
                auto idx = parse_ternary();
                expect(TokenType::RBracket, "expected ']'");
                if (validate_only_) { obj = std::monostate{}; continue; }

                // List index access — copy before reassigning obj, because
                // obj holds the shared_ptr<CelList> whose items we're reading;
                // assigning to obj destroys that shared_ptr first on MSVC.
                if (auto* l = std::get_if<std::shared_ptr<CelList>>(&obj)) {
                    if (auto* ii = std::get_if<int64_t>(&idx)) {
                        auto i = *ii;
                        auto& items = (*l)->items;
                        if (i >= 0 && static_cast<size_t>(i) < items.size()) {
                            CelValue extracted = items[static_cast<size_t>(i)];
                            obj = extracted;
                        } else {
                            obj = std::monostate{};
                        }
                    } else {
                        obj = std::monostate{};
                    }
                } else {
                    obj = std::monostate{};
                }
            } else {
                break;
            }
        }
        return obj;
    }

    CelValue parse_primary() {
        // Parenthesized expression
        if (current_.type == TokenType::LParen) {
            advance();
            auto val = parse_ternary();
            expect(TokenType::RParen, "expected closing parenthesis");
            return val;
        }

        // List literal
        if (current_.type == TokenType::LBracket) {
            advance();
            auto list = std::make_shared<CelList>();
            if (current_.type != TokenType::RBracket) {
                list->items.push_back(parse_ternary());
                while (current_.type == TokenType::Comma) {
                    advance();
                    if (list->items.size() >= kMaxListElements)
                        throw std::runtime_error("list exceeds maximum element count");
                    list->items.push_back(parse_ternary());
                }
            }
            expect(TokenType::RBracket, "expected ']'");
            if (validate_only_) return std::monostate{};
            return list;
        }

        // Literals
        if (current_.type == TokenType::KwTrue) {
            advance();
            return validate_only_ ? CelValue{std::monostate{}} : CelValue{true};
        }
        if (current_.type == TokenType::KwFalse) {
            advance();
            return validate_only_ ? CelValue{std::monostate{}} : CelValue{false};
        }
        if (current_.type == TokenType::KwNull) {
            advance();
            return std::monostate{};
        }
        if (current_.type == TokenType::IntLit) {
            std::string val = current_.value;
            advance();
            if (validate_only_) return std::monostate{};
            if (auto i = try_parse_int(val)) return *i;
            return std::monostate{};
        }
        if (current_.type == TokenType::DoubleLit) {
            std::string val = current_.value;
            advance();
            if (validate_only_) return std::monostate{};
            if (auto d = try_parse_double(val)) return *d;
            return std::monostate{};
        }
        if (current_.type == TokenType::StringLit) {
            std::string val = current_.value;
            advance();
            if (validate_only_) return std::monostate{};
            return val;
        }

        // Identifier — variable reference or global function call
        if (current_.type == TokenType::Ident) {
            std::string name = current_.value;
            advance();

            // Handle dotted identifiers for variable access (result.field)
            // and method calls (result.field.method())
            while (current_.type == TokenType::Dot) {
                advance(); // consume dot
                if (current_.type != TokenType::Ident &&
                    current_.type != TokenType::KwContains &&
                    current_.type != TokenType::KwStartswith &&
                    current_.type != TokenType::KwIn)
                    break; // dot not followed by ident — stop

                std::string member = current_.value;
                advance(); // look ahead past member name

                if (current_.type == TokenType::LParen) {
                    // Method call on variable: name.member(args...)
                    advance(); // consume '('
                    std::vector<CelValue> args;
                    if (current_.type != TokenType::RParen) {
                        args.push_back(parse_ternary());
                        while (current_.type == TokenType::Comma) {
                            advance();
                            args.push_back(parse_ternary());
                        }
                    }
                    expect(TokenType::RParen, "expected ')' after method arguments");

                    if (validate_only_) return std::monostate{};

                    CelValue receiver = resolve_variable(name);

                    if (member == "size" && args.empty())
                        return fn_size(receiver);
                    if (member == "startsWith" && args.size() == 1)
                        return fn_starts_with(receiver, args[0]);
                    if (member == "endsWith" && args.size() == 1)
                        return fn_ends_with(receiver, args[0]);
                    if (member == "contains" && args.size() == 1)
                        return fn_contains(receiver, args[0]);
                    if (member == "matches" && args.size() == 1)
                        return fn_matches(receiver, args[0]);
                    return std::monostate{};
                }

                // Not a method call — dotted field name (e.g. result.status)
                // current_ already holds the token after the member name
                name += "." + member;
                // Continue looping for deeper nesting (a.b.c)
            }

            // Global function call
            if (current_.type == TokenType::LParen) {
                advance();
                std::vector<CelValue> args;
                if (current_.type != TokenType::RParen) {
                    args.push_back(parse_ternary());
                    while (current_.type == TokenType::Comma) {
                        advance();
                        args.push_back(parse_ternary());
                    }
                }
                expect(TokenType::RParen, "expected ')' after function arguments");

                if (validate_only_) return std::monostate{};

                // Dispatch global functions
                if (name == "timestamp" && args.size() == 1)
                    return fn_timestamp(args[0]);
                if (name == "duration" && args.size() == 1)
                    return fn_duration(args[0]);
                if (name == "int" && args.size() == 1)
                    return fn_int(args[0]);
                if (name == "double" && args.size() == 1)
                    return fn_double_cast(args[0]);
                if (name == "string" && args.size() == 1)
                    return fn_string(args[0]);
                if (name == "size" && args.size() == 1)
                    return fn_size(args[0]);
                if (name == "has" && args.size() == 1) {
                    // has() checks if a variable exists and is non-empty
                    auto* s = std::get_if<std::string>(&args[0]);
                    if (s) {
                        auto it = vars_.find(*s);
                        return it != vars_.end() && !it->second.empty();
                    }
                    return !is_null(args[0]);
                }
                if (name == "matches" && args.size() == 2)
                    return fn_matches(args[0], args[1]);
                return std::monostate{};
            }

            if (validate_only_) return std::monostate{};

            return resolve_variable(name);
        }

        // End of input or unexpected token
        if (current_.type == TokenType::End)
            throw std::runtime_error("unexpected end of expression");
        throw std::runtime_error("unexpected token: " + current_.value);
    }

    CelValue resolve_variable(const std::string& name) {
        // Handle boolean literals
        if (name == "true")  return true;
        if (name == "false") return false;
        if (name == "null")  return std::monostate{};

        // Resolve result.field references
        if (name.starts_with("result.")) {
            auto field = name.substr(7);
            auto it = vars_.find(std::string(field));
            if (it != vars_.end())
                return coerce_string_value(it->second);
            return std::string{};
        }

        // Direct field lookup
        auto it = vars_.find(name);
        if (it != vars_.end())
            return coerce_string_value(it->second);

        // Return as string literal (for unresolved identifiers)
        return name;
    }
};

// ── Migration helpers ───────────────────────────────────────────────────────

struct MigrationToken {
    enum Type { Word, Op, Str, Other };
    Type type;
    std::string value;
    std::string original; // original text including surrounding whitespace
};

} // namespace

// ── Public API ──────────────────────────────────────────────────────────────

CelValue evaluate(std::string_view expression,
                  const std::map<std::string, std::string>& variables) {
    if (expression.empty())
        return true; // empty = always compliant (backward compat)
    if (expression.size() > kMaxExpressionLength)
        return std::monostate{};

    try {
        Parser parser(expression, variables);
        return parser.evaluate();
    } catch (...) {
        return std::monostate{};
    }
}

bool evaluate_bool(std::string_view expression,
                   const std::map<std::string, std::string>& variables) {
    if (expression.empty())
        return true;
    if (expression.size() > kMaxExpressionLength)
        return false;

    try {
        Parser parser(expression, variables);
        return to_bool(parser.evaluate());
    } catch (...) {
        return false;
    }
}

std::optional<bool> evaluate_tri(std::string_view expression,
                                 const std::map<std::string, std::string>& variables) {
    if (expression.empty())
        return true;
    if (expression.size() > kMaxExpressionLength)
        return std::nullopt; // error, not false

    try {
        Parser parser(expression, variables);
        auto result = parser.evaluate();
        // monostate = evaluation error (missing variable, type error, timeout)
        if (std::holds_alternative<std::monostate>(result))
            return std::nullopt;
        return to_bool(result);
    } catch (...) {
        return std::nullopt; // parse error or timeout
    }
}

std::string validate(std::string_view expression) {
    if (expression.empty())
        return {};
    if (expression.size() > kMaxExpressionLength)
        return "expression exceeds maximum length";

    try {
        static const std::map<std::string, std::string> empty_vars;
        Parser parser(expression, empty_vars, /*validate_only=*/true);
        return parser.validate();
    } catch (const std::exception& e) {
        return e.what();
    }
}

std::string migrate_expression(std::string_view legacy_expression) {
    if (legacy_expression.empty())
        return {};

    // First pass: scan for legacy keywords that need transformation.
    // If none are found, return the original expression unchanged to
    // preserve exact formatting.
    bool needs_migration = false;
    {
        Lexer scan(legacy_expression);
        while (true) {
            Token t = scan.next();
            if (t.type == TokenType::End) break;

            if (t.type == TokenType::KwContains || t.type == TokenType::KwStartswith) {
                needs_migration = true;
                break;
            }
            if (t.type == TokenType::OpAnd && t.value != "&&") {
                needs_migration = true;
                break;
            }
            if (t.type == TokenType::OpOr && t.value != "||") {
                needs_migration = true;
                break;
            }
            if (t.type == TokenType::OpNot && t.value != "!") {
                needs_migration = true;
                break;
            }
        }
    }
    if (!needs_migration)
        return std::string(legacy_expression);

    // Second pass: rebuild the expression with CEL syntax.
    // We do character-level scanning to preserve spacing as much as possible.
    std::string input(legacy_expression);
    std::string result;

    // Use a token-based approach: re-lex and rebuild
    Lexer lex(legacy_expression);

    struct TokInfo {
        Token tok;
        size_t end_pos; // position in input after this token
    };
    std::vector<TokInfo> tokens;
    while (true) {
        Token t = lex.next();
        tokens.push_back({t, lex.position()});
        if (t.type == TokenType::End) break;
    }

    for (size_t i = 0; i < tokens.size(); ++i) {
        auto& ti = tokens[i];
        auto& t = ti.tok;
        if (t.type == TokenType::End) break;

        // Keyword AND -> &&
        if (t.type == TokenType::OpAnd && t.value != "&&") {
            if (!result.empty() && result.back() != ' ') result += ' ';
            result += "&&";
            if (i + 1 < tokens.size() && tokens[i + 1].tok.type != TokenType::End)
                result += ' ';
            continue;
        }
        // Keyword OR -> ||
        if (t.type == TokenType::OpOr && t.value != "||") {
            if (!result.empty() && result.back() != ' ') result += ' ';
            result += "||";
            if (i + 1 < tokens.size() && tokens[i + 1].tok.type != TokenType::End)
                result += ' ';
            continue;
        }
        // Keyword NOT -> !
        if (t.type == TokenType::OpNot && t.value != "!") {
            if (!result.empty() && result.back() != ' ') result += ' ';
            result += "!";
            continue;
        }

        // contains/startswith: transform from infix to method call
        if (t.type == TokenType::KwContains || t.type == TokenType::KwStartswith) {
            // Remove trailing space from result (method call attaches to receiver)
            while (!result.empty() && result.back() == ' ') result.pop_back();

            std::string method = (t.type == TokenType::KwContains) ? "contains" : "startsWith";
            result += "." + method + "(";

            // Next token is the argument
            if (i + 1 < tokens.size() && tokens[i + 1].tok.type != TokenType::End) {
                ++i;
                auto& arg = tokens[i].tok;
                if (arg.type == TokenType::StringLit)
                    result += "'" + arg.value + "'";
                else
                    result += arg.value;
            }
            result += ")";
            continue;
        }

        // Default: add spacing and reproduce token
        if (!result.empty() && result.back() != ' ' && result.back() != '(' &&
            result.back() != '!' && result.back() != '[' && result.back() != '.') {
            if (t.type != TokenType::RParen && t.type != TokenType::RBracket &&
                t.type != TokenType::Comma && t.type != TokenType::Dot) {
                result += ' ';
            }
        }

        if (t.type == TokenType::StringLit)
            result += "'" + t.value + "'";
        else
            result += t.value;
    }

    return result;
}

} // namespace yuzu::server::cel
