/**
 * pii_checksum.hpp — Pure checksum/check-digit implementations for the
 * pii_scan plugin.
 *
 * Every algorithm here corresponds 1:1 to a named entry in
 * content/pii-rules/00-manifest.yaml's `checksumAlgorithms` registry —
 * that file is the human-readable specification (with sources and
 * confidence ratings); this file is the executable form. Names match
 * exactly so the rule engine can dispatch by string (the `checksum`
 * field on an embedded rule) without a second mapping table to keep in
 * sync.
 *
 * No filesystem/network access — pure functions over strings, fully
 * unit-testable (see tests/unit/test_pii_checksum.cpp), matching the
 * ssh_hardening_rules.hpp / vuln_scan cve_rules.hpp convention of
 * separating pure logic from OS-specific I/O.
 *
 * A function returns std::nullopt when the algorithm is inherently
 * non-validatable (no checksum publicly exists, or the described
 * algorithm's final substitution table could not be verified during
 * research — see the corresponding manifest entry's `notes`) rather
 * than fabricating a pass/fail. Callers MUST treat nullopt as "cannot
 * validate", not as "invalid".
 */
#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::pii::checksum {

// ── small helpers ────────────────────────────────────────────────────────

namespace detail {

inline int digit_value(char c) {
    return (c >= '0' && c <= '9') ? (c - '0') : -1;
}

// Mathematical modulo (always non-negative), distinct from C++'s
// truncating %, needed for a couple of algorithms whose spec computes an
// intermediate negative value before reducing.
inline long long mod_nonneg(long long a, long long m) {
    long long r = a % m;
    return r < 0 ? r + m : r;
}

// Strips everything except ASCII letters/digits (removes -, ., space,
// etc.) and upper-cases letters. Most identifiers are matched with
// cosmetic separators that must be stripped before checksum arithmetic.
inline std::string clean_alnum_upper(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (std::isalnum(static_cast<unsigned char>(c))) {
            out += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
    }
    return out;
}

inline bool all_digits(std::string_view s) {
    return !s.empty() &&
           std::all_of(s.begin(), s.end(), [](char c) { return digit_value(c) >= 0; });
}

} // namespace detail

// ── Luhn (mod-10) — generic, reused by ~10 named algorithms ────────────

// Validates a complete digit string including its own trailing check digit.
inline bool luhn_valid(std::string_view digits) {
    if (!detail::all_digits(digits))
        return false;
    int sum = 0;
    bool double_it = false; // start from the rightmost digit, don't double it
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        int d = detail::digit_value(*it);
        if (double_it) {
            d *= 2;
            if (d > 9)
                d -= 9;
        }
        sum += d;
        double_it = !double_it;
    }
    return sum % 10 == 0;
}

// Computes the check digit that would need to be appended to `payload`
// (which does NOT include a check digit) to make the result Luhn-valid.
inline int luhn_check_digit(std::string_view payload) {
    if (!detail::all_digits(payload))
        return -1;
    int sum = 0;
    bool double_it = true; // the digit immediately left of the (absent) check digit doubles first
    for (auto it = payload.rbegin(); it != payload.rend(); ++it) {
        int d = detail::digit_value(*it);
        if (double_it) {
            d *= 2;
            if (d > 9)
                d -= 9;
        }
        sum += d;
        double_it = !double_it;
    }
    return (10 - (sum % 10)) % 10;
}

// ── Verhoeff — dihedral-group D5 checksum (Aadhaar, Luxembourg C2) ──────

namespace detail {

inline constexpr int kVerhoeffD[10][10] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
    {2, 3, 4, 0, 1, 7, 8, 9, 5, 6}, {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
    {4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
    {6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
    {8, 7, 6, 5, 9, 3, 2, 1, 0, 4}, {9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
};
inline constexpr int kVerhoeffP[8][10] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
    {5, 8, 0, 3, 7, 9, 6, 1, 4, 2}, {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
    {9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
    {2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
};

} // namespace detail

// Validates a complete digit string including its own trailing check digit.
inline bool verhoeff_valid(std::string_view digits) {
    if (!detail::all_digits(digits))
        return false;
    int c = 0;
    int len = static_cast<int>(digits.size());
    for (int i = 0; i < len; ++i) {
        int d = detail::digit_value(digits[static_cast<size_t>(len - 1 - i)]);
        c = detail::kVerhoeffD[c][detail::kVerhoeffP[i % 8][d]];
    }
    return c == 0;
}

// ── ISO 7064 family ─────────────────────────────────────────────────────

// MOD 11-10 (Germany Steuer-ID). `digits10` = the first 10 digits (not
// including the check digit). Returns the computed check digit (0-9).
inline int iso7064_mod11_10_check_digit(std::string_view digits10) {
    if (!detail::all_digits(digits10) || digits10.size() != 10)
        return -1;
    int m = 10;
    for (char c : digits10) {
        int d = detail::digit_value(c);
        m = (d + m) % 10;
        if (m == 0)
            m = 10;
        m = (2 * m) % 11;
    }
    int check = 11 - m;
    if (check == 10)
        check = 0;
    return check;
}

// MOD 11-10, Croatia OIB's presentation (verbatim python-stdnum
// recurrence). Validates all 11 digits including the check digit.
inline bool iso7064_mod11_10_hr_valid(std::string_view digits11) {
    if (!detail::all_digits(digits11) || digits11.size() != 11)
        return false;
    int check = 5;
    for (char c : digits11) {
        int n = detail::digit_value(c);
        int effective = (check == 0) ? 10 : check;
        check = ((effective * 2) % 11 + n) % 10;
    }
    return check == 1;
}

// MOD 11-2 (China Resident Identity Card). `digits17` = first 17 digits.
// Returns the check character ('0'-'9' or 'X'), or '\0' on bad input.
inline char iso7064_mod11_2_check_char(std::string_view digits17) {
    if (!detail::all_digits(digits17) || digits17.size() != 17)
        return '\0';
    static constexpr int kWeights[17] = {7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
    long long sum = 0;
    for (size_t i = 0; i < 17; ++i) {
        sum += static_cast<long long>(detail::digit_value(digits17[i])) * kWeights[i];
    }
    int remainder = static_cast<int>(sum % 11);
    static constexpr std::array<char, 11> kTable = {'1', '0', '9', '8', '7', '6',
                                                      '5', '4', '3', '2', 'X'};
    return kTable[static_cast<size_t>(remainder)];
}

// ── IBAN — ISO 7064 MOD 97-10 ───────────────────────────────────────────

inline bool iban_mod97_valid(std::string_view iban_raw) {
    std::string iban = detail::clean_alnum_upper(iban_raw);
    if (iban.size() < 5)
        return false;
    // Move first 4 chars to the end.
    std::string rearranged = iban.substr(4) + iban.substr(0, 4);
    // Convert to the numeral string (letters -> two-digit values 10-35),
    // then reduce mod 97 incrementally (no bignum needed).
    long long remainder = 0;
    for (char c : rearranged) {
        if (c >= '0' && c <= '9') {
            remainder = (remainder * 10 + (c - '0')) % 97;
        } else if (c >= 'A' && c <= 'Z') {
            int v = c - 'A' + 10; // 10-35, always two digits
            remainder = (remainder * 10 + v / 10) % 97;
            remainder = (remainder * 10 + v % 10) % 97;
        } else {
            return false;
        }
    }
    return remainder == 1;
}

// ── Generic weighted-sum helper (used by many named algorithms below) ──

// sum(digit[i] * weights[i]) for i in [0, min(digits.size(), weights.size())).
inline long long weighted_sum(std::string_view digits, const std::vector<int>& weights) {
    long long sum = 0;
    size_t n = std::min(digits.size(), weights.size());
    for (size_t i = 0; i < n; ++i) {
        int d = detail::digit_value(digits[i]);
        if (d < 0)
            return -1;
        sum += static_cast<long long>(d) * weights[i];
    }
    return sum;
}

// ── Named algorithms (one function per 00-manifest.yaml registry entry) ─

// generic credit cards / Canada SIN / Sweden personnummer / South Africa
// ID / Israel Teudat Zehut / Saudi Arabia national ID / Greece AMKA /
// IMEI / Luxembourg matricule C1: all delegate to luhn_valid directly at
// the call site — no wrapper needed, the dispatcher (pii_rules.hpp) maps
// "luhn" straight to luhn_valid.

inline bool us_aba_routing_weighted(std::string_view digits9) {
    if (digits9.size() != 9 || !detail::all_digits(digits9))
        return false;
    static const std::vector<int> kWeights = {3, 7, 1, 3, 7, 1, 3, 7, 1};
    long long sum = weighted_sum(digits9, kWeights);
    return sum >= 0 && sum % 10 == 0;
}

inline int vin_iso3779_transliterate(char c) {
    static const std::array<std::pair<char, int>, 23> kTable = {{
        {'A', 1}, {'B', 2}, {'C', 3}, {'D', 4}, {'E', 5}, {'F', 6}, {'G', 7}, {'H', 8},
        {'J', 1}, {'K', 2}, {'L', 3}, {'M', 4}, {'N', 5}, {'P', 7}, {'R', 9}, {'S', 2},
        {'T', 3}, {'U', 4}, {'V', 5}, {'W', 6}, {'X', 7}, {'Y', 8}, {'Z', 9},
    }};
    if (c >= '0' && c <= '9')
        return c - '0';
    for (auto& [ch, v] : kTable) {
        if (ch == c)
            return v;
    }
    return -1; // I, O, Q — never valid in a VIN
}

inline bool vin_iso3779_weighted(std::string_view vin17) {
    if (vin17.size() != 17)
        return false;
    static constexpr int kWeights[17] = {8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2};
    long long sum = 0;
    for (size_t i = 0; i < 17; ++i) {
        int v = vin_iso3779_transliterate(static_cast<char>(std::toupper(
            static_cast<unsigned char>(vin17[i]))));
        if (v < 0)
            return false;
        sum += static_cast<long long>(v) * kWeights[i];
    }
    int r = static_cast<int>(sum % 11);
    char expected = (r == 10) ? 'X' : static_cast<char>('0' + r);
    return std::toupper(static_cast<unsigned char>(vin17[8])) == expected;
}

inline bool imei_luhn(std::string_view digits15) {
    return digits15.size() == 15 && luhn_valid(digits15);
}

inline bool us_npi_luhn_prefixed(std::string_view digits10) {
    if (digits10.size() != 10 || !detail::all_digits(digits10))
        return false;
    std::string prefixed = "80840" + std::string(digits10.substr(0, 9));
    int check = luhn_check_digit(prefixed);
    return check >= 0 && static_cast<char>('0' + check) == digits10[9];
}

inline bool pl_pesel_weighted(std::string_view digits11) {
    if (digits11.size() != 11 || !detail::all_digits(digits11))
        return false;
    static const std::vector<int> kWeights = {1, 3, 7, 9, 1, 3, 7, 9, 1, 3};
    long long sum = weighted_sum(digits11.substr(0, 10), kWeights);
    int check = static_cast<int>((10 - (sum % 10)) % 10);
    return detail::digit_value(digits11[10]) == check;
}

inline bool se_personnummer_luhn(std::string_view raw) {
    // Strip century prefix (if present) and separator, leaving exactly 10
    // digits (6-digit date + 4-digit serial incl. check digit).
    std::string cleaned = detail::clean_alnum_upper(raw);
    if (cleaned.size() == 11) // century prefix present (YYYYMMDDXXX-like)
        cleaned = cleaned.substr(2);
    if (cleaned.size() != 10)
        return false;
    return luhn_valid(cleaned);
}

inline bool au_tfn_weighted_mod11(std::string_view digits) {
    std::string d(digits);
    if (d.size() == 8)
        d = "0" + d;
    if (d.size() != 9 || !detail::all_digits(d))
        return false;
    static const std::vector<int> kWeights = {1, 4, 3, 7, 5, 8, 6, 9, 10};
    long long sum = weighted_sum(d, kWeights);
    return sum >= 0 && sum % 11 == 0;
}

inline bool au_medicare_weighted(std::string_view digits9) {
    if (digits9.size() != 9 || !detail::all_digits(digits9))
        return false;
    static const std::vector<int> kWeights = {1, 3, 7, 9, 1, 3, 7, 9};
    long long sum = weighted_sum(digits9.substr(0, 8), kWeights);
    return detail::digit_value(digits9[8]) == static_cast<int>(sum % 10);
}

inline bool br_cpf_weighted(std::string_view raw) {
    std::string digits = detail::clean_alnum_upper(raw);
    if (digits.size() != 11 || !detail::all_digits(digits))
        return false;
    if (std::all_of(digits.begin(), digits.end(), [&](char c) { return c == digits[0]; }))
        return false; // repeated-digit rejection (e.g. 111.111.111-11)
    static const std::vector<int> kW1 = {10, 9, 8, 7, 6, 5, 4, 3, 2};
    long long s1 = weighted_sum(digits.substr(0, 9), kW1);
    int r1 = static_cast<int>(s1 % 11);
    int y = (r1 < 2) ? 0 : (11 - r1);
    if (detail::digit_value(digits[9]) != y)
        return false;
    static const std::vector<int> kW2 = {11, 10, 9, 8, 7, 6, 5, 4, 3, 2};
    long long s2 = weighted_sum(digits.substr(0, 10), kW2);
    int r2 = static_cast<int>(s2 % 11);
    int z = (r2 < 2) ? 0 : (11 - r2);
    return detail::digit_value(digits[10]) == z;
}

namespace detail {
inline int cnpj_char_value(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'Z')
        return static_cast<int>(c) - 48; // ASCII code - 48, per SEFAZ alphanumeric spec
    return -1;
}
} // namespace detail

inline bool br_cnpj_weighted(std::string_view raw) {
    std::string s = detail::clean_alnum_upper(raw);
    if (s.size() != 14)
        return false;
    std::vector<int> vals(14);
    for (size_t i = 0; i < 14; ++i) {
        vals[static_cast<size_t>(i)] = detail::cnpj_char_value(s[i]);
        if (vals[static_cast<size_t>(i)] < 0)
            return false;
    }
    static const std::vector<int> kW1 = {5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2};
    long long s1 = 0;
    for (size_t i = 0; i < 12; ++i)
        s1 += static_cast<long long>(vals[i]) * kW1[i];
    int r1 = static_cast<int>(s1 % 11);
    int d13 = (r1 < 2) ? 0 : (11 - r1);
    if (vals[12] != d13)
        return false;
    static const std::vector<int> kW2 = {6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2};
    long long s2 = 0;
    for (size_t i = 0; i < 13; ++i)
        s2 += static_cast<long long>(vals[i]) * kW2[i];
    int r2 = static_cast<int>(s2 % 11);
    int d14 = (r2 < 2) ? 0 : (11 - r2);
    return vals[13] == d14;
}

inline bool jp_my_number_weighted(std::string_view digits12) {
    if (digits12.size() != 12 || !detail::all_digits(digits12))
        return false;
    static const std::vector<int> kW1 = {6, 5, 4, 3, 2};
    static const std::vector<int> kW2 = {7, 6, 5, 4, 3, 2};
    long long sum = weighted_sum(digits12.substr(0, 5), kW1) +
                    weighted_sum(digits12.substr(5, 6), kW2);
    int remainder = static_cast<int>(sum % 11);
    int check = 11 - remainder;
    if (check > 9)
        check = 0;
    return detail::digit_value(digits12[11]) == check;
}

inline bool kr_rrn_weighted_mod11(std::string_view raw) {
    std::string d = detail::clean_alnum_upper(raw);
    if (d.size() != 13 || !detail::all_digits(d))
        return false;
    static const std::vector<int> kWeights = {2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5};
    long long sum = weighted_sum(d.substr(0, 12), kWeights);
    int check = static_cast<int>((11 - (sum % 11)) % 10);
    return detail::digit_value(d[12]) == check;
}

// prefix: 'S','T','F','G','M'. digits: the 7 body digits. check_letter:
// the trailing letter to validate.
inline bool sg_nric_weighted(char prefix, std::string_view digits7, char check_letter) {
    if (digits7.size() != 7 || !detail::all_digits(digits7))
        return false;
    static const std::vector<int> kWeights = {2, 7, 6, 5, 4, 3, 2};
    long long sum = weighted_sum(digits7, kWeights);
    prefix = static_cast<char>(std::toupper(static_cast<unsigned char>(prefix)));
    int offset = 0;
    std::string_view table;
    if (prefix == 'T' || prefix == 'G') {
        offset = 4;
        table = (prefix == 'T') ? "JZIHGFEDCBA" : "XWUTRQPNMLK";
    } else if (prefix == 'M') {
        offset = 3;
        table = "TRQPNJLKXWU";
    } else if (prefix == 'S' || prefix == 'F') {
        offset = 0;
        table = (prefix == 'S') ? "JZIHGFEDCBA" : "XWUTRQPNMLK";
    } else {
        return false;
    }
    int remainder = static_cast<int>((sum + offset) % 11);
    char expected = table[static_cast<size_t>(remainder)];
    return std::toupper(static_cast<unsigned char>(check_letter)) == expected;
}

inline bool mx_curp_check(std::string_view curp18) {
    // clean_alnum_upper() drops non-ASCII bytes via std::isalnum, which
    // for a UTF-8 'Ñ' (2 bytes: 0xC3 0x91) would silently strip both
    // bytes and desync every subsequent position. Reject any raw input
    // containing a non-ASCII byte up front instead — CURP holders whose
    // surname contains Ñ are a genuine, disclosed gap in this checker
    // (position-2 of a CURP is the rare place Ñ can appear per RENAPO's
    // rules), not a silent miscalculation.
    for (unsigned char c : curp18) {
        if (c > 127)
            return false;
    }
    std::string s = detail::clean_alnum_upper(curp18);
    if (s.size() != 18)
        return false;
    // Value table: digits map to self (0-9); A-Z map to 10-35. CURP's real
    // alphabet inserts Ñ at value 24 (between N=23 and O=25) — since Ñ
    // can't reach here (rejected above), plain A-Z=10-35 is exact for
    // every string this function actually validates.
    auto value_of = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'A' && c <= 'Z')
            return 10 + (c - 'A');
        return -1;
    };
    static const std::vector<int> kWeights = {19, 18, 17, 16, 15, 14, 13, 12, 11,
                                               10, 9,  8,  7,  6,  5,  4,  3};
    long long sum = 0;
    for (size_t i = 0; i < 17; ++i) {
        int v = value_of(s[i]);
        if (v < 0)
            return false;
        sum += static_cast<long long>(v) * kWeights[i];
    }
    int check = static_cast<int>(10 - (sum % 10));
    if (check == 10)
        check = 0;
    return detail::digit_value(s[17]) == check;
}

inline bool ar_cuil_weighted(std::string_view raw) {
    std::string d = detail::clean_alnum_upper(raw);
    if (d.size() != 11 || !detail::all_digits(d))
        return false;
    static const std::vector<int> kWeights = {5, 4, 3, 2, 7, 6, 5, 4, 3, 2};
    long long sum = weighted_sum(d.substr(0, 10), kWeights);
    int r = static_cast<int>(sum % 11);
    int check = 11 - r;
    if (check == 11)
        check = 0;
    if (check == 10)
        return false; // AFIP never issues this — computed 10 means invalid
    return detail::digit_value(d[10]) == check;
}

inline bool cl_rut_mod11(std::string_view raw) {
    std::string s = detail::clean_alnum_upper(raw);
    if (s.size() < 2)
        return false;
    char check_char = s.back();
    std::string body = s.substr(0, s.size() - 1);
    if (!detail::all_digits(body))
        return false;
    long long sum = 0;
    int weight = 2;
    for (auto it = body.rbegin(); it != body.rend(); ++it) {
        sum += static_cast<long long>(detail::digit_value(*it)) * weight;
        weight = (weight == 7) ? 2 : weight + 1;
    }
    int r = static_cast<int>(sum % 11);
    int check_value = 11 - r;
    char expected;
    if (check_value == 11)
        expected = '0';
    else if (check_value == 10)
        expected = 'K';
    else
        expected = static_cast<char>('0' + check_value);
    return std::toupper(static_cast<unsigned char>(check_char)) == expected;
}

// Belgium: try both the pre-2000 and post-2000 interpretations since the
// matched text alone can't disambiguate the century.
inline bool be_nrn_mod97(std::string_view raw) {
    std::string d = detail::clean_alnum_upper(raw);
    if (d.size() != 11 || !detail::all_digits(d))
        return false;
    std::string n9 = d.substr(0, 9);
    int provided = std::stoi(d.substr(9, 2));
    long long remainder_pre2000 = 0;
    for (char c : n9)
        remainder_pre2000 = (remainder_pre2000 * 10 + detail::digit_value(c)) % 97;
    int check_pre2000 = static_cast<int>(97 - remainder_pre2000);
    if (check_pre2000 == provided)
        return true;
    long long remainder_post2000 = 2; // prepend '2'
    for (char c : n9)
        remainder_post2000 = (remainder_post2000 * 10 + detail::digit_value(c)) % 97;
    int check_post2000 = static_cast<int>(97 - remainder_post2000);
    return check_post2000 == provided;
}

inline bool at_vnr_weighted(std::string_view raw) {
    std::string d = detail::clean_alnum_upper(raw);
    if (d.size() != 10 || !detail::all_digits(d))
        return false;
    static const std::vector<int> kWeights = {3, 7, 9, 5, 8, 4, 2, 1, 6};
    std::string nine;
    nine += d[0];
    nine += d[1];
    nine += d[2];
    nine += d[4];
    nine += d[5];
    nine += d[6];
    nine += d[7];
    nine += d[8];
    nine += d[9];
    long long sum = weighted_sum(nine, kWeights);
    return detail::digit_value(d[3]) == static_cast<int>(sum % 11);
}

inline bool pt_nif_weighted(std::string_view digits9) {
    if (digits9.size() != 9 || !detail::all_digits(digits9))
        return false;
    static const std::vector<int> kWeights = {9, 8, 7, 6, 5, 4, 3, 2};
    long long sum = weighted_sum(digits9.substr(0, 8), kWeights);
    int r = static_cast<int>(sum % 11);
    int check = (r == 0 || r == 1) ? 0 : (11 - r);
    return detail::digit_value(digits9[8]) == check;
}

inline bool fi_hetu_mod31(std::string_view digits9, char check_char) {
    if (digits9.size() != 9 || !detail::all_digits(digits9))
        return false;
    static const std::string kTable = "0123456789ABCDEFHJKLMNPRSTUVWXY";
    long long n = std::stoll(std::string(digits9));
    int idx = static_cast<int>(n % 31);
    return std::toupper(static_cast<unsigned char>(check_char)) == kTable[static_cast<size_t>(idx)];
}

// Czech/Slovak Rodné číslo: modern strict rule (remainder must land
// exactly on the printed check digit 0-9; pre-1985 numbers whose
// remainder is 10 are a known, disclosed exception this does not model —
// see 00-manifest.yaml cz_sk_rc_mod11 notes).
inline bool cz_sk_rc_mod11(std::string_view raw) {
    std::string d = detail::clean_alnum_upper(raw);
    if (d.size() == 9)
        return false; // pre-1954 numbers carry no checksum — not applicable, not invalid
    if (d.size() != 10 || !detail::all_digits(d))
        return false;
    long long n9 = std::stoll(d.substr(0, 9));
    int r = static_cast<int>(n9 % 11);
    if (r == 10)
        return false; // strict modern rule
    return detail::digit_value(d[9]) == r;
}

inline bool ro_cnp_weighted(std::string_view digits13) {
    if (digits13.size() != 13 || !detail::all_digits(digits13))
        return false;
    static const std::vector<int> kWeights = {2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9};
    long long sum = weighted_sum(digits13.substr(0, 12), kWeights);
    int r = static_cast<int>(sum % 11);
    int check = (r == 10) ? 1 : r;
    return detail::digit_value(digits13[12]) == check;
}

inline bool hu_taj_weighted(std::string_view digits9) {
    if (digits9.size() != 9 || !detail::all_digits(digits9))
        return false;
    long long sum = 0;
    for (size_t i = 0; i < 8; ++i) {
        int weight = (i % 2 == 0) ? 3 : 7; // positions 1,3,5,7 (0-idx 0,2,4,6) -> 3; else 7
        sum += static_cast<long long>(detail::digit_value(digits9[i])) * weight;
    }
    return detail::digit_value(digits9[8]) == static_cast<int>(sum % 10);
}

inline bool ch_ahv_ean13(std::string_view raw) {
    std::string d = detail::clean_alnum_upper(raw);
    if (d.size() != 13 || !detail::all_digits(d))
        return false;
    long long sum = 0;
    for (size_t i = 0; i < 12; ++i) {
        int weight = (i % 2 == 0) ? 1 : 3;
        sum += static_cast<long long>(detail::digit_value(d[i])) * weight;
    }
    int check = static_cast<int>((10 - (sum % 10)) % 10);
    return detail::digit_value(d[12]) == check;
}

inline bool bg_egn_weighted(std::string_view digits10) {
    if (digits10.size() != 10 || !detail::all_digits(digits10))
        return false;
    static const std::vector<int> kWeights = {2, 4, 8, 5, 10, 9, 7, 3, 6};
    long long sum = weighted_sum(digits10.substr(0, 9), kWeights);
    int check = static_cast<int>((sum % 11) % 10);
    return detail::digit_value(digits10[9]) == check;
}

// Luxembourg matricule: C1 (Luhn) + C2 (Verhoeff), both over the same
// 11-digit prefix, each validated as a complete (prefix+own check digit)
// string.
inline bool lu_matricule_dual(std::string_view digits13) {
    if (digits13.size() != 13 || !detail::all_digits(digits13))
        return false;
    std::string prefix_plus_c1(digits13.substr(0, 12));
    std::string prefix_plus_c2 = std::string(digits13.substr(0, 11)) + std::string(1, digits13[12]);
    return luhn_valid(prefix_plus_c1) && verhoeff_valid(prefix_plus_c2);
}

inline bool si_emso_weighted(std::string_view digits13) {
    if (digits13.size() != 13 || !detail::all_digits(digits13))
        return false;
    static const std::vector<int> kWeights = {7, 6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2};
    long long sum = weighted_sum(digits13.substr(0, 12), kWeights);
    int check = static_cast<int>(((11 - (sum % 11)) % 11) % 10);
    return detail::digit_value(digits13[12]) == check;
}

inline bool baltic_two_pass_mod11(std::string_view digits11) {
    if (digits11.size() != 11 || !detail::all_digits(digits11))
        return false;
    static const std::vector<int> kW1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 1};
    long long s1 = weighted_sum(digits11.substr(0, 10), kW1);
    int p1 = static_cast<int>(s1 % 11);
    int check;
    if (p1 == 10) {
        static const std::vector<int> kW2 = {3, 4, 5, 6, 7, 8, 9, 1, 2, 3};
        long long s2 = weighted_sum(digits11.substr(0, 10), kW2);
        check = static_cast<int>((s2 % 11) % 10);
    } else {
        check = p1 % 10;
    }
    return detail::digit_value(digits11[10]) == check;
}

inline bool lv_old_weighted(std::string_view raw) {
    std::string d = detail::clean_alnum_upper(raw);
    if (d.size() != 11 || !detail::all_digits(d))
        return false;
    static const std::vector<int> kWeights = {1, 6, 3, 7, 9, 10, 5, 8, 4, 2};
    long long sum = weighted_sum(d.substr(0, 10), kWeights);
    int z = static_cast<int>(detail::mod_nonneg(detail::mod_nonneg(1 - sum, 11), 10));
    return detail::digit_value(d[10]) == z;
}

inline bool no_fodselsnummer_mod11(std::string_view digits11) {
    if (digits11.size() != 11 || !detail::all_digits(digits11))
        return false;
    static const std::vector<int> kW1 = {3, 7, 6, 1, 8, 9, 4, 5, 2};
    long long s1 = weighted_sum(digits11.substr(0, 9), kW1);
    int k1 = static_cast<int>(detail::mod_nonneg(11 - (s1 % 11), 11));
    if (k1 == 10 || detail::digit_value(digits11[9]) != k1)
        return false;
    static const std::vector<int> kW2 = {5, 4, 3, 2, 7, 6, 5, 4, 3, 2};
    std::string ten = std::string(digits11.substr(0, 9)) + std::to_string(k1);
    long long s2 = weighted_sum(ten, kW2);
    int k2 = static_cast<int>(detail::mod_nonneg(11 - (s2 % 11), 11));
    if (k2 == 10)
        return false;
    return detail::digit_value(digits11[10]) == k2;
}

inline bool fr_nir_mod97(std::string_view raw) {
    std::string d = detail::clean_alnum_upper(raw);
    // Expect 15 chars: 13-digit body (with 2A/2B possibly literal) + 2-digit key.
    if (d.size() != 15)
        return false;
    std::string body = d.substr(0, 13);
    std::string key_str = d.substr(13, 2);
    if (!detail::all_digits(key_str))
        return false;
    int provided_key = std::stoi(key_str);
    // Corsica substitution on the 2-char department field (positions 5-6, 0-idx).
    std::string dept = body.substr(5, 2);
    if (dept == "2A")
        body.replace(5, 2, "19");
    else if (dept == "2B")
        body.replace(5, 2, "18");
    if (!detail::all_digits(body))
        return false;
    long long remainder = 0;
    for (char c : body)
        remainder = (remainder * 10 + detail::digit_value(c)) % 97;
    int key = static_cast<int>(97 - remainder);
    if (key == 97 && remainder == 0)
        key = 97; // explicit: remainder 0 maps to key 97, not a rejection
    return key == provided_key;
}

// ── Spain DNI/NIE — shared mod-23 letter table ──────────────────────────

inline bool es_dni_nie_mod23(std::string_view raw) {
    std::string s = detail::clean_alnum_upper(raw);
    if (s.size() != 9)
        return false;
    static const std::string kTable = "TRWAGMYFPDXBNJZSQVHLCKE";
    std::string number_part = s.substr(0, 8);
    char lead = number_part[0];
    if (lead == 'X' || lead == 'Y' || lead == 'Z') {
        // NIE: X=0, Y=1, Z=2
        number_part[0] = static_cast<char>('0' + (lead - 'X'));
    }
    if (!detail::all_digits(number_part))
        return false;
    long long n = std::stoll(number_part);
    char expected = kTable[static_cast<size_t>(n % 23)];
    return std::toupper(static_cast<unsigned char>(s[8])) == expected;
}

// ── Italy Codice Fiscale ────────────────────────────────────────────────

inline bool it_codice_fiscale_check(std::string_view raw) {
    std::string s = detail::clean_alnum_upper(raw);
    if (s.size() != 16)
        return false;
    static const std::array<int, 36> kOdd = {
        // '0'-'9' then 'A'-'Z'
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21,             // 0-9
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, // A-M
        11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23,    // N-Z
    };
    static const std::array<int, 36> kEven = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9,                   // 0-9
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,   // A-M
        14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // N-Z
    };
    auto index_of = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'A' && c <= 'Z')
            return 10 + (c - 'A');
        return -1;
    };
    long long sum = 0;
    for (size_t i = 0; i < 15; ++i) {
        int idx = index_of(s[i]);
        if (idx < 0)
            return false;
        // 1-indexed position parity: i is 0-indexed, so 1-indexed = i+1.
        bool odd_position = ((i + 1) % 2 == 1);
        sum += odd_position ? kOdd[static_cast<size_t>(idx)] : kEven[static_cast<size_t>(idx)];
    }
    char expected = static_cast<char>('A' + (sum % 26));
    return s[15] == expected;
}

// ── Netherlands BSN — "11-proef" ────────────────────────────────────────

inline bool nl_elfproef(std::string_view digits9) {
    if (digits9.size() != 9 || !detail::all_digits(digits9))
        return false;
    static const std::vector<int> kWeights = {9, 8, 7, 6, 5, 4, 3, 2, -1};
    long long sum = 0;
    for (size_t i = 0; i < 9; ++i)
        sum += static_cast<long long>(detail::digit_value(digits9[i])) * kWeights[i];
    return sum % 11 == 0;
}

// ── ICAO 9303 MRZ check digit ────────────────────────────────────────────

// Character value: 0-9 -> 0-9, A-Z -> 10-35, '<' -> 0.
inline int mrz_char_value(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'Z')
        return 10 + (c - 'A');
    if (c == '<')
        return 0;
    return -1;
}

// Computes the ICAO check digit over `field` (weights cycle 7,3,1).
inline int mrz_check_digit(std::string_view field) {
    static constexpr int kWeights[3] = {7, 3, 1};
    long long sum = 0;
    for (size_t i = 0; i < field.size(); ++i) {
        int v = mrz_char_value(static_cast<char>(std::toupper(static_cast<unsigned char>(field[i]))));
        if (v < 0)
            return -1;
        sum += static_cast<long long>(v) * kWeights[i % 3];
    }
    return static_cast<int>(sum % 10);
}

inline bool mrz_check_digit_valid(std::string_view field, char provided) {
    int computed = mrz_check_digit(field);
    return computed >= 0 && detail::digit_value(provided) == computed;
}

// Full ICAO 9303 TD3 line-2 composite validation (standard passport
// booklet, the most common document type). `line2` must be exactly 44
// characters. Validates all four field check digits AND the final
// composite check digit — this is the highest-value, fully-implemented
// case; TD1/TD2 and non-TD3 MRZ lines are structural-match-only in this
// ruleset (see embed_pii_rules.py's normalize_passports()).
inline bool mrz_td3_line2_valid(std::string_view line2) {
    if (line2.size() != 44)
        return false;
    std::string s(line2);
    for (char& c : s)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    auto field = [&](size_t pos, size_t len) { return std::string_view(s).substr(pos, len); };

    if (!mrz_check_digit_valid(field(0, 9), s[9]))
        return false;
    if (!mrz_check_digit_valid(field(13, 6), s[19]))
        return false;
    if (!mrz_check_digit_valid(field(21, 6), s[27]))
        return false;
    if (!mrz_check_digit_valid(field(28, 14), s[42]))
        return false;

    std::string composite;
    composite += field(0, 10);  // passport number + its check digit
    composite += field(13, 7);  // DOB + its check digit
    composite += field(21, 22); // sex + expiry + its check digit + personal number + its check digit
    return mrz_check_digit_valid(composite, s[43]);
}

// ── Name-based dispatch ─────────────────────────────────────────────────
//
// Given the algorithm name from a rule's `checksum` field (matching
// 00-manifest.yaml's registry exactly) and the raw matched text, returns:
//   true      — checksum computed and PASSED
//   false     — checksum computed and FAILED
//   nullopt   — this name is unknown, or the algorithm is inherently
//               non-validatable (checksum: null in the manifest, or an
//               explicitly-disclosed "don't gate on this" entry like
//               Peru DNI's final letter or Denmark's abolished CPR check)
//
// Callers (pii_matcher.hpp) MUST treat nullopt as "cannot validate" and
// fall back to keyword-proximity confidence scoring — never as a failure.
inline std::optional<bool> validate_named(std::string_view algorithm, std::string_view raw_text) {
    std::string cleaned = detail::clean_alnum_upper(raw_text);

    if (algorithm == "luhn")
        return luhn_valid(cleaned);
    if (algorithm == "iban_mod97")
        return iban_mod97_valid(raw_text);
    if (algorithm == "iso7064_mod11_10") {
        if (cleaned.size() != 11)
            return std::nullopt;
        int check = iso7064_mod11_10_check_digit(cleaned.substr(0, 10));
        return check >= 0 && detail::digit_value(cleaned[10]) == check;
    }
    if (algorithm == "iso7064_mod11_10_hr")
        return iso7064_mod11_10_hr_valid(cleaned);
    if (algorithm == "iso7064_mod11_2") {
        if (cleaned.size() != 18)
            return std::nullopt;
        char expected = iso7064_mod11_2_check_char(cleaned.substr(0, 17));
        return expected != '\0' && std::toupper(static_cast<unsigned char>(cleaned[17])) == expected;
    }
    if (algorithm == "verhoeff")
        return verhoeff_valid(cleaned);
    if (algorithm == "mod23_pps") {
        // \d{7}[A-W][ABHWTX]?
        if (cleaned.size() < 8)
            return std::nullopt;
        std::string_view digits7 = std::string_view(cleaned).substr(0, 7);
        char check_letter = cleaned[7];
        static const std::string kAlpha = "WABCDEFGHIJKLMNOPQRSTUV";
        static const std::vector<int> kWeights = {8, 7, 6, 5, 4, 3, 2};
        long long total = weighted_sum(digits7, kWeights);
        if (cleaned.size() >= 9) {
            char second = cleaned[8];
            auto pos = kAlpha.find(static_cast<char>(std::toupper(static_cast<unsigned char>(second))));
            if (pos != std::string::npos)
                total += 9 * static_cast<long long>(pos);
        }
        char expected = kAlpha[static_cast<size_t>(total % 23)];
        return std::toupper(static_cast<unsigned char>(check_letter)) == expected;
    }
    if (algorithm == "fr_nir_mod97")
        return fr_nir_mod97(cleaned);
    if (algorithm == "es_dni_nie_mod23")
        return es_dni_nie_mod23(cleaned);
    if (algorithm == "it_codice_fiscale_check")
        return it_codice_fiscale_check(cleaned);
    if (algorithm == "nl_elfproef")
        return nl_elfproef(cleaned);
    if (algorithm == "no_fodselsnummer_mod11")
        return no_fodselsnummer_mod11(cleaned);
    if (algorithm == "pl_pesel_weighted")
        return pl_pesel_weighted(cleaned);
    if (algorithm == "se_personnummer_luhn")
        return se_personnummer_luhn(raw_text);
    if (algorithm == "dk_cpr_abolished")
        return std::nullopt; // checksum officially abolished — advisory only, never gate
    if (algorithm == "au_tfn_weighted_mod11")
        return au_tfn_weighted_mod11(cleaned);
    if (algorithm == "au_medicare_weighted") {
        if (cleaned.size() < 9)
            return std::nullopt;
        return au_medicare_weighted(cleaned.substr(0, 9));
    }
    if (algorithm == "br_cpf_weighted")
        return br_cpf_weighted(cleaned);
    if (algorithm == "br_cnpj_weighted")
        return br_cnpj_weighted(cleaned);
    if (algorithm == "jp_my_number_weighted")
        return jp_my_number_weighted(cleaned);
    if (algorithm == "kr_rrn_weighted_mod11")
        return kr_rrn_weighted_mod11(cleaned);
    if (algorithm == "sg_nric_weighted") {
        if (cleaned.size() != 9)
            return std::nullopt;
        return sg_nric_weighted(cleaned[0], std::string_view(cleaned).substr(1, 7), cleaned[8]);
    }
    if (algorithm == "mx_curp_check")
        return mx_curp_check(raw_text); // needs raw text for the non-ASCII/Ñ guard
    if (algorithm == "ar_cuil_weighted")
        return ar_cuil_weighted(cleaned);
    if (algorithm == "cl_rut_mod11")
        return cl_rut_mod11(cleaned);
    if (algorithm == "pe_dni_weighted")
        return std::nullopt; // final check-character mapping unverified — advisory only, never gate
    if (algorithm == "be_nrn_mod97")
        return be_nrn_mod97(cleaned);
    if (algorithm == "at_vnr_weighted")
        return at_vnr_weighted(cleaned);
    if (algorithm == "pt_nif_weighted") {
        if (cleaned.size() < 9)
            return std::nullopt;
        return pt_nif_weighted(cleaned.substr(0, 9));
    }
    if (algorithm == "fi_hetu_mod31") {
        if (cleaned.size() != 11)
            return std::nullopt;
        std::string nine = cleaned.substr(0, 6) + cleaned.substr(7, 3); // skip century char at index 6
        return fi_hetu_mod31(nine, cleaned[10]);
    }
    if (algorithm == "cz_sk_rc_mod11")
        return cz_sk_rc_mod11(cleaned);
    if (algorithm == "ro_cnp_weighted")
        return ro_cnp_weighted(cleaned);
    if (algorithm == "hu_taj_weighted")
        return hu_taj_weighted(cleaned);
    if (algorithm == "ch_ahv_ean13")
        return ch_ahv_ean13(cleaned);
    if (algorithm == "bg_egn_weighted")
        return bg_egn_weighted(cleaned);
    if (algorithm == "lu_matricule_dual")
        return lu_matricule_dual(cleaned);
    if (algorithm == "si_emso_weighted")
        return si_emso_weighted(cleaned);
    if (algorithm == "baltic_two_pass_mod11")
        return baltic_two_pass_mod11(cleaned);
    if (algorithm == "lv_old_weighted")
        return lv_old_weighted(cleaned);
    if (algorithm == "wa_dl_legacy_mod10")
        return std::nullopt; // position-specific letter tables never fully located — not implemented, not fabricated
    if (algorithm == "us_aba_routing_weighted")
        return us_aba_routing_weighted(cleaned);
    if (algorithm == "vin_iso3779_weighted")
        return vin_iso3779_weighted(cleaned);
    if (algorithm == "imei_luhn")
        return imei_luhn(cleaned);
    if (algorithm == "us_npi_luhn_prefixed")
        return us_npi_luhn_prefixed(cleaned);
    if (algorithm == "none_structural_only")
        return std::nullopt;
    if (algorithm == "icao_mrz_td3_line2")
        return mrz_td3_line2_valid(raw_text);

    return std::nullopt; // unknown algorithm name — fail safe to "cannot validate"
}

} // namespace yuzu::pii::checksum
