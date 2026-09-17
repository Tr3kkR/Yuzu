/**
 * test_pii_checksum.cpp — Unit tests for the pii_scan plugin's checksum
 * engine (pii_checksum.hpp).
 *
 * Coverage strategy, disclosed honestly: the shared primitives (Luhn,
 * Verhoeff, IBAN mod-97, the ICAO MRZ check digit) are tested against
 * either hand-computed small examples (shown inline) or extremely
 * well-established public test vectors (industry-standard test card
 * numbers used by every payment sandbox; the IBAN.com / Nationwide UK
 * example IBAN; Wikipedia's own Verhoeff worked example; the ICAO Doc
 * 9303 Erikson/Utopia example MRZ, reproduced in essentially every MRZ
 * library's own test suite). The named country-specific algorithms with
 * an independently-verified real-world worked example from this
 * ruleset's research pass (Chile RUT, US NPI) get a real vector too.
 *
 * The remaining ~30 named algorithms (see pii_checksum.hpp's
 * validate_named()) are each implemented directly from
 * content/pii-rules/00-manifest.yaml's documented weights/tables but are
 * NOT independently vector-tested here — an honest, disclosed gap rather
 * than a fabricated "passing" test built by round-tripping the function
 * through itself (which would prove internal consistency, not external
 * correctness, and isn't worth the false confidence). Follow-up: most of
 * these algorithms are sourced from python-stdnum
 * (github.com/arthurdejong/python-stdnum) — that library's own test
 * fixtures are the natural cross-check to add real vectors from.
 */

#include "pii_checksum.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::pii::checksum;

// ── Luhn ─────────────────────────────────────────────────────────────────

TEST_CASE("luhn_valid: well-known test card numbers pass", "[pii][checksum][luhn]") {
    // Industry-standard sandbox test numbers (Visa/Mastercard/Discover) —
    // used universally by payment processors' own test suites.
    CHECK(luhn_valid("4111111111111111"));
    CHECK(luhn_valid("4012888888881881"));
    CHECK(luhn_valid("5555555555554444"));
    CHECK(luhn_valid("6011111111111117"));
}

TEST_CASE("luhn_valid: a single mutated digit fails", "[pii][checksum][luhn]") {
    CHECK_FALSE(luhn_valid("4111111111111112"));
}

TEST_CASE("luhn_valid: non-digit input fails closed", "[pii][checksum][luhn]") {
    CHECK_FALSE(luhn_valid("411111111111111X"));
    CHECK_FALSE(luhn_valid(""));
}

TEST_CASE("luhn_check_digit: computes the digit that makes the payload Luhn-valid",
          "[pii][checksum][luhn]") {
    // "411111111111111" + computed digit should equal the known-valid
    // "4111111111111111".
    int d = luhn_check_digit("411111111111111");
    REQUIRE(d == 1);
}

// ── Verhoeff ─────────────────────────────────────────────────────────────

TEST_CASE("verhoeff_valid: Wikipedia's canonical worked example", "[pii][checksum][verhoeff]") {
    // "2363" is the standard worked example reproduced on Wikipedia's
    // "Verhoeff algorithm" page and in most reference implementations.
    CHECK(verhoeff_valid("2363"));
}

TEST_CASE("verhoeff_valid: a mutated digit fails", "[pii][checksum][verhoeff]") {
    CHECK_FALSE(verhoeff_valid("2364"));
}

// ── IBAN — ISO 7064 MOD 97-10 ───────────────────────────────────────────

TEST_CASE("iban_mod97_valid: the standard Nationwide UK example IBAN passes",
          "[pii][checksum][iban]") {
    // GB29NWBK60161331926819 is the IBAN.com / Nationwide worked example
    // reproduced in essentially every IBAN validation tutorial.
    CHECK(iban_mod97_valid("GB29NWBK60161331926819"));
}

TEST_CASE("iban_mod97_valid: separators and lowercase are tolerated", "[pii][checksum][iban]") {
    CHECK(iban_mod97_valid("gb29 nwbk 6016 1331 9268 19"));
}

TEST_CASE("iban_mod97_valid: a mutated digit fails", "[pii][checksum][iban]") {
    CHECK_FALSE(iban_mod97_valid("GB29NWBK60161331926818"));
}

// ── ICAO MRZ check digit ─────────────────────────────────────────────────

TEST_CASE("mrz_check_digit: hand-computed small examples", "[pii][checksum][mrz]") {
    // weights cycle 7,3,1; digit value = face value; '5'*7 + '2'*3 + '0'*1
    // = 35+6+0 = 41 -> 41 mod 10 = 1.
    CHECK(mrz_check_digit("520") == 1);
    // '3'*7 + '6'*3 = 21+18 = 39 -> 9.
    CHECK(mrz_check_digit("36") == 9);
    // filler '<' has value 0.
    CHECK(mrz_check_digit("<") == 0);
    // 'A' has value 10; 10*7 = 70 -> 0.
    CHECK(mrz_check_digit("A") == 0);
    // 'A'=10,'B'=11; 10*7 + 11*3 = 70+33 = 103 -> 3.
    CHECK(mrz_check_digit("AB") == 3);
}

TEST_CASE("mrz_td3_line2_valid: the ICAO Doc 9303 Erikson/Utopia example",
          "[pii][checksum][mrz]") {
    // The canonical worked example reproduced throughout ICAO Doc 9303
    // and virtually every MRZ-parsing library's own test suite.
    std::string_view line2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";
    // line2 as commonly quoted is 44 chars for the MRZ body — trailing
    // context here may include a newline from copy sources; the function
    // requires exactly 44.
    REQUIRE(line2.substr(0, 44).size() == 44);
    CHECK(mrz_td3_line2_valid(line2.substr(0, 44)));
}

TEST_CASE("mrz_td3_line2_valid: a mutated passport-number digit fails",
          "[pii][checksum][mrz]") {
    std::string line2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";
    line2[1] = '7'; // corrupt the passport number itself
    CHECK_FALSE(mrz_td3_line2_valid(line2));
}

TEST_CASE("mrz_td3_line2_valid: wrong length fails closed", "[pii][checksum][mrz]") {
    CHECK_FALSE(mrz_td3_line2_valid("TOOSHORT"));
}

// ── Named algorithms with an independently-verified real-world vector ──

TEST_CASE("validate_named luhn: dispatch matches luhn_valid directly", "[pii][checksum][named]") {
    auto r = validate_named("luhn", "4111111111111111");
    REQUIRE(r.has_value());
    CHECK(*r);
}

TEST_CASE("validate_named us_npi_luhn_prefixed: verified worked example (CMS/John D. Cook)",
          "[pii][checksum][named]") {
    // NPI 1993999998 -> prefix "80840"+"199399999" Luhn-checks to 8,
    // matching the actual 10th digit. Independently verified during
    // research against CMS's own published spec and a worked example.
    auto r = validate_named("us_npi_luhn_prefixed", "1993999998");
    REQUIRE(r.has_value());
    CHECK(*r);
}

TEST_CASE("validate_named us_npi_luhn_prefixed: mutated digit fails", "[pii][checksum][named]") {
    auto r = validate_named("us_npi_luhn_prefixed", "1993999997");
    REQUIRE(r.has_value());
    CHECK_FALSE(*r);
}

TEST_CASE("validate_named cl_rut_mod11: verified worked example (biobiochile.cl)",
          "[pii][checksum][named]") {
    // RUT 30.686.957 -> check digit 4, independently verified during research.
    auto r = validate_named("cl_rut_mod11", "30686957-4");
    REQUIRE(r.has_value());
    CHECK(*r);
}

TEST_CASE("validate_named cl_rut_mod11: mutated check digit fails", "[pii][checksum][named]") {
    auto r = validate_named("cl_rut_mod11", "30686957-5");
    REQUIRE(r.has_value());
    CHECK_FALSE(*r);
}

// ── Advisory-only algorithms: must never hard-gate ──────────────────────

TEST_CASE("validate_named: algorithms explicitly flagged non-validatable always return nullopt",
          "[pii][checksum][named]") {
    // Denmark's CPR checksum was abolished in 2007 — never gate on it.
    CHECK_FALSE(validate_named("dk_cpr_abolished", "0101001234").has_value());
    // Peru DNI's final check-character mapping was never verified — advisory only.
    CHECK_FALSE(validate_named("pe_dni_weighted", "17801146").has_value());
    // WA's legacy DL letter tables were never fully located — not implemented.
    CHECK_FALSE(validate_named("wa_dl_legacy_mod10", "ABCDE12345").has_value());
    // Unknown algorithm name — fail safe to "cannot validate", not a crash.
    CHECK_FALSE(validate_named("not_a_real_algorithm", "12345").has_value());
    CHECK_FALSE(validate_named("none_structural_only", "12345").has_value());
}

// ── VIN / IMEI (widely-published, deterministic algorithms) ────────────

TEST_CASE("vin_iso3779_transliterate: I, O, Q transliterate to -1 (never valid in a VIN)",
          "[pii][checksum][vin]") {
    CHECK(vin_iso3779_transliterate('I') == -1);
    CHECK(vin_iso3779_transliterate('O') == -1);
    CHECK(vin_iso3779_transliterate('Q') == -1);
    CHECK(vin_iso3779_transliterate('A') == 1);
    CHECK(vin_iso3779_transliterate('9') == 9);
}

// The test above (previously misnamed "vin_iso3779_weighted") only ever
// exercised the transliteration helper -- vin_iso3779_weighted() itself,
// the actual checksum function every "vin.*" rule dispatches to, had zero
// coverage. "1M8GDM9AXKP042788" is the standard textbook VIN check-digit
// worked example (check digit 'X' at position 9); hand-verified here
// against this file's own weights/transliteration table (weighted sum
// 351, 351 mod 11 = 10 -> 'X').
TEST_CASE("vin_iso3779_weighted: real worked-example VIN validates", "[pii][checksum][vin]") {
    CHECK(vin_iso3779_weighted("1M8GDM9AXKP042788"));
    CHECK_FALSE(vin_iso3779_weighted("1M8GDM9A0KP042788")); // wrong check digit
    CHECK_FALSE(vin_iso3779_weighted("1M8GDM9AXKP04278"));  // 16 chars, wrong length
    CHECK_FALSE(vin_iso3779_weighted("1M8GDM9AXKP0I2788")); // contains 'I' — never valid
}

TEST_CASE("imei_luhn: requires exactly 15 digits", "[pii][checksum][imei]") {
    CHECK_FALSE(imei_luhn("123456789012345")); // wrong checksum, right length — expect false unless coincidentally valid
    CHECK_FALSE(imei_luhn("12345678901234"));  // 14 digits — wrong length
}
