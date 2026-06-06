/**
 * test_mfa_qr.cpp — unit tests for the server-side MFA enrollment QR
 * renderer (issue #1232). Verifies otpauth_qr_svg() produces a
 * well-formed, deterministic inline SVG and fails soft on bad input.
 */

#include "../../../server/core/src/mfa_qr.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using yuzu::server::otpauth_qr_svg;

namespace {
const std::string kSampleUri =
    "otpauth://totp/Yuzu:admin?secret=JBSWY3DPEHPK3PXP&issuer=Yuzu&algorithm=SHA1&digits=6&period=30";
}

TEST_CASE("otpauth_qr_svg: renders a well-formed inline SVG for a normal otpauth URI",
          "[mfa][qr]") {
    auto svg = otpauth_qr_svg(kSampleUri);
    REQUIRE_FALSE(svg.empty());
    CHECK(svg.rfind("<svg", 0) == 0);                       // starts with <svg
    CHECK(svg.find("</svg>") != std::string::npos);          // closed
    CHECK(svg.find("viewBox=\"0 0 ") != std::string::npos);  // module-unit viewBox
    CHECK(svg.find("<path fill=\"#000000\"") != std::string::npos); // dark modules
    CHECK(svg.find("fill=\"#ffffff\"") != std::string::npos);       // white quiet-zone tile
    CHECK(svg.find("role=\"img\"") != std::string::npos);           // a11y label
    // No script / foreign content — it is pure shape markup.
    CHECK(svg.find("<script") == std::string::npos);
}

TEST_CASE("otpauth_qr_svg: deterministic for identical input", "[mfa][qr]") {
    CHECK(otpauth_qr_svg(kSampleUri) == otpauth_qr_svg(kSampleUri));
}

TEST_CASE("otpauth_qr_svg: different input yields different output", "[mfa][qr]") {
    CHECK(otpauth_qr_svg(kSampleUri) != otpauth_qr_svg(kSampleUri + "&x=1"));
}

TEST_CASE("otpauth_qr_svg: empty input still yields a valid (smallest) QR", "[mfa][qr]") {
    // qrcodegen encodes the empty string into a minimal symbol — should not
    // throw or return empty.
    auto svg = otpauth_qr_svg("");
    CHECK_FALSE(svg.empty());
    CHECK(svg.rfind("<svg", 0) == 0);
}

TEST_CASE("otpauth_qr_svg: markup in the URI never reaches the SVG output (XSS by construction)",
          "[mfa][qr]") {
    // The otpauth URI embeds the username; a hostile username could contain
    // SVG/HTML metacharacters. The QR encoder turns the URI into module BITS,
    // never echoing it as text, so the SVG (pure <rect>/<path> geometry) must
    // contain none of the injected markup. This is the regression pin for the
    // raw-injection (settings_routes html += / login_ui innerHTML) safety.
    const std::string hostile =
        "otpauth://totp/Yuzu:\"></svg><script>alert(1)</script>?secret=JBSWY3DPEHPK3PXP&issuer=Yuzu";
    auto svg = otpauth_qr_svg(hostile);
    REQUIRE_FALSE(svg.empty());
    CHECK(svg.find("<script") == std::string::npos);
    CHECK(svg.find("</svg><") == std::string::npos);
    CHECK(svg.find("alert(1)") == std::string::npos);
    CHECK(svg.find("\"></") == std::string::npos);
    // Only the one intended </svg> at the very end.
    CHECK(svg.rfind("</svg>") == svg.size() - 6);
}

TEST_CASE("otpauth_qr_svg: over-long input fails soft (empty string, no throw)", "[mfa][qr]") {
    // Far beyond any QR symbol's capacity → encodeText throws data_too_long;
    // the helper must catch it and return "" so the caller falls back to the
    // textual secret rather than 500-ing enrollment.
    std::string huge(20000, 'A');
    auto svg = otpauth_qr_svg(huge);
    CHECK(svg.empty());
}
