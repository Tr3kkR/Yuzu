/**
 * test_vuln_identity.cpp — unit tests for the vuln_scan installed-software
 * identity collector's pure parsing/formatting helpers (vuln_identity.hpp).
 *
 * Covers NEVRA decomposition per ecosystem, the "honest empty — never
 * synthesise" contract, stored-signature mapping, and the pipe-safety of the
 * output record. The collector reads STORED package-DB fields only; there is no
 * live signature verification to exercise here (that lives in no code path).
 */

#include "vuln_identity.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::vuln;

namespace {
// Build a 0x1F-delimited record from fields, matching the collector queryformat.
std::string us(std::initializer_list<std::string> fields) {
    std::string out;
    bool first = true;
    for (const auto& f : fields) {
        if (!first)
            out += kUS;
        first = false;
        out += f;
    }
    return out;
}
} // namespace

// ── split_evr ───────────────────────────────────────────────────────────────

TEST_CASE("split_evr: epoch + version + release", "[vuln][evr]") {
    std::string e, v, r;
    split_evr("1:2.3.4-5ubuntu2", e, v, r);
    CHECK(e == "1");
    CHECK(v == "2.3.4");
    CHECK(r == "5ubuntu2");
}

TEST_CASE("split_evr: no epoch", "[vuln][evr]") {
    std::string e, v, r;
    split_evr("2.3.4-5", e, v, r);
    CHECK(e.empty());
    CHECK(v == "2.3.4");
    CHECK(r == "5");
}

TEST_CASE("split_evr: native package (no release)", "[vuln][evr]") {
    std::string e, v, r;
    split_evr("2.3.4", e, v, r);
    CHECK(e.empty());
    CHECK(v == "2.3.4");
    CHECK(r.empty());
}

TEST_CASE("split_evr: colon that is not an epoch is not stripped", "[vuln][evr]") {
    // A non-numeric prefix before ':' is not a Debian epoch.
    std::string e, v, r;
    split_evr("abc:1.0-1", e, v, r);
    CHECK(e.empty());
    CHECK(v == "abc:1.0");
    CHECK(r == "1");
}

// ── rpm ─────────────────────────────────────────────────────────────────────

TEST_CASE("parse_rpm_line: full NEVRA + payload signed", "[vuln][rpm]") {
    // SIGPGP present, RSAHEADER absent.
    auto r = parse_rpm_line(us(
        {"openssh-server", "0", "8.7p1", "38.el9", "x86_64", "Red Hat, Inc.", "89abcdef", "(none)"}));
    REQUIRE(r.has_value());
    CHECK(r->kind == "package");
    CHECK(r->ecosystem == "rpm");
    CHECK(r->name == "openssh-server");
    CHECK(r->epoch == "0");
    CHECK(r->version == "8.7p1");
    CHECK(r->release == "38.el9");
    CHECK(r->arch == "x86_64");
    CHECK(r->packager == "Red Hat, Inc.");
    CHECK(r->signature_status == "signed");
}

TEST_CASE("parse_rpm_line: header-only signature counts as signed", "[vuln][rpm]") {
    // Modern RHEL/Fedora: %{SIGPGP}==(none) but %{RSAHEADER} present. Must NOT
    // be mislabelled unsigned (the false-signal bug cross-platform flagged).
    auto r = parse_rpm_line(
        us({"glibc", "2", "2.34", "60.el9", "x86_64", "Fedora Project", "(none)", "aabbccdd"}));
    REQUIRE(r.has_value());
    CHECK(r->epoch == "2");
    CHECK(r->signature_status == "signed");
}

TEST_CASE("parse_rpm_line: (none) maps to empty, unsigned", "[vuln][rpm]") {
    // Both signature tags absent → genuinely unsigned.
    auto r = parse_rpm_line(
        us({"local-build", "(none)", "1.0", "1", "noarch", "(none)", "(none)", "(none)"}));
    REQUIRE(r.has_value());
    CHECK(r->epoch.empty());          // honest empty, not "(none)"
    CHECK(r->packager.empty());
    CHECK(r->signature_status == "unsigned");
}

TEST_CASE("parse_rpm_line: too few fields rejected", "[vuln][rpm]") {
    CHECK_FALSE(parse_rpm_line(us({"name", "0", "1.0"})).has_value());
    CHECK_FALSE(parse_rpm_line(us({"n", "0", "1", "1", "x", "p", "s"})).has_value()); // 7 < 8
}

// ── dpkg ────────────────────────────────────────────────────────────────────

TEST_CASE("parse_dpkg_line: epoch parsed out of Version, no signature", "[vuln][dpkg]") {
    auto r = parse_dpkg_line(
        us({"openssl", "1:3.0.2-0ubuntu1.15", "amd64", "Ubuntu Devs", "ii "}));
    REQUIRE(r.has_value());
    CHECK(r->ecosystem == "deb");
    CHECK(r->name == "openssl");
    CHECK(r->epoch == "1");
    CHECK(r->version == "3.0.2");
    CHECK(r->release == "0ubuntu1.15");
    CHECK(r->arch == "amd64");
    CHECK(r->packager == "Ubuntu Devs");
    CHECK(r->signature_status.empty()); // dpkg stores none — honest empty
}

TEST_CASE("parse_dpkg_line: non-installed status is skipped", "[vuln][dpkg]") {
    // "rc" = removed, config remains; "un" = unknown — neither is installed.
    CHECK_FALSE(parse_dpkg_line(us({"oldpkg", "1.0", "amd64", "M", "rc "})).has_value());
    CHECK_FALSE(parse_dpkg_line(us({"ghost", "1.0", "amd64", "M", "un "})).has_value());
}

TEST_CASE("parse_dpkg_line: held-but-installed package is kept", "[vuln][dpkg]") {
    // "hi" = want:hold, status:installed (apt-mark hold / kernel pin). Present
    // and scannable — must NOT be dropped.
    auto r = parse_dpkg_line(us({"linux-image", "1:6.1.0-1", "amd64", "Debian", "hi "}));
    REQUIRE(r.has_value());
    CHECK(r->name == "linux-image");
    CHECK(r->epoch == "1");
    CHECK(r->version == "6.1.0");
    CHECK(r->release == "1");
}

// ── apk / pacman ─────────────────────────────────────────────────────────────

TEST_CASE("parse_apk_line: name/version/pkgrel", "[vuln][apk]") {
    auto r = parse_apk_line("musl-1.2.4-r2");
    REQUIRE(r.has_value());
    CHECK(r->ecosystem == "apk");
    CHECK(r->name == "musl");
    CHECK(r->version == "1.2.4");
    CHECK(r->release == "r2");
    CHECK(r->epoch.empty());
}

TEST_CASE("parse_apk_line: hyphenated package name", "[vuln][apk]") {
    auto r = parse_apk_line("ca-certificates-bundle-20240226-r0");
    REQUIRE(r.has_value());
    CHECK(r->name == "ca-certificates-bundle");
    CHECK(r->version == "20240226");
    CHECK(r->release == "r0");
}

TEST_CASE("parse_pacman_line: epoch + release decomposed", "[vuln][pacman]") {
    auto r = parse_pacman_line("linux 2:6.9.1-1");
    REQUIRE(r.has_value());
    CHECK(r->ecosystem == "pacman");
    CHECK(r->name == "linux");
    CHECK(r->epoch == "2");
    CHECK(r->version == "6.9.1");
    CHECK(r->release == "1");
}

TEST_CASE("parse_apk/pacman_line: malformed input rejected", "[vuln][apk][pacman]") {
    CHECK_FALSE(parse_apk_line("nodash").has_value());   // no '-' separators
    CHECK_FALSE(parse_apk_line("-r0").has_value());       // dash at 0
    CHECK_FALSE(parse_pacman_line("nospaceversion").has_value()); // no ' '
    CHECK_FALSE(parse_pacman_line(" 1.0").has_value());   // space at 0 (empty name)
}

// ── output formatting / pipe-safety ──────────────────────────────────────────

TEST_CASE("format_record: fixed column order", "[vuln][format]") {
    PackageRecord r;
    r.kind = "package";
    r.ecosystem = "rpm";
    r.name = "bash";
    r.epoch = "";
    r.version = "5.1.8";
    r.release = "9.el9";
    r.arch = "x86_64";
    r.packager = "Red Hat";
    r.signature_status = "signed";
    r.distro_id = "rhel";
    r.distro_version = "9.4";
    CHECK(format_record(r) ==
          "package|rpm|bash||5.1.8|9.el9|x86_64|Red Hat|signed|rhel|9.4");
}

TEST_CASE("format_record: a pipe in a value cannot forge a column", "[vuln][format]") {
    PackageRecord r;
    r.kind = "app";
    r.ecosystem = "windows";
    r.name = "Weird|Name";
    r.packager = "Vendor|Inc";
    auto out = format_record(r);
    // The literal pipes in values are escaped; the field count (10 separators)
    // is preserved so downstream column parsing stays aligned.
    CHECK(out.find("Weird\\|Name") != std::string::npos);
    CHECK(out.find("Vendor\\|Inc") != std::string::npos);
    size_t unescaped = 0;
    for (size_t i = 0; i < out.size(); ++i)
        if (out[i] == '|' && (i == 0 || out[i - 1] != '\\'))
            ++unescaped;
    CHECK(unescaped == 10); // 11 columns -> 10 delimiters
}

TEST_CASE("integration: a '|' in a parsed packager survives parse + format", "[vuln][format]") {
    // End-to-end proof of the header's guarantee: a rpm PACKAGER containing '|'
    // is parsed intact (0x1F queryformat delimiter) and then escaped on output
    // so it cannot forge a column boundary.
    auto r = parse_rpm_line(
        us({"p", "0", "1.0", "1", "x86_64", "Vendor|Inc, GPG (Fedora)", "sig", "(none)"}));
    REQUIRE(r.has_value());
    CHECK(r->packager == "Vendor|Inc, GPG (Fedora)"); // '|' preserved through parse
    auto out = format_record(*r);
    CHECK(out.find("Vendor\\|Inc") != std::string::npos); // escaped on output
    size_t unescaped = 0;
    for (size_t i = 0; i < out.size(); ++i)
        if (out[i] == '|' && (i == 0 || out[i - 1] != '\\'))
            ++unescaped;
    CHECK(unescaped == 10); // column count intact despite the '|' in the value
}

TEST_CASE("format_record: invalid UTF-8 is scrubbed, valid multibyte survives",
          "[vuln][format][utf8]") {
    PackageRecord bad;
    bad.kind = "package";
    bad.name = std::string("a\xff""b"); // lone 0xFF is not valid UTF-8
    CHECK(format_record(bad).find("a?b") != std::string::npos);

    PackageRecord good;
    good.kind = "package";
    good.name = "caf\xc3\xa9"; // "café" (valid 2-byte UTF-8) must pass through
    CHECK(format_record(good).find("caf\xc3\xa9") != std::string::npos);
}

TEST_CASE("format_record: control bytes can't forge a row (UP-1)", "[vuln][format][utf8]") {
    PackageRecord r;
    r.kind = "app";
    r.name = "Foo\nBar";      // embedded newline
    r.packager = "Vend\x1f""or"; // embedded unit separator
    auto out = format_record(r);
    CHECK(out.find('\n') == std::string::npos);   // no newline survives to forge a row
    CHECK(out.find('\x1f') == std::string::npos);  // no 0x1F survives
    CHECK(out.find("Foo Bar") != std::string::npos); // control byte -> space
}

TEST_CASE("parse_rpm_line: unexpanded %{RSAHEADER} is not read as signed", "[vuln][rpm]") {
    // An rpm too old to know the tag echoes the literal format string — must
    // NOT count as a signature (UP-4).
    auto r = parse_rpm_line(
        us({"p", "0", "1.0", "1", "x86_64", "Vendor", "(none)", "%{RSAHEADER}"}));
    REQUIRE(r.has_value());
    CHECK(r->signature_status == "unsigned");
}

TEST_CASE("parse_*_line: over-split (stray 0x1F in a field) is rejected", "[vuln][rpm][dpkg]") {
    // A value carrying a literal 0x1F over-splits the record; the exact
    // field-count guard drops it rather than mis-attributing shifted columns.
    CHECK_FALSE(parse_rpm_line(
                    us({"p", "0", "1.0", "1", "x86_64", "Ven", "dor", "sig", "(none)"}))
                    .has_value()); // 9 fields
    CHECK_FALSE(
        parse_dpkg_line(us({"p", "1.0", "amd64", "Ma", "int", "ii "})).has_value()); // 6 fields
}
