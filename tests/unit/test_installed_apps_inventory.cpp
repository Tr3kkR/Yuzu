/**
 * test_installed_apps_inventory.cpp -- pure parse/format vectors for the
 * `list_inventory` action's helpers (installed_apps_inventory.hpp, software-
 * inventory blob contract v2, ADR-0016).
 *
 * Everything here runs against fixture strings -- no dpkg/rpm/pacman/apk on the
 * test host -- because the helpers are pure by design (same header-for-
 * testability pattern as installed_apps_registry_utf8.hpp / #1662). The vectors
 * pin the v2 honesty contract: fields an ecosystem does not store come out
 * EMPTY, never synthesised (no "-0" release, no "-" placeholder).
 */

#include <catch2/catch_test_macros.hpp>

#include "installed_apps_inventory.hpp"

#include <algorithm>
#include <string>

using namespace yuzu::installed_apps::inventory;

TEST_CASE("split_deb_version handles epoch/upstream/revision shapes", "[installed_apps][inventory]") {
    SECTION("full epoch:upstream-revision") {
        const auto p = split_deb_version("1:1.2.3-4ubuntu5");
        CHECK(p.epoch == "1");
        CHECK(p.version == "1.2.3");
        CHECK(p.release == "4ubuntu5");
    }
    SECTION("native package: no revision, release stays empty") {
        const auto p = split_deb_version("5.0");
        CHECK(p.epoch.empty());
        CHECK(p.version == "5.0");
        CHECK(p.release.empty()); // never synthesise "-0"
    }
    SECTION("epoch without revision") {
        const auto p = split_deb_version("2:5.0");
        CHECK(p.epoch == "2");
        CHECK(p.version == "5.0");
        CHECK(p.release.empty());
    }
    SECTION("hyphenated upstream version: revision is after the LAST dash") {
        const auto p = split_deb_version("1.0-2-3");
        CHECK(p.epoch.empty());
        CHECK(p.version == "1.0-2");
        CHECK(p.release == "3");
    }
    SECTION("non-numeric prefix before colon is not an epoch") {
        const auto p = split_deb_version("v1:2.0-1");
        CHECK(p.epoch.empty());
        CHECK(p.version == "v1:2.0");
        CHECK(p.release == "1");
    }
    SECTION("empty input") {
        const auto p = split_deb_version("");
        CHECK(p.epoch.empty());
        CHECK(p.version.empty());
        CHECK(p.release.empty());
    }
}

TEST_CASE("split_pacman_version mirrors the [epoch:]pkgver-pkgrel shape", "[installed_apps][inventory]") {
    SECTION("epoch:pkgver-pkgrel") {
        const auto p = split_pacman_version("2:1.19.2-1");
        CHECK(p.epoch == "2");
        CHECK(p.version == "1.19.2");
        CHECK(p.release == "1");
    }
    SECTION("pkgver-pkgrel, no epoch") {
        const auto p = split_pacman_version("1.19.2-1");
        CHECK(p.epoch.empty());
        CHECK(p.version == "1.19.2");
        CHECK(p.release == "1");
    }
    SECTION("missing pkgrel tolerated: release stays empty") {
        const auto p = split_pacman_version("1.19.2");
        CHECK(p.epoch.empty());
        CHECK(p.version == "1.19.2");
        CHECK(p.release.empty());
    }
    SECTION("dotted pkgrel") {
        const auto p = split_pacman_version("6.0-1.1");
        CHECK(p.version == "6.0");
        CHECK(p.release == "1.1");
    }
}

TEST_CASE("split_apk_line splits name-pkgver-rN", "[installed_apps][inventory]") {
    SECTION("hyphenated package name") {
        const auto p = split_apk_line("openssl-dev-3.1.4-r5");
        CHECK(p.name == "openssl-dev");
        CHECK(p.version == "3.1.4");
        CHECK(p.release == "5"); // 'r' is apk display decoration, not pkgrel
    }
    SECTION("simple name") {
        const auto p = split_apk_line("musl-1.2.4-r2");
        CHECK(p.name == "musl");
        CHECK(p.version == "1.2.4");
        CHECK(p.release == "2");
    }
    SECTION("missing -rN tail tolerated: last segment becomes the version") {
        const auto p = split_apk_line("foo-1.2.3");
        CHECK(p.name == "foo");
        CHECK(p.version == "1.2.3");
        CHECK(p.release.empty());
    }
    SECTION("tail that only looks like a release (non-numeric) is a version") {
        const auto p = split_apk_line("foo-rc1");
        CHECK(p.name == "foo");
        CHECK(p.version == "rc1");
        CHECK(p.release.empty());
    }
    SECTION("no dash at all: whole line is the name, version empty") {
        const auto p = split_apk_line("busybox");
        CHECK(p.name == "busybox");
        CHECK(p.version.empty());
        CHECK(p.release.empty());
    }
    SECTION("version-rN with no name segment: name empty (caller drops row)") {
        const auto p = split_apk_line("1.2.3-r0");
        CHECK(p.name.empty());
        CHECK(p.version == "1.2.3");
        CHECK(p.release == "0");
    }
}

TEST_CASE("map_rpm_none maps the literal (none) to honest-empty", "[installed_apps][inventory]") {
    CHECK(map_rpm_none("(none)").empty());
    CHECK(map_rpm_none("x86_64") == "x86_64");
    CHECK(map_rpm_none("").empty());
    CHECK(map_rpm_none("(None)") == "(None)"); // rpm emits lowercase; don't over-match
}

TEST_CASE("parse_os_release extracts ID / VERSION_ID", "[installed_apps][inventory]") {
    const std::string content = "# a comment line\n"
                                "NAME=\"Ubuntu\"\r\n"
                                "ID=ubuntu\n"
                                "VERSION_ID=\"24.04\"\n"
                                "PRETTY='Single Quoted'\n"
                                "\n"
                                "  INDENTED=ok\n";
    SECTION("unquoted value") {
        CHECK(parse_os_release(content, "ID") == "ubuntu");
    }
    SECTION("double-quoted value") {
        CHECK(parse_os_release(content, "VERSION_ID") == "24.04");
    }
    SECTION("single-quoted value") {
        CHECK(parse_os_release(content, "PRETTY") == "Single Quoted");
    }
    SECTION("CRLF line ending stripped") {
        CHECK(parse_os_release(content, "NAME") == "Ubuntu");
    }
    SECTION("leading whitespace tolerated") {
        CHECK(parse_os_release(content, "INDENTED") == "ok");
    }
    SECTION("missing key is empty") {
        CHECK(parse_os_release(content, "VARIANT_ID").empty());
    }
    SECTION("comment lines never match") {
        CHECK(parse_os_release("#ID=nope\n", "ID").empty());
    }
    SECTION("key must match exactly, not by prefix") {
        CHECK(parse_os_release("VERSION_ID=1\n", "VERSION").empty());
        CHECK(parse_os_release("VERSION=2\n", "VERSION_ID").empty());
    }
    SECTION("empty content") {
        CHECK(parse_os_release("", "ID").empty());
    }
}

TEST_CASE("parse_dpkg_inv_line keeps installed+held, drops the rest (matches PR #1804's "
          "Status-Abbrev 2nd-char check exactly)",
          "[installed_apps][inventory]") {
    SECTION("installed package, full EVR (\"ii\": want=install, status=installed)") {
        const auto r = parse_dpkg_inv_line("bash\tii\t1:5.2.21-2ubuntu4\tamd64\tUbuntu "
                                           "Developers <ubuntu-devel-discuss@lists.ubuntu.com>");
        REQUIRE(r.has_value());
        CHECK(r->name == "bash");
        CHECK(r->epoch == "1");
        CHECK(r->version == "5.2.21");
        CHECK(r->release == "2ubuntu4");
        CHECK(r->arch == "amd64");
        CHECK(r->publisher ==
              "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>");
        CHECK(r->kind == "package");
        CHECK(r->ecosystem == "deb");
        CHECK(r->signature_status.empty()); // deb stores no signature -- honest-empty
        CHECK(r->install_date.empty());
    }
    SECTION("held package is kept (\"hi\": want=hold, status=installed)") {
        const auto r = parse_dpkg_inv_line("linux-image\thi\t6.8.0-31.31\tamd64\tX");
        REQUIRE(r.has_value());
        CHECK(r->version == "6.8.0");
        CHECK(r->release == "31.31");
    }
    SECTION("config-files residue is dropped (\"rc\": status=config-files, not installed)") {
        CHECK_FALSE(parse_dpkg_inv_line("old-pkg\trc\t1.0-1\tamd64\tX").has_value());
    }
    SECTION("unknown want-state is dropped (\"un\")") {
        CHECK_FALSE(parse_dpkg_inv_line("stray-pkg\tun\t1.0-1\tamd64\tX").has_value());
    }
    SECTION("native package: empty release") {
        const auto r = parse_dpkg_inv_line("mytool\tii\t5.0\tall\tMe <me@x>");
        REQUIRE(r.has_value());
        CHECK(r->version == "5.0");
        CHECK(r->release.empty());
    }
    SECTION("malformed (single-char or empty) status token is dropped") {
        CHECK_FALSE(parse_dpkg_inv_line("bash\ti\t1.0-1\tamd64\tX").has_value());
        CHECK_FALSE(parse_dpkg_inv_line("bash\t\t1.0-1\tamd64\tX").has_value());
    }
    SECTION("wrong token count is dropped") {
        CHECK_FALSE(parse_dpkg_inv_line("bash\tii\t1.0-1").has_value());
        CHECK_FALSE(parse_dpkg_inv_line("").has_value());
    }
}

TEST_CASE("rpm_sig_present treats only a real stored-tag value as present",
          "[installed_apps][inventory]") {
    CHECK(rpm_sig_present("abcdef0123456789")); // a real (fake-shaped) sig blob
    CHECK_FALSE(rpm_sig_present("(none)"));      // unset tag
    CHECK_FALSE(rpm_sig_present(""));            // empty
    CHECK_FALSE(rpm_sig_present("%{SIGPGP}"));   // rpm too old to know the tag: unexpanded literal
    CHECK_FALSE(rpm_sig_present("%{RSAHEADER}"));
}

TEST_CASE("parse_rpm_inv_line maps (none) and pins signature values (matches PR #1804's "
          "rpm_sig_present exactly)",
          "[installed_apps][inventory]") {
    SECTION("fully populated, payload+header both signed") {
        const auto r = parse_rpm_inv_line(
            "bash\t0\t5.2.21\t3.fc40\tx86_64\tFedora Project\tMon 01 Jan 2026\tsigpgpblob\trsahdrblob");
        REQUIRE(r.has_value());
        CHECK(r->name == "bash");
        CHECK(r->epoch == "0");
        CHECK(r->version == "5.2.21");
        CHECK(r->release == "3.fc40");
        CHECK(r->arch == "x86_64");
        CHECK(r->publisher == "Fedora Project");
        CHECK(r->install_date == "Mon 01 Jan 2026");
        CHECK(r->signature_status == "signed");
        CHECK(r->kind == "package");
        CHECK(r->ecosystem == "rpm");
    }
    SECTION("header-signed only (SIGPGP (none)) still reads signed -- the modern RHEL/Fedora case") {
        const auto r = parse_rpm_inv_line(
            "openssl\t1\t3.1.4\t1.fc40\tx86_64\tFedora Project\td\t(none)\trsahdrblob");
        REQUIRE(r.has_value());
        CHECK(r->signature_status == "signed");
    }
    SECTION("payload-signed only (RSAHEADER (none)) still reads signed") {
        const auto r =
            parse_rpm_inv_line("openssl\t1\t3.1.4\t1.fc40\tx86_64\tFedora Project\td\tsigpgpblob\t(none)");
        REQUIRE(r.has_value());
        CHECK(r->signature_status == "signed");
    }
    SECTION("both tags absent reads unsigned") {
        const auto r =
            parse_rpm_inv_line("openssl\t1\t3.1.4\t1.fc40\tx86_64\tFedora Project\td\t(none)\t(none)");
        REQUIRE(r.has_value());
        CHECK(r->signature_status == "unsigned");
    }
    SECTION("old-rpm literal %{...} echo on both tags reads unsigned, never a false positive") {
        const auto r = parse_rpm_inv_line(
            "openssl\t1\t3.1.4\t1.fc40\tx86_64\tFedora Project\td\t%{SIGPGP}\t%{RSAHEADER}");
        REQUIRE(r.has_value());
        CHECK(r->signature_status == "unsigned");
    }
    SECTION("(none) epoch/arch/packager map to honest-empty") {
        const auto r = parse_rpm_inv_line(
            "gpg-pubkey\t(none)\tabc123\t4f2a6fd2\t(none)\t(none)\tTue 02 Jan 2026\t(none)\t(none)");
        REQUIRE(r.has_value());
        CHECK(r->epoch.empty());
        CHECK(r->arch.empty());
        CHECK(r->publisher.empty());
        CHECK(r->signature_status == "unsigned");
    }
    SECTION("wrong token count is dropped") {
        CHECK_FALSE(parse_rpm_inv_line("bash\t0\t5.2.21").has_value());
        CHECK_FALSE(parse_rpm_inv_line("p\t0\t1\t1\tnoarch\tX\td\tonly-eight-tokens").has_value());
    }
}

TEST_CASE("parse_pacman_inv_line splits name and EVR", "[installed_apps][inventory]") {
    SECTION("epoch:pkgver-pkgrel") {
        const auto r = parse_pacman_inv_line("systemd 2:255.4-2");
        REQUIRE(r.has_value());
        CHECK(r->name == "systemd");
        CHECK(r->epoch == "2");
        CHECK(r->version == "255.4");
        CHECK(r->release == "2");
        CHECK(r->kind == "package");
        CHECK(r->ecosystem == "pacman");
        CHECK(r->arch.empty()); // -Q does not expose arch -- honest-empty
    }
    SECTION("no space means no record") {
        CHECK_FALSE(parse_pacman_inv_line("garbage").has_value());
        CHECK_FALSE(parse_pacman_inv_line(" 1.0-1").has_value());
    }
}

TEST_CASE("parse_apk_inv_line wraps split_apk_line", "[installed_apps][inventory]") {
    SECTION("normal line") {
        const auto r = parse_apk_inv_line("openssl-dev-3.1.4-r5");
        REQUIRE(r.has_value());
        CHECK(r->name == "openssl-dev");
        CHECK(r->version == "3.1.4");
        CHECK(r->release == "5");
        CHECK(r->kind == "package");
        CHECK(r->ecosystem == "apk");
    }
    SECTION("empty or nameless lines are dropped") {
        CHECK_FALSE(parse_apk_inv_line("").has_value());
        CHECK_FALSE(parse_apk_inv_line("1.2.3-r0").has_value());
    }
}

TEST_CASE("pipe_safe deletes framing/separator bytes", "[installed_apps][inventory]") {
    CHECK(pipe_safe("Vendor | Inc.") == "Vendor  Inc.");
    CHECK(pipe_safe("a\tb\rc\nd") == "abcd");
    CHECK(pipe_safe("clean") == "clean");
    CHECK(pipe_safe("").empty());
}

TEST_CASE("format_inv_row owns the 14-token layout", "[installed_apps][inventory]") {
    InvRecord r;
    r.name = "bash";
    r.version = "5.2.21";
    r.publisher = "Fedora Project";
    r.install_date = "Mon 01 Jan 2026";
    r.kind = "package";
    r.ecosystem = "rpm";
    r.epoch = "0";
    r.release = "3.fc40";
    r.arch = "x86_64";
    r.signature_status = "signed";
    r.distro_id = "fedora";
    r.distro_version = "40";
    r.bundle_id = "com.example.bash";
    CHECK(format_inv_row(r) ==
          "inv|bash|5.2.21|Fedora Project|Mon 01 Jan 2026|package|rpm|0|3.fc40|x86_64|signed|"
          "fedora|40|com.example.bash");

    SECTION("empty fields stay empty tokens -- no placeholder synthesis") {
        InvRecord app;
        app.name = "Google Chrome";
        app.version = "126.0";
        app.publisher = "Google LLC";
        app.kind = "app";
        app.ecosystem = "windows";
        // bundle_id (position 13) is unset -- stays an empty token, not synthesised.
        CHECK(format_inv_row(app) == "inv|Google Chrome|126.0|Google LLC||app|windows|||||||");
    }
    SECTION("pipe in a value cannot shift fields") {
        InvRecord bad;
        bad.name = "Evil|App";
        bad.kind = "app";
        bad.ecosystem = "windows";
        const std::string row = format_inv_row(bad);
        CHECK(row == "inv|EvilApp||||app|windows|||||||");
        // Exactly 13 separators after the prefix regardless of input bytes.
        CHECK(std::count(row.begin(), row.end(), '|') == 13);
    }
}

// ── macOS: system_profiler / codesign / mdls output parsing ────────────────
// (A-1.10 fix round finding A-3: these subprocess-output parsers are pure,
// so they run on any test host without system_profiler/codesign/mdls.)

TEST_CASE("parse_macos_app_headers splits system_profiler mini output into per-app records",
          "[installed_apps][inventory][macos]") {
    SECTION("one app, all three metadata fields") {
        const auto apps = parse_macos_app_headers(
            "    Google Chrome:\n"
            "      Version: 121.0.6167.184\n"
            "      Last Modified: 1/15/24, 10:23 AM\n"
            "      Location: /Applications/Google Chrome.app\n");
        REQUIRE(apps.size() == 1);
        CHECK(apps[0].name == "Google Chrome");
        CHECK(apps[0].version == "121.0.6167.184");
        CHECK(apps[0].last_modified == "1/15/24, 10:23 AM");
        CHECK(apps[0].location == "/Applications/Google Chrome.app");
    }
    SECTION("an app literally named \"Location\" is its own record, not swallowed as the "
            "preceding app's Location: field") {
        // Regression for A-1: the header line for an app named "Location" is a
        // bare 4-space "    Location:" whose trimmed text equals the metadata
        // prefix -- must be recognised by INDENTATION DEPTH, not text match.
        const auto apps = parse_macos_app_headers(
            "    Google Chrome:\n"
            "      Version: 121.0\n"
            "      Last Modified: d1\n"
            "      Location: /Applications/Google Chrome.app\n"
            "    Location:\n"
            "      Version: 2.1\n"
            "      Last Modified: d2\n"
            "      Location: /Applications/Location.app\n");
        REQUIRE(apps.size() == 2);
        CHECK(apps[0].name == "Google Chrome");
        CHECK(apps[0].location == "/Applications/Google Chrome.app");
        CHECK(apps[1].name == "Location");
        CHECK(apps[1].version == "2.1");
        CHECK(apps[1].last_modified == "d2");
        CHECK(apps[1].location == "/Applications/Location.app");
    }
    SECTION("an app literally named \"Version\" is its own record, not misread as the "
            "preceding app's Version: field (A-1 fix round regression)") {
        // Before the fix, the bare 4-space header "    Version:" matched the
        // metadata branch unconditionally (no is_metadata guard): find(':')+2
        // on the 8-byte view "Version:" is past-the-end, so
        // std::string_view::substr threw std::out_of_range instead of
        // starting a new app record.
        const auto apps = parse_macos_app_headers(
            "    Google Chrome:\n"
            "      Version: 121.0\n"
            "      Last Modified: d1\n"
            "      Location: /Applications/Google Chrome.app\n"
            "    Version:\n"
            "      Version: 2.1\n"
            "      Last Modified: d2\n"
            "      Location: /Applications/Version.app\n");
        REQUIRE(apps.size() == 2);
        CHECK(apps[0].name == "Google Chrome");
        CHECK(apps[1].name == "Version");
        CHECK(apps[1].version == "2.1");
        CHECK(apps[1].last_modified == "d2");
        CHECK(apps[1].location == "/Applications/Version.app");
    }
    SECTION("an app literally named \"Last Modified\" is its own record (A-1 fix round "
            "regression)") {
        const auto apps = parse_macos_app_headers("    Last Modified:\n"
                                                   "      Version: 3.0\n"
                                                   "      Last Modified: d3\n"
                                                   "      Location: /Applications/Last Modified.app\n");
        REQUIRE(apps.size() == 1);
        CHECK(apps[0].name == "Last Modified");
        CHECK(apps[0].version == "3.0");
        CHECK(apps[0].last_modified == "d3");
        CHECK(apps[0].location == "/Applications/Last Modified.app");
    }
    SECTION("a metadata label with no trailing value does not throw (bare colon, "
            "A-1 fix round regression)") {
        // find(':')+1 (never +2) so a value-less "Label:" at metadata depth
        // returns an empty value instead of an out-of-range substr.
        const auto apps =
            parse_macos_app_headers("    Solo:\n      Version:\n      Last Modified:\n");
        REQUIRE(apps.size() == 1);
        CHECK(apps[0].name == "Solo");
        CHECK(apps[0].version.empty());
        CHECK(apps[0].last_modified.empty());
    }
    SECTION("last record flushes with no trailing newline; unset fields stay empty") {
        const auto apps = parse_macos_app_headers("    Solo:\n      Version: 1.0");
        REQUIRE(apps.size() == 1);
        CHECK(apps[0].name == "Solo");
        CHECK(apps[0].version == "1.0");
        CHECK(apps[0].last_modified.empty());
        CHECK(apps[0].location.empty());
    }
    SECTION("empty input yields no records") {
        CHECK(parse_macos_app_headers("").empty());
    }
}

TEST_CASE("parse_codesign_output maps codesign -dvvv text to the signed/unsigned vocabulary",
          "[installed_apps][inventory][macos]") {
    SECTION("Authority= line present: signed, publisher is the leaf identity") {
        const auto info = parse_codesign_output(
            "Executable=/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n"
            "Identifier=com.google.Chrome\n"
            "Authority=Developer ID Application: Google LLC (EQHXZ8M8AV)\n"
            "Authority=Developer ID Certification Authority\n"
            "Authority=Apple Root CA\n");
        CHECK(info.signature_status == "signed");
        // First Authority= line wins -- the leaf identity, not an issuing CA.
        CHECK(info.publisher == "Developer ID Application: Google LLC (EQHXZ8M8AV)");
    }
    SECTION("\"code object is not signed at all\": unsigned, publisher empty") {
        const auto info =
            parse_codesign_output("/Applications/Foo.app: code object is not signed at all\n");
        CHECK(info.signature_status == "unsigned");
        CHECK(info.publisher.empty());
    }
    SECTION("no Authority= line at all (e.g. an ad-hoc signature): unsigned, never a third state") {
        const auto info = parse_codesign_output("Signature=adhoc\nFormat=app bundle\n");
        CHECK(info.signature_status == "unsigned");
        CHECK(info.publisher.empty());
    }
    SECTION("empty output: unsigned") {
        // Tool-UNAVAILABLE honest-empty ("" signature_status) is the caller's
        // job (codesign_info gates on codesign_available before ever calling
        // this parser) -- this pure function always returns signed/unsigned.
        const auto info = parse_codesign_output("");
        CHECK(info.signature_status == "unsigned");
        CHECK(info.publisher.empty());
    }
}

TEST_CASE("parse_mdls_bundle_id_output extracts CFBundleIdentifier",
          "[installed_apps][inventory][macos]") {
    SECTION("quoted value") {
        CHECK(parse_mdls_bundle_id_output(
                  "kMDItemCFBundleIdentifier = \"com.google.Chrome\"") == "com.google.Chrome");
    }
    SECTION("unset attribute: literal (null), honest-empty") {
        CHECK(parse_mdls_bundle_id_output("kMDItemCFBundleIdentifier = (null)").empty());
    }
    SECTION("mdls error text (path doesn't resolve): honest-empty") {
        CHECK(parse_mdls_bundle_id_output("/Applications/Ghost.app: no such file or directory")
                  .empty());
    }
    SECTION("empty output: honest-empty") {
        CHECK(parse_mdls_bundle_id_output("").empty());
    }
}
