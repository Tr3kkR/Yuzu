/**
 * test_browser_inventory_linux_parsers.cpp — injected-root walk tests for
 * the browser_inventory plugin's Linux leg (browser_inventory_linux_
 * parsers.hpp). This TU is UNGUARDED (compiles on every host, per run-
 * context.md X2's scoped exception: the pure-parser/dispatcher test TUs
 * stay unguarded even though the walk shell itself does not exist on
 * Windows) -- only the walk-case TEST_CASE bodies below are wrapped in
 * `#if !defined(_WIN32)`.
 *
 * MATERIALIZER (run-context.md X1). tests/unit/test_peripherals_linux_
 * parsers.cpp's own materializer (:19,54,178-182) is TU-local, hardcoded to
 * wave9's `sysfs_tree.manifest`, and supports only one line shape --
 * `<relative-path>\t<single-line content>`, no escapes. Per X1 this TU
 * COPIES that shape (never includes it) and extends it with ONE scheme,
 * defined and unit-tested right here: a line is `<relpath>\t<payload>`
 * where `payload` is `T:<text>` (with '\\', '\n', '\t' escaped as literal
 * two-char sequences "\\\\", "\\n", "\\t" -- see t_decode_payload below) or
 * `B:<base64>` for a binary file (unused by this package's own fixture
 * tree, since every file here is plain JSON text, but implemented and
 * tested for completeness/reuse per X1's "defined and unit-tested by that
 * TU"). A line starting with '#', or a blank line, is a comment and
 * skipped -- this fixture tree's own provenance note lives as such
 * comment lines at the top of tree.manifest (every payload byte in it is
 * copied verbatim from the already-provenanced tests/unit/fixtures/wave10/
 * browser_inventory/{edge,chrome}/provenance.txt fixtures this plugin's
 * P2a-1 package shipped; this file only relocates those bytes onto the
 * per-user home layout this leg walks).
 *
 * ROOT GUARD (X3): the chmod-000 case skips under uid 0 / CAP_DAC_OVERRIDE,
 * matching test_peripherals_linux_parsers.cpp:297,302's precedent.
 */
#include <catch2/catch_test_macros.hpp>

#include "browser_inventory_linux_parsers.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

std::filesystem::path manifest_path() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return std::filesystem::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "browser_inventory" / "linux" /
          "tree.manifest";
#else
    return std::filesystem::path(
        "tests/unit/fixtures/wave10/browser_inventory/linux/tree.manifest");
#endif
}

/// Base64 alphabet decode (standard, no URL variant, '=' padding) -- small
/// and local rather than pulling in a dependency for one test-only path.
std::string base64_decode(const std::string& in) {
    static const std::string kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<int> table(256, -1);
    for (std::size_t i = 0; i < kAlphabet.size(); ++i) table[static_cast<unsigned char>(kAlphabet[i])] = static_cast<int>(i);
    std::string out;
    int val = 0;
    int bits = -8;
    for (unsigned char c : in) {
        if (c == '=') break;
        if (table[c] == -1) continue;
        val = (val << 6) + table[c];
        bits += 6;
        if (bits >= 0) {
            out += static_cast<char>((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return out;
}

/// Reverses tree.manifest's `T:` escape scheme (this TU's own extension to
/// the peripherals materializer shape, per X1): a literal '\\' was encoded
/// first as "\\\\", so any other escape pair is unambiguous. An unrecognised
/// escape (should never occur from our own encoder) is passed through
/// literally rather than throwing, so a hand-edited fixture fails a content
/// assertion downstream instead of aborting the whole suite.
std::string t_decode_payload(const std::string& encoded) {
    std::string out;
    out.reserve(encoded.size());
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        if (encoded[i] == '\\' && i + 1 < encoded.size()) {
            const char next = encoded[i + 1];
            if (next == 'n') { out += '\n'; ++i; continue; }
            if (next == 't') { out += '\t'; ++i; continue; }
            if (next == '\\') { out += '\\'; ++i; continue; }
        }
        out += encoded[i];
    }
    return out;
}

/// Decodes one manifest payload (the part after the first '\t'): "T:..."
/// or "B:...". Unknown prefixes are reported via `ok=false`.
std::string decode_manifest_payload(const std::string& payload, bool& ok) {
    ok = true;
    if (payload.rfind("T:", 0) == 0) return t_decode_payload(payload.substr(2));
    if (payload.rfind("B:", 0) == 0) return base64_decode(payload.substr(2));
    ok = false;
    return {};
}

/// Materializes tree.manifest's `<relative-path>\t<payload>` lines onto
/// disk under `root`. POSIX only — callers must not invoke this on
/// Windows (the walk code under test does not exist there either; see this
/// TU's banner).
bool materialize_browser_inventory_tree(const std::filesystem::path& root, std::string& error) {
    const auto manifest_file = manifest_path();
    std::ifstream manifest(manifest_file, std::ios::binary);
    if (!manifest) {
        error = "could not open tree.manifest at " + manifest_file.string();
        return false;
    }
    std::string line;
    while (std::getline(manifest, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back(); // CRLF-checkout tolerance
        if (line.empty() || line[0] == '#') continue;
        const auto tab = line.find('\t');
        if (tab == std::string::npos) {
            error = "malformed tree.manifest line (no tab separator): " + line;
            return false;
        }
        const std::string rel = line.substr(0, tab);
        bool ok = false;
        const std::string content = decode_manifest_payload(line.substr(tab + 1), ok);
        if (!ok) {
            error = "malformed tree.manifest payload (unknown prefix) for " + rel;
            return false;
        }
        const auto out_path = root / rel;
        std::error_code ec;
        std::filesystem::create_directories(out_path.parent_path(), ec);
        if (ec) {
            error = "create_directories failed for " + out_path.parent_path().string() + ": " +
                    ec.message();
            return false;
        }
        std::ofstream out(out_path, std::ios::binary);
        if (!out) {
            error = "could not create fixture file " + out_path.string();
            return false;
        }
        out << content; // exactly the decoded bytes -- tree.manifest's own encoder stripped
                        // each source fixture's single trailing '\n' before encoding, so no
                        // extra newline is added back here (unlike the peripherals precedent,
                        // whose sysfs attribute files always end in exactly one '\n').
    }
    return true;
}

bool row_starts_with(const std::string& row, std::string_view prefix) {
    return row.size() >= prefix.size() && row.compare(0, prefix.size(), prefix) == 0;
}

/// Escape-aware field split (yuzu::util::safe_output_field escapes a
/// literal '|' as '\|' and folds a literal '\' to '/' first, so a value's
/// own backslash can never desynchronize this split -- see this leg's
/// header banner "WIRE GRAMMAR").
std::vector<std::string> split_fields_escape_aware(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

bool any_row_contains(const std::vector<std::string>& rows, std::string_view needle) {
    return std::any_of(rows.begin(), rows.end(),
                       [&](const std::string& r) { return r.find(needle) != std::string::npos; });
}

} // namespace

// ── manifest scheme (portable, no filesystem) ────────────────────────────

TEST_CASE("browser_inventory linux: T: payload round-trips backslash/newline/tab",
          "[browser_inventory][linux][fixture]") {
    const std::string original = "line one\\nline two\tindented\\\\literal-backslash";
    // Hand-encode the same way the fixture-generation step did: backslash
    // first, then the control characters -- see tree.manifest's banner.
    std::string encoded = original;
    std::string tmp;
    for (char c : encoded) {
        if (c == '\\') tmp += "\\\\";
        else if (c == '\n') tmp += "\\n";
        else if (c == '\t') tmp += "\\t";
        else tmp += c;
    }
    bool ok = false;
    const std::string decoded = decode_manifest_payload("T:" + tmp, ok);
    CHECK(ok);
    CHECK(decoded == original);
}

TEST_CASE("browser_inventory linux: B: payload decodes base64",
          "[browser_inventory][linux][fixture]") {
    bool ok = false;
    // "hi" -> base64 "aGk="
    const std::string decoded = decode_manifest_payload("B:aGk=", ok);
    CHECK(ok);
    CHECK(decoded == "hi");
}

TEST_CASE("browser_inventory linux: an unknown payload prefix is reported, not guessed",
          "[browser_inventory][linux][fixture]") {
    bool ok = true;
    decode_manifest_payload("Z:whatever", ok);
    CHECK_FALSE(ok);
}

// ── wire-grammar escaping (pure, portable) ────────────────────────────────

TEST_CASE("browser_inventory linux: a trailing-backslash field never desyncs the row split",
          "[browser_inventory][linux][wire]") {
    // X12: a value that can end in a backslash must go through
    // yuzu::util::safe_output_field before joining with '|'. Simulate a
    // display_name ending in a backslash (a legal, if unusual, Chromium
    // profile name) the way linux_profile_rows_at() itself would build a
    // row, and assert the exact field count survives.
    const std::string display_name_raw = "Work\\";
    const std::string row = std::string{"profile|alice|edge|Default|"} +
                            yuzu::util::safe_output_field(display_name_raw);
    const auto fields = split_fields_escape_aware(row);
    REQUIRE(fields.size() == 5);
    CHECK(fields[4] == "Work/"); // safe_output_field folds '\' -> '/' (documented lossy contract)
}

// ── walk-case tests (materialize the tree; POSIX only, X2) ───────────────
//
// Each TEST_CASE below is declared UNGUARDED (registered on every host, per
// X2's "the pure-parser/dispatcher test stays unguarded — the guard must
// never hide them" and this package spec's "Tree test asserts ... on every
// host"); only the BODY is wrapped in `#if !defined(_WIN32)`, with a
// Windows SKIP() naming why — the walk shell under test
// (browser_inventory_linux_parsers.hpp's lnx:: functions) is itself
// `#if !defined(_WIN32)`-gated at its definition (X2: "the walk shell does
// not exist on Windows"), so the symbols are simply unavailable to call
// there, matching test_posix_dir_walk.cpp's own precedent shape.

TEST_CASE("browser_inventory linux: linux_profile_rows_at finds alice/edge and bob/chrome profiles",
          "[browser_inventory][linux][walk]") {
#if defined(_WIN32)
    SKIP("browser_inventory_linux_parsers.hpp's O_NOFOLLOW walk shell is POSIX-only (run-context.md "
        "X2) -- not compiled on Windows");
#else
    using namespace yuzu::browser_inventory::lnx;
    yuzu::test::TempDir dir{"yuzu_test_browser_inventory_profiles_"};
    std::string error;
    REQUIRE(materialize_browser_inventory_tree(dir.path, error));

    std::optional<std::string> token;
    const auto rows = linux_profile_rows_at(dir.path, token);
    CHECK_FALSE(token.has_value());
    REQUIRE_FALSE(rows.empty());

    for (const auto& r : rows) CHECK(row_starts_with(r, "profile|"));

    const bool found_alice_edge_default = std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
        return row_starts_with(r, "profile|alice|edge|Default|");
    });
    CHECK(found_alice_edge_default);

    const bool found_bob_chrome = std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
        return row_starts_with(r, "profile|bob|chrome|");
    });
    CHECK(found_bob_chrome);

    // Every field-5 row parses cleanly under the escape-aware split.
    for (const auto& r : rows) {
        const auto fields = split_fields_escape_aware(r);
        REQUIRE(fields.size() == 5);
    }
#endif // !defined(_WIN32)
}

TEST_CASE("browser_inventory linux: linux_extension_rows_at resolves state from Secure Preferences "
         "for alice/edge and reports bob/chrome's rows",
         "[browser_inventory][linux][walk]") {
#if defined(_WIN32)
    SKIP("browser_inventory_linux_parsers.hpp's O_NOFOLLOW walk shell is POSIX-only (run-context.md "
        "X2) -- not compiled on Windows");
#else
    using namespace yuzu::browser_inventory::lnx;
    yuzu::test::TempDir dir{"yuzu_test_browser_inventory_extensions_"};
    std::string error;
    REQUIRE(materialize_browser_inventory_tree(dir.path, error));

    std::optional<std::string> token;
    const auto rows = linux_extension_rows_at(dir.path, token);
    CHECK_FALSE(token.has_value());
    REQUIRE_FALSE(rows.empty());

    for (const auto& r : rows) {
        CHECK(row_starts_with(r, "extension|"));
        const auto fields = split_fields_escape_aware(r);
        REQUIRE(fields.size() == 9);
    }

    // alice/edge/Default: >=1 enabled row, resolved from Secure Preferences
    // (edge/provenance.txt: 14 of 53 entries have state=1; Preferences
    // carries no extensions.settings at all on this real capture).
    const bool found_alice_enabled =
        std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
            if (!row_starts_with(r, "extension|alice|edge|Default|")) return false;
            const auto f = split_fields_escape_aware(r);
            return f[7] == "enabled" && f[6] != "-"; // name resolved
        });
    CHECK(found_alice_enabled);

    // bob/chrome/Default: the synthetic fixture's three states are covered
    // (enabled, disabled, unmodelled -- chrome/Default/Secure Preferences'
    // provenance.txt).
    const bool found_bob_enabled = std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
        return row_starts_with(r, "extension|bob|chrome|Default|") &&
              r.find("|enabled|") != std::string::npos;
    });
    const bool found_bob_disabled = std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
        return row_starts_with(r, "extension|bob|chrome|Default|") &&
              r.find("|disabled|") != std::string::npos;
    });
    const bool found_bob_unmodelled = std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
        return row_starts_with(r, "extension|bob|chrome|Default|") &&
              r.find("|unmodelled|") != std::string::npos;
    });
    CHECK(found_bob_enabled);
    CHECK(found_bob_disabled);
    CHECK(found_bob_unmodelled);
#endif // !defined(_WIN32)
}

TEST_CASE("browser_inventory linux: no row carries the fixtures' redaction/fabrication placeholders",
          "[browser_inventory][linux][privacy]") {
#if defined(_WIN32)
    SKIP("browser_inventory_linux_parsers.hpp's O_NOFOLLOW walk shell is POSIX-only (run-context.md "
        "X2) -- not compiled on Windows");
#else
    using namespace yuzu::browser_inventory::lnx;
    yuzu::test::TempDir dir{"yuzu_test_browser_inventory_privacy_"};
    std::string error;
    REQUIRE(materialize_browser_inventory_tree(dir.path, error));

    std::optional<std::string> profile_token;
    std::optional<std::string> extension_token;
    auto rows = linux_profile_rows_at(dir.path, profile_token);
    const auto extension_rows = linux_extension_rows_at(dir.path, extension_token);
    rows.insert(rows.end(), extension_rows.begin(), extension_rows.end());
    REQUIRE_FALSE(rows.empty());

    // edge/provenance.txt's redaction placeholder (profile.info_cache.*'s
    // user_name/gaia_id/gaia_name/... redacted string).
    CHECK_FALSE(any_row_contains(rows, "REDACTED"));
    // chrome/provenance.txt's fabricated-but-plausible user_name/gaia_id/
    // gaia_name values (the SYNTHETIC fixture's own "not just a placeholder
    // string" case -- see that file's Local State entry).
    CHECK_FALSE(any_row_contains(rows, "999999999999999999999"));
    CHECK_FALSE(any_row_contains(rows, "Not A Real Person"));
    CHECK_FALSE(any_row_contains(rows, "not-a-real-person@example.invalid"));
#endif // !defined(_WIN32)
}

TEST_CASE("browser_inventory linux: an absent root is supported with zero rows, not a failure",
          "[browser_inventory][linux][walk]") {
#if defined(_WIN32)
    SKIP("browser_inventory_linux_parsers.hpp's O_NOFOLLOW walk shell is POSIX-only (run-context.md "
        "X2) -- not compiled on Windows");
#else
    using namespace yuzu::browser_inventory::lnx;
    // Deliberately independent of the materialized tree (an absent root
    // needs nothing more than SOME existing, empty root under it).
    yuzu::test::TempDir dir{"yuzu_test_browser_inventory_absent_"};
    std::filesystem::create_directories(dir.path);

    std::optional<std::string> profile_token;
    const auto profile_rows = linux_profile_rows_at(dir.path, profile_token);
    CHECK(profile_rows.empty());
    CHECK_FALSE(profile_token.has_value());

    std::optional<std::string> extension_token;
    const auto extension_rows = linux_extension_rows_at(dir.path, extension_token);
    CHECK(extension_rows.empty());
    CHECK_FALSE(extension_token.has_value());

    std::optional<std::string> browser_token;
    const auto browser_rows = linux_browser_rows_at(dir.path, browser_token);
    CHECK_FALSE(browser_token.has_value());
    REQUIRE(browser_rows.size() == 3); // one row per candidate, all "not installed"
    for (const auto& r : browser_rows) CHECK(row_starts_with(r, "browser|"));
#endif // !defined(_WIN32)
}

TEST_CASE("browser_inventory linux: a chmod-000 profile dir reports constrained + a reason token",
          "[browser_inventory][linux][walk]") {
#if defined(_WIN32)
    SKIP("browser_inventory_linux_parsers.hpp's O_NOFOLLOW walk shell is POSIX-only (run-context.md "
        "X2) -- not compiled on Windows");
#else
    using namespace yuzu::browser_inventory::lnx;
    if (::geteuid() == 0) {
        SUCCEED("running as root (or CAP_DAC_OVERRIDE) -- permission bits are not enforced, skipping");
        return;
    }
    yuzu::test::TempDir dir{"yuzu_test_browser_inventory_chmod000_"};
    std::string error;
    REQUIRE(materialize_browser_inventory_tree(dir.path, error));

    const auto profile_dir = dir.path / "home" / "alice" / ".config" / "microsoft-edge" / "Default";
    REQUIRE(::chmod(profile_dir.string().c_str(), 0000) == 0);

    std::optional<std::string> token;
    const auto rows = linux_extension_rows_at(dir.path, token);

    // Restore permissions before TempDir's destructor tries to remove it.
    ::chmod(profile_dir.string().c_str(), 0700);

    REQUIRE(token.has_value());
    CHECK(token->find("linux:browser_inventory:permission_denied") != std::string::npos);
    // bob/chrome's rows are unaffected by alice's chmod -- a real failure
    // on one (user, browser, profile) triple never silently absorbs a
    // sibling's successful read.
    const bool found_bob = std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
        return row_starts_with(r, "extension|bob|chrome|Default|");
    });
    CHECK(found_bob);
#endif // !defined(_WIN32)
}
