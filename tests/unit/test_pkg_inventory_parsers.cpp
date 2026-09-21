/**
 * test_pkg_inventory_parsers.cpp — pure text/row tests for the pkg_inventory
 * plugin (pkg_inventory_parsers.hpp) plus small injected-root walk tests for
 * the macOS Homebrew shell. This TU is UNGUARDED: the pure cases run on every
 * OS; only the walk cases (which need the POSIX shell that does not exist on
 * Windows) wrap their bodies in `#if !defined(_WIN32)`.
 *
 * No committed fixture is loaded here. The directory layouts the walk cases
 * build in code are PROGRAMMATIC layouts that exercise the walk logic (nesting,
 * caps, hidden names, two prefixes, unreadable directories); they are not
 * captures and not committed fixtures. The real-capture tree manifest and the
 * dispatcher test are test_pkg_inventory_macos_parsers.cpp and
 * test_pkg_inventory_local_dispatcher.cpp.
 *
 * MUTATION NOTES (each names a wiring removal that would fail a case here):
 *  - dropping the macOS `/usr/local` prefix           -> "both prefixes" cases
 *  - dropping the macOS Caskroom walk                 -> casks=/cask row asserts
 *  - swallowing an open failure as zero rows          -> the constrained cases
 *  - ignoring Limits::max_entries_per_dir / max_package_rows
 *                                                     -> the cap / cap+1 cases
 */
#include <catch2/catch_test_macros.hpp>

#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_macos_parsers.hpp"
#include "pkg_inventory_parsers.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace pi = yuzu::pkg_inventory;

namespace {

/// The wire decoder's split (server/core/src/result_parsing.hpp): a backslash
/// immediately before a pipe makes it an escaped pipe, not a separator.
std::vector<std::string> split_wire(const std::string& row) {
    std::vector<std::string> fields;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '|' && !(i > 0 && row[i - 1] == '\\')) {
            fields.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    fields.push_back(cur);
    return fields;
}

} // namespace

// ── pure: tokens, status rows ────────────────────────────────────────────

TEST_CASE("pkg_inventory: tokens are wellformed and the fixed ones match the wire contract",
          "[pkg_inventory][parsers]") {
    CHECK(pi::is_wellformed_token("linux:owned_by_installed_apps"));
    CHECK(pi::is_wellformed_token("windows:planned"));
    CHECK(pi::is_wellformed_token("macos:homebrew_cellar:permission_denied"));
    CHECK_FALSE(pi::is_wellformed_token("planned"));
    CHECK_FALSE(pi::is_wellformed_token("freebsd:planned"));
    CHECK_FALSE(pi::is_wellformed_token("linux:"));
    CHECK_FALSE(pi::is_wellformed_token("linux:a::b"));
    CHECK_FALSE(pi::is_wellformed_token("linux:Upper"));
    CHECK(pi::kTokenLinuxPackagesOwned == "linux:owned_by_installed_apps");
    CHECK(pi::kTokenLinuxPlanned == "linux:planned");
    CHECK(pi::kTokenWindowsPlanned == "windows:planned");
    CHECK(pi::is_wellformed_token(pi::kTokenLinuxPackagesOwned));
    CHECK(pi::is_wellformed_token(pi::kTokenLinuxPlanned));
    CHECK(pi::is_wellformed_token(pi::kTokenWindowsPlanned));
    CHECK(pi::make_token("linux", "apt_sources_d", "entry_cap") == "linux:apt_sources_d:entry_cap");
    CHECK(pi::is_wellformed_token(pi::make_token("macos", "homebrew_taps", "io_error")));
}

TEST_CASE("pkg_inventory: status row is supported+dash when nothing failed, constrained+tokens otherwise",
          "[pkg_inventory][parsers][status]") {
    yuzu::shared::ConstraintAccumulator clean;
    // A genuinely absent manager/prefix: zero data rows and NO failure.
    CHECK(pi::status_row("managers", clean) == "status|managers|supported|-");

    yuzu::shared::ConstraintAccumulator bad;
    bad.add_failure("macos:homebrew_cellar:permission_denied");
    bad.add_failure("macos:homebrew_cellar:permission_denied"); // exact-string dedupe
    bad.add_failure("macos:homebrew_taps:entry_cap");
    CHECK(pi::status_row("packages", bad) ==
          "status|packages|constrained|"
          "macos:homebrew_cellar:permission_denied,macos:homebrew_taps:entry_cap");

    CHECK(pi::unsupported_status_row("packages", pi::kTokenLinuxPackagesOwned) ==
          "status|packages|unsupported|linux:owned_by_installed_apps");
    CHECK(pi::unsupported_status_row("managers", pi::kTokenLinuxPlanned) ==
          "status|managers|unsupported|linux:planned");
    CHECK(pi::unsupported_status_row("managers", pi::kTokenWindowsPlanned) ==
          "status|managers|unsupported|windows:planned");
}

TEST_CASE("pkg_inventory: action names round-trip and unknown names are rejected",
          "[pkg_inventory][parsers]") {
    CHECK(pi::parse_action("managers") == std::optional{pi::Action::managers});
    CHECK(pi::parse_action("packages") == std::optional{pi::Action::packages});
    CHECK_FALSE(pi::parse_action("list").has_value());
    CHECK_FALSE(pi::parse_action("").has_value());
    CHECK(pi::action_name(pi::Action::managers) == "managers");
    CHECK(pi::action_name(pi::Action::packages) == "packages");
}

TEST_CASE("pkg_inventory: errno -> token mapping keeps absence apart from every constraint",
          "[pkg_inventory][parsers][errno]") {
    CHECK(pi::is_benign_absent_errno(ENOENT));
    CHECK_FALSE(pi::is_benign_absent_errno(EACCES));
    CHECK_FALSE(pi::is_benign_absent_errno(ELOOP));
    CHECK(pi::open_failure_token(EACCES) == "permission_denied");
    CHECK(pi::open_failure_token(EPERM) == "permission_denied");
    CHECK(pi::open_failure_token(ELOOP) == "symlink_refused");
    CHECK(pi::open_failure_token(ENOTDIR) == "not_a_directory");
    // The named unmodelled bucket: distinct from absent and from every class above.
    CHECK(pi::open_failure_token(EIO) == "io_error");
}

// ── pure: row formatters + wire grammar (X12) ────────────────────────────

TEST_CASE("pkg_inventory: manager row has 7 fields and dashes for empty slots",
          "[pkg_inventory][parsers][rows]") {
    pi::Facts f;
    f.add("taps", std::size_t{3});
    f.add("formulae", std::size_t{66});
    const auto row = pi::format_manager_row(pi::Manager::homebrew, pi::Presence::present, "",
                                            "/opt/homebrew", f.str(), "");
    CHECK(row == "manager|homebrew|present|-|/opt/homebrew|taps=3;formulae=66|-");
    CHECK(split_wire(row).size() == 7);

    const auto bare = pi::format_manager_row(pi::Manager::rpm, pi::Presence::present, "", "",
                                             pi::Facts{}.str(), "");
    CHECK(bare == "manager|rpm|present|-|-|-|-");

    const auto unavailable =
        pi::format_manager_row(pi::Manager::homebrew, pi::Presence::unavailable, "", "/usr/local",
                               "-", "macos:homebrew_cellar:permission_denied");
    CHECK(unavailable ==
          "manager|homebrew|unavailable|-|/usr/local|-|macos:homebrew_cellar:permission_denied");
}

TEST_CASE("pkg_inventory: a trailing backslash or pipe in an OS value never shifts a column",
          "[pkg_inventory][parsers][rows][wire]") {
    // A trailing backslash would otherwise read as an escaped pipe and swallow
    // the separator; safe_output_field folds it to '/'.
    const auto manager = pi::format_manager_row(pi::Manager::apk, pi::Presence::present,
                                                "1.0\\", "C:\\pkgs\\", "k=v\\", "why\\");
    const auto fields = split_wire(manager);
    REQUIRE(fields.size() == 7);
    CHECK(fields[3] == "1.0/");
    CHECK(fields[4] == "C:/pkgs/");
    CHECK(fields[5] == "k=v/");
    CHECK(fields[6] == "why/");

    const auto pkg = pi::format_package_row("evil\\", "1|2\\", pi::PackageKind::cask);
    const auto pf = split_wire(pkg);
    REQUIRE(pf.size() == 5);
    CHECK(pf[0] == "package");
    CHECK(pf[1] == "homebrew");
    CHECK(pf[2] == "evil/");
    CHECK(pf[3] == "1\\|2/"); // the pipe survives as ONE escaped field character
    CHECK(pf[4] == "cask");

    const auto status = pi::format_status_row("managers", pi::StatusLevel::constrained, "a\\");
    CHECK(split_wire(status).size() == 4);
}

TEST_CASE("pkg_inventory: package row shape", "[pkg_inventory][parsers][rows]") {
    CHECK(pi::format_package_row("wget", "1.24.5", pi::PackageKind::formula) ==
          "package|homebrew|wget|1.24.5|formula");
    CHECK(pi::format_package_row("firefox", "130.0,1", pi::PackageKind::cask) ==
          "package|homebrew|firefox|130.0,1|cask");
}

// ── pure: Homebrew directory-name validation ─────────────────────────────

TEST_CASE("pkg_inventory: version_dir_name_ok accepts real Homebrew names, rejects the rest",
          "[pkg_inventory][parsers][names]") {
    for (const char* ok : {"wget", "1.24.5", "openssl@3", "gtk+", "3.3.1_1", "130.0,1",
                           "2024.09.01:abc"})
        CHECK(pi::version_dir_name_ok(ok));
    for (const char* bad : {"", ".metadata", ".keepme", ".", "..", "a/b", "a|b", "a\\b", "tab\there",
                            "nul\x01"})
        CHECK_FALSE(pi::version_dir_name_ok(bad));
    CHECK_FALSE(pi::version_dir_name_ok(std::string(256, 'a')));
    CHECK(pi::version_dir_name_ok(std::string(255, 'a')));
}

// ── walks: injected root (POSIX shell only; bodies guarded, see banner) ───

#if !defined(_WIN32)

namespace {

void write_file(const std::filesystem::path& root, const std::string& rel, const std::string& body,
                mode_t mode = 0644) {
    const auto p = root / rel;
    std::filesystem::create_directories(p.parent_path());
    {
        std::ofstream out(p, std::ios::binary);
        REQUIRE(out.good());
        out << body;
    }
    REQUIRE(::chmod(p.string().c_str(), mode) == 0);
}

void make_dir(const std::filesystem::path& root, const std::string& rel) {
    std::filesystem::create_directories(root / rel);
}

/// Restores a directory's permissions on scope exit so TempDir can remove it.
struct PermGuard {
    std::filesystem::path p;
    ~PermGuard() { ::chmod(p.string().c_str(), 0700); }
};

} // namespace

TEST_CASE("pkg_inventory walk: an absent root yields zero rows and NO constraint on the macOS shell",
          "[pkg_inventory][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_absent_"};
    std::filesystem::create_directories(dir.path);

    std::optional<std::string> token;
    CHECK(pi::mac::macos_manager_rows_at(dir.path, token).empty());
    CHECK_FALSE(token.has_value());
    CHECK(pi::mac::macos_package_rows_at(dir.path, token).empty());
    CHECK_FALSE(token.has_value());

    // A root that does not exist at all is the same "nothing here", not a failure.
    CHECK(pi::mac::macos_package_rows_at(dir.path / "does_not_exist", token).empty());
    CHECK_FALSE(token.has_value());
}

TEST_CASE("pkg_inventory walk: macOS Homebrew over both prefixes",
          "[pkg_inventory][walk][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_"};
    const auto& r = dir.path;
    // Apple-silicon prefix
    make_dir(r, "opt/homebrew/Cellar/wget/1.24.5");
    make_dir(r, "opt/homebrew/Cellar/openssl@3/3.3.1");
    make_dir(r, "opt/homebrew/Cellar/openssl@3/3.3.2");
    make_dir(r, "opt/homebrew/Cellar/.hidden/9.9"); // dot-prefixed: skipped
    write_file(r, "opt/homebrew/Cellar/README", "a file, not a formula\n");
    write_file(r, "opt/homebrew/Cellar/wget/INSTALL_RECEIPT.json", "{}"); // file, not a version dir
    make_dir(r, "opt/homebrew/Caskroom/some-cask/1.2.3,456");
    make_dir(r, "opt/homebrew/Caskroom/some-cask/.metadata");
    make_dir(r, "opt/homebrew/Library/Taps/homebrew/homebrew-core");
    make_dir(r, "opt/homebrew/Library/Taps/homebrew/homebrew-cask");
    make_dir(r, "opt/homebrew/Library/Taps/acme/homebrew-tools");
    // Intel prefix (also present on this synthetic host)
    make_dir(r, "usr/local/Cellar/jq/1.7.1");

    std::optional<std::string> token;
    const auto managers = pi::mac::macos_manager_rows_at(r, token);
    CHECK_FALSE(token.has_value());
    REQUIRE(managers.size() == 2);
    CHECK(managers[0] == "manager|homebrew|present|-|/opt/homebrew|taps=3;formulae=2;casks=1|-");
    CHECK(managers[1] == "manager|homebrew|present|-|/usr/local|taps=0;formulae=1;casks=0|-");
    for (const auto& row : managers)
        CHECK(split_wire(row).size() == 7);

    const auto packages = pi::mac::macos_package_rows_at(r, token);
    CHECK_FALSE(token.has_value());
    const std::vector<std::string> expected{
        "package|homebrew|openssl@3|3.3.1|formula",
        "package|homebrew|openssl@3|3.3.2|formula",
        "package|homebrew|wget|1.24.5|formula",
        "package|homebrew|some-cask|1.2.3,456|cask",
        "package|homebrew|jq|1.7.1|formula",
    };
    CHECK(packages == expected);
    for (const auto& row : packages)
        CHECK(split_wire(row).size() == 5);
}

TEST_CASE("pkg_inventory walk: /usr/local without Homebrew markers is not Homebrew",
          "[pkg_inventory][walk][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_nobrew_"};
    make_dir(dir.path, "usr/local/bin");
    make_dir(dir.path, "usr/local/share");
    std::optional<std::string> token;
    CHECK(pi::mac::macos_manager_rows_at(dir.path, token).empty());
    CHECK_FALSE(token.has_value());
}

TEST_CASE("pkg_inventory walk: an unreadable Cellar is unavailable + constrained, not absent",
          "[pkg_inventory][walk][macos]") {
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_eacces_"};
    make_dir(dir.path, "opt/homebrew/Cellar/wget/1.24.5");
    const auto cellar = dir.path / "opt/homebrew/Cellar";
    PermGuard guard{cellar};
    REQUIRE(::chmod(cellar.string().c_str(), 0000) == 0);

    std::optional<std::string> token;
    const auto managers = pi::mac::macos_manager_rows_at(dir.path, token);
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_cellar:permission_denied");
    REQUIRE(managers.size() == 1);
    CHECK(managers[0] == "manager|homebrew|unavailable|-|/opt/homebrew|-|"
                         "macos:homebrew_cellar:permission_denied");

    std::optional<std::string> ptoken;
    CHECK(pi::mac::macos_package_rows_at(dir.path, ptoken).empty());
    REQUIRE(ptoken.has_value());
    CHECK(*ptoken == "macos:homebrew_cellar:permission_denied");
}

TEST_CASE("pkg_inventory walk: a symlinked Cellar is refused, never followed",
          "[pkg_inventory][walk][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_symlink_"};
    make_dir(dir.path, "elsewhere/wget/1.24.5");
    make_dir(dir.path, "opt/homebrew");
    std::error_code ec;
    std::filesystem::create_directory_symlink(dir.path / "elsewhere", dir.path / "opt/homebrew/Cellar", ec);
    REQUIRE_FALSE(ec);

    std::optional<std::string> token;
    const auto packages = pi::mac::macos_package_rows_at(dir.path, token);
    CHECK(packages.empty()); // the symlink target's contents must not appear
    REQUIRE(token.has_value());
    CHECK(token->find("macos:homebrew_cellar:") == 0);
}

TEST_CASE("pkg_inventory walk: macOS Cellar entry cap and package row cap (injected Limits)",
          "[pkg_inventory][walk][macos][limits]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_caps_"};
    const auto& r = dir.path;
    make_dir(r, "opt/homebrew/Cellar/jq/1.7.1");
    make_dir(r, "opt/homebrew/Cellar/wget/1.24.4");
    make_dir(r, "opt/homebrew/Cellar/wget/1.24.5");

    {
        pi::Limits lim;
        lim.max_entries_per_dir = 2; // exactly the 2 formulae (jq, wget); wget has 2 versions
        std::optional<std::string> token;
        CHECK(pi::mac::macos_package_rows_at(r, token, lim).size() == 3);
        CHECK_FALSE(token.has_value()); // at the cap is complete

        make_dir(r, "opt/homebrew/Cellar/zsh/5.9"); // 3 formulae > cap 2
        const auto packages = pi::mac::macos_package_rows_at(r, token, lim);
        REQUIRE(token.has_value());
        CHECK(*token == "macos:homebrew_cellar:entry_cap");
        // The full walk yields 4 rows (jq 1, wget 2, zsh 1); a truncated listing
        // reads only 2 of the 3 formulae, so strictly fewer.
        CHECK(packages.size() < 4);
        std::filesystem::remove_all(r / "opt/homebrew/Cellar/zsh");
    }
    {
        pi::Limits lim; // row cap: 3 package rows exist
        lim.max_package_rows = 3;
        std::optional<std::string> token;
        CHECK(pi::mac::macos_package_rows_at(r, token, lim).size() == 3);
        CHECK_FALSE(token.has_value()); // at the cap is complete

        lim.max_package_rows = 2;
        const auto capped = pi::mac::macos_package_rows_at(r, token, lim);
        CHECK(capped.size() == 2);
        REQUIRE(token.has_value());
        CHECK(*token == "macos:homebrew_cellar:row_cap");
    }
}

#endif // !defined(_WIN32)
