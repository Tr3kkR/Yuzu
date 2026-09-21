/**
 * test_pkg_inventory_parsers.cpp — pure text/row tests for the pkg_inventory
 * plugin (pkg_inventory_parsers.hpp) plus small injected-root walk tests for
 * the Linux and macOS shells. This TU is UNGUARDED: the pure cases run on every
 * OS; only the walk cases (which need the POSIX shell that does not exist on
 * Windows) wrap their bodies in `#if !defined(_WIN32)`.
 *
 * Fixtures (tests/unit/fixtures/wave10/pkg_inventory/linux/, provenance.txt
 * beside them): dpkg_arch.txt, apk_repositories.txt and apk_arch.txt are REAL
 * CAPTURES from debian:bookworm / alpine:3.20 containers.
 *
 * The directory layouts the walk cases build in code are PROGRAMMATIC layouts
 * that exercise the walk logic (nesting, caps, hidden names, two prefixes,
 * unreadable directories); they are not captures and not committed fixtures.
 * Real-capture tree manifests and the dispatcher test are the follow-on
 * package's (test_pkg_inventory_{linux,macos}_parsers.cpp).
 *
 * MUTATION NOTES (each names a wiring removal that would fail a case here):
 *  - dropping the macOS `/usr/local` prefix           -> "both prefixes" cases
 *  - dropping the macOS Caskroom walk                 -> casks=/cask row asserts
 *  - dropping the dpkg/arch read in the Linux walk    -> architectures= assert
 *  - reading a tool as present without the X_OK bit   -> "0644 dnf" assert
 *  - swallowing an open failure as zero rows          -> the constrained cases
 *  - dropping O_NONBLOCK from read_file_bounded       -> the FIFO case HANGS (timeout)
 *  - reading a tool-lookup failure as "absent"        -> the *_tool constraint cases
 *  - counting directories named like a source file     -> the "only files" source-count case
 *  - ignoring Limits::max_config_bytes / max_entries_per_dir / max_package_rows
 *                                                     -> the cap / cap+1 cases
 */
#include <catch2/catch_test_macros.hpp>

#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_linux_parsers.hpp"
#include "pkg_inventory_macos_parsers.hpp"
#include "pkg_inventory_parsers.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace pi = yuzu::pkg_inventory;

namespace {

std::filesystem::path fixture_dir() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return std::filesystem::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "pkg_inventory" / "linux";
#else
    return std::filesystem::path("tests/unit/fixtures/wave10/pkg_inventory/linux");
#endif
}

std::string read_fixture(const char* name) {
    std::ifstream in(fixture_dir() / name, std::ios::binary);
    REQUIRE(in.good());
    return std::string{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

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
    CHECK(pi::kTokenWindowsPlanned == "windows:planned");
    CHECK(pi::is_wellformed_token(pi::kTokenLinuxPackagesOwned));
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

// ── pure: text parsers over REAL CAPTURE fixtures ────────────────────────

TEST_CASE("pkg_inventory: parse_dpkg_arch_file over the real debian:bookworm capture",
          "[pkg_inventory][parsers][dpkg]") {
    const auto parsed = pi::parse_dpkg_arch_file(read_fixture("dpkg_arch.txt"));
    REQUIRE(parsed.arches.size() == 2);
    CHECK(parsed.arches[0] == "arm64"); // native first
    CHECK(parsed.arches[1] == "i386");  // the foreign architecture dpkg registered
    CHECK(parsed.rejected == 0);
    CHECK(pi::join_arches(parsed.arches) == "arm64,i386");
}

TEST_CASE("pkg_inventory: parse_dpkg_arch_file tolerates comments/blank/dupes and counts junk",
          "[pkg_inventory][parsers][dpkg]") {
    const auto parsed = pi::parse_dpkg_arch_file("# note\n\namd64\r\n  i386  \namd64\nAMD64\nx y\n");
    CHECK(parsed.arches == std::vector<std::string>{"amd64", "i386"});
    CHECK(parsed.rejected == 2); // "AMD64" (uppercase) and "x y" (space) are not arch tokens
    CHECK(pi::parse_dpkg_arch_file("").arches.empty());
    CHECK(pi::parse_dpkg_arch_file("").rejected == 0);
    // apk's /etc/apk/arch shares the one-token-per-line grammar.
    const auto apk = pi::parse_dpkg_arch_file(read_fixture("apk_arch.txt"));
    REQUIRE(apk.arches.size() == 1);
    CHECK(apk.arches[0] == "aarch64");
    // Alpine on x86 writes `x86_64`: the underscore is a valid token character.
    const auto x86 = pi::parse_dpkg_arch_file("x86_64\n");
    CHECK(x86.arches == std::vector<std::string>{"x86_64"});
    CHECK(x86.rejected == 0);
    CHECK(pi::arch_token_ok("x86_64"));
    CHECK_FALSE(pi::arch_token_ok("x86 64"));
    CHECK_FALSE(pi::arch_token_ok(""));
}

TEST_CASE("pkg_inventory: parse_apk_repositories counts repositories and tagged pins only",
          "[pkg_inventory][parsers][apk]") {
    const auto real = pi::parse_apk_repositories(read_fixture("apk_repositories.txt"));
    CHECK(real.count == 2);
    CHECK(real.tagged == 0);

    const auto tagged = pi::parse_apk_repositories(
        "# c\nhttps://a.example/main\n@testing https://a.example/testing\n\n  @edge https://b\n");
    CHECK(tagged.count == 3);
    CHECK(tagged.tagged == 2);
    CHECK(pi::parse_apk_repositories("").count == 0);
}

TEST_CASE("pkg_inventory: count_nonblank_noncomment_lines", "[pkg_inventory][parsers][lines]") {
    CHECK(pi::count_nonblank_noncomment_lines("") == 0);
    CHECK(pi::count_nonblank_noncomment_lines("\n\n  \n# only a comment\n") == 0);
    CHECK(pi::count_nonblank_noncomment_lines("Server = a\n# Server = b\n  Server = c") == 2);
    CHECK(pi::count_nonblank_noncomment_lines("[main]\r\ngpgcheck=1\r\n") == 2);
}

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
    CHECK(pi::has_suffix("x.list", ".list"));
    CHECK_FALSE(pi::has_suffix(".list", ".list")); // a bare suffix is not a file of that type
    CHECK_FALSE(pi::has_suffix("x.listing", ".list"));
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

bool starts_with(const std::string& s, std::string_view prefix) {
    return s.compare(0, prefix.size(), prefix) == 0;
}

} // namespace

TEST_CASE("pkg_inventory walk: an absent root yields zero rows and NO constraint on both OS shells",
          "[pkg_inventory][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_absent_"};
    std::filesystem::create_directories(dir.path);

    std::optional<std::string> token;
    CHECK(pi::lnx::linux_manager_rows_at(dir.path, token).empty());
    CHECK_FALSE(token.has_value());
    CHECK(pi::mac::macos_manager_rows_at(dir.path, token).empty());
    CHECK_FALSE(token.has_value());
    CHECK(pi::mac::macos_package_rows_at(dir.path, token).empty());
    CHECK_FALSE(token.has_value());

    // A root that does not exist at all is the same "nothing here", not a failure.
    CHECK(pi::mac::macos_package_rows_at(dir.path / "does_not_exist", token).empty());
    CHECK_FALSE(token.has_value());
}

TEST_CASE("pkg_inventory walk: linux managers report presence + config facts, never packages",
          "[pkg_inventory][walk][linux]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_"};
    const auto& r = dir.path;
    // dpkg + apt (tools must be executable; arch is the REAL CAPTURE content)
    write_file(r, "usr/bin/dpkg", "", 0755);
    write_file(r, "usr/bin/apt-get", "", 0755);
    write_file(r, "var/lib/dpkg/arch", read_fixture("dpkg_arch.txt"));
    write_file(r, "etc/apt/sources.list", "# comment\ndeb http://a stable main\n\ndeb http://b stable main\n");
    write_file(r, "etc/apt/sources.list.d/debian.sources", "Types: deb\n");
    write_file(r, "etc/apt/sources.list.d/extra.list", "deb http://c x y\n");
    write_file(r, "etc/apt/sources.list.d/notes.txt", "not a source file\n");
    // dnf present as a file but NOT executable -> not present (X_OK is required)
    write_file(r, "usr/bin/dnf", "", 0644);
    // apk (REAL CAPTURE content)
    write_file(r, "sbin/apk", "", 0755);
    write_file(r, "etc/apk/repositories", read_fixture("apk_repositories.txt"));
    write_file(r, "etc/apk/arch", read_fixture("apk_arch.txt"));
    // A dpkg status file exists and is never read (no per-package rows exist).
    write_file(r, "var/lib/dpkg/status", "Package: leaked-package-name\nStatus: install ok installed\n");

    std::optional<std::string> token;
    const auto rows = pi::lnx::linux_manager_rows_at(r, token);
    CHECK_FALSE(token.has_value());
    REQUIRE(rows.size() == 3);
    CHECK(rows[0] == "manager|dpkg|present|-|/var/lib/dpkg|architectures=arm64,i386|-");
    CHECK(rows[1] == "manager|apt|present|-|/etc/apt|sources_list_lines=2;sources_d_files=2|-");
    CHECK(rows[2] == "manager|apk|present|-|/etc/apk|repositories=2;tagged=0;arch=aarch64|-");
    for (const auto& row : rows) {
        CHECK(starts_with(row, "manager|"));
        CHECK(row.find("leaked-package-name") == std::string::npos);
        CHECK(split_wire(row).size() == 7);
    }
    // status row for this result is the clean one (constraint unset)
    yuzu::shared::ConstraintAccumulator clean;
    CHECK(pi::status_row("managers", clean) == "status|managers|supported|-");
}

TEST_CASE("pkg_inventory walk: linux dnf, rpm and pacman facts", "[pkg_inventory][walk][linux]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_rpm_"};
    const auto& r = dir.path;
    write_file(r, "usr/bin/rpm", "", 0755);
    write_file(r, "usr/bin/dnf", "", 0755);
    write_file(r, "etc/yum.repos.d/a.repo", "[a]\n");
    write_file(r, "etc/yum.repos.d/b.repo", "[b]\n");
    write_file(r, "etc/dnf/dnf.conf", "[main]\ngpgcheck=1\n# c\ninstallonly_limit=3\n");
    write_file(r, "usr/bin/pacman", "", 0755);
    write_file(r, "etc/pacman.conf", "[options]\n#x\nHoldPkg = pacman\n");
    write_file(r, "etc/pacman.d/mirrorlist", "Server = https://m1/$repo\n#Server = https://m2\nServer = https://m3\n");

    std::optional<std::string> token;
    const auto rows = pi::lnx::linux_manager_rows_at(r, token);
    CHECK_FALSE(token.has_value());
    REQUIRE(rows.size() == 3);
    CHECK(rows[0] == "manager|rpm|present|-|-|-|-");
    CHECK(rows[1] == "manager|dnf|present|-|/etc/dnf|repo_files=2;dnf_conf_lines=3|-");
    CHECK(rows[2] == "manager|pacman|present|-|/etc/pacman.d|pacman_conf_lines=2;mirrors=2|-");
}

TEST_CASE("pkg_inventory walk: a malformed dpkg arch file is constrained, the row survives",
          "[pkg_inventory][walk][linux]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_badarch_"};
    write_file(dir.path, "usr/bin/dpkg", "", 0755);
    write_file(dir.path, "var/lib/dpkg/arch", "amd64\nNOT AN ARCH\n");

    std::optional<std::string> token;
    const auto rows = pi::lnx::linux_manager_rows_at(dir.path, token);
    REQUIRE(token.has_value());
    CHECK(*token == "linux:dpkg_arch:malformed");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "manager|dpkg|present|-|/var/lib/dpkg|architectures=amd64|-");
}

TEST_CASE("pkg_inventory walk: an unreadable apt sources.list.d is constrained, not zero",
          "[pkg_inventory][walk][linux]") {
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_eacces_"};
    write_file(dir.path, "usr/bin/apt-get", "", 0755);
    write_file(dir.path, "etc/apt/sources.list.d/a.list", "deb http://a x y\n");
    const auto d = dir.path / "etc/apt/sources.list.d";
    PermGuard guard{d};
    REQUIRE(::chmod(d.string().c_str(), 0000) == 0);

    std::optional<std::string> token;
    const auto rows = pi::lnx::linux_manager_rows_at(dir.path, token);
    REQUIRE(token.has_value());
    CHECK(*token == "linux:apt_sources_d:permission_denied");
    REQUIRE(rows.size() == 1);
    // The count fact is OMITTED (never a false 0) when the directory could not be read.
    CHECK(rows[0] == "manager|apt|present|-|/etc/apt|sources_list_lines=0|-");
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

TEST_CASE("pkg_inventory walk: apt/dnf source counts include only files, never directories",
          "[pkg_inventory][walk][linux]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_srcfiles_"};
    const auto& r = dir.path;
    write_file(r, "usr/bin/apt-get", "", 0755);
    write_file(r, "usr/bin/dnf", "", 0755);
    write_file(r, "etc/apt/sources.list.d/real.list", "deb http://a x y\n");
    make_dir(r, "etc/apt/sources.list.d/dir.list");    // a directory, not a source file
    make_dir(r, "etc/apt/sources.list.d/dir.sources"); // likewise
    std::error_code ec;
    std::filesystem::create_symlink("real.list", r / "etc/apt/sources.list.d/link.list", ec);
    REQUIRE_FALSE(ec);
    REQUIRE(::mkfifo((r / "etc/apt/sources.list.d/pipe.list").string().c_str(), 0600) == 0);
    write_file(r, "etc/yum.repos.d/a.repo", "[a]\n");
    make_dir(r, "etc/yum.repos.d/dir.repo");

    std::optional<std::string> token;
    const auto rows = pi::lnx::linux_manager_rows_at(r, token);
    CHECK_FALSE(token.has_value());
    REQUIRE(rows.size() == 2);
    // real.list + link.list only (the linked source file counts; dirs and the fifo do not).
    CHECK(rows[0] == "manager|apt|present|-|/etc/apt|sources_list_lines=0;sources_d_files=2|-");
    CHECK(rows[1] == "manager|dnf|present|-|/etc/dnf|repo_files=1;dnf_conf_lines=0|-");
}

TEST_CASE("pkg_inventory walk: a FIFO in place of a config file is rejected, never blocked on",
          "[pkg_inventory][walk][linux]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_fifo_"};
    write_file(dir.path, "usr/bin/dpkg", "", 0755);
    make_dir(dir.path, "var/lib/dpkg");
    // No writer ever opens this FIFO. Without O_NONBLOCK the bounded reader's
    // open() blocks forever (this case then hangs); with it the open returns
    // at once and the regular-file check refuses the node.
    REQUIRE(::mkfifo((dir.path / "var/lib/dpkg/arch").string().c_str(), 0600) == 0);

    std::optional<std::string> token;
    const auto rows = pi::lnx::linux_manager_rows_at(dir.path, token);
    REQUIRE(token.has_value());
    CHECK(*token == "linux:dpkg_arch:not_regular");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "manager|dpkg|present|-|/var/lib/dpkg|-|-");
}

TEST_CASE("pkg_inventory walk: a failed tool lookup is constrained, not an absent manager",
          "[pkg_inventory][walk][linux]") {
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_toolloop_"};
    make_dir(dir.path, "usr/bin");
    // dpkg resolves through a self-referential symlink: stat() fails with ELOOP,
    // which is neither ENOENT nor ENOTDIR, so it must NOT read as "not installed".
    std::error_code ec;
    std::filesystem::create_symlink("dpkg", dir.path / "usr/bin/dpkg", ec);
    REQUIRE_FALSE(ec);

    std::optional<std::string> token;
    const auto rows = pi::lnx::linux_manager_rows_at(dir.path, token);
    CHECK(rows.empty()); // the tool could not be confirmed, so no manager row ...
    REQUIRE(token.has_value());
    CHECK(*token == "linux:dpkg_tool:symlink_refused"); // ... but the failure is surfaced
}

TEST_CASE("pkg_inventory walk: an untraversable tool directory is constrained per manager",
          "[pkg_inventory][walk][linux]") {
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_tooldir_"};
    write_file(dir.path, "usr/bin/dpkg", "", 0755);
    const auto d = dir.path / "usr/bin";
    PermGuard guard{d};
    REQUIRE(::chmod(d.string().c_str(), 0000) == 0);

    std::optional<std::string> token;
    const auto rows = pi::lnx::linux_manager_rows_at(dir.path, token);
    CHECK(rows.empty());
    REQUIRE(token.has_value());
    CHECK(token->find("linux:dpkg_tool:permission_denied") != std::string::npos);
    CHECK(token->find("linux:apt_tool:permission_denied") != std::string::npos);
}

TEST_CASE("pkg_inventory walk: config file byte cap at cap and cap+1 (injected Limits)",
          "[pkg_inventory][walk][linux][limits]") {
    pi::Limits lim;
    lim.max_config_bytes = 12;

    {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_cap_at_"};
        write_file(dir.path, "usr/bin/dpkg", "", 0755);
        write_file(dir.path, "var/lib/dpkg/arch", "amd64\narm64\n"); // exactly 12 bytes
        std::optional<std::string> token;
        const auto rows = pi::lnx::linux_manager_rows_at(dir.path, token, lim);
        CHECK_FALSE(token.has_value()); // at the cap is NOT oversized
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "manager|dpkg|present|-|/var/lib/dpkg|architectures=amd64,arm64|-");
    }
    {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_cap_over_"};
        write_file(dir.path, "usr/bin/dpkg", "", 0755);
        write_file(dir.path, "var/lib/dpkg/arch", "amd64\narm64\ni386\n"); // 18 bytes
        std::optional<std::string> token;
        const auto rows = pi::lnx::linux_manager_rows_at(dir.path, token, lim);
        REQUIRE(token.has_value());
        CHECK(*token == "linux:dpkg_arch:oversized");
        REQUIRE(rows.size() == 1);
        // Only the 12-byte prefix was parsed: `i386` is past the cap.
        CHECK(rows[0] == "manager|dpkg|present|-|/var/lib/dpkg|architectures=amd64,arm64|-");
    }
    {
        // The count_lines path (sources.list) honours the same bound.
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_cap_lines_"};
        write_file(dir.path, "usr/bin/apt-get", "", 0755);
        write_file(dir.path, "etc/apt/sources.list", "deb a\ndeb b\ndeb c\n"); // 18 bytes
        std::optional<std::string> token;
        const auto rows = pi::lnx::linux_manager_rows_at(dir.path, token, lim);
        REQUIRE(token.has_value());
        CHECK(*token == "linux:apt_sources_list:oversized");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "manager|apt|present|-|/etc/apt|sources_list_lines=2;sources_d_files=0|-");
    }
}

TEST_CASE("pkg_inventory walk: directory entry cap at cap and cap+1 (injected Limits)",
          "[pkg_inventory][walk][linux][limits]") {
    pi::Limits lim;
    lim.max_entries_per_dir = 3;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_entrycap_"};
    const auto& r = dir.path;
    write_file(r, "usr/bin/apt-get", "", 0755);
    for (const char* n : {"a.list", "b.list", "c.list"})
        write_file(r, std::string{"etc/apt/sources.list.d/"} + n, "deb x y z\n");

    std::optional<std::string> token;
    auto rows = pi::lnx::linux_manager_rows_at(r, token, lim);
    CHECK_FALSE(token.has_value()); // exactly at the cap is complete
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "manager|apt|present|-|/etc/apt|sources_list_lines=0;sources_d_files=3|-");

    write_file(r, "etc/apt/sources.list.d/d.list", "deb x y z\n"); // cap + 1
    rows = pi::lnx::linux_manager_rows_at(r, token, lim);
    REQUIRE(token.has_value());
    CHECK(*token == "linux:apt_sources_d:entry_cap");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "manager|apt|present|-|/etc/apt|sources_list_lines=0;sources_d_files=3|-");
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
