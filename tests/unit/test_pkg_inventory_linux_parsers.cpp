/**
 * test_pkg_inventory_linux_parsers.cpp — injected-root tests for the pkg_inventory
 * Linux `managers` walk (linux_manager_rows_at) over a committed REAL CAPTURE
 * tree manifest (tests/unit/fixtures/wave10/pkg_inventory/linux/tree.manifest;
 * provenance in its header). This TU is UNGUARDED: the manifest parser cases run
 * on every OS; the cases that materialize a tree and run the walk wrap their
 * BODIES in `#if !defined(_WIN32)` because the O_NOFOLLOW/dirent walk shell
 * (posix_dir_walk.hpp) does not exist on Windows (scoped, reasoned exception:
 * the shell itself is absent there, the TU is not hidden).
 *
 * MATERIALIZER. Copied from test_peripherals_linux_parsers.cpp (that one is
 * TU-local, single-line, hardcoded to its own manifest) and extended with ONE
 * scheme defined and tested here: line = `<relpath><TAB><payload>`, payload
 * `T:<text; escapes \n \t \\>` (file) | `D:` (directory) | `L:<target>`
 * (symlink); '#' lines and blank lines are comments. No `B:` (binary): nothing
 * in this tree is binary, and unwired code is not committed.
 *
 * The tool files (usr/bin/dpkg, ...) land as 0644 from an ofstream, and the leg
 * probes them with an X_OK stat, so the test chmods them 0755 after
 * materialization. The three P1c-1 real-capture files in the fixture directory
 * (dpkg_arch.txt, apk_repositories.txt, apk_arch.txt) are copied into the tree
 * rather than duplicated into the manifest.
 *
 * MUTATION NOTES (each names a wiring removal that would fail a case here):
 *  - dropping the dpkg/arch read in linux_manager_rows_at   -> "architectures=arm64,i386" exact row
 *  - dropping the apt sources.list.d count                  -> "sources_d_files=1" exact row
 *  - counting only the first repo suffix / dropping .repo   -> "repo_files=4" exact row
 *  - dropping the dnf.conf / apk repositories / apk arch read -> the dnf and apk exact rows
 *  - probing /usr/bin/dnf with lstat instead of stat        -> the dnf row goes missing (symlink to dnf-3)
 *  - reading a tool-lookup EACCES as "absent"               -> the unreadable-usr/bin case
 *  - swallowing an open failure as a zero count             -> the unreadable sources.list.d case
 *  - emitting the injected root instead of the logical path -> the "no temp path" check
 */
#include <catch2/catch_test_macros.hpp>

#include "pkg_inventory_linux_parsers.hpp"
#include "pkg_inventory_parsers.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace {

// ── manifest format (portable: pure text, no filesystem) ─────────────────

enum class Payload { text, dir, link };

struct Entry {
    std::string rel;
    Payload kind = Payload::text;
    std::string data; ///< decoded text (T:) or link target (L:); empty for D:
};

/// Decodes a T: payload. Only \n, \t and \\ are escapes; anything else after a
/// backslash (or a trailing backslash) is a malformed manifest, never guessed.
bool unescape_text(std::string_view in, std::string& out, std::string& error) {
    out.clear();
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '\\') {
            out += in[i];
            continue;
        }
        if (i + 1 >= in.size()) {
            error = "trailing backslash in T: payload";
            return false;
        }
        switch (in[++i]) {
        case 'n': out += '\n'; break;
        case 't': out += '\t'; break;
        case '\\': out += '\\'; break;
        default: error = std::string{"unknown escape \\"} + in[i]; return false;
        }
    }
    return true;
}

bool rel_path_ok(std::string_view rel) {
    if (rel.empty() || rel.front() == '/' || rel.find('\\') != std::string_view::npos) return false;
    std::size_t pos = 0;
    while (pos <= rel.size()) {
        const auto slash = rel.find('/', pos);
        const auto seg = rel.substr(pos, slash == std::string_view::npos ? slash : slash - pos);
        if (seg.empty() || seg == "." || seg == "..") return false;
        if (slash == std::string_view::npos) break;
        pos = slash + 1;
    }
    return true;
}

/// One manifest line -> Entry. Comment and blank lines are the caller's to skip.
bool parse_manifest_line(const std::string& line, Entry& out, std::string& error) {
    const auto tab = line.find('\t');
    if (tab == std::string::npos) {
        error = "no tab separator: " + line;
        return false;
    }
    out = Entry{};
    out.rel = line.substr(0, tab);
    if (!rel_path_ok(out.rel)) {
        error = "unsafe relative path: " + out.rel;
        return false;
    }
    const std::string payload = line.substr(tab + 1);
    if (payload == "D:") {
        out.kind = Payload::dir;
        return true;
    }
    if (payload.rfind("L:", 0) == 0) {
        out.kind = Payload::link;
        out.data = payload.substr(2);
        if (out.data.empty()) {
            error = "empty link target for " + out.rel;
            return false;
        }
        return true;
    }
    if (payload.rfind("T:", 0) == 0) {
        out.kind = Payload::text;
        return unescape_text(std::string_view{payload}.substr(2), out.data, error);
    }
    error = "unknown payload scheme for " + out.rel;
    return false;
}

bool parse_manifest(std::istream& in, std::vector<Entry>& out, std::string& error) {
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back(); // CRLF-checkout tolerance
        if (line.empty() || line.front() == '#') continue;
        Entry e;
        if (!parse_manifest_line(line, e, error)) return false;
        out.push_back(std::move(e));
    }
    return true;
}

fs::path fixture_dir() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "pkg_inventory" / "linux";
#else
    return fs::path("tests/unit/fixtures/wave10/pkg_inventory/linux");
#endif
}

bool load_tree_manifest(std::vector<Entry>& out, std::string& error) {
    const auto path = fixture_dir() / "tree.manifest";
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "could not open " + path.string();
        return false;
    }
    return parse_manifest(in, out, error);
}

const Entry* find_entry(const std::vector<Entry>& entries, std::string_view rel) {
    for (const auto& e : entries)
        if (e.rel == rel) return &e;
    return nullptr;
}

} // namespace

TEST_CASE("pkg_inventory linux tree manifest: line grammar", "[pkg_inventory][linux][manifest]") {
    Entry e;
    std::string err;

    REQUIRE(parse_manifest_line("etc/a\tT:x\\ny\\tz\\\\w\\n", e, err));
    CHECK(e.kind == Payload::text);
    CHECK(e.data == "x\ny\tz\\w\n");

    REQUIRE(parse_manifest_line("usr/bin/tool\tT:", e, err)); // empty file
    CHECK(e.kind == Payload::text);
    CHECK(e.data.empty());

    REQUIRE(parse_manifest_line("opt/dir\tD:", e, err));
    CHECK(e.kind == Payload::dir);

    REQUIRE(parse_manifest_line("usr/bin/dnf\tL:dnf-3", e, err));
    CHECK(e.kind == Payload::link);
    CHECK(e.data == "dnf-3");

    // Malformed lines are errors, never guessed at.
    CHECK_FALSE(parse_manifest_line("no-tab-here", e, err));
    CHECK_FALSE(parse_manifest_line("a\tX:unknown", e, err));
    CHECK_FALSE(parse_manifest_line("a\tT:bad\\q", e, err));
    CHECK_FALSE(parse_manifest_line("a\tT:trailing\\", e, err));
    CHECK_FALSE(parse_manifest_line("a\tL:", e, err));
    // A manifest can never write outside the materialization root.
    CHECK_FALSE(parse_manifest_line("../escape\tT:x", e, err));
    CHECK_FALSE(parse_manifest_line("a/../b\tT:x", e, err));
    CHECK_FALSE(parse_manifest_line("/abs\tT:x", e, err));
    CHECK_FALSE(parse_manifest_line("a//b\tT:x", e, err));
    CHECK_FALSE(parse_manifest_line("a\\b\tT:x", e, err));
}

TEST_CASE("pkg_inventory linux tree manifest: the committed capture parses",
          "[pkg_inventory][linux][manifest]") {
    std::vector<Entry> entries;
    std::string err;
    REQUIRE(load_tree_manifest(entries, err));
    INFO(err);
    CHECK(entries.size() == 12);

    const auto* deb = find_entry(entries, "etc/apt/sources.list.d/debian.sources");
    REQUIRE(deb != nullptr);
    CHECK(deb->kind == Payload::text);
    CHECK(deb->data.rfind("Types: deb\n", 0) == 0);

    const auto* dnf_conf = find_entry(entries, "etc/dnf/dnf.conf");
    REQUIRE(dnf_conf != nullptr);
    CHECK(dnf_conf->data.rfind("[main]\n", 0) == 0);

    const auto* dnf = find_entry(entries, "usr/bin/dnf");
    REQUIRE(dnf != nullptr);
    CHECK(dnf->kind == Payload::link);
    CHECK(dnf->data == "dnf-3");
}

#if !defined(_WIN32)

namespace {

/// Tools the leg probes with an X_OK stat: a fresh ofstream file is 0644.
constexpr const char* kToolFiles[] = {"usr/bin/dpkg", "usr/bin/apt-get", "usr/bin/rpm",
                                      "usr/bin/dnf-3", "sbin/apk"};

bool materialize(const fs::path& root, const std::vector<Entry>& entries, std::string& error) {
    std::error_code ec;
    fs::create_directories(root, ec);
    if (ec) {
        error = "create_directories(root): " + ec.message();
        return false;
    }
    for (const auto& e : entries) {
        const auto out_path = root / e.rel;
        if (e.kind == Payload::dir) {
            fs::create_directories(out_path, ec);
        } else {
            fs::create_directories(out_path.parent_path(), ec);
            if (ec) {
                error = "create_directories failed for " + out_path.parent_path().string();
                return false;
            }
            if (e.kind == Payload::link) {
                fs::create_symlink(e.data, out_path, ec);
            } else {
                std::ofstream out(out_path, std::ios::binary);
                if (!out) {
                    error = "could not create " + out_path.string();
                    return false;
                }
                out << e.data;
            }
        }
        if (ec) {
            error = "materialize failed for " + out_path.string() + ": " + ec.message();
            return false;
        }
    }
    return true;
}

bool copy_fixture(const std::string& name, const fs::path& dest, std::string& error) {
    std::ifstream in(fixture_dir() / name, std::ios::binary);
    if (!in) {
        error = "could not open fixture " + name;
        return false;
    }
    std::error_code ec;
    fs::create_directories(dest.parent_path(), ec);
    std::ofstream out(dest, std::ios::binary);
    if (!out) {
        error = "could not create " + dest.string();
        return false;
    }
    out << in.rdbuf();
    return true;
}

/// Materializes the committed tree plus the three P1c-1 captures and chmods the
/// tool files 0755, under `root`.
bool build_linux_tree(const fs::path& root, std::string& error) {
    std::vector<Entry> entries;
    if (!load_tree_manifest(entries, error) || !materialize(root, entries, error)) return false;
    if (!copy_fixture("dpkg_arch.txt", root / "var/lib/dpkg/arch", error) ||
        !copy_fixture("apk_repositories.txt", root / "etc/apk/repositories", error) ||
        !copy_fixture("apk_arch.txt", root / "etc/apk/arch", error))
        return false;
    for (const auto* rel : kToolFiles) {
        const auto p = (root / rel).string();
        if (::chmod(p.c_str(), 0755) != 0) {
            error = "chmod 0755 failed for " + p;
            return false;
        }
    }
    return true;
}

/// Restores a directory's mode on scope exit so TempDir's remove_all can run
/// even when a REQUIRE unwinds. Declared AFTER the TempDir so it is destroyed
/// first.
struct ModeGuard {
    fs::path path;
    mode_t restore;
    ~ModeGuard() { ::chmod(path.string().c_str(), restore); }
};

/// Escape-aware field split (safe_output_field escapes a literal '|' as '\|').
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

bool row_contains(const std::vector<std::string>& rows, const std::string& exact) {
    for (const auto& r : rows)
        if (r == exact) return true;
    return false;
}

} // namespace

TEST_CASE("pkg_inventory linux: managers walk over the real-capture tree",
          "[pkg_inventory][linux][walk]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_"};
    std::string err;
    REQUIRE(build_linux_tree(dir.path, err));

    std::optional<std::string> token;
    const auto rows = lnx::linux_manager_rows_at(dir.path, token);

    CHECK_FALSE(token.has_value()); // nothing failed: supported, not constrained

    // Fixed order dpkg, apt, rpm, dnf, (pacman absent), apk. Each row carries a
    // value read from the tree, so removing any per-manager read (see the
    // MUTATION NOTES) changes an exact row below.
    const std::vector<std::string> expected{
        "manager|dpkg|present|-|/var/lib/dpkg|architectures=arm64,i386|-",
        "manager|apt|present|-|/etc/apt|sources_list_lines=0;sources_d_files=1|-",
        "manager|rpm|present|-|-|-|-",
        "manager|dnf|present|-|/etc/dnf|repo_files=4;dnf_conf_lines=6|-",
        "manager|apk|present|-|/etc/apk|repositories=2;tagged=0;arch=aarch64|-",
    };
    REQUIRE(rows.size() == expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        INFO("row " << i);
        CHECK(rows[i] == expected[i]);
    }

    for (const auto& r : rows) {
        INFO("row: " << r);
        CHECK(split_fields_escape_aware(r).size() == 7);
        // The row names the LOGICAL path, never the injected root.
        CHECK(r.find(dir.path.string()) == std::string::npos);
        // The Linux leg never enumerates a package.
        CHECK(r.rfind("package|", 0) == std::string::npos);
    }
    // No pacman anywhere in the tree: no row and no constraint (absent, not failed).
    for (const auto& r : rows)
        CHECK(r.find("|pacman|") == std::string::npos);
}

TEST_CASE("pkg_inventory linux: an absent root is supported with zero rows",
          "[pkg_inventory][linux][walk]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_absent_"};

    // Root that does not exist at all.
    std::optional<std::string> token;
    auto rows = lnx::linux_manager_rows_at(dir.path / "no_such_root", token);
    CHECK(rows.empty());
    CHECK_FALSE(token.has_value());

    // Root that exists but holds no package manager.
    std::error_code ec;
    fs::create_directories(dir.path / "empty_root", ec);
    REQUIRE_FALSE(ec);
    token.reset();
    rows = lnx::linux_manager_rows_at(dir.path / "empty_root", token);
    CHECK(rows.empty());
    CHECK_FALSE(token.has_value());
}

TEST_CASE("pkg_inventory linux: an unreadable source directory is constrained, never a false zero",
          "[pkg_inventory][linux][walk]") {
    using namespace yuzu::pkg_inventory;
    // Root (or CAP_DAC_OVERRIDE) bypasses the permission bits this case relies on.
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");

    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_eacces_"};
    std::string err;
    REQUIRE(build_linux_tree(dir.path, err));

    const auto sources_d = dir.path / "etc/apt/sources.list.d";
    REQUIRE(::chmod(sources_d.string().c_str(), 0000) == 0);
    ModeGuard restore{sources_d, 0755};

    std::optional<std::string> token;
    const auto rows = lnx::linux_manager_rows_at(dir.path, token);

    REQUIRE(token.has_value());
    CHECK(*token == "linux:apt_sources_d:permission_denied");
    REQUIRE(rows.size() == 5); // the other managers are unaffected
    // The apt row is still reported, but the unreadable fact is OMITTED rather
    // than emitted as sources_d_files=0.
    CHECK(row_contains(rows, "manager|apt|present|-|/etc/apt|sources_list_lines=0|-"));
    CHECK(row_contains(rows, "manager|dpkg|present|-|/var/lib/dpkg|architectures=arm64,i386|-"));
}

TEST_CASE("pkg_inventory linux: an inaccessible tool directory is a constraint, not an uninstalled manager",
          "[pkg_inventory][linux][walk]") {
    using namespace yuzu::pkg_inventory;
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");

    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_linux_tooleacces_"};
    std::string err;
    REQUIRE(build_linux_tree(dir.path, err));

    // usr/bin holds dpkg/apt-get/rpm/dnf: stat of any of them now fails EACCES.
    const auto usr_bin = dir.path / "usr/bin";
    REQUIRE(::chmod(usr_bin.string().c_str(), 0000) == 0);
    ModeGuard restore{usr_bin, 0755};

    std::optional<std::string> token;
    const auto rows = lnx::linux_manager_rows_at(dir.path, token);

    REQUIRE(token.has_value());
    for (const char* t : {"linux:dpkg_tool:permission_denied", "linux:apt_tool:permission_denied",
                          "linux:rpm_tool:permission_denied", "linux:dnf_tool:permission_denied",
                          "linux:pacman_tool:permission_denied"}) {
        INFO("token: " << t);
        CHECK(token->find(t) != std::string::npos);
    }
    // apk lives in sbin/, outside the unreadable directory, so it is still found.
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].rfind("manager|apk|present|", 0) == 0);
}

#endif // !defined(_WIN32)
