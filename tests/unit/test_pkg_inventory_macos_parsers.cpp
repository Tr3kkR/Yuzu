/**
 * test_pkg_inventory_macos_parsers.cpp — injected-root tests for the pkg_inventory
 * macOS Homebrew walks (macos_manager_rows_at, macos_package_rows_at) over a
 * committed REAL CAPTURE tree manifest
 * (tests/unit/fixtures/wave10/pkg_inventory/macos/tree.manifest; provenance.txt
 * beside it). The seams are NOVEL design (peripherals' injected-root precedent is
 * Linux-only). This TU is UNGUARDED: the manifest parser cases run on every OS;
 * the cases that materialize a tree and run the walk wrap their BODIES in
 * `#if !defined(_WIN32)` because the O_NOFOLLOW/dirent walk shell
 * (posix_dir_walk.hpp) does not exist on Windows. They run on Linux CI too: the
 * walk reads an injected root, not this host's /opt/homebrew.
 *
 * The capture is FORMULAE-ONLY (ten real Cellar entries, an empty real Caskroom,
 * no Taps directory), per the plan-gate ruling: the capture host has no casks
 * and no taps, and populated trees would be invented. taps=0 / casks=0 here are
 * real "absent" / "exists but empty" readings; cask ROWS and non-zero tap counts
 * are not exercised against real data by this TU (see provenance.txt).
 *
 * MATERIALIZER: `<relpath><TAB><payload>`, payload `T:<text; escapes \n \t \\>` |
 * `D:` (directory) | `L:<target>` (symlink); '#' lines are comments. This tree
 * uses `D:` only, because the capture is a listing of directories.
 *
 * MUTATION NOTES (each names a wiring removal that would fail a case here):
 *  - dropping the Cellar walk in macos_package_rows_at      -> the ten exact package rows
 *  - dropping the Cellar count in macos_manager_rows_at     -> "formulae=10" exact row
 *  - dropping the Caskroom count                            -> "casks=0" exact row
 *  - dropping the Taps count                                -> "taps=0" exact row
 *  - reporting the injected root instead of the logical prefix -> the "/opt/homebrew" exact row
 *  - swallowing an open failure as zero rows / a false 0    -> the unreadable-Cellar case
 */
#include <catch2/catch_test_macros.hpp>

#include "pkg_inventory_macos_parsers.hpp"
#include "pkg_inventory_parsers.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <initializer_list>
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
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "pkg_inventory" / "macos";
#else
    return fs::path("tests/unit/fixtures/wave10/pkg_inventory/macos");
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

TEST_CASE("pkg_inventory macos tree manifest: line grammar", "[pkg_inventory][macos][manifest]") {
    Entry e;
    std::string err;

    REQUIRE(parse_manifest_line("opt/homebrew/Cellar/fmt/12.2.0\tD:", e, err));
    CHECK(e.kind == Payload::dir);
    REQUIRE(parse_manifest_line("a/b\tT:x\\ny", e, err));
    CHECK(e.kind == Payload::text);
    CHECK(e.data == "x\ny");
    REQUIRE(parse_manifest_line("a/link\tL:b", e, err));
    CHECK(e.kind == Payload::link);
    CHECK(e.data == "b");

    CHECK_FALSE(parse_manifest_line("no-tab-here", e, err));
    CHECK_FALSE(parse_manifest_line("a\tX:unknown", e, err));
    CHECK_FALSE(parse_manifest_line("a\tT:bad\\q", e, err));
    CHECK_FALSE(parse_manifest_line("../escape\tD:", e, err));
    CHECK_FALSE(parse_manifest_line("/abs\tD:", e, err));
    CHECK_FALSE(parse_manifest_line("a//b\tD:", e, err));
}

TEST_CASE("pkg_inventory macos tree manifest: the committed capture parses",
          "[pkg_inventory][macos][manifest]") {
    std::vector<Entry> entries;
    std::string err;
    REQUIRE(load_tree_manifest(entries, err));
    INFO(err);
    CHECK(entries.size() == 11); // ten Cellar version directories + the empty Caskroom

    const auto* fmt = find_entry(entries, "opt/homebrew/Cellar/fmt/12.2.0");
    REQUIRE(fmt != nullptr);
    CHECK(fmt->kind == Payload::dir);
    const auto* casks = find_entry(entries, "opt/homebrew/Caskroom");
    REQUIRE(casks != nullptr);
    CHECK(casks->kind == Payload::dir);
    // Formulae-only capture: no Taps entry is recorded (the host has none).
    for (const auto& e : entries)
        CHECK(e.rel.find("Library/Taps") == std::string::npos);
}

#if !defined(_WIN32)

namespace {

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

bool build_macos_tree(const fs::path& root, std::string& error) {
    std::vector<Entry> entries;
    return load_tree_manifest(entries, error) && materialize(root, entries, error);
}

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

/// Restores a directory's mode on scope exit so TempDir's remove_all can run
/// even when a REQUIRE unwinds. Declared AFTER the TempDir so it is destroyed
/// first.
struct ModeGuard {
    fs::path path;
    mode_t restore;
    ~ModeGuard() { ::chmod(path.string().c_str(), restore); }
};

} // namespace

TEST_CASE("pkg_inventory macos: manager row over the real-capture tree",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_"};
    std::string err;
    REQUIRE(build_macos_tree(dir.path, err));

    std::optional<std::string> token;
    const auto rows = mac::macos_manager_rows_at(dir.path, token);

    CHECK_FALSE(token.has_value());
    // Exactly one prefix (/opt/homebrew) holds Homebrew; /usr/local is absent.
    // The counts are read from the tree (10 Cellar formulae, an empty Caskroom,
    // no Taps directory), and root_path is the LOGICAL prefix, not the temp dir.
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "manager|homebrew|present|-|/opt/homebrew|taps=0;formulae=10;casks=0|-");
    CHECK(split_fields_escape_aware(rows[0]).size() == 7);
    CHECK(rows[0].find(dir.path.string()) == std::string::npos);
}

TEST_CASE("pkg_inventory macos: package rows over the real-capture tree",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_pkgs_"};
    std::string err;
    REQUIRE(build_macos_tree(dir.path, err));

    std::optional<std::string> token;
    const auto rows = mac::macos_package_rows_at(dir.path, token);

    CHECK_FALSE(token.has_value());
    // Sorted by formula name; version is the real directory name. The Caskroom
    // is empty in the capture, so there are formula rows only.
    const std::vector<std::string> expected{
        "package|homebrew|ccache|4.13.6_1|formula", "package|homebrew|cmake|4.4.2|formula",
        "package|homebrew|fmt|12.2.0|formula",      "package|homebrew|lz4|1.10.0|formula",
        "package|homebrew|meson|1.12.0|formula",    "package|homebrew|ninja|1.13.2|formula",
        "package|homebrew|openssl@3|3.6.3|formula", "package|homebrew|sqlite|3.53.4|formula",
        "package|homebrew|xz|5.8.3|formula",        "package|homebrew|zstd|1.5.7_1|formula",
    };
    REQUIRE(rows.size() == expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        INFO("row " << i);
        CHECK(rows[i] == expected[i]);
        CHECK(split_fields_escape_aware(rows[i]).size() == 5);
    }
}

TEST_CASE("pkg_inventory macos: an absent root is supported with zero rows",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_absent_"};

    std::error_code ec;
    fs::create_directories(dir.path / "empty_root", ec);
    REQUIRE_FALSE(ec);

    for (const auto& root : {dir.path / "no_such_root", dir.path / "empty_root"}) {
        INFO("root: " << root.filename().string());
        std::optional<std::string> token;
        CHECK(mac::macos_manager_rows_at(root, token).empty());
        CHECK_FALSE(token.has_value());
        CHECK(mac::macos_package_rows_at(root, token).empty());
        CHECK_FALSE(token.has_value());
    }
}

TEST_CASE("pkg_inventory macos: an unreadable Cellar is constrained, never a false zero",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    // Root (or CAP_DAC_OVERRIDE) bypasses the permission bits this case relies on.
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");

    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_eacces_"};
    std::string err;
    REQUIRE(build_macos_tree(dir.path, err));

    const auto cellar = dir.path / "opt/homebrew/Cellar";
    REQUIRE(::chmod(cellar.string().c_str(), 0000) == 0);
    ModeGuard restore{cellar, 0755};

    std::optional<std::string> token;
    const auto managers = mac::macos_manager_rows_at(dir.path, token);
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_cellar:permission_denied");
    // Homebrew is still reported present (Caskroom reads fine), but the
    // unreadable formulae fact is OMITTED rather than emitted as formulae=0.
    REQUIRE(managers.size() == 1);
    CHECK(managers[0] == "manager|homebrew|present|-|/opt/homebrew|taps=0;casks=0|-");

    token.reset();
    const auto packages = mac::macos_package_rows_at(dir.path, token);
    CHECK(packages.empty());
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_cellar:permission_denied");
}

#endif // !defined(_WIN32)
