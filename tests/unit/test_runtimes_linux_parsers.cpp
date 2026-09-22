/**
 * test_runtimes_linux_parsers.cpp -- tests for the runtimes plugin's Linux leg
 * (runtimes_linux_parsers.hpp): the portable pure layer on EVERY OS, and the
 * injected-root directory walks over a materialized fixture tree on POSIX.
 *
 * SCOPED GUARD (reasoned exception to the never-guard-a-test-TU rule): the walk
 * shell is built on agents/shared/posix_dir_walk.hpp, which does not exist on
 * Windows, so the tree walk tests sit in one `#if !defined(_WIN32)` region.
 * Everything else (manifest decoder, errno maps, wire-grammar checks) is
 * unguarded. The dispatcher TU is never guarded.
 *
 * FIXTURE TREE. tests/unit/fixtures/wave10/runtimes/linux/tree.manifest
 * describes a root subtree (REAL CAPTURE structure: eclipse-temurin:17,
 * mcr.microsoft.com/dotnet/runtime:8.0, debian:12 -- commands and dates in
 * provenance.txt), materialized under a fresh yuzu_test_runtimes_ TempDir;
 * nothing is read from a real /usr. Line grammar (decoded and tested here):
 *   <relative-path> TAB T:<text with \n \t \\ escapes> | L:<symlink target> | D:
 * Shapes the captures lack (an sdk/ directory, an oversized `release`, a planted
 * symlink) are built inline and labelled SYNTHETIC.
 *
 * MUTATION NOTES: exact-row assertions fail if a *_rows_at stops reading its
 * root or drops the vendor/flavour/version wiring or the exact-row dedupe;
 * resetting the accumulator per root turns the "later root never hides an
 * earlier failure" case red; dropping O_NOFOLLOW on `release` surfaces the
 * planted target as a row; following symlinked entries duplicates rows; dropping
 * the 64 KiB bound or the nullopt-row check loses the oversize/unparsable tokens;
 * discarding the rows before emit_read in run_linux_at turns the clean
 * CommandContext case red; reporting OK/FULL regardless of the accumulator turns
 * the forced-constraint CommandContext case red; requiring an alias target to
 * OPEN turns the dangling-alias case red. The two chmod-000 cases SKIP at euid 0;
 * the constrained path stays covered there by the symlink, cap and oversize
 * cases and by the forced-constraint CommandContext case, none of which needs
 * permission bits.
 */
#include <catch2/catch_test_macros.hpp>

#include "runtimes_legs.hpp"
#include "runtimes_linux_parsers.hpp"
#include "runtimes_parsers.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#if !defined(_WIN32)
#include "local_dispatcher.hpp" // yuzu::agent::LocalDispatcher (a real CommandContext)

#include <yuzu/plugin.h>

#include <sys/stat.h>
#include <unistd.h>
#endif

namespace rt = yuzu::runtimes;
namespace lnx = yuzu::runtimes::lnx;
namespace fs = std::filesystem;

namespace {

// -- manifest line decoder (pure; portable) ----------------------------------------

enum class ManifestKind { text, symlink, directory };

struct ManifestEntry {
    std::string rel;
    ManifestKind kind = ManifestKind::text;
    std::string payload; // decoded text | link target | (unused)
};

enum class LineOutcome { skipped, entry, malformed };

struct ParsedLine {
    LineOutcome outcome = LineOutcome::skipped;
    ManifestEntry entry;
    std::string error;
};

/// Decodes the escapes of a `T:` payload (\n, \t, \\). nullopt on a dangling
/// backslash or an unknown escape.
std::optional<std::string> unescape_text(std::string_view s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '\\') {
            out += s[i];
            continue;
        }
        if (++i >= s.size()) return std::nullopt;
        switch (s[i]) {
        case 'n':  out += '\n'; break;
        case 't':  out += '\t'; break;
        case '\\': out += '\\'; break;
        default:   return std::nullopt;
        }
    }
    return out;
}

ParsedLine parse_manifest_line(std::string line) {
    ParsedLine r;
    if (!line.empty() && line.back() == '\r') line.pop_back(); // CRLF checkout tolerance
    if (line.empty() || line.front() == '#') return r;
    const auto bad = [&r](std::string msg) {
        r.outcome = LineOutcome::malformed;
        r.error = std::move(msg);
        return r;
    };
    const auto tab = line.find('\t');
    if (tab == std::string::npos || tab == 0) return bad("no tab separator: " + line);
    r.entry.rel = line.substr(0, tab);
    if (r.entry.rel.front() == '/' || r.entry.rel.find("..") != std::string::npos)
        return bad("path must be relative and inside the tree: " + r.entry.rel);
    const std::string payload = line.substr(tab + 1);
    if (payload.size() < 2 || payload[1] != ':') return bad("payload lacks a kind prefix: " + line);
    const std::string body = payload.substr(2);
    switch (payload[0]) {
    case 'T': {
        auto t = unescape_text(body);
        if (!t) return bad("bad escape in T: payload: " + line);
        r.entry.kind = ManifestKind::text;
        r.entry.payload = std::move(*t);
        break;
    }
    case 'L':
        r.entry.kind = ManifestKind::symlink;
        r.entry.payload = body;
        break;
    case 'D': r.entry.kind = ManifestKind::directory; break;
    default: return bad("unknown payload kind: " + line);
    }
    if (r.entry.kind == ManifestKind::symlink && r.entry.payload.empty())
        return bad("empty L: payload: " + line);
    r.outcome = LineOutcome::entry;
    return r;
}

bool token_matches_leg_grammar(std::string_view t) {
    // ^linux:[a-z0-9_]+(:[a-z0-9_]+)*$
    constexpr std::string_view p = "linux:";
    if (t.substr(0, p.size()) != p) return false;
    t.remove_prefix(p.size());
    bool seg_nonempty = false;
    for (char c : t) {
        if (c == ':') {
            if (!seg_nonempty) return false;
            seg_nonempty = false;
        } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
            seg_nonempty = true;
        } else {
            return false;
        }
    }
    return seg_nonempty;
}

} // namespace

// == portable pure layer (every OS) =====================================================

TEST_CASE("runtimes linux: manifest line decoder handles every payload kind",
          "[runtimes][linux][manifest]") {
    // Blank lines and comments are skipped.
    CHECK(parse_manifest_line("").outcome == LineOutcome::skipped);
    CHECK(parse_manifest_line("# a comment\twith a tab").outcome == LineOutcome::skipped);

    auto t = parse_manifest_line("usr/x\tT:a\\nb\\tc\\\\d");
    REQUIRE(t.outcome == LineOutcome::entry);
    CHECK(t.entry.rel == "usr/x");
    CHECK(t.entry.kind == ManifestKind::text);
    CHECK(t.entry.payload == "a\nb\tc\\d");

    auto empty = parse_manifest_line("usr/empty\tT:");
    REQUIRE(empty.outcome == LineOutcome::entry);
    CHECK(empty.entry.payload.empty()); // an empty regular file

    auto crlf = parse_manifest_line("opt/r\tT:JAVA_VERSION=\"17\"\\n\r"); // CRLF tolerated
    REQUIRE(crlf.outcome == LineOutcome::entry);
    CHECK(crlf.entry.kind == ManifestKind::text);
    CHECK(crlf.entry.payload == "JAVA_VERSION=\"17\"\n");

    auto l = parse_manifest_line("usr/lib/jvm/java-1.17.0-openjdk-arm64\tL:java-17-openjdk-arm64");
    REQUIRE(l.outcome == LineOutcome::entry);
    CHECK(l.entry.kind == ManifestKind::symlink);
    CHECK(l.entry.payload == "java-17-openjdk-arm64");

    auto d = parse_manifest_line("usr/share/dotnet/sdk\tD:");
    REQUIRE(d.outcome == LineOutcome::entry);
    CHECK(d.entry.kind == ManifestKind::directory);
}

TEST_CASE("runtimes linux: manifest line decoder rejects malformed lines, never skips them",
          "[runtimes][linux][manifest]") {
    for (const char* bad : {"no-tab-here", "\tT:x", "/abs\tT:x", "a/../b\tT:x", "usr/x\tQ:x",
                            "usr/x\tnokind", "usr/x\tT:bad\\q", "usr/x\tT:dangling\\",
                            "usr/x\tF:sibling.txt", "usr/x\tL:"}) {
        INFO("line: " << bad);
        CHECK(parse_manifest_line(bad).outcome == LineOutcome::malformed);
    }
}

TEST_CASE("runtimes linux: errno maps separate absent from failure",
          "[runtimes][linux][parsers]") {
    // ENOENT is the ONLY benign case in each map.
    CHECK_FALSE(lnx::dir_open_errno_token(ENOENT).has_value());
    CHECK_FALSE(lnx::stat_errno_token(ENOENT).has_value());
    CHECK_FALSE(lnx::file_open_errno_token(ENOENT).has_value());

    CHECK(lnx::dir_open_errno_token(EACCES) == lnx::kTokPermissionDenied);
    CHECK(lnx::dir_open_errno_token(ELOOP) == lnx::kTokSymlinkRefused);
    CHECK(lnx::dir_open_errno_token(ENOTDIR) == lnx::kTokNotADirectory);
    CHECK(lnx::dir_open_errno_token(EIO) == lnx::kTokDirOpenFailed);
    CHECK(lnx::stat_errno_token(EACCES) == lnx::kTokPermissionDenied);
    CHECK(lnx::stat_errno_token(EIO) == lnx::kTokStatFailed);
    CHECK(lnx::file_open_errno_token(EACCES) == lnx::kTokPermissionDenied);
    CHECK(lnx::file_open_errno_token(ELOOP) == lnx::kTokSymlinkRefused);
    CHECK(lnx::file_open_errno_token(EIO) == lnx::kTokReadFailed);
}

TEST_CASE("runtimes linux: every failure token matches the leg-token grammar",
          "[runtimes][linux][parsers]") {
    for (const auto tok :
         {lnx::kTokPermissionDenied, lnx::kTokSymlinkRefused, lnx::kTokNotADirectory,
          lnx::kTokDirOpenFailed, lnx::kTokStatFailed, lnx::kTokReadFailed, lnx::kTokTruncated,
          lnx::kTokNotARegularFile, lnx::kTokReleaseOversize, lnx::kTokReleaseUnparsable}) {
        INFO("token: " << tok);
        CHECK(token_matches_leg_grammar(tok));
    }
}

TEST_CASE("runtimes linux: join_logical avoids a doubled slash",
          "[runtimes][linux][parsers]") {
    CHECK(lnx::join_logical("/", "usr") == "/usr");
    CHECK(lnx::join_logical("/usr", "bin") == "/usr/bin");
}

// == walks over the fixture tree (POSIX) =================================================

#if !defined(_WIN32)

namespace {

fs::path fixture_dir() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "runtimes" / "linux";
#else
    return fs::path("tests/unit/fixtures/wave10/runtimes/linux");
#endif
}

/// Materializes tree.manifest under `root`. Returns false with `error` set on any
/// failure so the caller can REQUIRE with a useful message.
bool materialize_manifest(const fs::path& root, std::string& error) {
    const auto manifest_file = fixture_dir() / "tree.manifest";
    std::ifstream in(manifest_file, std::ios::binary);
    if (!in) {
        error = "could not open " + manifest_file.string();
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        const auto p = parse_manifest_line(line);
        if (p.outcome == LineOutcome::skipped) continue;
        if (p.outcome == LineOutcome::malformed) {
            error = p.error;
            return false;
        }
        const fs::path target = root / p.entry.rel;
        std::error_code ec;
        fs::create_directories(p.entry.kind == ManifestKind::directory ? target
                                                                        : target.parent_path(),
                               ec);
        if (ec) {
            error = "create_directories failed for " + target.string() + ": " + ec.message();
            return false;
        }
        switch (p.entry.kind) {
        case ManifestKind::directory: break;
        case ManifestKind::symlink:
            fs::create_symlink(p.entry.payload, target, ec);
            if (ec) {
                error = "create_symlink failed for " + target.string() + ": " + ec.message();
                return false;
            }
            break;
        case ManifestKind::text: {
            std::ofstream out(target, std::ios::binary);
            if (!out) {
                error = "could not create " + target.string();
                return false;
            }
            out << p.entry.payload;
            break;
        }
        }
    }
    return true;
}

void write_text(const fs::path& p, const std::string& text) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    REQUIRE_FALSE(ec);
    std::ofstream out(p, std::ios::binary);
    REQUIRE(out.good());
    out << text;
}

void make_dir(const fs::path& p) {
    std::error_code ec;
    fs::create_directories(p, ec);
    REQUIRE_FALSE(ec);
}

/// Restores a path's permission bits at scope exit (declared AFTER the TempDir so it runs
/// first and remove_all can descend).
struct PermRestore {
    fs::path path;
    ~PermRestore() { ::chmod(path.c_str(), 0755); }
};

/// permission-bit cases are vacuous when the process bypasses them.
bool running_privileged() { return ::geteuid() == 0; }

using Acc = yuzu::shared::ConstraintAccumulator;

const char* kTemurinRow = "jvm|jdk|17.0.20|/opt/java/openjdk|Eclipse Adoptium";
const char* kDebianRow = "jvm|unmodelled|17.0.20.1|/usr/lib/jvm/java-17-openjdk-arm64|Debian";
const char* kDotnetRow =
    "dotnet|core|8.0.31|/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.31|-";

// -- CommandContext-level harness --------------------------------------------------------
// Drives the PRODUCTION leg body (lnx::run_linux_at) through a real CommandContext via
// LocalDispatcher (the test_filesystem_posture_local_dispatcher.cpp precedent: a synthetic
// descriptor whose execute() calls the code under test), so what is asserted is the rows the
// command actually emits AND the typed result status it reports -- not only the walk's return
// values.

struct LegRun {
    int rc = -1;
    std::vector<std::string> rows;
    YuzuResultStatus status = YUZU_RESULT_STATUS_UNDECLARED;
    YuzuResultCompleteness completeness = YUZU_RESULT_COMPLETENESS_UNKNOWN;
    std::string provenance;
};

const fs::path* g_leg_root = nullptr;

int leg_execute(YuzuCommandContext* raw, const char* action, const YuzuParam* /*params*/,
                std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    const auto a = rt::parse_action(action);
    if (!a) return 1;
    return lnx::run_linux_at(ctx, *a, *g_leg_root);
}

LegRun run_leg(rt::Action action, const fs::path& root) {
    g_leg_root = &root;
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &leg_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(&descriptor, rt::action_name(action));
    g_leg_root = nullptr;

    LegRun out;
    out.rc = result.rc;
    out.status = result.result_status;
    out.completeness = result.result_completeness;
    out.provenance = result.result_provenance;
    std::istringstream lines(result.captured);
    for (std::string line; std::getline(lines, line);)
        if (!line.empty()) out.rows.push_back(line);
    return out;
}

} // namespace

TEST_CASE("runtimes linux: jvm_rows_at reads both roots' release files, skips the alias symlink",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_jvm_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));
    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc);
    CHECK_FALSE(acc.any_failure());
    // Root order: /usr/lib/jvm (Debian, no IMAGE_TYPE -> unmodelled), then /opt/java (Temurin).
    // java-1.17.0-openjdk-arm64 is a symlink alias of java-17-openjdk-arm64: not a second row.
    REQUIRE(rows.size() == 2);
    CHECK(rows[0] == kDebianRow);
    CHECK(rows[1] == kTemurinRow);
}

TEST_CASE("runtimes linux: dotnet_rows_at reads the captured runtime tree",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_dotnet_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));
    Acc acc;
    const auto rows = lnx::dotnet_rows_at(dir.path, acc);
    CHECK_FALSE(acc.any_failure());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == kDotnetRow);
}

TEST_CASE("runtimes linux: dotnet sdk, unmodelled framework and non-version entries (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // SYNTHETIC tree: the captured runtime image has no sdk/ directory and no unusual entries.
    // Modelled on the documented dotnet install layout (shared/<fw>/<ver>, sdk/<ver>).
    yuzu::test::TempDir dir{"yuzu_test_runtimes_dotnet_syn_"};
    make_dir(dir.path / "usr/lib64/dotnet/sdk/8.0.100");
    make_dir(dir.path / "usr/lib64/dotnet/sdk/NuGetFallbackFolder"); // not a version
    write_text(dir.path / "usr/lib64/dotnet/sdk/9.0.100", "a file, not a version dir");
    make_dir(dir.path / "usr/lib64/dotnet/shared/Microsoft.AspNetCore.App/8.0.31");
    make_dir(dir.path / "usr/lib64/dotnet/shared/Some.Other.App/1.0.0");
    make_dir(dir.path / "usr/lib64/dotnet/shared/Microsoft.NETCore.App/not a version");
    Acc acc;
    const auto rows = lnx::dotnet_rows_at(dir.path, acc);
    CHECK_FALSE(acc.any_failure());
    REQUIRE(rows.size() == 3);
    // shared/ frameworks first (sorted by name), then sdk/.
    CHECK(rows[0] == "dotnet|core|8.0.31|/usr/lib64/dotnet/shared/Microsoft.AspNetCore.App/8.0.31|-");
    CHECK(rows[1] == "dotnet|unmodelled|1.0.0|/usr/lib64/dotnet/shared/Some.Other.App/1.0.0|-");
    CHECK(rows[2] == "dotnet|sdk|8.0.100|/usr/lib64/dotnet/sdk/8.0.100|-");
}

TEST_CASE("runtimes linux: an absent root is supported with zero rows, not constrained",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_absent_"};
    make_dir(dir.path); // exists, empty
    for (const fs::path& root : {dir.path, dir.path / "no_such_root"}) {
        INFO("root: " << root.string());
        Acc acc;
        CHECK(lnx::dotnet_rows_at(root, acc).empty());
        CHECK(lnx::jvm_rows_at(root, acc).empty());
        CHECK_FALSE(acc.any_failure());
        const auto out = rt::compose_output("jvm", {}, acc);
        REQUIRE(out.size() == 1);
        CHECK(out[0] == "status|jvm|supported|-");
    }
}

TEST_CASE("runtimes linux: an unreadable directory is constrained with a token, never absent",
          "[runtimes][linux][walk]") {
    if (running_privileged()) SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    yuzu::test::TempDir dir{"yuzu_test_runtimes_eacces_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));
    const PermRestore restore{dir.path / "usr/lib/jvm"};
    REQUIRE(::chmod(restore.path.c_str(), 0000) == 0);

    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc);

    // The first root (/usr/lib/jvm) failed; the second (/opt/java) still succeeded and its row is
    // present -- and the later success did NOT erase the earlier failure (mutation: resetting the
    // accumulator per root makes this constrained assertion fail).
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == kTemurinRow);
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokPermissionDenied});
    const auto out = rt::compose_output("jvm", rows, acc);
    REQUIRE(out.size() == 2);
    CHECK(out[0] == "status|jvm|constrained|linux:runtimes:permission_denied");
    CHECK(out[1] == kTemurinRow);
}

TEST_CASE("runtimes linux: an unreadable release file is constrained and yields no row",
          "[runtimes][linux][walk]") {
    if (running_privileged()) SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    yuzu::test::TempDir dir{"yuzu_test_runtimes_release_eacces_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));
    const PermRestore restore{dir.path / "opt/java/openjdk/release"};
    REQUIRE(::chmod(restore.path.c_str(), 0000) == 0);

    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc);
    REQUIRE(rows.size() == 1); // only the Debian home
    CHECK(rows[0] == kDebianRow);
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokPermissionDenied});
}

TEST_CASE("runtimes linux: a symlinked release file is refused, not followed (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // SYNTHETIC: a `release` that is a symlink to a real, parseable file elsewhere in the tree.
    // O_NOFOLLOW must refuse it (mutation: dropping O_NOFOLLOW surfaces the target as a row).
    yuzu::test::TempDir dir{"yuzu_test_runtimes_release_link_"};
    write_text(dir.path / "elsewhere/release", "JAVA_VERSION=\"21.0.1\"\nIMAGE_TYPE=\"JDK\"\n");
    make_dir(dir.path / "usr/lib/jvm/evil");
    std::error_code ec;
    fs::create_symlink(dir.path / "elsewhere/release", dir.path / "usr/lib/jvm/evil/release", ec);
    REQUIRE_FALSE(ec);

    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc);
    CHECK(rows.empty());
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokSymlinkRefused});
}

TEST_CASE("runtimes linux: a symlinked candidate root is an alias, skipped without following",
          "[runtimes][linux][walk]") {
    // SYNTHETIC: Fedora's /usr/share/dotnet -> ../lib64/dotnet. The real tree is read through its
    // own candidate path; the symlinked candidate contributes nothing and is not a failure.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_alias_"};
    make_dir(dir.path / "usr/lib64/dotnet/shared/Microsoft.NETCore.App/8.0.31");
    make_dir(dir.path / "usr/share");
    std::error_code ec;
    fs::create_symlink("../lib64/dotnet", dir.path / "usr/share/dotnet", ec);
    REQUIRE_FALSE(ec);

    Acc acc;
    const auto rows = lnx::dotnet_rows_at(dir.path, acc);
    CHECK_FALSE(acc.any_failure());
    REQUIRE(rows.size() == 1); // exactly once, via the real path
    CHECK(rows[0] == "dotnet|core|8.0.31|/usr/lib64/dotnet/shared/Microsoft.NETCore.App/8.0.31|-");
}

TEST_CASE("runtimes linux: a symlinked intermediate component is not followed",
          "[runtimes][linux][walk]") {
    // SYNTHETIC: /usr/lib64 -> lib (Arch). The candidate /usr/lib64/dotnet resolves through a
    // symlinked parent, which is refused hop-by-hop; /usr/lib/dotnet is the real path.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_alias_mid_"};
    make_dir(dir.path / "usr/lib/dotnet/sdk/8.0.100");
    std::error_code ec;
    fs::create_symlink("lib", dir.path / "usr/lib64", ec);
    REQUIRE_FALSE(ec);

    Acc acc;
    const auto rows = lnx::dotnet_rows_at(dir.path, acc);
    CHECK_FALSE(acc.any_failure());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "dotnet|sdk|8.0.100|/usr/lib/dotnet/sdk/8.0.100|-");
}

TEST_CASE("runtimes linux: a dangling in-set candidate alias is genuine absence, not constrained "
          "(SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // Arch: /usr/lib64 -> lib on EVERY host, here with no .NET installed. The candidate
    // /usr/lib64/dotnet stops at the lib64 alias; its target /usr/lib/dotnet is another candidate
    // that is simply absent, so the family is absent: supported + zero rows. MUTATION:
    // alias_is_covered requiring the target to OPEN (== OpenStatus::opened) records
    // symlink_refused here and reports a stock host as constrained.
    yuzu::test::TempDir with_lib{"yuzu_test_runtimes_dangling_"};
    make_dir(with_lib.path / "usr/lib"); // exists, holds no dotnet
    yuzu::test::TempDir without_lib{"yuzu_test_runtimes_dangling2_"};
    make_dir(without_lib.path / "usr"); // no usr/lib at all
    for (const fs::path& root : {with_lib.path, without_lib.path}) {
        INFO("root: " << root.string());
        std::error_code ec;
        fs::create_symlink("lib", root / "usr/lib64", ec);
        REQUIRE_FALSE(ec);
        Acc acc;
        CHECK(lnx::dotnet_rows_at(root, acc).empty());
        CHECK_FALSE(acc.any_failure());
        const auto out = rt::compose_output("dotnet", {}, acc);
        REQUIRE(out.size() == 1);
        CHECK(out[0] == "status|dotnet|supported|-");
    }

    // jvm: /opt/java -> ../usr/lib/jvm with no JVM installed anywhere.
    yuzu::test::TempDir jvm{"yuzu_test_runtimes_dangling_jvm_"};
    make_dir(jvm.path / "opt");
    std::error_code ec;
    fs::create_symlink("../usr/lib/jvm", jvm.path / "opt/java", ec);
    REQUIRE_FALSE(ec);
    Acc acc;
    CHECK(lnx::jvm_rows_at(jvm.path, acc).empty());
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("runtimes linux: a refused symlink with no alternative candidate is constrained, not "
          "an empty success (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // /usr/share/dotnet points OUTSIDE the candidate set and every other candidate is absent: the
    // install it names is unread, so the result must not claim "no dotnet" (supported + zero rows).
    yuzu::test::TempDir dir{"yuzu_test_runtimes_refused_"};
    make_dir(dir.path / "srv/dotnet/shared/Microsoft.NETCore.App/8.0.31");
    make_dir(dir.path / "usr/share");
    std::error_code ec;
    fs::create_symlink("../../srv/dotnet", dir.path / "usr/share/dotnet", ec);
    REQUIRE_FALSE(ec);

    Acc acc;
    const auto rows = lnx::dotnet_rows_at(dir.path, acc);
    CHECK(rows.empty()); // not followed
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokSymlinkRefused});
    const auto out = rt::compose_output("dotnet", rows, acc);
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "status|dotnet|constrained|linux:runtimes:symlink_refused");
}

TEST_CASE("runtimes linux: an absolute link target is read from the injected root (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // Production /usr/share/dotnet -> /usr/lib64/dotnet: an absolute target naming another
    // candidate is a covered alias; one naming anything else (/etc/alternatives) is refused.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_abs_"};
    make_dir(dir.path / "usr/lib64/dotnet/sdk/8.0.100");
    make_dir(dir.path / "usr/share");
    std::error_code ec;
    fs::create_symlink("/usr/lib64/dotnet", dir.path / "usr/share/dotnet", ec);
    REQUIRE_FALSE(ec);
    Acc covered;
    const auto rows = lnx::dotnet_rows_at(dir.path, covered);
    CHECK_FALSE(covered.any_failure());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "dotnet|sdk|8.0.100|/usr/lib64/dotnet/sdk/8.0.100|-");

    yuzu::test::TempDir other{"yuzu_test_runtimes_abs2_"};
    make_dir(other.path / "usr/share");
    fs::create_symlink("/etc/alternatives/dotnet", other.path / "usr/share/dotnet", ec);
    REQUIRE_FALSE(ec);
    Acc refused;
    CHECK(lnx::dotnet_rows_at(other.path, refused).empty());
    REQUIRE(refused.any_failure());
    CHECK(refused.reason() == std::string{lnx::kTokSymlinkRefused});
}

TEST_CASE("runtimes linux: mutually aliasing candidates are refused, not both trusted (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // usr/share/dotnet -> ../lib/dotnet and usr/lib/dotnet -> ../share/dotnet: each names the
    // other, neither opens directly, so no directory is ever read. The cycle must be constrained.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_cycle_"};
    make_dir(dir.path / "usr/share");
    make_dir(dir.path / "usr/lib");
    std::error_code ec;
    fs::create_symlink("../lib/dotnet", dir.path / "usr/share/dotnet", ec);
    REQUIRE_FALSE(ec);
    fs::create_symlink("../share/dotnet", dir.path / "usr/lib/dotnet", ec);
    REQUIRE_FALSE(ec);
    Acc acc;
    CHECK(lnx::dotnet_rows_at(dir.path, acc).empty());
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokSymlinkRefused});
}

TEST_CASE("runtimes linux: a symlinked shared/ or sdk/ subdirectory is refused (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_subdir_"};
    make_dir(dir.path / "usr/lib/dotnet");
    make_dir(dir.path / "srv/sdk/8.0.100");
    std::error_code ec;
    fs::create_symlink("../../../srv/sdk", dir.path / "usr/lib/dotnet/sdk", ec);
    REQUIRE_FALSE(ec);
    Acc acc;
    CHECK(lnx::dotnet_rows_at(dir.path, acc).empty());
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokSymlinkRefused});
}

TEST_CASE("runtimes linux: a symlinked jvm root with no alternative is refused (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_refused_jvm_"};
    make_dir(dir.path / "srv/jvm/jdk/");
    write_text(dir.path / "srv/jvm/jdk/release", "JAVA_VERSION=\"21.0.1\"\nIMAGE_TYPE=\"JDK\"\n");
    make_dir(dir.path / "usr/lib");
    std::error_code ec;
    fs::create_symlink("../../srv/jvm", dir.path / "usr/lib/jvm", ec);
    REQUIRE_FALSE(ec);

    Acc jvm_acc;
    CHECK(lnx::jvm_rows_at(dir.path, jvm_acc).empty());
    REQUIRE(jvm_acc.any_failure());
    CHECK(jvm_acc.reason() == std::string{lnx::kTokSymlinkRefused});
}

TEST_CASE("runtimes linux: the per-directory cap bounds the rows and becomes `truncated` "
          "(SYNTHETIC)",
          "[runtimes][linux][walk][cap]") {
    // The cap is a parameter (production: kMaxDirEntries = 16384) so this needs 5 directories,
    // not 16k. Mutations: dropping the `max_entries` argument in a walk enumerates all 5 rows;
    // dropping the `res.truncated` record leaves the accumulator clean.
    constexpr std::size_t kCap = 3;
    yuzu::test::TempDir dir{"yuzu_test_runtimes_cap_"};
    for (const char* v : {"8.0.100", "8.0.101", "8.0.102", "8.0.103", "8.0.104"})
        make_dir(dir.path / "usr/lib/dotnet/sdk" / v);
    for (const char* h : {"a", "b", "c", "d", "e"})
        write_text(dir.path / "usr/lib/jvm" / h / "release", "JAVA_VERSION=\"17.0.1\"\n");

    const auto check_truncated = [](const std::vector<std::string>& rows, const Acc& acc) {
        CHECK(rows.size() == kCap); // bounded, not all 5
        REQUIRE(acc.any_failure());
        CHECK(acc.reason() == std::string{lnx::kTokTruncated});
    };
    {
        Acc acc;
        check_truncated(lnx::dotnet_rows_at(dir.path, acc, kCap), acc);
    }
    {
        Acc acc;
        check_truncated(lnx::jvm_rows_at(dir.path, acc, kCap), acc);
    }
    // Boundary: a directory holding exactly `cap` entries is complete, not truncated.
    {
        Acc acc;
        CHECK(lnx::dotnet_rows_at(dir.path, acc, 5).size() == 5);
        CHECK_FALSE(acc.any_failure());
    }
    // The truncated output is constrained, never a bare full-looking inventory.
    {
        Acc acc;
        const auto rows = lnx::dotnet_rows_at(dir.path, acc, kCap);
        const auto out = rt::compose_output("dotnet", rows, acc);
        REQUIRE(out.size() == kCap + 1);
        CHECK(out[0] == "status|dotnet|constrained|linux:runtimes:truncated");
    }
}

TEST_CASE("runtimes linux: an oversized release file is constrained, never a row (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_oversize_"};
    write_text(dir.path / "opt/java/big/release",
               "JAVA_VERSION=\"17.0.1\"\nPAD=\"" + std::string(lnx::kMaxReleaseBytes, 'A') + "\"\n");
    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc);
    CHECK(rows.empty());
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokReleaseOversize});
}

TEST_CASE("runtimes linux: a version-less release is constrained; a home without one is silent "
          "(SYNTHETIC)",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_unparsable_"};
    write_text(dir.path / "usr/lib/jvm/garbled/release", "not a release file\nMODULES=\"java.base\"\n");
    make_dir(dir.path / "usr/lib/jvm/not-a-jvm"); // no release file: not a JVM home
    write_text(dir.path / "usr/lib/jvm/.hidden.jinfo", "a file, ignored");
    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc);
    CHECK(rows.empty());
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokReleaseUnparsable}); // only the garbled one
}

TEST_CASE("runtimes linux: action_rows_at routes each action to its own walk",
          "[runtimes][linux][walk][wire]") {
    // The injected entry point run_linux_at is `action_rows_at` + emit_read. Exact-row
    // equality per action fails if a switch arm is removed (empty rows -> a `supported` status
    // with no data) or two arms are swapped.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_dispatch_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));

    Acc jvm_acc;
    const auto jvm = lnx::action_rows_at(rt::Action::jvm, dir.path, jvm_acc);
    CHECK_FALSE(jvm_acc.any_failure());
    CHECK(jvm == std::vector<std::string>{kDebianRow, kTemurinRow});

    Acc dn_acc;
    const auto dn = lnx::action_rows_at(rt::Action::dotnet, dir.path, dn_acc);
    CHECK_FALSE(dn_acc.any_failure());
    CHECK(dn == std::vector<std::string>{kDotnetRow});

    // The composed output a consumer sees: status row first, then the rows, per action.
    for (const auto& [action, rows, acc] :
         {std::tuple{rt::Action::jvm, &jvm, &jvm_acc},
          std::tuple{rt::Action::dotnet, &dn, &dn_acc}}) {
        const auto out = rt::compose_output(rt::action_name(action), *rows, *acc);
        REQUIRE(out.size() == rows->size() + 1);
        CHECK(out[0] == std::string{"status|"} + std::string{rt::action_name(action)} +
                            "|supported|-");
    }
}

TEST_CASE("runtimes linux: action_rows_at carries a failure through for every action",
          "[runtimes][linux][walk][wire]") {
    // A refused (symlinked, no alternative) candidate for each action must surface through the
    // dispatch as a recorded failure -- an arm that dropped its accumulator would report supported.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_dispatch_fail_"};
    make_dir(dir.path / "usr/lib");
    make_dir(dir.path / "usr/share");
    make_dir(dir.path / "srv");
    std::error_code ec;
    fs::create_symlink("../../srv", dir.path / "usr/share/dotnet", ec);
    REQUIRE_FALSE(ec);
    fs::create_symlink("../../srv", dir.path / "usr/lib/jvm", ec);
    REQUIRE_FALSE(ec);
    for (const auto action : {rt::Action::dotnet, rt::Action::jvm}) {
        INFO("action: " << rt::action_name(action));
        Acc acc;
        CHECK(lnx::action_rows_at(action, dir.path, acc).empty());
        REQUIRE(acc.any_failure());
        CHECK(acc.reason() == std::string{lnx::kTokSymlinkRefused});
    }
}

TEST_CASE("runtimes linux: run_linux_at emits the populated rows and OK/FULL through a real "
          "CommandContext",
          "[runtimes][linux][walk][wire]") {
    // The populated jvm and dotnet rows are asserted here at the command level, not just below
    // the emission seam (action_rows_at): the host-independent replacement for a host-guaranteed
    // populated-row assertion (a CI runner may have no JVM or .NET installed).
    // MUTATION: discarding the rows before emit_read in run_linux_at (`emit_read(ctx, a, {}, acc)`)
    // leaves only the status row and fails the exact-row assertions below; dropping the status
    // row fails them too. The CONSTRAINED arm of emit_read is pinned by the next case.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_leg_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));

    const auto jvm = run_leg(rt::Action::jvm, dir.path);
    CHECK(jvm.rc == 0);
    // status row first, then the two captured homes in root order (the alias symlink is no row).
    CHECK(jvm.rows == std::vector<std::string>{"status|jvm|supported|-", kDebianRow, kTemurinRow});
    CHECK(jvm.status == YUZU_RESULT_STATUS_OK);
    CHECK(jvm.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(jvm.provenance.empty());

    const auto dn = run_leg(rt::Action::dotnet, dir.path);
    CHECK(dn.rc == 0);
    CHECK(dn.rows == std::vector<std::string>{"status|dotnet|supported|-", kDotnetRow});
    CHECK(dn.status == YUZU_RESULT_STATUS_OK);
    CHECK(dn.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(dn.provenance.empty());
}

TEST_CASE("runtimes linux: run_linux_at reports a forced constraint through BOTH the status row "
          "and the typed status of a real CommandContext",
          "[runtimes][linux][walk][wire]") {
    // The failure source is a planted symlink, refused by O_NOFOLLOW on every POSIX host, root
    // included -- no chmod, so no euid-0 SKIP: this case runs everywhere. The real rows are
    // still read, so one run pins "rows survive" AND "the typed status degrades".
    // MUTATION (an orchestrator probe confirmed it survived before this case existed): making
    // emit_read report OK/FULL regardless of the accumulator turns every status/completeness/
    // provenance assertion below red while the status ROW still says `constrained`.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_leg_constrained_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));
    std::error_code ec;
    // jvm: a symlinked `release` in an extra home; the two captured homes are still read.
    write_text(dir.path / "elsewhere/release", "JAVA_VERSION=\"21.0.1\"\nIMAGE_TYPE=\"JDK\"\n");
    make_dir(dir.path / "usr/lib/jvm/evil");
    fs::create_symlink(dir.path / "elsewhere/release", dir.path / "usr/lib/jvm/evil/release", ec);
    REQUIRE_FALSE(ec);
    // dotnet: a symlinked fixed `sdk` subdirectory is refused outright; shared/ is still read.
    fs::create_symlink("../../../srv/sdk", dir.path / "usr/share/dotnet/sdk", ec);
    REQUIRE_FALSE(ec);

    const auto jvm = run_leg(rt::Action::jvm, dir.path);
    CHECK(jvm.rc == 0); // a degraded read is never a failed command
    CHECK(jvm.rows == std::vector<std::string>{
              "status|jvm|constrained|linux:runtimes:symlink_refused", kDebianRow, kTemurinRow});
    CHECK(jvm.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(jvm.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(jvm.provenance == std::string{lnx::kTokSymlinkRefused}); // one seam, two views

    const auto dn = run_leg(rt::Action::dotnet, dir.path);
    CHECK(dn.rc == 0);
    CHECK(dn.rows == std::vector<std::string>{
              "status|dotnet|constrained|linux:runtimes:symlink_refused", kDotnetRow});
    CHECK(dn.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(dn.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(dn.provenance == std::string{lnx::kTokSymlinkRefused});
}

#endif // !defined(_WIN32)
