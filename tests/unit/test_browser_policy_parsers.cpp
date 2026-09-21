/**
 * test_browser_policy_parsers.cpp — pure row-model tests plus the Linux
 * injected-root policy walk for the browser_policy plugin
 * (browser_policy_parsers.hpp, browser_policy_linux_parsers.hpp).
 *
 * UNGUARDED (every OS): the wire-row formatter, the JSON -> type-enum
 * mapper (including the literal `unmodelled` outcome) and the JSON failure
 * tokens. Nothing here touches disk.
 *
 * `#if !defined(_WIN32)` (X2, a scoped exception to "never platform-guard a
 * test TU": the walk shell uses posix_dir_walk.hpp/openat, which do not exist
 * on Windows): the tree-manifest cases. They materialize
 * tests/unit/fixtures/wave10/browser_policy/linux/tree.manifest into a
 * `yuzu_test_browser_policy_` temp root and run lnx::linux_policy_rows_at
 * over it. The materializer is COPIED from test_peripherals_linux_parsers.cpp
 * (never included) and extended with one scheme, defined and unit-tested
 * below: line = `<relpath>\t<payload>`, payload `T:<text; \n \t \\>` |
 * `B:<base64>` | `L:<symlink target>`; `#` lines and blanks are comments.
 *
 * Fixture labels: chrome_managed.json / chrome_recommended.json are
 * SYNTHETIC (Alex sign-off 2026-09-21), edge_managed.json is a
 * RECONSTRUCTION; see the directory's provenance.txt. Inline JSON below is
 * likewise hand-written test input (RECONSTRUCTION, not a capture).
 *
 * Mutation notes (each assertion fails if the named wiring is removed):
 *   - exact chrome/edge/recommended rows: drop a vendor or level from
 *     kVendorDirs/kLevelDirs, or the walk itself;
 *   - "kept alongside a failure": swallow parse failures instead of
 *     accumulating them;
 *   - symlink refusals: drop O_NOFOLLOW from open_dir_at / read_file_at;
 *   - command status (run_linux_at through a real CommandContext via
 *     LocalDispatcher): pass "" instead of failure_reason to mark_result_read,
 *     or make it always report OK/FULL -> the CONSTRAINED/PARTIAL + exact-token
 *     assertions fail;
 *   - saturation (WalkLimits shrinks the caps so the boundary is cheap and
 *     machine-independent): drop the `walk.truncated` reporting branch or a
 *     row-cap guard -> the `linux:row_cap` cases fail; the exactly-at-cap
 *     controls fail if a cap is tightened to `>` off-by-one;
 *   - NUL: drop the NUL replacement in format_policy_row -> the row is
 *     truncated at the C-string boundary and the `nul_replaced` tail is lost;
 *   - read-to-EOF (Linux only, /proc reports st_size 0): read exactly st_size
 *     -> the /proc read returns empty.
 */
#include <catch2/catch_test_macros.hpp>

#include "browser_policy_parsers.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <vector>

#if !defined(_WIN32)
#include "browser_policy_linux_parsers.hpp"
#include "local_dispatcher.hpp" // yuzu::agent::LocalDispatcher (real CommandContext)
#include "test_helpers.hpp"     // yuzu::test::TempDir

#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#endif

using namespace yuzu::browser_policy;

namespace {

/// Escape-aware split matching the server decoder (result_parsing.hpp
/// find_unescaped_pipe): a backslash immediately before a pipe is an escaped
/// pipe, not a separator.
std::vector<std::string> split_fields(const std::string& row) {
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

const PolicyRow* find_row(const std::vector<PolicyRow>& rows, std::string_view name) {
    for (const auto& r : rows)
        if (r.name == name)
            return &r;
    return nullptr;
}

JsonPolicyParse parse_inline(std::string_view text) {
    return rows_from_json_policy_text(text, Browser::chrome, Level::mandatory, "machine",
                                      "/etc/opt/chrome/policies/managed/t.json");
}

} // namespace

// ── unguarded: the pure row model ─────────────────────────────────────────

TEST_CASE("browser_policy: a row is nine fields and hostile values cannot shift the count",
          "[browser_policy][parsers]") {
    PolicyRow r;
    r.browser = Browser::edge;
    r.level = Level::recommended;
    r.scope = user_scope("a|b");
    r.name = "Pipe|Name";
    r.value = {PolicyType::String, "C:\\Program Files\\", {}}; // trailing backslash
    r.source = "/etc/opt/edge/policies/recommended/x|y.json";

    const auto fields = split_fields(format_policy_row(r));
    REQUIRE(fields.size() == 9);
    CHECK(fields[0] == "policy");
    CHECK(fields[1] == "edge");
    CHECK(fields[2] == "recommended");
    CHECK(fields[3] == "user:a|b");
    CHECK(fields[4] == "Pipe|Name");
    CHECK(fields[5] == "string");
    CHECK(fields[6] == "C:/Program Files/"); // backslash folded by safe_output_field
    CHECK(fields[7] == "/etc/opt/edge/policies/recommended/x|y.json");
    CHECK(fields[8] == "-"); // empty detail -> "-"
}

TEST_CASE("browser_policy: every JSON type lands on the type enum", "[browser_policy][parsers]") {
    const auto p = parse_inline(R"({"b":true,"i":-3,"u":18446744073709551615,"r":1.5,)"
                                R"("s":"x","l":[1,"a"],"d":{"k":[]},"n":null})");
    REQUIRE_FALSE(p.failure.has_value());
    REQUIRE(p.rows.size() == 8);
    // Rows come out sorted by policy name.
    const std::vector<std::string> names = {"b", "d", "i", "l", "n", "r", "s", "u"};
    for (std::size_t i = 0; i < names.size(); ++i)
        CHECK(p.rows[i].name == names[i]);

    auto check = [&](std::string_view name, PolicyType t, std::string_view value) {
        const auto* row = find_row(p.rows, name);
        REQUIRE(row != nullptr);
        CHECK(row->value.type == t);
        CHECK(row->value.value == value);
    };
    check("b", PolicyType::Bool, "true");
    check("i", PolicyType::Int, "-3");
    check("u", PolicyType::Int, "18446744073709551615");
    check("r", PolicyType::Real, "1.5");
    check("s", PolicyType::String, "x");
    check("l", PolicyType::List, R"([1,"a"])");
    check("d", PolicyType::Dict, R"({"k":[]})");
    check("n", PolicyType::Null, "null");
}

TEST_CASE("browser_policy: a value the mapper does not model is the literal unmodelled outcome",
          "[browser_policy][parsers]") {
    // A JSON `binary` cannot come out of a text parse, but the mapper is
    // total: it must land on Unmodelled, never on some other type or a throw.
    const auto v = json_to_policy_value(nlohmann::json::binary({0x01, 0x02}));
    CHECK(v.type == PolicyType::Unmodelled);
    CHECK(type_token(v.type) == "unmodelled");
    CHECK(v.value == "-");
    CHECK(v.detail == "json_type");

    PolicyRow r;
    r.name = "Odd";
    r.scope = "machine";
    r.source = "/x";
    r.value = unmodelled_value("date");
    CHECK(format_policy_row(r) == "policy|chrome|mandatory|machine|Odd|unmodelled|-|/x|date");
}

TEST_CASE("browser_policy: malformed policy JSON is a failure token, never empty success",
          "[browser_policy][parsers]") {
    for (const std::string_view bad : {std::string_view{R"({"HomepageLocation": )"},
                                       std::string_view{""}, std::string_view{"not json"},
                                       std::string_view{"{\"a\":\"\xff\"}"}}) {
        const auto p = parse_inline(bad);
        REQUIRE(p.failure.has_value());
        CHECK(*p.failure == "linux:json_unparseable");
        CHECK(p.rows.empty());
    }
    for (const std::string_view not_object :
         {std::string_view{"[1,2]"}, std::string_view{"\"str\""}, std::string_view{"7"}}) {
        const auto p = parse_inline(not_object);
        REQUIRE(p.failure.has_value());
        CHECK(*p.failure == "linux:json_not_object");
    }
    // A container nested past kMaxNestingDepth is a constraint (bounds dump()).
    std::string deep = R"({"k":)";
    deep.append(static_cast<std::size_t>(kMaxNestingDepth) + 8, '[');
    deep.append(static_cast<std::size_t>(kMaxNestingDepth) + 8, ']');
    deep += "}";
    const auto p = parse_inline(deep);
    REQUIRE(p.failure.has_value());
    CHECK(*p.failure == "linux:json_too_deep");
    CHECK(p.rows.empty());
}

TEST_CASE("browser_policy: comments and a UTF-8 BOM in a policy file are tolerated",
          "[browser_policy][parsers]") {
    const auto p = parse_inline("\xEF\xBB\xBF// header\n/* block */ {\"ShowHomeButton\": true}\n");
    REQUIRE_FALSE(p.failure.has_value());
    REQUIRE(p.rows.size() == 1);
    CHECK(p.rows[0].name == "ShowHomeButton");
    CHECK(p.rows[0].value.type == PolicyType::Bool);
}

TEST_CASE("browser_policy: an embedded NUL cannot truncate a wire row",
          "[browser_policy][parsers]") {
    // Valid JSON: \u0000 survives parsing in both a value and a key.
    const auto p = parse_inline(R"({"K":"a\u0000b","N\u0000x":true})");
    REQUIRE_FALSE(p.failure.has_value());
    REQUIRE(p.rows.size() == 2);
    CHECK(p.rows[0].value.value == std::string("a\0b", 3)); // the parser keeps it...

    // ...the wire form must not: CommandContext::write_output takes a C string.
    const auto v = format_policy_row(p.rows[0]);
    CHECK(v.find('\0') == std::string::npos);
    CHECK(v == "policy|chrome|mandatory|machine|K|string|a\xEF\xBF\xBD"
               "b|/etc/opt/chrome/policies/managed/t.json|nul_replaced");
    CHECK(split_fields(v).size() == 9);

    const auto k = format_policy_row(p.rows[1]);
    CHECK(k.find('\0') == std::string::npos);
    CHECK(k == "policy|chrome|mandatory|machine|N\xEF\xBF\xBD"
               "x|bool|true|/etc/opt/chrome/policies/managed/t.json|nul_replaced");

    // A pre-existing detail keeps its qualifier and gains the NUL flag.
    PolicyRow r;
    r.name = std::string("n\0", 2);
    r.scope = "machine";
    r.source = "/x";
    r.value = unmodelled_value("date");
    CHECK(format_policy_row(r) ==
          "policy|chrome|mandatory|machine|n\xEF\xBF\xBD|unmodelled|-|/x|date,nul_replaced");
}

#if !defined(_WIN32)

namespace {

namespace fs = std::filesystem;

// ── tree-manifest materializer (copied from test_peripherals_linux_parsers.cpp,
//    extended with T:/B:/L: payloads; TU-local by design) ──────────────────

bool base64_decode(std::string_view in, std::string& out) {
    static const std::string kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned acc = 0;
    int bits = 0;
    out.clear();
    for (const char c : in) {
        if (c == '=')
            break;
        const auto pos = kAlphabet.find(c);
        if (pos == std::string::npos)
            return false;
        acc = (acc << 6) | static_cast<unsigned>(pos);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((acc >> bits) & 0xFF);
        }
    }
    return true;
}

bool unescape_text(std::string_view in, std::string& out) {
    out.clear();
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '\\') {
            out += in[i];
            continue;
        }
        if (++i >= in.size())
            return false;
        switch (in[i]) {
        case 'n':  out += '\n'; break;
        case 't':  out += '\t'; break;
        case '\\': out += '\\'; break;
        default:   return false;
        }
    }
    return true;
}

bool materialize(std::istream& manifest, const fs::path& root, std::string& error) {
    std::string line;
    while (std::getline(manifest, line)) {
        if (!line.empty() && line.back() == '\r') // CRLF-checkout tolerance
            line.pop_back();
        if (line.empty() || line[0] == '#')
            continue;
        const auto tab = line.find('\t');
        if (tab == std::string::npos || tab + 2 >= line.size() || line[tab + 2] != ':') {
            error = "malformed manifest line: " + line.substr(0, 80);
            return false;
        }
        const fs::path out_path = root / line.substr(0, tab);
        const char kind = line[tab + 1];
        const std::string_view payload = std::string_view{line}.substr(tab + 3);
        std::error_code ec;
        fs::create_directories(out_path.parent_path(), ec);
        if (ec) {
            error = "create_directories failed: " + ec.message();
            return false;
        }
        if (kind == 'L') {
            fs::create_symlink(std::string{payload}, out_path, ec);
            if (ec) {
                error = "create_symlink failed: " + ec.message();
                return false;
            }
            continue;
        }
        std::string bytes;
        if (kind == 'T' ? !unescape_text(payload, bytes)
                        : (kind == 'B' ? !base64_decode(payload, bytes) : true)) {
            error = "bad payload for " + out_path.string();
            return false;
        }
        std::ofstream out(out_path, std::ios::binary);
        if (!out) {
            error = "could not create " + out_path.string();
            return false;
        }
        out << bytes;
    }
    return true;
}

fs::path manifest_path() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "browser_policy" / "linux" / "tree.manifest";
#else
    return fs::path("tests/unit/fixtures/wave10/browser_policy/linux/tree.manifest");
#endif
}

void materialize_fixture(const fs::path& root) {
    std::ifstream in(manifest_path(), std::ios::binary);
    REQUIRE(in.good());
    std::string error;
    REQUIRE(materialize(in, root, error));
}

void write_file(const fs::path& root, const std::string& rel, const std::string& content) {
    const fs::path p = root / rel;
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out << content;
}

std::string read_all(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool has_row(const std::vector<std::string>& rows, std::string_view exact) {
    return std::find(rows.begin(), rows.end(), exact) != rows.end();
}

std::size_t count_prefix(const std::vector<std::string>& rows, std::string_view prefix) {
    return static_cast<std::size_t>(std::count_if(rows.begin(), rows.end(), [&](const auto& r) {
        return r.compare(0, prefix.size(), prefix) == 0;
    }));
}

/// Restores a directory's permissions so TempDir's remove_all can run.
struct PermRestore {
    fs::path path;
    ~PermRestore() { ::chmod(path.c_str(), 0755); }
};

constexpr std::string_view kChromeManaged = "/etc/opt/chrome/policies/managed/chrome_managed.json";

// ── CommandContext-level harness ─────────────────────────────────────────
// Drives the PRODUCTION leg body (run_linux_at) through a real CommandContext
// via LocalDispatcher (the test_filesystem_posture_local_dispatcher.cpp
// precedent: a synthetic descriptor whose execute() calls the code under
// test), so what is asserted is the emitted rows AND the CC-07 status the
// command actually reports — not just the walk's return values.

struct LegRun {
    int rc = -1;
    std::vector<std::string> rows;
    YuzuResultStatus status = YUZU_RESULT_STATUS_UNDECLARED;
    YuzuResultCompleteness completeness = YUZU_RESULT_COMPLETENESS_UNKNOWN;
    std::string provenance;
};

const fs::path* g_leg_root = nullptr;
const WalkLimits* g_leg_limits = nullptr;

int leg_execute(YuzuCommandContext* raw, const char* /*action*/, const YuzuParam* /*params*/,
                std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return run_linux_at(ctx, *g_leg_root, *g_leg_limits);
}

LegRun run_leg(const fs::path& root, const WalkLimits& limits = {}) {
    g_leg_root = &root;
    g_leg_limits = &limits;
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &leg_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(&descriptor, "probe");
    g_leg_root = nullptr;
    g_leg_limits = nullptr;

    LegRun out;
    out.rc = result.rc;
    out.status = result.result_status;
    out.completeness = result.result_completeness;
    out.provenance = result.result_provenance;
    std::istringstream lines(result.captured);
    for (std::string line; std::getline(lines, line);)
        if (!line.empty())
            out.rows.push_back(line);
    return out;
}

} // namespace

TEST_CASE("browser_policy tree: the manifest materializer handles T:, B:, L: and rejects garbage",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mat_"};
    fs::create_directories(dir.path);
    std::istringstream in("# comment\n\n"
                          "a/b.txt\tT:l1\\nl2\\ttab\\\\end\n"
                          "a/bin.dat\tB:AAH/\n"
                          "a/link\tL:b.txt\n");
    std::string error;
    REQUIRE(materialize(in, dir.path, error));
    CHECK(read_all(dir.path / "a" / "b.txt") == "l1\nl2\ttab\\end");
    CHECK(read_all(dir.path / "a" / "bin.dat") == std::string("\x00\x01\xff", 3));
    CHECK(fs::is_symlink(dir.path / "a" / "link"));
    CHECK(fs::read_symlink(dir.path / "a" / "link") == "b.txt");

    std::istringstream bad("a/x\tno-kind-prefix\n");
    CHECK_FALSE(materialize(bad, dir.path, error));
    CHECK_FALSE(error.empty());
}

TEST_CASE("browser_policy linux: the fixture tree yields chrome, edge and recommended rows",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_tree_"};
    fs::create_directories(dir.path);
    materialize_fixture(dir.path);

    std::string reason = "sentinel";
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    CHECK(reason.empty()); // complete read: no constraint

    CHECK(count_prefix(rows, "policy|chrome|mandatory|machine|") == 8);
    CHECK(count_prefix(rows, "policy|chrome|recommended|machine|") == 2);
    CHECK(count_prefix(rows, "policy|edge|mandatory|machine|") == 4);
    CHECK(rows.size() == 14);

    // Exact rows: a value flowing from the file to the wire (mutation: drop a
    // vendor/level/dir from the walk and the matching row disappears).
    CHECK(has_row(rows, "policy|chrome|mandatory|machine|HomepageLocation|string|"
                        "https://intranet.example.com/|" +
                            std::string{kChromeManaged} + "|-"));
    CHECK(has_row(rows, "policy|chrome|mandatory|machine|RestoreOnStartup|int|4|" +
                            std::string{kChromeManaged} + "|-"));
    CHECK(has_row(rows, "policy|chrome|mandatory|machine|PasswordManagerEnabled|bool|false|" +
                            std::string{kChromeManaged} + "|-"));
    CHECK(has_row(rows, "policy|chrome|mandatory|machine|ExtensionSettings|dict|"
                        "{\"*\":{\"installation_mode\":\"blocked\"}}|" +
                            std::string{kChromeManaged} + "|-"));
    CHECK(has_row(rows, "policy|chrome|recommended|machine|BookmarkBarEnabled|bool|true|"
                        "/etc/opt/chrome/policies/recommended/chrome_recommended.json|-"));
    CHECK(has_row(rows, "policy|edge|mandatory|machine|InPrivateModeAvailability|int|1|"
                        "/etc/opt/edge/policies/managed/edge_managed.json|-"));
    CHECK(has_row(rows, "policy|edge|mandatory|machine|ExtensionInstallBlocklist|list|[\"*\"]|"
                        "/etc/opt/edge/policies/managed/edge_managed.json|-"));

    // Every row is exactly nine fields.
    for (const auto& r : rows)
        CHECK(split_fields(r).size() == 9);
}

TEST_CASE("browser_policy linux: fixtures carry the sign-off / reconstruction headers",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_hdr_"};
    fs::create_directories(dir.path);
    materialize_fixture(dir.path);
    constexpr std::string_view kHeader = "SYNTHETIC \xE2\x80\x94 not a real capture "
                                         "(Alex sign-off 2026-09-21)";
    CHECK(read_all(dir.path / "etc/opt/chrome/policies/managed/chrome_managed.json").find(kHeader) !=
          std::string::npos);
    CHECK(read_all(dir.path / "etc/opt/chrome/policies/recommended/chrome_recommended.json")
              .find(kHeader) != std::string::npos);
    const auto edge = read_all(dir.path / "etc/opt/edge/policies/managed/edge_managed.json");
    CHECK(edge.find("RECONSTRUCTION") != std::string::npos);
    CHECK(edge.find("learn.microsoft.com/deployedge/microsoft-edge-policies") != std::string::npos);
}

TEST_CASE("browser_policy linux: an absent root or no managed policy is zero rows and complete",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_absent_"};
    std::string reason = "sentinel";

    // Root does not exist at all.
    auto rows = lnx::linux_policy_rows_at(dir.path / "no_such_root", reason);
    CHECK(rows.empty());
    CHECK(reason.empty());

    // Root exists, no browser installed.
    fs::create_directories(dir.path / "etc" / "opt");
    reason = "sentinel";
    rows = lnx::linux_policy_rows_at(dir.path, reason);
    CHECK(rows.empty());
    CHECK(reason.empty());
}

TEST_CASE("browser_policy linux: chromium's directory is walked and non-json files are ignored",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_chromium_"};
    write_file(dir.path, "etc/chromium/policies/managed/c.json", R"({"IncognitoModeAvailability": 1})");
    write_file(dir.path, "etc/chromium/policies/managed/README.txt", "not a policy file");
    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    CHECK(reason.empty());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "policy|chromium|mandatory|machine|IncognitoModeAvailability|int|1|"
                     "/etc/chromium/policies/managed/c.json|-");
}

TEST_CASE("browser_policy linux: malformed JSON is constrained and never hides its siblings",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_bad_"};
    write_file(dir.path, "etc/opt/chrome/policies/managed/a_bad.json", R"({"HomepageLocation": )");
    write_file(dir.path, "etc/opt/chrome/policies/managed/b_good.json", R"({"ShowHomeButton": true})");
    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    // The good sibling is kept...
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].find("|ShowHomeButton|bool|true|") != std::string::npos);
    // ...and the bad one is reported, not absorbed into an unqualified success.
    CHECK(reason.find("linux:json_unparseable") != std::string::npos);

    // Only a bad file: zero rows but STILL constrained (failure != absent).
    yuzu::test::TempDir only_bad{"yuzu_test_browser_policy_onlybad_"};
    write_file(only_bad.path, "etc/opt/edge/policies/recommended/x.json", "{ nope");
    const auto none = lnx::linux_policy_rows_at(only_bad.path, reason);
    CHECK(none.empty());
    CHECK(reason == "linux:json_unparseable");
}

TEST_CASE("browser_policy linux: an unreadable policy directory is constrained, siblings survive",
          "[browser_policy][linux][tree]") {
    // Skip if the test happens to run as root (uid 0 / CAP_DAC_OVERRIDE bypass
    // the permission bits this test exercises).
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");

    yuzu::test::TempDir dir{"yuzu_test_browser_policy_eacces_"};
    fs::create_directories(dir.path);
    materialize_fixture(dir.path);
    const fs::path locked = dir.path / "etc/opt/chrome/policies/managed";
    PermRestore restore{locked};
    REQUIRE(::chmod(locked.c_str(), 0000) == 0);

    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    // Listing the locked directory must fail loudly, not read as "no policy".
    CHECK(reason.find("linux:permission_denied") != std::string::npos);
    CHECK(count_prefix(rows, "policy|chrome|mandatory|") == 0);
    // The other directories still read.
    CHECK(count_prefix(rows, "policy|chrome|recommended|") == 2);
    CHECK(count_prefix(rows, "policy|edge|mandatory|") == 4);
}

TEST_CASE("browser_policy linux: an unreadable policy FILE is constrained",
          "[browser_policy][linux][tree]") {
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");

    yuzu::test::TempDir dir{"yuzu_test_browser_policy_fileacces_"};
    write_file(dir.path, "etc/opt/edge/policies/managed/locked.json", R"({"A": 1})");
    const fs::path locked = dir.path / "etc/opt/edge/policies/managed/locked.json";
    PermRestore restore{locked};
    REQUIRE(::chmod(locked.c_str(), 0000) == 0);

    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    CHECK(rows.empty());
    CHECK(reason == "linux:permission_denied");
}

TEST_CASE("browser_policy linux: symlinks below the root are refused, the root itself may be one",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_symlink_"};
    fs::create_directories(dir.path);

    // (a) a symlinked policy DIRECTORY component is not followed.
    write_file(dir.path, "elsewhere/policies/managed/p.json", R"({"HomepageLocation": "x"})");
    fs::create_directories(dir.path / "root_a" / "etc" / "opt");
    fs::create_directory_symlink(dir.path / "elsewhere", dir.path / "root_a" / "etc" / "opt" / "chrome");
    std::string reason;
    auto rows = lnx::linux_policy_rows_at(dir.path / "root_a", reason);
    CHECK(rows.empty());
    CHECK_FALSE(reason.empty()); // refused loudly (mutation: drop O_NOFOLLOW -> rows appear)

    // (b) a symlinked policy FILE is not followed.
    write_file(dir.path, "target.json", R"({"A": 1})");
    fs::create_directories(dir.path / "root_b" / "etc" / "opt" / "edge" / "policies" / "managed");
    fs::create_symlink(dir.path / "target.json",
                       dir.path / "root_b" / "etc" / "opt" / "edge" / "policies" / "managed" / "l.json");
    rows = lnx::linux_policy_rows_at(dir.path / "root_b", reason);
    CHECK(rows.empty());
    CHECK(reason == "linux:symlink_refused");

    // (c) the injected root itself may be a symlink (e.g. /tmp -> /private/tmp).
    materialize_fixture(dir.path / "real_root");
    fs::create_directory_symlink(dir.path / "real_root", dir.path / "root_link");
    rows = lnx::linux_policy_rows_at(dir.path / "root_link", reason);
    CHECK(reason.empty());
    CHECK(rows.size() == 14);
}

TEST_CASE("browser_policy linux: an oversized policy file is constrained, not truncated",
          "[browser_policy][linux][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_big_"};
    std::string big = "{\"K\": \"";
    big.append(kMaxPolicyFileBytes + 1, 'a');
    big += "\"}";
    write_file(dir.path, "etc/opt/chrome/policies/managed/big.json", big);
    std::string reason;
    const auto rows = lnx::linux_policy_rows_at(dir.path, reason);
    CHECK(rows.empty());
    CHECK(reason == "linux:oversized");
}

// ── failure -> command status (the seam every degraded read reports through) ──

TEST_CASE("browser_policy linux leg: acquisition failure reaches the command as CONSTRAINED/PARTIAL",
          "[browser_policy][linux][status]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_bad_"};
    write_file(dir.path, "etc/opt/chrome/policies/managed/a_bad.json", R"({"HomepageLocation": )");
    write_file(dir.path, "etc/opt/chrome/policies/managed/b_good.json", R"({"ShowHomeButton": true})");

    const auto run = run_leg(dir.path);
    CHECK(run.rc == 0); // a degraded read is not a failed command
    // The good sibling was emitted...
    REQUIRE(run.rows.size() == 1);
    CHECK(run.rows[0].find("|ShowHomeButton|bool|true|") != std::string::npos);
    // ...and the failure is on the wire status with the exact token, not OK/FULL.
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == "linux:json_unparseable");

    // Only a bad file: zero rows but STILL constrained — a failure never reads as absent.
    yuzu::test::TempDir only_bad{"yuzu_test_browser_policy_leg_onlybad_"};
    write_file(only_bad.path, "etc/opt/edge/policies/recommended/x.json", "{ nope");
    const auto none = run_leg(only_bad.path);
    CHECK(none.rows.empty());
    CHECK(none.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(none.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(none.provenance == "linux:json_unparseable");
}

TEST_CASE("browser_policy linux leg: a genuinely absent or complete read is OK/FULL",
          "[browser_policy][linux][status]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_ok_"};

    // Absent root: zero rows, no placeholder, complete.
    auto run = run_leg(dir.path / "no_such_root");
    CHECK(run.rc == 0);
    CHECK(run.rows.empty());
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(run.provenance.empty());

    // Populated fixture: every row emitted, still complete.
    materialize_fixture(dir.path / "fixture_root");
    run = run_leg(dir.path / "fixture_root");
    CHECK(run.rows.size() == 14);
    CHECK(count_prefix(run.rows, "policy|chrome|mandatory|machine|") == 8);
    CHECK(count_prefix(run.rows, "policy|edge|") == 4);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(run.provenance.empty());
}

TEST_CASE("browser_policy linux leg: a NUL in a policy value reaches the command whole",
          "[browser_policy][linux][status]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_nul_"};
    write_file(dir.path, "etc/opt/chrome/policies/managed/n.json", R"({"K":"a\u0000b"})");
    const auto run = run_leg(dir.path);
    REQUIRE(run.rows.size() == 1);
    // Truncating at the NUL would drop the source and detail fields.
    CHECK(run.rows[0] == "policy|chrome|mandatory|machine|K|string|a\xEF\xBF\xBD"
                         "b|/etc/opt/chrome/policies/managed/n.json|nul_replaced");
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
}

// ── saturation: row cap, directory cap, file cap (WalkLimits, exactly-at-cap controls) ──

TEST_CASE("browser_policy linux leg: the row cap is reported, and exactly-at-cap is complete",
          "[browser_policy][linux][cap]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_rowcap_"};
    write_file(dir.path, "etc/opt/chrome/policies/managed/a.json", R"({"A": 1, "B": 2})");
    write_file(dir.path, "etc/opt/chrome/policies/managed/b.json", R"({"C": 3, "D": 4})");

    WalkLimits limits;
    limits.max_rows = 4; // exactly the row count: the control
    auto run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 4);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.provenance.empty());

    limits.max_rows = 3; // one over: capped, reported, lower bound
    run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 3);
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == "linux:row_cap");

    // The cap is per leg, not per file: it also stops the next vendor/level.
    write_file(dir.path, "etc/opt/edge/policies/managed/e.json", R"({"E": 5})");
    limits.max_rows = 4;
    run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 4);
    CHECK(run.provenance == "linux:row_cap");
}

TEST_CASE("browser_policy linux leg: a truncated directory listing is reported, never complete",
          "[browser_policy][linux][cap]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_dircap_"};
    for (const char* name : {"a.json", "b.json", "c.json"})
        write_file(dir.path, std::string{"etc/opt/chrome/policies/managed/"} + name,
                   std::string{"{\""} + name + "\": true}");

    WalkLimits limits;
    limits.max_entries_per_dir = 3; // exactly the entry count: the control
    auto run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 3);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.provenance.empty());

    limits.max_entries_per_dir = 2; // an entry remains unread: must not read as complete
    run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 2); // only the examined entries
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == "linux:row_cap");
}

TEST_CASE("browser_policy linux leg: the file-size cap is exact and reported",
          "[browser_policy][linux][cap]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_leg_filecap_"};
    const std::string body = R"({"A": 1})";
    write_file(dir.path, "etc/opt/chrome/policies/managed/a.json", body);

    WalkLimits limits;
    limits.max_file_bytes = body.size(); // exactly the size: read
    auto run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 1);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);

    limits.max_file_bytes = body.size() - 1; // one byte over: constrained
    run = run_leg(dir.path, limits);
    CHECK(run.rows.empty());
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.provenance == "linux:oversized");
}

#if defined(__linux__)
TEST_CASE("browser_policy linux: a file is read to EOF, not to its fstat size",
          "[browser_policy][linux][read]") {
    // /proc reports st_size 0 for a non-empty regular file: reading exactly
    // st_size would return an empty (and "successful") body — the same shape
    // as a file that grew between fstat and read.
    posix::Fd proc_self{::open("/proc/self", O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    REQUIRE(proc_self.valid());
    const auto whole = posix::read_file_at(proc_self.get(), "status");
    REQUIRE(whole.status == posix::OpenStatus::ok);
    CHECK(whole.bytes.find("Name:") != std::string::npos);

    // Growth past the cap is `oversized` even though st_size (0) was under it.
    const auto capped = posix::read_file_at(proc_self.get(), "status", 16);
    CHECK(capped.status == posix::OpenStatus::failed);
    CHECK(capped.detail == "oversized");
}
#endif // defined(__linux__)

#endif // !defined(_WIN32)
