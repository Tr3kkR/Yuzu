/**
 * test_browser_policy_macos_plist.cpp — CoreFoundation plist decode and the
 * injected-root Managed Preferences walk for the browser_policy macOS leg
 * (browser_policy_macos.hpp, browser_policy_macos_parsers.hpp).
 *
 * The whole body is `#ifdef __APPLE__`: CoreFoundation exists nowhere else.
 * (The pure row model and the Linux walk are tested unguarded in
 * test_browser_policy_parsers.cpp.) This is what makes the macOS leg execute
 * at least once in the unit suite, on the Mac legs of CI.
 *
 * Fixture: tests/unit/fixtures/wave10/browser_policy/macos/tree.manifest,
 * materialized into a `yuzu_test_browser_policy_` temp root. The
 * materializer is COPIED from test_peripherals_linux_parsers.cpp (never
 * included) and extended with one scheme, defined and unit-tested below:
 * line = `<relpath>\t<payload>`, payload `T:<text; \n \t \\>` | `B:<base64>` |
 * `L:<symlink target>`; `#` lines and blanks are comments. The two
 * com.google.Chrome.plist entries are SYNTHETIC (Alex sign-off 2026-09-21);
 * com.microsoft.Edge.plist is a RECONSTRUCTION stored as a BINARY plist (what
 * cfprefsd actually writes), so the binary decode path runs too — see the
 * directory's provenance.txt. The inline plist XML below is hand-written test
 * input (RECONSTRUCTION, not a capture).
 *
 * Mutation notes (each assertion fails if the named wiring is removed):
 *   - `user:alice` rows: drop the per-user walk in macos_policy_rows_at;
 *   - the Edge binary-plist rows: drop the Edge entry from kPlistNames or
 *     break CFPropertyListCreateWithData's binary handling;
 *   - "unmodelled" date/data: route CFDate/CFData to any other type;
 *   - symlink refusals: drop O_NOFOLLOW from the openat chain;
 *   - command status (run_macos_at through a real CommandContext via
 *     LocalDispatcher): pass "" instead of failure_reason to mark_result_read,
 *     or make it always report OK/FULL -> the CONSTRAINED/PARTIAL + exact-token
 *     assertions fail;
 *   - saturation (WalkLimits shrinks the caps): drop the truncated-listing
 *     reporting or a row-cap guard -> the `macos:row_cap` cases fail; the
 *     exactly-at-cap controls fail on an off-by-one;
 *   - NUL in a CFString value/key: revert cfstring_to_utf8 to a C-string
 *     conversion -> the value is truncated at the NUL and the `nul_replaced`
 *     detail is lost.
 */
#ifdef __APPLE__

#include <catch2/catch_test_macros.hpp>

#include "browser_policy_macos_parsers.hpp"

#include "local_dispatcher.hpp" // yuzu::agent::LocalDispatcher (real CommandContext)
#include "test_helpers.hpp"     // yuzu::test::TempDir

#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::browser_policy;

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
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "browser_policy" / "macos" / "tree.manifest";
#else
    return fs::path("tests/unit/fixtures/wave10/browser_policy/macos/tree.manifest");
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

const PolicyRow* find_row(const std::vector<PolicyRow>& rows, std::string_view name) {
    for (const auto& r : rows)
        if (r.name == name)
            return &r;
    return nullptr;
}

/// Restores a directory's permissions so TempDir's remove_all can run.
struct PermRestore {
    fs::path path;
    ~PermRestore() { ::chmod(path.c_str(), 0755); }
};

std::string plist_xml(std::string_view body) {
    return std::string{"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                       "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
                       "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                       "<plist version=\"1.0\">\n"} +
           std::string{body} + "\n</plist>\n";
}

mac::PlistPolicyParse parse_xml(std::string_view body) {
    return mac::rows_from_plist_bytes(plist_xml(body), Browser::chrome, "machine", "/p.plist");
}

constexpr std::string_view kMp = "/Library/Managed Preferences";

// NOT a bare word: a single token such as `garbage` is a valid old-style
// (ASCII) plist STRING and decodes to `plist_not_dictionary`, not
// `plist_unparseable` (CFPropertyListCreateWithData accepts the OpenStep format).
constexpr const char* kNotAPlist = "not a plist at all";

// ── CommandContext-level harness (see test_browser_policy_parsers.cpp) ─────
// Drives the PRODUCTION leg body (run_macos_at) through a real CommandContext
// via LocalDispatcher so the emitted rows and the CC-07 status the command
// actually reports are what is asserted.

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
    return run_macos_at(ctx, *g_leg_root, *g_leg_limits);
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

/// A BINARY plist whose dictionary has a string VALUE and a string KEY that
/// each contain an embedded NUL, built through CoreFoundation (XML cannot
/// carry U+0000, so this is the only way such bytes reach the decoder).
std::string binary_plist_with_nuls() {
    using yuzu::agent::ScopedCFRef;
    const UInt8 value_bytes[] = {'a', 0, 'b'};
    const UInt8 key_bytes[] = {'N', 0, 'x'};
    ScopedCFRef<CFStringRef> plain_key(
        CFStringCreateWithCString(kCFAllocatorDefault, "K", kCFStringEncodingUTF8));
    ScopedCFRef<CFStringRef> nul_key(CFStringCreateWithBytes(
        kCFAllocatorDefault, key_bytes, 3, kCFStringEncodingUTF8, false));
    ScopedCFRef<CFStringRef> nul_value(CFStringCreateWithBytes(
        kCFAllocatorDefault, value_bytes, 3, kCFStringEncodingUTF8, false));
    REQUIRE(plain_key);
    REQUIRE(nul_key);
    REQUIRE(nul_value);
    const void* keys[] = {plain_key.get(), nul_key.get()};
    const void* vals[] = {nul_value.get(), kCFBooleanTrue};
    ScopedCFRef<CFDictionaryRef> dict(CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 2,
                                                         &kCFTypeDictionaryKeyCallBacks,
                                                         &kCFTypeDictionaryValueCallBacks));
    REQUIRE(dict);
    ScopedCFRef<CFDataRef> data(CFPropertyListCreateData(
        kCFAllocatorDefault, dict.get(), kCFPropertyListBinaryFormat_v1_0, 0, nullptr));
    REQUIRE(data);
    return std::string{reinterpret_cast<const char*>(CFDataGetBytePtr(data.get())),
                       static_cast<std::size_t>(CFDataGetLength(data.get()))};
}

} // namespace

TEST_CASE("browser_policy macOS tree: the manifest materializer handles T:, B:, L: and rejects garbage",
          "[browser_policy][macos][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mac_mat_"};
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

    std::istringstream bad("a/x\tno-kind-prefix\n");
    CHECK_FALSE(materialize(bad, dir.path, error));
    CHECK_FALSE(error.empty());
}

TEST_CASE("browser_policy macOS: the fixture tree yields machine and user rows",
          "[browser_policy][macos][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mac_tree_"};
    fs::create_directories(dir.path);
    materialize_fixture(dir.path);

    std::string reason = "sentinel";
    const auto rows = mac::macos_policy_rows_at(dir.path, reason);
    CHECK(reason.empty()); // complete read

    CHECK(count_prefix(rows, "policy|chrome|mandatory|machine|") == 6);
    CHECK(count_prefix(rows, "policy|chrome|mandatory|user:alice|") == 6);
    CHECK(count_prefix(rows, "policy|edge|mandatory|machine|") == 3);
    CHECK(rows.size() == 15);

    const std::string machine_chrome = std::string{kMp} + "/com.google.Chrome.plist";
    const std::string alice_chrome = std::string{kMp} + "/alice/com.google.Chrome.plist";
    const std::string machine_edge = std::string{kMp} + "/com.microsoft.Edge.plist";

    CHECK(has_row(rows, "policy|chrome|mandatory|machine|HomepageLocation|string|"
                        "https://intranet.example.com/|" +
                            machine_chrome + "|-"));
    CHECK(has_row(rows, "policy|chrome|mandatory|machine|ShowHomeButton|bool|true|" +
                            machine_chrome + "|-"));
    CHECK(has_row(rows, "policy|chrome|mandatory|machine|HomepageIsNewTabPage|bool|false|" +
                            machine_chrome + "|-"));
    CHECK(has_row(rows, "policy|chrome|mandatory|machine|RestoreOnStartupURLs|list|"
                        "[\"https://intranet.example.com/\",\"https://wiki.example.com/\"]|" +
                            machine_chrome + "|-"));
    CHECK(has_row(rows, "policy|chrome|mandatory|machine|ExtensionSettings|dict|"
                        "{\"*\":{\"installation_mode\":\"blocked\"}}|" +
                            machine_chrome + "|-"));
    // Per-user scope: same policy, `user:<directory name>` and its own source path.
    CHECK(has_row(rows, "policy|chrome|mandatory|user:alice|RestoreOnStartup|int|4|" +
                            alice_chrome + "|-"));
    // The Edge plist is a BINARY plist: the binary decode path.
    CHECK(has_row(rows, "policy|edge|mandatory|machine|SmartScreenEnabled|bool|true|" +
                            machine_edge + "|-"));
    CHECK(has_row(rows, "policy|edge|mandatory|machine|InPrivateModeAvailability|int|1|" +
                            machine_edge + "|-"));

    for (const auto& r : rows)
        CHECK(std::count(r.begin(), r.end(), '|') == 8); // nine fields (no value here has a pipe)
}

TEST_CASE("browser_policy macOS: the synthetic Chrome plists carry the sign-off header",
          "[browser_policy][macos][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mac_hdr_"};
    fs::create_directories(dir.path);
    materialize_fixture(dir.path);
    constexpr std::string_view kHeader = "SYNTHETIC \xE2\x80\x94 not a real capture "
                                         "(Alex sign-off 2026-09-21)";
    CHECK(read_all(dir.path / "Library/Managed Preferences/com.google.Chrome.plist").find(kHeader) !=
          std::string::npos);
    CHECK(read_all(dir.path / "Library/Managed Preferences/alice/com.google.Chrome.plist")
              .find(kHeader) != std::string::npos);
}

TEST_CASE("browser_policy macOS: no Managed Preferences is zero rows and complete",
          "[browser_policy][macos][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mac_absent_"};
    std::string reason = "sentinel";
    auto rows = mac::macos_policy_rows_at(dir.path / "no_such_root", reason);
    CHECK(rows.empty());
    CHECK(reason.empty());

    fs::create_directories(dir.path / "Library");
    reason = "sentinel";
    rows = mac::macos_policy_rows_at(dir.path, reason);
    CHECK(rows.empty());
    CHECK(reason.empty());
}

TEST_CASE("browser_policy macOS: every CF type maps to the type enum, date/data are unmodelled",
          "[browser_policy][macos][plist]") {
    const auto p = parse_xml(
        "<dict>"
        "<key>Str</key><string>x</string>"
        "<key>Yes</key><true/>"
        "<key>No</key><false/>"
        "<key>Int</key><integer>-7</integer>"
        "<key>Real</key><real>1.5</real>"
        "<key>List</key><array><string>a</string><integer>2</integer></array>"
        "<key>Dict</key><dict><key>k</key><string>v</string></dict>"
        "<key>When</key><date>2026-09-21T00:00:00Z</date>"
        "<key>Blob</key><data>AAEC</data>"
        "<key>NestedDate</key><array><string>a</string><date>2026-09-21T00:00:00Z</date></array>"
        "<key>NestedData</key><dict><key>k</key><data>AA==</data></dict>"
        "</dict>");
    REQUIRE_FALSE(p.failure.has_value());
    REQUIRE(p.rows.size() == 11);

    auto check = [&](std::string_view name, PolicyType t, std::string_view value,
                     std::string_view detail) {
        const auto* row = find_row(p.rows, name);
        REQUIRE(row != nullptr);
        CHECK(row->value.type == t);
        CHECK(row->value.value == value);
        CHECK(row->value.detail == detail);
        CHECK(row->level == Level::mandatory);
    };
    check("Str", PolicyType::String, "x", "");
    check("Yes", PolicyType::Bool, "true", "");
    check("No", PolicyType::Bool, "false", "");
    check("Int", PolicyType::Int, "-7", "");
    check("Real", PolicyType::Real, "1.5", "");
    check("List", PolicyType::List, R"(["a",2])", "");
    check("Dict", PolicyType::Dict, R"({"k":"v"})", "");
    // CFDate / CFData: the literal `unmodelled` outcome, not dropped, not another type.
    check("When", PolicyType::Unmodelled, "-", "date");
    check("Blob", PolicyType::Unmodelled, "-", "data");
    // Nested: the container row survives, marked degraded, the element is named.
    check("NestedDate", PolicyType::List, R"(["a","unmodelled:date"])", "nested_unmodelled");
    check("NestedData", PolicyType::Dict, R"({"k":"unmodelled:data"})", "nested_unmodelled");

    // Rows are sorted by policy name.
    CHECK(std::is_sorted(p.rows.begin(), p.rows.end(),
                         [](const PolicyRow& a, const PolicyRow& b) { return a.name < b.name; }));
    // And the wire form of an unmodelled row keeps nine fields.
    CHECK(format_policy_row(*find_row(p.rows, "When")) ==
          "policy|chrome|mandatory|machine|When|unmodelled|-|/p.plist|date");
}

TEST_CASE("browser_policy macOS: an undecodable or non-dictionary plist is a failure token",
          "[browser_policy][macos][plist]") {
    for (const std::string_view bad : {std::string_view{"not a plist at all"}, std::string_view{""},
                                       std::string_view{"<plist><dict><key>a</key>"}}) {
        const auto p = mac::rows_from_plist_bytes(bad, Browser::chrome, "machine", "/p.plist");
        REQUIRE(p.failure.has_value());
        CHECK(*p.failure == "macos:plist_unparseable");
        CHECK(p.rows.empty());
    }
    const auto arr = mac::rows_from_plist_bytes(plist_xml("<array><string>a</string></array>"),
                                                Browser::chrome, "machine", "/p.plist");
    REQUIRE(arr.failure.has_value());
    CHECK(*arr.failure == "macos:plist_not_dictionary");
    CHECK(arr.rows.empty());
}

TEST_CASE("browser_policy macOS: a corrupt plist is constrained and never hides its siblings",
          "[browser_policy][macos][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mac_bad_"};
    write_file(dir.path, "Library/Managed Preferences/com.google.Chrome.plist", kNotAPlist);
    write_file(dir.path, "Library/Managed Preferences/com.microsoft.Edge.plist",
               plist_xml("<dict><key>SmartScreenEnabled</key><true/></dict>"));
    std::string reason;
    const auto rows = mac::macos_policy_rows_at(dir.path, reason);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].find("policy|edge|mandatory|machine|SmartScreenEnabled|bool|true|") == 0);
    CHECK(reason == "macos:plist_unparseable");
}

TEST_CASE("browser_policy macOS: an unreadable user directory is constrained, machine rows survive",
          "[browser_policy][macos][tree]") {
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");

    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mac_eacces_"};
    fs::create_directories(dir.path);
    materialize_fixture(dir.path);
    const fs::path locked = dir.path / "Library/Managed Preferences/alice";
    PermRestore restore{locked};
    REQUIRE(::chmod(locked.c_str(), 0000) == 0);

    std::string reason;
    const auto rows = mac::macos_policy_rows_at(dir.path, reason);
    CHECK(reason == "macos:permission_denied");
    CHECK(count_prefix(rows, "policy|chrome|mandatory|user:alice|") == 0);
    CHECK(count_prefix(rows, "policy|chrome|mandatory|machine|") == 6);
    CHECK(count_prefix(rows, "policy|edge|mandatory|machine|") == 3);
}

TEST_CASE("browser_policy macOS: symlinks below the root are refused",
          "[browser_policy][macos][tree]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mac_symlink_"};
    fs::create_directories(dir.path);

    // (a) a symlinked "Managed Preferences" directory is not followed.
    write_file(dir.path, "elsewhere/com.google.Chrome.plist",
               plist_xml("<dict><key>A</key><true/></dict>"));
    fs::create_directories(dir.path / "root_a" / "Library");
    fs::create_directory_symlink(dir.path / "elsewhere",
                                 dir.path / "root_a" / "Library" / "Managed Preferences");
    std::string reason;
    auto rows = mac::macos_policy_rows_at(dir.path / "root_a", reason);
    CHECK(rows.empty());
    CHECK_FALSE(reason.empty()); // mutation: drop O_NOFOLLOW -> rows appear

    // (b) a symlinked per-user directory is refused and reported.
    write_file(dir.path, "root_b/Library/Managed Preferences/.keep", "");
    fs::create_directory_symlink(dir.path / "elsewhere",
                                 dir.path / "root_b" / "Library" / "Managed Preferences" / "mallory");
    rows = mac::macos_policy_rows_at(dir.path / "root_b", reason);
    CHECK(rows.empty());
    CHECK(reason == "macos:symlink_refused");

    // (c) a symlinked plist is refused.
    write_file(dir.path, "target.plist", plist_xml("<dict><key>A</key><true/></dict>"));
    fs::create_directories(dir.path / "root_c" / "Library" / "Managed Preferences");
    fs::create_symlink(dir.path / "target.plist", dir.path / "root_c" / "Library" /
                                                      "Managed Preferences" / "com.microsoft.Edge.plist");
    rows = mac::macos_policy_rows_at(dir.path / "root_c", reason);
    CHECK(rows.empty());
    CHECK(reason == "macos:symlink_refused");
}

TEST_CASE("browser_policy macOS: an embedded NUL in a CFString is kept by the decoder, flagged on the wire",
          "[browser_policy][macos][plist]") {
    const auto p = mac::rows_from_plist_bytes(binary_plist_with_nuls(), Browser::chrome, "machine",
                                              "/p.plist");
    REQUIRE_FALSE(p.failure.has_value());
    REQUIRE(p.rows.size() == 2);
    // Length-aware conversion: nothing after the NUL is silently dropped.
    const auto* value_row = find_row(p.rows, "K");
    REQUIRE(value_row != nullptr);
    CHECK(value_row->value.value == std::string("a\0b", 3));
    const auto* key_row = find_row(p.rows, std::string("N\0x", 3));
    REQUIRE(key_row != nullptr); // the key was not truncated to "N" either
    CHECK(key_row->value.type == PolicyType::Bool);

    // The wire form never carries the NUL (C-string transport) and says so.
    const auto v = format_policy_row(*value_row);
    CHECK(v.find('\0') == std::string::npos);
    CHECK(v == "policy|chrome|mandatory|machine|K|string|a\xEF\xBF\xBD"
               "b|/p.plist|nul_replaced");
    const auto k = format_policy_row(*key_row);
    CHECK(k.find('\0') == std::string::npos);
    CHECK(k == "policy|chrome|mandatory|machine|N\xEF\xBF\xBD"
               "x|bool|true|/p.plist|nul_replaced");
}

// ── failure -> command status ──

TEST_CASE("browser_policy macOS leg: acquisition failure reaches the command as CONSTRAINED/PARTIAL",
          "[browser_policy][macos][status]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mac_leg_bad_"};
    write_file(dir.path, "Library/Managed Preferences/com.google.Chrome.plist", kNotAPlist);
    write_file(dir.path, "Library/Managed Preferences/com.microsoft.Edge.plist",
               plist_xml("<dict><key>SmartScreenEnabled</key><true/></dict>"));

    const auto run = run_leg(dir.path);
    CHECK(run.rc == 0); // a degraded read is not a failed command
    REQUIRE(run.rows.size() == 1);
    CHECK(run.rows[0].find("policy|edge|mandatory|machine|SmartScreenEnabled|bool|true|") == 0);
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == "macos:plist_unparseable");

    // Only a bad plist: zero rows but STILL constrained — a failure never reads as absent.
    yuzu::test::TempDir only_bad{"yuzu_test_browser_policy_mac_leg_onlybad_"};
    write_file(only_bad.path, "Library/Managed Preferences/alice/com.google.Chrome.plist", kNotAPlist);
    const auto none = run_leg(only_bad.path);
    CHECK(none.rows.empty());
    CHECK(none.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(none.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(none.provenance == "macos:plist_unparseable");
}

TEST_CASE("browser_policy macOS leg: a genuinely absent or complete read is OK/FULL",
          "[browser_policy][macos][status]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mac_leg_ok_"};

    auto run = run_leg(dir.path / "no_such_root");
    CHECK(run.rc == 0);
    CHECK(run.rows.empty());
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(run.provenance.empty());

    materialize_fixture(dir.path / "fixture_root");
    run = run_leg(dir.path / "fixture_root");
    CHECK(run.rows.size() == 15);
    CHECK(count_prefix(run.rows, "policy|chrome|mandatory|machine|") == 6);
    CHECK(count_prefix(run.rows, "policy|chrome|mandatory|user:alice|") == 6);
    CHECK(count_prefix(run.rows, "policy|edge|mandatory|machine|") == 3);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(run.provenance.empty());
}

TEST_CASE("browser_policy macOS leg: a NUL in a plist value reaches the command whole",
          "[browser_policy][macos][status]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mac_leg_nul_"};
    write_file(dir.path, "Library/Managed Preferences/com.google.Chrome.plist",
               binary_plist_with_nuls());
    const auto run = run_leg(dir.path);
    REQUIRE(run.rows.size() == 2);
    // Truncating at the NUL would drop the source and detail fields.
    CHECK(has_row(run.rows,
                  "policy|chrome|mandatory|machine|K|string|a\xEF\xBF\xBD"
                  "b|/Library/Managed Preferences/com.google.Chrome.plist|nul_replaced"));
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
}

// ── saturation (WalkLimits; exactly-at-cap controls) ──

TEST_CASE("browser_policy macOS leg: the row cap is reported, and exactly-at-cap is complete",
          "[browser_policy][macos][cap]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mac_leg_rowcap_"};
    write_file(dir.path, "Library/Managed Preferences/com.google.Chrome.plist",
               plist_xml("<dict><key>A</key><true/><key>B</key><true/></dict>"));
    write_file(dir.path, "Library/Managed Preferences/alice/com.google.Chrome.plist",
               plist_xml("<dict><key>C</key><true/><key>D</key><true/></dict>"));

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
    CHECK(run.provenance == "macos:row_cap");
}

TEST_CASE("browser_policy macOS leg: a truncated user listing is reported, never complete",
          "[browser_policy][macos][cap]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mac_leg_dircap_"};
    for (const char* user : {"alice", "bob", "carol"})
        write_file(dir.path, std::string{"Library/Managed Preferences/"} + user +
                                 "/com.google.Chrome.plist",
                   plist_xml("<dict><key>A</key><true/></dict>"));

    WalkLimits limits;
    limits.max_entries_per_dir = 3; // exactly the entry count: the control
    auto run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 3);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);
    CHECK(run.provenance.empty());

    limits.max_entries_per_dir = 2; // an entry remains unread: must not read as complete
    run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 2); // only the examined users
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == "macos:row_cap");
}

TEST_CASE("browser_policy macOS leg: the file-size cap is exact and reported",
          "[browser_policy][macos][cap]") {
    yuzu::test::TempDir dir{"yuzu_test_browser_policy_mac_leg_filecap_"};
    const std::string body = plist_xml("<dict><key>A</key><true/></dict>");
    write_file(dir.path, "Library/Managed Preferences/com.google.Chrome.plist", body);

    WalkLimits limits;
    limits.max_file_bytes = body.size(); // exactly the size: read
    auto run = run_leg(dir.path, limits);
    CHECK(run.rows.size() == 1);
    CHECK(run.status == YUZU_RESULT_STATUS_OK);

    limits.max_file_bytes = body.size() - 1; // one byte over: constrained
    run = run_leg(dir.path, limits);
    CHECK(run.rows.empty());
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.provenance == "macos:oversized");
}

#endif // __APPLE__
