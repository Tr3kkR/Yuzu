/**
 * test_autoruns_linux_local.cpp — loads the ACTUAL built autoruns plugin via
 * PluginHandle::load and drives it through yuzu::agent::LocalDispatcher,
 * asserting on the Linux-source rows/status of a real "list" capture.
 *
 * UNGUARDED, deliberately (see test_autoruns_local_dispatcher.cpp's own
 * banner: a `#ifndef __linux__` exclusion on a dispatcher TU is exactly how
 * a compiled-out leg ships green with no test ever loading it). On a
 * non-Linux build host, `collect_linux` resolves to autoruns_legs.hpp's
 * foreign-OS stub (P11), so every `lnx_*` SourceId is expected to report
 * `unsupported|0|foreign_os` -- asserted explicitly below rather than
 * skipped, so a future accidental narrowing of that stub is still caught on
 * every CI leg, not just Linux's.
 *
 * On a Linux build host this exercises the REAL `collect_linux`
 * (autoruns_linux.cpp, P13) against whatever cron/systemd/XDG state the
 * host actually has -- assertions here are host-tolerant by design (no
 * invented fixture data): they check the SHAPE every Linux source's status
 * line must have, never a specific row count, since a real capture's row
 * count depends on the host's own configuration.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include "autoruns_catalog.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

/// Autoruns folds '|' to U+2502 rather than escaping it, so a naive
/// split('|') is already safe -- no field can contain a raw '|'.
std::vector<std::string> fields_of(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : row) {
        if (c == '|') { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    out.push_back(cur);
    return out;
}

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("autoruns plugin library not found under meson test -- the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("autoruns plugin library not found -- skipping the LocalDispatcher round-trip");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_autoruns_plugin() {
    const std::string lib_name = std::string{"autoruns"} + kPluginExt;
    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "autoruns" / lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "autoruns" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "autoruns" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "autoruns" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_autoruns_plugin() {
    auto path = find_autoruns_plugin();
    if (path.empty()) return std::nullopt;
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

std::vector<yuzu::autoruns::SourceId> linux_source_ids() {
    std::vector<yuzu::autoruns::SourceId> out;
    for (const auto& decl : yuzu::autoruns::kSourceCatalog)
        if (decl.linux != YUZU_SUPPORT_UNSUPPORTED) out.push_back(decl.id);
    return out;
}

struct SourceStatus {
    std::string status;
    std::string row_count;
    std::string reason;
};

std::optional<SourceStatus> find_status(const std::vector<std::string>& rows, const std::string& id) {
    for (const auto& r : rows) {
        auto f = fields_of(r);
        if (f.size() == 5 && f[0] == "source" && f[1] == id)
            return SourceStatus{f[2], f[3], f[4]};
    }
    return std::nullopt;
}

} // namespace

TEST_CASE("autoruns Linux leg: every lnx_* SourceId emits exactly one source| line",
          "[autoruns][actions][linux]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    const auto ids = linux_source_ids();
    REQUIRE_FALSE(ids.empty());

    for (const auto id : ids) {
        const std::string id_str{yuzu::autoruns::source_id_string(id)};
        int count = 0;
        for (const auto& r : rows) {
            auto f = fields_of(r);
            if (f.size() == 5 && f[0] == "source" && f[1] == id_str) ++count;
        }
        INFO("source id: " << id_str);
        CHECK(count == 1);
    }
}

#if !defined(__linux__)

TEST_CASE("autoruns Linux leg: on a non-Linux build every lnx_* source reports "
          "unsupported|0|foreign_os",
          "[autoruns][actions][linux]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);

    for (const auto id : linux_source_ids()) {
        const std::string id_str{yuzu::autoruns::source_id_string(id)};
        auto st = find_status(rows, id_str);
        REQUIRE(st.has_value());
        INFO("source id: " << id_str);
        CHECK(st->status == "unsupported");
        CHECK(st->row_count == "0");
        CHECK(st->reason == "foreign_os");
    }
}

#else // defined(__linux__)

TEST_CASE("autoruns Linux leg: real collect_linux never reports foreign_os for a lnx_* source",
          "[autoruns][actions][linux]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);

    static const std::set<std::string> kValidStatus{"supported", "constrained", "unsupported"};
    for (const auto id : linux_source_ids()) {
        const std::string id_str{yuzu::autoruns::source_id_string(id)};
        auto st = find_status(rows, id_str);
        REQUIRE(st.has_value());
        INFO("source id: " << id_str);
        CHECK(kValidStatus.count(st->status) == 1);
        // This TU is compiled only when __linux__ is defined, so
        // collect_linux ran for real -- "foreign_os" (the non-Linux stub's
        // exclusive reason string) must never appear here.
        CHECK(st->reason != "foreign_os");
    }
}

TEST_CASE("autoruns Linux leg: lnx_init_d is always reported CONSTRAINED (catalog-declared, "
          "listing-only)",
          "[autoruns][actions][linux]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);

    auto st = find_status(rows, "lnx_init_d");
    REQUIRE(st.has_value());
    // SysV enablement is distro-dependent and not modelled -- this source is
    // declared CONSTRAINED in the catalog on every real host, success or not.
    CHECK(st->status == "constrained");

    for (const auto& r : rows) {
        auto f = fields_of(r);
        if (f.size() == 12 && f[0] == "autorun" && f[1] == "lnx_init_d") {
            // field 7 (0-indexed) is `enabled` in the fixed row schema.
            CHECK(f[7] == "unknown");
        }
    }
}

TEST_CASE("autoruns Linux leg: systemd sources are self-consistent with /run/systemd/system "
          "tri-state on this real host",
          "[autoruns][actions][linux]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);

    auto sys_st = find_status(rows, "lnx_systemd_timers_system");
    auto usr_st = find_status(rows, "lnx_systemd_timers_user");
    REQUIRE(sys_st.has_value());
    REQUIRE(usr_st.has_value());

    std::error_code ec;
    const bool systemd_dir_present = fs::is_directory("/run/systemd/system", ec) && !ec;
    if (!systemd_dir_present) {
        // absent -> both systemd sources must be honestly unsupported, never
        // silently reported as supported-with-zero-rows.
        CHECK(sys_st->status == "unsupported");
        CHECK(sys_st->reason == "no_systemd");
        CHECK(usr_st->status == "unsupported");
        CHECK(usr_st->reason == "no_systemd");
    } else {
        // present -> neither source is the no_systemd/undetermined tri-state;
        // the row count each carries depends on the host's real unit dirs.
        CHECK(sys_st->reason != "no_systemd");
        CHECK(usr_st->reason != "no_systemd");

        // lnx_systemd_timers_user is a permanent catalog-declared exception
        // (autoruns_catalog.hpp) -- CONSTRAINED with narrow_search_path_coverage
        // named in the reason on every reportable path, real ones included.
        // Drives the ACTUAL collect_linux integration points via a live
        // dispatch (RECONSTRUCTION: pins round 7's should-fix -- the
        // apply_narrow_search_path_coverage TEST_CASE above only calls the
        // function directly, so a later edit removing one of the three real
        // call sites would leave that test green while this one catches it).
        CHECK(usr_st->status == "constrained");
        CHECK(usr_st->reason.find("narrow_search_path_coverage") != std::string::npos);
    }
}

#endif // defined(__linux__)

#if defined(__linux__)

// Direct source inclusion, Linux-only: read_file_bounded and
// classify_read_error are declared and defined ONLY in autoruns_linux.cpp
// (by design -- see that file's own banner), with internal (anonymous-
// namespace) linkage, so there is no header seam to reach them through
// otherwise. The macro excludes collect_linux itself from this inclusion
// (see autoruns_linux.cpp's own guard comment) so the rung-2 subprocess
// fallback's runner symbols are never pulled into this test binary's link
// -- this TU never statically links the real plugin either way (the
// TEST_CASEs above load it via PluginHandle::load/dlopen at runtime), so a
// second compilation of the same free functions here creates no
// ODR/duplicate-symbol conflict.
#define YUZU_AUTORUNS_LINUX_UNIT_TEST_INTERNALS_ONLY 1
#include "../../agents/plugins/autoruns/src/autoruns_linux.cpp"
#undef YUZU_AUTORUNS_LINUX_UNIT_TEST_INTERNALS_ONLY

TEST_CASE("autoruns Linux leg: read_file_bounded/classify_read_error distinguish "
          "symlink_refused and oversized from a constructed fixture",
          "[autoruns][actions][linux]") {
    namespace fsx = std::filesystem;
    yuzu::test::TempDir tmp("yuzu_test_autoruns_linux_");
    fsx::create_directories(tmp.path);
    const fsx::path& dir = tmp.path;
    std::error_code ec;

    SECTION("a symlinked leaf is refused with symlink_refused, never resolved") {
        fsx::path target = dir / "target.txt";
        { std::ofstream(target) << "real file\n"; }
        fsx::path link = dir / "link.txt";
        fsx::create_symlink(target, link, ec);
        REQUIRE_FALSE(ec);

        auto result = yuzu::autoruns::read_file_bounded(link.string());
        REQUIRE_FALSE(result.has_value());
        auto cls = yuzu::autoruns::classify_read_error(result.error(), /*required_by_catalog=*/false);
        CHECK(cls.reason == "symlink_refused");
    }

    SECTION("a file over the byte cap is refused with oversized") {
        // The cap itself is injected (max_bytes), so the fixture only needs
        // to exceed a small, test-chosen cap -- not the real 1 MiB default --
        // keeping this unit test's I/O a few bytes rather than a megabyte-plus
        // write (test-efficiency discipline: no unjustified disk cost).
        fsx::path big = dir / "big.txt";
        {
            std::ofstream out(big, std::ios::binary);
            out << "0123456789"; // 10 bytes > the 4-byte cap below
        }
        auto result = yuzu::autoruns::read_file_bounded(big.string(), /*max_bytes=*/4);
        REQUIRE_FALSE(result.has_value());
        auto cls = yuzu::autoruns::classify_read_error(result.error(), /*required_by_catalog=*/false);
        CHECK(cls.reason == "oversized");
    }
}

TEST_CASE("autoruns Linux leg: list_dir reports truncated for exactly one real entry "
          "beyond the cap (RECONSTRUCTION: pins the fix for an adversarial-review "
          "falsifier -- an earlier version discarded the over-cap entry itself while "
          "probing for a SECOND one, so cap=2 with exactly 3 real entries reported "
          "truncated=false)",
          "[autoruns][actions][linux]") {
    yuzu::test::TempDir tmp("yuzu_test_autoruns_linux_listdir_");
    std::error_code ec;
    std::filesystem::create_directories(tmp.path, ec);
    REQUIRE_FALSE(ec);
    for (const char* name : {"a.txt", "b.txt", "c.txt"}) {
        std::ofstream(tmp.path / name) << "x";
    }

    SECTION("cap+1 real entries -> truncated") {
        auto listing = yuzu::autoruns::list_dir(tmp.path.string(), /*cap=*/2);
        CHECK(listing.opened);
        CHECK(listing.names.size() == 2);
        CHECK(listing.truncated);
    }

    SECTION("exactly cap entries -> not truncated") {
        auto listing = yuzu::autoruns::list_dir(tmp.path.string(), /*cap=*/3);
        CHECK(listing.opened);
        CHECK(listing.names.size() == 3);
        CHECK_FALSE(listing.truncated);
    }

    SECTION("cap well above the real entry count -> not truncated") {
        auto listing = yuzu::autoruns::list_dir(tmp.path.string(), /*cap=*/4096);
        CHECK(listing.opened);
        CHECK(listing.names.size() == 3);
        CHECK_FALSE(listing.truncated);
    }
}

TEST_CASE("autoruns Linux leg: timer_scan_status combines truncation and per-file "
          "constraints into one status/reason pair",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::TimerScan;
    using yuzu::autoruns::timer_scan_status;

    SECTION("neither flag set -> supported, dash reason") {
        TimerScan scan;
        const auto [support, reason] = timer_scan_status(scan);
        CHECK(support == YUZU_SUPPORT_SUPPORTED);
        CHECK(reason == "-");
    }

    SECTION("truncated only -> constrained, row_cap") {
        TimerScan scan;
        scan.any_truncated = true;
        const auto [support, reason] = timer_scan_status(scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "row_cap");
    }

    SECTION("file-constrained only -> constrained, the file's reason") {
        TimerScan scan;
        scan.any_file_constrained = true;
        scan.file_constrained_reason = "permission_denied";
        const auto [support, reason] = timer_scan_status(scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "permission_denied");
    }

    SECTION("both -> constrained, comma-joined reason") {
        TimerScan scan;
        scan.any_truncated = true;
        scan.any_file_constrained = true;
        scan.file_constrained_reason = "permission_denied";
        const auto [support, reason] = timer_scan_status(scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "permission_denied,row_cap");
    }

    SECTION("permission-denied only -> constrained, partial_permission_denied "
            "(round-3 should-fix: a per-home directory-open failure must not "
            "be silently folded into Supported just because a global "
            "directory succeeded)") {
        TimerScan scan;
        scan.any_permission_denied = true;
        const auto [support, reason] = timer_scan_status(scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "partial_permission_denied");
    }

    SECTION("permission-denied plus truncated -> both reasons, denial first") {
        TimerScan scan;
        scan.any_permission_denied = true;
        scan.any_truncated = true;
        const auto [support, reason] = timer_scan_status(scan);
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "partial_permission_denied,row_cap");
    }
}

TEST_CASE("autoruns Linux leg: apply_narrow_search_path_coverage always "
          "downgrades to Constrained and names the permanent gap "
          "(RECONSTRUCTION: pins round 4's should-fix -- extracted from the "
          "call site into a named function specifically so this integration "
          "point, previously unexercised by any test, is now directly "
          "testable)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::apply_narrow_search_path_coverage;

    SECTION("Supported -> Constrained, standalone reason") {
        const auto [support, reason] =
            apply_narrow_search_path_coverage(YUZU_SUPPORT_SUPPORTED, "-");
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "narrow_search_path_coverage");
    }

    SECTION("already Constrained -> stays Constrained, reason appended") {
        const auto [support, reason] =
            apply_narrow_search_path_coverage(YUZU_SUPPORT_CONSTRAINED, "partial_permission_denied");
        CHECK(support == YUZU_SUPPORT_CONSTRAINED);
        CHECK(reason == "partial_permission_denied,narrow_search_path_coverage");
    }
}

TEST_CASE("autoruns Linux leg: timer_enabled correlates a global-directory "
          "unit against every enumerated user's own wants directory "
          "(RECONSTRUCTION: pins round 3's blocker -- an ordinary "
          "`systemctl --user enable` on a vendor-shipped unit writes its "
          "enablement symlink into the enabling user's OWN "
          "~/.config/systemd/user/timers.target.wants, which has no "
          "relationship to where the unit file itself lives; the fix must "
          "check that directory too, not just the unit's own dir and the "
          "global /etc/systemd/user root)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::Enabled;
    using yuzu::autoruns::Scope;
    using yuzu::autoruns::timer_enabled;

    yuzu::test::TempDir vendor_dir("yuzu_test_autoruns_vendor_");
    yuzu::test::TempDir user_dir("yuzu_test_autoruns_user_");
    std::filesystem::create_directories(vendor_dir.path);
    std::filesystem::create_directories(user_dir.path / "timers.target.wants");

    // The unit file lives ONLY in the vendor (global) directory -- this
    // mirrors /usr/lib/systemd/user on a real host.
    const auto unit_file = vendor_dir.path / "backup.timer";
    { std::ofstream f(unit_file); f << "[Timer]\nOnCalendar=daily\n"; }

    // The enablement symlink lives ONLY in the user's own dir -- this
    // mirrors ~/.config/systemd/user/timers.target.wants after `systemctl
    // --user enable backup.timer`, and deliberately does NOT also appear
    // under the global /etc/systemd/user root this fix already handled.
    std::filesystem::create_symlink(unit_file, user_dir.path / "timers.target.wants" / "backup.timer");

    SECTION("without the user's wants dir threaded through -> disabled "
            "(reproduces the round-3 blocker)") {
        CHECK(timer_enabled(vendor_dir.path.string(), "backup.timer", "", Scope::user, {}) ==
             Enabled::disabled);
    }

    SECTION("with the user's wants dir threaded through -> enabled") {
        CHECK(timer_enabled(vendor_dir.path.string(), "backup.timer", "", Scope::user,
                            {user_dir.path.string()}) == Enabled::enabled);
    }

    SECTION("a different, unrelated user's wants dir does not falsely enable it") {
        yuzu::test::TempDir other_user_dir("yuzu_test_autoruns_other_user_");
        std::filesystem::create_directories(other_user_dir.path / "timers.target.wants");
        CHECK(timer_enabled(vendor_dir.path.string(), "backup.timer", "", Scope::user,
                            {other_user_dir.path.string()}) == Enabled::disabled);
    }

    SECTION("a same-named timer enabled in one user's own directory does not "
            "falsely enable an unrelated user's separate, never-enabled timer "
            "of the same name (RECONSTRUCTION: pins round 4's should-fix -- "
            "user_wants_bases must reach only the two GLOBAL-directory scans, "
            "never the per-home scans, whose own unit_dir is already the "
            "correct wants base; the round-3 fix passed it to every "
            "user-scope call, so Bob enabling his own same.timer used to "
            "falsely mark Alice's separate same.timer enabled too)") {
        using yuzu::autoruns::Row;
        using yuzu::autoruns::scan_systemd_timer_dir_unique;
        using yuzu::autoruns::TimerScan;

        yuzu::test::TempDir bob_dir("yuzu_test_autoruns_bob_");
        yuzu::test::TempDir alice_dir("yuzu_test_autoruns_alice_");
        std::filesystem::create_directories(bob_dir.path / "timers.target.wants");
        std::filesystem::create_directories(alice_dir.path);

        const auto bob_unit = bob_dir.path / "same.timer";
        { std::ofstream f(bob_unit); f << "[Timer]\nOnCalendar=daily\n"; }
        std::filesystem::create_symlink(bob_unit, bob_dir.path / "timers.target.wants" / "same.timer");

        const auto alice_unit = alice_dir.path / "same.timer";
        { std::ofstream f(alice_unit); f << "[Timer]\nOnCalendar=daily\n"; }
        // Alice never enables her copy -- no wants symlink in her directory.

        TimerScan scan;
        std::vector<std::pair<dev_t, ino_t>> seen_dirs;
        // Matches the real call site exactly: per-home scans get no
        // user_wants_bases argument at all.
        scan_systemd_timer_dir_unique(bob_dir.path.string(), Scope::user, "bob", scan, seen_dirs);
        scan_systemd_timer_dir_unique(alice_dir.path.string(), Scope::user, "alice", scan, seen_dirs);

        Enabled bob_enabled = Enabled::unknown, alice_enabled = Enabled::unknown;
        for (const auto& row : scan.rows) {
            if (row.user == "bob") bob_enabled = row.enabled;
            if (row.user == "alice") alice_enabled = row.enabled;
        }
        CHECK(bob_enabled == Enabled::enabled);
        CHECK(alice_enabled == Enabled::disabled);
    }
}

TEST_CASE("autoruns Linux leg: a wants-directory scan capped before reaching the real "
          "enablement symlink reports unknown, never a confident disabled "
          "(RECONSTRUCTION: pins PR #4154 round 8's blocker -- build_wants_listing's "
          "kMaxDirEntries cap carried no distinct truncation signal, so timer_enabled "
          "fell through to a confident Enabled::disabled exactly as if the symlink "
          "genuinely didn't exist; round 8's own falsifier used 5,000 real entries in a "
          ".wants directory with the real symlink placed beyond the cap)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::Enabled;
    using yuzu::autoruns::Scope;
    using yuzu::autoruns::timer_enabled;

    yuzu::test::TempDir dir("yuzu_test_autoruns_cap_");
    std::filesystem::create_directories(dir.path / "timers.target.wants");

    const auto unit_file = dir.path / "backup.timer";
    { std::ofstream f(unit_file); f << "[Timer]\nOnCalendar=daily\n"; }

    // One real enablement symlink for the unit under test, PLUS enough
    // decoy entries (matching production's kMaxDirEntries, 4096) that a
    // correct implementation cannot promise it saw the real one -- the
    // decoys are named to sort well ahead of "backup.timer" so a
    // lexicographic-order filesystem walk (the common case) genuinely
    // exercises the cap-before-match path this test exists to pin, while a
    // hash-ordered filesystem still gets a real assertion out of it (never
    // confidently disabled, whether or not the match happened to survive).
    std::filesystem::create_symlink(unit_file, dir.path / "timers.target.wants" / "backup.timer");
    for (int i = 0; i < 4096; ++i) {
        const auto decoy = dir.path / "timers.target.wants" / ("aaa-decoy-" + std::to_string(i) + ".timer");
        std::filesystem::create_symlink(unit_file, decoy);
    }

    const auto result = timer_enabled(dir.path.string(), "backup.timer", "", Scope::user, {});
    CHECK(result != Enabled::disabled);
}

TEST_CASE("autoruns Linux leg: note_file_constraint dedups a repeated token "
          "(RECONSTRUCTION: pins a governance-Gate-4 finding -- a per-file "
          "constraint hit across many entries/profiles used to grow the "
          "reason string once per occurrence instead of once per distinct "
          "reason)",
          "[autoruns][actions][linux]") {
    bool any = false;
    std::string reason;
    yuzu::autoruns::note_file_constraint(any, reason, "permission_denied");
    yuzu::autoruns::note_file_constraint(any, reason, "permission_denied");
    yuzu::autoruns::note_file_constraint(any, reason, "permission_denied");
    CHECK(any);
    CHECK(reason == "permission_denied");

    yuzu::autoruns::note_file_constraint(any, reason, "oversized");
    CHECK(reason == "permission_denied,oversized");
}

TEST_CASE("autoruns Linux leg: trim_possibly_truncated_tail drops a partial "
          "trailing line only on a non-clean subprocess stop "
          "(RECONSTRUCTION: pins a governance-Gate-4 finding -- the rung-2 "
          "systemctl fallback could silently emit a truncated field as if "
          "it were a real, complete value)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::trim_possibly_truncated_tail;

    CHECK(trim_possibly_truncated_tail("a.timer b.service\n", true) == "a.timer b.service\n");
    CHECK(trim_possibly_truncated_tail("a.timer b.service", true) == "a.timer b.service");
    CHECK(trim_possibly_truncated_tail("a.timer b.service\n", false) == "a.timer b.service\n");
    CHECK(trim_possibly_truncated_tail("a.timer b.service\nc.timer d.se", false) ==
         "a.timer b.service\n");
    CHECK(trim_possibly_truncated_tail("c.timer d.se", false).empty());
    CHECK(trim_possibly_truncated_tail("", false).empty());
}

TEST_CASE("autoruns Linux leg: list_dir reports permission_denied, not absent, for a "
          "genuinely unreadable existing directory "
          "(RECONSTRUCTION: pins round 5's should-fix -- the round-4 XDG-denial fix "
          "had no regression test; this follows the same try-then-verify pattern "
          "already established in this repo (test_guardian_state_reader.cpp's "
          "read_file permission test) rather than a geteuid()==0 precheck, since "
          "even a non-root but capability-elevated runner can bypass the check)",
          "[autoruns][actions][linux]") {
    using yuzu::autoruns::list_dir;

    yuzu::test::TempDir dir("yuzu_test_autoruns_denied_");
    std::filesystem::create_directories(dir.path);
    std::error_code ec;
    std::filesystem::permissions(dir.path, std::filesystem::perms::none, ec);
    if (ec) SKIP("could not remove directory permissions");

    const auto listing = list_dir(dir.path.string());

    std::filesystem::permissions(dir.path, std::filesystem::perms::owner_all, ec); // restore for cleanup
    if (listing.opened) SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");

    CHECK_FALSE(listing.absent);        // the directory demonstrably EXISTS...
    CHECK(listing.permission_denied);   // ...so this is a real denial, never folded into "absent"
}

#endif // defined(__linux__)

TEST_CASE("autoruns Linux leg: an unknown action is refused, not silently ignored",
          "[autoruns][actions][linux]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc != 0);
}
