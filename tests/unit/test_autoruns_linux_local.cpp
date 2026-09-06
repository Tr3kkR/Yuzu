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
    std::error_code ec;
    fsx::path dir = fsx::temp_directory_path(ec) /
                    ("autoruns_linux_test_" + std::to_string(static_cast<long>(::getpid())));
    fsx::create_directories(dir, ec);
    REQUIRE_FALSE(ec);
    struct Cleanup {
        fsx::path p;
        ~Cleanup() {
            std::error_code ec2;
            fsx::remove_all(p, ec2);
        }
    } cleanup{dir};

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
        fsx::path big = dir / "big.txt";
        {
            std::ofstream out(big, std::ios::binary);
            const std::string chunk(1024, 'x');
            for (int i = 0; i < 1025; ++i) out << chunk; // 1025 KiB > 1 MiB cap
        }
        auto result = yuzu::autoruns::read_file_bounded(big.string(), /*max_bytes=*/1'048'576);
        REQUIRE_FALSE(result.has_value());
        auto cls = yuzu::autoruns::classify_read_error(result.error(), /*required_by_catalog=*/false);
        CHECK(cls.reason == "oversized");
    }
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
