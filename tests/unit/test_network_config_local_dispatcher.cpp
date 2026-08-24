/**
 * test_network_config_local_dispatcher.cpp -- PKG-NC (Wave-4 PR4.1): loads
 * the ACTUAL built network_config plugin (network_config.dylib/.so, the
 * same artifact the agent daemon loads in production) via PluginHandle::load
 * and drives it through yuzu::agent::LocalDispatcher -- the same pattern
 * test_users_posix_actions.cpp established. This exercises the real
 * rtnetlink/getifaddrs/PF_ROUTE/proc-net-arp legs end to end against the
 * actual kernel on the test host.
 *
 * What these tests can and cannot catch: do_adapters() and do_arp() both
 * return 0 on EVERY path, including getifaddrs failure and an incomplete
 * rtnetlink dump, so `rc == 0` is close to vacuous on its own. The load-
 * bearing assertions are therefore on emitted-row SHAPE (field count,
 * non-empty key fields, known status values), on macOS loopback presence,
 * and on arp de-duplication -- three properties that a broken or reverted
 * leg actually violates. Row COUNT is deliberately not asserted: an empty
 * ARP table and a container with no non-loopback interface are both
 * legitimate host states, not migration failures.
 *
 * POSIX-only (macOS + Linux) -- Windows already reads every leg through
 * native Win32 APIs untouched by this package, so there is nothing new to
 * verify there.
 *
 * `adapters` and `arp` are exercised because both run real native syscalls
 * on the build host on every leg this package touches (rtnetlink/getifaddrs
 * for adapters; /proc/net/arp or the PF_ROUTE sysctl for arp) -- unlike
 * ip_addresses/dns_servers/proxy/dns_cache, which either depend on host
 * network state (a configured IP, a resolvable DNS server) or (dns_cache on
 * macOS) are an intentional permanent unsupported sentinel.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Captured plugin output is newline-separated `field|field|...` rows. These
// two helpers let the tests assert on SHAPE rather than only on rc, which
// do_adapters()/do_arp() return as 0 on every path including failure.
std::vector<std::string> rows_with_prefix(const std::string& captured, const std::string& prefix) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.rfind(prefix, 0) == 0)
            out.push_back(line);
    }
    return out;
}

std::vector<std::string> split_fields(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    std::istringstream ss(row);
    while (std::getline(ss, cur, '|'))
        out.push_back(cur);
    return out;
}

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Mirrors test_users_posix_actions.cpp's find_users_plugin, pointed at the
// network_config plugin's own build output. Empty path (never a hard
// failure) when not found, so a build without agent plugins skips rather
// than fails.
fs::path find_network_config_plugin() {
    const std::string lib_name = std::string{"network_config"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "network_config" /
                                lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "network_config" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "network_config" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "network_config" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "network_config" /
                            lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_network_config_plugin() {
    auto plugin_path = find_network_config_plugin();
    if (plugin_path.empty())
        return std::nullopt;
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value())
        return std::nullopt;
    const auto* descriptor = handle->descriptor();
    if (!descriptor)
        return std::nullopt;
    return LoadedPlugin{std::move(*handle), descriptor};
}

} // namespace

TEST_CASE("network_config plugin: adapters lists at least one real interface via the native leg",
         "[network_config][posix_actions]") {
    auto plugin = load_network_config_plugin();
    if (!plugin) {
        WARN("network_config plugin library not found -- skipping LocalDispatcher round-trip test");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "adapters");
    CHECK(result.rc == 0);

    // rc alone proves nothing: do_adapters() returns 0 on every path,
    // including getifaddrs failure and an incomplete rtnetlink dump. Assert
    // on the OUTPUT so a broken or reverted leg actually turns this red.
    const auto rows = rows_with_prefix(result.captured, "adapter|");

#if defined(__APPLE__)
    // macOS always has lo0, and the pre-migration `ifconfig -a` leg reported
    // it as a real adapter row. An early migration draft copied a loopback
    // skip here from do_ip_addresses and silently dropped it -- caught only
    // by a live before/after parity diff. This pins that regression.
    REQUIRE_FALSE(rows.empty());
    bool saw_lo0 = false;
    for (const auto& r : rows) {
        if (r.rfind("adapter|lo0|", 0) == 0)
            saw_lo0 = true;
    }
    CHECK(saw_lo0); // do_adapters must NOT filter loopback on macOS
#endif

    // Shape contract, portable: every row is `adapter|name|mac|speed|status`
    // with a non-empty name and a status drawn from the known set. A leg that
    // emits a wrong field count or an unmapped status fails here.
    for (const auto& r : rows) {
        const auto f = split_fields(r);
        CHECK(f.size() == 5);
        if (f.size() == 5) {
            CHECK_FALSE(f[1].empty());
            CHECK((f[4] == "up" || f[4] == "down" || f[4] == "unknown"));
        }
    }
}

TEST_CASE("network_config plugin: arp exercises the real native leg without error",
         "[network_config][posix_actions]") {
    auto plugin = load_network_config_plugin();
    if (!plugin) {
        WARN("network_config plugin library not found -- skipping");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "arp");
    CHECK(result.rc == 0);

    // An empty ARP/neighbour table is legitimate on a freshly-booted or
    // sandboxed runner, so row COUNT is not asserted. Row SHAPE is: every
    // emitted row must be `arp|iface|ip|mac|type` with a non-empty ip and
    // mac. The macOS leg honestly reports iface and type as "-" (the
    // RTF_LLINFO dump does not carry them); it must still emit five fields.
    for (const auto& r : rows_with_prefix(result.captured, "arp|")) {
        const auto f = split_fields(r);
        CHECK(f.size() == 5);
        if (f.size() == 5) {
            CHECK_FALSE(f[2].empty()); // ip
            CHECK_FALSE(f[3].empty()); // mac
        }
    }

    // Duplicate (ip, mac) rows were a real regression on macOS: the
    // PF_ROUTE dump can report the same neighbour twice and the first draft
    // emitted both. Deduplication is part of the contract.
    const auto rows = rows_with_prefix(result.captured, "arp|");
    std::set<std::string> unique(rows.begin(), rows.end());
    CHECK(unique.size() == rows.size());
}

#endif // !_WIN32
