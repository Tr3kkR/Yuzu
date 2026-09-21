/**
 * test_system_hardening_local_dispatcher.cpp -- loads the ACTUAL built
 * system_hardening plugin (system_hardening.dylib / .so / .dll) via
 * PluginHandle::load and drives it through yuzu::agent::LocalDispatcher, so
 * the real per-OS leg runs on the build host (the peripherals/disk_actions
 * dispatcher-test shape).
 *
 * RUNS ON ALL THREE PLATFORMS -- no platform guard on the TU (a guarded
 * dispatcher TU once hid a never-loaded plugin). Only the two host-specific
 * assertions consult a constexpr: on Linux/macOS the leg is this package's
 * and must emit exactly one row per allowlisted key; the Windows leg is a
 * sibling package's, so there only the row grammar and the status/token
 * contract are asserted. The Windows leg's <state> vocabulary is {on, off, default,
 * unmodelled, absent, unreadable} by Architect ruling (a tri-state override,
 * not a hardening level), so the row-grammar check keys the accepted set on
 * the host. There is no host-specific VALUE assertion anywhere: CI runners
 * are shared and unknown-hardware, and an absent key (no Yama on a Docker
 * kernel, no MitigationOptions on a default Windows install) is a legitimate,
 * modal host answer: it adds no failure token and does not lower the status.
 * Only an UNREADABLE key is a failure. The status test below holds on every
 * host, Windows included, because that contract is the same on all three legs.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "system_hardening_parsers.hpp"

#include <array>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::system_hardening;

namespace {

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
constexpr bool kLegIsThisPackages = false;
constexpr std::size_t kExpectedRows = 0; // unused: the Windows leg is not this package's
constexpr std::string_view kExpectedOs = "windows";
// Quoted from the sibling leg's ROW contract (its win-parsers header's ROW comment;
// P81b-2 respec s4) -- a tri-state override, not a hardening level. If the
// sibling changes its vocabulary this test fails on Windows CI, which is the guard.
constexpr std::array<std::string_view, 6> kHostStateTokens{"on",         "off",    "default",
                                                            "unmodelled", "absent", "unreadable"};
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
constexpr bool kLegIsThisPackages = true;
const std::size_t kExpectedRows = kMacosAllowlist.size();
constexpr std::string_view kExpectedOs = "macos";
const auto& kHostStateTokens = kStateTokens;
#else
constexpr const char* kPluginExt = ".so";
constexpr bool kLegIsThisPackages = true;
const std::size_t kExpectedRows = kLinuxAllowlist.size();
constexpr std::string_view kExpectedOs = "linux";
const auto& kHostStateTokens = kStateTokens;
#endif

/// Escape-aware field split: safe_output_field escapes a literal '|' as '\|'.
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

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996) // getenv, as in every sibling *_local_dispatcher.cpp
#endif
/// Under `meson test` (MESON_BUILD_ROOT always set) a missing plugin means the
/// build is genuinely broken and must NOT report "All tests passed".
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("system_hardening plugin library not found under meson test -- the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    WARN("system_hardening plugin library not found -- skipping the LocalDispatcher round-trip");
}

fs::path find_plugin() {
    const std::string lib = std::string{"system_hardening"} + kPluginExt;
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{root} / "agents" / "plugins" / "system_hardening" / lib);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "system_hardening" / lib);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "system_hardening" / lib);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "system_hardening" / lib);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
};

std::optional<LoadedPlugin> load_plugin() {
    const auto path = find_plugin();
    if (path.empty()) return std::nullopt;
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

bool is_state_token(const std::string& s) {
    for (const auto t : kHostStateTokens)
        if (t == s) return true;
    return false;
}

/// The status reason is the comma-joined `<key>:<cause>` failure tokens.
std::vector<std::string> split_tokens(const std::string& reason) {
    std::vector<std::string> out;
    std::istringstream ss(reason);
    std::string tok;
    while (std::getline(ss, tok, ','))
        if (!tok.empty()) out.push_back(tok);
    return out;
}

bool has_token_for(const std::vector<std::string>& tokens, const std::string& key) {
    for (const auto& t : tokens)
        if (t.rfind(key + ":", 0) == 0) return true;
    return false;
}

} // namespace

TEST_CASE("system_hardening plugin: every row is posture|os|key|raw|state with a known state",
          "[system_hardening][actions]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "posture");
    CHECK(result.rc == 0); // a missing or unreadable key is a degraded read, never a failed command
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        INFO("row: " << r);
        const auto f = split_fields(r);
        REQUIRE(f.size() == 5);
        CHECK(f[0] == "posture");
        CHECK(f[1] == kExpectedOs);
        CHECK_FALSE(f[2].empty());
        CHECK(is_state_token(f[4]));
        // "-" means "nothing was read": exactly the absent/unreadable rows.
        const bool no_value = (f[4] == "absent" || f[4] == "unreadable");
        CHECK((f[3] == "-") == no_value);
    }
}

TEST_CASE("system_hardening plugin: one row per allowlisted key, in allowlist order (Linux/macOS)",
          "[system_hardening][actions]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    if (!kLegIsThisPackages) SKIP("Windows leg is a sibling package's; its rows are shape-checked above");
    yuzu::agent::LocalDispatcher dispatcher;
    const auto rows = captured_rows(dispatcher.run(plugin->descriptor, "posture").captured);
    // Rows are emitted for absent/unreadable keys too, so the count is host-independent.
    REQUIRE(rows.size() == kExpectedRows);
    for (std::size_t i = 0; i < rows.size(); ++i) {
        [[maybe_unused]] const auto f = split_fields(rows[i]);
#if defined(__APPLE__)
        CHECK(f[2] == kMacosAllowlist[i].name);
#elif !defined(_WIN32)
        CHECK(f[2] == kLinuxAllowlist[i].key);
#endif
    }
}

TEST_CASE("system_hardening plugin: the typed status agrees with the rows; only an unreadable key is a failure",
          "[system_hardening][status]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "posture");
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    std::vector<std::vector<std::string>> unreadable;
    std::vector<std::vector<std::string>> absent;
    for (const auto& r : rows) {
        const auto f = split_fields(r);
        if (f.size() != 5) continue;
        if (f[4] == "unreadable") unreadable.push_back(f);
        else if (f[4] == "absent") absent.push_back(f);
    }
    const bool is_ok = result.result_status == YUZU_RESULT_STATUS_OK;
    const bool is_constrained = result.result_status == YUZU_RESULT_STATUS_CONSTRAINED;
    // Only the Windows leg sets PERMISSION_DENIED (ERROR_ACCESS_DENIED); the Linux/macOS
    // legs (emit_posture) never emit it.
    const bool is_denied =
        !kLegIsThisPackages && result.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED;
    REQUIRE((is_ok || is_constrained || is_denied));
    const auto tokens = split_tokens(result.result_provenance);
    if (is_ok) {
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
        CHECK(tokens.empty());
    } else {
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK_FALSE(result.result_provenance.empty());
    }
    // OK exactly when no key was unreadable -- no silent OK, no phantom failure. An absent key
    // (no Yama on a Docker kernel, no MitigationOptions on a default Windows install) does NOT
    // lower the status.
    CHECK(is_ok == unreadable.empty());
    // An unreadable key is named by a `<key>:<cause>` token; an absent key has none.
    for (const auto& f : unreadable) {
        INFO("unreadable key: " << f[2]);
        CHECK(has_token_for(tokens, f[2]));
    }
    for (const auto& f : absent) {
        INFO("absent key: " << f[2]);
        CHECK_FALSE(has_token_for(tokens, f[2]));
    }
    // The retired absence tokens must never come back.
    for (const auto& t : tokens) {
        INFO("token: " << t);
        CHECK(t.find(":enoent") == std::string::npos);
        CHECK(t.find(":not_found") == std::string::npos);
        CHECK(t.find(":unsupported") == std::string::npos);
    }
}

TEST_CASE("system_hardening plugin: an unknown action is refused, not silently ignored",
          "[system_hardening][actions]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    CHECK(dispatcher.run(plugin->descriptor, "no_such_action").rc != 0);
}
