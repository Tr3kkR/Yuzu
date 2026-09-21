/**
 * test_local_security_policy_local_dispatcher.cpp -- loads the ACTUAL built plugin and drives
 * every action through yuzu::agent::LocalDispatcher. Unguarded (runs on all three OSes).
 * Assertions are row FAMILIES and status invariants, never host-specific values: a host may
 * or may not have auditd, faillock or root read access.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(_WIN32)
constexpr const char* kExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kExt = ".dylib";
#else
constexpr const char* kExt = ".so";
#endif

std::optional<yuzu::agent::PluginHandle> load_plugin() {
    const std::string lib = std::string{"local_security_policy"} + kExt;
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{root} / "agents" / "plugins" / "local_security_policy" / lib);
    for (const char* b : {"", "..", "build-macos", "build-windows", "build-linux"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "local_security_policy" / lib);
    for (const auto& c : candidates) {
        std::error_code ec;
        if (!fs::exists(c, ec)) continue;
        auto h = yuzu::agent::PluginHandle::load(fs::absolute(c, ec));
        if (h.has_value() && h->descriptor() != nullptr) return std::move(*h);
    }
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) // under meson a missing plugin is a broken build
        FAIL("local_security_policy plugin library not found under meson test");
    WARN("local_security_policy plugin library not found -- skipping (run via `meson test`)");
    return std::nullopt;
}

std::vector<std::string> rows_of(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    for (std::string l; std::getline(ss, l);) {
        if (!l.empty() && l.back() == '\r') l.pop_back();
        if (!l.empty()) out.push_back(l);
    }
    return out;
}

// A backslash-preceded '|' is data (safe_output_field's pipe escape).
std::size_t field_count(const std::string& row) {
    std::size_t n = 1;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') ++i;
        else if (row[i] == '|') ++n;
    }
    return n;
}

bool degraded(YuzuResultStatus s) {
    return s == YUZU_RESULT_STATUS_CONSTRAINED || s == YUZU_RESULT_STATUS_PERMISSION_DENIED;
}

} // namespace

// Fails under: any leg's support/rung changing without this pin (rung 2 = the pwpolicy/secedit argv leaves).
TEST_CASE("local_security_policy: descriptor pins per action and OS", "[local_security_policy][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    const auto* d = plugin->descriptor();
    REQUIRE(d->action_descriptor_count == 4);
    struct Want { const char* action; int lin, mac, win; };
    const Want want[] = {{"password_policy", 1, 2, 2}, {"lockout_policy", 1, 2, 2},
                         {"audit_policy", 1, 1, 2}, {"sudoers", 1, 1, 0}};
    for (std::size_t i = 0; i < 4; ++i) {
        CHECK(std::string{d->action_descriptors[i].action} == want[i].action);
        CHECK(d->action_descriptors[i].linux_leg.rung == want[i].lin);
        CHECK(d->action_descriptors[i].macos_leg.rung == want[i].mac);
        CHECK(d->action_descriptors[i].windows_leg.rung == want[i].win);
    }
    CHECK(d->action_descriptors[3].windows_leg.support == YUZU_SUPPORT_UNSUPPORTED);
}

TEST_CASE("local_security_policy: unknown action is rejected with an escaped diagnostic", "[local_security_policy][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(plugin->descriptor(), "bogus|action");
    CHECK(r.rc == 1);
    CHECK(r.captured == "unknown action: bogus\\|action");
}

TEST_CASE("local_security_policy: policy actions emit 4-field rows and explain any degradation", "[local_security_policy][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* action : {"password_policy", "lockout_policy", "audit_policy"}) {
        INFO(action);
        const auto r = dispatcher.run(plugin->descriptor(), action);
        const auto rows = rows_of(r.captured);
#if defined(_WIN32)
        // The Windows leg needs agent.data_dir (unset under LocalDispatcher): one constrained row.
        if (rows.size() == 1 && rows[0].rfind("constrained|", 0) == 0) {
            CHECK(degraded(r.result_status));
            continue;
        }
#endif
        CHECK(r.rc == 0);
        REQUIRE_FALSE(rows.empty()); // every host yields a data, source_state or policies row
        for (const auto& row : rows) {
            CHECK(row.rfind(std::string{action} + "|", 0) == 0);
            CHECK(field_count(row) == 4);
        }
        if (degraded(r.result_status)) CHECK_FALSE(r.result_provenance.empty());
    }
}

TEST_CASE("local_security_policy: sudoers emits 7-field rows; a refusal is an unreadable row", "[local_security_policy][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto r = dispatcher.run(plugin->descriptor(), "sudoers");
    const auto rows = rows_of(r.captured);
    REQUIRE_FALSE(rows.empty());
    bool any_unreadable = false;
    for (const auto& row : rows) {
        CHECK(row.rfind("sudoers|", 0) == 0);
        CHECK(field_count(row) == 7);
        any_unreadable = any_unreadable || row.find("|unreadable|") != std::string::npos;
    }
#if defined(_WIN32)
    CHECK(r.rc == 1);
    CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(rows[0] == "sudoers|-|unsupported|-|-|-|windows_has_no_sudoers");
#else
    CHECK(r.rc == 0);
    // Failure never reads as absent: a denied/failed status must be visible in a row.
    if (degraded(r.result_status)) CHECK(any_unreadable);
    if (r.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED) CHECK(r.result_provenance.find("permission_denied") != std::string::npos);
#endif
}
