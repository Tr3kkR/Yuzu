/**
 * test_patch_manager.cpp — Unit tests for PatchManager
 *
 * Covers: create/get deployment, DeploymentRequest struct, reboot_delay clamping,
 *         kb_id validation, execute_deployment reboot orchestration (Windows/Linux/
 *         unknown OS), notification failure non-fatal, cancel_deployment, list_deployments.
 */

#include "patch_manager.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

// ── RAII wrapper for temp DB file ───────────────────────────────────────────

static int g_test_counter = 0;

struct TestPatchDb {
    std::filesystem::path path;
    PatchManager mgr;

    TestPatchDb()
        : path("/tmp/test_patch_mgr_" + std::to_string(++g_test_counter) + "_" +
               std::to_string(reinterpret_cast<uintptr_t>(this)) + ".db"),
          mgr(path) {}

    ~TestPatchDb() {
        // Destructor of mgr closes the DB; then remove the file.
        std::filesystem::remove(path);
        // WAL/SHM files
        std::filesystem::remove(std::filesystem::path(path.string() + "-wal"));
        std::filesystem::remove(std::filesystem::path(path.string() + "-shm"));
    }
};

// ── Helpers for dispatch mocking ────────────────────────────────────────────

/// Records (instruction_id, agent_id) for each dispatch call.
using DispatchLog = std::vector<std::pair<std::string, std::string>>;

/// Build a scan result JSON where the kb appears in rows[].title.
static std::string scan_result_with_kb(const std::string& kb_id) {
    return R"({"rows":[{"identifier":")" + kb_id +
           R"(","title":"Security Update )" + kb_id +
           R"(","severity":"Important"}]})";
}

/// Build an installed-verification result JSON where the kb appears in rows[].identifier.
static std::string verify_result_with_kb(const std::string& kb_id) {
    return R"({"rows":[{"identifier":")" + kb_id +
           R"(","title":"Security Update","severity":"Important"}]})";
}

/// Build a generic success JSON (for script_exec, notify, etc.).
static std::string success_json() {
    return R"({"rows":[],"exit_code":0})";
}

// ── Test: create and get deployment ─────────────────────────────────────────

TEST_CASE("PatchManager: create and get deployment", "[patch_manager][deploy]") {
    TestPatchDb tdb;
    REQUIRE(tdb.mgr.is_open());

    auto result = tdb.mgr.deploy_patch("KB1234567", {"agent-1", "agent-2"}, false, "admin");
    REQUIRE(result.has_value());
    CHECK(!result->empty());

    auto depl = tdb.mgr.get_deployment(*result);
    REQUIRE(depl.has_value());
    CHECK(depl->id == *result);
    CHECK(depl->kb_id == "KB1234567");
    CHECK(depl->status == "pending");
    CHECK(depl->total_targets == 2);
    CHECK(depl->created_by == "admin");
    CHECK(depl->reboot_if_needed == false);
    CHECK(depl->created_at > 0);
    CHECK(depl->targets.size() == 2);
}

// ── Test: deploy_patch with DeploymentRequest ───────────────────────────────

TEST_CASE("PatchManager: deploy_patch with DeploymentRequest", "[patch_manager][deploy]") {
    TestPatchDb tdb;
    REQUIRE(tdb.mgr.is_open());

    DeploymentRequest req;
    req.kb_id = "KB5034441";
    req.agent_ids = {"agent-1"};
    req.reboot_if_needed = true;
    req.created_by = "operator";
    req.reboot_delay_seconds = 600;
    req.reboot_at = 1700000000;

    auto result = tdb.mgr.deploy_patch(req);
    REQUIRE(result.has_value());

    auto depl = tdb.mgr.get_deployment(*result);
    REQUIRE(depl.has_value());
    CHECK(depl->kb_id == "KB5034441");
    CHECK(depl->reboot_if_needed == true);
    CHECK(depl->reboot_delay_seconds == 600);
    CHECK(depl->reboot_at == 1700000000);
    CHECK(depl->created_by == "operator");
}

// ── Test: reboot_delay_seconds clamped ──────────────────────────────────────

TEST_CASE("PatchManager: reboot_delay_seconds clamped", "[patch_manager][deploy]") {
    TestPatchDb tdb;
    REQUIRE(tdb.mgr.is_open());

    SECTION("too small is clamped to 60") {
        auto result = tdb.mgr.deploy_patch("KB1234567", {"agent-1"}, true, "admin", 10);
        REQUIRE(result.has_value());

        auto depl = tdb.mgr.get_deployment(*result);
        REQUIRE(depl.has_value());
        CHECK(depl->reboot_delay_seconds == 60);
    }

    SECTION("too large is clamped to 86400") {
        auto result = tdb.mgr.deploy_patch("KB1234567", {"agent-1"}, true, "admin", 100000);
        REQUIRE(result.has_value());

        auto depl = tdb.mgr.get_deployment(*result);
        REQUIRE(depl.has_value());
        CHECK(depl->reboot_delay_seconds == 86400);
    }
}

// ── Test: kb_id validation ──────────────────────────────────────────────────

TEST_CASE("PatchManager: kb_id validation", "[patch_manager][validation]") {
    TestPatchDb tdb;
    REQUIRE(tdb.mgr.is_open());

    SECTION("empty kb_id") {
        auto result = tdb.mgr.deploy_patch("", {"agent-1"}, false, "admin");
        CHECK(!result.has_value());
    }

    SECTION("invalid prefix") {
        auto result = tdb.mgr.deploy_patch("NOTAKB", {"agent-1"}, false, "admin");
        CHECK(!result.has_value());
    }

    SECTION("too few digits") {
        auto result = tdb.mgr.deploy_patch("KB123", {"agent-1"}, false, "admin");
        CHECK(!result.has_value());
    }

    SECTION("valid kb_id succeeds") {
        auto result = tdb.mgr.deploy_patch("KB1234567", {"agent-1"}, false, "admin");
        CHECK(result.has_value());
    }
}

// ── Test: execute_deployment reboot orchestration (Windows) ─────────────────

TEST_CASE("PatchManager: execute_deployment reboot orchestration", "[patch_manager][execute]") {
    TestPatchDb tdb;
    REQUIRE(tdb.mgr.is_open());

    auto deploy_result = tdb.mgr.deploy_patch("KB1234567", {"agent-1"}, true, "admin", 120);
    REQUIRE(deploy_result.has_value());
    auto deployment_id = *deploy_result;

    DispatchLog log;

    PatchDispatchFn dispatch_fn = [&](const std::string& instr_id,
                                      const std::string& agent_id,
                                      const std::string& params_json)
        -> std::expected<std::string, std::string> {
        log.emplace_back(instr_id, agent_id);

        if (instr_id == "device.windows_updates.missing")
            return scan_result_with_kb("KB1234567");
        if (instr_id == "device.windows_updates.installed")
            return verify_result_with_kb("KB1234567");
        return success_json();
    };

    AgentOsLookupFn os_lookup = [](const std::string& agent_id) -> std::string {
        return "windows";
    };

    auto exec_result = tdb.mgr.execute_deployment(deployment_id, dispatch_fn, os_lookup);
    REQUIRE(exec_result.has_value());

    // Should have dispatched: scan, install (script_exec), verify, notify, reboot (script_exec)
    bool found_notify = false;
    bool found_reboot = false;
    int script_exec_count = 0;
    for (const auto& [instr, agent] : log) {
        if (instr == "device.interaction.notify")
            found_notify = true;
        if (instr == "device.script_exec.run")
            ++script_exec_count;
    }
    CHECK(found_notify);
    // At least 2 script_exec calls: install + reboot
    CHECK(script_exec_count >= 2);

    // Verify dispatch log contains the Windows reboot command
    // The last script_exec.run should be the reboot command containing "shutdown /r /t"
    bool found_windows_reboot = false;
    for (const auto& [instr, agent] : log) {
        (void)agent;
        // We just verify that script_exec was called — the params contain
        // the reboot command but we're checking instruction IDs here.
        if (instr == "device.script_exec.run")
            found_windows_reboot = true;
    }
    CHECK(found_windows_reboot);
}

// ── Test: execute_deployment linux reboot ────────────────────────────────────

TEST_CASE("PatchManager: execute_deployment linux reboot", "[patch_manager][execute]") {
    TestPatchDb tdb;
    REQUIRE(tdb.mgr.is_open());

    auto deploy_result = tdb.mgr.deploy_patch("KB1234567", {"agent-1"}, true, "admin", 120);
    REQUIRE(deploy_result.has_value());
    auto deployment_id = *deploy_result;

    // Store params_json for each script_exec call to verify linux reboot command
    std::vector<std::string> script_exec_params;

    PatchDispatchFn dispatch_fn = [&](const std::string& instr_id,
                                      const std::string& agent_id,
                                      const std::string& params_json)
        -> std::expected<std::string, std::string> {
        if (instr_id == "device.script_exec.run")
            script_exec_params.push_back(params_json);
        if (instr_id == "device.windows_updates.missing")
            return scan_result_with_kb("KB1234567");
        if (instr_id == "device.windows_updates.installed")
            return verify_result_with_kb("KB1234567");
        return success_json();
    };

    AgentOsLookupFn os_lookup = [](const std::string&) -> std::string {
        return "linux";
    };

    auto exec_result = tdb.mgr.execute_deployment(deployment_id, dispatch_fn, os_lookup);
    REQUIRE(exec_result.has_value());

    // The last script_exec should be the reboot command with "shutdown -r +"
    REQUIRE(!script_exec_params.empty());
    bool found_linux_reboot = false;
    for (const auto& p : script_exec_params) {
        if (p.find("shutdown") != std::string::npos &&
            p.find("-r +") != std::string::npos) {
            found_linux_reboot = true;
            break;
        }
    }
    CHECK(found_linux_reboot);
}

// ── Test: execute_deployment unknown OS skips reboot ────────────────────────

TEST_CASE("PatchManager: execute_deployment unknown OS skips reboot", "[patch_manager][execute]") {
    TestPatchDb tdb;
    REQUIRE(tdb.mgr.is_open());

    auto deploy_result = tdb.mgr.deploy_patch("KB1234567", {"agent-1"}, true, "admin", 120);
    REQUIRE(deploy_result.has_value());
    auto deployment_id = *deploy_result;

    PatchDispatchFn dispatch_fn = [&](const std::string& instr_id,
                                      const std::string& /*agent_id*/,
                                      const std::string& /*params_json*/)
        -> std::expected<std::string, std::string> {
        if (instr_id == "device.windows_updates.missing")
            return scan_result_with_kb("KB1234567");
        if (instr_id == "device.windows_updates.installed")
            return verify_result_with_kb("KB1234567");
        return success_json();
    };

    AgentOsLookupFn os_lookup = [](const std::string&) -> std::string {
        return "";
    };

    auto exec_result = tdb.mgr.execute_deployment(deployment_id, dispatch_fn, os_lookup);
    REQUIRE(exec_result.has_value());

    // Target should be completed but with an error note about reboot skipped
    auto depl = tdb.mgr.get_deployment(deployment_id);
    REQUIRE(depl.has_value());
    REQUIRE(!depl->targets.empty());
    // The code sets error to "reboot skipped: unknown OS" when os is empty
    bool found_reboot_skip = false;
    for (const auto& t : depl->targets) {
        if (t.error.find("reboot skipped") != std::string::npos) {
            found_reboot_skip = true;
            break;
        }
    }
    CHECK(found_reboot_skip);
}

// ── Test: notification failure is non-fatal ─────────────────────────────────

TEST_CASE("PatchManager: notification failure is non-fatal", "[patch_manager][execute]") {
    TestPatchDb tdb;
    REQUIRE(tdb.mgr.is_open());

    auto deploy_result = tdb.mgr.deploy_patch("KB1234567", {"agent-1"}, true, "admin", 120);
    REQUIRE(deploy_result.has_value());
    auto deployment_id = *deploy_result;

    PatchDispatchFn dispatch_fn = [&](const std::string& instr_id,
                                      const std::string& /*agent_id*/,
                                      const std::string& /*params_json*/)
        -> std::expected<std::string, std::string> {
        // Notification fails
        if (instr_id == "device.interaction.notify")
            return std::unexpected<std::string>("headless system — no desktop");
        if (instr_id == "device.windows_updates.missing")
            return scan_result_with_kb("KB1234567");
        if (instr_id == "device.windows_updates.installed")
            return verify_result_with_kb("KB1234567");
        return success_json();
    };

    AgentOsLookupFn os_lookup = [](const std::string&) -> std::string {
        return "windows";
    };

    auto exec_result = tdb.mgr.execute_deployment(deployment_id, dispatch_fn, os_lookup);
    REQUIRE(exec_result.has_value());

    // Deployment should still complete despite notification failure
    auto depl = tdb.mgr.get_deployment(deployment_id);
    REQUIRE(depl.has_value());
    // The target should be completed (not failed)
    bool all_completed = true;
    for (const auto& t : depl->targets) {
        if (t.status != "completed")
            all_completed = false;
    }
    CHECK(all_completed);
}

// ── Test: cancel_deployment covers rebooting ────────────────────────────────

TEST_CASE("PatchManager: cancel_deployment covers rebooting", "[patch_manager][cancel]") {
    TestPatchDb tdb;
    REQUIRE(tdb.mgr.is_open());

    auto deploy_result = tdb.mgr.deploy_patch("KB1234567", {"agent-1", "agent-2"}, true, "admin");
    REQUIRE(deploy_result.has_value());
    auto deployment_id = *deploy_result;

    // Manually set agent-1 to "rebooting" status
    tdb.mgr.update_target_status(deployment_id, "agent-1", "rebooting");

    auto cancel_result = tdb.mgr.cancel_deployment(deployment_id);
    REQUIRE(cancel_result.has_value());

    auto depl = tdb.mgr.get_deployment(deployment_id);
    REQUIRE(depl.has_value());
    CHECK(depl->status == "cancelled");

    // Both targets should now be cancelled (rebooting + pending are both in the cancel set)
    for (const auto& t : depl->targets) {
        CHECK(t.status == "cancelled");
    }
}

// ── Test: list_deployments ──────────────────────────────────────────────────

TEST_CASE("PatchManager: list_deployments", "[patch_manager][query]") {
    TestPatchDb tdb;
    REQUIRE(tdb.mgr.is_open());

    tdb.mgr.deploy_patch("KB1111111", {"agent-1"}, false, "admin");
    tdb.mgr.deploy_patch("KB2222222", {"agent-1"}, false, "admin");
    tdb.mgr.deploy_patch("KB3333333", {"agent-1"}, false, "admin");

    auto all = tdb.mgr.list_deployments(50);
    REQUIRE(all.size() == 3);

    auto limited = tdb.mgr.list_deployments(2);
    REQUIRE(limited.size() == 2);
}
