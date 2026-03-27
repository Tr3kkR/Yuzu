/**
 * test_software_deployment_store.cpp — Unit tests for SoftwareDeploymentStore
 *
 * Covers: packages CRUD, deployment lifecycle, agent status,
 * refresh_counts, active_count, and full end-to-end lifecycle.
 */

#include "software_deployment_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <string>

using namespace yuzu::server;

namespace {

struct TempDb {
    std::filesystem::path path;
    TempDb() : path(std::filesystem::temp_directory_path() / "test_software_deployment.db") {
        std::filesystem::remove(path);
    }
    ~TempDb() { std::filesystem::remove(path); }
};

SoftwarePackage make_package(const std::string& name = "Firefox",
                              const std::string& version = "125.0",
                              const std::string& platform = "windows") {
    SoftwarePackage pkg;
    pkg.name = name;
    pkg.version = version;
    pkg.platform = platform;
    pkg.installer_type = "msi";
    pkg.content_hash = "abc123def456";
    pkg.content_url = "https://content.example.com/firefox-125.msi";
    pkg.silent_args = "/qn /norestart";
    pkg.verify_command = "reg query HKLM\\Software\\Mozilla";
    pkg.rollback_command = "msiexec /x {id} /qn";
    pkg.size_bytes = 85000000;
    pkg.created_by = "admin";
    return pkg;
}

SoftwareDeployment make_deployment(const std::string& package_id,
                                    const std::string& scope = "ostype = 'windows'",
                                    int agents_targeted = 5) {
    SoftwareDeployment dep;
    dep.package_id = package_id;
    dep.scope_expression = scope;
    dep.agents_targeted = agents_targeted;
    dep.created_by = "admin";
    return dep;
}

} // namespace

// ============================================================================
// Package CRUD
// ============================================================================

TEST_CASE("SoftwareDeploymentStore: create package and get", "[software_deployment][package]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto result = store.create_package(make_package());
    REQUIRE(result.has_value());
    CHECK(!result->empty());

    auto pkg = store.get_package(*result);
    REQUIRE(pkg.has_value());
    CHECK(pkg->id == *result);
    CHECK(pkg->name == "Firefox");
    CHECK(pkg->version == "125.0");
    CHECK(pkg->platform == "windows");
    CHECK(pkg->installer_type == "msi");
    CHECK(pkg->content_hash == "abc123def456");
    CHECK(pkg->silent_args == "/qn /norestart");
    CHECK(pkg->size_bytes == 85000000);
    CHECK(pkg->created_at > 0);
    CHECK(pkg->created_by == "admin");
}

TEST_CASE("SoftwareDeploymentStore: list packages", "[software_deployment][package]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    store.create_package(make_package("Firefox", "125.0"));
    store.create_package(make_package("Chrome", "124.0"));
    store.create_package(make_package("VSCode", "1.89"));

    auto pkgs = store.list_packages();
    CHECK(pkgs.size() == 3);
}

TEST_CASE("SoftwareDeploymentStore: delete package", "[software_deployment][package]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto id = store.create_package(make_package());
    REQUIRE(id.has_value());

    bool deleted = store.delete_package(*id);
    CHECK(deleted);

    auto pkg = store.get_package(*id);
    CHECK(!pkg.has_value());

    auto list = store.list_packages();
    CHECK(list.empty());
}

TEST_CASE("SoftwareDeploymentStore: delete nonexistent package returns false",
          "[software_deployment][package]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    CHECK(!store.delete_package("nonexistent-id"));
}

TEST_CASE("SoftwareDeploymentStore: create package empty name fails",
          "[software_deployment][package]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg = make_package();
    pkg.name = "";
    auto result = store.create_package(pkg);
    CHECK(!result.has_value());
}

// ============================================================================
// Deployment Lifecycle
// ============================================================================

TEST_CASE("SoftwareDeploymentStore: create deployment has staged status",
          "[software_deployment][deployment]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    CHECK(dep->status == "staged");
    CHECK(dep->package_id == *pkg_id);
    CHECK(dep->agents_targeted == 5);
    CHECK(dep->created_at > 0);
    CHECK(dep->started_at == 0);
}

TEST_CASE("SoftwareDeploymentStore: start deployment staged to deploying",
          "[software_deployment][deployment]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    bool started = store.start_deployment(*dep_id);
    CHECK(started);

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    CHECK(dep->status == "deploying");
    CHECK(dep->started_at > 0);
}

TEST_CASE("SoftwareDeploymentStore: start non-staged deployment fails",
          "[software_deployment][deployment]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    // Start it first (staged -> deploying)
    bool started = store.start_deployment(*dep_id);
    REQUIRE(started);

    // Try to start again (deploying is not staged) — should fail
    bool started_again = store.start_deployment(*dep_id);
    CHECK(!started_again);
}

TEST_CASE("SoftwareDeploymentStore: cancel from staged", "[software_deployment][deployment]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    bool cancelled = store.cancel_deployment(*dep_id);
    CHECK(cancelled);

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    CHECK(dep->status == "cancelled");
    CHECK(dep->completed_at > 0);
}

TEST_CASE("SoftwareDeploymentStore: cancel from deploying", "[software_deployment][deployment]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    store.start_deployment(*dep_id); // staged -> deploying

    bool cancelled = store.cancel_deployment(*dep_id);
    CHECK(cancelled);

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    CHECK(dep->status == "cancelled");
}

TEST_CASE("SoftwareDeploymentStore: cancel from completed fails",
          "[software_deployment][deployment]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    // Cancel once (from staged)
    store.cancel_deployment(*dep_id);

    // Try to cancel again (already cancelled — not in staged/deploying)
    bool cancelled_again = store.cancel_deployment(*dep_id);
    CHECK(!cancelled_again);
}

TEST_CASE("SoftwareDeploymentStore: rollback deployment", "[software_deployment][deployment]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    store.start_deployment(*dep_id); // staged -> deploying

    bool rolled_back = store.rollback_deployment(*dep_id);
    CHECK(rolled_back);

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    CHECK(dep->status == "rolled_back");
    CHECK(dep->completed_at > 0);
}

TEST_CASE("SoftwareDeploymentStore: rollback staged fails",
          "[software_deployment][deployment]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    // Cannot rollback from staged (only deploying/verifying/completed)
    bool rolled_back = store.rollback_deployment(*dep_id);
    CHECK(!rolled_back);
}

// ============================================================================
// Agent Status & Refresh Counts
// ============================================================================

TEST_CASE("SoftwareDeploymentStore: update agent status", "[software_deployment][agent]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep_id = store.create_deployment(make_deployment(*pkg_id, "all", 3));
    REQUIRE(dep_id.has_value());

    AgentDeploymentStatus s1;
    s1.agent_id = "agent-1";
    s1.status = "success";
    s1.started_at = 1000;
    s1.completed_at = 1010;

    store.update_agent_status(*dep_id, s1);

    auto statuses = store.get_agent_statuses(*dep_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].agent_id == "agent-1");
    CHECK(statuses[0].status == "success");
    CHECK(statuses[0].started_at == 1000);
    CHECK(statuses[0].completed_at == 1010);
}

TEST_CASE("SoftwareDeploymentStore: refresh counts", "[software_deployment][agent]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep_id = store.create_deployment(make_deployment(*pkg_id, "all", 3));
    REQUIRE(dep_id.has_value());

    // Add agent statuses: 2 success, 1 failed
    AgentDeploymentStatus s1;
    s1.agent_id = "agent-1";
    s1.status = "success";
    store.update_agent_status(*dep_id, s1);

    AgentDeploymentStatus s2;
    s2.agent_id = "agent-2";
    s2.status = "success";
    store.update_agent_status(*dep_id, s2);

    AgentDeploymentStatus s3;
    s3.agent_id = "agent-3";
    s3.status = "failed";
    s3.error = "download timeout";
    store.update_agent_status(*dep_id, s3);

    store.refresh_counts(*dep_id);

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    CHECK(dep->agents_success == 2);
    CHECK(dep->agents_failure == 1);
}

TEST_CASE("SoftwareDeploymentStore: get agent statuses returns all agents",
          "[software_deployment][agent]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep_id = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep_id.has_value());

    for (int i = 1; i <= 5; ++i) {
        AgentDeploymentStatus s;
        s.agent_id = "agent-" + std::to_string(i);
        s.status = (i <= 3) ? "success" : "failed";
        store.update_agent_status(*dep_id, s);
    }

    auto statuses = store.get_agent_statuses(*dep_id);
    CHECK(statuses.size() == 5);
}

// ============================================================================
// Active count
// ============================================================================

TEST_CASE("SoftwareDeploymentStore: active count", "[software_deployment][deployment]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    // Staged deployment (not active)
    auto dep1 = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep1.has_value());

    CHECK(store.active_count() == 0);

    // Start deployment (now deploying = active)
    store.start_deployment(*dep1);
    CHECK(store.active_count() == 1);

    // Create and start another
    auto dep2 = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep2.has_value());
    store.start_deployment(*dep2);
    CHECK(store.active_count() == 2);

    // Cancel one — no longer active
    store.cancel_deployment(*dep1);
    CHECK(store.active_count() == 1);
}

// ============================================================================
// List deployments
// ============================================================================

TEST_CASE("SoftwareDeploymentStore: list deployments with status filter",
          "[software_deployment][deployment]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    auto pkg_id = store.create_package(make_package());
    REQUIRE(pkg_id.has_value());

    auto dep1 = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep1.has_value());

    auto dep2 = store.create_deployment(make_deployment(*pkg_id));
    REQUIRE(dep2.has_value());
    store.start_deployment(*dep2);

    // All deployments
    auto all = store.list_deployments();
    CHECK(all.size() == 2);

    // Filter by status
    auto staged = store.list_deployments("staged");
    CHECK(staged.size() == 1);

    auto deploying = store.list_deployments("deploying");
    CHECK(deploying.size() == 1);
}

// ============================================================================
// Full lifecycle
// ============================================================================

TEST_CASE("SoftwareDeploymentStore: full lifecycle",
          "[software_deployment][lifecycle]") {
    TempDb tmp;
    SoftwareDeploymentStore store(tmp.path);
    REQUIRE(store.is_open());

    // Step 1: Create package
    auto pkg_id = store.create_package(make_package("Firefox", "125.0", "windows"));
    REQUIRE(pkg_id.has_value());

    auto pkg = store.get_package(*pkg_id);
    REQUIRE(pkg.has_value());
    CHECK(pkg->name == "Firefox");

    // Step 2: Create deployment (staged)
    auto dep_id = store.create_deployment(make_deployment(*pkg_id, "ostype = 'windows'", 3));
    REQUIRE(dep_id.has_value());

    auto dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    CHECK(dep->status == "staged");

    // Step 3: Start deployment (staged -> deploying)
    bool started = store.start_deployment(*dep_id);
    CHECK(started);
    CHECK(store.active_count() == 1);

    dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    CHECK(dep->status == "deploying");
    CHECK(dep->started_at > 0);

    // Step 4: Agents report statuses
    AgentDeploymentStatus s1;
    s1.agent_id = "agent-1";
    s1.status = "success";
    s1.started_at = 100;
    s1.completed_at = 110;
    store.update_agent_status(*dep_id, s1);

    AgentDeploymentStatus s2;
    s2.agent_id = "agent-2";
    s2.status = "success";
    s2.started_at = 100;
    s2.completed_at = 115;
    store.update_agent_status(*dep_id, s2);

    AgentDeploymentStatus s3;
    s3.agent_id = "agent-3";
    s3.status = "failed";
    s3.error = "installer exit code 1603";
    s3.started_at = 100;
    s3.completed_at = 112;
    store.update_agent_status(*dep_id, s3);

    // Step 5: Refresh counts
    store.refresh_counts(*dep_id);

    dep = store.get_deployment(*dep_id);
    REQUIRE(dep.has_value());
    CHECK(dep->agents_success == 2);
    CHECK(dep->agents_failure == 1);

    // Step 6: Verify agent statuses
    auto statuses = store.get_agent_statuses(*dep_id);
    CHECK(statuses.size() == 3);

    // Verify error detail is preserved
    bool found_failed = false;
    for (const auto& a : statuses) {
        if (a.agent_id == "agent-3") {
            CHECK(a.status == "failed");
            CHECK(a.error == "installer exit code 1603");
            found_failed = true;
        }
    }
    CHECK(found_failed);
}
