/**
 * test_agent_health_store.cpp — Unit tests for AgentHealthStore fleet health aggregation
 *
 * The real AgentHealthStore lives inside server.cpp (detail namespace) and uses
 * google::protobuf::Map in its interface, so we test a standalone reproduction
 * that exercises the same MetricsRegistry output contract.
 */

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

// ── Standalone reproduction of AgentHealthStore ─────────────────────────────

class TestAgentHealthStore {
public:
    void upsert(const std::string& agent_id,
                const std::unordered_map<std::string, std::string>& tags) {
        std::lock_guard lock(mu_);
        auto& snap = snapshots_[agent_id];
        snap.agent_id = agent_id;
        snap.status_tags = tags;
        snap.last_seen = std::chrono::steady_clock::now();
    }

    void remove(const std::string& agent_id) {
        std::lock_guard lock(mu_);
        snapshots_.erase(agent_id);
    }

    void recompute_metrics(yuzu::MetricsRegistry& metrics,
                           std::chrono::seconds staleness) {
        std::lock_guard lock(mu_);
        auto now = std::chrono::steady_clock::now();

        std::erase_if(snapshots_, [&](const auto& pair) {
            return (now - pair.second.last_seen) > staleness;
        });

        metrics.clear_gauge_family("yuzu_fleet_agents_by_os");
        metrics.clear_gauge_family("yuzu_fleet_agents_by_arch");
        metrics.clear_gauge_family("yuzu_fleet_agents_by_version");

        std::unordered_map<std::string, int> os_counts, arch_counts, version_counts;
        double total_commands = 0.0;
        int healthy_count = 0;

        for (const auto& [id, snap] : snapshots_) {
            ++healthy_count;

            auto get = [&](const std::string& key) -> std::string {
                auto it = snap.status_tags.find(key);
                return it != snap.status_tags.end() ? it->second : "";
            };

            auto os_val = get("yuzu.os");
            if (!os_val.empty()) os_counts[os_val]++;

            auto arch_val = get("yuzu.arch");
            if (!arch_val.empty()) arch_counts[arch_val]++;

            auto ver_val = get("yuzu.agent_version");
            if (!ver_val.empty()) version_counts[ver_val]++;

            auto cmd_val = get("yuzu.commands_executed");
            if (!cmd_val.empty()) {
                try { total_commands += std::stod(cmd_val); } catch (...) {}
            }
        }

        metrics.gauge("yuzu_fleet_agents_healthy").set(
            static_cast<double>(healthy_count));

        for (const auto& [os, count] : os_counts)
            metrics.gauge("yuzu_fleet_agents_by_os", {{"os", os}})
                .set(static_cast<double>(count));

        for (const auto& [arch, count] : arch_counts)
            metrics.gauge("yuzu_fleet_agents_by_arch", {{"arch", arch}})
                .set(static_cast<double>(count));

        for (const auto& [ver, count] : version_counts)
            metrics.gauge("yuzu_fleet_agents_by_version", {{"version", ver}})
                .set(static_cast<double>(count));

        metrics.gauge("yuzu_fleet_commands_executed_total").set(total_commands);
    }

private:
    struct Snapshot {
        std::string agent_id;
        std::unordered_map<std::string, std::string> status_tags;
        std::chrono::steady_clock::time_point last_seen;
    };

    std::mutex mu_;
    std::unordered_map<std::string, Snapshot> snapshots_;
};

// ── Tests ───────────────────────────────────────────────────────────────────

TEST_CASE("AgentHealthStore: upsert stores health data", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.os", "linux"}, {"yuzu.arch", "x86_64"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    REQUIRE(metrics.gauge("yuzu_fleet_agents_healthy").value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "linux"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_arch", {{"arch", "x86_64"}}).value() == 1.0);
}

TEST_CASE("AgentHealthStore: multiple agents aggregate correctly", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.os", "linux"}, {"yuzu.arch", "x86_64"}});
    store.upsert("agent-2", {{"yuzu.os", "windows"}, {"yuzu.arch", "x86_64"}});
    store.upsert("agent-3", {{"yuzu.os", "linux"}, {"yuzu.arch", "aarch64"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    REQUIRE(metrics.gauge("yuzu_fleet_agents_healthy").value() == 3.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "linux"}}).value() == 2.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "windows"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_arch", {{"arch", "x86_64"}}).value() == 2.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_arch", {{"arch", "aarch64"}}).value() == 1.0);
}

TEST_CASE("AgentHealthStore: stale entries are pruned", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.os", "linux"}});

    // Sleep long enough to exceed the staleness window
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    store.recompute_metrics(metrics, std::chrono::seconds(0));

    REQUIRE(metrics.gauge("yuzu_fleet_agents_healthy").value() == 0.0);
}

TEST_CASE("AgentHealthStore: remove deletes agent", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.os", "linux"}});
    store.remove("agent-1");
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    REQUIRE(metrics.gauge("yuzu_fleet_agents_healthy").value() == 0.0);
}

TEST_CASE("AgentHealthStore: recompute clears stale label combinations", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.os", "linux"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));
    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "linux"}}).value() == 1.0);

    // Same agent switches OS
    store.upsert("agent-1", {{"yuzu.os", "windows"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "windows"}}).value() == 1.0);

    // The old "linux" label combination must have been cleared
    auto output = metrics.serialize();
    CHECK(output.find("os=\"linux\"") == std::string::npos);
}

TEST_CASE("AgentHealthStore: commands_executed sums across fleet", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.commands_executed", "10"}});
    store.upsert("agent-2", {{"yuzu.commands_executed", "20"}});
    store.upsert("agent-3", {{"yuzu.commands_executed", "30"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    REQUIRE(metrics.gauge("yuzu_fleet_commands_executed_total").value() == 60.0);
}

TEST_CASE("AgentHealthStore: version breakdown", "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("agent-1", {{"yuzu.agent_version", "1.0.0"}});
    store.upsert("agent-2", {{"yuzu.agent_version", "1.0.0"}});
    store.upsert("agent-3", {{"yuzu.agent_version", "1.1.0"}});
    store.upsert("agent-4", {{"yuzu.agent_version", "2.0.0"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    CHECK(metrics.gauge("yuzu_fleet_agents_by_version", {{"version", "1.0.0"}}).value() == 2.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_version", {{"version", "1.1.0"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_agents_by_version", {{"version", "2.0.0"}}).value() == 1.0);
}
