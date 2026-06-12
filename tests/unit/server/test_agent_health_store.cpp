/**
 * test_agent_health_store.cpp — Unit tests for AgentHealthStore fleet health aggregation
 *
 * The real AgentHealthStore lives inside server.cpp (detail namespace) and uses
 * google::protobuf::Map in its interface, so we test a standalone reproduction
 * that exercises the same MetricsRegistry output contract.
 */

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

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

    void recompute_metrics(yuzu::MetricsRegistry& metrics, std::chrono::seconds staleness) {
        std::lock_guard lock(mu_);
        auto now = std::chrono::steady_clock::now();

        std::erase_if(snapshots_,
                      [&](const auto& pair) { return (now - pair.second.last_seen) > staleness; });

        metrics.clear_gauge_family("yuzu_fleet_agents_by_os");
        metrics.clear_gauge_family("yuzu_fleet_agents_by_arch");
        metrics.clear_gauge_family("yuzu_fleet_agents_by_version");
        metrics.clear_gauge_family("yuzu_fleet_perf_cpu_pct");
        metrics.clear_gauge_family("yuzu_fleet_perf_commit_pct");
        metrics.clear_gauge_family("yuzu_fleet_perf_disk_lat_ms");

        std::unordered_map<std::string, int> os_counts, arch_counts, version_counts;
        double total_commands = 0.0;
        int healthy_count = 0;
        int dex_observer_disarmed = 0;
        double total_dex_observed = 0.0;
        std::vector<double> perf_cpu, perf_commit, perf_disk_lat;

        for (const auto& [id, snap] : snapshots_) {
            ++healthy_count;

            auto get = [&](const std::string& key) -> std::string {
                auto it = snap.status_tags.find(key);
                return it != snap.status_tags.end() ? it->second : "";
            };

            auto os_val = get("yuzu.os");
            if (!os_val.empty())
                os_counts[os_val]++;

            auto arch_val = get("yuzu.arch");
            if (!arch_val.empty())
                arch_counts[arch_val]++;

            auto ver_val = get("yuzu.agent_version");
            if (!ver_val.empty())
                version_counts[ver_val]++;

            // Mirrors AgentRegistry::recompute_metrics: std::stod does NOT throw on
            // "inf"/"nan", so guard finite + non-negative or one rogue agent poisons the
            // fleet gauge.
            auto add_finite_count = [](double& acc, const std::string& s) {
                try {
                    double v = std::stod(s);
                    if (std::isfinite(v) && v >= 0.0)
                        acc += v;
                } catch (...) {}
            };

            auto cmd_val = get("yuzu.commands_executed");
            if (!cmd_val.empty())
                add_finite_count(total_commands, cmd_val);

            if (get("yuzu.dex_observer_armed") == "0")
                ++dex_observer_disarmed;

            auto dex_val = get("yuzu.dex_observed");
            if (!dex_val.empty())
                add_finite_count(total_dex_observed, dex_val);

            // A4 perf tags — finite, non-negative, percentages clamped to 100.
            auto collect_finite = [&](std::vector<double>& out, const std::string& key,
                                      double clamp_hi) {
                const auto s = get(key);
                if (s.empty())
                    return;
                try {
                    double v = std::stod(s);
                    if (std::isfinite(v) && v >= 0.0)
                        out.push_back(clamp_hi > 0.0 ? (std::min)(v, clamp_hi) : v);
                } catch (...) {}
            };
            collect_finite(perf_cpu, "yuzu.perf_cpu_pct", 100.0);
            collect_finite(perf_commit, "yuzu.perf_commit_pct", 100.0);
            collect_finite(perf_disk_lat, "yuzu.perf_disk_lat_ms", 0.0);
        }

        metrics.gauge("yuzu_fleet_agents_healthy").set(static_cast<double>(healthy_count));
        metrics.gauge("yuzu_fleet_agents_dex_observer_disarmed")
            .set(static_cast<double>(dex_observer_disarmed));
        metrics.gauge("yuzu_fleet_dex_observed_total").set(total_dex_observed);

        for (const auto& [os, count] : os_counts)
            metrics.gauge("yuzu_fleet_agents_by_os", {{"os", os}}).set(static_cast<double>(count));

        for (const auto& [arch, count] : arch_counts)
            metrics.gauge("yuzu_fleet_agents_by_arch", {{"arch", arch}})
                .set(static_cast<double>(count));

        for (const auto& [ver, count] : version_counts)
            metrics.gauge("yuzu_fleet_agents_by_version", {{"version", ver}})
                .set(static_cast<double>(count));

        metrics.gauge("yuzu_fleet_commands_executed_total").set(total_commands);

        // A4 fleet perf rollup — mirrors AgentHealthStore::recompute_metrics.
        auto set_stats = [&](const char* family, std::vector<double>& vals) {
            if (vals.empty())
                return;
            std::sort(vals.begin(), vals.end());
            const auto n = vals.size();
            double sum = 0.0;
            for (double v : vals)
                sum += v;
            auto rank = [&](double p) {
                return vals[static_cast<std::size_t>(static_cast<double>(n - 1) * p)];
            };
            metrics.gauge(family, {{"stat", "avg"}}).set(sum / static_cast<double>(n));
            metrics.gauge(family, {{"stat", "p50"}}).set(rank(0.50));
            metrics.gauge(family, {{"stat", "p90"}}).set(rank(0.90));
            metrics.gauge(family, {{"stat", "max"}}).set(vals.back());
        };
        metrics.gauge("yuzu_fleet_perf_reporting").set(static_cast<double>(perf_cpu.size()));
        set_stats("yuzu_fleet_perf_cpu_pct", perf_cpu);
        set_stats("yuzu_fleet_perf_commit_pct", perf_commit);
        set_stats("yuzu_fleet_perf_disk_lat_ms", perf_disk_lat);
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

TEST_CASE("AgentHealthStore: DEX signal observer disarmed count + signals summed",
          "[health_store]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // Armed Windows agent — must NOT count as disarmed; contributes its signal count.
    store.upsert("win-armed", {{"yuzu.dex_observer_armed", "1"}, {"yuzu.dex_observed", "3"}});
    // Windows agent that FAILED to arm — the fault we want visible; 0 signals.
    store.upsert("win-deaf", {{"yuzu.dex_observer_armed", "0"}, {"yuzu.dex_observed", "0"}});
    // Non-Windows / --dex-disable agent never emits the tag — must NOT count as disarmed.
    store.upsert("lin-1", {{"yuzu.os", "linux"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    // Exactly one genuine arm FAILURE — absent tag and armed=1 are not counted.
    CHECK(metrics.gauge("yuzu_fleet_agents_dex_observer_disarmed").value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_dex_observed_total").value() == 3.0);
}

TEST_CASE("AgentHealthStore: non-finite/garbage signal count does not poison the fleet gauge",
          "[health_store]") {
    // std::stod("inf"/"nan") returns a non-finite value WITHOUT throwing, so a single
    // rogue/buggy agent could push the fleet-wide gauge to +/-Inf or NaN for every
    // operator. The finite+non-negative guard rejects those; well-formed counts still sum.
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("good", {{"yuzu.dex_observed", "5"}, {"yuzu.commands_executed", "10"}});
    store.upsert("inf", {{"yuzu.dex_observed", "inf"}, {"yuzu.commands_executed", "inf"}});
    store.upsert("nan", {{"yuzu.dex_observed", "nan"}});
    store.upsert("neg", {{"yuzu.dex_observed", "-4"}}); // negative count is nonsense
    store.upsert("junk", {{"yuzu.dex_observed", "garbage"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    // Only the well-formed counts survive; the gauges stay finite.
    const double signals = metrics.gauge("yuzu_fleet_dex_observed_total").value();
    const double cmds = metrics.gauge("yuzu_fleet_commands_executed_total").value();
    CHECK(signals == 5.0);
    CHECK(cmds == 10.0);
    CHECK(std::isfinite(signals));
    CHECK(std::isfinite(cmds));
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

// ── A4 fleet perf rollup ─────────────────────────────────────────────────────

TEST_CASE("AgentHealthStore: perf tags aggregate to avg/p50/p90/max + population",
          "[health_store][perf]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // Ten agents with CPU 10..100 — known percentile answers (nearest-rank,
    // floor((n-1)*p): p50 -> index 4 = 50, p90 -> index 8 = 90).
    for (int i = 1; i <= 10; ++i)
        store.upsert("a" + std::to_string(i),
                     {{"yuzu.perf_cpu_pct", std::to_string(i * 10) + ".0"},
                      {"yuzu.perf_commit_pct", "40.0"},
                      {"yuzu.perf_disk_lat_ms", "2.50"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    CHECK(metrics.gauge("yuzu_fleet_perf_reporting").value() == 10.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "avg"}}).value() == 55.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "p50"}}).value() == 50.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "p90"}}).value() == 90.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "max"}}).value() == 100.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_commit_pct", {{"stat", "avg"}}).value() == 40.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_disk_lat_ms", {{"stat", "max"}}).value() == 2.5);
}

TEST_CASE("AgentHealthStore: perf gauges go absent (not zero) when nobody reports",
          "[health_store][perf]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // First cycle: one reporter populates the family.
    store.upsert("w1", {{"yuzu.perf_cpu_pct", "42.0"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));
    REQUIRE(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "avg"}}).value() == 42.0);

    // Second cycle: the agent stops reporting the tag (e.g. --dex-disable or a
    // non-Windows fleet). The family must be CLEARED — a stale 42% or a
    // fabricated 0% would both be lies; only the population gauge reads 0.
    store.upsert("w1", {{"yuzu.os", "windows"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));
    CHECK(metrics.gauge("yuzu_fleet_perf_reporting").value() == 0.0);
    const auto text = metrics.serialize();
    CHECK(text.find("yuzu_fleet_perf_cpu_pct{") == std::string::npos);
}

TEST_CASE("AgentHealthStore: rogue perf values cannot poison fleet percentiles",
          "[health_store][perf]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("good", {{"yuzu.perf_cpu_pct", "50.0"}, {"yuzu.perf_disk_lat_ms", "3.0"}});
    store.upsert("inf", {{"yuzu.perf_cpu_pct", "inf"}, {"yuzu.perf_disk_lat_ms", "nan"}});
    store.upsert("neg", {{"yuzu.perf_cpu_pct", "-5"}});
    store.upsert("junk", {{"yuzu.perf_cpu_pct", "garbage"}});
    // A >100% CPU claim is a lie, not an outlier — clamped to 100, so it can
    // shift max to the clamp but never to an absurd magnitude.
    store.upsert("liar", {{"yuzu.perf_cpu_pct", "9000"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    CHECK(metrics.gauge("yuzu_fleet_perf_reporting").value() == 2.0); // good + liar
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "max"}}).value() == 100.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "avg"}}).value() == 75.0);
    CHECK(std::isfinite(metrics.gauge("yuzu_fleet_perf_disk_lat_ms", {{"stat", "avg"}}).value()));
    CHECK(metrics.gauge("yuzu_fleet_perf_disk_lat_ms", {{"stat", "avg"}}).value() == 3.0);
}
