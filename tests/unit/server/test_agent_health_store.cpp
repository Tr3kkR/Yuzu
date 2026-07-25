/**
 * test_agent_health_store.cpp — Unit tests for AgentHealthStore fleet health aggregation
 *
 * TWO KINDS OF TEST LIVE HERE, AND THE DIFFERENCE MATTERS.
 *
 * 1. `TestAgentHealthStore` (below) is a standalone REPRODUCTION. The real store's upsert()
 *    takes a `google::protobuf::Map`, so the reproduction exists to exercise the
 *    MetricsRegistry output contract without dragging protobuf into every case. It reuses the
 *    SHIPPED helpers (network_perf_rules.hpp, spark_fleet_tags.hpp) rather than re-deriving
 *    their logic, so helper drift IS caught.
 *
 *    But a reproduction can only ever catch MODEL drift, never a COVERAGE gap: delete the
 *    spark rollup from agent_registry.cpp and every mirror-based case here still passes. A
 *    previous version of this file carried a comment asserting the opposite — that the
 *    four-posture bucketing was covered because the mirror had been taught the four postures.
 *    It was not. Overclaiming coverage in a comment is how this branch shipped bugs through
 *    five review rounds; do not do it again.
 *
 * 2. The `[spark][rollup][real]` case at the bottom drives the REAL
 *    `yuzu::server::detail::AgentHealthStore::recompute_metrics` through a real
 *    `protobuf::Map` upsert. That is the only case in this file that would fail if the
 *    shipped rollup were deleted — and it has been verified to do so.
 *    (governance Gate-8 round 7 consistency S-1.)
 *
 * The real store lives in `server/core/src/agent_registry.hpp` (namespace
 * yuzu::server::detail) — NOT inside server.cpp, as this header used to claim.
 */

#include "agent_registry.hpp"     // the REAL AgentHealthStore (detail namespace)
#include "network_perf_rules.hpp" // SHIPPED net-fact validators (no parallel repro)
#include "spark_fleet_tags.hpp"   // SHIPPED spark helpers (no parallel repro)

#include <yuzu/metrics.hpp>

#include <google/protobuf/map.h>

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
        metrics.clear_gauge_family("yuzu_fleet_net_rtt_ms");
        metrics.clear_gauge_family("yuzu_fleet_net_retrans_pct");
        metrics.clear_gauge_family("yuzu_fleet_net_throughput_bps");
        metrics.clear_gauge_family("yuzu_fleet_net_degraded");
        metrics.clear_gauge_family("yuzu_fleet_net_reporting");
        metrics.clear_gauge_family("yuzu_fleet_net_retrans_reporting");

        std::unordered_map<std::string, int> os_counts, arch_counts, version_counts;
        double total_commands = 0.0;
        int healthy_count = 0;
        int dex_observer_disarmed = 0;
        double total_dex_observed = 0.0;
        std::vector<double> perf_cpu, perf_commit, perf_disk_lat;
        // Per-OS net buckets (mirrors AgentRegistry::recompute_metrics — no blend).
        std::unordered_map<std::string, std::vector<double>> net_rtt_os, net_retrans_os,
            net_tput_os;
        std::unordered_map<std::string, int> net_reporting_os, net_degraded_os,
            net_degraded_reporting_os;
        // Mirrors the production retransmit gauge-eligibility gate (Windows rate is
        // unvalidated — #1465 — so withheld from the gauge; Linux is validated).
        auto retrans_gauge_eligible = [](const std::string& os) { return os == "linux"; };
        // Mirrors the production os-label allowlist (agent-controlled yuzu.os →
        // bounded label, anti cardinality-injection).
        auto normalize_os = [](const std::string& os) -> std::string {
            if (os == "windows" || os == "linux" || os == "darwin")
                return os;
            return os.empty() ? "unknown" : "other";
        };

        for (const auto& [id, snap] : snapshots_) {
            ++healthy_count;

            auto get = [&](const std::string& key) -> std::string {
                auto it = snap.status_tags.find(key);
                return it != snap.status_tags.end() ? it->second : "";
            };

            auto os_val = get("yuzu.os");
            if (!os_val.empty())
                os_counts[normalize_os(os_val)]++;

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

            // A4 perf tags — finite, non-negative; percentages clamp at 100,
            // latency rejects above the sanity ceiling (absurd-but-finite).
            auto collect_finite = [&](std::vector<double>& out, const std::string& key,
                                      double clamp_hi, double reject_above) {
                const auto s = get(key);
                if (s.empty())
                    return;
                try {
                    double v = std::stod(s);
                    if (std::isfinite(v) && v >= 0.0 && v <= reject_above)
                        out.push_back(clamp_hi > 0.0 ? (std::min)(v, clamp_hi) : v);
                } catch (...) {}
            };
            collect_finite(perf_cpu, "yuzu.perf_cpu_pct", 100.0, 1.0e6);
            collect_finite(perf_commit, "yuzu.perf_commit_pct", 100.0, 1.0e6);
            collect_finite(perf_disk_lat, "yuzu.perf_disk_lat_ms", 0.0, 1.0e6);

            // Use the SHIPPED validators (network_perf_rules.hpp) — not a
            // hand-rolled parallel copy — so this repro can't drift from
            // production's forged-value posture (full-token parse, locale
            // hardening, ceilings/clamps). Mirrors agent_registry.cpp incl. the
            // UP-9 gate (degraded counted only for metric-reporting devices).
            namespace rules = yuzu::server::detail;
            const std::string net_os = normalize_os(os_val);
            bool net_any = false;
            if (auto v = rules::parse_net_rtt_ms(get(rules::kNetTagRttP50Ms))) {
                net_rtt_os[net_os].push_back(*v);
                net_any = true;
            }
            if (auto v = rules::parse_net_retrans_pct(get(rules::kNetTagRetransPct))) {
                if (retrans_gauge_eligible(net_os))
                    net_retrans_os[net_os].push_back(*v);
                net_any = true;
            }
            if (auto v = rules::parse_net_throughput_bps(get(rules::kNetTagThroughputBps))) {
                net_tput_os[net_os].push_back(*v);
                net_any = true;
            }
            if (net_any) {
                ++net_reporting_os[net_os];
                if (auto d = rules::parse_net_degraded(get(rules::kNetTagDegraded))) {
                    ++net_degraded_reporting_os[net_os];
                    if (*d)
                        ++net_degraded_os[net_os];
                }
            }
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
                const auto idx =
                    static_cast<std::size_t>(std::ceil(p * static_cast<double>(n)));
                return vals[(std::min)(idx == 0 ? 0 : idx - 1, n - 1)];
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

        auto set_stats_os = [&](const char* family, const std::string& os,
                                std::vector<double>& vals) {
            if (vals.empty())
                return;
            std::sort(vals.begin(), vals.end());
            const auto n = vals.size();
            double sum = 0.0;
            for (double v : vals)
                sum += v;
            auto rank = [&](double p) {
                const auto idx = static_cast<std::size_t>(std::ceil(p * static_cast<double>(n)));
                return vals[(std::min)(idx == 0 ? 0 : idx - 1, n - 1)];
            };
            metrics.gauge(family, {{"stat", "avg"}, {"os", os}}).set(sum / static_cast<double>(n));
            metrics.gauge(family, {{"stat", "p50"}, {"os", os}}).set(rank(0.50));
            metrics.gauge(family, {{"stat", "p90"}, {"os", os}}).set(rank(0.90));
            metrics.gauge(family, {{"stat", "max"}, {"os", os}}).set(vals.back());
        };
        for (auto& [os, n] : net_reporting_os)
            metrics.gauge("yuzu_fleet_net_reporting", {{"os", os}}).set(static_cast<double>(n));
        for (auto& [os, vals] : net_retrans_os)
            metrics.gauge("yuzu_fleet_net_retrans_reporting", {{"os", os}})
                .set(static_cast<double>(vals.size()));
        for (auto& [os, n] : net_degraded_reporting_os)
            if (n > 0)
                metrics.gauge("yuzu_fleet_net_degraded", {{"os", os}})
                    .set(static_cast<double>(net_degraded_os[os]));
        for (auto& [os, vals] : net_rtt_os)
            set_stats_os("yuzu_fleet_net_rtt_ms", os, vals);
        for (auto& [os, vals] : net_retrans_os)
            set_stats_os("yuzu_fleet_net_retrans_pct", os, vals);
        for (auto& [os, vals] : net_tput_os)
            set_stats_os("yuzu_fleet_net_throughput_bps", os, vals);
    }

    // Spark rollup MIRROR (gov qe-S1) — the same bucketing + gauge glue as
    // AgentRegistry::recompute_metrics, reusing the SHIPPED spark_fleet_tags.hpp
    // helpers (no parallel repro of the parse logic, per the net precedent above).
    //
    // It mirrors the FOUR-POSTURE split (running / disabled / failed / absent), so MODEL
    // drift between the mirror and the shipped helpers is caught.
    //
    // WHAT IT CANNOT CATCH: a coverage gap. This is a reproduction — deleting the spark
    // rollup from agent_registry.cpp leaves every case that uses it green. The
    // "[spark][rollup][real]" case at the bottom of this file is the one that pins the
    // SHIPPED code. See the file header. (governance Gate-8 round 7 consistency S-1.)
    void recompute_spark(yuzu::MetricsRegistry& metrics) {
        namespace sd = yuzu::server::detail;
        std::lock_guard lock(mu_);
        for (const char* f : {"yuzu_fleet_spark_reporting", "yuzu_fleet_spark_disabled",
                              "yuzu_fleet_spark_failed", "yuzu_fleet_spark_mechanisms",
                              "yuzu_fleet_spark_watch_rejected"})
            metrics.clear_gauge_family(f);
        auto norm_os = [](const std::string& os) -> std::string {
            if (os == "windows" || os == "linux" || os == "darwin")
                return os;
            return os.empty() ? "unknown" : "other";
        };
        std::unordered_map<std::string, int> reporting;
        std::unordered_map<std::string, std::unordered_map<std::string, int>> mechs;
        std::unordered_map<std::string, std::unordered_map<std::string, double>> rejected;
        std::unordered_map<std::string, int> disabled;
        std::unordered_map<std::string, int> failed;
        for (auto& [id, snap] : snapshots_) {
            auto get = [&](const std::string& k) -> std::string {
                auto it = snap.status_tags.find(k);
                return it != snap.status_tags.end() ? it->second : "";
            };
            const std::string os = norm_os(get("yuzu.os"));
            // STRICT: only "1"/"0" mean anything. Garbage is NotReported and contributes
            // to nothing — it must NOT fall into `failed`, the gauge operators alert on.
            const sd::SparkRunState state = sd::parse_spark_running(get(sd::kSparkTagRunning));
            if (state == sd::SparkRunState::NotRunning) {
                // The DISABLED vs FAILED split — a deliberate opt-out must never be
                // confused with an engine that threw at boot. STRICT (Gate-4 UP-3): a
                // non-conforming discriminator is Unknown → neither bucket, mirroring the
                // shipped store so this model does not drift.
                switch (sd::parse_spark_disabled(get(sd::kSparkTagDisabled))) {
                case sd::SparkDisabledState::Disabled:
                    ++disabled[os];
                    break;
                case sd::SparkDisabledState::NotDisabled:
                    ++failed[os];
                    break;
                case sd::SparkDisabledState::Unknown:
                    break;
                }
                continue;
            }
            if (state != sd::SparkRunState::Running)
                continue; // ABSENT / unparseable — contributes to nothing at all
            ++reporting[os];
            for (const auto& tok : sd::spark_mechs_from_csv(get(sd::kSparkTagMechs)))
                ++mechs[os][tok];
            for (const char* m : sd::kSparkMechTokens)
                if (auto v = sd::parse_spark_count(
                        get(sd::spark_type_metric_tag(m, sd::kSparkMetricWatchRejected))))
                    rejected[os][m] += *v;
        }
        for (auto& [os, n] : reporting)
            metrics.gauge("yuzu_fleet_spark_reporting", {{"os", os}}).set(n);
        for (auto& [os, n] : disabled)
            metrics.gauge("yuzu_fleet_spark_disabled", {{"os", os}}).set(n);
        for (auto& [os, n] : failed)
            metrics.gauge("yuzu_fleet_spark_failed", {{"os", os}}).set(n);
        for (auto& [os, mm] : mechs)
            for (auto& [mech, n] : mm)
                metrics.gauge("yuzu_fleet_spark_mechanisms", {{"os", os}, {"mechanism", mech}})
                    .set(n);
        for (auto& [os, mm] : rejected)
            for (auto& [mech, v] : mm)
                metrics.gauge("yuzu_fleet_spark_watch_rejected", {{"os", os}, {"mechanism", mech}})
                    .set(v);
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

TEST_CASE("AgentHealthStore: spark rollup buckets per os and mechanism", "[health_store][spark]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // linux agent: service only, one watch rejection.
    store.upsert("a1", {{"yuzu.os", "linux"},
                        {"yuzu.spark_running", "1"},
                        {"yuzu.spark_mechs", "service"},
                        {"yuzu.spark_service_watch_rejected", "2"}});
    // windows agent: all three mechanisms, quiescent (no counters).
    store.upsert("a2", {{"yuzu.os", "windows"},
                        {"yuzu.spark_running", "1"},
                        {"yuzu.spark_mechs", "file,service,registry"}});
    // ABSENT: no spark tags at all (a pre-rung-1 agent, or one mid-graceful-shutdown) —
    // contributes to NOTHING, not even the disabled bucket.
    store.upsert("a3", {{"yuzu.os", "linux"}});
    store.recompute_spark(metrics);

    CHECK(metrics.gauge("yuzu_fleet_spark_reporting", {{"os", "linux"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_spark_reporting", {{"os", "windows"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_spark_mechanisms", {{"os", "linux"}, {"mechanism", "service"}})
              .value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_spark_mechanisms", {{"os", "windows"}, {"mechanism", "file"}})
              .value() == 1.0);
    CHECK(metrics
              .gauge("yuzu_fleet_spark_watch_rejected", {{"os", "linux"}, {"mechanism", "service"}})
              .value() == 2.0);
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
    // Latency has NO semantic bound to clamp to — an absurd-but-finite claim
    // (1e308 passes the isfinite check!) is REJECTED above the sanity ceiling,
    // otherwise one agent drags avg/max to nonsense (grill finding 2).
    store.upsert("lat-liar", {{"yuzu.perf_disk_lat_ms", "1e308"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    CHECK(metrics.gauge("yuzu_fleet_perf_reporting").value() == 2.0); // good + liar
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "max"}}).value() == 100.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "avg"}}).value() == 75.0);
    CHECK(std::isfinite(metrics.gauge("yuzu_fleet_perf_disk_lat_ms", {{"stat", "avg"}}).value()));
    CHECK(metrics.gauge("yuzu_fleet_perf_disk_lat_ms", {{"stat", "avg"}}).value() == 3.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_disk_lat_ms", {{"stat", "max"}}).value() == 3.0);
}

TEST_CASE("AgentHealthStore: true nearest-rank percentiles in tiny fleets",
          "[health_store][perf]") {
    // floor((n-1)·p) would return the MIN as p90 for n=2 — the regression the
    // grill caught. True nearest-rank (ceil(p·n)−1) returns the max.
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    store.upsert("a", {{"yuzu.perf_cpu_pct", "10.0"}});
    store.upsert("b", {{"yuzu.perf_cpu_pct", "90.0"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "p50"}}).value() == 10.0);
    CHECK(metrics.gauge("yuzu_fleet_perf_cpu_pct", {{"stat", "p90"}}).value() == 90.0);
}

// ── network fleet rollup (slice 3) ───────────────────────────────────────────

TEST_CASE("AgentHealthStore: network facts aggregate to gauges + degraded count",
          "[health_store][network]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // a/c are Linux (RTT + retransmit + a's degraded); b is Windows (throughput +
    // a retransmit that is WITHHELD from the gauge until validated, #1465). Per-OS,
    // never blended; Windows throughput (a real counter) DOES reach the gauge.
    store.upsert("a", {{"yuzu.net_rtt_p50_ms", "100.0"},
                       {"yuzu.net_retrans_pct", "1.0"},
                       {"yuzu.net_degraded", "1"},
                       {"yuzu.os", "linux"}});
    store.upsert("c", {{"yuzu.net_rtt_p50_ms", "200.0"},
                       {"yuzu.net_retrans_pct", "3.0"},
                       {"yuzu.os", "linux"}});
    store.upsert("b", {{"yuzu.net_throughput_bps", "1000000"},
                       {"yuzu.net_retrans_pct", "250"}, // withheld from the gauge (unvalidated)
                       {"yuzu.os", "windows"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    // Reporting is per-OS (a/c via rtt+retrans; b via throughput).
    CHECK(metrics.gauge("yuzu_fleet_net_reporting", {{"os", "linux"}}).value() == 2.0);
    CHECK(metrics.gauge("yuzu_fleet_net_reporting", {{"os", "windows"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_net_degraded", {{"os", "linux"}}).value() == 1.0); // a
    // Linux retransmit + RTT reach the gauge; Windows throughput reaches it.
    CHECK(metrics.gauge("yuzu_fleet_net_rtt_ms", {{"stat", "max"}, {"os", "linux"}}).value() ==
          200.0);
    CHECK(metrics.gauge("yuzu_fleet_net_retrans_pct", {{"stat", "max"}, {"os", "linux"}}).value() ==
          3.0);
    CHECK(metrics.gauge("yuzu_fleet_net_throughput_bps", {{"stat", "max"}, {"os", "windows"}})
              .value() == 1000000.0);
    // The unvalidated Windows retransmit is WITHHELD — a linux retransmit series
    // exists (format pinned) but NO windows one (it would read artificially healthy).
    const auto text = metrics.serialize();
    CHECK(text.find("yuzu_fleet_net_retrans_pct{stat=\"max\",os=\"linux\"}") != std::string::npos);
    CHECK(text.find("yuzu_fleet_net_retrans_pct{stat=\"max\",os=\"windows\"}") ==
          std::string::npos);
}

TEST_CASE("AgentHealthStore: network gauges go absent (not zero) when nobody reports",
          "[health_store][network]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("a", {{"yuzu.net_rtt_p50_ms", "50.0"}, {"yuzu.os", "linux"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));
    REQUIRE(metrics.gauge("yuzu_fleet_net_rtt_ms", {{"stat", "avg"}, {"os", "linux"}}).value() ==
            50.0);

    // The agent stops reporting network facts — every net family must CLEAR (a
    // stale 50 or a fabricated 0 would both be lies); no per-os series should
    // remain, including the reporting denominator.
    store.upsert("a", {{"yuzu.os", "linux"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));
    const auto text = metrics.serialize();
    CHECK(text.find("yuzu_fleet_net_reporting{") == std::string::npos);
    CHECK(text.find("yuzu_fleet_net_rtt_ms{") == std::string::npos);
}

TEST_CASE("AgentHealthStore: agent-controlled os is allowlisted (anti cardinality-injection)",
          "[health_store][network]") {
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // `yuzu.os` is agent-controlled. A hostile/buggy agent sprays a junk value; it
    // must collapse to "other", never create an attacker-named series (a Prometheus
    // cardinality DoS) — across both yuzu_fleet_agents_by_os and the net families.
    store.upsert("evil", {{"yuzu.os", "pwn-uniquely-named-series"},
                          {"yuzu.net_throughput_bps", "1000"}});
    store.upsert("good", {{"yuzu.os", "linux"}, {"yuzu.net_rtt_p50_ms", "10.0"}});
    store.recompute_metrics(metrics, std::chrono::seconds(60));

    const auto text = metrics.serialize();
    CHECK(text.find("pwn-") == std::string::npos); // the junk value never becomes a label
    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "other"}}).value() == 1.0);  // collapsed
    CHECK(metrics.gauge("yuzu_fleet_agents_by_os", {{"os", "linux"}}).value() == 1.0);  // canonical kept
    CHECK(metrics.gauge("yuzu_fleet_net_reporting", {{"os", "other"}}).value() == 1.0); // net too
}

TEST_CASE("spark rollup: the four postures bucket separately", "[spark][fleet][health]") {
    // Governance Gate-4 consistency C-1. Before this, the disabled/failed bucketing — the
    // whole justification of the round — had ZERO coverage: you could delete that branch
    // from agent_registry.cpp's rollup and every test still passed.
    //
    // The split is what makes a fleet-wide spark BOOT FAILURE visible. Conflate FAILED with
    // DISABLED and a failed fleet looks like a deliberate opt-out; conflate FAILED with
    // ABSENT and it emits nothing at all.
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    // RUNNING x2 (windows)
    store.upsert("run1", {{"yuzu.os", "windows"},
                          {"yuzu.spark_running", "1"},
                          {"yuzu.spark_mechs", "file,registry,service"}});
    store.upsert("run2", {{"yuzu.os", "windows"},
                          {"yuzu.spark_running", "1"},
                          {"yuzu.spark_mechs", "file,registry,service"}});
    // DISABLED — a deliberate opt-out. Expected to be non-zero; never alert on it.
    store.upsert("off1", {{"yuzu.os", "windows"},
                          {"yuzu.spark_running", "0"},
                          {"yuzu.spark_disabled", "1"}});
    // FAILED — enabled, but the engine threw at boot. THE gauge operators alert on.
    store.upsert("bad1", {{"yuzu.os", "windows"}, {"yuzu.spark_running", "0"}});
    // ABSENT — no spark tags at all (pre-rung-1 agent, or mid-graceful-shutdown).
    store.upsert("old1", {{"yuzu.os", "windows"}});
    // A CONTAINER: running, but its only mechanism is inert -> empty capability CSV.
    store.upsert("ctr1", {{"yuzu.os", "linux"},
                          {"yuzu.spark_running", "1"},
                          {"yuzu.spark_mechs", ""}});

    store.recompute_spark(metrics);

    // Assert on VALUES, not on serialize() substrings: `find("} 1")` also matches "} 10"
    // and "} 12", so a substring assertion silently passes on a wrong count the moment the
    // fixture grows past 9 agents (governance Gate-8 quality).
    CHECK(metrics.gauge("yuzu_fleet_spark_reporting", {{"os", "windows"}}).value() == 2.0);
    CHECK(metrics.gauge("yuzu_fleet_spark_disabled", {{"os", "windows"}}).value() == 1.0);
    CHECK(metrics.gauge("yuzu_fleet_spark_failed", {{"os", "windows"}}).value() == 1.0);
    // The container reports, but claims no capability: no {os=linux,mechanism=*} series.
    CHECK(metrics.gauge("yuzu_fleet_spark_reporting", {{"os", "linux"}}).value() == 1.0);
    const bool linux_mech_series =
        metrics.serialize().find("yuzu_fleet_spark_mechanisms{os=\"linux\"") != std::string::npos;
    CHECK_FALSE(linux_mech_series);
}

TEST_CASE("spark rollup: a garbage spark_running value must NOT page as FAILED",
          "[spark][fleet][health]") {
    // Governance Gate-4 UP-6 / consistency C-2. The rollup used to bucket `== "1"` as
    // running and ANY other non-empty string as not-running -> with no `spark_disabled` key
    // that landed in yuzu_fleet_spark_failed{os}, the ONE gauge documented "alert on it".
    // So "true", " 1", "01", "2" or "x" from a single buggy or forked agent build could page
    // on-call. It is also a forward-compat trap: a third posture value added in a later rung
    // would make an OLD server alarm the whole fleet during a rolling upgrade.
    TestAgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    store.upsert("g1", {{"yuzu.os", "windows"}, {"yuzu.spark_running", "true"}});
    store.upsert("g2", {{"yuzu.os", "windows"}, {"yuzu.spark_running", " 1"}});
    store.upsert("g3", {{"yuzu.os", "windows"}, {"yuzu.spark_running", "01"}});
    store.upsert("g4", {{"yuzu.os", "windows"}, {"yuzu.spark_running", "2"}});
    store.upsert("g5", {{"yuzu.os", "windows"}, {"yuzu.spark_running", "x"}});
    // ...and one agent that HAS genuinely failed, to prove the gauge still works.
    store.upsert("real", {{"yuzu.os", "windows"}, {"yuzu.spark_running", "0"}});

    store.recompute_spark(metrics);

    // Exactly ONE failure — the real one. The five garbage values contribute NOTHING: not to
    // failed (which would page), not to reporting, not to disabled.
    CHECK(metrics.gauge("yuzu_fleet_spark_failed", {{"os", "windows"}}).value() == 1.0);
    const bool any_reporting =
        metrics.serialize().find("yuzu_fleet_spark_reporting{os=\"windows\"}") !=
        std::string::npos;
    CHECK_FALSE(any_reporting);
}

// ── The REAL rollup ─────────────────────────────────────────────────────────
//
// Everything above this line drives TestAgentHealthStore, a reproduction. This case drives
// the SHIPPED yuzu::server::detail::AgentHealthStore through a real protobuf::Map upsert, so
// it is the only one that fails if the spark bucketing is deleted from agent_registry.cpp.
//
// VERIFIED to fail without the shipped code: commenting out the spark block in
// recompute_metrics turns this red (the reproduction-based cases stay green — which is
// exactly the blind spot this case exists to remove). governance Gate-8 round 7, S-1.
TEST_CASE("REAL AgentHealthStore: the four spark postures reach the shipped gauges",
          "[spark][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    // RUNNING — reports spark_running=1 and a capability CSV.
    beat("run-1", {{"yuzu.spark_running", "1"}, {"yuzu.spark_mechs", "file,registry"}});
    beat("run-2", {{"yuzu.spark_running", "1"}, {"yuzu.spark_mechs", "file"}});
    // DISABLED — spark_running=0 AND spark_disabled=1 (operator turned it off).
    beat("dis-1", {{"yuzu.spark_running", "0"}, {"yuzu.spark_disabled", "1"}});
    // FAILED — spark_running=0 with NO spark_disabled (boot-time instantiation threw).
    beat("fail-1", {{"yuzu.spark_running", "0"}});
    // ABSENT — no spark keys at all (a pre-rung-1 agent, or one shutting down). Must land in
    // NO bucket: absent-not-zero.
    beat("absent-1", {});

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    auto val = [&](const std::string& series) -> double {
        const auto pos = out.find(series);
        REQUIRE(pos != std::string::npos);
        return std::stod(out.substr(pos + series.size()));
    };

    // The bucketing this round exists to add. Deleting it from agent_registry.cpp makes
    // these three lines fail — which no mirror-based case in this file can do.
    CHECK(val("yuzu_fleet_spark_reporting{os=\"linux\"} ") == 2.0); // RUNNING only
    CHECK(val("yuzu_fleet_spark_disabled{os=\"linux\"} ") == 1.0);
    CHECK(val("yuzu_fleet_spark_failed{os=\"linux\"} ") == 1.0);

    // Capability CSV fans out per mechanism, and only from RUNNING agents.
    // Label order is the gauge's own ({os}, then {mechanism}) — asserted against the shipped
    // serialization, not a guess. (My first draft guessed the reverse order and this test
    // caught it, which is the point of driving the real store.)
    CHECK(val("yuzu_fleet_spark_mechanisms{os=\"linux\",mechanism=\"file\"} ") == 2.0);
    CHECK(val("yuzu_fleet_spark_mechanisms{os=\"linux\",mechanism=\"registry\"} ") == 1.0);

    // ABSENT is not a zero: the absent agent must not appear in any spark bucket, and a
    // never-seen OS must not be seeded at 0 (the absent-not-zero convention).
    CHECK(out.find("yuzu_fleet_spark_reporting{os=\"windows\"}") == std::string::npos);
    CHECK(out.find("yuzu_fleet_spark_failed{os=\"windows\"}") == std::string::npos);
}

TEST_CASE("REAL AgentHealthStore: a garbage spark_disabled value pages on neither bucket",
          "[spark][rollup][real]") {
    // Governance Gate-4 UP-3. spark_running parses NotRunning (strict "0"), but the DISABLED
    // vs FAILED discriminator used to be a bare `spark_disabled == "1" ? disabled : failed`,
    // so an opted-out agent whose forked build emits `spark_disabled="01"`/`"true"` was bucketed
    // FAILED — the ONE gauge with an active alert. parse_spark_disabled now treats any non-
    // conforming discriminator as Unknown → NEITHER bucket. Driven through the SHIPPED store.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "windows";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    // Five opted-out agents with a NON-conforming disabled value — must count in neither bucket.
    beat("g1", {{"yuzu.spark_running", "0"}, {"yuzu.spark_disabled", "01"}});
    beat("g2", {{"yuzu.spark_running", "0"}, {"yuzu.spark_disabled", "true"}});
    beat("g3", {{"yuzu.spark_running", "0"}, {"yuzu.spark_disabled", " 1"}});
    beat("g4", {{"yuzu.spark_running", "0"}, {"yuzu.spark_disabled", "2"}});
    beat("g5", {{"yuzu.spark_running", "0"}, {"yuzu.spark_disabled", "yes"}});
    // ...and one genuinely failed agent (no disabled key), to prove the gauge still works.
    beat("real", {{"yuzu.spark_running", "0"}});

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    auto val = [&](const std::string& series) -> double {
        const auto pos = out.find(series);
        REQUIRE(pos != std::string::npos);
        return std::stod(out.substr(pos + series.size()));
    };

    // Exactly ONE failure — the real one. The five garbage discriminators page on NOTHING.
    CHECK(val("yuzu_fleet_spark_failed{os=\"windows\"} ") == 1.0);
    CHECK(out.find("yuzu_fleet_spark_disabled{os=\"windows\"}") == std::string::npos);
}

// ── Guardian durable lifecycle-journal fleet rollup (#2298 gate 3) ────────────
//
// Driven through the REAL AgentHealthStore, never the reproduction at the top of this
// file: a mirror-based case here would still pass with the rollup deleted from
// agent_registry.cpp, which is the coverage gap this file's header records.
//
// The gauges are UNLABELLED, so a series lookup must anchor to the start of a line -
// "yuzu_fleet_guardian_journal_bytes " also matches the "# HELP yuzu_fleet_..." line,
// and parsing a number off THAT throws. The labelled spark cases above are immune only
// because their `{os="..."}` fragment never appears in a HELP line.

namespace {

/// Value of an unlabelled fleet series, anchored to line start (see note above).
double unlabelled_series(const std::string& out, const std::string& name) {
    const auto pos = out.find("\n" + name + " ");
    REQUIRE(pos != std::string::npos);
    return std::stod(out.substr(pos + 1 + name.size()));
}

/// True if the series has a SAMPLE line. A described-but-empty family still emits its
/// "# HELP"/"# TYPE" lines, so a bare find(name) would report a cleared family as present.
bool has_unlabelled_series(const std::string& out, const std::string& name) {
    return out.find("\n" + name + " ") != std::string::npos;
}

} // namespace

TEST_CASE("REAL AgentHealthStore: guardian journal tags sum into unlabelled fleet gauges",
          "[guardian][journal][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "windows";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    // Two agents whose journals have something to report...
    beat("j1", {{"yuzu.guardian_journal_stage_dropped", "1"},
                {"yuzu.guardian_journal_batches_written", "10"},
                {"yuzu.guardian_journal_evicted_no_send_evidence", "2"},
                {"yuzu.guardian_journal_bytes", "4096"}});
    beat("j2", {{"yuzu.guardian_journal_stage_dropped", "4"},
                {"yuzu.guardian_journal_batches_written", "20"},
                {"yuzu.guardian_journal_bytes", "8192"}});
    // ...and one whose journal is quiescent or inert (prefer_spark off): the writer is
    // sparse, so it ships NO journal tag. It must contribute nothing - not a 0 that
    // drags a family into existence.
    beat("quiet", {});

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    // Fleet sums, unlabelled. Deleting the rollup from agent_registry.cpp fails these.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_stage_dropped") == 5.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_batches_written") == 30.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_bytes") == 12288.0);
    // Only one agent reported the integrity-gap counter - it still publishes, at ITS value.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_evicted_no_send_evidence") == 2.0);

    // A signal NOBODY reported stays absent. This is the whole point: a fabricated 0 on
    // a loss counter reads as "checked, nothing lost" when nothing was ever checked.
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_write_failures"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_quarantined"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_maint_exceptions"));

    // No agent-controlled label anywhere in this family (it is flat by design), so the
    // fleet cardinality is exactly one series per reported signal.
    CHECK(out.find("yuzu_fleet_guardian_journal_stage_dropped{") == std::string::npos);
}

TEST_CASE("REAL AgentHealthStore: journal AGE tags roll up as MAX (worst endpoint), never SUM",
          "[guardian][journal][rollup][real]") {
    // The age family (item 6 + #2364) is the first non-SUM fleet rollup: a SUM of ages
    // is meaningless (two 30 s-stale agents are not one 60 s-stale agent), and the
    // fleet question is "how bad is the WORST endpoint". Deleting the MAX block from
    // agent_registry.cpp fails these.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    beat("a1", {{"yuzu.guardian_journal_page_stale_seconds", "30"},
                {"yuzu.guardian_journal_prune_stale_seconds", "100"}});
    beat("a2", {{"yuzu.guardian_journal_page_stale_seconds", "200"},
                {"yuzu.guardian_journal_prune_stale_seconds", "50"},
                {"yuzu.guardian_journal_headroom_blocked_seconds", "700000"}});
    beat("quiet", {}); // dormant (prefer_spark off): ships no age tag, contends for no MAX

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    // MAX per signal, independently - NOT 230/150 (the SUM), and not one agent owning both.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_page_stale_seconds_max") == 200.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_prune_stale_seconds_max") == 100.0);
    // A single reporter owns its MAX (the sparse blocked gauge, near its 7-day threshold).
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_headroom_blocked_seconds_max") ==
          700000.0);
    // Flat family: no labels.
    CHECK(out.find("yuzu_fleet_guardian_journal_page_stale_seconds_max{") == std::string::npos);
}

TEST_CASE("REAL AgentHealthStore: age gauges publish an explicit 0, reject forged values, "
          "stay absent unreported",
          "[guardian][journal][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;
    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    // A live fresh fleet: the writer emits the staleness pair INCLUDING 0, so the fleet
    // MAX publishes AT 0 - "every worker alive and fresh" is a real measurement, distinct
    // from the dormant fleet where the family is absent.
    beat("fresh", {{"yuzu.guardian_journal_page_stale_seconds", "0"},
                   {"yuzu.guardian_journal_prune_stale_seconds", "0"}});
    // A forged age above the plausibility ceiling is REJECTED (counted), never clamped -
    // one rogue agent must not own the fleet MAX forever.
    beat("rogue", {{"yuzu.guardian_journal_headroom_blocked_seconds", "9999999999"}});

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_page_stale_seconds_max") == 0.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_prune_stale_seconds_max") == 0.0);
    // The rogue value was rejected: the blocked gauge stays ABSENT and the rejection is
    // visible on the family's existing meta-signal.
    CHECK_FALSE(
        has_unlabelled_series(out, "yuzu_fleet_guardian_journal_headroom_blocked_seconds_max"));
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_tag_rejected") == 1.0);
}

TEST_CASE("REAL AgentHealthStore: a stale agent's age reading leaves the fleet MAX",
          "[guardian][journal][rollup][real]") {
    // The MAX sibling of the counter family's staleness-eviction test below: the
    // staleness prune runs before accumulation, so an aged-out agent's staleness
    // reading drops out of the MAX on the next sweep. For MAX this is double-edged and
    // deliberate (governance UP-11/UP-12): eviction can only LOWER the max - the
    // honest reading, since a silent agent's age is unknowable - but it also means the
    // worst endpoint leaving the reporting population resolves the fleet signal
    // without the endpoint healing. Driven with a zero window for determinism.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    tags["yuzu.guardian_journal_page_stale_seconds"] = "900";
    store.upsert("doomed", tags);

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    REQUIRE(unlabelled_series(metrics.serialize(),
                              "yuzu_fleet_guardian_journal_page_stale_seconds_max") == 900.0);

    store.recompute_metrics(metrics, std::chrono::seconds{0});
    CHECK_FALSE(has_unlabelled_series(metrics.serialize(),
                                      "yuzu_fleet_guardian_journal_page_stale_seconds_max"));
}

TEST_CASE("REAL AgentHealthStore: guardian journal gauges go absent (not zero) when nobody reports",
          "[guardian][journal][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> reporting;
    reporting["yuzu.os"] = "linux";
    reporting["yuzu.guardian_journal_write_failures"] = "7";
    store.upsert("j1", reporting);
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    REQUIRE(unlabelled_series(metrics.serialize(), "yuzu_fleet_guardian_journal_write_failures") ==
            7.0);

    // The journal recovers (or the agent is downgraded / prefer_spark turned off), so the
    // sparse writer stops emitting the tag. A stale 7 and a fabricated 0 are BOTH lies -
    // the family must clear. The 0 is the more dangerous of the two: it is the reading an
    // operator would accept as evidence the journal was checked and found clean.
    google::protobuf::Map<std::string, std::string> quiet;
    quiet["yuzu.os"] = "linux";
    store.upsert("j1", quiet);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_write_failures"));
    // Nothing else in the family was conjured either.
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_batches_written"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_pending"));
}

TEST_CASE("REAL AgentHealthStore: a rogue agent cannot poison a guardian journal fleet gauge",
          "[guardian][journal][rollup][real]") {
    // The tag values are fully agent-controlled. std::stod (the idiom the older tag
    // families use) accepts "inf"/"nan" WITHOUT throwing, and a near-UINT64_MAX value
    // would annihilate every honest agent's contribution in the double-precision sum
    // (1.8e19 + 1 == 1.8e19). parse_guardian_journal_count rejects all of it as "did not
    // report". Driven through the SHIPPED store so the wiring, not just the parser, is
    // covered.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id, const std::string& value) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        tags["yuzu.guardian_journal_stage_dropped"] = value;
        store.upsert(id, tags);
    };

    beat("honest", "5");
    beat("inf", "inf");
    beat("nan", "nan");
    beat("neg", "-1");
    beat("frac", "1.5");
    beat("junk", "garbage");
    beat("huge", "18446744073709551615"); // UINT64_MAX
    beat("over", "1000000001");           // one past the implausibility ceiling
    beat("long", std::string(4096, '9'));

    store.recompute_metrics(metrics, std::chrono::seconds{300});
    const std::string out = metrics.serialize();

    const double sum = unlabelled_series(out, "yuzu_fleet_guardian_journal_stage_dropped");
    CHECK(sum == 5.0); // only the honest agent contributed
    CHECK(std::isfinite(sum));
}

TEST_CASE("REAL AgentHealthStore: guardian journal meta-signals publish even at zero",
          "[guardian][journal][rollup][real]") {
    // The 22 counters are absent-not-zero; these two are the OPPOSITE and deliberately
    // so. They are server-owned counts that always have a true value, so publishing 0
    // is a measurement ("nothing is reporting") rather than a fabricated zero. Without
    // them, a dark telemetry pipeline is indistinguishable from a healthy quiet fleet
    // (governance Gate-4 UP-9 / Gate-6 sre).
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> quiet;
    quiet["yuzu.os"] = "linux";
    store.upsert("no-journal", quiet);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_reporting") == 0.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_tag_rejected") == 0.0);
    // ...while the counters themselves stay absent, as before.
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_batches_written"));
}

TEST_CASE("REAL AgentHealthStore: guardian journal reporting counts agents, not tags",
          "[guardian][journal][rollup][real]") {
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    auto beat = [&](const std::string& id,
                    const std::vector<std::pair<std::string, std::string>>& kv) {
        google::protobuf::Map<std::string, std::string> tags;
        tags["yuzu.os"] = "linux";
        for (const auto& [k, v] : kv)
            tags[k] = v;
        store.upsert(id, tags);
    };

    // Two reporters (one with four tags, one with one) and two non-reporters.
    beat("j1", {{"yuzu.guardian_journal_batches_written", "10"},
                {"yuzu.guardian_journal_pruned", "3"},
                {"yuzu.guardian_journal_pages", "7"},
                {"yuzu.guardian_journal_bytes", "2048"}});
    beat("j2", {{"yuzu.guardian_journal_batches_written", "5"}});
    beat("quiet-1", {});
    beat("quiet-2", {});
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    // AGENTS, not tags: j1's four tags count once.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_reporting") == 2.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_batches_written") == 15.0);
}

TEST_CASE("REAL AgentHealthStore: a rejected journal tag is counted, not silently dropped",
          "[guardian][journal][rollup][real]") {
    // Gate-5 CH-6 / Gate-4 UP-16. A value that fails the forged-value parse used to
    // vanish without trace: if the rejecting agent was the ONLY reporter, its family
    // went absent, and absent reads as "checked, nothing lost". Now the drop is
    // counted, so an operator can tell "nothing to report" from "something unreadable".
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> rogue;
    rogue["yuzu.os"] = "linux";
    rogue["yuzu.guardian_journal_evicted_no_send_evidence"] = "1000000001"; // past the ceiling
    rogue["yuzu.guardian_journal_stage_dropped"] = "garbage";
    store.upsert("rogue", rogue);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_tag_rejected") == 2.0);
    // The families stay ABSENT (the values were never admitted) - but the rejection
    // counter is what stops that absence being misread as health.
    CHECK_FALSE(
        has_unlabelled_series(out, "yuzu_fleet_guardian_journal_evicted_no_send_evidence"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_stage_dropped"));
    // The agent reported nothing PARSEABLE, so it is not in the coverage denominator.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_reporting") == 0.0);
}

TEST_CASE("REAL AgentHealthStore: an explicit journal zero publishes as zero",
          "[guardian][journal][rollup][real]") {
    // The `reported` flag is tracked separately from the sum precisely so this case
    // stays honest: the real writer is sparse and never emits "0", but a non-conforming
    // or forked agent build can. An explicit "0" IS a report of zero, so it publishes
    // as 0 rather than being suppressed into absence (which would misreport a
    // reporting fleet as silent). Documented divergence, now covered.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    tags["yuzu.guardian_journal_stage_dropped"] = "0";
    store.upsert("nonconforming", tags);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_stage_dropped") == 0.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_reporting") == 1.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_tag_rejected") == 0.0);
}

TEST_CASE("REAL AgentHealthStore: a stale agent's journal counters leave the fleet sum",
          "[guardian][journal][rollup][real]") {
    // The staleness prune runs BEFORE the accumulation loop, so an aged-out agent's
    // counters silently drop out of the sum - which is the mechanism behind the whole
    // absent-not-zero story and was previously untested here (and is still untested for
    // the sibling spark rollup). Driven with a zero staleness window so the prune is
    // deterministic rather than timing-dependent.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    tags["yuzu.guardian_journal_evicted_no_send_evidence"] = "9";
    store.upsert("doomed", tags);

    // Generous window: the agent is fresh, so it counts.
    store.recompute_metrics(metrics, std::chrono::seconds{300});
    REQUIRE(unlabelled_series(metrics.serialize(),
                              "yuzu_fleet_guardian_journal_evicted_no_send_evidence") == 9.0);

    // Zero window: every snapshot is stale, so the agent is pruned before accumulation.
    // Its integrity counter vanishes from the fleet view even though the loss it
    // recorded really happened - the alert-resolves-without-the-gap-healing case.
    store.recompute_metrics(metrics, std::chrono::seconds{0});
    const std::string out = metrics.serialize();
    CHECK_FALSE(
        has_unlabelled_series(out, "yuzu_fleet_guardian_journal_evicted_no_send_evidence"));
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_reporting") == 0.0);
}

TEST_CASE("REAL AgentHealthStore: one agent mixing parseable and rejected journal tags",
          "[guardian][journal][rollup][real]") {
    // Gate-3 re-run (quality-engineer): every prior case gave an agent EITHER good tags
    // or bad ones, so the interaction of the two meta-signals on a SINGLE agent was
    // untested - and they are computed from the same loop pass. Also covers the
    // over-long token through the STORE (previously parser-level only): the 10-digit
    // length gate runs before the plausibility ceiling, so an 11-digit value is refused
    // unread rather than by the ceiling.
    yuzu::server::detail::AgentHealthStore store;
    yuzu::MetricsRegistry metrics;

    google::protobuf::Map<std::string, std::string> tags;
    tags["yuzu.os"] = "linux";
    tags["yuzu.guardian_journal_batches_written"] = "40";       // parseable
    tags["yuzu.guardian_journal_pruned"] = "9";                 // parseable
    tags["yuzu.guardian_journal_stage_dropped"] = "999999999999"; // 12 digits: length gate
    tags["yuzu.guardian_journal_write_failures"] = "1000000001";  // 10 digits: ceiling
    tags["yuzu.guardian_journal_pages"] = "not-a-number";         // malformed
    store.upsert("mixed", tags);
    store.recompute_metrics(metrics, std::chrono::seconds{300});

    const std::string out = metrics.serialize();
    // The parseable half lands in its own gauges...
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_batches_written") == 40.0);
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_pruned") == 9.0);
    // ...the rejected half leaves its families ABSENT and is counted instead.
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_stage_dropped"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_write_failures"));
    CHECK_FALSE(has_unlabelled_series(out, "yuzu_fleet_guardian_journal_pages"));
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_tag_rejected") == 3.0);
    // One agent, and it DID report something parseable, so it counts once toward
    // coverage even though three of its five journal tags were refused.
    CHECK(unlabelled_series(out, "yuzu_fleet_guardian_journal_reporting") == 1.0);
}
