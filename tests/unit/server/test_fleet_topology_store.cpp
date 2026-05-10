/**
 * test_fleet_topology_store.cpp -- FleetTopologyStore + process classify tests
 *
 * Covers:
 *   * Process categorization heuristics (classify())
 *   * Snapshot shape + JSON serialization
 *   * Cross-machine IP resolution (ip -> agent_id, scope classification)
 *   * Loopback / unspecified / external handling
 *   * Cache hit/miss + TTL expiry behaviour
 *   * Single-flight: concurrent get() calls fan one fetch
 *   * Stale-agent rows propagate without breaking the build
 *   * Vuln overlay path is testable without an NvdDatabase instance
 *     (we test that omitted/null nvd_ leaves worst_severity empty)
 */

#include "fleet_topology_store.hpp"
#include "fleet_topology_types.hpp"
#include "process_category.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <thread>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

RawAgentSnapshot make_agent(std::string id, std::string host, std::vector<std::string> ips) {
    RawAgentSnapshot r;
    r.agent_id = std::move(id);
    r.hostname = std::move(host);
    r.os = "linux";
    r.ts = 1715299200;
    r.local_ips = std::move(ips);
    return r;
}

RawAgentSnapshot::RawProcess proc(uint32_t pid, uint32_t ppid, std::string name, std::string user) {
    RawAgentSnapshot::RawProcess p;
    p.pid = pid;
    p.ppid = ppid;
    p.name = std::move(name);
    p.user = std::move(user);
    return p;
}

RawAgentSnapshot::RawConnection conn(std::string proto, std::string la, int lp, std::string ra,
                                     int rp, std::string state = "ESTABLISHED", uint32_t pid = 1) {
    RawAgentSnapshot::RawConnection c;
    c.proto = std::move(proto);
    c.local_addr = std::move(la);
    c.local_port = lp;
    c.remote_addr = std::move(ra);
    c.remote_port = rp;
    c.state = std::move(state);
    c.pid = pid;
    return c;
}

FleetTopologyStore::Fetcher fixed_fetcher(std::vector<RawAgentSnapshot> data) {
    return [data = std::move(data)](std::chrono::milliseconds) {
        return data;
    };
}

} // namespace

// =============================================================================
// classify()
// =============================================================================

TEST_CASE("classify: known database executables map to Database", "[viz][category]") {
    CHECK(classify("postgres") == ProcessCategory::Database);
    CHECK(classify("mysqld") == ProcessCategory::Database);
    CHECK(classify("redis-server") == ProcessCategory::Database);
    CHECK(classify("mongod") == ProcessCategory::Database);
}

TEST_CASE("classify: known browsers map to Browser", "[viz][category]") {
    CHECK(classify("chrome") == ProcessCategory::Browser);
    CHECK(classify("firefox") == ProcessCategory::Browser);
    CHECK(classify("msedge") == ProcessCategory::Browser);
    CHECK(classify("safari") == ProcessCategory::Browser);
}

TEST_CASE("classify: known web servers map to Web", "[viz][category]") {
    CHECK(classify("nginx") == ProcessCategory::Web);
    CHECK(classify("apache2") == ProcessCategory::Web);
    CHECK(classify("haproxy") == ProcessCategory::Web);
}

TEST_CASE("classify: runtimes map to Runtime", "[viz][category]") {
    CHECK(classify("java") == ProcessCategory::Runtime);
    CHECK(classify("python3") == ProcessCategory::Runtime);
    CHECK(classify("node") == ProcessCategory::Runtime);
    CHECK(classify("dotnet") == ProcessCategory::Runtime);
}

TEST_CASE("classify: known system processes map to System", "[viz][category]") {
    CHECK(classify("systemd") == ProcessCategory::System);
    CHECK(classify("launchd") == ProcessCategory::System);
    CHECK(classify("svchost") == ProcessCategory::System);
    CHECK(classify("kthreadd") == ProcessCategory::System);
}

TEST_CASE("classify: case-insensitive + Windows .exe stripped", "[viz][category]") {
    CHECK(classify("Chrome.exe") == ProcessCategory::Browser);
    CHECK(classify("PostgreS") == ProcessCategory::Database);
    CHECK(classify("MSEDGE.EXE") == ProcessCategory::Browser);
}

TEST_CASE("classify: unknown executables fall to Other", "[viz][category]") {
    CHECK(classify("my-custom-binary") == ProcessCategory::Other);
    CHECK(classify("") == ProcessCategory::Other);
    CHECK(classify("xyz123") == ProcessCategory::Other);
}

TEST_CASE("classify: full path stripped to basename", "[viz][category]") {
    CHECK(classify("/usr/bin/postgres") == ProcessCategory::Database);
    CHECK(classify("C:\\Program Files\\Mozilla Firefox\\firefox.exe") == ProcessCategory::Browser);
}

// =============================================================================
// build_snapshot — IP resolution + scope classification
// =============================================================================

TEST_CASE("topology: cross-machine connection resolves dst_agent_id", "[viz][topology]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.processes.push_back(proc(100, 1, "client", "alice"));
    a.connections.push_back(conn("tcp", "10.0.0.7", 50000, "10.0.0.42", 5432));

    auto b = make_agent("agent-B", "hostB", {"10.0.0.42"});
    b.processes.push_back(proc(200, 1, "postgres", "postgres"));

    FleetTopologyStore store(fixed_fetcher({a, b}));
    auto snap = store.get(false);
    REQUIRE(snap);
    REQUIRE(snap->machines.size() == 2);

    const auto& edge = snap->machines[0].connections.at(0);
    CHECK(edge.scope == EdgeScope::InternalFleet);
    CHECK(edge.dst_agent_id == "agent-B");
}

TEST_CASE("topology: loopback connections classified as Local", "[viz][topology]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.connections.push_back(conn("tcp", "127.0.0.1", 8080, "127.0.0.1", 41234));
    a.connections.push_back(conn("tcp6", "::1", 8080, "::1", 41235));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    REQUIRE(snap->machines.at(0).connections.size() == 2);
    CHECK(snap->machines[0].connections[0].scope == EdgeScope::Local);
    CHECK(snap->machines[0].connections[1].scope == EdgeScope::Local);
}

TEST_CASE("topology: connection to non-fleet IP marked External", "[viz][topology]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.connections.push_back(conn("tcp", "10.0.0.7", 50000, "8.8.8.8", 443));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    CHECK(snap->machines[0].connections[0].scope == EdgeScope::External);
    CHECK(snap->machines[0].connections[0].dst_agent_id.empty());
}

TEST_CASE("topology: 0.0.0.0 / :: in local_ips skipped from ip_to_agent map", "[viz][topology]") {
    auto a = make_agent("agent-A", "hostA", {"0.0.0.0", "10.0.0.7", "::"});
    auto b = make_agent("agent-B", "hostB", {"10.0.0.42"});
    // B connects to 0.0.0.0:9000 -- if not skipped, would resolve to A.
    b.connections.push_back(conn("tcp", "10.0.0.42", 50000, "0.0.0.0", 9000));

    FleetTopologyStore store(fixed_fetcher({a, b}));
    auto snap = store.get(false);
    auto& edges = snap->machines[1].connections;
    REQUIRE(edges.size() == 1);
    CHECK(edges[0].scope == EdgeScope::External);
    CHECK(edges[0].dst_agent_id.empty());
}

TEST_CASE("topology: connections without remote endpoint are dropped", "[viz][topology]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.connections.push_back(conn("tcp", "10.0.0.7", 22, "", 0, "LISTEN"));
    a.connections.push_back(conn("tcp", "10.0.0.7", 50000, "10.0.0.42", 443));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    CHECK(snap->machines[0].connections.size() == 1);
    CHECK(snap->machines[0].connections[0].dst_port == 443);
}

TEST_CASE("topology: process category attached to ProcessNode", "[viz][topology]") {
    auto a = make_agent("agent-A", "hostA", {});
    a.processes.push_back(proc(1, 0, "systemd", "root"));
    a.processes.push_back(proc(100, 1, "nginx", "www-data"));
    a.processes.push_back(proc(200, 1, "postgres", "postgres"));
    a.processes.push_back(proc(300, 1, "weird-binary", "nathan"));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    const auto& procs = snap->machines.at(0).processes;
    REQUIRE(procs.size() == 4);
    CHECK(procs[0].category == ProcessCategory::System);
    CHECK(procs[1].category == ProcessCategory::Web);
    CHECK(procs[2].category == ProcessCategory::Database);
    CHECK(procs[3].category == ProcessCategory::Other);
}

TEST_CASE("topology: stale agent row preserved with empty inventory", "[viz][topology]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.stale = true;
    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    REQUIRE(snap->machines.size() == 1);
    CHECK(snap->machines[0].stale == true);
    CHECK(snap->machines[0].processes.empty());
    CHECK(snap->machines[0].connections.empty());
}

TEST_CASE("topology: include_vuln=false leaves worst_severity empty", "[viz][topology][vuln]") {
    auto a = make_agent("agent-A", "hostA", {});
    a.processes.push_back(proc(100, 1, "postgres", "postgres"));
    FleetTopologyStore store(fixed_fetcher({a}), nullptr);
    auto snap = store.get(false);
    CHECK(snap->machines[0].processes[0].worst_severity.empty());
    CHECK(snap->machines[0].processes[0].cve_count == 0);
}

// =============================================================================
// JSON shape (locked by tests)
// =============================================================================

TEST_CASE("topology: TopologySnapshot serializes to fleet_topology.v1 JSON",
          "[viz][topology][json]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.processes.push_back(proc(100, 1, "nginx", "www-data"));
    a.connections.push_back(conn("tcp", "10.0.0.7", 50000, "8.8.8.8", 443));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    json j = *snap;

    CHECK(j["schema"] == "fleet_topology.v1");
    CHECK(j["include_vuln"] == false);
    REQUIRE(j["machines"].size() == 1);
    CHECK(j["machines"][0]["agent_id"] == "agent-A");
    CHECK(j["machines"][0]["hostname"] == "hostA");
    CHECK(j["machines"][0]["local_ips"][0] == "10.0.0.7");
    CHECK(j["machines"][0]["processes"][0]["category"] == "web");
    CHECK(j["machines"][0]["connections"][0]["scope"] == "external");
}

// =============================================================================
// Cache behaviour
// =============================================================================

TEST_CASE("cache: second get() within TTL is a hit", "[viz][cache]") {
    std::atomic<int> calls{0};
    auto fetcher = [&calls](std::chrono::milliseconds) {
        ++calls;
        return std::vector<RawAgentSnapshot>{};
    };
    FleetTopologyStore store(fetcher, nullptr, std::chrono::seconds(60));

    auto s1 = store.get(false);
    auto s2 = store.get(false);
    CHECK(calls.load() == 1);
    CHECK(s1 == s2); // shared_ptr identity -- same cached object
    CHECK(store.cache_hits() == 1);
    CHECK(store.cache_misses() == 1);
}

TEST_CASE("cache: short TTL expires and triggers refill", "[viz][cache]") {
    std::atomic<int> calls{0};
    auto fetcher = [&calls](std::chrono::milliseconds) {
        ++calls;
        return std::vector<RawAgentSnapshot>{};
    };
    // 1 ms TTL so the second call can guarantee expiry.
    FleetTopologyStore store(fetcher, nullptr, std::chrono::milliseconds(1));

    store.get(false);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    store.get(false);
    CHECK(calls.load() == 2);
    CHECK(store.cache_misses() == 2);
}

TEST_CASE("cache: invalidate() forces next get to refill", "[viz][cache]") {
    std::atomic<int> calls{0};
    auto fetcher = [&calls](std::chrono::milliseconds) {
        ++calls;
        return std::vector<RawAgentSnapshot>{};
    };
    FleetTopologyStore store(fetcher, nullptr, std::chrono::seconds(60));

    store.get(false);
    store.invalidate();
    store.get(false);
    CHECK(calls.load() == 2);
}

TEST_CASE("cache: include_vuln=true and =false are independent slots", "[viz][cache]") {
    std::atomic<int> calls{0};
    auto fetcher = [&calls](std::chrono::milliseconds) {
        ++calls;
        return std::vector<RawAgentSnapshot>{};
    };
    FleetTopologyStore store(fetcher, nullptr, std::chrono::seconds(60));

    store.get(false);
    store.get(true);
    store.get(false); // should hit
    store.get(true);  // should hit
    CHECK(calls.load() == 2);
}

TEST_CASE("cache: single-flight -- concurrent get() calls fan one fetch",
          "[viz][cache][singleflight]") {
    std::atomic<int> calls{0};
    auto fetcher = [&calls](std::chrono::milliseconds) {
        ++calls;
        // Sleep long enough that all threads pile up before the first finishes.
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
        return std::vector<RawAgentSnapshot>{};
    };
    FleetTopologyStore store(fetcher, nullptr, std::chrono::seconds(60));

    constexpr int N = 16;
    std::vector<std::future<std::shared_ptr<const TopologySnapshot>>> futures;
    futures.reserve(N);
    for (int i = 0; i < N; ++i) {
        futures.push_back(std::async(std::launch::async, [&] { return store.get(false); }));
    }
    for (auto& f : futures) {
        REQUIRE(f.get() != nullptr);
    }
    CHECK(calls.load() == 1);
    CHECK(store.refill_waiters() >= 1); // some fraction of N-1 were waiters
}

TEST_CASE("cache: fetcher exception returns empty sentinel, unblocks waiters",
          "[viz][cache][singleflight]") {
    // UP-9 fix: get() must never return nullptr. On first-call fetcher
    // exception, callers receive an empty TopologySnapshot rather than
    // nullptr so PR 3's REST handler can serialise without null-check.
    std::atomic<int> calls{0};
    auto fetcher = [&calls](std::chrono::milliseconds) -> std::vector<RawAgentSnapshot> {
        ++calls;
        throw std::runtime_error("boom");
    };
    FleetTopologyStore store(fetcher, nullptr, std::chrono::seconds(60));

    auto snap = store.get(false);
    REQUIRE(snap != nullptr);
    CHECK(snap->machines.empty());
    CHECK(snap->generated_at != 0);
    CHECK(calls.load() == 1);
    // Subsequent get() should also retry (slot empty, treat as miss).
    auto snap2 = store.get(false);
    REQUIRE(snap2 != nullptr);
    CHECK(snap2->machines.empty());
    CHECK(calls.load() == 2);
}

// =============================================================================
// New tests added in governance round 1
// =============================================================================

TEST_CASE("topology: agent self-connection classified as External, not Internal",
          "[viz][topology][self]") {
    // QE-S3 — connection from a host to one of its own non-loopback IPs
    // should not be a fleet edge.
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.connections.push_back(conn("tcp", "10.0.0.7", 50000, "10.0.0.7", 8080));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    REQUIRE(snap->machines.at(0).connections.size() == 1);
    CHECK(snap->machines[0].connections[0].scope == EdgeScope::External);
    CHECK(snap->machines[0].connections[0].dst_agent_id.empty());
}

TEST_CASE("topology: link-local IPs in local_ips are skipped from ip_to_agent",
          "[viz][topology][defence]") {
    // cons-N3 — defence-in-depth: malformed agent emitting 169.254.x.x or
    // fe80::* in local_ips must not seed cross-machine resolution.
    auto a = make_agent("agent-A", "hostA", {"169.254.1.5", "fe80::abcd", "10.0.0.7"});
    auto b = make_agent("agent-B", "hostB", {"10.0.0.42"});
    b.connections.push_back(conn("tcp", "10.0.0.42", 50000, "169.254.1.5", 5432));
    b.connections.push_back(conn("tcp6", "fd00::2", 50001, "fe80::abcd", 5432));

    FleetTopologyStore store(fixed_fetcher({a, b}));
    auto snap = store.get(false);
    auto& edges = snap->machines[1].connections;
    REQUIRE(edges.size() == 2);
    CHECK(edges[0].scope == EdgeScope::External);
    CHECK(edges[0].dst_agent_id.empty());
    CHECK(edges[1].scope == EdgeScope::External);
    CHECK(edges[1].dst_agent_id.empty());
}

TEST_CASE("topology: IPv6 bracketed and zone-id forms normalized for ip_to_agent lookup",
          "[viz][topology][ipv6]") {
    // UP-7 — agent A reports `fd00::1`; agent B's connection lists
    // `[fd00::1]:443` (bracket form) or `fd00::1%eth0` (zone-id). All three
    // must resolve to the same canonical key.
    auto a = make_agent("agent-A", "hostA", {"fd00::1"});
    auto b = make_agent("agent-B", "hostB", {"fd00::2"});
    b.connections.push_back(conn("tcp6", "fd00::2", 50000, "[fd00::1]", 443));
    b.connections.push_back(conn("tcp6", "fd00::2", 50001, "fd00::1%eth0", 443));

    FleetTopologyStore store(fixed_fetcher({a, b}));
    auto snap = store.get(false);
    auto& edges = snap->machines[1].connections;
    REQUIRE(edges.size() == 2);
    CHECK(edges[0].scope == EdgeScope::InternalFleet);
    CHECK(edges[0].dst_agent_id == "agent-A");
    CHECK(edges[1].scope == EdgeScope::InternalFleet);
    CHECK(edges[1].dst_agent_id == "agent-A");
}

// =============================================================================
// PR 6 / OBS-2: fetch-duration observer
// =============================================================================

TEST_CASE("observer: set_fetch_duration_observer fires once per refill", "[viz][cache][obs]") {
    // OBS-2 — every cache miss observer call lets server.cpp wire the
    // fetch into a Prometheus histogram. Cache hits MUST NOT fire (the
    // fetcher didn't run).
    std::atomic<int> observer_calls{0};
    std::atomic<int> fetcher_calls{0};
    auto a = make_agent("agent-A", "hostA", {});
    auto fetcher = [&fetcher_calls, a](std::chrono::milliseconds) {
        ++fetcher_calls;
        return std::vector<RawAgentSnapshot>{a};
    };
    // gov R6 QE SHOULD-4: the original 50ms TTL + 80ms sleep was a
    // 1.6× ratio — flake-prone on slow CI runners (e.g. Defender-throttled
    // Windows under #473). Match the established 1ms TTL + 10ms sleep
    // pattern from the sibling `cache: short TTL expires and triggers
    // refill` test (10× ratio).
    FleetTopologyStore store(fetcher, nullptr, std::chrono::milliseconds(1));
    store.set_fetch_duration_observer(
        [&observer_calls](std::chrono::duration<double>) { ++observer_calls; });

    // First get: cache miss -> fetcher runs -> observer fires.
    auto s1 = store.get(false);
    REQUIRE(s1 != nullptr);
    CHECK(observer_calls.load() == 1);
    CHECK(fetcher_calls.load() == 1);

    // gov R6: a get() within 1ms TTL is a coin-flip on slow CI -- the
    // sibling test takes the same approach of immediately invalidating
    // for the cache-hit assertion to be deterministic. Use a fresh
    // store with longer TTL just for the cache-hit branch.
    FleetTopologyStore store_long(fetcher, nullptr, std::chrono::seconds(60));
    std::atomic<int> long_observer_calls{0};
    std::atomic<int> long_fetcher_calls{0};
    auto fetcher_long = [&long_fetcher_calls, a](std::chrono::milliseconds) {
        ++long_fetcher_calls;
        return std::vector<RawAgentSnapshot>{a};
    };
    FleetTopologyStore store_long2(fetcher_long, nullptr, std::chrono::seconds(60));
    store_long2.set_fetch_duration_observer(
        [&long_observer_calls](std::chrono::duration<double>) { ++long_observer_calls; });
    auto sl1 = store_long2.get(false);
    REQUIRE(sl1 != nullptr);
    CHECK(long_observer_calls.load() == 1);
    auto sl2 = store_long2.get(false);
    REQUIRE(sl2 != nullptr);
    CHECK(long_observer_calls.load() == 1); // cache hit, observer NOT fired
    CHECK(long_fetcher_calls.load() == 1);

    // Force expiry on the short-TTL store, third get: refill -> observer fires again.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto s3 = store.get(false);
    REQUIRE(s3 != nullptr);
    CHECK(observer_calls.load() == 2);
    CHECK(fetcher_calls.load() == 2);
}

TEST_CASE("observer: fetch-duration observer fires even on fetcher exception",
          "[viz][cache][obs]") {
    // OBS-2 — a hung / throwing fetcher must still produce a histogram
    // observation; otherwise the gate that says "agent dispatch is slow"
    // would silently miss the worst case.
    std::atomic<int> observer_calls{0};
    auto fetcher = [](std::chrono::milliseconds) -> std::vector<RawAgentSnapshot> {
        throw std::runtime_error("boom");
    };
    FleetTopologyStore store(fetcher);
    store.set_fetch_duration_observer(
        [&observer_calls](std::chrono::duration<double>) { ++observer_calls; });

    auto snap = store.get(false);
    REQUIRE(snap != nullptr); // empty sentinel, never null
    CHECK(observer_calls.load() == 1);
}

TEST_CASE("observer: cleared observer is not invoked", "[viz][cache][obs]") {
    // Setting an empty std::function clears the observer slot. The
    // refill path must check before calling.
    std::atomic<int> observer_calls{0};
    auto a = make_agent("agent-A", "hostA", {});
    FleetTopologyStore store(fixed_fetcher({a}));
    store.set_fetch_duration_observer(
        [&observer_calls](std::chrono::duration<double>) { ++observer_calls; });
    auto s1 = store.get(false);
    REQUIRE(s1 != nullptr);
    CHECK(observer_calls.load() == 1);

    store.set_fetch_duration_observer(FleetTopologyStore::FetchDurationObserver{});
    store.invalidate();
    auto s2 = store.get(false);
    REQUIRE(s2 != nullptr);
    CHECK(observer_calls.load() == 1); // not incremented
}

// =============================================================================
// (existing) cache: oversized snapshot
// =============================================================================

TEST_CASE("cache: oversized snapshot is returned but not cached", "[viz][cache][cap]") {
    // CAP-1 — when a refill exceeds max_snapshot_bytes, the caller still
    // receives the snapshot for this request, but the cache slot is NOT
    // populated (next get() refills from scratch).
    std::atomic<int> calls{0};
    auto a = make_agent("agent-A", "hostA", {});
    for (int i = 0; i < 100; ++i)
        a.processes.push_back(proc(static_cast<uint32_t>(i), 1, "p", "u"));
    auto fetcher = [&calls, a](std::chrono::milliseconds) {
        ++calls;
        return std::vector<RawAgentSnapshot>{a};
    };
    // Set max_snapshot_bytes very low so the realistic snapshot blows past it.
    FleetTopologyStore store(fetcher, nullptr, std::chrono::seconds(60),
                             std::chrono::milliseconds(5000), /*max_snapshot_bytes=*/256);

    auto snap1 = store.get(false);
    REQUIRE(snap1 != nullptr);
    REQUIRE(snap1->machines.size() == 1);
    CHECK(calls.load() == 1);

    // Second call should NOT be a cache hit -- slot was refused due to size.
    auto snap2 = store.get(false);
    REQUIRE(snap2 != nullptr);
    CHECK(calls.load() == 2);
    CHECK(store.refill_oversize_drops() >= 2);
}
