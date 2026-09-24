/// HA WS-8 (ADR-2002 §12): `/readyz`'s runtime Postgres-reachability signal —
/// the pure rule (pg_reachability_rules.hpp), the probe's publication/loop
/// contract with an injected ping, the real libpq probe's client-side deadlines
/// against a peer that never answers, and the real probe against Postgres
/// (terminated backend, simulated standby, unreachable port). Plus the pure
/// drain-wait rule behind `--shutdown-drain-seconds` (shutdown_drain_rules.hpp).

#include "pg_reachability_probe.hpp"
#include "pg_reachability_rules.hpp"
#include "shutdown_drain_rules.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <string>
#include <thread>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace yuzu::server;
namespace pr = yuzu::server::pg_reachability;
using namespace std::chrono_literals;

namespace {

constexpr std::int64_t ns(std::chrono::nanoseconds d) {
    return d.count();
}

using PingResult = PgReachabilityProbe::PingResult;
using Kind = PingResult::Kind;

/// A ping whose next outcome the test sets.
struct ScriptedPing {
    std::atomic<int> kind{static_cast<int>(Kind::Ok)};
    std::atomic<int> calls{0};
    PgReachabilityProbe::PingFn fn() {
        return [this](const std::atomic<bool>&) {
            ++calls;
            return PingResult{static_cast<Kind>(kind.load()), "scripted"};
        };
    }
    void set(Kind k) { kind.store(static_cast<int>(k)); }
};

/// Append `key=value` to a libpq DSN, keyword or URI form.
std::string dsn_with(const std::string& dsn, const std::string& key, const std::string& value) {
    const bool uri = dsn.rfind("postgres://", 0) == 0 || dsn.rfind("postgresql://", 0) == 0;
    if (uri)
        return dsn + (dsn.find('?') == std::string::npos ? "?" : "&") + key + "=" + value;
    return dsn + " " + key + "=" + value;
}

/// Backends connected to the test database under `app` (excluding the caller).
int count_backends(const std::string& admin_dsn, const std::string& app) {
    PGconn* c = PQconnectdb(admin_dsn.c_str());
    int n = -1;
    if (PQstatus(c) == CONNECTION_OK) {
        const char* params[] = {app.c_str()};
        PGresult* r = PQexecParams(c,
                                   "SELECT count(*) FROM pg_stat_activity WHERE datname = "
                                   "current_database() AND application_name = $1 AND pid <> "
                                   "pg_backend_pid()",
                                   1, nullptr, params, nullptr, nullptr, 0);
        if (PQresultStatus(r) == PGRES_TUPLES_OK)
            n = std::stoi(PQgetvalue(r, 0, 0));
        PQclear(r);
    }
    PQfinish(c);
    return n;
}

int wait_for_backends(const std::string& admin_dsn, const std::string& app, int want) {
    int n = -1;
    for (int i = 0; i < 50; ++i) { // ≤5s: backend exit after a client close is asynchronous
        n = count_backends(admin_dsn, app);
        if (n == want)
            break;
        std::this_thread::sleep_for(100ms);
    }
    return n;
}

} // namespace

// ---------------------------------------------------------------------------
// The pure rule
// ---------------------------------------------------------------------------

TEST_CASE("pg_reachability rule: verdict table", "[server][readyz][pg_reachability]") {
    const std::int64_t t0 = ns(1000s);
    pr::Snapshot s;

    SECTION("nothing probed yet is NotYetProbed (not ready)") {
        CHECK(pr::classify(s, t0) == pr::Verdict::NotYetProbed);
    }
    SECTION("a failure before any success is Unreachable") {
        s.consecutive_failures = 1;
        s.last_failure = pr::FailureKind::Unreachable;
        CHECK(pr::classify(s, t0) == pr::Verdict::Unreachable);
    }
    SECTION("a fresh success is Ready") {
        s.last_success_ns = t0;
        CHECK(pr::classify(s, t0 + ns(1s)) == pr::Verdict::Ready);
    }
    SECTION("ONE unreachable failure after a success stays Ready (a blip)") {
        s.last_success_ns = t0;
        s.consecutive_failures = 1;
        s.last_failure = pr::FailureKind::Unreachable;
        CHECK(pr::classify(s, t0 + ns(3s)) == pr::Verdict::Ready);
    }
    SECTION("kFailThreshold consecutive failures is Unreachable") {
        s.last_success_ns = t0;
        s.consecutive_failures = pr::kFailThreshold;
        s.last_failure = pr::FailureKind::Unreachable;
        CHECK(pr::classify(s, t0 + ns(5s)) == pr::Verdict::Unreachable);
    }
    SECTION("ReadOnly is immediate — one observation") {
        s.last_success_ns = t0;
        s.consecutive_failures = 1;
        s.last_failure = pr::FailureKind::ReadOnly;
        CHECK(pr::classify(s, t0 + ns(1s)) == pr::Verdict::ReadOnly);
    }
    SECTION("no success within kStaleAfter is Stale, even with no failure counted") {
        // A tick that never completes (wedged outside the probe's deadlines):
        // the counter never advances, so staleness is what turns /readyz red.
        s.last_success_ns = t0;
        CHECK(pr::classify(s, t0 + ns(pr::kStaleAfter)) == pr::Verdict::Ready);
        CHECK(pr::classify(s, t0 + ns(pr::kStaleAfter) + 1) == pr::Verdict::Stale);
    }
    SECTION("a clock reading before the last success does not overflow into Stale") {
        s.last_success_ns = t0;
        CHECK(pr::classify(s, t0 - ns(1s)) == pr::Verdict::Ready);
    }
}

TEST_CASE("pg_reachability rule: the timing budget never reds a healthy replica",
          "[server][readyz][pg_reachability]") {
    // The longest healthy gap between two successes is one full interval plus
    // a tick that uses its whole connect and query deadlines. It must sit
    // inside kStaleAfter, or a slow-but-healthy replica flaps.
    STATIC_REQUIRE(pr::kProbeInterval + pr::kConnectDeadline + pr::kQueryDeadline <
                   pr::kStaleAfter);
    STATIC_REQUIRE(pr::kFailThreshold >= 2);
}

TEST_CASE("pg_reachability rule: reason tokens are stable and carry no detail",
          "[server][readyz][pg_reachability]") {
    CHECK(std::string(pr::reason(pr::Verdict::Ready)) == "ok");
    CHECK(std::string(pr::reason(pr::Verdict::NotYetProbed)) == "not_yet_probed");
    CHECK(std::string(pr::reason(pr::Verdict::Unreachable)) == "unreachable");
    CHECK(std::string(pr::reason(pr::Verdict::ReadOnly)) == "read_only");
    CHECK(std::string(pr::reason(pr::Verdict::Stale)) == "stale");
}

// ---------------------------------------------------------------------------
// The drain rule
// ---------------------------------------------------------------------------

TEST_CASE("shutdown drain rule: minimum grace, then the execution cap",
          "[server][readyz][shutdown_drain]") {
    using shutdown_drain::keep_draining;
    using shutdown_drain::kExecutionDrainCap;

    SECTION("default grace 0 with nothing running stops immediately (unchanged behaviour)") {
        CHECK_FALSE(keep_draining(0s, 0s, false));
    }
    SECTION("a grace holds even with nothing running") {
        CHECK(keep_draining(0s, 10s, false));
        CHECK(keep_draining(9s, 10s, false));
        CHECK_FALSE(keep_draining(10s, 10s, false));
    }
    SECTION("running executions extend past the grace, up to the cap") {
        CHECK(keep_draining(12s, 10s, true));
        CHECK(keep_draining(kExecutionDrainCap - 1s, 0s, true));
        CHECK_FALSE(keep_draining(kExecutionDrainCap, 0s, true));
    }
    SECTION("a grace longer than the cap is honoured whether or not work is running") {
        CHECK(keep_draining(45s, 50s, true));
        CHECK(keep_draining(45s, 50s, false));
        CHECK_FALSE(keep_draining(50s, 50s, true));
    }
    SECTION("the flag's cap fits the shipped 210s stop budget") {
        // docs/user-manual/upgrading.md's ~115s stacked worst case already
        // INCLUDES the 30s execution drain (30 + 5 gRPC + 5 NVD + 15 web thread
        // + 60 delivery queues). The drain grace replaces that first stage with
        // max(N, 30), so the stack becomes max(N, 30) + 85, which must fit the
        // shipped compose/systemd 210s grace.
        constexpr int kFirstStage = std::max<int>(shutdown_drain::kMaxShutdownDrainSeconds,
                                                  static_cast<int>(kExecutionDrainCap.count()));
        constexpr int kCap = static_cast<int>(kExecutionDrainCap.count());
        STATIC_REQUIRE(kFirstStage + (115 - kCap) <= 210);
        // ... and the rare thread-exhaustion fallback path's documented ~175s
        // (docs/user-manual/server-admin.md) — the tight one: 205s at N = 60.
        STATIC_REQUIRE(kFirstStage + (175 - kCap) <= 210);
    }
}

// ---------------------------------------------------------------------------
// The probe with an injected ping
// ---------------------------------------------------------------------------

TEST_CASE("PgReachabilityProbe: publication follows the ping outcomes",
          "[server][readyz][pg_reachability]") {
    ScriptedPing ping;
    int failures_seen = 0;
    PgReachabilityProbe probe(ping.fn(), {.on_failure = [&] { ++failures_seen; }});

    CHECK(probe.verdict() == pr::Verdict::NotYetProbed);

    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::Ready);

    ping.set(Kind::Failed);
    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::Ready); // one blip
    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::Unreachable);
    CHECK(failures_seen == 2);

    ping.set(Kind::Ok);
    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::Ready); // one success recovers

    ping.set(Kind::ReadOnly);
    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::ReadOnly); // immediate
    CHECK(failures_seen == 3);

    ping.set(Kind::Ok);
    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::Ready);
    CHECK(probe.snapshot().consecutive_failures == 0);
    CHECK(probe.snapshot().last_failure == pr::FailureKind::None);
}

TEST_CASE("PgReachabilityProbe: a success older than kStaleAfter reads Stale",
          "[server][readyz][pg_reachability]") {
    ScriptedPing ping;
    PgReachabilityProbe probe(ping.fn());
    probe.probe_once();
    const auto now = PgReachabilityProbe::now_ns();
    CHECK(probe.verdict_at(now) == pr::Verdict::Ready);
    CHECK(probe.verdict_at(now + ns(pr::kStaleAfter) + ns(1s)) == pr::Verdict::Stale);
}

TEST_CASE("PgReachabilityProbe: a throwing ping counts as a failure, never escapes",
          "[server][readyz][pg_reachability]") {
    PgReachabilityProbe probe(
        [](const std::atomic<bool>&) -> PingResult { throw std::runtime_error("boom"); });
    probe.probe_once();
    probe.probe_once();
    CHECK(probe.verdict() == pr::Verdict::Unreachable);
}

TEST_CASE("PgReachabilityProbe: the loop probes on its interval and stop() is prompt and sticky",
          "[server][readyz][pg_reachability]") {
    ScriptedPing ping;
    PgReachabilityProbe probe(ping.fn(), {}, 20ms);
    probe.start();
    for (int i = 0; i < 200 && ping.calls.load() < 3; ++i)
        std::this_thread::sleep_for(10ms);
    CHECK(ping.calls.load() >= 3);
    CHECK(probe.verdict() == pr::Verdict::Ready);

    const auto t = std::chrono::steady_clock::now();
    probe.stop();
    CHECK(std::chrono::steady_clock::now() - t < 1s);

    const int after = ping.calls.load();
    probe.start(); // sticky: no restart after stop
    std::this_thread::sleep_for(100ms);
    CHECK(ping.calls.load() == after);
    probe.stop(); // idempotent
}

TEST_CASE("PgReachabilityProbe: stop() interrupts a ping blocked past its deadline",
          "[server][readyz][pg_reachability]") {
    // A ping that honours the stop flag but would otherwise block for 30s — the
    // shape of the real probe against a frozen backend.
    std::atomic<bool> entered{false};
    PgReachabilityProbe probe(
        [&](const std::atomic<bool>& stop) {
            entered = true;
            for (int i = 0; i < 3000 && !stop.load(); ++i)
                std::this_thread::sleep_for(10ms);
            return PingResult{Kind::Failed, "stopped"};
        },
        {}, 10ms);
    probe.start();
    for (int i = 0; i < 200 && !entered.load(); ++i)
        std::this_thread::sleep_for(10ms);
    REQUIRE(entered.load());

    const auto t = std::chrono::steady_clock::now();
    probe.stop();
    CHECK(std::chrono::steady_clock::now() - t < 1s);
    // A probe cut short by stop() publishes nothing.
    CHECK(probe.verdict() == pr::Verdict::NotYetProbed);
}

// ---------------------------------------------------------------------------
// The real libpq probe — no Postgres needed
// ---------------------------------------------------------------------------

TEST_CASE("PgReachabilityProbe (libpq): a refused port is Unreachable after the threshold",
          "[server][readyz][pg_reachability]") {
    // Port 1 on loopback: nothing listens, so connect is refused at once.
    auto probe = PgReachabilityProbe::make_libpq(
        "host=127.0.0.1 port=1 dbname=yuzu user=yuzu connect_timeout=2");
    const auto t = std::chrono::steady_clock::now();
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::Unreachable); // never succeeded
    probe->probe_once();
    CHECK(probe->snapshot().consecutive_failures == 2);
    CHECK(std::chrono::steady_clock::now() - t < pr::kConnectDeadline);
}

#ifndef _WIN32
namespace {
/// A TCP listener that completes the handshake (kernel backlog) and then never
/// reads or writes — a peer that ACKs but never answers, like a paused primary.
struct SilentListener {
    int fd{-1};
    int port{0};
    SilentListener() {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0; // ephemeral — salted per process, safe on shared CI runners
        ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        ::listen(fd, 8);
        socklen_t len = sizeof(a);
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len);
        port = ntohs(a.sin_port);
    }
    ~SilentListener() {
        if (fd >= 0)
            ::close(fd);
    }
    std::string dsn() const {
        return "host=127.0.0.1 port=" + std::to_string(port) + " dbname=yuzu user=yuzu";
    }
};
} // namespace

TEST_CASE("PgReachabilityProbe (libpq): a peer that never answers fails at the connect "
          "deadline, not the OS timeout",
          "[server][readyz][pg_reachability]") {
    SilentListener peer;
    REQUIRE(peer.port > 0);
    auto probe = PgReachabilityProbe::make_libpq(peer.dsn());
    const auto t = std::chrono::steady_clock::now();
    probe->probe_once();
    const auto took = std::chrono::steady_clock::now() - t;
    CHECK(took >= pr::kConnectDeadline - 100ms);
    CHECK(took < pr::kConnectDeadline + 2s);
    CHECK(probe->snapshot().consecutive_failures == 1);
}

TEST_CASE("PgReachabilityProbe (libpq): stop() returns promptly while a connect is stuck",
          "[server][readyz][pg_reachability]") {
    SilentListener peer;
    REQUIRE(peer.port > 0);
    auto probe = PgReachabilityProbe::make_libpq(peer.dsn());
    probe->start(); // the loop's first tick blocks in the connect wait
    std::this_thread::sleep_for(300ms);
    const auto t = std::chrono::steady_clock::now();
    probe->stop();
    CHECK(std::chrono::steady_clock::now() - t < 1s);
}
#endif

// ---------------------------------------------------------------------------
// The real libpq probe against Postgres
// ---------------------------------------------------------------------------

TEST_CASE("PgReachabilityProbe (libpq, pg): a reachable primary is Ready and keeps one connection",
          "[server][readyz][pg_reachability][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    const std::string app = "yuzu_ws8_probe_ok";
    auto probe = PgReachabilityProbe::make_libpq(dsn_with(db.dsn(), "application_name", app));
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::Ready);
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::Ready);
    // One dedicated connection, reused across ticks.
    CHECK(wait_for_backends(db.dsn(), app, 1) == 1);
}

TEST_CASE("PgReachabilityProbe (libpq, pg): a terminated backend is one blip, then a reconnect",
          "[server][readyz][pg_reachability][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    const std::string app = "yuzu_ws8_probe_blip";
    auto probe = PgReachabilityProbe::make_libpq(dsn_with(db.dsn(), "application_name", app));
    probe->probe_once();
    REQUIRE(probe->verdict() == pr::Verdict::Ready);

    {
        PGconn* admin = PQconnectdb(db.dsn().c_str());
        REQUIRE(PQstatus(admin) == CONNECTION_OK);
        const char* params[] = {app.c_str()};
        PGresult* r = PQexecParams(admin,
                                   "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                                   "WHERE application_name = $1",
                                   1, nullptr, params, nullptr, nullptr, 0);
        CHECK(PQresultStatus(r) == PGRES_TUPLES_OK);
        PQclear(r);
        PQfinish(admin);
    }
    REQUIRE(wait_for_backends(db.dsn(), app, 0) == 0);

    probe->probe_once(); // the dead session fails ...
    CHECK(probe->snapshot().consecutive_failures == 1);
    CHECK(probe->verdict() == pr::Verdict::Ready); // ... below the threshold
    probe->probe_once();                           // ... and the next tick reconnects
    CHECK(probe->verdict() == pr::Verdict::Ready);
    CHECK(probe->snapshot().consecutive_failures == 0);
}

TEST_CASE("PgReachabilityProbe (libpq, pg): reaching a standby is ReadOnly AND drops the "
          "connection so the next tick re-resolves",
          "[server][readyz][pg_reachability][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    const std::string app = "yuzu_ws8_probe_standby";
    // `SELECT true` stands in for pg_is_in_recovery() on a standby.
    auto probe = PgReachabilityProbe::make_libpq(dsn_with(db.dsn(), "application_name", app), {},
                                                 "SELECT true");
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::ReadOnly);
    // Not pinned to the demoted node: no connection is held between ticks.
    CHECK(wait_for_backends(db.dsn(), app, 0) == 0);
    probe->probe_once(); // reconnects, still a "standby"
    CHECK(probe->verdict() == pr::Verdict::ReadOnly);
    CHECK(wait_for_backends(db.dsn(), app, 0) == 0);
}
