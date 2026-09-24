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
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <atomic>
#include <chrono>
#include <stdexcept>
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

/// Run one parameterised statement on a fresh admin connection; RAII-owned
/// (pg::PgConn / pg::PgResult), so a throwing assertion cannot leak either.
/// Returns the first cell, or nullopt on any failure.
std::optional<std::string> admin_scalar(const std::string& admin_dsn, const char* sql,
                                        const std::string& param) {
    yuzu::server::pg::PgConn c{PQconnectdb(admin_dsn.c_str())};
    if (PQstatus(c.get()) != CONNECTION_OK)
        return std::nullopt;
    const char* params[] = {param.c_str()};
    yuzu::server::pg::PgResult r{
        PQexecParams(c.get(), sql, 1, nullptr, params, nullptr, nullptr, 0)};
    if (r.status() != PGRES_TUPLES_OK && r.status() != PGRES_COMMAND_OK)
        return std::nullopt;
    if (PQntuples(r.get()) < 1 || PQnfields(r.get()) < 1)
        return std::string{};
    return std::string(PQgetvalue(r.get(), 0, 0));
}

/// Backends connected to the test database under `app` (excluding the caller).
int count_backends(const std::string& admin_dsn, const std::string& app) {
    const auto v = admin_scalar(admin_dsn,
                                "SELECT count(*) FROM pg_stat_activity WHERE datname = "
                                "current_database() AND application_name = $1 AND pid <> "
                                "pg_backend_pid()",
                                app);
    return v && !v->empty() ? std::stoi(*v) : -1;
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
    // Refused, not timed out: well inside two deadlines even where the OS retries
    // a refused loopback SYN (Windows, ~2s per attempt).
    CHECK(std::chrono::steady_clock::now() - t < 2 * pr::kConnectDeadline);
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
    CHECK(took < pr::kConnectDeadline + 5s); // slack for sanitizer / contended CI legs
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

    REQUIRE(admin_scalar(db.dsn(),
                         "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
                         "WHERE application_name = $1 AND datname = current_database()",
                         app)
                .has_value());
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
    // Not pinned to a standby: no connection is held between ticks.
    CHECK(wait_for_backends(db.dsn(), app, 0) == 0);
    probe->probe_once(); // reconnects, still a "standby"
    CHECK(probe->verdict() == pr::Verdict::ReadOnly);
    CHECK(wait_for_backends(db.dsn(), app, 0) == 0);
}

TEST_CASE("PgReachabilityProbe (libpq, pg): a primary with default_transaction_read_only is "
          "ReadOnly",
          "[server][readyz][pg_reachability][pg]") {
    // Managed Postgres flips this on a full disk: not in recovery, yet refuses
    // writes — the probe must not call it writable (Gate 4 UP-4).
    YUZU_REQUIRE_PG_DB(db);
    const std::string app = "yuzu_ws8_probe_ro_primary";
    {
        yuzu::server::pg::PgConn c{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
        const std::string dbname = PQdb(c.get());
        yuzu::server::pg::PgResult r{PQexec(
            c.get(),
            ("ALTER DATABASE \"" + dbname + "\" SET default_transaction_read_only = on").c_str())};
        REQUIRE(r.status() == PGRES_COMMAND_OK);
    }
    auto probe = PgReachabilityProbe::make_libpq(dsn_with(db.dsn(), "application_name", app));
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::ReadOnly);
    CHECK(wait_for_backends(db.dsn(), app, 0) == 0); // dropped, re-resolves next tick
}

TEST_CASE("PgReachabilityProbe (libpq, pg): a query that outlives kQueryDeadline fails at the "
          "deadline on the real query path",
          "[server][readyz][pg_reachability][pg]") {
    // The frozen-after-connect shape the probe exists for: the connection is up,
    // the reply never comes in time. pg_sleep stands in for a frozen backend.
    YUZU_REQUIRE_PG_DB(db);
    const std::string app = "yuzu_ws8_probe_slow";
    auto probe = PgReachabilityProbe::make_libpq(dsn_with(db.dsn(), "application_name", app), {},
                                                 "SELECT pg_sleep(30)");
    const auto t = std::chrono::steady_clock::now();
    probe->probe_once();
    const auto took = std::chrono::steady_clock::now() - t;
    CHECK(took >= pr::kQueryDeadline - 100ms);
    CHECK(took < pr::kQueryDeadline + 5s);
    CHECK(probe->snapshot().consecutive_failures == 1);
    // The busy connection is dropped, never reused: the next tick opens a FRESH
    // backend. (The first backend lingers server-side, still sleeping, until it
    // next writes to its closed socket — so the proof is a second backend, not zero.)
    probe->probe_once();
    CHECK(probe->snapshot().consecutive_failures == 2);
    CHECK(wait_for_backends(db.dsn(), app, 2) == 2);
}

TEST_CASE("PgReachabilityProbe (libpq, pg): stop() interrupts a real in-flight query promptly",
          "[server][readyz][pg_reachability][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    auto probe = PgReachabilityProbe::make_libpq(
        dsn_with(db.dsn(), "application_name", "yuzu_ws8_probe_stopq"), {}, "SELECT pg_sleep(30)");
    probe->start();
    // Wait until the probe's query is actually running server-side, so stop()
    // lands in the QUERY wait, not the connect wait.
    bool active = false;
    for (int i = 0; i < 100 && !active; ++i) {
        const auto n = admin_scalar(db.dsn(),
                                    "SELECT count(*) FROM pg_stat_activity WHERE "
                                    "application_name = $1 AND state = 'active'",
                                    "yuzu_ws8_probe_stopq");
        active = n && *n == "1";
        if (!active)
            std::this_thread::sleep_for(100ms);
    }
    REQUIRE(active);
    const auto t = std::chrono::steady_clock::now();
    probe->stop();
    CHECK(std::chrono::steady_clock::now() - t < 1s);
}

TEST_CASE("PgReachabilityProbe (libpq, pg): the probe tags its connection unless the DSN names one",
          "[server][readyz][pg_reachability][pg]") {
    YUZU_REQUIRE_PG_DB(db);
    auto probe = PgReachabilityProbe::make_libpq(db.dsn());
    probe->probe_once();
    REQUIRE(probe->verdict() == pr::Verdict::Ready);
    CHECK(wait_for_backends(db.dsn(), "yuzu-readyz-probe", 1) == 1);
}

#ifndef _WIN32
namespace {
/// The test database's own keyword DSN with `host`/`port` replaced by lists.
std::string multi_host_dsn(const std::string& dsn, const std::string& hosts,
                           const std::string& ports) {
    char* err = nullptr;
    std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)> opts(
        PQconninfoParse(dsn.c_str(), &err), &PQconninfoFree);
    const std::unique_ptr<char, decltype(&PQfreemem)> err_owner(err, &PQfreemem);
    // Keyword-DSN quoting: a value is single-quoted, and ' and \ inside it are
    // backslash-escaped (libpq conninfo syntax).
    auto quote = [](const char* v) {
        std::string q = "'";
        for (const char* c = v; *c; ++c) {
            if (*c == '\'' || *c == '\\')
                q += '\\';
            q += *c;
        }
        return q + "'";
    };
    std::string out = "host=" + hosts + " port=" + ports;
    for (const PQconninfoOption* o = opts.get(); o && o->keyword; ++o) {
        const std::string k = o->keyword;
        if (!o->val || k == "host" || k == "hostaddr" || k == "port")
            continue;
        out += " " + k + "=" + quote(o->val);
    }
    return out;
}
} // namespace

TEST_CASE("PgReachabilityProbe (libpq, pg): a frozen FIRST host of a multi-host DSN costs one "
          "deadline, then the next host serves",
          "[server][readyz][pg_reachability][pg]") {
    // Gate 4 UP-1: libpq's non-blocking connect never advances past a host that
    // accepts TCP and goes silent; the probe splits the list itself.
    YUZU_REQUIRE_PG_DB(db);
    SilentListener frozen;
    REQUIRE(frozen.port > 0);
    char* err = nullptr;
    std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)> opts(
        PQconninfoParse(db.dsn().c_str(), &err), &PQconninfoFree);
    const std::unique_ptr<char, decltype(&PQfreemem)> err_owner(err, &PQfreemem);
    REQUIRE(opts);
    std::string pg_host = "localhost", pg_port = "5432";
    for (const PQconninfoOption* o = opts.get(); o->keyword; ++o) {
        if (o->val && std::string(o->keyword) == "host")
            pg_host = o->val;
        if (o->val && std::string(o->keyword) == "port")
            pg_port = o->val;
    }
    const std::string dsn = multi_host_dsn(db.dsn(), "127.0.0.1," + pg_host,
                                           std::to_string(frozen.port) + "," + pg_port);
    auto probe = PgReachabilityProbe::make_libpq(dsn);
    const auto t = std::chrono::steady_clock::now();
    probe->probe_once();
    const auto took = std::chrono::steady_clock::now() - t;
    CHECK(probe->verdict() == pr::Verdict::Ready);
    CHECK(took >= pr::kConnectDeadline - 100ms); // paid the frozen host's deadline once
    CHECK(took < pr::kConnectDeadline + 5s);
    // The connection is now held on the second host: the next tick is fast.
    const auto t2 = std::chrono::steady_clock::now();
    probe->probe_once();
    CHECK(probe->verdict() == pr::Verdict::Ready);
    CHECK(std::chrono::steady_clock::now() - t2 < 1s);

    // A RECONNECT starts from the host that last worked (Gate 8): kill the probe's
    // backend; the next tick fails on the dead session, the one after reconnects
    // straight to the second host — no second payment of the frozen host's deadline.
    REQUIRE(admin_scalar(db.dsn(),
                         "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
                         "WHERE application_name = $1 AND datname = current_database()",
                         "yuzu-readyz-probe")
                .has_value());
    REQUIRE(wait_for_backends(db.dsn(), "yuzu-readyz-probe", 0) == 0);
    probe->probe_once(); // dead session → one failure
    const auto t3 = std::chrono::steady_clock::now();
    probe->probe_once(); // reconnect
    CHECK(probe->verdict() == pr::Verdict::Ready);
    CHECK(std::chrono::steady_clock::now() - t3 < pr::kConnectDeadline - 1s);
}
#endif
