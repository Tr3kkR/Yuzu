#ifdef _WIN32
// windows.h defines function-like min()/max() macros that break
// std::numeric_limits<...>::min() (pg_reachability_rules.hpp) — the same guard
// server.cpp and key_provider.cpp carry. Must come before the first Windows header.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <winsock2.h>  // must precede windows.h to avoid redefinition
#include <windows.h>
// clang-format on
#else
#include <cerrno>
#include <poll.h>
#endif

#include "pg_reachability_probe.hpp"

#include "background_jobs.hpp"
#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

using Clock = std::chrono::steady_clock;
namespace pr = pg_reachability;

/// Longest single poll() slice, so `stop` is noticed promptly mid-wait.
constexpr std::chrono::milliseconds kPollSlice{200};

/// Set on the probe's connection unless the DSN names one, so the probe's
/// backend is identifiable in pg_stat_activity.
constexpr const char* kProbeApplicationName = "yuzu-readyz-probe";

enum class Want { Read, Write };

/// Wait until `sock` is ready for `want`, the deadline passes, or `stop` is
/// set. Returns true only when the socket is ready (an error/hangup condition
/// counts as ready: the next libpq call surfaces it).
bool wait_socket(int sock, Want want, Clock::time_point deadline, const std::atomic<bool>& stop) {
    if (sock < 0)
        return false; // no socket (connection already failed); poll() would ignore it and spin
    for (;;) {
        if (stop.load(std::memory_order_acquire))
            return false;
        const auto now = Clock::now();
        if (now >= deadline)
            return false;
        const auto slice = std::min<Clock::duration>(deadline - now, kPollSlice);
        const int timeout_ms = static_cast<int>(
            std::max<std::int64_t>(1, std::chrono::ceil<std::chrono::milliseconds>(slice).count()));
#ifdef _WIN32
        WSAPOLLFD pfd{};
        pfd.fd = static_cast<SOCKET>(sock);
        pfd.events = static_cast<SHORT>(want == Want::Read ? POLLRDNORM : POLLWRNORM);
        const int rc = WSAPoll(&pfd, 1, timeout_ms);
        if (rc > 0)
            return true;
        if (rc < 0)
            return false;
#else
        pollfd pfd{};
        pfd.fd = sock;
        pfd.events = static_cast<short>(want == Want::Read ? POLLIN : POLLOUT);
        const int rc = ::poll(&pfd, 1, timeout_ms);
        if (rc > 0)
            return true;
        if (rc < 0 && errno != EINTR)
            return false;
#endif
    }
}

std::vector<std::string> split_commas(std::string_view v) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (;;) {
        const std::size_t comma = v.find(',', start);
        out.emplace_back(v.substr(start, comma == std::string_view::npos ? v.npos : comma - start));
        if (comma == std::string_view::npos)
            break;
        start = comma + 1;
    }
    return out;
}

using ConnOptions = std::vector<std::pair<std::string, std::string>>;

/// The probe's connection options: every option the DSN sets, exactly as libpq
/// parsed it, plus `application_name` when the DSN names none. An unparseable
/// DSN is handed to libpq raw (expand_dbname) and its connect reports a FIXED
/// message, never libpq's parse text (which can echo part of a password).
struct ProbeConnInfo {
    ConnOptions opts;
    bool unparseable{false};
};

ProbeConnInfo probe_conninfo(const std::string& dsn) {
    char* errmsg = nullptr;
    std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)> parsed(
        PQconninfoParse(dsn.c_str(), &errmsg), &PQconninfoFree);
    // Owned, never read (see above).
    const std::unique_ptr<char, decltype(&PQfreemem)> errmsg_owner(errmsg, &PQfreemem);
    if (!parsed)
        return {ConnOptions{{"dbname", dsn}}, true};
    ProbeConnInfo info;
    bool has_app_name = false;
    for (const PQconninfoOption* o = parsed.get(); o->keyword != nullptr; ++o) {
        if (o->val == nullptr)
            continue;
        has_app_name = has_app_name || std::string_view{o->keyword} == "application_name";
        info.opts.emplace_back(o->keyword, o->val);
    }
    if (!has_app_name)
        info.opts.emplace_back("application_name", kProbeApplicationName);
    return info;
}

/// One entry of the host list libpq is walking.
struct HostEntry {
    std::string host, hostaddr, port;
};

/// The host list libpq resolved for `c` — the DSN's, else the environment's
/// (`PGHOST`/`PGHOSTADDR`/`PGPORT`), which PQconninfo reports as applied. Empty
/// when there is at most one host or the list shapes disagree (libpq then fails
/// the connection itself), so the caller has nothing to move on to.
std::vector<HostEntry> host_list(PGconn* c) {
    std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)> ci(PQconninfo(c),
                                                                    &PQconninfoFree);
    std::vector<std::string> hosts, addrs, ports;
    for (const PQconninfoOption* o = ci.get(); o && o->keyword != nullptr; ++o) {
        if (o->val == nullptr || *o->val == '\0')
            continue;
        const std::string_view k{o->keyword};
        if (k == "host")
            hosts = split_commas(o->val);
        else if (k == "hostaddr")
            addrs = split_commas(o->val);
        else if (k == "port")
            ports = split_commas(o->val);
    }
    const std::size_t n = std::max(hosts.size(), addrs.size());
    if (n < 2 || (!hosts.empty() && hosts.size() != n) || (!addrs.empty() && addrs.size() != n) ||
        (ports.size() > 1 && ports.size() != n))
        return {};
    std::vector<HostEntry> out(n);
    for (std::size_t i = 0; i < n; ++i) {
        out[i].host = hosts.empty() ? std::string{} : hosts[i];
        out[i].hostaddr = addrs.empty() ? std::string{} : addrs[i];
        out[i].port = ports.empty() ? std::string{} : ports.size() == 1 ? ports[0] : ports[i];
    }
    return out;
}

/// libpq's message on one line (a multi-host failure lists one line per host).
/// Server log only — never the /readyz body.
std::string pq_error(PGconn* c, const char* fallback) {
    const char* m = c ? PQerrorMessage(c) : nullptr;
    std::string s = (m && *m) ? std::string(m) : std::string(fallback);
    std::ranges::replace_if(s, [](char ch) { return ch == '\n' || ch == '\r' || ch == '\t'; }, ' ');
    while (!s.empty() && s.back() == ' ')
        s.pop_back();
    return s;
}

/// The production ping: owns the dedicated connection between ticks.
class LibpqPinger {
public:
    LibpqPinger(const std::string& dsn, std::string sql)
        : info_(probe_conninfo(dsn)), sql_(std::move(sql)) {}

    PgReachabilityProbe::PingResult ping(const std::atomic<bool>& stop) {
        using R = PgReachabilityProbe::PingResult;
        if (!conn_ || PQstatus(conn_.get()) != CONNECTION_OK) {
            conn_.reset();
            if (auto err = connect(stop)) {
                conn_.reset();
                return R{R::Kind::Failed, std::move(*err)};
            }
        }
        std::optional<bool> read_only;
        if (auto err = query(stop, read_only)) {
            conn_.reset(); // reconnect next tick
            return R{R::Kind::Failed, std::move(*err)};
        }
        if (*read_only) {
            // A standby, or a primary refusing writes (default_transaction_read_only,
            // e.g. managed Postgres on a full disk). Drop the session so the next tick
            // re-resolves from the top of the host list / through the proxy (header,
            // finding 2) — the same choice a fresh pool connection would make.
            conn_.reset();
            return R{R::Kind::ReadOnly, "connected server does not accept writes (in recovery, or "
                                        "transaction_read_only is on)"};
        }
        return R{R::Kind::Ok, {}};
    }

private:
    /// Connect the way a new pool connection does, and let LIBPQ walk the host
    /// list: its order (DSN order, or a fresh shuffle per connection under
    /// `load_balance_hosts=random`), which failures move it to the next host or
    /// address (a refused or failed connect, 57P03, a target_session_attrs
    /// rejection) and which end the attempt (a failed login, too many clients,
    /// an SSL or protocol failure, a peer that hangs up), and the addresses of
    /// a name. Four governance rounds found a probe that
    /// re-implemented any part of that walk diverging from the pool and
    /// reporting ready while the pool could not connect (Gate 8 rounds 2-5, all
    /// reproduced); so the probe does not.
    ///
    /// The ONE thing added: libpq's non-blocking connect never moves past a host
    /// that accepts TCP and then goes silent (its blocking connect, which the
    /// pool uses, moves on after `connect_timeout`). So each host gets its own
    /// kConnectDeadline, measured from when libpq starts on it (PQhost/PQport);
    /// on expiry the attempt is restarted over the hosts libpq has not yet
    /// tried, and libpq walks those. Residual: a silent ADDRESS of a host name
    /// with several addresses skips that name's remaining addresses (the pool
    /// would try them) — a false red, never a false green.
    std::optional<std::string> connect(const std::atomic<bool>& stop) {
        std::string stalled; // hosts given up on at their deadline, for the log
        std::vector<HostEntry> hosts;
        std::vector<bool> tried;
        ConnOptions opts = info_.opts;
        for (bool first = true;; first = false) {
            if (stop.load(std::memory_order_acquire))
                return std::string("stopped");
            std::vector<const char*> keys, vals;
            keys.reserve(opts.size() + 1);
            vals.reserve(opts.size() + 1);
            for (const auto& [k, v] : opts) {
                keys.push_back(k.c_str());
                vals.push_back(v.c_str());
            }
            keys.push_back(nullptr);
            vals.push_back(nullptr);
            conn_ = pg::PgConn{
                PQconnectStartParams(keys.data(), vals.data(), info_.unparseable ? 1 : 0)};
            PGconn* c = conn_.get();
            if (c == nullptr)
                return std::string("PQconnectStartParams returned null (out of memory)");
            if (PQstatus(c) == CONNECTION_BAD) {
                if (info_.unparseable) // never echo libpq's text for an unparseable DSN
                    return std::string("the configured Postgres DSN could not be parsed");
                return stalled + pq_error(c, "connection failed");
            }
            if (first) {
                hosts = host_list(c);
                tried.assign(hosts.size(), false);
            }
            std::string current; // "host:port" libpq is on
            auto host_deadline = Clock::now() + pr::kConnectDeadline;
            // libpq contract: after PQconnectStart, proceed as if PQconnectPoll had
            // returned PGRES_POLLING_WRITING.
            PostgresPollingStatusType st = PGRES_POLLING_WRITING;
            bool restart = false;
            while (!restart) {
                if (st == PGRES_POLLING_OK) {
                    if (PQsetnonblocking(c, 1) != 0)
                        return pq_error(c, "could not set non-blocking mode");
                    return std::nullopt;
                }
                if (st == PGRES_POLLING_FAILED) // libpq ended the walk
                    return stalled + pq_error(c, "connection failed");
                const char* h = PQhost(c);
                const char* pt = PQport(c);
                const std::string at = std::string(h ? h : "") + ":" + (pt ? pt : "");
                if (at != current) { // libpq moved to another host: a new deadline
                    current = at;
                    host_deadline = Clock::now() + pr::kConnectDeadline;
                    mark_tried(hosts, tried, h, pt);
                }
                const int sock = PQsocket(c); // may change between addresses — re-read
                if (sock < 0)
                    return stalled + std::string("connection has no socket");
                if (wait_socket(sock, st == PGRES_POLLING_READING ? Want::Read : Want::Write,
                                host_deadline, stop)) {
                    st = PQconnectPoll(c);
                    continue;
                }
                if (stop.load(std::memory_order_acquire))
                    return std::string("stopped");
                stalled += current + " connect timed out; ";
                ConnOptions next = with_untried_hosts(hosts, tried);
                if (next.empty()) // nothing left to try (or a single host)
                    return stalled.substr(0, stalled.size() - 2);
                opts = std::move(next);
                restart = true;
            }
            conn_.reset();
        }
    }

    static void mark_tried(const std::vector<HostEntry>& hosts, std::vector<bool>& tried,
                           const char* h, const char* port) {
        const std::string_view hv = h ? h : "", pv = port ? port : "";
        for (std::size_t i = 0; i < hosts.size(); ++i) {
            const std::string& shown = hosts[i].host.empty() ? hosts[i].hostaddr : hosts[i].host;
            if (shown == hv && (hosts[i].port.empty() || hosts[i].port == pv))
                tried[i] = true;
        }
    }

    /// The probe's options with host/hostaddr/port replaced by the hosts libpq
    /// has not tried yet, in the original order (libpq re-shuffles them under
    /// load_balance_hosts=random). Empty when none remain.
    ConnOptions with_untried_hosts(const std::vector<HostEntry>& hosts,
                                   const std::vector<bool>& tried) const {
        std::string hl, al, pl;
        bool any = false, has_host = false, has_addr = false, has_port = false;
        for (std::size_t i = 0; i < hosts.size(); ++i) {
            if (tried[i])
                continue;
            const char* sep = any ? "," : "";
            hl += sep + hosts[i].host;
            al += sep + hosts[i].hostaddr;
            pl += sep + hosts[i].port;
            has_host = has_host || !hosts[i].host.empty();
            has_addr = has_addr || !hosts[i].hostaddr.empty();
            has_port = has_port || !hosts[i].port.empty();
            any = true;
        }
        if (!any)
            return {};
        ConnOptions out;
        for (const auto& kv : info_.opts)
            if (kv.first != "host" && kv.first != "hostaddr" && kv.first != "port")
                out.push_back(kv);
        if (has_host)
            out.emplace_back("host", hl);
        if (has_addr)
            out.emplace_back("hostaddr", al);
        if (has_port)
            out.emplace_back("port", pl);
        return out;
    }

    /// The probe query (`kProbeSql` in production) under kQueryDeadline. Sets
    /// `read_only` on success; returns an error string on any failure.
    std::optional<std::string> query(const std::atomic<bool>& stop,
                                     std::optional<bool>& read_only) {
        PGconn* c = conn_.get();
        const auto deadline = Clock::now() + pr::kQueryDeadline;
        const auto timed_out = [&]() {
            return std::string(stop.load(std::memory_order_acquire) ? "stopped"
                                                                    : "query timed out");
        };
        if (PQsendQuery(c, sql_.c_str()) == 0)
            return pq_error(c, "could not send probe query");
        for (;;) {
            const int f = PQflush(c);
            if (f == 0)
                break;
            if (f < 0)
                return pq_error(c, "could not flush probe query");
            if (!wait_socket(PQsocket(c), Want::Write, deadline, stop))
                return timed_out();
        }
        std::optional<std::string> result_error;
        for (;;) {
            if (PQconsumeInput(c) == 0)
                return pq_error(c, "connection lost during probe");
            bool done = false;
            while (PQisBusy(c) == 0) {
                PGresult* raw = PQgetResult(c);
                if (raw == nullptr) {
                    done = true;
                    break;
                }
                pg::PgResult r{raw};
                if (r.status() == PGRES_TUPLES_OK && PQntuples(r.get()) == 1 &&
                    PQnfields(r.get()) == 1 && !PQgetisnull(r.get(), 0, 0)) {
                    const char* v = PQgetvalue(r.get(), 0, 0);
                    read_only = v != nullptr && v[0] == 't';
                } else if (!result_error) {
                    const char* m = PQresultErrorMessage(r.get());
                    result_error = (m && *m) ? std::string(m) : std::string("unexpected result");
                }
            }
            if (done)
                break;
            // Read-readiness only: the reply to this one-statement query is a few
            // hundred bytes, so a TLS record OpenSSL buffered ahead of poll() is not
            // a practical concern — at worst one tick fails at the deadline, which is
            // below kFailThreshold.
            if (!wait_socket(PQsocket(c), Want::Read, deadline, stop))
                return timed_out();
        }
        if (result_error)
            return result_error;
        if (!read_only)
            return std::string("probe query returned no row");
        return std::nullopt;
    }

    ProbeConnInfo info_;
    std::string sql_;
    pg::PgConn conn_;
};

} // namespace

std::unique_ptr<PgReachabilityProbe> PgReachabilityProbe::make_libpq(std::string dsn, Observer obs,
                                                                     std::string probe_sql) {
    auto pinger = std::make_shared<LibpqPinger>(dsn, std::move(probe_sql));
    return std::make_unique<PgReachabilityProbe>(
        [pinger](const std::atomic<bool>& stop) { return pinger->ping(stop); }, std::move(obs));
}

PgReachabilityProbe::PgReachabilityProbe(PingFn ping, Observer obs,
                                         std::chrono::milliseconds interval)
    : ping_(std::move(ping)), obs_(std::move(obs)), interval_(interval) {}

PgReachabilityProbe::~PgReachabilityProbe() {
    stop();
}

std::int64_t PgReachabilityProbe::now_ns() noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch())
        .count();
}

pg_reachability::Snapshot PgReachabilityProbe::snapshot() const noexcept {
    // Leaf lock: held only to copy three fields, never across I/O — so a
    // stalled probe cannot stall a reader (the #4013 lesson), and a reader
    // never sees a torn mix of two publications.
    std::lock_guard<std::mutex> lk(snap_mu_);
    return snap_;
}

pg_reachability::Verdict PgReachabilityProbe::verdict_at(std::int64_t now) const noexcept {
    return pg_reachability::classify(snapshot(), now);
}

pg_reachability::Verdict PgReachabilityProbe::verdict() const noexcept {
    return verdict_at(now_ns());
}

void PgReachabilityProbe::publish(const PingResult& r) {
    using K = PingResult::Kind;
    const auto now = now_ns();
    pr::Snapshot after;
    {
        std::lock_guard<std::mutex> lk(snap_mu_);
        if (r.kind == K::Ok) {
            snap_.last_failure = pr::FailureKind::None;
            snap_.consecutive_failures = 0;
            snap_.last_success_ns = now;
        } else {
            snap_.last_failure =
                r.kind == K::ReadOnly ? pr::FailureKind::ReadOnly : pr::FailureKind::Unreachable;
            ++snap_.consecutive_failures;
        }
        after = snap_;
    }
    if (r.kind != K::Ok && obs_.on_failure)
        obs_.on_failure();

    // Logged when a COMPLETED probe changes the verdict, plus a reminder every
    // 60s while not ready. (A probe stuck outside its deadlines — see the
    // resolver residual in the header — reads Stale without completing, so the
    // next log line comes when it does.)
    constexpr std::int64_t kReminderNs = std::chrono::nanoseconds(std::chrono::seconds(60)).count();
    const auto v = pr::classify(after, now);
    const std::string detail = r.detail.empty() ? std::string("-") : r.detail;
    if (v != logged_verdict_) {
        if (v == pr::Verdict::Ready) {
            spdlog::info(logged_verdict_ == pr::Verdict::NotYetProbed
                             ? "[readyz] Postgres reachable — pg_reachable ok"
                             : "[readyz] Postgres reachable again — pg_reachable ok");
        } else {
            spdlog::warn("[readyz] Postgres not reachable from this replica — pg_reachable={} "
                         "(/readyz reports not ready): {}",
                         pr::reason(v), detail);
            last_red_log_ns_ = now;
        }
        logged_verdict_ = v;
    } else if (v != pr::Verdict::Ready && now - last_red_log_ns_ >= kReminderNs) {
        spdlog::warn("[readyz] Postgres not reachable from this replica (still) — "
                     "pg_reachable={}: {}",
                     pr::reason(v), detail);
        last_red_log_ns_ = now;
    }
}

void PgReachabilityProbe::probe_once() {
    PingResult r;
    try {
        r = ping_(stop_);
    } catch (const std::exception& e) {
        r = PingResult{PingResult::Kind::Failed, std::string("probe threw: ") + e.what()};
    } catch (...) {
        r = PingResult{PingResult::Kind::Failed, "probe threw an unknown exception"};
    }
    // A probe cut short by stop() says nothing about Postgres — don't publish.
    if (stop_.load(std::memory_order_acquire))
        return;
    publish(r);
}

void PgReachabilityProbe::start() {
    std::lock_guard<std::mutex> lk(mu_);
    if (started_ || stop_.load(std::memory_order_acquire))
        return;
    started_ = true;
    thread_ = std::thread([this] { run_loop(); });
}

void PgReachabilityProbe::stop() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        stop_.store(true, std::memory_order_release);
    }
    cv_.notify_all();
    // Join outside mu_: the loop takes mu_ for its interval wait. Not safe to
    // call from two threads at once (both could see joinable()); ServerImpl's
    // callers are serialised by lifecycle_mu_, and the destructor runs after.
    if (thread_.joinable() && thread_.get_id() != std::this_thread::get_id())
        thread_.join();
}

void PgReachabilityProbe::run_loop() {
    YUZU_ASSERT_BACKGROUND_JOB("pg_reachability_probe.tick"); // WS-10 ReplicaSafe (per-replica)
    while (!stop_.load(std::memory_order_acquire)) {
        try {
            probe_once();
        } catch (...) {
            // publish() allocates (logging); an escaping exception on a
            // std::thread entry is std::terminate. Swallow and keep probing.
        }
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait_for(lk, interval_, [this] { return stop_.load(std::memory_order_acquire); });
    }
}

} // namespace yuzu::server
