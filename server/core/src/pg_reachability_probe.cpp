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

std::string pq_error(PGconn* c, const char* fallback) {
    const char* m = c ? PQerrorMessage(c) : nullptr;
    std::string s = (m && *m) ? std::string(m) : std::string(fallback);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
        s.pop_back();
    return s;
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

struct ConnTarget {
    ConnOptions opts;
    bool expand_dbname{false}; ///< true only for the unparseable-DSN fallback
};

/// One connection attempt per host (UP-1). libpq's NON-blocking connect
/// (`PQconnectStart`/`PQconnectPoll`) never moves past a host that accepts the
/// TCP handshake and then goes silent — only the BLOCKING path applies
/// `connect_timeout` per host and advances. A multi-host DSN
/// (`host=n1,n2,n3 target_session_attrs=read-write`, the pattern
/// docs/user-manual/ha-postgres.md documents) would otherwise wait out the
/// whole deadline on a frozen n1 every tick while the pool serves from n2.
/// So the probe splits the host list itself and gives each host its own
/// deadline. Residuals, documented: a single host NAME that resolves to several
/// addresses is iterated inside libpq and keeps the no-advance behaviour, and a
/// host list supplied through `service=` or `PGHOST` is not split (PQconninfoParse
/// expands neither). On a list shape libpq itself would reject, returns ONE target
/// carrying the original values, so libpq reports that error; on a parse failure,
/// one raw-DSN target whose connect reports a FIXED message (connect_one).
std::vector<ConnTarget> build_targets(const std::string& dsn) {
    ConnOptions base;
    std::vector<std::string> hosts, addrs, ports;
    bool has_app_name = false;
    char* errmsg = nullptr;
    std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)> opts(
        PQconninfoParse(dsn.c_str(), &errmsg), &PQconninfoFree);
    // Owned, never read: libpq's parse message can echo a DSN fragment, including
    // part of a password (e.g. a bad percent-escape), so it must not reach a log.
    const std::unique_ptr<char, decltype(&PQfreemem)> errmsg_owner(errmsg, &PQfreemem);
    if (!opts) // unparseable: hand libpq the raw DSN; connect_one reports a fixed message
        return {ConnTarget{ConnOptions{{"dbname", dsn}}, true}};
    for (const PQconninfoOption* o = opts.get(); o->keyword != nullptr; ++o) {
        if (o->val == nullptr)
            continue;
        const std::string_view k{o->keyword};
        if (k == "host")
            hosts = split_commas(o->val);
        else if (k == "hostaddr")
            addrs = split_commas(o->val);
        else if (k == "port")
            ports = split_commas(o->val);
        else {
            if (k == "application_name")
                has_app_name = true;
            base.emplace_back(o->keyword, o->val);
        }
    }
    if (!has_app_name)
        base.emplace_back("application_name", kProbeApplicationName);

    const std::size_t n = std::max<std::size_t>({hosts.size(), addrs.size(), 1});
    const bool shape_ok = (hosts.empty() || hosts.size() == n) &&
                          (addrs.empty() || addrs.size() == n) &&
                          (ports.size() <= 1 || ports.size() == n);
    auto join = [](const std::vector<std::string>& v) {
        std::string s;
        for (std::size_t i = 0; i < v.size(); ++i)
            s += (i ? "," : "") + v[i];
        return s;
    };
    std::vector<ConnTarget> targets;
    if (n == 1 || !shape_ok) {
        ConnOptions t = base;
        if (!hosts.empty())
            t.emplace_back("host", join(hosts));
        if (!addrs.empty())
            t.emplace_back("hostaddr", join(addrs));
        if (!ports.empty())
            t.emplace_back("port", join(ports));
        targets.push_back(ConnTarget{std::move(t)});
        return targets;
    }
    for (std::size_t i = 0; i < n; ++i) {
        ConnOptions t = base;
        if (!hosts.empty())
            t.emplace_back("host", hosts[i]);
        if (!addrs.empty())
            t.emplace_back("hostaddr", addrs[i]);
        if (!ports.empty())
            t.emplace_back("port", ports.size() == 1 ? ports[0] : ports[i]);
        targets.push_back(ConnTarget{std::move(t)});
    }
    return targets;
}

/// The production ping: owns the dedicated connection between ticks.
class LibpqPinger {
public:
    LibpqPinger(const std::string& dsn, std::string sql)
        : targets_(build_targets(dsn)), sql_(std::move(sql)) {}

    PgReachabilityProbe::PingResult ping(const std::atomic<bool>& stop) {
        using R = PgReachabilityProbe::PingResult;
        if (!conn_ || PQstatus(conn_.get()) != CONNECTION_OK) {
            conn_.reset();
            if (auto err = connect_any(stop)) {
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
    /// Try each target IN THE DSN'S ORDER, each under its own kConnectDeadline —
    /// the same order libpq, and so the server's pool, uses for a fresh
    /// connection. The probe must measure the host the pool would reach, not be
    /// cleverer than it: two governance rounds tried a "start from the last host
    /// that worked" preference, and it either pinned the probe to a read-only
    /// host after the primary came back or — rotated — found a writable host the
    /// pool never uses and reported ready while every pool write failed (Gate 8
    /// rounds 2 and 3, both reproduced). Cost, accepted: silent hosts listed
    /// ahead of the primary are walked on every reconnect, exactly as a new pool
    /// connection walks them. Returns every host's error on total failure.
    std::optional<std::string> connect_any(const std::atomic<bool>& stop) {
        std::string errors;
        const std::size_t n = targets_.size();
        for (std::size_t i = 0; i < n; ++i) {
            if (stop.load(std::memory_order_acquire))
                return std::string("stopped");
            auto err = connect_one(targets_[i], stop);
            if (!err)
                return std::nullopt;
            conn_.reset();
            if (n > 1)
                errors += (errors.empty() ? "" : "; ") + ("host " + std::to_string(i + 1) + ": ");
            errors += *err;
        }
        return errors.empty() ? std::string("no connection target") : errors;
    }

    std::optional<std::string> connect_one(const ConnTarget& target,
                                           const std::atomic<bool>& stop) {
        std::vector<const char*> keys, vals;
        keys.reserve(target.opts.size() + 1);
        vals.reserve(target.opts.size() + 1);
        for (const auto& [k, v] : target.opts) {
            keys.push_back(k.c_str());
            vals.push_back(v.c_str());
        }
        keys.push_back(nullptr);
        vals.push_back(nullptr);

        const auto deadline = Clock::now() + pr::kConnectDeadline;
        conn_ = pg::PgConn{
            PQconnectStartParams(keys.data(), vals.data(), target.expand_dbname ? 1 : 0)};
        PGconn* c = conn_.get();
        if (c == nullptr)
            return std::string("PQconnectStartParams returned null (out of memory)");
        if (PQstatus(c) == CONNECTION_BAD) {
            if (target.expand_dbname) // the unparseable-DSN fallback: never echo libpq's text
                return std::string("the configured Postgres DSN could not be parsed");
            return pq_error(c, "connection failed");
        }
        // libpq contract: after PQconnectStart, proceed as if PQconnectPoll had
        // returned PGRES_POLLING_WRITING.
        PostgresPollingStatusType st = PGRES_POLLING_WRITING;
        for (;;) {
            if (st == PGRES_POLLING_OK)
                break;
            if (st == PGRES_POLLING_FAILED)
                return pq_error(c, "connection failed");
            const int sock = PQsocket(c); // may change between addresses — re-read
            if (sock < 0)
                return std::string("connection has no socket");
            if (!wait_socket(sock, st == PGRES_POLLING_READING ? Want::Read : Want::Write, deadline,
                             stop))
                return std::string(stop.load(std::memory_order_acquire) ? "stopped"
                                                                        : "connect timed out");
            st = PQconnectPoll(c);
        }
        if (PQsetnonblocking(c, 1) != 0)
            return pq_error(c, "could not set non-blocking mode");
        return std::nullopt;
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

    std::vector<ConnTarget> targets_;
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
