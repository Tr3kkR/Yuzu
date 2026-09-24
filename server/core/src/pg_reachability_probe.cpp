#ifdef _WIN32
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
#include <optional>
#include <utility>

namespace yuzu::server {

namespace {

using Clock = std::chrono::steady_clock;
namespace pr = pg_reachability;

/// Longest single poll() slice, so `stop` is noticed promptly mid-wait.
constexpr std::chrono::milliseconds kPollSlice{200};

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
        pfd.events = want == Want::Read ? POLLRDNORM : POLLWRNORM;
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

/// The production ping: owns the dedicated connection between ticks.
class LibpqPinger {
public:
    LibpqPinger(std::string dsn, std::string sql) : dsn_(std::move(dsn)), sql_(std::move(sql)) {}

    PgReachabilityProbe::PingResult ping(const std::atomic<bool>& stop) {
        using R = PgReachabilityProbe::PingResult;
        if (!conn_ || PQstatus(conn_.get()) != CONNECTION_OK) {
            conn_.reset();
            if (auto err = connect(stop)) {
                conn_.reset();
                return R{R::Kind::Failed, std::move(*err)};
            }
        }
        std::optional<bool> in_recovery;
        if (auto err = query(stop, in_recovery)) {
            conn_.reset(); // reconnect next tick
            return R{R::Kind::Failed, std::move(*err)};
        }
        if (*in_recovery) {
            // A standby: drop the session so the next tick re-resolves through
            // the proxy to whichever node is primary now (header, finding 2).
            conn_.reset();
            return R{R::Kind::ReadOnly, "connected server is in recovery (standby)"};
        }
        return R{R::Kind::Ok, {}};
    }

private:
    /// Returns an error string on failure, nullopt on success.
    std::optional<std::string> connect(const std::atomic<bool>& stop) {
        if (dsn_.empty())
            return std::string("no DSN configured");
        const auto deadline = Clock::now() + pr::kConnectDeadline;
        conn_ = pg::PgConn{PQconnectStart(dsn_.c_str())};
        PGconn* c = conn_.get();
        if (c == nullptr)
            return std::string("PQconnectStart returned null (out of memory)");
        if (PQstatus(c) == CONNECTION_BAD)
            return pq_error(c, "connection failed");
        // libpq contract: after PQconnectStart, proceed as if PQconnectPoll had
        // returned PGRES_POLLING_WRITING.
        PostgresPollingStatusType st = PGRES_POLLING_WRITING;
        for (;;) {
            if (st == PGRES_POLLING_OK)
                break;
            if (st == PGRES_POLLING_FAILED)
                return pq_error(c, "connection failed");
            const int sock = PQsocket(c); // may change between hosts — re-read
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

    /// The probe query (`kProbeSql` in production) under kQueryDeadline. Sets `in_recovery`
    /// on success; returns an error string on any failure.
    std::optional<std::string> query(const std::atomic<bool>& stop,
                                     std::optional<bool>& in_recovery) {
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
                    in_recovery = v != nullptr && v[0] == 't';
                } else if (!result_error) {
                    const char* m = PQresultErrorMessage(r.get());
                    result_error = (m && *m) ? std::string(m) : std::string("unexpected result");
                }
            }
            if (done)
                break;
            if (!wait_socket(PQsocket(c), Want::Read, deadline, stop))
                return timed_out();
        }
        if (result_error)
            return result_error;
        if (!in_recovery)
            return std::string("probe query returned no row");
        return std::nullopt;
    }

    std::string dsn_;
    std::string sql_;
    pg::PgConn conn_;
};

} // namespace

std::unique_ptr<PgReachabilityProbe> PgReachabilityProbe::make_libpq(std::string dsn, Observer obs,
                                                                     std::string probe_sql) {
    auto pinger = std::make_shared<LibpqPinger>(std::move(dsn), std::move(probe_sql));
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
    pg_reachability::Snapshot s;
    s.last_success_ns = last_success_ns_.load(std::memory_order_acquire);
    s.consecutive_failures = consecutive_failures_.load(std::memory_order_acquire);
    s.last_failure =
        static_cast<pg_reachability::FailureKind>(last_failure_.load(std::memory_order_acquire));
    return s;
}

pg_reachability::Verdict PgReachabilityProbe::verdict_at(std::int64_t now) const noexcept {
    return pg_reachability::classify(snapshot(), now);
}

pg_reachability::Verdict PgReachabilityProbe::verdict() const noexcept {
    return verdict_at(now_ns());
}

void PgReachabilityProbe::publish(const PingResult& r) {
    using K = PingResult::Kind;
    if (r.kind == K::Ok) {
        // Order: clear the failure state BEFORE stamping success, so a reader
        // racing this never sees a fresh success paired with a stale ReadOnly.
        last_failure_.store(static_cast<std::uint8_t>(pr::FailureKind::None),
                            std::memory_order_release);
        consecutive_failures_.store(0, std::memory_order_release);
        last_success_ns_.store(now_ns(), std::memory_order_release);
    } else {
        last_failure_.store(static_cast<std::uint8_t>(r.kind == K::ReadOnly
                                                          ? pr::FailureKind::ReadOnly
                                                          : pr::FailureKind::Unreachable),
                            std::memory_order_release);
        consecutive_failures_.fetch_add(1, std::memory_order_acq_rel);
        if (obs_.on_failure)
            obs_.on_failure();
    }

    // Transition-only logging, plus a periodic reminder while not ready, so a
    // long outage is neither silent nor one log line per tick.
    constexpr std::int64_t kReminderNs = std::chrono::nanoseconds(std::chrono::seconds(60)).count();
    const auto now = now_ns();
    const auto v = pr::classify(snapshot(), now);
    if (v != logged_verdict_) {
        if (v == pr::Verdict::Ready) {
            spdlog::info("[readyz] Postgres reachable again — pg_reachable ok");
        } else {
            spdlog::warn("[readyz] Postgres not reachable from this replica — pg_reachable={} "
                         "(/readyz reports not ready): {}",
                         pr::reason(v), r.detail.empty() ? std::string("-") : r.detail);
            last_red_log_ns_ = now;
        }
        logged_verdict_ = v;
    } else if (v != pr::Verdict::Ready && now - last_red_log_ns_ >= kReminderNs) {
        spdlog::warn(
            "[readyz] Postgres still not reachable from this replica — pg_reachable={}: {}",
            pr::reason(v), r.detail.empty() ? std::string("-") : r.detail);
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
    // Join outside mu_: the loop takes mu_ for its interval wait.
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
