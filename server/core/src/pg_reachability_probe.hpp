#pragma once

/// @file pg_reachability_probe.hpp
/// HA WS-8 (ADR-2002 §12): the runtime "can this replica reach the `yuzu`
/// primary?" signal behind `/readyz`'s `pg_reachable` row. The decision rule is
/// in pg_reachability_rules.hpp (pure); this file is the I/O half.
///
/// WHY A DEDICATED CONNECTION, NOT A POOL LEASE. A probe that leases from
/// `pg_pool` false-negatives under saturation and would evict a busy-but-
/// healthy replica from the load balancer (the governance UP-2 precedent on the
/// `pg_pool` row). The probe owns ONE connection of its own (+1 connection per
/// replica against `max_connections`). It is built from the pool's DSN via
/// `build_coord_dsn` (keepalives), the same augmentation the LeaderElector uses.
///
/// WHY NOT REUSE THE LEADERELECTOR'S PING (pre-implementation review Q1). The
/// elector is best-effort (boot continues without it), its `is_open()` takes a
/// mutex held across blocking libpq calls (#4013), and its cadence is a backoff
/// schedule, not a readiness clock. Leadership is also NOT a readiness
/// condition: a follower serves every operator-synchronous path (two dispatch
/// planes, leader_elector.hpp), so a follower is fully ready. That is the
/// recorded #4014 decision — the elector stays out of `/readyz`.
///
/// EVERY LIBPQ CALL HAS A CLIENT-SIDE DEADLINE. The probe uses libpq's
/// non-blocking API (`PQconnectStart`/`PQconnectPoll`, `PQsendQuery` +
/// `poll()`/`PQconsumeInput`/`PQisBusy`) under `kConnectDeadline` /
/// `kQueryDeadline`, sliced so `stop()` is observed within ~200ms. This is
/// load-bearing: against a FROZEN backend (a `docker pause`d or black-holed
/// primary whose kernel still ACKs), a blocking `PQexec` measured 101s in this
/// tree (see `make_containment_gate` in server.cpp) — `statement_timeout` is
/// enforced server-side and `tcp_user_timeout`/keepalives never fire while the
/// peer ACKs. A blocking probe would make `stop()`'s join unbounded.
/// Residual: `PQconnectStart` resolves a host NAME synchronously
/// (getaddrinfo), bounded by the system resolver's timeouts, not ours.
///
/// Any failure, AND reaching a server in recovery, CLOSES the connection so the
/// next tick reconnects. The recovery case matters: without it a probe pinned
/// to a demoted primary (behind a proxy that does not kill sessions on
/// failover) would report read-only forever while a healthy new primary exists
/// — every replica stuck red (pre-implementation review, finding 2).
///
/// PUBLICATION IS LOCK-FREE. `/readyz` and `/metrics` read three atomics and
/// never touch the probe's connection or thread, so a stalled probe can never
/// stall a health check (the #4013 lesson).
///
/// LIFETIME (ServerImpl). The first probe runs SYNCHRONOUSLY in `run()` before
/// the HTTP listener binds (no `not_yet_probed` window after bind); `start()`
/// then spawns the loop. `stop()` signals and joins — bounded by one slice
/// (~200ms) because every wait checks the stop flag. `stop()` may run while
/// HTTP handlers are still executing (they keep running after
/// `web_server_->stop()` until `listen()` returns): that is safe because
/// `snapshot()` only reads atomics. The OBJECT must therefore outlive the
/// web thread — ServerImpl keeps it as a member destroyed at `~ServerImpl`,
/// never `reset()` inside `stop()`.

#include "pg_reachability_rules.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace yuzu::server {

class PgReachabilityProbe {
public:
    /// Outcome of one probe.
    struct PingResult {
        enum class Kind : std::uint8_t { Ok, ReadOnly, Failed } kind{Kind::Failed};
        /// Operator-facing detail for the server log ONLY (may carry libpq
        /// text, host names). Never placed in an HTTP body.
        std::string detail;
    };

    /// One probe. MUST return promptly once `stop` reads true, and must bound
    /// its own blocking work. Called only from one thread at a time.
    using PingFn = std::function<PingResult(const std::atomic<bool>& stop)>;

    struct Observer {
        /// Every failed probe (Failed or ReadOnly) — feeds the failure counter.
        std::function<void()> on_failure;
    };

    /// The probe query. Must return exactly one boolean: `true` means "the
    /// connected server is in recovery (a standby)".
    static constexpr const char* kProbeSql = "SELECT pg_is_in_recovery()";

    /// Production: a real libpq probe against `dsn` (already augmented by
    /// `build_coord_dsn`). Does not connect until `probe_once()`. `probe_sql`
    /// exists for tests only (e.g. `SELECT true` to simulate a standby without
    /// one); production always passes the default.
    static std::unique_ptr<PgReachabilityProbe> make_libpq(std::string dsn, Observer obs = {},
                                                           std::string probe_sql = kProbeSql);

    /// Test seam: any ping function, with an injectable interval so a loop test
    /// does not take seconds.
    PgReachabilityProbe(PingFn ping, Observer obs = {},
                        std::chrono::milliseconds interval = pg_reachability::kProbeInterval);
    ~PgReachabilityProbe();

    PgReachabilityProbe(const PgReachabilityProbe&) = delete;
    PgReachabilityProbe& operator=(const PgReachabilityProbe&) = delete;

    /// Run one probe on the CALLING thread and publish the result. Used for the
    /// synchronous first probe in `run()`, before `start()`. Must not be called
    /// concurrently with the loop thread.
    void probe_once();

    /// Spawn the probe loop. Idempotent; a no-op after `stop()`.
    void start();

    /// Signal and join the loop. Idempotent. Sticky: no restart after stop.
    void stop();

    /// Lock-free read of the published state.
    pg_reachability::Snapshot snapshot() const noexcept;

    /// `classify(snapshot(), now_ns)`.
    pg_reachability::Verdict verdict_at(std::int64_t now_ns) const noexcept;
    pg_reachability::Verdict verdict() const noexcept;

    /// steady_clock ns since its epoch — the clock every timestamp here uses.
    static std::int64_t now_ns() noexcept;

private:
    void run_loop();
    void publish(const PingResult& r);

    PingFn ping_;
    Observer obs_;
    std::chrono::milliseconds interval_;

    std::atomic<std::int64_t> last_success_ns_{pg_reachability::kNever};
    std::atomic<int> consecutive_failures_{0};
    std::atomic<std::uint8_t> last_failure_{
        static_cast<std::uint8_t>(pg_reachability::FailureKind::None)};

    std::atomic<bool> stop_{false};
    std::mutex mu_; ///< guards cv_ waits and thread_ start/join only
    std::condition_variable cv_;
    std::thread thread_;
    bool started_{false};

    // Logging state — touched only by whichever single thread is probing
    // (the boot caller, then the loop thread; never both at once).
    pg_reachability::Verdict logged_verdict_{pg_reachability::Verdict::NotYetProbed};
    std::int64_t last_red_log_ns_{0};
};

} // namespace yuzu::server
