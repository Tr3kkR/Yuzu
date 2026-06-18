#pragma once

/// @file pg_pool.hpp
/// Bounded, thread-safe pool of libpq connections — the one shared
/// `PgPool` every Postgres-backed server store receives in place of the
/// per-store `sqlite3*` handle (ADR-0008 "Connection model"). Generalizes
/// `InstructionDbPool` from one shared handle to a checkout-per-operation,
/// pin-per-transaction set, exploiting Postgres's real concurrency (the
/// per-store `shared_mutex` serialization goes away) while bounding backend
/// processes.
///
/// Usage:
///     PgPool pool{{.conninfo = dsn, .size = 16}};
///     if (!pool.valid()) { ... }            // conninfo failed to parse
///     {
///         auto lease = pool.acquire();      // blocks; empty on shutdown or
///         if (!lease) { ... }               // connection failure
///         PgResult r{PQexec(lease.get(), "SELECT 1")};
///     }                                      // lease returns the conn
///
/// Error surfaces never echo raw DSN fragments: a malformed conninfo is
/// reported as a fixed string (libpq's parse error quotes tokens, which can
/// include credentials — F1 conditions ledger #3 on #1320). Connect errors
/// from a well-formed conninfo pass through `PQerrorMessage`, which names
/// host/port but never the password.
///
/// TLS note for DSN wiring (F1 ledger #4): on Windows libpq verifies
/// `sslmode=verify-ca/verify-full` against `%APPDATA%\postgresql\root.crt`
/// (or the DSN's `sslrootcert=`), NOT the Windows certificate store that
/// `cert_store.cpp` handles — provision the root there when a TLS DSN ships.

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <random>
#include <string>

#include <libpq-fe.h>

namespace yuzu::server::pg {

class PgPool {
public:
    /// Optional observability hooks (#1368). Every callback is invoked
    /// WITHOUT the pool's internal lock held, so an implementation may do
    /// real work — but it MUST NOT re-enter the pool (acquire/with_txn/
    /// destroy), which risks self-deadlock, and SHOULD NOT throw
    /// (`on_unhealthy_discard` fires from a noexcept context, where a throw
    /// is swallowed). The server wires these to its Prometheus registry; the
    /// default — every hook empty — is a zero-overhead no-op. Connection
    /// in_use/open/size are polled gauges via the accessors below, not hooks.
    struct Observer {
        /// A fresh connection attempt failed (feeds a connect-failure counter).
        std::function<void()> on_connect_failure;
        /// `try_acquire_for` gave up at its deadline (acquire-timeout counter).
        std::function<void()> on_acquire_timeout;
        /// A returned connection was discarded as unhealthy (discard counter).
        std::function<void()> on_unhealthy_discard;
        /// Wall time a successful `acquire`/`try_acquire_for` spent waiting,
        /// in seconds (the acquire-wait histogram — the leading saturation
        /// indicator). Observed on every successful checkout, including the
        /// zero-wait idle-hit fast path.
        std::function<void(double)> on_acquire_wait_seconds;
    };

    struct Options {
        /// Connection string — keyword/value or URI form, as accepted by
        /// `PQconnectdb`.
        std::string conninfo;
        /// Maximum simultaneously open connections (= max Postgres backend
        /// processes this pool can consume). Connections are opened lazily
        /// on demand and never reaped, so the steady-state backend count
        /// equals the historical peak concurrency, not `size`. 0 is
        /// clamped to 1.
        std::size_t size = 16;
        /// Applied to every connection attempt unless the conninfo already
        /// carries its own `connect_timeout`. libpq has NO client-side
        /// timeout by default — without this a black-holed host wedges the
        /// acquiring thread indefinitely.
        int connect_timeout_s = 10;
        /// Server-side per-statement timeout (ms), injected as a startup GUC
        /// (`-c statement_timeout=`) via the `options` keyword unless the
        /// conninfo sets its own `options`. Bounds a wedged query — including
        /// the `PgTxn`-dtor ROLLBACK on a half-open connection. 0 disables
        /// (libpq default = no timeout). (#1368 UP-2/4)
        int statement_timeout_ms = 30000;
        /// Server-side lock-acquisition timeout (ms), injected the same way.
        /// Bounds the migration-runner advisory-lock wait so a wedged
        /// lock-holder fails the boot closed instead of hanging forever — the
        /// runner inherits this from its pooled lease. 0 disables. (#1368 CH-10)
        int lock_timeout_ms = 10000;
        /// TCP keepalive idle (s), injected as `keepalives=1 keepalives_idle=`
        /// unless the conninfo sets `keepalives`. Surfaces a silently-dropped
        /// connection (NAT/firewall reap) as a failed statement instead of an
        /// indefinite hang. 0 leaves libpq defaults.
        int keepalives_idle_s = 30;
        /// Connect-failure circuit breaker (#1368 cheap-idle): after a failed
        /// connect, suppress further connect attempts for an
        /// exponentially-growing window (`base × 2^(failures-1)`, capped, with
        /// ±25% jitter) so a down database is not hammered by `size`
        /// simultaneous `connect_timeout_s` connects on every retry. During
        /// the window `acquire()` fails fast with an empty lease; a returned
        /// healthy idle connection is still served immediately (recovery is
        /// not blocked). A successful connect resets the breaker.
        std::chrono::milliseconds connect_backoff_base{200};
        std::chrono::milliseconds connect_backoff_cap{5000};
        /// Observability hooks; see Observer. All optional.
        Observer observer;
    };

    /// Parses (but does not connect) the conninfo. A parse failure leaves the
    /// pool constructed-but-invalid: `valid()` is false and every `acquire`
    /// returns an empty lease.
    explicit PgPool(Options opts);

    /// Blocks until every outstanding lease has been returned and every
    /// thread blocked in `acquire()` has been woken (they receive empty
    /// leases), then closes all connections. Two caller obligations:
    ///  - a thread that holds a lease MUST NOT destroy the pool — the
    ///    destructor waits for that very lease and self-deadlocks;
    ///  - entering `acquire()` for the first time after the destructor has
    ///    returned is a use-after-destroy like any other.
    ~PgPool();

    PgPool(const PgPool&) = delete;
    PgPool& operator=(const PgPool&) = delete;
    PgPool(PgPool&&) = delete;
    PgPool& operator=(PgPool&&) = delete;

    /// RAII checkout. Returns the connection to the pool on destruction; a
    /// connection that is no longer healthy (or stuck in a transaction the
    /// caller failed to close — the pool rolls it back defensively) is
    /// discarded instead, freeing capacity for a fresh one.
    class Lease {
    public:
        Lease() = default;
        ~Lease() { reset(); }

        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& o) noexcept : pool_(o.pool_), conn_(o.conn_) {
            o.pool_ = nullptr;
            o.conn_ = nullptr;
        }
        Lease& operator=(Lease&& o) noexcept {
            if (this != &o) {
                reset();
                pool_ = o.pool_;
                conn_ = o.conn_;
                o.pool_ = nullptr;
                o.conn_ = nullptr;
            }
            return *this;
        }

        PGconn* get() const noexcept { return conn_; }
        explicit operator bool() const noexcept { return conn_ != nullptr; }

        /// Return the connection early. Idempotent.
        void reset() noexcept {
            if (pool_ && conn_)
                pool_->release(conn_);
            pool_ = nullptr;
            conn_ = nullptr;
        }

    private:
        friend class PgPool;
        Lease(PgPool* pool, PGconn* conn) noexcept : pool_(pool), conn_(conn) {}

        PgPool* pool_{nullptr};
        PGconn* conn_{nullptr};
    };

    /// Block until a connection is available. Empty lease when the pool is
    /// invalid, shutting down, or a fresh connection attempt failed (the
    /// failure reason is in `last_error()`).
    [[nodiscard]] Lease acquire();

    /// As `acquire()`, but gives up after `timeout` when the pool is
    /// exhausted and nothing is released in time. Bound caveat: a fresh
    /// connection attempt is only STARTED before the deadline, but once
    /// started it runs to completion — worst case is roughly
    /// `timeout + connect_timeout_s`.
    [[nodiscard]] Lease try_acquire_for(std::chrono::milliseconds timeout);

    /// Pin one connection for a transaction: BEGIN, run `fn`, COMMIT when it
    /// returns true, ROLLBACK when it returns false or throws (the exception
    /// propagates). Returns false on acquire/BEGIN/COMMIT failure or when
    /// `fn` returned false.
    ///
    /// Store-contract notes (PR-3 consumers):
    ///  - Reserve with_txn for multi-statement atomic units. A
    ///    single-statement operation (e.g. the heartbeat
    ///    `INSERT ... ON CONFLICT ... RETURNING`) should run on a plain
    ///    `acquire()` lease under autocommit — with_txn would triple its
    ///    round-trips (BEGIN/COMMIT).
    ///  - Nesting with_txn (calling it from inside `fn`) acquires a SECOND
    ///    connection: it deadlocks a size-1 pool and is rarely what you
    ///    want — restructure instead.
    ///  - A connection severed while idle (NAT/firewall reap) surfaces as a
    ///    failed first statement; the pool discards it on release. Stores
    ///    should treat one connection-level retry as routine.
    bool with_txn(const std::function<bool(PGconn*)>& fn);

    /// False when the conninfo failed to parse at construction.
    [[nodiscard]] bool valid() const noexcept { return valid_; }

    /// Last acquire/connect failure, sanitized (never raw DSN fragments).
    [[nodiscard]] std::string last_error() const;

    /// Configured capacity.
    [[nodiscard]] std::size_t size() const noexcept { return size_; }

    /// Connections currently leased out (PR-3 Prometheus gauge feed).
    [[nodiscard]] std::size_t in_use() const;

    /// Connections currently open (leased + idle).
    [[nodiscard]] std::size_t open() const;

    /// Threads currently blocked in acquire() waiting for a lease — the
    /// saturation depth that fills the gap between "all leased" and a /readyz
    /// flip (gov sre).
    [[nodiscard]] std::size_t waiters() const;

    /// True while the connect-failure breaker is suppressing new connects.
    /// A cheap, NON-lease-consuming health signal for readiness probes: armed
    /// ⇒ the database is unreachable (recent connect failures). Pool
    /// saturation alone — all leases out but no connect failures — does NOT
    /// arm the breaker, so this never false-trips under load, which a
    /// lease-consuming probe would (gov UP-2).
    [[nodiscard]] bool connect_breaker_open() const;

private:
    void release(PGconn* conn) noexcept;
    Lease acquire_internal(const std::chrono::steady_clock::time_point* deadline);
    /// Connect with the pool's effective parameters. Called WITHOUT the lock
    /// held (connects can take seconds). Returns nullptr on failure and
    /// stores the reason via `set_error`.
    PGconn* connect_one();
    void set_error(std::string msg);
    /// Arm the connect-failure breaker after a failed connect. Caller holds
    /// `mu_`; grows the suppression window exponentially with ±jitter.
    void arm_connect_backoff_locked();

    std::string conninfo_;
    std::size_t size_{16};
    int connect_timeout_s_{10};
    int statement_timeout_ms_{30000};
    int lock_timeout_ms_{10000};
    int keepalives_idle_s_{30};
    bool valid_{false};
    bool conninfo_has_timeout_{false};
    bool conninfo_has_options_{false};
    bool conninfo_has_keepalives_{false};
    Observer observer_;

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<PGconn*> idle_;
    std::size_t open_{0};       ///< established connections (leased + idle)
    std::size_t leased_{0};     ///< checked out right now
    std::size_t connecting_{0}; ///< reserved capacity, connect in flight
    std::size_t waiters_{0};    ///< threads blocked inside acquire's wait
    bool shutdown_{false};
    std::string last_error_;

    // Connect-failure circuit breaker (guarded by mu_). connect_blocked_until_
    // is the steady-clock instant before which no new connect is attempted.
    std::chrono::milliseconds backoff_base_{200};
    std::chrono::milliseconds backoff_cap_{5000};
    std::size_t connect_failures_{0};
    std::chrono::steady_clock::time_point connect_blocked_until_{};
    std::minstd_rand jitter_rng_{0x79757a75u}; ///< "yuzu"; jitter only, not crypto
};

} // namespace yuzu::server::pg
