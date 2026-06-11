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

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <string>

#include <libpq-fe.h>

namespace yuzu::server::pg {

class PgPool {
public:
    struct Options {
        /// Connection string — keyword/value or URI form, as accepted by
        /// `PQconnectdb`.
        std::string conninfo;
        /// Maximum simultaneously open connections (= max Postgres backend
        /// processes this pool can consume).
        std::size_t size = 16;
        /// Applied to every connection attempt unless the conninfo already
        /// carries its own `connect_timeout`. libpq has NO client-side
        /// timeout by default — without this a black-holed host wedges the
        /// acquiring thread indefinitely.
        int connect_timeout_s = 10;
    };

    /// Parses (but does not connect) the conninfo. A parse failure leaves the
    /// pool constructed-but-invalid: `valid()` is false and every `acquire`
    /// returns an empty lease.
    explicit PgPool(Options opts);

    /// Blocks until every outstanding lease has been returned, then closes
    /// all connections. Threads blocked in `acquire()` are woken and receive
    /// empty leases.
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
    /// exhausted and nothing is released in time.
    [[nodiscard]] Lease try_acquire_for(std::chrono::milliseconds timeout);

    /// Pin one connection for a transaction: BEGIN, run `fn`, COMMIT when it
    /// returns true, ROLLBACK when it returns false or throws (the exception
    /// propagates). Returns false on acquire/BEGIN/COMMIT failure or when
    /// `fn` returned false.
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

private:
    void release(PGconn* conn) noexcept;
    Lease acquire_internal(const std::chrono::steady_clock::time_point* deadline);
    /// Connect with the pool's effective parameters. Called WITHOUT the lock
    /// held (connects can take seconds). Returns nullptr on failure and
    /// stores the reason via `set_error`.
    PGconn* connect_one();
    void set_error(std::string msg);

    std::string conninfo_;
    std::size_t size_{16};
    int connect_timeout_s_{10};
    bool valid_{false};
    bool conninfo_has_timeout_{false};

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<PGconn*> idle_;
    std::size_t open_{0};       ///< established connections (leased + idle)
    std::size_t leased_{0};     ///< checked out right now
    std::size_t connecting_{0}; ///< reserved capacity, connect in flight
    bool shutdown_{false};
    std::string last_error_;
};

} // namespace yuzu::server::pg
