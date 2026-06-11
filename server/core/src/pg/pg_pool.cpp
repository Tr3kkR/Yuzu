#include "pg_pool.hpp"

#include "pg_raii.hpp"

#include <spdlog/spdlog.h>

#include <cstdlib>
#include <string_view>
#include <utility>

namespace yuzu::server::pg {

namespace {

/// Scan a parsed conninfo for an explicitly-set keyword. `PQconninfoParse`
/// returns entries for every known keyword; only those with a non-null `val`
/// were actually present in the string (or inherited from the environment —
/// close enough: an operator setting PGCONNECT_TIMEOUT wins too, which is the
/// right precedence).
bool conninfo_sets(PQconninfoOption* opts, const char* keyword) {
    for (PQconninfoOption* o = opts; o && o->keyword; ++o) {
        if (std::string_view(o->keyword) == keyword)
            return o->val != nullptr && o->val[0] != '\0';
    }
    return false;
}

} // namespace

PgPool::PgPool(Options opts)
    : conninfo_(std::move(opts.conninfo)), size_(opts.size > 0 ? opts.size : 1),
      connect_timeout_s_(opts.connect_timeout_s) {
    // Parse up front so a malformed conninfo is caught here, once, with a
    // sanitized error — NOT at first acquire with libpq's parse error, which
    // quotes the offending token (potentially a credential).
    char* errmsg = nullptr;
    PQconninfoOption* parsed = PQconninfoParse(conninfo_.c_str(), &errmsg);
    if (!parsed) {
        // errmsg deliberately NOT propagated: it echoes conninfo fragments.
        set_error("invalid connection string (details withheld — conninfo "
                  "fragments are never echoed)");
        spdlog::error("PgPool: connection string failed to parse; refusing all acquires");
        if (errmsg)
            PQfreemem(errmsg);
        return;
    }
    // PQconninfoParse does NOT consult the environment, so honour an
    // operator's PGCONNECT_TIMEOUT explicitly — it should win over the
    // pool's injected default, same as a conninfo-level setting.
    const char* env_timeout = std::getenv("PGCONNECT_TIMEOUT");
    conninfo_has_timeout_ = conninfo_sets(parsed, "connect_timeout") ||
                            (env_timeout != nullptr && env_timeout[0] != '\0');
    PQconninfoFree(parsed);
    valid_ = true;
}

PgPool::~PgPool() {
    std::unique_lock lk{mu_};
    shutdown_ = true;
    cv_.notify_all();
    // Wait for every lease to come home, every in-flight connect to
    // resolve, AND every blocked acquirer to leave its wait — destroying
    // mu_/cv_ while a woken waiter is still reacquiring the mutex inside
    // cv_.wait would be UB (Gate 3 cpp-B1). release() closes connections
    // instead of pooling them once shutdown_ is set; waiters observe
    // shutdown_, decrement waiters_, notify, and return empty leases.
    // Calling acquire() for the FIRST time after the destructor returns
    // is a caller lifetime bug, same as any destroyed object.
    cv_.wait(lk, [this] { return leased_ == 0 && connecting_ == 0 && waiters_ == 0; });
    while (!idle_.empty()) {
        PQfinish(idle_.front());
        idle_.pop_front();
        --open_;
    }
}

PgPool::Lease PgPool::acquire() {
    return acquire_internal(nullptr);
}

PgPool::Lease PgPool::try_acquire_for(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    return acquire_internal(&deadline);
}

PgPool::Lease PgPool::acquire_internal(const std::chrono::steady_clock::time_point* deadline) {
    std::unique_lock lk{mu_};
    if (!valid_)
        return {};

    for (;;) {
        if (shutdown_) {
            last_error_ = "pool is shutting down";
            // The destructor may be waiting on waiters_ == 0; make sure it
            // re-evaluates after we leave (we may have just decremented).
            cv_.notify_all();
            return {};
        }
        if (!idle_.empty()) {
            PGconn* c = idle_.front();
            idle_.pop_front();
            ++leased_;
            return Lease{this, c};
        }
        // Deadline gate: never START a connect (or another wait) past the
        // caller's deadline. An idle connection at/past the deadline is
        // still taken above — that costs nothing.
        if (deadline && std::chrono::steady_clock::now() >= *deadline) {
            last_error_ = "pool exhausted (all connections leased)";
            return {};
        }
        if (open_ + connecting_ < size_) {
            ++connecting_;
            lk.unlock();
            PGconn* c = nullptr;
            try {
                c = connect_one(); // slow; deliberately outside the lock
            } catch (...) {
                // bad_alloc from error-string building: restore the
                // reserved capacity or the destructor waits forever on
                // connecting_ == 0 (Gate 3 cpp-S1).
                lk.lock();
                --connecting_;
                cv_.notify_all();
                throw;
            }
            lk.lock();
            --connecting_;
            if (!c) {
                // Capacity we reserved is free again — wake a waiter so it
                // can retry (or fail) rather than sleep forever.
                cv_.notify_all();
                return {};
            }
            if (shutdown_) {
                PQfinish(c);
                cv_.notify_all();
                last_error_ = "pool is shutting down";
                return {};
            }
            ++open_;
            ++leased_;
            return Lease{this, c};
        }
        // waiters_ keeps the destructor from tearing the pool down while we
        // are still inside the wait (it spins on waiters_ == 0).
        ++waiters_;
        if (deadline)
            cv_.wait_until(lk, *deadline);
        else
            cv_.wait(lk);
        --waiters_;
    }
}

PGconn* PgPool::connect_one() {
    // Expand the caller's conninfo through the `dbname` keyword
    // (expand_dbname=1) and append our connect_timeout default only when the
    // conninfo (or PGCONNECT_TIMEOUT) doesn't set one — libpq has no
    // client-side timeout otherwise, and a black-holed host would wedge the
    // acquiring thread.
    const std::string timeout = std::to_string(connect_timeout_s_);
    const char* keys[] = {"dbname", "connect_timeout", nullptr};
    const char* vals[] = {conninfo_.c_str(), timeout.c_str(), nullptr};
    if (conninfo_has_timeout_)
        keys[1] = nullptr; // vals[1] ignored past the terminator

    PgConn conn{PQconnectdbParams(keys, vals, /*expand_dbname=*/1)};
    if (PQstatus(conn.get()) != CONNECTION_OK) {
        // Safe to surface: connect errors from a *well-formed* conninfo name
        // host/port and the failure cause, never credentials. The malformed
        // case never reaches here (rejected at construction).
        std::string err = conn ? PQerrorMessage(conn.get()) : "out of memory";
        spdlog::warn("PgPool: connection attempt failed: {}", err);
        set_error(std::move(err));
        return nullptr;
    }
    return conn.release();
}

void PgPool::release(PGconn* conn) noexcept {
    bool healthy = PQstatus(conn) == CONNECTION_OK;
    if (healthy && PQtransactionStatus(conn) != PQTRANS_IDLE) {
        // The caller leaked an open/failed transaction into the pool. Roll it
        // back defensively; if the connection still isn't idle, discard it.
        PgResult rollback{PQexec(conn, "ROLLBACK")};
        healthy = PQstatus(conn) == CONNECTION_OK && PQtransactionStatus(conn) == PQTRANS_IDLE;
        if (healthy)
            spdlog::warn("PgPool: connection returned mid-transaction; rolled back");
    }

    std::lock_guard lk{mu_};
    --leased_;
    if (shutdown_ || !healthy) {
        PQfinish(conn);
        --open_;
    } else {
        try {
            idle_.push_back(conn);
        } catch (...) {
            // release() is noexcept; a bad_alloc from the deque must not
            // terminate — drop the connection instead (capacity frees up
            // for a fresh connect).
            PQfinish(conn);
            --open_;
        }
    }
    cv_.notify_all();
}

bool PgPool::with_txn(const std::function<bool(PGconn*)>& fn) {
    Lease lease = acquire();
    if (!lease)
        return false;

    PgResult begin{PQexec(lease.get(), "BEGIN")};
    if (begin.status() != PGRES_COMMAND_OK) {
        spdlog::error("PgPool: BEGIN failed: {}", PQerrorMessage(lease.get()));
        return false;
    }
    // Declared after `lease` so unwind order is txn-rollback first, then the
    // lease returns the (now idle) connection.
    PgTxn txn{lease.get()};
    if (!fn(lease.get()))
        return false; // txn dtor rolls back
    // Refuse to "commit" an aborted transaction: COMMIT in PQTRANS_INERROR
    // completes as ROLLBACK yet reports PGRES_COMMAND_OK, so a callback
    // that swallowed a statement failure and returned true would otherwise
    // get `true` back with nothing persisted (UP-3). Enforce here instead
    // of trusting every store author to check.
    if (PQtransactionStatus(lease.get()) != PQTRANS_INTRANS) {
        spdlog::error("PgPool: with_txn callback returned true on an aborted/idle "
                      "transaction — rolling back");
        return false; // txn dtor rolls back
    }
    return txn.commit();
}

std::string PgPool::last_error() const {
    std::lock_guard lk{mu_};
    return last_error_;
}

std::size_t PgPool::in_use() const {
    std::lock_guard lk{mu_};
    return leased_;
}

std::size_t PgPool::open() const {
    std::lock_guard lk{mu_};
    return open_;
}

void PgPool::set_error(std::string msg) {
    std::lock_guard lk{mu_};
    last_error_ = std::move(msg);
}

} // namespace yuzu::server::pg
