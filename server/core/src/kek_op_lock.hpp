#pragma once

/// @file kek_op_lock.hpp
/// The cluster-wide KEK-operation advisory lock (#2395).
///
/// Extracted from server.cpp so it can be exercised directly by tests: this is
/// the highest-consequence resource in the KEK surface. A leaked session-scoped
/// advisory lock is not a transient error — it wedges every future KEK
/// operation across the whole cluster until the holding backend dies, and
/// because session advisory locks are RE-ENTRANT per backend, the wedge is
/// asymmetric: whichever request next draws the poisoned pooled connection
/// succeeds while every other connection gets 409 (gov unhappy-path UP-1).
/// Governance cpp-safety flagged that this had zero test coverage; it now has
/// a [pg] test that takes two real connections.

#include "pg/pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <chrono>

namespace yuzu::server::detail {

constexpr std::chrono::milliseconds kKekOpAcquireTimeout{5000};
constexpr const char* kKekOpTryLockSql =
    "SELECT pg_try_advisory_lock(2037545589, hashtext('secrets_kek_op'))";
constexpr const char* kKekOpUnlockSql =
    "SELECT pg_advisory_unlock(2037545589, hashtext('secrets_kek_op'))";

enum class KekOpLockAttempt { kAcquired, kConflict, kError };

/// Non-blocking try-lock on `conn`. `kConflict` means another KEK operation
/// (rotate/rewrap/status, on this server or another pointed at the same
/// database) currently holds it — the caller must NOT wait, just report
/// Conflict immediately (rule from #2395: KEK ops never queue behind each
/// other).
[[nodiscard]] inline KekOpLockAttempt try_lock_kek_op(PGconn* conn) {
    pg::PgResult res{PQexec(conn, kKekOpTryLockSql)};
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("KEK op: advisory-lock attempt failed: {}", PQerrorMessage(conn));
        return KekOpLockAttempt::kError;
    }
    // Guard the row read by construction, not by assumption: PQgetvalue
    // returns nullptr out-of-range, so a future edit to the SQL would turn
    // this into a null deref on a privileged path (gov cpp-safety NICE).
    if (PQntuples(res.get()) != 1 || PQgetisnull(res.get(), 0, 0)) {
        spdlog::error("KEK op: advisory-lock attempt returned an unexpected result shape");
        return KekOpLockAttempt::kError;
    }
    return (PQgetvalue(res.get(), 0, 0)[0] == 't') ? KekOpLockAttempt::kAcquired
                                                    : KekOpLockAttempt::kConflict;
}

/// RAII release of the `secrets_kek_op` session advisory lock taken via
/// `try_lock_kek_op`. Fires on EVERY exit path, including an exception
/// unwind — a leaked session-scoped advisory lock wedges every future KEK
/// operation across the whole cluster against this one backend connection
/// until that backend process dies, so this is the single highest-risk line
/// in the KEK seam (#2395). Construct it only after a `kAcquired` result, and
/// declare it AFTER the pool `Lease` in the same scope so it destructs
/// (releases) BEFORE the lease returns the connection to the pool — a
/// session advisory lock outlives the statement, so releasing it is not
/// optional cleanup, it is the only way to unlock at all.
class KekOpLockGuard {
public:
    explicit KekOpLockGuard(PGconn* conn) noexcept : conn_(conn) {}
    ~KekOpLockGuard() {
        // Implicitly noexcept: a throwing log sink here would std::terminate on
        // the exact path that already signals trouble. Everything is wrapped.
        try {
            pg::PgResult res{PQexec(conn_, kKekOpUnlockSql)};
            if (res.ok())
                return;

            // The unlock failed. Two very different worlds (gov cpp-safety
            // BLOCKING / unhappy-path UP-1):
            //
            //  - Connection already dead => the SESSION is gone, and a
            //    session-scoped advisory lock dies with its session. Nothing
            //    leaked; the pool discards the connection on release.
            //  - Connection still HEALTHY => the lock is genuinely still held,
            //    and PgPool::release would hand this connection back to the
            //    pool still holding it. Session advisory locks are re-entrant
            //    per backend, so the wedge is worse than it looks: whichever
            //    request next draws THIS connection succeeds while every other
            //    connection 409s indefinitely.
            //
            // For the second case, end the session deliberately. Terminating
            // our own backend releases every session lock it holds and marks
            // the connection bad, so PgPool::release discards it instead of
            // recycling a poisoned one. Killing one pooled connection is
            // strictly better than wedging KEK rotation cluster-wide until the
            // next process restart.
            if (PQstatus(conn_) != CONNECTION_OK) {
                spdlog::warn("KEK op: advisory-lock release failed on an already-dead "
                             "connection — the session (and its locks) are gone; nothing leaked");
                return;
            }
            spdlog::critical("KEK op: could not release the 'secrets_kek_op' advisory lock on a "
                             "live connection: {} — terminating this backend to guarantee the "
                             "lock is released",
                             PQerrorMessage(conn_));
            pg::PgResult kill{PQexec(conn_, "SELECT pg_terminate_backend(pg_backend_pid())")};
            (void)kill; // best-effort; the connection is discarded either way
        } catch (...) {
            // Nothing safe left to do during unwind.
        }
    }
    KekOpLockGuard(const KekOpLockGuard&) = delete;
    KekOpLockGuard& operator=(const KekOpLockGuard&) = delete;
    KekOpLockGuard(KekOpLockGuard&&) = delete;
    KekOpLockGuard& operator=(KekOpLockGuard&&) = delete;

private:
    PGconn* conn_;
};

} // namespace yuzu::server::detail
