#pragma once

/// @file pg_session_advisory_lock.hpp
/// Generic exception-safe RAII release for a SESSION-scoped Postgres
/// advisory lock — lifted out of `kek_op_lock.hpp`'s `KekOpLockGuard` (#2395,
/// governance-hardened) so a second store that needs a session-scoped lock
/// does not hand-roll its own release protocol.
///
/// The mechanism this guard defends against, precisely: a session advisory
/// lock is released by an explicit `pg_advisory_unlock` call, which is an
/// ORDINARY SQL statement — so if the connection is in an ABORTED
/// transaction when that statement runs, it fails at the QUERY level
/// (`current transaction is aborted, commands ignored until end of
/// transaction block`) rather than actually releasing the lock. The lock
/// then survives whatever ROLLBACK eventually happens, the connection
/// itself stays `CONNECTION_OK`, and `PgPool::release()` (which only checks
/// `PQstatus` and rolls back a non-idle transaction) recycles a connection
/// still holding the lock. Session advisory locks are re-entrant per
/// backend, so the wedge is asymmetric: whichever request next draws the
/// poisoned connection succeeds while every other connection is denied
/// indefinitely.
///
/// An earlier revision of the T12 rotation sweep's store-wide sweep lock
/// (`api_token_store.cpp`, #2964 fix round) carried its own ad-hoc
/// `ScopeExit`-based release with a `pg_advisory_unlock_all()` fallback and a
/// FALSE in-code claim that the fallback was a working safety net.
/// GOVERNANCE CHAOS-INJECTION FINDING (#2964 fix round): that specific call
/// site was NOT actually reachable to the aborted-transaction failure mode
/// above — the unlock guard is declared BEFORE the `pg::PgTxn` covering the
/// classification transaction, so C++'s reverse-destruction-order guarantee
/// means `~PgTxn`'s ROLLBACK always runs before the unlock attempt on every
/// return path, leaving the connection clean by the time the unlock query
/// fires. Induced directly against live Postgres: a forced mid-transaction
/// failure left the database with zero advisory locks held afterward. So
/// this specific hole is closed by declaration order today, not by this
/// guard — do not describe adopting this guard as fixing a live/reachable
/// wedge at that call site.
///
/// What is still wrong, and still worth fixing, regardless: (1)
/// `pg_advisory_unlock_all()` is an ordinary SQL statement too, and fails
/// IDENTICALLY to the targeted unlock in exactly the aborted-transaction
/// case it would be relied on for — it is not a "belt and suspenders"
/// fallback, it is a second copy of the same failure, and the in-code claim
/// that it was a working safety net was false regardless of whether the
/// aborted-transaction case is reachable here; (2) the sweep's safety today
/// is an UNPINNED dependency on getting a specific pair of declarations in a
/// specific order — nothing enforces it, and a future edit (reordering the
/// two declarations, adding an early return between them, or splitting the
/// classification into two transactions) could silently reintroduce exactly
/// the KEK-class hazard this guard exists to close, with no compiler
/// diagnostic and no test failure. Adopting this shared, already-hardened
/// guard removes that dependency: its destructor handles a failed unlock
/// correctly (dead-connection vs live-connection discrimination, backend
/// self-termination on the live case) regardless of WHY the unlock query
/// failed or what declaration order got it there — correct by construction,
/// not correct by the current code's luck.

#include "pg_raii.hpp"

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#include <string>
#include <utility>

namespace yuzu::server::pg {

/// Construct only after the caller has confirmed the lock was actually
/// granted (e.g. a `pg_try_advisory_lock`/`pg_advisory_lock` call that
/// returned true) — OR, defensively, when the caller could not tell whether
/// it was granted (a failed try-lock probe) and wants to release-if-held
/// rather than risk leaving a silently-granted lock on the connection. In
/// the latter case, releasing a lock this session never held is a harmless
/// no-op (Postgres reports `false`, which this guard treats the same as
/// "released" — see the destructor).
///
/// Declare this guard AFTER the pool `Lease`/connection in the same scope so
/// it destructs (releases) BEFORE the lease returns the connection to the
/// pool — a session-scoped advisory lock outlives the statement/transaction
/// that took it, so releasing it here is not optional cleanup, it is the
/// only way to unlock at all.
class PgSessionAdvisoryLockGuard {
public:
    /// `unlock_sql` — a complete `SELECT pg_advisory_unlock(...)` statement
    /// (single-bigint-key or two-int32-key form, caller's choice) whose sole
    /// output column is the boolean unlock result. `label` is a short,
    /// human-readable name for this lock (e.g. `"KEK op"`,
    /// `"api_token_store rotation sweep"`) used to prefix every log line this
    /// guard emits, so a caller can tell which lock family is misbehaving
    /// without inspecting the SQL string.
    PgSessionAdvisoryLockGuard(PGconn* conn, std::string unlock_sql, std::string label) noexcept
        : conn_(conn), unlock_sql_(std::move(unlock_sql)), label_(std::move(label)) {}

    ~PgSessionAdvisoryLockGuard() {
        // Implicitly noexcept: a throwing log sink here would std::terminate
        // on the exact path that already signals trouble. Everything below
        // is wrapped.
        try {
            pg::PgResult res{PQexec(conn_, unlock_sql_.c_str())};
            // A successfully-executed unlock query (`res.ok()`, i.e. the
            // QUERY ran, regardless of the boolean value it returned) is
            // never itself the wedge case this guard exists to prevent — a
            // `false` return means "this session did not hold the lock",
            // which is a legitimate benign outcome for the defensive
            // release-if-held case above, not a fault. The actual failure
            // mode reproduced against live Postgres is the query ITSELF
            // failing (aborted-transaction), which `res.ok()` catches.
            if (res.ok())
                return;

            // The unlock QUERY failed. Two very different worlds:
            //
            //  - Connection already dead => the SESSION is gone, and a
            //    session-scoped advisory lock dies with its session. Nothing
            //    leaked; the pool discards the connection on release.
            //  - Connection still HEALTHY => the lock is genuinely still
            //    held (or unknowable — an aborted transaction blocks every
            //    ordinary statement, including the unlock itself), and
            //    `PgPool::release` would hand this connection back to the
            //    pool possibly still holding it. Session advisory locks are
            //    re-entrant per backend, so the wedge is worse than it
            //    looks: whichever request next draws THIS connection
            //    succeeds while every other connection is denied
            //    indefinitely.
            //
            // For the second case, end the session deliberately. Terminating
            // our own backend releases every session lock it holds and marks
            // the connection bad, so `PgPool::release` discards it instead of
            // recycling a poisoned one. Killing one pooled connection is
            // strictly better than wedging this lock cluster-wide until the
            // next process restart.
            if (PQstatus(conn_) != CONNECTION_OK) {
                spdlog::warn("{}: advisory-lock release failed on an already-dead connection — "
                             "the session (and its locks) are gone; nothing leaked",
                             label_);
                return;
            }
            spdlog::critical("{}: could not release the advisory lock on a live connection: {} "
                             "— terminating this backend to guarantee the lock is released",
                             label_, PQerrorMessage(conn_));
            pg::PgResult kill{PQexec(conn_, "SELECT pg_terminate_backend(pg_backend_pid())")};
            (void)kill; // best-effort; the connection is discarded either way
        } catch (...) {
            // Nothing safe left to do during unwind.
        }
    }

    PgSessionAdvisoryLockGuard(const PgSessionAdvisoryLockGuard&) = delete;
    PgSessionAdvisoryLockGuard& operator=(const PgSessionAdvisoryLockGuard&) = delete;
    PgSessionAdvisoryLockGuard(PgSessionAdvisoryLockGuard&&) = delete;
    PgSessionAdvisoryLockGuard& operator=(PgSessionAdvisoryLockGuard&&) = delete;

private:
    PGconn* conn_;
    std::string unlock_sql_;
    std::string label_;
};

} // namespace yuzu::server::pg
