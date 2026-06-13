#pragma once

/// @file sqlite_raii.hpp
/// Tiny RAII owners for the two SQLite resources whose manual cleanup is easy to
/// leak on an early return or — the case that motivated this header — an
/// exception thrown between `BEGIN` and `COMMIT` (e.g. a `std::bad_alloc` from a
/// `std::string`/container op while building an error message or de-dup set).
/// CLAUDE.md governance treats manual resource cleanup not wrapped in a RAII
/// owner as BLOCKING; these are the owners the Guardian stores use.
///
/// Reuse note: `response_store` caches *persistent* prepared statements as
/// members (a different ownership model); these owners are for the
/// *per-operation* prepare/step/finalize pattern the Baseline + event stores use
/// inside a transaction.

#include <sqlite3.h>

namespace yuzu::server {

/// RAII finalizer for a prepared statement. `sqlite3_finalize` runs on scope
/// exit — including exception unwind — so no early-return/error/throw path
/// between prepare and finalize can leak the statement. Move-only.
class SqliteStmt {
public:
    SqliteStmt() = default;
    explicit SqliteStmt(sqlite3_stmt* s) noexcept : s_(s) {}
    ~SqliteStmt() { reset(); }

    SqliteStmt(const SqliteStmt&) = delete;
    SqliteStmt& operator=(const SqliteStmt&) = delete;
    SqliteStmt(SqliteStmt&& o) noexcept : s_(o.s_) { o.s_ = nullptr; }
    SqliteStmt& operator=(SqliteStmt&& o) noexcept {
        if (this != &o) {
            reset();
            s_ = o.s_;
            o.s_ = nullptr;
        }
        return *this;
    }

    /// Address for `sqlite3_prepare_v2(db, sql, -1, stmt.addr(), nullptr)`.
    sqlite3_stmt** addr() noexcept { return &s_; }
    sqlite3_stmt* get() const noexcept { return s_; }
    explicit operator bool() const noexcept { return s_ != nullptr; }

    /// Finalize early (e.g. before COMMIT). Idempotent.
    void reset() noexcept {
        if (s_) {
            sqlite3_finalize(s_);
            s_ = nullptr;
        }
    }

private:
    sqlite3_stmt* s_{nullptr};
};

/// RAII transaction guard. The CALLER issues `BEGIN` (so it can choose
/// `BEGIN`/`BEGIN IMMEDIATE` and map the begin-failure error itself) and then
/// constructs the guard. On scope exit the guard issues `ROLLBACK` unless
/// `commit()` has succeeded — so any early return OR exception between `BEGIN`
/// and a successful `commit()` leaves the connection rolled back, never wedged in
/// an open transaction.
///
/// Ordering: declare the guard BEFORE any `SqliteStmt` used in the transaction
/// (or finalize the statements first). C++ destroys locals in reverse order, so
/// the statements then finalize before the rollback runs — SQLite wants live
/// statements finalized/reset before `ROLLBACK`.
class SqliteTxn {
public:
    explicit SqliteTxn(sqlite3* db) noexcept : db_(db) {}
    ~SqliteTxn() {
        if (db_ && !committed_)
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
    }

    SqliteTxn(const SqliteTxn&) = delete;
    SqliteTxn& operator=(const SqliteTxn&) = delete;

    /// Run `COMMIT`; on success disarm the rollback. On failure the guard stays
    /// armed and the destructor rolls back. Returns the `sqlite3_exec` code.
    int commit() noexcept {
        const int rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr);
        if (rc == SQLITE_OK)
            committed_ = true;
        return rc;
    }

private:
    sqlite3* db_{nullptr};
    bool committed_{false};
};

} // namespace yuzu::server
