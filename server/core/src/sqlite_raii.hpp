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

/// RAII owner for a `char*` message allocated by SQLite (the `errmsg` out-param
/// of `sqlite3_exec`). `sqlite3_free` runs on scope exit, so a throw between the
/// `exec` and the free -- an fmt or `bad_alloc` throw from the log call that
/// formats the message being the realistic one -- cannot leak it. Move-only.
class SqliteErrMsg {
public:
    SqliteErrMsg() = default;
    ~SqliteErrMsg() { reset(); }

    SqliteErrMsg(const SqliteErrMsg&) = delete;
    SqliteErrMsg& operator=(const SqliteErrMsg&) = delete;
    SqliteErrMsg(SqliteErrMsg&& o) noexcept : m_(o.m_) { o.m_ = nullptr; }
    SqliteErrMsg& operator=(SqliteErrMsg&& o) noexcept {
        if (this != &o) {
            reset();
            m_ = o.m_;
            o.m_ = nullptr;
        }
        return *this;
    }

    /// Address for `sqlite3_exec(db, sql, nullptr, nullptr, msg.addr())`.
    char** addr() noexcept {
        reset(); // reusing a live owner would otherwise leak the old message
        return &m_;
    }

    /// Never null. SQLite leaves the out-param untouched on success and does not
    /// set it on every failure path either, so callers get a usable string
    /// without each writing its own ternary at the log site.
    const char* c_str() const noexcept { return m_ ? m_ : "unknown error"; }

    void reset() noexcept {
        if (m_) {
            sqlite3_free(m_);
            m_ = nullptr;
        }
    }

private:
    char* m_{nullptr};
};

/// RAII owner for the connection itself. `sqlite3_close` runs on scope exit,
/// which is what makes a store's CONSTRUCTOR exception-safe: a throw after the
/// handle is open but before the constructor completes means `~Store` never
/// runs, so a raw `sqlite3*` member leaks the connection and its WAL/SHM files.
/// Holding the handle in a member owner instead moves the close into member
/// destruction, which DOES run during constructor unwind. Move-only.
///
/// `close()` is exposed for stores that deliberately close early and then treat
/// a null handle as "degraded, fail every operation" (a failed migration, for
/// example); it is idempotent, so the destructor after an explicit close is a
/// no-op rather than a double close.
class SqliteDb {
public:
    SqliteDb() = default;
    explicit SqliteDb(sqlite3* db) noexcept : db_(db) {}
    ~SqliteDb() { close(); }

    SqliteDb(const SqliteDb&) = delete;
    SqliteDb& operator=(const SqliteDb&) = delete;
    SqliteDb(SqliteDb&& o) noexcept : db_(o.db_) { o.db_ = nullptr; }
    SqliteDb& operator=(SqliteDb&& o) noexcept {
        if (this != &o) {
            close();
            db_ = o.db_;
            o.db_ = nullptr;
        }
        return *this;
    }

    /// Address for `sqlite3_open_v2(path, db.addr(), flags, nullptr)`. SQLite
    /// may allocate the handle even when the open FAILS, which is exactly why it
    /// wants an owner from the first call rather than after the error check.
    sqlite3** addr() noexcept {
        close(); // re-opening through a live owner would otherwise leak it
        return &db_;
    }
    sqlite3* get() const noexcept { return db_; }
    explicit operator bool() const noexcept { return db_ != nullptr; }

    /// close_v2, NOT close. `sqlite3_close` returns SQLITE_BUSY and does NOT
    /// close when any statement is still outstanding -- so nulling the member
    /// after it would leak the connection and its WAL/SHM files while this owner
    /// reported success, which is precisely the leak this class exists to stop.
    /// close_v2 marks the connection zombie and closes it when the last
    /// statement finalizes. Reachable: a store method holding a raw
    /// `sqlite3_stmt*` across an allocating loop can unwind past its finalize.
    void close() noexcept {
        if (db_) {
            sqlite3_close_v2(db_);
            db_ = nullptr;
        }
    }

private:
    sqlite3* db_{nullptr};
};

} // namespace yuzu::server
