#pragma once

/**
 * test_helpers.hpp — shared test utilities for agent + server unit suites.
 *
 * Header-only inline implementations so every test executable that includes
 * this file owns its own salt and counter. There is no shared-state hazard
 * across the two test binaries — each process gets its own static locals at
 * first use.
 *
 * Layout: `tests/unit/test_helpers.hpp`. Agent-side tests include with
 * `"test_helpers.hpp"`; server-side tests with `"../test_helpers.hpp"`.
 * Intentionally not promoted to a separate include directory in meson —
 * `#include` paths alone are enough, and keeping the header next to the
 * consumers makes grep-discoverable what tests rely on it.
 *
 * History: commit a90a21e hardened `test_guardian_engine.cpp`'s
 * `unique_kv_path()` after Windows MSVC flake #473 traced the fixture
 * collision to `std::hash<std::thread::id>{}` + `steady_clock::now()` —
 * single-threaded Catch2 runs left the clock as the only uniqueness source,
 * and MSVC's steady_clock resolution on some Windows builds was coarse
 * enough that two back-to-back fixtures produced identical paths under
 * Defender-induced I/O serialisation. See #482 for the follow-up that
 * ported the same fix across `test_rest_guaranteed_state.cpp`,
 * `test_rest_api_tokens.cpp`, `test_rest_api_t2.cpp`, and
 * `test_kv_store.cpp`.
 */

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <random>
#include <string>
#include <string_view>

#if defined(YUZU_TEST_ENABLE_PG)
#include <format>

#include <libpq-fe.h>

#include "pg/pg_raii.hpp" // server suite only — include path carries server/core/src
#endif

namespace yuzu::test {

/// Generate a unique filesystem path under the system temp directory.
///
/// Uniqueness is guaranteed within a process by a monotonic atomic counter;
/// the counter's initial value is seeded from a process-local 64-bit random
/// salt so two concurrently-running test binaries (if meson ever runs `-j2`
/// on a single suite) cannot collide with each other either. Clock-based
/// uniqueness is explicitly NOT part of the scheme — MSVC's steady_clock on
/// some Windows builds has coarse-enough resolution under Defender-induced
/// I/O serialisation that two back-to-back fixture constructions produced
/// identical paths, causing flake #473.
///
/// The returned path does NOT exist on disk and has no parent directory
/// created. Callers are responsible for creating parent directories and
/// cleaning up (prefer `TempDbFile` RAII below for SQLite stores).
inline std::filesystem::path unique_temp_path(std::string_view prefix = "yuzu-test-") {
    static const std::uint64_t salt = [] {
        std::mt19937_64 rng{std::random_device{}()};
        return rng();
    }();
    static std::atomic<std::uint64_t> counter{0};
    const auto n = counter.fetch_add(1, std::memory_order_relaxed);

    std::string name;
    name.reserve(prefix.size() + 40);
    name.append(prefix);
    name.append(std::to_string(salt));
    name.push_back('_');
    name.append(std::to_string(n));
    return std::filesystem::temp_directory_path() / name;
}

/// RAII guard for a per-test SQLite database file. Cleans up the base
/// `.db` plus the `-wal` and `-shm` companion files on destruction. Declare
/// this as the FIRST member of any test harness that opens SQLite so the
/// destructor fires even if downstream construction throws — partial-
/// construction leak pattern documented in `feedback_governance_run.md`
/// (finding qe-B1 from Run 3).
///
/// This is the preferred pattern for new tests. `unique_temp_path()` alone
/// is a lower-level primitive exposed for tests that do not own a SQLite
/// file (e.g. KV-store tests which open via `KvStore::open(path)` and do
/// not generate WAL/SHM directly).
/// RAII temp DIRECTORY for tests that need a private scratch dir (e.g. a
/// FileKeyProvider base dir). Created lazily by the consumer; recursively
/// removed on destruction. Promoted from per-file copies in
/// test_key_provider.cpp / test_secret_codec.cpp (governance CON-S4 — the
/// promote-at-second-user rule; test_default_certs.cpp's local copy migrates
/// opportunistically).
struct TempDir {
    std::filesystem::path path;
    TempDir() : path(unique_temp_path("yuzu-test-dir-")) {}
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
};

struct TempDbFile {
    std::filesystem::path path;

    explicit TempDbFile(std::string_view prefix = "yuzu-test-") : path(unique_temp_path(prefix)) {}

    /// Adopt a caller-computed path. Useful when the fixture needs to place
    /// the file under a subdirectory that `unique_temp_path` does not model
    /// (e.g. a per-UID dir shared across tests). The caller is still
    /// responsible for ensuring the path is unique — typically by deriving
    /// its filename from `unique_temp_path`.
    explicit TempDbFile(std::filesystem::path explicit_path) : path(std::move(explicit_path)) {}

    ~TempDbFile() noexcept {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        std::filesystem::remove(std::filesystem::path(path.string() + "-wal"), ec);
        std::filesystem::remove(std::filesystem::path(path.string() + "-shm"), ec);
    }

    TempDbFile(const TempDbFile&) = delete;
    TempDbFile& operator=(const TempDbFile&) = delete;
    TempDbFile(TempDbFile&&) = delete;
    TempDbFile& operator=(TempDbFile&&) = delete;
};

#if defined(YUZU_TEST_ENABLE_PG)

/// ── Postgres test support (#1320 PR 1) ──────────────────────────────────
///
/// Compiled only into suites that link libpq (the server suite defines
/// YUZU_TEST_ENABLE_PG in tests/meson.build); the agent/tar suites include
/// this header without a libpq include path, so everything Postgres-shaped
/// stays behind the guard.
///
/// Skip-vs-fail contract (F1 ledger, #1320): when YUZU_TEST_POSTGRES_DSN is
/// UNSET the test skips cleanly (local dev without a Postgres). When it is
/// SET but broken the test FAILS — in CI `scripts/ci/ensure-postgres.sh`
/// guarantees a reachable database (SOFT_EXIT=1), so an unreachable DSN is
/// breakage to surface, never to skip past.

/// The operator/CI-provided admin DSN, or nullptr when unset/empty.
inline const char* pg_admin_dsn_env() {
    const char* v = std::getenv("YUZU_TEST_POSTGRES_DSN");
    return (v != nullptr && v[0] != '\0') ? v : nullptr;
}

/// RAII fixture for an ephemeral, uniquely-named Postgres database.
///
/// Connects to YUZU_TEST_POSTGRES_DSN, issues `CREATE DATABASE
/// yuzu_test_<salt>_<n>`, and exposes a rewritten conninfo (`dsn()`)
/// pointing at it; the destructor drops the database (`WITH (FORCE)`, so a
/// leaked test connection cannot keep it alive). Name uniqueness uses the
/// same process-salt + atomic-counter scheme as `unique_temp_path` — never
/// thread-id/clock salting (flake #473).
class PostgresTestDb {
public:
    PostgresTestDb() {
        const char* admin = pg_admin_dsn_env();
        if (admin == nullptr) {
            error_ = "YUZU_TEST_POSTGRES_DSN not set";
            return;
        }
        admin_dsn_ = admin;
        db_name_ = unique_db_name();

        // RAII owners (server/core/src/pg/pg_raii.hpp): an allocation throw
        // while building error_ must not leak the admin connection/result.
        yuzu::server::pg::PgConn conn{PQconnectdb(admin_dsn_.c_str())};
        if (PQstatus(conn.get()) != CONNECTION_OK) {
            error_ = std::string("admin connect failed: ") + PQerrorMessage(conn.get());
            return;
        }
        const std::string create = "CREATE DATABASE \"" + db_name_ + "\"";
        yuzu::server::pg::PgResult res{PQexec(conn.get(), create.c_str())};
        if (!res.ok()) {
            error_ = std::string("CREATE DATABASE failed: ") + PQerrorMessage(conn.get());
            return;
        }
        res.reset();
        conn.reset();

        dsn_ = rewrite_dbname(admin_dsn_, db_name_);
        if (dsn_.empty()) {
            error_ = "could not parse YUZU_TEST_POSTGRES_DSN to rewrite dbname";
            return;
        }
        available_ = true;
    }

    ~PostgresTestDb() {
        if (db_name_.empty() || admin_dsn_.empty())
            return;
        yuzu::server::pg::PgConn conn{PQconnectdb(admin_dsn_.c_str())};
        if (PQstatus(conn.get()) != CONNECTION_OK) {
            // Can't throw from a dtor — but a silent failure piles leaked
            // yuzu_test_* databases onto a shared instance; say so.
            log_leak("teardown admin connect failed", nullptr);
            return;
        }
        // FORCE (PG 13+; every supported leg pins 16): terminate any
        // connection a test leaked so the drop cannot fail and pile up
        // databases on the shared instance.
        const std::string drop = "DROP DATABASE IF EXISTS \"" + db_name_ + "\" WITH (FORCE)";
        yuzu::server::pg::PgResult res{PQexec(conn.get(), drop.c_str())};
        if (!res.ok())
            log_leak("DROP DATABASE failed", PQerrorMessage(conn.get()));
    }

    PostgresTestDb(const PostgresTestDb&) = delete;
    PostgresTestDb& operator=(const PostgresTestDb&) = delete;
    PostgresTestDb(PostgresTestDb&&) = delete;
    PostgresTestDb& operator=(PostgresTestDb&&) = delete;

    /// True when the ephemeral database exists and `dsn()` is usable.
    [[nodiscard]] bool available() const noexcept { return available_; }
    /// Why `available()` is false.
    [[nodiscard]] const std::string& error() const noexcept { return error_; }
    /// Conninfo (keyword/value form) for the ephemeral database.
    [[nodiscard]] const std::string& dsn() const noexcept { return dsn_; }
    [[nodiscard]] const std::string& db_name() const noexcept { return db_name_; }

private:
    // std::format + fputs, never printf-family (docs/cpp-conventions.md;
    // std::print is unavailable on GCC 13 libstdc++ / Apple Clang 15 — same
    // portable form as canary_main.cpp). Called from the dtor, so formatting
    // must not throw out: fall back to a static message on bad_alloc.
    void log_leak(const char* what, const char* detail) const noexcept {
        try {
            const std::string msg =
                detail != nullptr
                    ? std::format("PostgresTestDb: {} — leaked {}: {}\n", what, db_name_, detail)
                    : std::format("PostgresTestDb: {} — leaked {}\n", what, db_name_);
            std::fputs(msg.c_str(), stderr);
        } catch (...) {
            std::fputs("PostgresTestDb: teardown failed — leaked a yuzu_test_* database\n", stderr);
        }
    }

    static std::string unique_db_name() {
        static const std::uint64_t salt = [] {
            std::mt19937_64 rng{std::random_device{}()};
            return rng();
        }();
        static std::atomic<std::uint64_t> counter{0};
        const auto n = counter.fetch_add(1, std::memory_order_relaxed);
        return "yuzu_test_" + std::to_string(salt % 1000000000) + "_" + std::to_string(n);
    }

    /// Re-emit `admin_dsn` as a keyword/value conninfo with dbname replaced.
    /// Round-trips through PQconninfoParse so both URI and keyword forms
    /// work. Returns empty on parse failure.
    static std::string rewrite_dbname(const std::string& admin_dsn, const std::string& new_db) {
        char* errmsg = nullptr;
        PQconninfoOption* opts = PQconninfoParse(admin_dsn.c_str(), &errmsg);
        if (opts == nullptr) {
            if (errmsg != nullptr)
                PQfreemem(errmsg);
            return {};
        }
        std::string out;
        for (PQconninfoOption* o = opts; o->keyword != nullptr; ++o) {
            if (o->val == nullptr || std::string_view(o->keyword) == "dbname")
                continue;
            out += o->keyword;
            out += "='";
            for (const char* p = o->val; *p != '\0'; ++p) {
                if (*p == '\\' || *p == '\'')
                    out += '\\';
                out += *p;
            }
            out += "' ";
        }
        PQconninfoFree(opts);
        out += "dbname='" + new_db + "'";
        return out;
    }

    std::string admin_dsn_;
    std::string db_name_;
    std::string dsn_;
    std::string error_;
    bool available_{false};
};

/// Standard prologue for a Postgres-backed TEST_CASE: skip when no DSN is
/// configured, fail when it is configured but broken, else bind `var` to a
/// fresh ephemeral database. Requires Catch2 macros at the expansion site.
/// Expands to an unbraced `if` plus declarations — use only as a direct
/// statement at block scope (never as the body of an if/loop).
#define YUZU_REQUIRE_PG_DB(var)                                                                    \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                              \
    yuzu::test::PostgresTestDb var;                                                                \
    INFO("PostgresTestDb: " << var.error());                                                       \
    REQUIRE(var.available())

#endif // YUZU_TEST_ENABLE_PG

} // namespace yuzu::test
