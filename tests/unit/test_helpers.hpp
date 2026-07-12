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
#include <chrono>
#include <expected>
#include <format>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <thread>

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

/// ── Stale test-database sweeping ─────────────────────────────────────────
///
/// An abnormal exit (SIGKILL, OOM, the CI job-timeout kill — i.e. exactly
/// the incident this machinery exists for) leaks that process's ephemeral
/// and template databases permanently: nothing re-runs their teardown, and
/// there is no janitor on the shared instances (#2091 review). Every
/// database name therefore embeds its creation epoch
/// (`yuzu_test_<epoch>_<salt>_<n>`, `yuzu_test_tpl_<epoch>_<salt>_<key>`),
/// and the Catch2 testRunStarting listener (test_pg_template_cleanup.cpp)
/// sweeps names older than kTestDbStaleAfterSeconds at suite start.
///
/// Safety against concurrent suites on one shared instance (Wee Tam / Big
/// Tam run 4 runner agents per box): the threshold is far beyond any CI
/// server-suite-running job's possible lifetime (their job-level timeouts
/// are 90-120 min; jobs without [pg] tests never own these DBs), so a
/// swept database cannot belong to a live run. Pre-epoch-format names
/// (`yuzu_test_<salt>_<n>` — salt < 1e9 parses as a pre-2021 "epoch") are
/// deliberately NOT swept: during rollout a concurrent job running an
/// older binary may legitimately own one. Old leaks need one manual
/// `DROP`; everything after this format sweeps automatically.
inline constexpr std::int64_t kTestDbStaleAfterSeconds = 6 * 3600;

/// Parse the creation epoch out of a test-database name, or nullopt when
/// the name is not ours / malformed / not charset-safe. Charset guard
/// matters: sweep-eligible names are spliced into a quoted DROP statement,
/// so anything outside [a-z0-9_] is refused outright. Pure.
inline std::optional<std::int64_t> parse_test_db_epoch(std::string_view datname) {
    constexpr std::string_view prefix = "yuzu_test_";
    if (!datname.starts_with(prefix))
        return std::nullopt;
    for (const char c : datname)
        if ((c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_')
            return std::nullopt;
    std::string_view rest = datname.substr(prefix.size());
    if (rest.starts_with("tpl_"))
        rest = rest.substr(4);
    std::int64_t epoch = 0;
    std::size_t i = 0;
    for (; i < rest.size() && rest[i] >= '0' && rest[i] <= '9'; ++i) {
        // Bound the digit run BEFORE accumulating: a hostile co-tenant name
        // with a 20-digit run would signed-overflow (UB). Valid epochs are
        // 10 digits; 12 is generous slack.
        if (i >= 12)
            return std::nullopt;
        epoch = epoch * 10 + (rest[i] - '0');
    }
    if (i == 0 || i == rest.size() || rest[i] != '_')
        return std::nullopt;
    return epoch;
}

/// True iff the parsed epoch is inside the plausibility window:
/// pre-epoch-format salts are < 1e9 (pre-2021) and a clock-skewed future
/// stamp must not look "aged"; both are excluded (and therefore never
/// swept — only hand-cleaning reclaims them).
inline bool test_db_epoch_plausible(std::int64_t epoch, std::int64_t now_epoch) {
    return epoch >= 1'600'000'000 && epoch <= now_epoch + 86'400;
}

/// True iff `datname` is one of ours (charset-guarded), carries a
/// plausible creation epoch, and that epoch is older than
/// kTestDbStaleAfterSeconds relative to `now_epoch`. Pure — unit-tested
/// with a fixed `now_epoch`.
inline bool test_db_is_stale(std::string_view datname, std::int64_t now_epoch) {
    const auto epoch = parse_test_db_epoch(datname);
    if (!epoch || !test_db_epoch_plausible(*epoch, now_epoch))
        return false;
    return now_epoch - *epoch > kTestDbStaleAfterSeconds;
}

/// Best-effort sweep of stale `yuzu_test_*` databases on the shared
/// instance. Failures are non-fatal but announced (a silent skip would
/// extend the leak horizon with no signal); every drop is announced on
/// stderr, plus one unconditional summary line so CI logs distinguish
/// "nothing to sweep" from "sweep never ran".
inline void sweep_stale_test_databases(const std::string& admin_dsn) {
    try {
        yuzu::server::pg::PgConn conn{PQconnectdb(admin_dsn.c_str())};
        if (PQstatus(conn.get()) != CONNECTION_OK) {
            std::fputs("PgTestTemplate: sweep skipped — admin connect failed\n", stderr);
            return;
        }
        // 'now' comes from the SERVER clock, not the runner clock: names are
        // stamped by whichever runner created them, and on the per-box CI
        // topology (Postgres local to each runner host) the server clock IS
        // the stamper clock — this collapses stamper-vs-sweeper skew when a
        // second machine's suite does the sweeping.
        std::int64_t now = 0;
        {
            yuzu::server::pg::PgResult t{
                PQexec(conn.get(), "SELECT extract(epoch FROM now())::bigint")};
            if (PQresultStatus(t.get()) == PGRES_TUPLES_OK && PQntuples(t.get()) == 1) {
                now = std::atoll(PQgetvalue(t.get(), 0, 0));
            } else {
                now = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
            }
        }
        yuzu::server::pg::PgResult res{PQexec(
            conn.get(), "SELECT datname FROM pg_database WHERE datname LIKE 'yuzu\\_test\\_%'")};
        if (PQresultStatus(res.get()) != PGRES_TUPLES_OK) {
            std::fputs("PgTestTemplate: sweep skipped — pg_database query failed\n", stderr);
            return;
        }
        const int total = PQntuples(res.get());
        int swept = 0;
        int unsweepable = 0; // parse-fail or implausible epoch — NOT live fresh names
        for (int i = 0; i < total; ++i) {
            const std::string name = PQgetvalue(res.get(), i, 0);
            const auto epoch = parse_test_db_epoch(name);
            if (!epoch || !test_db_epoch_plausible(*epoch, now)) {
                ++unsweepable;
                continue;
            }
            if (now - *epoch <= kTestDbStaleAfterSeconds)
                continue; // plausibly live — a concurrent run's database
            const std::string drop = "DROP DATABASE IF EXISTS \"" + name + "\" WITH (FORCE)";
            yuzu::server::pg::PgResult d{PQexec(conn.get(), drop.c_str())};
            if (d.ok()) {
                ++swept;
                std::fputs(
                    std::format("PgTestTemplate: swept stale test database {}\n", name).c_str(),
                    stderr);
            } else {
                std::fputs(std::format("PgTestTemplate: stale sweep of {} failed: {} — drop it "
                                       "manually if it persists\n",
                                       name, PQerrorMessage(conn.get()))
                               .c_str(),
                           stderr);
            }
        }
        std::fputs(std::format("PgTestTemplate: sweep saw {} yuzu_test_* database(s), dropped {} "
                               "stale\n",
                               total, swept)
                       .c_str(),
                   stderr);
        // Names the sweeper can NEVER reclaim (pre-epoch format, implausible
        // clock stamps) only accumulate — say so before it becomes an
        // incident. Fresh live names from concurrent runs are deliberately
        // NOT counted here (they self-clean).
        if (unsweepable > 50)
            std::fputs(std::format("PgTestTemplate: WARNING — {} yuzu_test_* databases can never "
                                   "be swept (pre-epoch names or implausible clock stamps); "
                                   "inspect and hand-clean the instance\n",
                                   unsweepable)
                           .c_str(),
                       stderr);
    } catch (...) {
        std::fputs("PgTestTemplate: sweep aborted by exception\n", stderr);
    }
}

class PgTestTemplate;

/// RAII fixture for an ephemeral, uniquely-named Postgres database.
///
/// Connects to YUZU_TEST_POSTGRES_DSN, issues `CREATE DATABASE
/// yuzu_test_<epoch>_<salt>_<n>`, and exposes a rewritten conninfo (`dsn()`)
/// pointing at it; the destructor drops the database (`WITH (FORCE)`, so a
/// leaked test connection cannot keep it alive). Name uniqueness uses the
/// same process-salt + atomic-counter scheme as `unique_temp_path` — never
/// thread-id/clock salting (flake #473).
///
/// The one-arg form clones from a pre-migrated `PgTestTemplate` instead of
/// creating an empty database — see PgTestTemplate for when to use which.
class PostgresTestDb {
public:
    PostgresTestDb() { init(nullptr); }

    /// Clone an ephemeral database from `tpl` (`CREATE DATABASE ...
    /// TEMPLATE`), so the store constructors under test find every
    /// migration already applied and skip straight through the
    /// schema_meta version check.
    explicit PostgresTestDb(PgTestTemplate& tpl);

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
    /// Shared constructor body. `tpl_name` == nullptr -> empty database
    /// (default template1); else clone from the named template database.
    void init(const std::string* tpl_name) {
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
        std::string create = "CREATE DATABASE \"" + db_name_ + "\"";
        if (tpl_name != nullptr)
            create += " TEMPLATE \"" + *tpl_name + "\"";
        // Clone-from-template refuses while ANY connection to the template
        // is open (SQLSTATE 55006). The builder's PgPool has PQfinish()ed by
        // the time ensure() returns, but the backend teardown can lag a
        // moment — retry briefly instead of failing the fixture.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        for (;;) {
            yuzu::server::pg::PgResult res{PQexec(conn.get(), create.c_str())};
            if (res.ok())
                break;
            const char* sqlstate = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
            const bool in_use = sqlstate != nullptr && std::string_view(sqlstate) == "55006";
            if (!in_use || std::chrono::steady_clock::now() >= deadline) {
                error_ = std::string("CREATE DATABASE failed: ") + PQerrorMessage(conn.get());
                if (in_use)
                    error_ += " — the template stayed busy past the 5s retry window; a "
                              "template setup callback may have leaked a connection (e.g. a "
                              "store background thread holding a pool lease)";
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        conn.reset();

        dsn_ = rewrite_dbname(admin_dsn_, db_name_);
        if (dsn_.empty()) {
            error_ = "could not parse YUZU_TEST_POSTGRES_DSN to rewrite dbname";
            return;
        }

        // Post-create connectivity probe (#1961): CREATE DATABASE on the admin
        // connection proves the database EXISTS, not that the cluster will accept a
        // FRESH connection to it at the moment a pool later connects. PgPool
        // connects lazily on first acquire() and valid() only proves the DSN parsed
        // (pg/pg_pool.hpp), so a transient create-then-connect gap on a shared CI
        // cluster — max_connections pressure, a loopback refusal — surfaces far
        // downstream as an empty lease in whichever [pg] test happened to run,
        // reported without a reason. Prove connectability HERE, with a brief retry,
        // so available() means CONNECTABLE (not merely CREATED) and a genuine outage
        // fails this fixture with the real libpq reason.
        {
            std::string probe_err;
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            for (;;) {
                yuzu::server::pg::PgConn probe{PQconnectdb(dsn_.c_str())};
                if (PQstatus(probe.get()) == CONNECTION_OK)
                    break;
                probe_err = PQerrorMessage(probe.get());
                if (std::chrono::steady_clock::now() >= deadline) {
                    error_ = "post-create connect probe failed: " +
                             (probe_err.empty() ? std::string("unknown error") : probe_err);
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        available_ = true;
    }

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
        // Leading epoch feeds the stale-sweep (test_db_is_stale); the salt +
        // counter carry uniqueness exactly as before.
        const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
        return "yuzu_test_" + std::to_string(epoch) + "_" + std::to_string(salt % 1000000000) +
               "_" + std::to_string(n);
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

    friend class PgTestTemplate; // rewrite_dbname for the template's own DSN
};

/// A pre-migrated template database, built at most once per process and
/// cloned per test (2026-07-12 Wee Tam server-suite timeout: per-test
/// `CREATE DATABASE` + full store migrations + `DROP` made the [pg] tests
/// the slowest-scaling part of the suite under runner contention — the
/// migration DDL is the bulk of it, and a `CREATE DATABASE ... TEMPLATE`
/// clone hands every test an already-migrated schema instead).
///
/// Declare one per test file (or share a name across files that need the
/// exact same store set — the registry builds each NAME once, and every
/// further setup attaching to the key is replay-verified against a fresh
/// scratch database, so a divergent setup — additive or subset — fails its
/// own tests loudly instead of inheriting the wrong template):
///
///   static yuzu::test::PgTestTemplate tpl{"swinv", [](const std::string& dsn) {
///       yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
///       yuzu::server::SoftwareInventoryStore store{pool};  // ctor migrates
///   }};
///   TEST_CASE("...", "[pg]...") {
///       YUZU_REQUIRE_PG_DB_TPL(db, tpl);
///       ...
///   }
///
/// The setup callback MUST construct (and destruct, by scope exit) every
/// store the file's tests rely on: Postgres refuses to clone a template
/// that still has open connections, so a pool leaked past the callback
/// turns into a fixture error, not a hang. Keep using plain
/// YUZU_REQUIRE_PG_DB for tests that exercise migration / fresh-database /
/// pg-substrate behaviour itself (pg_migration_runner, fail-closed ctors
/// on broken schemas) — those need the empty database.
///
/// Template databases carry their own process-random salt (an independent
/// generator, same collision-avoidance scheme as `unique_db_name` — two
/// suite processes on one shared instance never collide) and are dropped
/// at testRunEnded; an abnormal exit (SIGKILL, job-timeout kill) leaks
/// them exactly like ephemeral databases, and they match the same
/// `yuzu_test_*` sweep pattern.
class PgTestTemplate {
public:
    /// Builds the template's schema: construct (and scope-destruct) every
    /// store the file's tests rely on. Contract:
    ///  - MUST close all connections before returning (scope exit of
    ///    pools/stores does it) — a leaked connection fails later clones.
    ///  - MUST be re-runnable against both an empty database and an
    ///    already-migrated one (true by construction for store-ctor
    ///    setups — the migration runner skips applied versions).
    ///  - MUST NOT construct PostgresTestDb / touch any PgTestTemplate:
    ///    ensure() holds a non-recursive registry mutex across this
    ///    callback, so re-entry self-deadlocks.
    using Setup = void (*)(const std::string& dsn);

    /// `name` must be short lowercase [a-z0-9_] (it is spliced into a
    /// quoted SQL identifier and must stay sweep-eligible); invalid keys
    /// surface as a fixture error at first ensure(), never at static init.
    PgTestTemplate(std::string name, Setup setup) : name_(std::move(name)), setup_(setup) {}

    PgTestTemplate(const PgTestTemplate&) = delete;
    PgTestTemplate& operator=(const PgTestTemplate&) = delete;
    PgTestTemplate(PgTestTemplate&&) = delete;
    PgTestTemplate& operator=(PgTestTemplate&&) = delete;

    /// Build (once) and return the template database name; on failure
    /// returns an empty string and sets `error`. A database that was
    /// CREATEd before the failure stays registered (Entry::db_name) so
    /// drop_all_built() still removes it — it just is not handed out.
    /// A FAILED build is retried on the next ensure() (the previous
    /// half-built database is dropped first): a transient Postgres blip
    /// during the first [pg] test must not poison the key for the whole
    /// process — each affected test pays its own attempt, exactly the
    /// pre-template per-test semantics.
    ///
    /// Shared-key safety (#2091 review): when a DIFFERENT setup callback
    /// attaches to an already-built key, it is verified by REPLAY — run
    /// against a FRESH scratch database (not a clone, so a setup that
    /// builds a SUBSET of the template's stores diverges too) and required
    /// to produce the template's structural fingerprint. A divergent setup
    /// (e.g. one file's shared-key lambda edited without the others) fails
    /// ITS tests loudly instead of silently inheriting whichever template
    /// happened to build first; the original template and its tests are
    /// untouched. Fingerprint mismatches are deterministic and cached per
    /// setup; transient replay failures (connectivity) are retried on the
    /// next ensure().
    std::string ensure(const std::string& admin_dsn, std::string& error) {
        if (!key_valid()) {
            error = "template key '" + name_ +
                    "' invalid: keys must be 1-24 chars of [a-z0-9_] (PG 63-byte identifier "
                    "limit + sweep-eligibility)";
            return {};
        }
        Registry& reg = registry();
        const std::lock_guard<std::mutex> lock(reg.mu);
        auto it = reg.entries.find(name_);
        if (it != reg.entries.end() && !it->second.error.empty()) {
            // Previous build failed — reclaim its half-built database (if
            // any) and retry from scratch.
            drop_entry(it->second);
            reg.entries.erase(it);
            it = reg.entries.end();
        }
        if (it == reg.entries.end()) {
            Entry e = build(admin_dsn);
            it = reg.entries.emplace(name_, std::move(e)).first;
        }
        Entry& entry = it->second;
        if (!entry.error.empty()) {
            error = entry.error;
            return {};
        }
        if (!entry.verified.contains(setup_)) {
            const auto cached = entry.mismatched.find(setup_);
            if (cached != entry.mismatched.end()) {
                error = cached->second;
                return {};
            }
            bool deterministic = false;
            const std::string replay_err = verify_replay(entry, deterministic);
            if (!replay_err.empty()) {
                error = "template '" + name_ + "' shared-key setup mismatch: " + replay_err;
                if (deterministic)
                    entry.mismatched.emplace(setup_, error);
                return {};
            }
            entry.verified.insert(setup_);
        }
        error.clear();
        return entry.db_name;
    }

    /// Drop every built template database NOW. Called from the Catch2
    /// testRunEnded listener (test_pg_template_cleanup.cpp) — i.e. before
    /// main returns, while libpq's TLS stack is guaranteed alive. The
    /// Registry static destructor cannot be trusted with this: its
    /// registration order vs OpenSSL's atexit cleanup depends on which test
    /// ran first, and on Catch2-filtered runs (`"[pg]"`, a single case) the
    /// exit-time PQconnectdb finds OpenSSL already torn down and leaks every
    /// template onto the shared instance.
    ///
    /// Emits one summary line when anything was registered, so job logs can
    /// distinguish "no templates this run" from "drops happened silently".
    static void drop_all_built() {
        Registry& reg = registry();
        const std::lock_guard<std::mutex> lock(reg.mu);
        const std::size_t total = reg.entries.size();
        for (const auto& [name, e] : reg.entries)
            drop_entry(e);
        reg.entries.clear();
        if (total > 0) {
            try {
                std::fputs(
                    std::format("PgTestTemplate: dropped {} template database(s) at run end\n",
                                total)
                        .c_str(),
                    stderr);
            } catch (...) {
            }
        }
    }

    /// Drop ONE key's template (if built) and forget it — the key rebuilds
    /// transparently on its next ensure(). Exists so the mechanism test can
    /// assert drop behaviour without wiping every other file's templates
    /// mid-suite (under `--order rand` a global wipe would silently
    /// re-impose the per-test migration cost this machinery removes).
    static void drop_built(const std::string& name) {
        Registry& reg = registry();
        const std::lock_guard<std::mutex> lock(reg.mu);
        auto it = reg.entries.find(name);
        if (it == reg.entries.end())
            return;
        drop_entry(it->second);
        reg.entries.erase(it);
    }

private:
    struct Entry {
        std::string db_name; ///< empty only when CREATE DATABASE itself failed
        std::string error;   ///< nonempty = build failed (db_name may still be set)
        std::string admin_dsn; ///< for the cleanup drop
        /// Structural fingerprint of the built template (schemas, columns,
        /// indexes, constraints).
        std::string fingerprint;
        /// Setup callbacks proven equivalent to the one that built this
        /// template — byte-identical lambdas in different TUs are distinct
        /// functions, so each TU sharing a key is replay-verified once.
        std::set<Setup> verified;
        /// Deterministic replay verdicts (fingerprint mismatch) cached per
        /// setup, so a divergent setup fails fast on every test instead of
        /// re-paying the full replay each time. Transient replay failures
        /// are NOT cached.
        std::map<Setup, std::string> mismatched;
    };

    [[nodiscard]] bool key_valid() const noexcept {
        // 24 keeps the full name ("yuzu_test_tpl_" + 10-digit epoch + "_" +
        // 9-digit salt + "_" + key = 59) under PG's 63-byte identifier
        // limit — a longer name would silently truncate and could collide.
        if (name_.empty() || name_.size() > 24)
            return false;
        for (const char c : name_)
            if ((c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_')
                return false;
        return true;
    }

    /// Process-lifetime registry: dedupes builds by template name. The real
    /// cleanup is drop_all_built() from the testRunEnded listener; this
    /// destructor is only a best-effort backstop for a run that never
    /// reached testRunEnded, and can itself fail on ordering (see
    /// drop_all_built's comment) — hence the stderr breadcrumbs.
    struct Registry {
        std::mutex mu;
        std::map<std::string, Entry> entries;

        ~Registry() {
            for (const auto& [name, e] : entries)
                drop_entry(e);
        }
    };

    /// Best-effort drop of one built template database; failures go to
    /// stderr (same philosophy as PostgresTestDb::log_leak — a silent
    /// failure piles leaked yuzu_test_tpl_* databases onto a shared
    /// instance). noexcept in effect: called from ~Registry at static
    /// destruction, where an escaping bad_alloc would std::terminate.
    static void drop_entry(const Entry& e) noexcept {
        try {
            if (e.db_name.empty())
                return;
            yuzu::server::pg::PgConn conn{PQconnectdb(e.admin_dsn.c_str())};
            if (PQstatus(conn.get()) != CONNECTION_OK) {
                std::fputs("PgTestTemplate: teardown admin connect failed — leaked a "
                           "yuzu_test_tpl_* database\n",
                           stderr);
                return;
            }
            // FORCE for the same reason as PostgresTestDb's dtor: a connection a
            // setup callback failed to scope-close must not make the drop fail
            // and pile template databases onto the shared instance.
            const std::string drop = "DROP DATABASE IF EXISTS \"" + e.db_name + "\" WITH (FORCE)";
            yuzu::server::pg::PgResult res{PQexec(conn.get(), drop.c_str())};
            if (!res.ok())
                std::fputs(PQerrorMessage(conn.get()), stderr);
        } catch (...) {
            std::fputs("PgTestTemplate: teardown failed — leaked a yuzu_test_tpl_* database\n",
                       stderr);
        }
    }

    static Registry& registry() {
        static Registry r;
        return r;
    }

    Entry build(const std::string& admin_dsn) const {
        Entry e;
        e.admin_dsn = admin_dsn;
        const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
        // Leading epoch feeds the stale-sweep (test_db_is_stale), exactly
        // like ephemeral names.
        const std::string db_name = "yuzu_test_tpl_" + std::to_string(epoch) + "_" +
                                    std::to_string(process_salt()) + "_" + name_;
        {
            yuzu::server::pg::PgConn conn{PQconnectdb(admin_dsn.c_str())};
            if (PQstatus(conn.get()) != CONNECTION_OK) {
                e.error = std::string("template admin connect failed: ") + PQerrorMessage(conn.get());
                return e;
            }
            const std::string create = "CREATE DATABASE \"" + db_name + "\"";
            yuzu::server::pg::PgResult res{PQexec(conn.get(), create.c_str())};
            if (!res.ok()) {
                e.error = std::string("template CREATE DATABASE failed: ") + PQerrorMessage(conn.get());
                return e;
            }
        }
        // Record the name NOW, not on full success: if rewrite_dbname or the
        // setup callback fails below, the database physically exists and must
        // stay registered so drop_all_built()/the dtor can still drop it —
        // otherwise every failing CI process leaks one more permanent
        // yuzu_test_tpl_* database on the shared instance (review finding on
        // #2091; same reason PostgresTestDb assigns db_name_ before CREATE).
        e.db_name = db_name;
        const std::string tpl_dsn = PostgresTestDb::rewrite_dbname(admin_dsn, db_name);
        if (tpl_dsn.empty()) {
            e.error = "could not parse YUZU_TEST_POSTGRES_DSN to rewrite dbname";
            return e;
        }
        try {
            setup_(tpl_dsn); // store ctors run the migrations; scope exit closes conns
        } catch (const std::exception& ex) {
            e.error = std::string("template setup threw: ") + ex.what();
            return e;
        } catch (...) {
            e.error = "template setup threw a non-std exception";
            return e;
        }
        auto fp = structure_fingerprint(tpl_dsn);
        if (fp) {
            e.fingerprint = std::move(*fp);
            e.verified.insert(setup_);
        } else {
            e.error = std::move(fp.error());
        }
        return e;
    }

    /// Structural fingerprint of a database: md5 over the sorted set of
    /// non-system schemas, (schema, table, column, type) tuples, index
    /// definitions, and table constraints. Deliberately structure-only —
    /// a setup may reset DATA after migrating (e.g. the secrets template
    /// clears kek_meta) and still be equivalent. NOT covered: triggers and
    /// functions (no store migration creates them today; extend here if
    /// one ever does).
    static std::expected<std::string, std::string> structure_fingerprint(const std::string& dsn) {
        yuzu::server::pg::PgConn conn{PQconnectdb(dsn.c_str())};
        if (PQstatus(conn.get()) != CONNECTION_OK)
            return std::unexpected(std::string("fingerprint connect failed: ") +
                                   PQerrorMessage(conn.get()));
        static constexpr const char* kQuery =
            "SELECT COALESCE(md5(string_agg(t, '|' ORDER BY t)), 'empty') FROM ("
            "  SELECT nspname || ':schema' AS t FROM pg_namespace"
            "   WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema'"
            "  UNION ALL"
            "  SELECT table_schema || '.' || table_name || '.' || column_name || ':' || data_type"
            "    FROM information_schema.columns"
            "   WHERE table_schema NOT LIKE 'pg\\_%' AND table_schema <> 'information_schema'"
            "  UNION ALL"
            "  SELECT schemaname || '.' || tablename || ':index:' || indexname || ':' || indexdef"
            "    FROM pg_indexes"
            "   WHERE schemaname NOT LIKE 'pg\\_%' AND schemaname <> 'information_schema'"
            "  UNION ALL"
            "  SELECT table_schema || '.' || table_name || ':constraint:' || constraint_name "
            "         || ':' || constraint_type"
            "    FROM information_schema.table_constraints"
            "   WHERE table_schema NOT LIKE 'pg\\_%' AND table_schema <> 'information_schema'"
            ") s";
        yuzu::server::pg::PgResult res{PQexec(conn.get(), kQuery)};
        if (PQresultStatus(res.get()) != PGRES_TUPLES_OK || PQntuples(res.get()) != 1)
            return std::unexpected(std::string("fingerprint query failed: ") +
                                   PQerrorMessage(conn.get()));
        return std::string{PQgetvalue(res.get(), 0, 0)};
    }

    /// Replay `setup_` against a FRESH scratch database and require the
    /// template's structural fingerprint. Fresh, not a clone: on a clone
    /// every migration no-ops, so a setup building a SUBSET of the
    /// template's stores would fingerprint identically and silently
    /// inherit schema it never builds — replaying from empty makes the
    /// fingerprint capture exactly what THIS setup produces, catching
    /// divergence in both directions. Returns the mismatch / failure
    /// description (empty when equivalent); `deterministic` is set when
    /// the failure is a fingerprint mismatch (cacheable), not transient.
    std::string verify_replay(const Entry& entry, bool& deterministic) const {
        deterministic = false;
        const std::string scratch = PostgresTestDb::unique_db_name();
        {
            yuzu::server::pg::PgConn conn{PQconnectdb(entry.admin_dsn.c_str())};
            if (PQstatus(conn.get()) != CONNECTION_OK)
                return std::string("replay admin connect failed: ") + PQerrorMessage(conn.get());
            const std::string create = "CREATE DATABASE \"" + scratch + "\"";
            yuzu::server::pg::PgResult res{PQexec(conn.get(), create.c_str())};
            if (!res.ok())
                return std::string("replay scratch CREATE failed: ") + PQerrorMessage(conn.get());
        }
        std::string result;
        const std::string scratch_dsn = PostgresTestDb::rewrite_dbname(entry.admin_dsn, scratch);
        if (scratch_dsn.empty()) {
            result = "replay could not rewrite dbname";
        } else {
            try {
                setup_(scratch_dsn);
                auto fp = structure_fingerprint(scratch_dsn);
                if (!fp) {
                    result = std::move(fp.error());
                } else if (*fp != entry.fingerprint) {
                    deterministic = true;
                    result = "this setup produces a different schema than the one that built "
                             "the template (fingerprint " +
                             *fp + " vs " + entry.fingerprint +
                             ") — shared-key setups must apply the same migrations";
                }
            } catch (const std::exception& ex) {
                result = std::string("replay setup threw: ") + ex.what();
            } catch (...) {
                result = "replay setup threw a non-std exception";
            }
        }
        {
            yuzu::server::pg::PgConn conn{PQconnectdb(entry.admin_dsn.c_str())};
            if (PQstatus(conn.get()) == CONNECTION_OK) {
                const std::string drop = "DROP DATABASE IF EXISTS \"" + scratch + "\" WITH (FORCE)";
                yuzu::server::pg::PgResult res{PQexec(conn.get(), drop.c_str())};
                if (!res.ok())
                    std::fputs(std::format("PgTestTemplate: replay scratch drop of {} failed: {}\n",
                                           scratch, PQerrorMessage(conn.get()))
                                   .c_str(),
                               stderr);
            } else {
                std::fputs("PgTestTemplate: replay scratch drop connect failed — leaked a "
                           "yuzu_test_* database (next sweep reclaims it)\n",
                           stderr);
            }
        }
        return result;
    }

    static std::uint64_t process_salt() {
        static const std::uint64_t salt = [] {
            std::mt19937_64 rng{std::random_device{}()};
            return rng() % 1000000000;
        }();
        return salt;
    }

    std::string name_;
    Setup setup_;
};

inline PostgresTestDb::PostgresTestDb(PgTestTemplate& tpl) {
    const char* admin = pg_admin_dsn_env();
    if (admin == nullptr) {
        error_ = "YUZU_TEST_POSTGRES_DSN not set";
        return;
    }
    std::string tpl_error;
    const std::string tpl_name = tpl.ensure(admin, tpl_error);
    if (tpl_name.empty()) {
        error_ = "template build failed: " + tpl_error;
        return;
    }
    init(&tpl_name);
}

/// Standard prologue for a Postgres-backed TEST_CASE: skip when no DSN is
/// configured, fail when it is configured but broken, else bind `var` to a
/// fresh ephemeral database. Requires Catch2 macros at the expansion site.
/// Expands to an unbraced `if` plus declarations — use only as a direct
/// statement at block scope (never as the body of an if/loop).
///
/// NOTE: store-BEHAVIOUR tests should use YUZU_REQUIRE_PG_DB_TPL (below)
/// with a pre-migrated PgTestTemplate instead — this plain form re-runs
/// every migration per test and is reserved for migration / fresh-database
/// / pg-substrate behaviour tests.
#define YUZU_REQUIRE_PG_DB(var)                                                                    \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                              \
    yuzu::test::PostgresTestDb var;                                                                \
    INFO("[YUZU_REQUIRE_PG_DB] fixture status (blank == database came up OK): " << var.error());   \
    REQUIRE(var.available())

/// Same contract as YUZU_REQUIRE_PG_DB, but `var` is cloned from the
/// pre-migrated PgTestTemplate `tpl` instead of starting empty — use for
/// store-behaviour tests; keep the plain macro for migration/fresh-database
/// behaviour tests.
#define YUZU_REQUIRE_PG_DB_TPL(var, tpl)                                                           \
    if (yuzu::test::pg_admin_dsn_env() == nullptr) {                                               \
        SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");                            \
    }                                                                                              \
    yuzu::test::PostgresTestDb var{tpl};                                                           \
    INFO("[YUZU_REQUIRE_PG_DB_TPL] fixture status (blank == database came up OK): "                \
         << var.error());                                                                          \
    REQUIRE(var.available())

#endif // YUZU_TEST_ENABLE_PG

} // namespace yuzu::test
