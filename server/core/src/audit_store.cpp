#include "audit_store.hpp"
#include "migration_runner.hpp"
#include "sqlite_raii.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <mutex>
#include <optional>
#include <random>
#include <shared_mutex>
#include <span>
#include <string>

namespace yuzu::server {

AuditStore::AuditStore(const std::filesystem::path& db_path, int retention_days,
                       int cleanup_interval_min)
    : retention_days_(retention_days), cleanup_interval_min_(cleanup_interval_min) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("AuditStore: failed to open {}: {}", db_path.string(), sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }

    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    create_tables();
    if (db_)
        spdlog::info("AuditStore: opened {} (retention={}d)", db_path.string(), retention_days_);
}

AuditStore::~AuditStore() {
    stop_cleanup();
    if (db_)
        sqlite3_close(db_);
}

bool AuditStore::is_open() const {
    return db_ != nullptr;
}

void AuditStore::create_tables() {
    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS audit_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       INTEGER NOT NULL,
                principal       TEXT    NOT NULL,
                principal_role  TEXT    NOT NULL,
                action          TEXT    NOT NULL,
                target_type     TEXT,
                target_id       TEXT,
                detail          TEXT,
                source_ip       TEXT,
                user_agent      TEXT,
                session_id      TEXT,
                result          TEXT    NOT NULL,
                ttl_expires_at  INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_audit_ts
                ON audit_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_principal_ts
                ON audit_events(principal, timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_action_ts
                ON audit_events(action, timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_target_ts
                ON audit_events(target_type, target_id, timestamp);
        )"},
        // ADR-1005 Decision 9 / execution-plan Phase 3a: additive actor-class
        // column, no delegation semantics, no Postgres migration required (the
        // exec plan explicitly scopes this ahead of AuditStore's own eventual PG
        // Wave-1 cutover). Existing rows backfill to '' (honest-empty — this
        // program cannot retroactively attribute historical rows).
        {2, R"(
            ALTER TABLE audit_events ADD COLUMN principal_class TEXT NOT NULL DEFAULT '';
        )"},
        // #2360 retention clock guard: durable guard state. Only the last
        // observed clock reading lives here, and it is what makes the elapsed-
        // time check survive a restart. Without it the check is process-local,
        // so a server that BOOTS with an already-wrong clock never sees a step
        // at all -- which is the dead-CMOS / restored-snapshot case the guard
        // exists for. The per-table decline latch is deliberately NOT persisted:
        // re-declining once after a restart is the safe direction.
        //
        // One row today, written once per cleanup interval. Nothing here is
        // O(table size), so it is safe inside the startup migration transaction.
        {3, R"(
            CREATE TABLE IF NOT EXISTS audit_retention_meta (
                key   TEXT    PRIMARY KEY,
                value INTEGER NOT NULL
            );
        )"},
    };
    if (!MigrationRunner::run(db_, "audit_store", kMigrations)) {
        spdlog::error("AuditStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
        return;
    }
    ensure_retention_index();
    last_pass_now_ = load_meta(kLastPassNowKey);
}

void AuditStore::ensure_retention_index() {
    // The guarded cleanup pass issues two EXISTS probes and one ordered LIMIT
    // delete per pass, all keyed on ttl_expires_at, under the same exclusive
    // lock every audit INSERT takes. Without a covering index each is a full
    // scan of a table that reaches millions of rows, so the guard would trade a
    // wipe risk for a write stall. Partial on `ttl_expires_at > 0` because rows
    // with retention disabled (ttl 0) are never candidates -- and because
    // matching the probes' own predicate is what lets SQLite pick it (the term
    // is load-bearing in the queries too, not just here).
    //
    // Built OUTSIDE MigrationRunner, best-effort, deliberately. A failed
    // migration closes the database, and from then on every log() returns false
    // -- so routing an O(N log N) index build through the fail-closed path would
    // let a transient temp-space shortfall at first post-upgrade boot take the
    // SOC 2 audit trail offline. The index is a PERFORMANCE artifact; the guard
    // is correct without it. Measured cost at 5M rows: ~1.4s and ~81MB, paid
    // once; the elapsed time is logged so an operator can see it on a large
    // table (extrapolating to ~16s at 50M rows).
    const auto t0 = std::chrono::steady_clock::now();
    char* err = nullptr;
    const int rc = sqlite3_exec(db_,
                                "CREATE INDEX IF NOT EXISTS idx_audit_ttl_id "
                                "ON audit_events(ttl_expires_at, id) WHERE ttl_expires_at > 0;",
                                nullptr, nullptr, &err);
    const auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    if (rc != SQLITE_OK) {
        // Degraded, not broken: retention still runs, just with full scans under
        // the store lock. Surfaced loudly so it is not mistaken for healthy.
        // Counted, not just logged. Without the index every hourly pass full-scans
        // audit_events under the exclusive lock that every audit write needs, and
        // that cost GROWS with the table -- turning a bounded ~315ms/hour hold
        // into an unbounded one, silently. This is the one failure that
        // invalidates the "latency, not availability" property of the whole pass.
        retention_index_ok_.store(false, std::memory_order_relaxed);
        spdlog::error("AuditStore: could not create idx_audit_ttl_id ({}); retention will run "
                      "WITHOUT its index and each pass will scan audit_events",
                      err ? err : "unknown error");
        sqlite3_free(err);
        return;
    }
    sqlite3_free(err);
    if (ms >= 1000)
        spdlog::info("AuditStore: built idx_audit_ttl_id in {} ms (one-time, first boot after "
                     "upgrade on an existing audit_events)",
                     ms);
}

std::optional<std::int64_t> AuditStore::load_meta(const char* key) const {
    if (!db_)
        return std::nullopt;
    SqliteStmt stmt;
    if (sqlite3_prepare_v2(db_, "SELECT value FROM audit_retention_meta WHERE key = ?", -1,
                           stmt.addr(), nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(stmt.get(), 1, key, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW)
        return sqlite3_column_int64(stmt.get(), 0);
    // Absent row and read error are both "no comparison point". Returning an
    // optional rather than 0 matters because 0 is a LEGITIMATE reading: a dead
    // CMOS reporting the Unix epoch is the motivating case for this whole guard,
    // and collapsing it into the sentinel would suppress the check on the very
    // pass after NTP corrects.
    return std::nullopt;
}

bool AuditStore::store_meta(const char* key, std::int64_t value) {
    if (!db_)
        return false;
    SqliteStmt stmt;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO audit_retention_meta (key, value) VALUES (?, ?) "
                           "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                           -1, stmt.addr(), nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_text(stmt.get(), 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt.get(), 2, value);
    return sqlite3_step(stmt.get()) == SQLITE_DONE;
}

bool AuditStore::log(const AuditEvent& event) {
    std::unique_lock lock(mtx_);
    if (!db_) {
        // Audit DB not open — surface as a failure so callers can flag the
        // gap on the response (HIGH-2 from PR #883). Operators running
        // audit-off (no AuditStore wired at all) never reach this code
        // path because AuthRoutes::audit_log short-circuits on a null
        // store and returns true.
        emit_failed_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    const char* sql = R"(
        INSERT INTO audit_events (timestamp, principal, principal_role, action,
            target_type, target_id, detail, source_ip, user_agent, session_id, result, ttl_expires_at,
            principal_class)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        emit_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::error("AuditStore: sqlite3_prepare_v2 failed: {}", sqlite3_errmsg(db_));
        return false;
    }

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto ts = event.timestamp > 0 ? event.timestamp : now;
    auto ttl = retention_days_ > 0 ? now + retention_days_ * 86400LL : 0;

    sqlite3_bind_int64(stmt, 1, ts);
    sqlite3_bind_text(stmt, 2, event.principal.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, event.principal_role.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, event.action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, event.target_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, event.target_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, event.detail.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, event.source_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, event.user_agent.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, event.session_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, event.result.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 12, ttl);
    sqlite3_bind_text(stmt, 13, event.principal_class.c_str(), -1, SQLITE_TRANSIENT);

    int step_rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // SOC 2 CC7.2: a privileged-mutation handler that emits an audit event
    // and silently fails to persist it produces a forensically-empty row.
    // Surface the failure count so operators can alert on a non-zero rate.
    // We still bucket the per-result counter below so the success/failure
    // ratio remains observable separately from the emit-failed signal.
    if (step_rc != SQLITE_DONE) {
        emit_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::error("AuditStore: sqlite3_step rc={} ({}); event lost", step_rc,
                      sqlite3_errmsg(db_));
        return false;
    }

    // Bucket the write into a Prometheus-friendly counter so the audit subsystem
    // is observable from the /metrics scrape. Result vocabulary is open-ended at
    // call sites — collapse anything we don't recognise into "other" rather than
    // letting cardinality grow unbounded.
    if (event.result == "success")
        events_success_.fetch_add(1, std::memory_order_relaxed);
    else if (event.result == "failure")
        events_failure_.fetch_add(1, std::memory_order_relaxed);
    else if (event.result == "denied")
        events_denied_.fetch_add(1, std::memory_order_relaxed);
    else
        events_other_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

uint64_t AuditStore::events_written(const std::string& result) const noexcept {
    if (result == "success")
        return events_success_.load(std::memory_order_relaxed);
    if (result == "failure")
        return events_failure_.load(std::memory_order_relaxed);
    if (result == "denied")
        return events_denied_.load(std::memory_order_relaxed);
    if (result == "other")
        return events_other_.load(std::memory_order_relaxed);
    return 0;
}

std::vector<AuditEvent> AuditStore::query(const AuditQuery& q, std::size_t* out_pool_size) const {
    std::shared_lock lock(mtx_);
    std::vector<AuditEvent> results;
    if (!db_)
        return results;

    std::string sql =
        "SELECT id, timestamp, principal, principal_role, action, target_type, target_id, detail, "
        "source_ip, user_agent, session_id, result, principal_class FROM audit_events WHERE 1=1";
    std::vector<std::pair<int, std::string>> text_binds;
    // int64_binds: (param_index, value) pairs for integer parameters
    std::vector<std::pair<int, int64_t>> int_binds;
    int bind_idx = 1;

    if (!q.principal.empty()) {
        sql += " AND principal = ?";
        text_binds.emplace_back(bind_idx++, q.principal);
    }
    if (!q.action.empty()) {
        sql += " AND action = ?";
        text_binds.emplace_back(bind_idx++, q.action);
    }
    if (!q.target_type.empty()) {
        sql += " AND target_type = ?";
        text_binds.emplace_back(bind_idx++, q.target_type);
    }
    if (!q.target_id.empty()) {
        sql += " AND target_id = ?";
        text_binds.emplace_back(bind_idx++, q.target_id);
    }
    if (q.since > 0) {
        sql += " AND timestamp >= ?";
        int_binds.emplace_back(bind_idx++, q.since);
    }
    if (q.until > 0) {
        sql += " AND timestamp <= ?";
        int_binds.emplace_back(bind_idx++, q.until);
    }
    // Prefix OR-group (e.g. auth./mfa./session. for the auth-log sample, #4).
    // Prefixes are code-controlled constants, not user input, so they carry no
    // LIKE metacharacters to escape; each binds as `<prefix>%`.
    if (!q.action_prefixes.empty()) {
        sql += " AND (";
        bool first = true;
        for (const auto& p : q.action_prefixes) {
            // Runtime enforcement of the header contract (Hermes M-2): a prefix is
            // bound into an unescaped `LIKE <p>%`, so a `%`/`_`/`\` in it would be a
            // wildcard. Prefixes are meant to be literals — drop any that carry LIKE
            // metacharacters (fails closed for that prefix) rather than trusting the
            // caller, so a future call site that wires untrusted input cannot smuggle
            // wildcards.
            if (p.empty() || p.find_first_of("%_\\") != std::string::npos)
                continue;
            sql += first ? "action LIKE ?" : " OR action LIKE ?";
            text_binds.emplace_back(bind_idx++, p + "%");
            first = false;
        }
        // All prefixes empty → an always-false guard so an explicitly-empty
        // filter never silently widens to "all actions".
        sql += first ? "0)" : ")";
    }
    // Always order by the indexed timestamp (early-terminating index scan) — never
    // `ORDER BY RANDOM()`, which would force a full scan of every matching row in
    // the window while holding the reader lock (Hermes M-1: DoS / cleanup-thread
    // starvation on a large table). For random_sample we instead bind a bounded
    // candidate cap here and shuffle+truncate in C++ below. OFFSET is meaningless
    // under random order, so it is skipped there.
    const int64_t kRandomSampleScanCap = static_cast<int64_t>(kAuditSampleScanCap);
    sql += " ORDER BY timestamp DESC";
    sql += " LIMIT ?";
    int limit_idx = bind_idx++;
    int offset_idx = 0;
    if (q.offset > 0 && !q.random_sample) {
        sql += " OFFSET ?";
        offset_idx = bind_idx++;
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        // UP-5: a prepare failure (corruption, locked-past-timeout, schema drift)
        // otherwise returns an empty vector indistinguishable from "no rows" — a
        // false "no audit activity" for an evidence query. Make it observable; a
        // fully-broken store is already pulled from /readyz, and the error-signaling
        // query() contract (so the REST layer can 503 instead of 200-empty) is the
        // tracked follow-up.
        spdlog::error("AuditStore::query prepare failed: {}", sqlite3_errmsg(db_));
        return results;
    }

    for (const auto& [idx, val] : text_binds) {
        sqlite3_bind_text(stmt, idx, val.c_str(), -1, SQLITE_TRANSIENT);
    }
    for (const auto& [idx, val] : int_binds) {
        sqlite3_bind_int64(stmt, idx, val);
    }
    // Under random_sample, over-fetch a bounded candidate pool (capped, indexed)
    // and sample from it in C++ — bounding both CPU and lock-hold. When the window
    // holds more than the cap, the pool is the most-recent kRandomSampleScanCap
    // events (a documented recency bias above the cap; true uniform sampling of an
    // unbounded window would reintroduce the M-1 full-scan).
    const int64_t fetch_limit =
        q.random_sample ? std::max(static_cast<int64_t>(q.limit), kRandomSampleScanCap) : q.limit;
    sqlite3_bind_int64(stmt, limit_idx, fetch_limit);
    if (offset_idx > 0) {
        sqlite3_bind_int64(stmt, offset_idx, q.offset);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AuditEvent e;
        e.id = sqlite3_column_int64(stmt, 0);
        e.timestamp = sqlite3_column_int64(stmt, 1);
        auto col_text = [&](int c) -> std::string {
            auto t = sqlite3_column_text(stmt, c);
            return t ? reinterpret_cast<const char*>(t) : std::string{};
        };
        e.principal = col_text(2);
        e.principal_role = col_text(3);
        e.action = col_text(4);
        e.target_type = col_text(5);
        e.target_id = col_text(6);
        e.detail = col_text(7);
        e.source_ip = col_text(8);
        e.user_agent = col_text(9);
        e.session_id = col_text(10);
        e.result = col_text(11);
        e.principal_class = col_text(12);
        results.push_back(std::move(e));
    }
    sqlite3_finalize(stmt);

    // random_sample: shuffle the bounded candidate pool and truncate to limit, so
    // the returned rows are a random draw rather than the newest-N (Hermes M-1 —
    // the randomness is now O(pool) in C++, not an unbounded SQL sort under lock).
    if (q.random_sample) {
        // Report the pre-truncation pool size so the caller can detect the
        // recency cap (pool == kAuditSampleScanCap ⇒ the window held >= cap and
        // the sample is recency-biased) — evidence honesty, #4.
        if (out_pool_size)
            *out_pool_size = results.size();
        if (results.size() > static_cast<std::size_t>(std::max(q.limit, 0))) {
            static thread_local std::mt19937_64 rng{std::random_device{}()};
            std::shuffle(results.begin(), results.end(), rng);
            results.resize(static_cast<std::size_t>(std::max(q.limit, 0)));
        }
    }
    return results;
}

std::size_t AuditStore::total_count() const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return 0;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM audit_events", -1, &stmt, nullptr) !=
        SQLITE_OK)
        return 0;
    std::size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return count;
}

void AuditStore::start_cleanup() {
    if (!db_ || cleanup_interval_min_ <= 0)
        return;
#ifdef __cpp_lib_jthread
    cleanup_thread_ = std::jthread([this](std::stop_token stop) { run_cleanup(stop); });
#else
    stop_requested_ = false;
    cleanup_thread_ = std::thread([this]() { run_cleanup(); });
#endif
}

void AuditStore::stop_cleanup() {
#ifdef __cpp_lib_jthread
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.request_stop();
        cleanup_thread_.join();
    }
#else
    stop_requested_ = true;
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
#endif
}

namespace {

// Run a one-row EXISTS probe. Returns nullopt on any prepare/bind/step error so
// the caller can fail closed rather than read a default.
//
// `binds` is a span, not a pointer+count: the arity is then deduced from the
// array at the call site and checked against the statement's own parameter
// count below. A hand-maintained count could silently disagree with the SQL --
// and an unbound parameter reads as NULL, which makes `ttl_expires_at < NULL`
// yield NULL, which makes EXISTS return 0, which reads as "nothing is expired".
// Retention would then stop forever while every counter reported healthy.
std::optional<bool> exists_probe(sqlite3* db, const char* sql,
                                 std::span<const std::int64_t> binds) {
    SqliteStmt stmt;
    if (sqlite3_prepare_v2(db, sql, -1, stmt.addr(), nullptr) != SQLITE_OK)
        return std::nullopt;
    if (static_cast<std::size_t>(sqlite3_bind_parameter_count(stmt.get())) != binds.size())
        return std::nullopt; // SQL and call site disagree -- refuse to guess
    for (std::size_t i = 0; i < binds.size(); ++i)
        if (sqlite3_bind_int64(stmt.get(), static_cast<int>(i) + 1, binds[i]) != SQLITE_OK)
            return std::nullopt;
    // EXISTS(...) always yields exactly one row holding 0 or 1.
    if (sqlite3_step(stmt.get()) != SQLITE_ROW)
        return std::nullopt;
    return sqlite3_column_int(stmt.get(), 0) != 0;
}

} // namespace

std::size_t AuditStore::cleanup_once(std::int64_t now) {
    // What this pass wants logged, filled in under the lock and emitted after it
    // is released: spdlog formatting is neither cheap nor bounded, and every
    // audit log() blocks on this same exclusive lock.
    enum class Emit {
        None,
        ProbeFailed,
        DeclineFirstPass,
        DeclineStep,
        DeclineBackward,
        Deleted,
        DeleteFailed
    };
    Emit emit = Emit::None;
    bool emit_persist_failed = false;
    std::string emit_err;
    std::size_t deleted = 0;
    std::int64_t emit_delta = 0, emit_window = 0;
    bool emit_full_wipe = false, emit_capped = false;

    {
        std::unique_lock lock(mtx_);
        if (!db_) {
            // Defensive only, and deliberately NOT the production signal for a
            // closed store: start_cleanup() early-returns when db_ is null, so no
            // thread ever reaches this in a running server. A store closed by a
            // failed migration surfaces through log()'s emit_failed_ counter and
            // /healthz, not here. Counted anyway so a direct caller (a test, or a
            // future scheduler that does not check is_open()) is not silently
            // told the pass succeeded.
            cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
            return 0;
        }

        // A non-positive retention setting means "never expire": log() stamps ttl
        // 0 on every row, so no row is ever a cleanup candidate and the window
        // below would be a meaningless zero to compare a clock step against.
        const std::int64_t window =
            retention_days_ > 0 ? static_cast<std::int64_t>(retention_days_) * 86400 : 0;

        // Record this pass's reading for the NEXT pass's step check, before any
        // early return below. The reading is an honest observation of the clock
        // whatever the pass goes on to do, and not recording it on a failing pass
        // would make a later recovery report a step that was really an outage.
        //
        // Persisted (#2360 governance): the step check is the ONLY half of this
        // guard that works when the clock was already wrong before the process
        // started. Held in memory alone it compares against zero on the first
        // pass and never fires -- exactly the dead-CMOS-at-boot case. A failed
        // write is not fatal: it costs the NEXT restart its comparison point.
        const std::optional<std::int64_t> raw_prev = last_pass_now_;
        last_pass_now_ = now;
        if (!store_meta(kLastPassNowKey, now)) {
            emit_persist_failed = true;
            // The restart-surviving half of the guard silently degrades if this
            // keeps failing, so it gets a counter rather than a log line only.
            persist_failed_.fetch_add(1, std::memory_order_relaxed);
        }

        // SANITISE the reading before doing arithmetic on it. It is durable
        // state in the same database as the evidence, so it can come back
        // corrupt, hand-edited, or -- far more mundanely -- stamped by an
        // earlier pass that ran while the clock was skewed FORWARD. Any of those
        // leaves `prev > now`, which would make `now - prev` negative for as long
        // as real time takes to catch up (potentially years), silently killing
        // the only detector that survives a restart. An INT64_MAX value would
        // make the subtraction signed-overflow UB outright.
        //
        // A reading from the future is itself evidence the clock moved, so it is
        // treated as an anomaly rather than discarded quietly, and `now` is
        // persisted above either way so the state self-heals on this pass.
        std::optional<std::int64_t> prev_pass_now = raw_prev;
        bool prev_from_future = false;
        if (prev_pass_now && (*prev_pass_now < 0 || *prev_pass_now > now)) {
            prev_from_future = *prev_pass_now > now;
            prev_pass_now.reset();
        }

        // Detect by OUTCOME rather than by a clock delta alone, because the
        // outcome test needs no history and so survives a restart with an empty
        // process state. Two EXISTS probes answer the whole question and stay
        // index-driven; a COUNT(*) pair would scan.
        //
        // NOTE the outcome test is defeated by ANY write landing after the jump:
        // a fresh row is a datable survivor, so `would_wipe` goes false. On a
        // server that is up and serving, that is the common case. The persisted
        // step check above is what actually covers the restart scenario; this
        // test covers an idle or newly-restored store. Together they are still
        // best-effort DETECTION -- the per-pass cap below is the half that
        // bounds the damage unconditionally.
        //
        // `datable` deliberately EXCLUDES rows whose TTL is implausibly far in
        // the future (see kAuditTtlFutureSlackSec): they can never expire, so
        // treating them as ordinary survivors would let one forward-skew row
        // disarm the guard permanently.
        const std::int64_t datable_horizon = now + window + kAuditTtlFutureSlackSec;
        const std::int64_t expired_binds[] = {now};
        const std::int64_t survivor_binds[] = {now, datable_horizon};
        const auto has_expired =
            exists_probe(db_,
                         "SELECT EXISTS(SELECT 1 FROM audit_events "
                         "WHERE ttl_expires_at > 0 AND ttl_expires_at < ?)",
                         expired_binds);
        // BETWEEN, not `>= ? AND <= ?`. Both give a byte-identical EXPLAIN QUERY
        // PLAN, but with two separate comparisons SQLite picks the literal
        // `ttl_expires_at > 0` as the index seek bound and demotes `>= now` to a
        // per-row filter -- so the probe walks the ENTIRE expired backlog before
        // it can answer. Measured on 5M rows: 120ms at a 4.5M backlog versus
        // 0.004ms with BETWEEN, under the lock every audit write needs.
        const auto has_datable_survivor =
            exists_probe(db_,
                         "SELECT EXISTS(SELECT 1 FROM audit_events "
                         "WHERE ttl_expires_at > 0 AND ttl_expires_at BETWEEN ? AND ?)",
                         survivor_binds);
        if (!has_expired || !has_datable_survivor) {
            // Fail closed: delete nothing, and RE-ARM the guard. A failed pass
            // tells us nothing about the clock, so carrying a set latch across it
            // would mean the next pass that really would wipe the table deletes
            // with no decline, no warn line and no counter -- the guard silently
            // spent on an anomaly that may already be over. Re-arming costs at
            // most one extra declined pass, and while a failure persists
            // cleanup_failed_ rises alongside the skips, so the two are never
            // confusable.
            cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
            clock_anomaly_latched_ = false;
            emit = Emit::ProbeFailed;
            emit_err = sqlite3_errmsg(db_); // copy: read before the lock drops
        } else if (!*has_expired) {
            // Nothing to delete, so nothing to guard against. Clearing the latch
            // here is the same rule the accepting path applies below: the anomaly
            // is over once no expired backlog remains.
            clock_anomaly_latched_ = false;
        } else {
            // Every datable row is expired: one more `DELETE ... WHERE ttl < now`
            // empties the evidence table.
            const bool would_wipe = !*has_datable_survivor;
            // Supplement, not a replacement. `would_wipe` only fires when a
            // forward jump exceeds the WHOLE retention window; a half-window jump
            // expires half the store, which the cap bounds but nothing would
            // otherwise report. Persisted across restarts (see above), so unlike
            // the outcome test it still fires when a write has already landed
            // after the jump.
            //
            // The threshold is floored (kAuditMinBigStepSec). Elapsed time cannot
            // tell a clock jump from an outage, so on a SHORT retention setting
            // an ordinary maintenance window would report as a clock anomaly. The
            // check only fires past a duration where an outage is itself
            // remarkable -- and the warn text names both causes, because this
            // signal genuinely cannot distinguish them.
            const std::int64_t step_threshold = std::max(window, kAuditMinBigStepSec);
            const bool big_step =
                prev_pass_now && window > 0 && now - *prev_pass_now > step_threshold;
            emit_delta = prev_pass_now ? now - *prev_pass_now : 0;
            emit_window = step_threshold;
            emit_full_wipe = would_wipe;

            if ((would_wipe || big_step || prev_from_future) && !clock_anomaly_latched_) {
                clock_anomaly_skips_.fetch_add(1, std::memory_order_relaxed);
                clock_anomaly_latched_ = true;
                emit = prev_from_future  ? Emit::DeclineBackward
                       : !prev_pass_now  ? Emit::DeclineFirstPass
                                         : Emit::DeclineStep;
            } else {
                deleted = delete_capped_locked(now, would_wipe, emit_err);
                if (!emit_err.empty())
                    emit = Emit::DeleteFailed;
                else if (deleted > 0) {
                    emit = Emit::Deleted;
                    emit_capped = deleted >= kMaxAuditDeletesPerPass;
                }
            }
        }
    } // lock released before any formatting

    if (emit_persist_failed)
        spdlog::warn("AuditStore: could not persist the retention clock reading; a restart before "
                     "the next pass will lose its clock-step comparison point");
    switch (emit) {
    case Emit::None:
        break;
    case Emit::DeclineBackward:
        spdlog::warn("AuditStore: the stored retention clock reading is AHEAD of the current "
                     "clock, so this server's clock moved backward or that state was tampered "
                     "with; declining once and re-anchoring on the current reading");
        break;
    case Emit::ProbeFailed:
        spdlog::warn("AuditStore: retention probe failed ({}); skipping this pass", emit_err);
        break;
    case Emit::DeleteFailed:
        spdlog::warn("AuditStore: cleanup error: {}", emit_err);
        break;
    case Emit::DeclineFirstPass:
        spdlog::warn("AuditStore: the first retention pass after start would expire EVERY datable "
                     "audit row; declining once so a clock anomaly cannot delete the audit trail "
                     "wholesale");
        break;
    case Emit::DeclineStep:
        spdlog::warn("AuditStore: this retention pass would expire {} ({}s since the last pass, "
                     "threshold {}s -- a forward clock jump OR an outage that long); declining "
                     "once so a clock anomaly cannot delete the audit trail wholesale",
                     emit_full_wipe ? "EVERY datable audit row" : "an unexpectedly large slice",
                     emit_delta, emit_window);
        break;
    case Emit::Deleted:
        if (emit_capped)
            spdlog::info("AuditStore: expired {} rows (per-pass cap reached; the remainder ages "
                         "out on subsequent passes)",
                         deleted);
        else
            spdlog::info("AuditStore: expired {} rows", deleted);
        break;
    }
    return deleted;
}

std::size_t AuditStore::delete_capped_locked(std::int64_t now, bool would_wipe,
                                             std::string& out_err) {

    // Accepted. Bound the pass so that even a wipe this guard chose to allow
    // ages out at a paced rate instead of in one statement. Oldest-first so the
    // pacing never strands the oldest evidence behind newer expiries.
    //
    // RETURNING carries the deleted count on the statement itself: reading
    // sqlite3_changes() after step() on this FULLMUTEX connection is the #1033
    // data race (FULLMUTEX serialises the calls, not the step->changes pair).
    static constexpr char kDeleteSql[] = R"(
        DELETE FROM audit_events WHERE id IN (
            SELECT id FROM audit_events
             WHERE ttl_expires_at > 0 AND ttl_expires_at < ?
             ORDER BY ttl_expires_at ASC, id ASC
             LIMIT ?)
        RETURNING id
    )";
    SqliteStmt del;
    if (sqlite3_prepare_v2(db_, kDeleteSql, -1, del.addr(), nullptr) != SQLITE_OK) {
        cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
        clock_anomaly_latched_ = false; // re-arm, as on the probe path above
        out_err = sqlite3_errmsg(db_);
        return 0;
    }
    sqlite3_bind_int64(del.get(), 1, now);
    sqlite3_bind_int64(del.get(), 2, static_cast<std::int64_t>(kMaxAuditDeletesPerPass));
    std::size_t deleted = 0;
    int rc = SQLITE_OK;
    // A RETURNING statement is not finished until it steps to SQLITE_DONE, so
    // drain it rather than stopping at the first row. (SQLite performs the whole
    // delete on the FIRST step and buffers the output rows, so the loop is
    // bookkeeping over that buffer -- the per-pass cap doubles as its bound.)
    while ((rc = sqlite3_step(del.get())) == SQLITE_ROW)
        ++deleted;
    if (rc != SQLITE_DONE) {
        cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
        out_err = sqlite3_errmsg(db_); // read BEFORE the statement is finalized
        clock_anomaly_latched_ = false; // re-arm, as on the probe path above
        // Report 0, not the RETURNING rows seen so far: SQLite unwinds a failed
        // statement from its statement journal, so those rows are back.
        return 0;
    }
    del.reset();
    rows_deleted_.fetch_add(deleted, std::memory_order_relaxed);
    if (deleted >= kMaxAuditDeletesPerPass)
        // The cap bound this pass, so a backlog remains. Counted, not just
        // logged: a cap that binds on every pass for a sustained period is the
        // one failure the cap itself introduces (audit.db growing without
        // bound), and nothing else on /metrics would show it.
        cap_reached_.fetch_add(1, std::memory_order_relaxed);

    // Hold the latch only while the wipe condition itself persists, so a large
    // all-expired backlog drains at cap pace without re-tripping the guard --
    // and, crucially, an ORDINARY over-cap backlog (survivors present, so
    // `would_wipe` is false) never arms it. Arming on ordinary backlog would
    // mask the decline+counter signal of a real anomaly arriving next.
    clock_anomaly_latched_ = would_wipe;
    return deleted;
}

#ifdef __cpp_lib_jthread
void AuditStore::run_cleanup(std::stop_token stop) {
    while (!stop.stop_requested()) {
        for (int i = 0; i < cleanup_interval_min_ * 60 && !stop.stop_requested(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stop.stop_requested())
            break;
#else
void AuditStore::run_cleanup() {
    while (!stop_requested_.load()) {
        for (int i = 0; i < cleanup_interval_min_ * 60 && !stop_requested_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stop_requested_.load())
            break;
#endif

        cleanup_once(std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count());
    }
}

} // namespace yuzu::server
