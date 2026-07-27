#include "audit_store.hpp"
#include "migration_runner.hpp"
#include "sqlite_raii.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <exception>
#include <random>
#include <shared_mutex>
#include <expected>
#include <limits>
#include <span>
#include <string_view>
#include <vector>
#include <utility>

namespace yuzu::server {

AuditStore::AuditStore(const std::filesystem::path& db_path, int retention_days,
                       int cleanup_interval_min)
    : retention_days_(retention_days), cleanup_interval_min_(cleanup_interval_min) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), db_.addr(),
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        // `db_.get()` owns whatever the failed open allocated; its destructor closes it
        // whether we return here or a later log call throws.
        spdlog::error("AuditStore: failed to open {}: {}", db_path.string(),
                      sqlite3_errmsg(db_.get()));
        db_.close();
        return;
    }

    sqlite3_exec(db_.get(), "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    create_tables();
    if (db_)
        spdlog::info("AuditStore: opened {} (retention={}d)", db_path.string(), retention_days_);
}

AuditStore::~AuditStore() {
    // Join FIRST: the cleanup thread touches `db_.get()` every pass, so the connection
    // must outlive it. `db_`'s own destructor then closes the handle.
    stop_cleanup();
}

bool AuditStore::is_open() const {
    return static_cast<bool>(db_);
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
        // Durable state for the retention clock guard (#2360). One row, so this
        // migration is instant on any table size -- unlike the retention index,
        // which is deliberately NOT here (see ensure_retention_index).
        {3, R"(
            CREATE TABLE IF NOT EXISTS audit_retention_meta (
                key   TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );
        )"},
    };
    if (!MigrationRunner::run(db_.get(), "audit_store", kMigrations)) {
        // Deliberate early close: from here every operation fails, which is the
        // fail-closed posture for an evidence store whose schema is wrong.
        spdlog::error("AuditStore: schema migration failed, closing database");
        db_.close();
        return;
    }
    ensure_retention_index();
    if (auto r = load_meta(kLastPassNowKey)) {
        last_pass_now_ = *r;
    } else {
        last_pass_now_.reset();
        // BOTH non-benign shapes are carried as an anomaly. Absent alone is the
        // ordinary fresh-install case and says nothing. Malformed and Unreadable
        // both mean "there is durable state and we could not use it", which the
        // first pass must report rather than treat as a clean slate.
        loaded_meta_unusable_ = (r.error() != MetaReadError::Absent);
        if (r.error() == MetaReadError::Malformed)
            spdlog::error("AuditStore: the stored retention clock reading is not an integer; "
                          "treating it as a clock anomaly and re-anchoring on the next pass");
        else if (r.error() == MetaReadError::Unreadable)
            spdlog::error("AuditStore: could not read the stored retention clock reading; the "
                          "restart-surviving half of the clock guard starts this process with no "
                          "comparison point");
    }
}

void AuditStore::ensure_retention_index() {
    // The guarded cleanup pass issues two EXISTS probes and one ordered LIMIT
    // delete per pass, all keyed on ttl_expires_at, under the same exclusive
    // lock every audit INSERT takes. Without a covering index each is a full
    // scan of a table that reaches millions of rows, so the guard would trade a
    // wipe risk for a write stall. Partial on `ttl_expires_at > 0` because rows
    // with retention disabled (ttl 0) are never candidates -- and because
    // matching the probes' own predicate is what lets SQLite pick it, so the
    // term is load-bearing in the queries too, not just here.
    //
    // Built OUTSIDE MigrationRunner, best-effort, deliberately. A failed
    // migration closes the database, and from then on every log() returns false
    // -- so routing an O(N log N) index build through that fail-closed path
    // would let a transient temp-space shortfall at the first post-upgrade boot
    // take the SOC 2 audit trail offline. The index is a PERFORMANCE artifact;
    // the guard is correct without it. Measured cost at 5M rows on NVMe: ~81 MB
    // and ~1.8-3.3 s, paid once. At 50M rows the build reads a ~16 GB table --
    // tens of seconds on local NVMe, potentially minutes on overlayfs or network
    // storage, which is why `upgrading.md` tells operators to widen the
    // orchestrator's startup budget. The elapsed time is logged when it is long
    // enough for an operator to have noticed.
    if (!db_)
        return; // symmetry with load_meta/store_meta; also true after a failed migration
    const auto t0 = std::chrono::steady_clock::now();
    SqliteErrMsg err;
    const int rc = sqlite3_exec(db_.get(),
                                "CREATE INDEX IF NOT EXISTS idx_audit_ttl_id "
                                "ON audit_events(ttl_expires_at, id) WHERE ttl_expires_at > 0;",
                                nullptr, nullptr, err.addr());
    const auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    if (rc != SQLITE_OK) {
        // Degraded, not broken: retention still runs, just with full scans under
        // the store lock, which makes the hold grow with the table. LOG ONLY --
        // there is deliberately no metric for this state (#2526): three separate
        // implementations of a health gauge here each shipped a defect, for a
        // signal about a PERFORMANCE artifact the guard is correct without.
        spdlog::error("AuditStore: could not create idx_audit_ttl_id ({}); retention will run "
                      "WITHOUT its index and each pass will scan audit_events",
                      err.c_str());
        return;
    }
    if (ms >= 1000)
        spdlog::info("AuditStore: built idx_audit_ttl_id in {} ms (one-time, first boot after "
                     "upgrade on an existing audit_events)",
                     ms);
}

std::expected<std::int64_t, AuditStore::MetaReadError>
AuditStore::load_meta(const char* key) const {
    if (!db_)
        return std::unexpected(MetaReadError::Unreadable);
    SqliteStmt stmt;
    if (sqlite3_prepare_v2(db_.get(), "SELECT value FROM audit_retention_meta WHERE key = ?", -1,
                           stmt.addr(), nullptr) != SQLITE_OK)
        return std::unexpected(MetaReadError::Unreadable);
    sqlite3_bind_text(stmt.get(), 1, key, -1, SQLITE_STATIC);
    const int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        // Check the STORED TYPE, do not just coerce. The table is not `STRICT`,
        // so `value INTEGER NOT NULL` is an affinity preference, not a
        // constraint: SQLite accepts a TEXT value into it, and
        // `sqlite3_column_int64` then silently coerces `'not-a-number'` to 0.
        // Zero is a legitimate reading (a dead CMOS at the Unix epoch is the
        // motivating case), so without this check a corrupted or hand-edited row
        // is indistinguishable from a real one, and the "unparseable durable
        // state is an anomaly" property this guard claims would not exist.
        // Verified against the shipped SQLite before this check was written.
        if (sqlite3_column_type(stmt.get(), 0) != SQLITE_INTEGER)
            return std::unexpected(MetaReadError::Malformed); // present, but not a number
        return sqlite3_column_int64(stmt.get(), 0);
    }
    // A non-DONE step is a READ FAILURE (SQLITE_CORRUPT, SQLITE_BUSY,
    // SQLITE_IOERR), not an empty table. Collapsing it into Absent would make a
    // transient error at boot look exactly like a fresh install and silently
    // disable the persisted step check for the whole process lifetime -- the
    // silence-means-healthy hole this guard exists to close.
    if (rc != SQLITE_DONE)
        return std::unexpected(MetaReadError::Unreadable);
    // Absent is NOT the same as malformed or unreadable -- see MetaReadError.
    // Returning a typed error rather than 0 matters because 0 is a LEGITIMATE
    // reading: a dead CMOS reporting the Unix epoch is the motivating case for
    // this whole guard, and collapsing it into a sentinel would suppress the
    // check on the very pass after NTP corrects.
    return std::unexpected(MetaReadError::Absent);
}

bool AuditStore::store_meta(const char* key, std::int64_t value) {
    if (!db_)
        return false;
    SqliteStmt stmt;
    if (sqlite3_prepare_v2(db_.get(),
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
    SqliteStmt stmt;
    if (sqlite3_prepare_v2(db_.get(), sql, -1, stmt.addr(), nullptr) != SQLITE_OK) {
        emit_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::error("AuditStore: sqlite3_prepare_v2 failed: {}", sqlite3_errmsg(db_.get()));
        return false;
    }

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto ts = event.timestamp > 0 ? event.timestamp : now;
    auto ttl = retention_days_ > 0 ? now + retention_days_ * 86400LL : 0;

    sqlite3_bind_int64(stmt.get(), 1, ts);
    sqlite3_bind_text(stmt.get(), 2, event.principal.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, event.principal_role.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, event.action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, event.target_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, event.target_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 7, event.detail.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 8, event.source_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 9, event.user_agent.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 10, event.session_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 11, event.result.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 12, ttl);
    sqlite3_bind_text(stmt.get(), 13, event.principal_class.c_str(), -1, SQLITE_TRANSIENT);

    int step_rc = sqlite3_step(stmt.get());

    // SOC 2 CC7.2: a privileged-mutation handler that emits an audit event
    // and silently fails to persist it produces a forensically-empty row.
    // Surface the failure count so operators can alert on a non-zero rate.
    // We still bucket the per-result counter below so the success/failure
    // ratio remains observable separately from the emit-failed signal.
    if (step_rc != SQLITE_DONE) {
        emit_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::error("AuditStore: sqlite3_step rc={} ({}); event lost", step_rc,
                      sqlite3_errmsg(db_.get()));
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

    SqliteStmt stmt;
    if (sqlite3_prepare_v2(db_.get(), sql.c_str(), -1, stmt.addr(), nullptr) != SQLITE_OK) {
        // UP-5: a prepare failure (corruption, locked-past-timeout, schema drift)
        // otherwise returns an empty vector indistinguishable from "no rows" — a
        // false "no audit activity" for an evidence query. Make it observable; a
        // fully-broken store is already pulled from /readyz, and the error-signaling
        // query() contract (so the REST layer can 503 instead of 200-empty) is the
        // tracked follow-up.
        spdlog::error("AuditStore::query prepare failed: {}", sqlite3_errmsg(db_.get()));
        return results;
    }

    for (const auto& [idx, val] : text_binds) {
        sqlite3_bind_text(stmt.get(), idx, val.c_str(), -1, SQLITE_TRANSIENT);
    }
    for (const auto& [idx, val] : int_binds) {
        sqlite3_bind_int64(stmt.get(), idx, val);
    }
    // Under random_sample, over-fetch a bounded candidate pool (capped, indexed)
    // and sample from it in C++ — bounding both CPU and lock-hold. When the window
    // holds more than the cap, the pool is the most-recent kRandomSampleScanCap
    // events (a documented recency bias above the cap; true uniform sampling of an
    // unbounded window would reintroduce the M-1 full-scan).
    const int64_t fetch_limit =
        q.random_sample ? std::max(static_cast<int64_t>(q.limit), kRandomSampleScanCap) : q.limit;
    sqlite3_bind_int64(stmt.get(), limit_idx, fetch_limit);
    if (offset_idx > 0) {
        sqlite3_bind_int64(stmt.get(), offset_idx, q.offset);
    }

    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        AuditEvent e;
        e.id = sqlite3_column_int64(stmt.get(), 0);
        e.timestamp = sqlite3_column_int64(stmt.get(), 1);
        auto col_text = [&](int c) -> std::string {
            auto t = sqlite3_column_text(stmt.get(), c);
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
    SqliteStmt stmt;
    if (sqlite3_prepare_v2(db_.get(), "SELECT COUNT(*) FROM audit_events", -1, stmt.addr(), nullptr) !=
        SQLITE_OK)
        return 0;
    std::size_t count = 0;
    if (sqlite3_step(stmt.get()) == SQLITE_ROW)
        count = static_cast<std::size_t>(sqlite3_column_int64(stmt.get(), 0));
    return count;
}

namespace {

// Run a one-row EXISTS probe. Returns the REASON on any prepare/bind/step error so
// the caller can fail closed rather than read a default.
//
// `binds` is a span, not a pointer+count: the arity is then deduced from the
// array at the call site and checked against the statement's own parameter
// count below. A hand-maintained count could silently disagree with the SQL --
// and an unbound parameter reads as NULL, which makes `ttl_expires_at < NULL`
// yield NULL, which makes EXISTS return 0, which reads as "nothing is expired".
// Retention would then stop forever while every counter reported healthy.
std::expected<bool, std::string> exists_probe(sqlite3* db, const char* sql,
                                             std::span<const std::int64_t> binds) {
    // Returns the REASON, not a bare optional. The caller cannot reconstruct it
    // with `sqlite3_errmsg` after the fact: the arity branch below fails without
    // any SQLite call having failed, so errmsg would report "not an error" (or a
    // stale message from an unrelated call) in a SOC 2-relevant warn line, and
    // the statement is finalized by the time the caller looks.
    SqliteStmt stmt;
    if (sqlite3_prepare_v2(db, sql, -1, stmt.addr(), nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db));
    if (static_cast<std::size_t>(sqlite3_bind_parameter_count(stmt.get())) != binds.size())
        return std::unexpected("bind arity mismatch: the SQL and the call site disagree");
    for (std::size_t i = 0; i < binds.size(); ++i)
        if (sqlite3_bind_int64(stmt.get(), static_cast<int>(i) + 1, binds[i]) != SQLITE_OK)
            return std::unexpected(sqlite3_errmsg(db));
    // EXISTS(...) always yields exactly one row holding 0 or 1.
    if (sqlite3_step(stmt.get()) != SQLITE_ROW)
        return std::unexpected(sqlite3_errmsg(db));
    return sqlite3_column_int(stmt.get(), 0) != 0;
}

} // namespace

std::size_t AuditStore::cleanup_once(std::int64_t now) {
    // Liveness, stamped for EVERY pass -- including the implausible-`now`
    // refusal below, declines, and failures. The documented contract is "passes
    // ATTEMPTED"; a reaper that runs and refuses is healthy, a reaper that never
    // runs is the failure these two exist to expose, and no other counter moves
    // in that state. Stamped BEFORE any return so no branch can make the
    // liveness signal lie.
    retention_passes_.fetch_add(1, std::memory_order_relaxed);

    // Sanitise the CALLER's clock, not only the stored reading. In production
    // `run_cleanup` passes `system_clock` seconds, but this method is public and
    // `now + window + kAuditTtlFutureSlackSec` below is signed-overflow UB for a
    // `now` near INT64_MAX. A reading that far out is not one this guard can
    // reason about, so refuse the pass instead of computing on it. Counted, not
    // silent: returning a bare 0 is indistinguishable from a healthy no-op.
    // UPPER bound only. A NEGATIVE `now` is both safe and legitimate here: it is
    // the dead-CMOS-reporting-1969 case this guard exists for. It cannot
    // underflow either subtraction, because the stored-reading sanitiser admits
    // only `0 <= prev <= now`, which no prev satisfies when `now < 0`, so the
    // elapsed-time arithmetic is skipped entirely. Rejecting it would refuse the
    // pass on exactly the machine the guard is for.
    constexpr std::int64_t kMaxPlausibleNow = std::numeric_limits<std::int64_t>::max() / 4;
    if (now > kMaxPlausibleNow) {
        cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
        spdlog::warn("AuditStore: retention pass called with an implausible clock reading ({}); "
                     "declining the pass",
                     now);
        return 0;
    }

    // Stamped only for a reading the guard is willing to reason about. Stamping
    // the refused value would poison the gauge permanently on a machine whose
    // clock jumped far forward -- and the "last pass is stale" diagnostic the
    // absence alert points operators at would then never fire again. The
    // ATTEMPT is already counted above; this is the reading, and a reading we
    // just declared unusable is not one.
    last_pass_unixtime_.store(now, std::memory_order_relaxed);

    // What this pass wants logged, filled in under the lock and emitted after it
    // is released: spdlog formatting is neither cheap nor bounded, and every
    // audit log() blocks on this same exclusive lock.
    enum class Emit {
        None,
        ProbeFailed,
        DeclineFirstPass,
        DeclineWipe,
        DeclineStep,
        DeclineImplausible,
        CorruptStateReported,
        Deleted,
        DeleteFailed
    };
    Emit emit = Emit::None;
    bool emit_persist_failed = false;
    std::string emit_err;
    std::size_t deleted = 0;
    std::int64_t emit_delta = 0, emit_window = 0;
    bool emit_full_wipe = false, emit_capped = false;
    std::string emit_backlog_probe_err;

    {
        std::unique_lock lock(mtx_);
        if (!db_) {
            // Defensive only, and deliberately NOT the production signal for a
            // closed store: start_cleanup() early-returns when db_.get() is null, so
            // no thread reaches this in a running server. A store closed by a
            // failed migration surfaces through log()'s emit_failed_ counter.
            // Counted anyway so a direct caller (a test, or a future scheduler
            // that does not check is_open()) is not silently told it succeeded.
            cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
            return 0;
        }

        // A non-positive retention setting means "never expire": log() stamps
        // ttl 0 on every row, so no row is ever a candidate.
        const std::int64_t window =
            retention_days_ > 0 ? static_cast<std::int64_t>(retention_days_) * 86400 : 0;

        // Record this pass's reading for the NEXT pass, before any early return
        // below. The reading is an honest observation of the clock whatever the
        // pass goes on to do, and not recording it on a failing pass would make
        // a later recovery report a step that was really an outage. Re-anchoring
        // here is also what lets a poisoned or stale value self-heal.
        //
        // Persisted, because the step check is the ONLY half of this guard that
        // works when the clock was already wrong before the process started.
        // Held in memory alone it has no comparison point on the first pass and
        // never fires -- exactly the dead-CMOS-at-boot case. A failed write is
        // not fatal: it costs the NEXT restart its comparison point.
        const std::optional<std::int64_t> raw_prev = last_pass_now_;
        last_pass_now_ = now;
        if (!store_meta(kLastPassNowKey, now)) {
            emit_persist_failed = true;
            persist_failed_.fetch_add(1, std::memory_order_relaxed);
        }

        // SANITISE the reading before doing arithmetic on it. It is durable
        // state in the same database as the evidence, so it can come back
        // corrupt, hand-edited, or -- far more mundanely -- stamped by an
        // earlier pass that ran while the clock was skewed FORWARD. `prev > now`
        // makes `now - prev` negative for as long as real time takes to catch up
        // (potentially years), silently killing the only detector that survives
        // a restart. `now - INT64_MIN` also overflows, and is reachable with an
        // ordinary expired backlog, so this prevents UB as well as the silent
        // disable.
        //
        // BOTH out-of-range directions are anomalies, not quiet resets. They are
        // NOT proof of tampering and must not be described as such: this very
        // code persists a NEGATIVE reading when it runs on a dead-CMOS machine
        // (the upper-bound-only guard admits `now < 0` deliberately), and an
        // ordinary backward NTP correction leaves a perfectly legitimate earlier
        // reading ahead of `now`. What they prove is that the reading cannot be
        // reasoned about: the clock moved backward, or the state was corrupted.
        // Quietly accepting one is how the step check gets disabled while every
        // counter reports healthy, which is why it declines either way.
        // Was the clock MOVED, materially, since the previous pass? Computed
        // before the sanitiser resets the reading below. NOT symmetric with
        // `big_step`, in three ways that are each load-bearing: this test has no
        // `window > 0` gate, it compares magnitude in either direction rather
        // than forward elapsed time, and it is inclusive of the floor where
        // `big_step` is strict. A movement of EXACTLY the floor is a
        // `clock_event` and is not a `big_step`. Collapsing the two re-opens the
        // class this guard exists to catch.
        //
        // The floor is the whole point. An earlier version treated ANY backward
        // reading as an event, with no magnitude test at all, while its forward
        // twin required seven days. Because an event forces the REPORT branch,
        // and the report branch is the branch that does NOT delete, a clock
        // regressing one second per pass -- two disagreeing time sources, a
        // hypervisor sync racing NTP -- reported forever and never drained once.
        // Sub-floor jitter is a CONDITION: say it once, then get on with the
        // drain. True for MONOTONE drift, which is the common shape.
        //
        // NOT fixed, and tracked: any clock that yields an EVENT on every pass
        // holds the report branch and so starves the drain for as long as it
        // lasts. Three shapes reach that, and they do NOT share preconditions.
        // BACKWARD movement of at least the floor qualifies on its own, via
        // `BadState` ahead of every other test. FORWARD movement of more than
        // the floor qualifies only through `Step`, so it inherits `window > 0`
        // and `has_expired` -- with retention disabled a forward ratchet over
        // legacy non-zero TTLs classifies `None` and DELETES, it does not
        // starve. Sub-floor ALTERNATION needs a standing would-wipe:
        // `prev_unusable` flips every pass, so the fact set changes every pass
        // and dedup never engages, which in turn needs a store with no audit
        // write inside a whole retention window. All three raise
        // `clock_anomaly_skips_` on every halted pass, so they are loud rather
        // than silent, and all three predate this floor.
        //
        // `clock_event`'s own directional symmetry -- not symmetry with
        // `big_step`, which the paragraph above rules out -- also covers the
        // case a backward-only test missed entirely:
        // recovery OUT of negative time (dead CMOS, then NTP) is a forward
        // movement of enormous magnitude carried by `BadState`, not by
        // `big_step`, because the sanitiser has already discarded the negative
        // reading by the time `big_step` is computed.
        const bool clock_event =
            raw_prev && audit_retention::moved_at_least(*raw_prev, now, kAuditMinBigStepSec);
        std::optional<std::int64_t> prev_pass_now = raw_prev;
        // A row that existed but was not an integer is corrupted durable state,
        // which is an anomaly in its own right -- distinct from no row at all.
        // NOT cleared here. This pass may still return before the decline is
        // decided -- an unreadable probe, or simply nothing expired -- and
        // clearing on those paths swallows the corruption signal with no
        // decline, no counter and no warn. It is cleared only where it is
        // actually CONSUMED, below. (The durable row is already re-anchored, so
        // the flag is the only remaining carrier of "the state was corrupt".)
        bool prev_unusable = loaded_meta_unusable_;
        if (prev_pass_now && (*prev_pass_now < 0 || *prev_pass_now > now)) {
            prev_unusable = true;
            prev_pass_now.reset();
        }

        // Detect by OUTCOME, not by a clock delta alone: the outcome test needs
        // no history, so it survives a restart with empty process state. Two
        // EXISTS probes answer the whole question and stay index-driven; a
        // COUNT(*) pair would scan.
        //
        // `would_wipe` reduces to "no datable row survives the cutoff". A row
        // older than `cutoff` is necessarily at or below `now + window + slack`,
        // so every expired row is also datable -- which makes a separate
        // "datable > 0" term dead, and leaves a single EXISTS over the half-open
        // band that short-circuits on the first survivor.
        //
        // NOTE this test is defeated by ANY write landing after the jump: a
        // fresh row is a datable survivor. On a server that is up and serving,
        // that is the common case, which is why the persisted step check below
        // is not optional. Together they are still best-effort DETECTION -- the
        // per-pass cap is the half that bounds the damage unconditionally.
        const std::int64_t datable_horizon = now + window + kAuditTtlFutureSlackSec;
        const std::int64_t expired_binds[] = {now};
        const std::int64_t survivor_binds[] = {now, datable_horizon};
        const auto has_expired =
            exists_probe(db_.get(),
                         "SELECT EXISTS(SELECT 1 FROM audit_events "
                         "WHERE ttl_expires_at > 0 AND ttl_expires_at < ?)",
                         expired_binds);
        // `BETWEEN` IS LOAD-BEARING. Do not rewrite it as `>= ? AND <= ?`.
        //
        // The partial index carries the literal `ttl_expires_at > 0`. With two
        // SEPARATE comparisons SQLite can take that literal as its lower seek
        // bound and demote `>= now` to a per-row filter, so the probe walks the
        // ENTIRE expired prefix instead of seeking past it. `BETWEEN` is treated
        // as one range constraint and is not vulnerable to that.
        //
        // Measured here, 3M expired rows + 1 survivor, SQLite 3.52, this index:
        //   `> 0 AND ttl BETWEEN ? AND ?`    0.0069 ms   <-- as written
        //   `ttl BETWEEN ? AND ? AND > 0`    0.0068 ms
        //   `> 0 AND ttl >= ? AND ttl <= ?`  83.6 ms     <-- the trap
        //   `ttl >= ? AND ttl <= ? AND > 0`  0.0066 ms
        //
        // So BETWEEN is safe in EITHER position; only the separate-comparison
        // form is order-sensitive. A rewrite to `>= AND <=` that leaves `> 0`
        // first therefore reintroduces an ~84 ms hold under the lock every audit
        // write takes -- with identical results AND a byte-identical EXPLAIN
        // QUERY PLAN, so no test and no plan check would notice. This comment is
        // the guard.
        const auto has_datable_survivor =
            exists_probe(db_.get(),
                         "SELECT EXISTS(SELECT 1 FROM audit_events "
                         "WHERE ttl_expires_at > 0 AND ttl_expires_at BETWEEN ? AND ?)",
                         survivor_binds);

        if (!has_expired || !has_datable_survivor) {
            // Fail closed: a probe we could not read is not evidence that
            // deleting is safe. No verdict is possible, so the anomaly state is
            // RE-ARMED (a failed pass says nothing about the clock, and carrying
            // a report across it would let the next genuinely-wiping pass delete
            // silently) but the load-time flag is deliberately NOT consumed --
            // this pass did not act on it.
            cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
            last_reported_.reset();
            emit = Emit::ProbeFailed;
            emit_err = !has_expired ? has_expired.error() : has_datable_survivor.error();
        } else {
            const bool would_wipe = !*has_datable_survivor;
            // Supplement, not a replacement. `would_wipe` only fires when a
            // forward jump exceeds the WHOLE retention window; a half-window
            // jump expires half the store, which the cap bounds but nothing
            // would otherwise report. Persisted across restarts, so unlike the
            // outcome test it still fires when a write has already landed after
            // the jump.
            const bool big_step =
                prev_pass_now && window > 0 && now - *prev_pass_now > kAuditMinBigStepSec;
            emit_delta = prev_pass_now ? now - *prev_pass_now : 0;
            emit_window = kAuditMinBigStepSec;
            emit_full_wipe = would_wipe;

            // `cleanup_once` is the ONLY caller of `classify`; the rule lives in its
            // own header so it can be pinned exhaustively (all 16 inputs) without a
            // database, not because anything else consumes it.
            const audit_retention::Facts facts{.has_expired = *has_expired,
                                               .would_wipe = would_wipe,
                                               .big_step = big_step,
                                               .prev_unusable = prev_unusable};
            const audit_retention::Anomaly a = audit_retention::classify(facts);
            // Consumed HERE, unconditionally, at exactly one site: this pass has
            // folded it into the verdict. The durable row was re-anchored above,
            // so from now on the VALUE carries the truth. Three conditional
            // clear sites is what produced both the cleared-too-early and the
            // cleared-too-late defects.
            loaded_meta_unusable_ = false;

            // ONE rule for the whole guard: report an anomaly when it is not the
            // one already being reported, and stand down when it is gone. This
            // subsumes what used to be a shared bool latch plus a separate
            // one-shot flag plus per-branch clearing -- and it fixes what that
            // could not express, namely a DIFFERENT anomaly arriving while
            // latched, which the single bool silently swallowed.
            // EVENTS are not deduplicated; CONDITIONS are.
            //
            // A CONDITION persists on its own -- an all-expired table, a corrupt
            // stored reading -- so a repeat is the same anomaly still being
            // worked off. Suppressing it is what stops a legitimately
            // all-expired store from declining forever.
            //
            // An EVENT is a material clock MOVEMENT. It is observable only
            // because this pass re-anchored the reading, so a second one is a
            // second incident, never a continuation of the first, and must
            // report every time. It cannot spam: after any pass the stored
            // reading is `now`, so the next pass sees an interval-sized delta
            // unless the clock actually moved again.
            //
            // Deduplication compares the whole FACT SET, not the classified
            // enum. `classify` collapses four facts onto one value, so an enum
            // comparison cannot see a new condition arriving underneath a
            // reported one: a `Wipe` appearing under a standing `BadState`
            // classifies as `BadState` both times, matches, and is silently
            // deleted for. That is the dead-CMOS-then-NTP sequence, and for any
            // store below the cap it took the entire SOC 2 trail in one pass
            // with no warning and no counter.
            const bool is_event = (a == audit_retention::Anomaly::Step) ||
                                  (a == audit_retention::Anomaly::BadState && clock_event);
            if (a != audit_retention::Anomaly::None &&
                (is_event || !last_reported_ || *last_reported_ != facts)) {
                clock_anomaly_skips_.fetch_add(1, std::memory_order_relaxed);
                // NOT unobservable for `Step`, which an earlier comment here
                // claimed. Being event-exempt means this write cannot cause
                // SUPPRESSION -- that is all that proof established. It does
                // re-arm the comparison, so a condition recurring after a step
                // is reported rather than swallowed. Dropping it for `Step`
                // survived the whole suite until a test was written for it.
                last_reported_ = facts;
                switch (a) {
                case audit_retention::Anomaly::BadState:
                    // Same condition, two audiences: with a backlog pending the
                    // operator needs to know deletion was held back; without
                    // one, that nothing was at risk.
                    emit = *has_expired ? Emit::DeclineImplausible : Emit::CorruptStateReported;
                    break;
                case audit_retention::Anomaly::Step:
                    emit = Emit::DeclineStep;
                    break;
                case audit_retention::Anomaly::Wipe:
                    emit = prev_pass_now ? Emit::DeclineWipe : Emit::DeclineFirstPass;
                    break;
                case audit_retention::Anomaly::None:
                    break; // unreachable: guarded above
                }
            } else {
                if (a == audit_retention::Anomaly::None)
                    last_reported_.reset(); // stood down; re-armed
                // Either nothing is wrong, or we are working off an anomaly we
                // have already reported. Both delete -- paced by the cap, which
                // is what actually bounds the damage.
                if (*has_expired) {
                    auto outcome = delete_capped_locked(now);
                    if (!outcome) {
                        emit = Emit::DeleteFailed;
                        emit_err = std::move(outcome.error());
                    } else {
                        deleted = outcome->deleted;
                        // "the cap bound AND rows were left behind" -- the same
                        // post-delete fact the cap counter uses, so the log line
                        // and the metric cannot disagree.
                        emit_capped = outcome->backlog_remains;
                        emit_backlog_probe_err = std::move(outcome->backlog_probe_err);
                        if (deleted > 0)
                            emit = Emit::Deleted;
                        // STAND DOWN once the backlog that anomaly produced is
                        // gone. This is the other half of the one rule, and it
                        // must key on the POST-delete fact: without it, a pass
                        // that drains everything leaves the anomaly still
                        // "being reported", so a fresh one arriving before any
                        // intervening quiet pass is silently swallowed. An
                        // unreadable backlog probe reports `true` conservatively,
                        // which keeps the report standing -- the safe direction.
                        if (!outcome->backlog_remains)
                            last_reported_.reset();
                    }
                }
            }
        }

    } // lock released before any formatting

    if (!emit_backlog_probe_err.empty())
        spdlog::warn("AuditStore: the post-delete backlog probe failed ({}); this pass assumed a "
                     "backlog remains, so the cap counter and the reported-anomaly state are both "
                     "acting on an assumption rather than a reading",
                     emit_backlog_probe_err);
    if (emit_persist_failed)
        spdlog::warn("AuditStore: could not persist the retention clock reading; a restart before "
                     "the next pass will lose its clock-step comparison point");
    switch (emit) {
    case Emit::None:
        break;
    case Emit::DeclineImplausible:
        spdlog::warn("AuditStore: the stored retention clock reading is not usable (negative, "
                     "ahead of the current clock, present but not an integer, or unreadable), "
                     "so this "
                     "server's clock moved backward or that durable state was corrupted; "
                     "declining once and re-anchoring on the current reading");
        break;
    case Emit::CorruptStateReported:
        spdlog::warn("AuditStore: the stored retention clock reading was unusable (negative, "
                     "ahead of the current clock, not an integer, or unreadable) and has been "
                     "re-anchored. This pass declined "
                     "to trust it and deleted nothing -- there was nothing expired to delete "
                     "either way -- so the restart-surviving half of the clock guard had no "
                     "comparison point until now");
        break;
    case Emit::ProbeFailed:
        spdlog::warn("AuditStore: retention probe failed ({}); skipping this pass", emit_err);
        break;
    case Emit::DeleteFailed:
        spdlog::warn("AuditStore: cleanup error: {}", emit_err);
        break;
    case Emit::DeclineFirstPass:
        spdlog::warn("AuditStore: the first retention pass against this database would expire "
                     "EVERY datable audit row; declining once so a clock anomaly cannot delete "
                     "the audit trail wholesale. (There is no previous reading to compare "
                     "against, so nothing can be said about the clock yet.)");
        break;
    case Emit::DeclineWipe:
        spdlog::warn("AuditStore: this retention pass would expire EVERY datable audit row; "
                     "declining once so a clock anomaly cannot delete the audit trail wholesale. "
                     "(No unusual gap since the last pass -- either the clock moved while this "
                     "server was running, or the store is genuinely all-expired.)");
        break;
    case Emit::DeclineStep:
        spdlog::warn("AuditStore: {}s elapsed since the last retention pass, over the {}s "
                     "threshold -- a forward clock jump OR an outage that long. This pass would "
                     "have expired {}; declining once so a clock anomaly cannot delete the audit "
                     "trail wholesale",
                     emit_delta, emit_window,
                     emit_full_wipe ? "EVERY datable audit row" : "an unexpectedly large slice");
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

std::expected<AuditStore::DeleteOutcome, std::string>
AuditStore::delete_capped_locked(std::int64_t now) {
    // Bound the pass so that even a wipe this guard chose to allow ages out at a
    // paced rate instead of in one statement. Oldest-first so the pacing never
    // strands the oldest evidence behind newer expiries.
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
    if (sqlite3_prepare_v2(db_.get(), kDeleteSql, -1, del.addr(), nullptr) != SQLITE_OK) {
        cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
        last_reported_.reset(); // re-arm, as on the probe path
        return std::unexpected(sqlite3_errmsg(db_.get()));
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
        // Read BEFORE the SqliteStmt destructor finalizes the statement.
        std::string err = sqlite3_errmsg(db_.get());
        last_reported_.reset();
        // The rows RETURNING already yielded are NOT deleted: SQLite unwinds a
        // failed statement from its statement journal, so they are back.
        return std::unexpected(std::move(err));
    }
    del.reset();
    rows_deleted_.fetch_add(deleted, std::memory_order_relaxed);

    // Did this pass actually leave a backlog? One bounded EXISTS, and ONLY when
    // the cap bound the pass, so the healthy path pays nothing.
    //
    // Guessing this from `deleted >= cap` is wrong: a drain that removed exactly
    // a cap's worth and emptied the backlog would still count as capped, while
    // every doc says that counter proves a backlog remains. The caller ALSO
    // needs the real answer -- it is what stands the reported anomaly down once
    // the backlog it produced is gone -- so it must be an observation, not an
    // inference from the row count.
    bool backlog_remains = false;
    std::string probe_err;
    if (deleted >= kMaxAuditDeletesPerPass) {
        const std::int64_t binds[] = {now};
        const auto more = exists_probe(db_.get(),
                                       "SELECT EXISTS(SELECT 1 FROM audit_events "
                                       "WHERE ttl_expires_at > 0 AND ttl_expires_at < ?)",
                                       binds);
        // Unreadable: assume a backlog remains. That keeps the anomaly reported and
        // the counter moving, the conservative direction for both -- but SAY SO.
        // Without this the failure is the only one in the pass that moves no
        // counter and writes no line, and `cap_reached_` would then be
        // incremented on an assumption while its own description claims it
        // proves a backlog. Near-unreachable (the exclusive lock means only an
        // out-of-process writer could make the delete succeed and an
        // identical-predicate probe fail), which is exactly why it must not be
        // the one silent path.
        if (!more) {
            probe_err = more.error();
            cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
        }
        backlog_remains = !more || *more;
        if (backlog_remains)
            cap_reached_.fetch_add(1, std::memory_order_relaxed);
    }

    // NO anomaly bookkeeping here. This function deletes; deciding what is being
    // reported belongs to the one rule in cleanup_once, which re-evaluates the
    // condition each pass from the probes. Deriving the reported state from a
    // post-delete fact here is what produced the pre-delete/post-delete
    // ordering defects.
    return DeleteOutcome{deleted, backlog_remains, std::move(probe_err)};
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

        auto now = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();

        // NOTHING may escape a thread function: an exception here is
        // std::terminate, i.e. the whole server dies because a retention pass
        // could not allocate. `cleanup_once` allocates (the error string) and
        // formats log lines, so the surface is real (#2037 class).
        try {
            cleanup_once(now);
        } catch (...) {
            // The counter first, and unconditionally: it is the part that must
            // survive. REPORTING the failure allocates (spdlog formats), so a
            // bad_alloc in the handler would escape this thread function and
            // terminate the server -- the exact condition the handler exists to
            // prevent. The report is therefore nested and everything is
            // swallowed: a pass that failed AND could not say so still leaves
            // `cleanup_failed_` moving, which is what the alert keys on.
            cleanup_failed_.fetch_add(1, std::memory_order_relaxed);
            try {
                try {
                    throw;
                } catch (const std::exception& e) {
                    spdlog::error("AuditStore: retention pass threw ({}); abandoned, retried at "
                                  "the next interval",
                                  e.what());
                } catch (...) {
                    spdlog::error("AuditStore: retention pass threw a non-std exception; "
                                  "abandoned, retried at the next interval");
                }
            } catch (...) {
                // Nothing escapes a thread function, not even a failure to report.
            }
        }
    }
}

} // namespace yuzu::server
