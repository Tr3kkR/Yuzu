#pragma once

#include <sqlite3.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

namespace yuzu::server {

struct AuditEvent {
    int64_t id{0};
    int64_t timestamp{0}; // epoch seconds
    std::string principal;
    std::string principal_role;
    std::string action;
    std::string target_type;
    std::string target_id;
    std::string detail;
    std::string source_ip;
    std::string user_agent;
    std::string session_id;
    std::string result;   // "success", "failure", "denied"
    std::string mcp_tool; // MCP tool name if action was MCP-initiated (empty otherwise)
    // Actor class (ADR-1005 Decision 9 / execution-plan Phase 3a), mirroring
    // principal_class.hpp's HTTP request-metric label: "human" (session
    // cookie), "agent" (bearer/API token), "none" (unauthenticated — a failed
    // login, a probe-adjacent request; honest label, not a guess at human vs.
    // agent), or "" for any row this program cannot attribute to an HTTP
    // session/token principal at all (the agent-daemon's own gRPC channel,
    // gateway-proxied calls, server-internal/background writers — a different
    // kind of actor `principal_class_of` was never meant to classify; see its
    // own header comment). "engine" is reserved, live once Phase 4 engine-token
    // sessions exist. Populated at `AuthRoutes::make_audit_event`/
    // `audit_log_for_principal` (the two HTTP-request-shaped constructors) via
    // `principal_class_of(req)`; every other AuditEvent construction leaves it
    // at its default "".
    std::string principal_class;
};

struct AuditQuery {
    std::string principal;
    std::string action;
    std::string target_type;
    std::string target_id;
    int64_t since{0};
    int64_t until{0};
    int limit{100};
    int offset{0};
    // Match any action that starts with one of these prefixes (OR-combined),
    // e.g. {"auth.","mfa.","session."} to scope to the authentication surface
    // (sampled auth-log evidence export, #4 / SOC 2 CC7.2). Empty = no prefix
    // filter. Combines with `action` (exact) if both are set.
    //
    // CONTRACT (Hermes I-1): prefixes are bound as a SQL `LIKE <prefix>%` pattern
    // and are NOT escaped, so a caller must only ever pass code-controlled literal
    // prefixes — never untrusted input, which could smuggle `%`/`_` wildcards.
    // A degenerate all-empty list does NOT widen to "all actions" (query() emits
    // an always-false guard), so it fails closed.
    std::vector<std::string> action_prefixes;
    // When true, the result is a pseudo-random sample rather than newest-first:
    // query() fetches a bounded candidate pool in indexed timestamp order (capped
    // at kAuditSampleScanCap to bound CPU + reader-lock hold — NOT `ORDER BY
    // RANDOM()`, which would full-scan the window), then shuffles in C++ and
    // truncates to `limit`. When the window holds more than the cap, the pool is
    // the most-recent kAuditSampleScanCap events (a recency bias above the cap —
    // callers presenting this as evidence must surface it). `offset` is ignored.
    bool random_sample{false};
};

// Candidate-pool cap for AuditQuery::random_sample. A sample is drawn from at
// most this many most-recent matching rows; above it the sample is recency-biased
// (see random_sample). Public so the REST layer can report `recency_capped` to an
// auditor (#4 / SOC 2 CC7.2 evidence honesty).
inline constexpr std::size_t kAuditSampleScanCap = 10000;

// ── Retention clock guard (#2360) ──────────────────────────────────────────
//
// Retention deletes rows whose TTL has passed, with "has passed" decided by the
// server's wall clock. One forward step -- a restored VM snapshot, an NTP
// correction after a dead CMOS battery, a hand-set date -- marks the whole
// evidence table expired at once, and an unguarded `DELETE ... WHERE ttl < now`
// actions that in a single statement. These constants bound that.
//
// The division of labour matters and is easy to get backwards: the CAP is the
// guarantee, the detectors are best-effort. See `cleanup_once`.

// Rows whose TTL lands more than this far in the future are excluded from the
// "would this pass delete everything datable?" question. A TTL is stamped
// `insert_time + retention_days*86400` from the local clock, so the newest
// healthy row sits exactly one retention window ahead of `now`; anything past
// window+slack was written under a forward-skewed clock. Such a row can never
// itself expire, so counting it as a survivor would let ONE bad row veto the
// guard for the life of the store -- the guard would die precisely when it is
// needed. Slack absorbs ordinary NTP correction and the write-to-cleanup gap.
//
// The direction of error is deliberate. Rows stamped under a LONGER retention
// setting (an operator who just cut retention from 365d to 30d) also land past
// the horizon, so they are excluded too and the wipe test becomes EASIER to
// fire. Over-firing costs one declined pass and then paced deletion;
// under-excluding disarms the guard.
inline constexpr std::int64_t kAuditTtlFutureSlackSec = 2 * 86400;

// Upper bound on rows deleted by ONE retention pass. This is the load-bearing
// half of the guard: it applies unconditionally, whether or not anything was
// detected, and it is what turns an accepted wipe into a paced ageing-out an
// operator can still catch.
//
// Sized as a DRAIN RATE, not as a batch-size guess: at the 60-minute default
// interval this drains 0.6M rows/day, far above any plausible steady-state
// expiry rate for an audit table, so the accepting path keeps up and the latch
// never sits permanently set. It does imply a sustained-throughput ceiling of
// ~6.9 events/sec; past that the backlog never drains, which is what
// `cap_reached_count()` exists to report.
//
// Retention here is a floor: deleting late harms nothing the evidence store
// exists for, so over-retaining is the safe direction.
inline constexpr std::size_t kMaxAuditDeletesPerPass = 25000;

// Threshold for the elapsed-time detector. ABSOLUTE -- how far the clock moved
// has nothing to do with how long rows are kept.
//
// Deriving this from the retention window is the obvious-looking mistake and it
// is fatal: at the 365-day default the threshold becomes a YEAR, so the check
// never fires on a stock server. Since the outcome test is separately defeated
// by any row written after the jump, BOTH detectors then go inert for anything
// short of a year-long gap, and a month-long jump deletes a month of extra
// evidence silently. Test fixtures using a short retention setting will not
// catch that, because there the constant dominates anyway.
//
// Elapsed time cannot distinguish a clock jump from an outage, so the value is
// set past the point where an outage is itself remarkable, and the warning text
// names both causes. A server genuinely down for eight days declines one pass:
// cheap, and the right trade for catching a month-long jump.
inline constexpr std::int64_t kAuditMinBigStepSec = 7 * 86400;

class AuditStore {
public:
    explicit AuditStore(const std::filesystem::path& db_path, int retention_days = 365,
                        int cleanup_interval_min = 60);
    ~AuditStore();

    AuditStore(const AuditStore&) = delete;
    AuditStore& operator=(const AuditStore&) = delete;

    bool is_open() const;

    /// Persist an audit event. Returns true iff the row was written. The
    /// bool return is part of the SOC 2 CC6.6/CC7.2 evidence-integrity
    /// chain: handlers that emit an audit row as their compliance evidence
    /// for a privileged mutation MUST observe the return and surface
    /// partial-success on the response when the persist fails — otherwise
    /// a "200 OK" + dropped row produces fictional audit evidence. On
    /// failure `emit_failed_` increments and the row is lost. Callers that
    /// legitimately fire-and-forget (background tasks, denied gates that
    /// already failed the operation) may discard the bool; the
    /// `[[nodiscard]]` flag makes the discard locally visible.
    [[nodiscard]] bool log(const AuditEvent& event);
    /// Query audit events. When `q.random_sample` is set and `out_pool_size` is
    /// non-null, `*out_pool_size` receives the size of the candidate pool the
    /// sample was drawn from BEFORE shuffle/truncate (<= kAuditSampleScanCap) —
    /// so the caller can report `recency_capped = (*out_pool_size == kAuditSampleScanCap)`
    /// for evidence honesty (#4). For non-sample queries `*out_pool_size` is left
    /// untouched.
    std::vector<AuditEvent> query(const AuditQuery& q = {},
                                  std::size_t* out_pool_size = nullptr) const;
    std::size_t total_count() const;

    /// Cumulative audit-event write counts grouped by `result` value. Exposed for
    /// Prometheus scraping; reset at process start. Lock-free reads.
    uint64_t events_written(const std::string& result) const noexcept;

    /// Cumulative count of audit events that failed to persist (sqlite3_step
    /// did not return SQLITE_DONE). Audit pipeline degradation is a SOC 2
    /// CC7.2 evidence-chain risk; surface it on /metrics so operators can
    /// page on a non-zero rate.
    uint64_t emit_failed_count() const noexcept {
        return emit_failed_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of retention passes that DECLINED to delete. Three
    /// triggers: the pass would have aged out every datable row; the gap since
    /// the previous pass exceeded kAuditMinBigStepSec; or the stored clock
    /// reading was AHEAD of the current clock (or otherwise not a plausible past
    /// reading). The middle one cannot distinguish a forward clock jump from an
    /// outage that long, so a non-zero value means "this server's clock moved,
    /// OR it was down that long" -- not the clock alone.
    uint64_t clock_anomaly_skips_count() const noexcept {
        return clock_anomaly_skips_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of retention passes that failed outright (a probe or the
    /// delete itself returned a SQLite error). Scraped SEPARATELY from
    /// `clock_anomaly_skips_count()` on purpose: both leave rows undeleted, but
    /// one means "the guard is protecting the table" and the other means "the
    /// cleanup loop is broken". A single counter could not tell an operator
    /// which, so an unbounded-growth audit table would look like a working guard.
    uint64_t cleanup_failed_count() const noexcept {
        return cleanup_failed_.load(std::memory_order_relaxed);
    }

    /// Cumulative rows deleted by retention, and the number of passes that hit
    /// the per-pass cap AND left a backlog behind. The cap is what turns an
    /// allowed wipe into a paced ageing-out, but it introduces its own failure
    /// mode: if it binds on every pass for a sustained period, expiry is
    /// outrunning the drain and `audit.db` grows without bound. Neither the skip
    /// counter nor the failure counter moves in that state, so without this pair
    /// it is invisible on /metrics.
    uint64_t rows_deleted_count() const noexcept {
        return rows_deleted_.load(std::memory_order_relaxed);
    }
    uint64_t cap_reached_count() const noexcept {
        return cap_reached_.load(std::memory_order_relaxed);
    }

    /// True while the retention index exists. Evaluated once, at construction,
    /// so it cannot detect an index dropped at runtime. Without the index every
    /// pass full-scans `audit_events` under the exclusive lock every audit write
    /// needs, and that cost grows with the table -- this is the one signal that
    /// says the pass's bounded lock hold is no longer bounded.
    bool retention_index_ok() const noexcept {
        return retention_index_ok_.load(std::memory_order_relaxed);
    }

    /// Cumulative failures to persist the retention clock reading. A sustained
    /// non-zero rate means the restart-surviving half of the guard is degraded.
    uint64_t persist_failed_count() const noexcept {
        return persist_failed_.load(std::memory_order_relaxed);
    }

    /// Run exactly ONE retention pass against `now` (epoch seconds) and return
    /// the number of rows deleted. Returns 0 when the pass declined (clock
    /// guard), when nothing was expired, or when the pass failed.
    ///
    /// This is the whole body of the cleanup loop, factored out so tests can
    /// drive a pass at an arbitrary `now` without sleeping the cleanup interval
    /// and without touching the wall clock. All guard state is read and written
    /// under `mtx_`, so calling it concurrently with a running cleanup thread is
    /// safe (if pointless); tests generally do not call `start_cleanup()`.
    std::size_t cleanup_once(std::int64_t now);

    void start_cleanup();
    void stop_cleanup();

private:
    sqlite3* db_{nullptr};
    int retention_days_;
    int cleanup_interval_min_;
    mutable std::shared_mutex mtx_;

    // Cumulative event write counters bucketed by `result` field. Lock-free.
    std::atomic<uint64_t> events_success_{0};
    std::atomic<uint64_t> events_failure_{0};
    std::atomic<uint64_t> events_denied_{0};
    std::atomic<uint64_t> events_other_{0};
    // Persistence-failure counter: rows where the INSERT step returned
    // anything other than SQLITE_DONE.
    std::atomic<uint64_t> emit_failed_{0};
    // Retention-guard counters (#2360). Atomic because the /metrics scrape
    // thread reads them without taking mtx_; all are only ever incremented from
    // inside cleanup_once()'s exclusive lock.
    std::atomic<uint64_t> clock_anomaly_skips_{0};
    std::atomic<uint64_t> cleanup_failed_{0};
    std::atomic<uint64_t> rows_deleted_{0};
    std::atomic<uint64_t> cap_reached_{0};
    std::atomic<uint64_t> persist_failed_{0};
    // Defaults FALSE and is set true only on the index-build success path. A
    // store whose migration failed never reaches the build at all, so an
    // initialise-true/clear-on-failure scheme would publish "index healthy" for
    // a database that does not exist -- backwards for the one gauge whose whole
    // job is to say the pass is degraded.
    std::atomic<bool> retention_index_ok_{false};

    // Guard state for cleanup_once(). Plain (non-atomic) members: both are read
    // and written only under the exclusive mtx_ that cleanup_once() holds for
    // the whole pass, and no accessor exposes them.
    //
    // The latch makes a decline fire ONCE per anomaly rather than every pass --
    // a store whose datable rows are all genuinely expired would otherwise never
    // age out anything at all. Deliberately NOT persisted: re-declining once
    // after a restart is the safe direction.
    bool clock_anomaly_latched_{false};
    // Wall-clock reading the previous pass saw. PERSISTED in
    // `audit_retention_meta` and reloaded at construction, because the
    // elapsed-time check is the only half of this guard that still works once a
    // write has landed after the clock moved -- held in memory alone it has no
    // comparison point on the first pass of a process, so a server that BOOTS
    // with an already-wrong clock would never see a step at all.
    //
    // Disengaged means "no comparison point": no pass has run against this
    // database, the row could not be read, or the stored value was rejected by
    // the sanitiser. Deliberately not spelled 0 -- zero is a legitimate reading
    // (a dead CMOS reporting the Unix epoch is the case this guard exists for),
    // and collapsing the two suppresses the check on the pass right after NTP
    // corrects.
    std::optional<std::int64_t> last_pass_now_;
    static constexpr const char* kLastPassNowKey = "last_pass_now";
#ifdef __cpp_lib_jthread
    std::jthread cleanup_thread_;
#else
    std::thread cleanup_thread_;
    std::atomic<bool> stop_requested_{false};
#endif

    void create_tables();
    /// Build `idx_audit_ttl_id` best-effort, OUTSIDE the migration runner. See
    /// the definition for why it must not be a Migration entry.
    void ensure_retention_index();
    /// Read/write one row of `audit_retention_meta`. `load_meta` returns
    /// nullopt for both "absent" and "unreadable" -- see `last_pass_now_` for
    /// why that is not folded into a 0.
    std::optional<std::int64_t> load_meta(const char* key) const;
    bool store_meta(const char* key, std::int64_t value);
    /// The accepted-delete half of a pass. Caller must hold `mtx_` exclusively.
    /// `would_wipe` is the pre-delete outcome test; `out_err` receives a SQLite
    /// message on failure so the caller can log it after releasing the lock.
    std::size_t delete_capped_locked(std::int64_t now, bool would_wipe, std::string& out_err);
#ifdef __cpp_lib_jthread
    void run_cleanup(std::stop_token stop);
#else
    void run_cleanup();
#endif
};

} // namespace yuzu::server
