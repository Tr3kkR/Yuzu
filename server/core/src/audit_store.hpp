#pragma once

#include "sqlite_raii.hpp"

#include <sqlite3.h>

#include <atomic>
#include <expected>
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
// then acts on that in a single statement. These constants bound it.
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
// setting also land past the horizon, so they are excluded too and the wipe test
// becomes EASIER to fire. That covers two real cases: an operator who just cut
// retention from 365d to 30d, and a store whose retention was switched OFF
// entirely (window 0), where every legacy-TTL row sits past a horizon of
// `now + slack`. Over-firing costs one declined pass and then paced deletion;
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

    /// Cumulative count of retention passes that DECLINED to delete. Triggers:
    /// the pass would have aged out every datable row; the gap since the
    /// previous pass exceeded kAuditMinBigStepSec; or the stored clock reading
    /// was not usable -- ahead of the current clock, negative, present but not
    /// an integer, or unreadable. Reducing `audit_retention_days` also declines
    /// a pass by design, since it narrows the survivor horizon. The elapsed-time
    /// trigger cannot distinguish a forward clock jump from an outage that long,
    /// so a non-zero value means "this server's clock moved, OR it was down that
    /// long, OR retention was just reconfigured" -- not the clock alone.
    uint64_t clock_anomaly_skips_count() const noexcept {
        return clock_anomaly_skips_.load(std::memory_order_relaxed);
    }

    /// Cumulative count of retention passes that did NOT do their job. Seven
    /// sites: an unreadable pre-delete probe; a failed delete prepare; a failed
    /// delete step; an unreadable POST-delete backlog probe; a pass refused
    /// because the caller's clock was implausible; a pass against a closed
    /// store; and an exception escaping the pass, caught at the thread
    /// boundary. NOT all of them mean the delete failed -- the post-delete
    /// backlog probe fires AFTER a successful delete, so the pass drained rows
    /// and is merely degraded. Read it as "retention is not fully healthy",
    /// never as "nothing was deleted".
    /// Scraped SEPARATELY from
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

    /// Cumulative retention passes ATTEMPTED, and the wall-clock reading of the
    /// most recent pass WHOSE CLOCK WAS USABLE (0 if none has run in this
    /// process). The two differ deliberately: a pass refused for an implausible
    /// caller clock counts as attempted but does not stamp the reading, since
    /// publishing a value the guard just declared unusable would corrupt the
    /// staleness signal this gauge exists to provide. A stale gauge with a
    /// RISING pass counter therefore means "alive but refusing an unusable
    /// clock" -- a different fault from "stopped".
    ///
    /// These exist because every other COUNTER here is silence-means-healthy: a
    /// cleanup thread that never starts, dies, or is stopped leaves them all
    /// flat at 0 forever, which is indistinguishable from a quiet, healthy
    /// store. An operator alerts on ABSENCE here.
    std::uint64_t retention_passes_count() const noexcept {
        return retention_passes_.load(std::memory_order_relaxed);
    }
    std::int64_t last_pass_unixtime() const noexcept {
        return last_pass_unixtime_.load(std::memory_order_relaxed);
    }

    /// Cumulative failures to persist the retention clock reading. A sustained
    /// non-zero rate means the restart-surviving half of the guard is degraded.
    uint64_t persist_failed_count() const noexcept {
        return persist_failed_.load(std::memory_order_relaxed);
    }

    /// What the guard can conclude about a pass, in precedence order. A pure
    /// function of that pass's inputs -- see `classify`.
    ///
    /// PUBLIC deliberately, alongside `cleanup_once`: `classify` holds the
    /// whole precedence contract and is a pure function of four bools, so it
    /// can be pinned by a table with no database, no clock and no fixture.
    /// Exposing a function that reads no state is strictly less invasive than
    /// the `cleanup_once` seam below, and the alternative -- reaching it only
    /// through seeded multi-pass integration tests -- is how the precedence
    /// went unpinned long enough for two mutations to survive.
    enum class Anomaly { None, Wipe, Step, BadState };
    /// Classify one pass. PURE: no member reads, no side effects, so it can be
    /// reasoned about and tested one condition at a time. Precedence is
    /// BadState > Step > Wipe: a reading we cannot trust makes the other two
    /// unreliable, and an elapsed-time step explains a wipe better than the wipe
    /// explains itself.
    static Anomaly classify(bool has_expired, bool would_wipe, bool big_step,
                            bool prev_unusable) noexcept {
        if (prev_unusable)
            return Anomaly::BadState;
        if (!has_expired)
            return Anomaly::None; // nothing to delete, so nothing to guard
        if (big_step)
            return Anomaly::Step;
        return would_wipe ? Anomaly::Wipe : Anomaly::None;
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
    // Owned by an RAII wrapper, NOT a raw handle: `create_tables()` and
    // `ensure_retention_index()` both run from the CONSTRUCTOR and both format
    // log messages, so a throw there (fmt, `bad_alloc`) escapes the constructor
    // and `~AuditStore` never runs. Member destruction DOES run during that
    // unwind, so holding the connection here is what stops it -- and its WAL/SHM
    // files -- from leaking. Access is `db_.get()`; `db_.close()` is the
    // deliberate early close on a failed migration.
    SqliteDb db_;
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
    // thread reads them without taking mtx_. MOST are incremented inside
    // cleanup_once()'s exclusive lock -- but NOT all: `cleanup_failed_` also
    // increments before the lock (the implausible-clock refusal) and outside it
    // entirely (the thread-boundary catch), and the two liveness values are
    // stamped before the lock is taken.
    std::atomic<uint64_t> clock_anomaly_skips_{0};
    std::atomic<uint64_t> cleanup_failed_{0};
    std::atomic<uint64_t> rows_deleted_{0};
    std::atomic<uint64_t> cap_reached_{0};
    std::atomic<uint64_t> persist_failed_{0};
    // Liveness. Incremented/stamped on EVERY pass including declined and failed
    // ones -- the question these answer is "did the reaper run at all", which is
    // not the same question as "did it delete anything".
    std::atomic<uint64_t> retention_passes_{0};
    std::atomic<std::int64_t> last_pass_unixtime_{0};

    // Guard state for cleanup_once(). Plain (non-atomic) members: both are read
    // and written only under the exclusive mtx_ that cleanup_once() holds for
    // the whole pass, and no accessor exposes them.
    //
    // The anomaly currently being REPORTED, replacing what used to be a shared
    // bool latch. One variable, one rule (in `cleanup_once`): report when the
    // anomaly differs from this, stand down to None when there is none. That
    // makes a repeat of the SAME condition silent -- so a legitimately
    // all-expired store still ages out, costing one interval -- while a
    // DIFFERENT condition arriving mid-anomaly is still reported, which a single
    // bool could not express and silently swallowed.
    //
    // Deliberately NOT persisted: re-reporting once after a restart is the safe
    // direction.
    Anomaly last_reported_{Anomaly::None};
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
    // Set at construction when durable state EXISTED but could not be used --
    // either not an integer, or unreadable (corruption, busy, I/O error).
    // Absent is NOT carried: that is the ordinary fresh-install shape.
    // Cleared at exactly three sites, all of which REPORT it first: the decline
    // branch, the nothing-expired branch (which reports it via
    // Emit::CorruptStateReported), and the accepting path that goes on to
    // delete. It is NOT cleared on a pass that reaches no verdict -- an
    // unreadable probe, or a closed store -- because those say nothing about
    // the state. Clearing without reporting would swallow the corruption signal
    // entirely, which is the failure mode this flag exists to prevent.
    bool loaded_meta_unusable_{false};
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
    /// Why a durable reading could not be used. ABSENT and MALFORMED must stay
    /// DISTINGUISHABLE: absent is the ordinary fresh-install shape and says
    /// nothing about the clock, whereas a row that exists but is not an integer
    /// is corrupted or hand-edited durable state and is an ANOMALY. Folding them
    /// together is what made the advertised "unparseable is an anomaly" property
    /// not actually exist.
    enum class MetaReadError { Absent, Malformed, Unreadable };
    /// Read one row of `audit_retention_meta`. Never returns a coerced value --
    /// see the definition for why `sqlite3_column_int64` alone is unsafe here.
    std::expected<std::int64_t, MetaReadError> load_meta(const char* key) const;
    bool store_meta(const char* key, std::int64_t value);
    /// What one accepted delete did. `backlog_remains` is the POST-delete fact
    /// the latch, the cap counter and the operator log line are ALL derived
    /// from, so they cannot disagree.
    struct DeleteOutcome {
        std::size_t deleted{0};
        bool backlog_remains{false};
        /// Empty when the post-delete backlog probe was read. Non-empty means it
        /// could NOT be, so `backlog_remains` above is an ASSUMPTION
        /// (conservative: true) rather than an observation, and this carries the
        /// reason out for the caller to log after the lock. Carried IN the
        /// outcome rather than through an out-param: conventions forbid those,
        /// and the delete itself still succeeded, so this is not an error return.
        std::string backlog_probe_err;
    };
    /// The accepted-delete half of a pass. Caller must hold `mtx_` exclusively.
    /// On failure returns the SQLite
    /// message so the caller can log it AFTER releasing the lock.
    std::expected<DeleteOutcome, std::string> delete_capped_locked(std::int64_t now);
#ifdef __cpp_lib_jthread
    void run_cleanup(std::stop_token stop);
#else
    void run_cleanup();
#endif
};

} // namespace yuzu::server
