/**
 * tar_usage.cpp -- the SQLite shell for the `usage` derived fold (see
 * tar_usage.hpp for the pure pairing logic and the drain-arithmetic banner).
 *
 * run_usage_fold() is the ONE entry point tar_plugin.cpp's collect_fast_impl
 * calls, once per fast tick, after both process feeders (gap-free stream or
 * snapshot-diff poll) have inserted for that tick. It writes usage_daily,
 * usage_daily_user, usage_live's open-run set, AND the tar_config counters
 * (including usage_hwm_id) in ONE TarDatabase::execute_atomic_batch_gated
 * call -- ONE transaction, ONE COMMIT. usage_daily_user's own RETENTION
 * prune is NOT here -- it runs under tar_aggregator.cpp's clock-guarded
 * run_retention instead (see docs/clock-guarded-retention.md).
 *
 * The data statements (usage_daily/usage_daily_user/usage_live) are the
 * DATA group; the tar_config counters are the GATED group, issued inside
 * that SAME transaction only if every data statement completed with zero
 * flagged failures (Wave 7 PR7.2 adversarial review, Blocker 1):
 * TarDatabase::execute_atomic_batch is documented as deliberately NOT
 * all-or-nothing on a transaction-preserving error -- a batch can commit
 * with one statement flagged `failed[i]` while every OTHER statement in that
 * SAME commit, including a tar_config upsert, is fully durable. Folding the
 * hwm advance in unconditionally would let a broken usage_daily/
 * usage_daily_user write (e.g. a stuck-at-schema-5 migration with no
 * matching unique index for `ON CONFLICT`) get silently skipped while
 * usage_hwm_id still advanced past it, forever.
 *
 * An EARLIER version of this fix expressed that gate as TWO SEPARATE
 * execute_atomic_batch calls -- a data batch, then a confirm batch issued
 * only after checking the first one's result. That closed the original
 * Blocker 1 gap but opened a worse one (Wave 7 PR7.2 governance re-review,
 * fix-of-a-fix): the data batch's own COMMIT is a fully durable transaction
 * on its own, so a genuine process crash between the two CALLS durably
 * applied the data while usage_hwm_id stayed behind -- and the next tick's
 * retry re-read the same un-advanced hwm, re-derived the SAME closed-run
 * deltas, and re-applied them on top of already-durable data via the
 * additive `run_count = run_count + excluded.run_count` upserts, silently
 * double-counting `usage_daily`/`usage_daily_user`. This was NOT the
 * "bounded overcount" the two-call version's own commentary claimed for its
 * documented residual (an unrelated failure of the SEPARATE confirm call);
 * it was the double-count Blocker 1 was written to prevent, just relocated
 * to a new commit boundary that hadn't existed before.
 *
 * execute_atomic_batch_gated (tar_db.hpp/.cpp) removes that boundary instead
 * of shrinking it: the gate decision (did every data statement complete
 * clean?) is made in C++, inside the SAME held transaction, BEFORE the
 * single COMMIT -- so a crash can only land before that COMMIT (nothing
 * durable at all; SQLite's WAL recovery rolls the whole thing back on
 * restart) or after it (data and hwm/counters durable together, always).
 * A residual was accepted here in an earlier round and then found NOT to be
 * bounded (Wave 7 PR7.2a, governance round 5, Blocker 3): a genuine
 * transaction-preserving SQL fault on a tar_config upsert itself (not a
 * crash, and not the data statements) used to still let the data commit
 * while that specific counter was skipped, on the reasoning that this was
 * "bounded to the crash's own window" like the two-call gap above. It is
 * not -- a PERSISTENT (not one-shot) fault on the same gated statement
 * re-fires on every subsequent tick, and each tick's data still commits, so
 * the same un-advanced hwm makes every following tick re-derive and
 * re-apply the SAME closed-run deltas on top of already-durable data:
 * unbounded double-counting, for as long as the fault persists.
 * `execute_atomic_batch_gated` (tar_db.cpp) now forces the WHOLE
 * transaction to roll back on any gated-statement fault, so "committed" for
 * this call always means "data and hwm/counters durable together" or
 * "neither is" -- never split -- and the below check via `batch.committed`
 * catches this case directly (`batch.ran_gated`/gated `failed` entries are
 * now a defensive invariant check only; see the comment at that check).
 *
 * GAP CHECK FIRST, before any events are read: process_live is retained by
 * ROW COUNT (kRowCount, 100k rows, tar_schema_registry.cpp), and its prune
 * (tar_aggregator.cpp run_retention) deletes the LOWEST ids, up to 5000 per
 * rollup pass. If this fold's persisted `usage_hwm_id` is now BELOW the
 * table's current MIN(id) - 1, the rows in between were destroyed before the
 * fold ever read them -- a genuine capture gap, not a caught-up state. That
 * is counted (`usage_gap_count`, `usage_gap_lost_events`,
 * `usage_gap_last_ts`) and the hwm is re-baselined to `min_id - 1` in the
 * SAME transaction as everything else this tick produces, so the gap is
 * never a silent skip: any open run whose "stopped" fell inside the lost
 * range simply never gets one and drains through expire_open_runs on a
 * later tick, counted as `expired` there.
 *
 * tar_config keys this file owns (P22/P24 read them, never write them):
 *   usage_hwm_id            -- high-water mark over process_live.id
 *   usage_unmatched_stops   -- cumulative, += per fold
 *   usage_clock_anomalies   -- cumulative, += per fold
 *   usage_lag_events        -- max_id - new hwm, snapshot as of last fold
 *   usage_last_fold_ts      -- epoch seconds of the last fold attempt (any outcome)
 *   usage_gap_count         -- cumulative count of gap events detected
 *   usage_gap_lost_events   -- cumulative count of events lost to gaps
 *   usage_gap_last_ts       -- epoch seconds of the most recent gap
 *   usage_feeder_enabled    -- "true"/"false", gating snapshot for P22's report
 *   usage_coverage_since    -- epoch seconds the fold has counted from (re-baseline)
 *   usage_schema_stalled    -- "true"/"false", whether schema_version is stuck below
 *                              kUsageDailySchemaVersion (v7's usage_daily.fold_hwm
 *                              migration never completed) -- see the gate near the
 *                              top of run_usage_fold()
 */

#include "tar_usage.hpp"

#include "tar_aggregator.hpp"       // source_enabled

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <format>
#include <map>
#include <set>
#include <utility>

namespace yuzu::tar::usage {

namespace {

// Doubles embedded single quotes -- the only escape SQLite string literals
// need. Every dynamic string value (exe_key, user) that reaches a hand-built
// SQL statement in this file goes through this; there is no bound-parameter
// path on TarDatabase::execute_atomic_batch (it takes finished SQL text).
std::string sql_str(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('\'');
    for (char c : s) {
        if (c == '\'')
            out.push_back('\'');
        out.push_back(c);
    }
    out.push_back('\'');
    return out;
}

// The schema_version (tar_db.cpp) at which usage_daily gained its fold_hwm
// column -- the ALTER TABLE that column's v7 migration performs. Below this
// version, every statement in this file that references fold_hwm (both
// build_daily_upsert() forms) is rejected by SQLite at prepare time.
constexpr int kUsageDailySchemaVersion = 7;

int64_t parse_i64(std::string_view s, int64_t def = 0) {
    if (s.empty())
        return def;
    int64_t v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p != s.data() + s.size())
        return def;
    return v;
}

// One usage_daily upsert statement for `d`, either the plain additive form
// (`guarded=false`, used for a carried-over-only key) or the fold_hwm-gated
// form (`guarded=true`, used for a same-tick-only OR a provenance-mixed key
// -- see the merge step ahead of run_usage_fold's `stmts` build for why a
// mixed key must ALWAYS take this branch and never the plain one). Factored
// to a single site so the two shapes cannot drift apart from each other, the
// way the previous two-copy-pasted-loop version already had (identical
// column list, identical DO UPDATE SET body, differing only in the trailing
// fold_hwm clause).
std::string build_daily_upsert(const DailyDelta& d, int64_t new_hwm, bool guarded) {
    std::string sql = std::format(
        "INSERT INTO usage_daily (day_ts, exe_key, run_count, total_seconds, first_seen, "
        "last_seen, distinct_users, superseded_runs, expired_runs, fold_hwm) VALUES ({}, {}, "
        "{}, {}, {}, {}, 0, {}, {}, {}) ON CONFLICT(day_ts, exe_key) DO UPDATE SET "
        "run_count = run_count + excluded.run_count, "
        "total_seconds = total_seconds + excluded.total_seconds, "
        "first_seen = MIN(first_seen, excluded.first_seen), "
        "last_seen = MAX(last_seen, excluded.last_seen), "
        "superseded_runs = superseded_runs + excluded.superseded_runs, "
        "expired_runs = expired_runs + excluded.expired_runs",
        d.day_ts, sql_str(d.exe_key), d.run_count, d.total_seconds, d.first_seen, d.last_seen,
        d.superseded_runs, d.expired_runs, new_hwm);
    if (guarded)
        sql += ", fold_hwm = excluded.fold_hwm WHERE fold_hwm < excluded.fold_hwm";
    return sql;
}

// Combines two DailyDelta values for the SAME (day_ts, exe_key) key into one
// -- used only when a key is touched by both the carried-over and same-tick
// provenance groups within a single tick (see the merge step below).
DailyDelta merge_daily_delta(const DailyDelta& a, const DailyDelta& b) {
    DailyDelta out = a;
    out.run_count += b.run_count;
    out.total_seconds += b.total_seconds;
    out.first_seen = std::min(out.first_seen, b.first_seen);
    out.last_seen = std::max(out.last_seen, b.last_seen);
    out.superseded_runs += b.superseded_runs;
    out.expired_runs += b.expired_runs;
    return out;
}

} // namespace

std::expected<void, std::string> usage_rebaseline(TarDatabase& db, int64_t now) {
    auto max_id_res = db.execute_query("SELECT COALESCE(MAX(id), 0) FROM process_live", 1);
    if (!max_id_res.has_value()) {
        // BLOCKER 3 fix: a failed probe must not proceed to persist hwm=0
        // alongside a fresh coverage marker -- that combination is exactly
        // what disarms the retry path (it gates on the marker's ABSENCE).
        // Nothing is written; the caller retries with coverage still absent.
        spdlog::error("TAR usage_rebaseline: MAX(id) probe failed ({}) -- hwm/coverage_since NOT "
                      "written, open runs NOT cleared; will retry",
                      max_id_res.error());
        return std::unexpected(max_id_res.error());
    }
    int64_t hwm = 0;
    if (!max_id_res->rows.empty() && !max_id_res->rows[0].empty())
        hwm = parse_i64(max_id_res->rows[0][0]);

    const auto batch = db.execute_atomic_batch({
        "DELETE FROM usage_live",
        std::format("INSERT INTO tar_config (key, value) VALUES ('usage_hwm_id', '{}') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    hwm),
        std::format("INSERT INTO tar_config (key, value) VALUES ('usage_coverage_since', '{}') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    now),
    });
    if (!batch.committed) {
        spdlog::error("TAR usage_rebaseline: transaction failed to commit -- hwm/coverage_since "
                      "unchanged, open runs NOT cleared; will retry on the next enable edge or "
                      "plugin restart");
        return std::unexpected("rebaseline transaction failed to commit");
    }
    return {};
}

UsageFoldResult run_usage_fold(TarDatabase& db, int64_t now, int64_t max_events_per_tick) {
    UsageFoldResult result;

    const bool usage_on = source_enabled(db, "usage");
    const bool process_on = source_enabled(db, "process");
    db.set_config("usage_feeder_enabled", (usage_on && process_on) ? "true" : "false");
    if (!usage_on || !process_on) {
        result.ok = true; // nothing to do this tick -- not a failure
        return result;
    }

    // v7 schema-migration stall gate (round-3 fix). usage_daily/
    // usage_daily_user's fold_hwm column -- the replay guard the upsert
    // statements below depend on -- exists only once TarDatabase::open's v7
    // migration (tar_db.cpp, the ALTER TABLE ... ADD COLUMN fold_hwm step)
    // has actually run. That migration can fail (disk full, I/O error) and
    // leaves schema_version pinned at v6 until an operator manually applies
    // it -- logged as an ERROR at open time, but with nothing to stop this
    // function from running unconditionally every tick afterwards. Without
    // this gate: every usage_daily/usage_daily_user statement below
    // references a nonexistent column and is rejected by SQLite at PREPARE
    // time -- a per-statement, transaction-preserving fault under
    // TarDatabase::execute_atomic_batch_gated's continue-on-error contract
    // -- while the UNRELATED usage_live DELETE/INSERT statements in the SAME
    // batch still succeed and commit. Net effect: usage_daily permanently
    // and silently stops accumulating while usage_live/hwm bookkeeping
    // keeps churning as if nothing were wrong, with only a one-time log line
    // from the failed migration itself as a trace. Failing the WHOLE tick
    // HERE instead -- before usage_live is touched either -- keeps the
    // existing ok=false path (tar_plugin.cpp's rate-limited warn, retried
    // every tick until the migration completes) as the loud signal, and
    // `usage_schema_stalled` makes the SAME condition visible on the `tar
    // status` action (P22/P24-readable) alongside every other usage_* key,
    // not only in a log an unattended endpoint's operator may never open.
    if (db.schema_version() < kUsageDailySchemaVersion) {
        db.set_config("usage_schema_stalled", "true");
        result.error = std::format(
            "usage fold: schema stuck at v{} (usage_daily.fold_hwm needs v{}) -- refusing to "
            "run until the pending ALTER TABLE migration completes; see TarDatabase::open's v7 "
            "migration failure log for the manual recovery statement",
            db.schema_version(), kUsageDailySchemaVersion);
        return result; // ok=false, nothing touched this tick
    }
    db.set_config("usage_schema_stalled", "false");

    // Forward-only boundary gate (Wave 7 PR7.2 adversarial review, Blocker
    // 3): the fold must never consume a process_live row before a
    // successful baseline transaction has established coverage. The
    // previous shape gated only on the two enable flags above, so a
    // transient failure in tar_plugin.cpp's boot-time try_get_config/
    // rebaseline call -- or a rebaseline whose own MAX(id) probe or commit
    // failed -- left usage_coverage_since absent with nothing to notice: the
    // NEXT healthy tick would fold straight from hwm=0, replaying the whole
    // pre-consent process_live history for this default-on,
    // works-council-class source. Checking (and, if needed, retrying) the
    // baseline HERE, before a single event is read, closes that: a missing
    // marker is retried on every tick rather than only once at boot.
    auto coverage = db.try_get_config("usage_coverage_since");
    if (!coverage.has_value() || !coverage->has_value()) {
        if (auto rb = usage_rebaseline(db, now); !rb.has_value()) {
            result.error = std::format(
                "usage fold: coverage baseline not established ({}); refusing to consume "
                "process_live until a rebaseline succeeds",
                !coverage.has_value() ? coverage.error() : rb.error());
            return result; // ok=false, hwm unchanged, nothing consumed this tick
        }
        // Baseline just succeeded: usage_coverage_since = now, hwm =
        // MAX(id) as of this instant. Report success but fold no events
        // this tick -- the very next tick reads forward from this
        // baseline, exactly as a boot-time rebaseline would have.
        result.ok = true;
        result.hwm_id = parse_i64(db.get_config("usage_hwm_id", "0"));
        return result;
    }

    int64_t hwm = parse_i64(db.get_config("usage_hwm_id", "0"));
    result.hwm_id = hwm;

    // ── Gap check + event read, in ONE statement ────────────────────────────
    // These used to be two separate execute_query() calls. TarDatabase::mu_ is
    // released between statement-scoped calls, so a concurrent retention pass
    // (do_rollup -> run_retention, tar_aggregator.cpp) pruning process_live's
    // lowest ids by row-count could land in the window between them: the range
    // query sees no gap (MIN(id) still <= hwm+1), the prune then deletes ids up
    // to and past that range, and the event query -- now running against the
    // post-prune table -- silently skips straight to whatever ids survived,
    // advancing usage_hwm_id past the lost range with usage_gap_count never
    // incremented. Folding both reads into one SQL statement (one execute_query
    // call, one continuous hold of mu_) means no prune can execute between the
    // range read and the event read -- they observe the SAME snapshot. The
    // aggregate range (over the WHOLE table) is computed in a one-row derived
    // table `r`, LEFT JOINed against the hwm-filtered event rows `e` so `r`'s
    // columns are still present even when zero events match (an empty `e`
    // would otherwise make the outer query return zero rows and lose the range
    // entirely).
    auto combined_res = db.execute_query(
        std::format(
            "SELECT r.min_id, r.max_id, r.row_count, e.id, e.ts, e.action, e.pid, e.name, e.user "
            "FROM (SELECT COALESCE(MIN(id), 0) AS min_id, COALESCE(MAX(id), 0) AS max_id, "
            "COUNT(*) AS row_count FROM process_live) r "
            "LEFT JOIN (SELECT id, ts, action, pid, name, user FROM process_live "
            "WHERE id > {} ORDER BY id LIMIT {}) e ON 1=1 "
            "ORDER BY e.id",
            hwm, max_events_per_tick),
        static_cast<int>(max_events_per_tick) + 2);
    if (!combined_res.has_value() || combined_res->rows.empty()) {
        result.error = combined_res.has_value() ? "process_live range/event query returned no row"
                                                 : combined_res.error();
        return result; // ok=false, hwm unchanged -- nothing written, retried next tick
    }
    const int64_t min_id = parse_i64(combined_res->rows[0][0]);
    const int64_t max_id = parse_i64(combined_res->rows[0][1]);
    const int64_t row_count = parse_i64(combined_res->rows[0][2]);

    int64_t effective_hwm = hwm;
    int64_t gap_lost = 0;
    if (row_count > 0 && hwm > 0 && min_id > hwm + 1) {
        result.gap_detected = true;
        gap_lost = min_id - hwm - 1;
        effective_hwm = min_id - 1;
    }

    // ── Load the open-run table (usage_live) ────────────────────────────────
    FoldState state;
    auto open_res =
        db.execute_query("SELECT pid, exe_key, user, start_ts FROM usage_live WHERE action='open'",
                         1'000'000);
    if (!open_res.has_value()) {
        result.error = open_res.error();
        return result; // ok=false, hwm unchanged
    }
    // Snapshot of what was DURABLY open before this tick's own events are
    // folded in -- the replay-safety split below (building `deltas_guarded`)
    // needs to tell "this closed run was already persisted in usage_live
    // before this tick" from "this run's whole open+close lifecycle happened
    // within this tick's own event window", and this is the only point where
    // that distinction is still visible (state.open is mutated below).
    std::set<std::pair<uint32_t, std::string>> initial_open_keys;
    for (const auto& row : open_res->rows) {
        OpenRun run;
        run.pid = static_cast<uint32_t>(parse_i64(row[0]));
        run.exe_key = row[1];
        run.user = row[2];
        run.start_ts = parse_i64(row[3]);
        initial_open_keys.insert({run.pid, run.exe_key});
        state.open[{run.pid, run.exe_key}] = run;
    }

    // ── Fold in the events already read above ───────────────────────────────
    // A row's `e.id` column (index 3) is empty when the LEFT JOIN found no
    // matching event (the placeholder row carrying only the range columns) --
    // never mistake it for a real process_live row with id 0 (ids are an
    // AUTOINCREMENT primary key, never 0).
    std::vector<ProcessEvent> events;
    int64_t new_hwm = effective_hwm;
    for (const auto& row : combined_res->rows) {
        if (row[3].empty())
            continue;
        const int64_t id = parse_i64(row[3]);
        ProcessEvent pe;
        pe.ts = parse_i64(row[4]);
        pe.action = row[5];
        pe.pid = static_cast<uint32_t>(parse_i64(row[6]));
        pe.name = row[7];
        pe.user = row[8];
        events.push_back(std::move(pe));
        new_hwm = std::max(new_hwm, id);
    }
    result.events_seen = static_cast<int64_t>(events.size());
    result.lag_events = max_id - new_hwm;

    // ── Fold: pairing, expiry, cap ───────────────────────────────────────────
    std::vector<ClosedRun> closed;
    std::set<std::pair<uint32_t, std::string>> opened_this_tick;
    for (const auto& ev : events) {
        if (ev.action == "started")
            opened_this_tick.insert({ev.pid, normalise_exe_key(ev.name)});
        if (auto c = apply_event(state, ev))
            closed.push_back(std::move(*c));
    }
    for (auto& c : expire_open_runs(state, now))
        closed.push_back(std::move(c));
    for (auto& c : cap_open_runs(state))
        closed.push_back(std::move(c));
    result.runs_closed = static_cast<int64_t>(closed.size());

    // Split by provenance BEFORE aggregating -- the two groups need different
    // upsert shapes below (see the comment ahead of the `deltas_guarded`
    // loop). A closed run is "carried_over" iff its (pid, exe_key) was
    // ALREADY durably open in usage_live before this tick touched anything:
    // closing it (via a stop event, expiry, or the cap) is part of the SAME
    // data commit that removes/rewrites its usage_live row, so a replay of
    // this tick (hwm unmoved, same window) reloads `state.open` from
    // usage_live and finds that row already gone/changed -- it structurally
    // CANNOT re-derive the identical closure a second time. It is
    // "same_tick" otherwise: the run's entire open-then-close lifecycle
    // happened inside THIS tick's own event window, so usage_live never
    // carried a durable trace of it at all, and replaying the SAME events
    // (hwm unmoved) reproduces the identical closure with no signal to stop
    // it.
    std::vector<ClosedRun> closed_carried_over, closed_same_tick;
    for (auto& c : closed) {
        if (initial_open_keys.contains({c.pid, c.exe_key}))
            closed_carried_over.push_back(c);
        else
            closed_same_tick.push_back(c);
    }
    const auto deltas_unguarded = fold_daily(closed_carried_over);
    const auto deltas_guarded = fold_daily(closed_same_tick);

    // Merge any (day_ts, exe_key) key touched by BOTH provenance groups this
    // tick into ONE combined delta, emitted as a single guarded statement --
    // see the big comment below for why a split-into-two-statements shape is
    // unsound for a mixed key, and why "always route a mixed key through the
    // guarded form" is correct in general, not just for one reported repro.
    //
    // VERIFIED BUG (round 3 adversarial re-verification of round 2): the
    // carried-over group's upsert never touches `fold_hwm` on ITS OWN
    // ON CONFLICT branch, but on a FRESH row (no existing usage_daily row for
    // this key before the tick) its plain INSERT ... VALUES still SETS
    // fold_hwm = new_hwm as part of the VALUES clause -- there is no way to
    // omit a NOT NULL column from an INSERT. If a same-tick closure for the
    // SAME key lands in this SAME tick and the carried-over statement runs
    // first, the guarded statement's `WHERE fold_hwm < excluded.fold_hwm`
    // then compares new_hwm against the new_hwm the sibling statement JUST
    // stamped moments earlier in the same transaction -- equal, not less
    // than -- so the guard fires and the same-tick contribution is silently
    // dropped. Reordering the two statement groups only relocates the
    // collision (a later same-tick key could still race an earlier
    // carried-over key writing the identical row, or vice versa, depending
    // on which key set happens to iterate first); the actual invariant this
    // must satisfy is that a (day_ts, exe_key) row NEVER receives more than
    // one upsert statement per tick, since fold_hwm is a per-ROW replay
    // marker, not a per-STATEMENT one. Merging at the key level enforces
    // that unconditionally, and stays sound under a later replay: a
    // carried-over closure is only ever derivable ONCE, because closing it
    // durably mutates usage_live in the SAME commit that would need to
    // produce it again -- so a replay of a tick whose data already committed
    // can only ever re-derive the same-tick HALF of a merged delta, never
    // the carried-over half a second time. Routing the merged row through
    // the guarded form therefore protects exactly the part that can recur,
    // and the part that cannot recur is correctly represented as part of the
    // row's already-durable base value once the first attempt lands.
    std::map<std::pair<int64_t, std::string>, DailyDelta> guarded_by_key;
    for (const auto& d : deltas_guarded)
        guarded_by_key.emplace(std::make_pair(d.day_ts, d.exe_key), d);

    std::vector<DailyDelta> final_unguarded;
    std::vector<DailyDelta> final_guarded;
    for (const auto& d : deltas_unguarded) {
        auto it = guarded_by_key.find({d.day_ts, d.exe_key});
        if (it == guarded_by_key.end()) {
            final_unguarded.push_back(d);
        } else {
            final_guarded.push_back(merge_daily_delta(d, it->second));
            guarded_by_key.erase(it); // consumed -- do not also emit it below
        }
    }
    for (const auto& [key, d] : guarded_by_key)
        final_guarded.push_back(d);

    // ── Build the DATA transaction ──────────────────────────────────────────
    std::vector<std::string> stmts;

    // Carried-over-only contributions: already replay-safe (see the split
    // above -- closing a carried-over run mutates usage_live in the same
    // commit, so a replay can never re-derive it), so this is the plain
    // additive upsert with no fold_hwm guard.
    for (const auto& d : final_unguarded)
        stmts.push_back(build_daily_upsert(d, new_hwm, /*guarded=*/false));

    // Same-tick-only AND provenance-mixed contributions: `fold_hwm`
    // (tar_db.cpp v7 migration) is this PASS's target new_hwm, stamped on
    // every row this loop touches, and is what makes a same-tick
    // contribution idempotent under an exact-window replay: `WHERE fold_hwm
    // < excluded.fold_hwm` makes the whole ON CONFLICT DO UPDATE a no-op
    // once the row already reflects this pass's contribution (fold_hwm
    // already >= new_hwm) instead of adding a second time. That is exactly
    // the shape a genuine crash (or a gated tar_config statement failure)
    // between this data commit and the usage_hwm_id advance produces:
    // usage_hwm_id stays at the OLD value, so the next tick re-reads the
    // SAME process_live range and re-derives the SAME same-tick closures for
    // the SAME new_hwm -- the guard recognises that as "already applied"
    // rather than adding on top. `new_hwm` is a sound replay key for this
    // group (mixed or not) because a same-tick closure requires reading at
    // least one genuinely new event (the "started" that created it), so
    // new_hwm strictly advances whenever a NEW (non-replay) same-tick
    // closure occurs -- unlike a carried-over-only key, where new_hwm can
    // legitimately stay flat across multiple distinct ticks (no new process
    // activity, yet different long-open runs individually crossing max_age)
    // and would otherwise collide and wrongly no-op a second, genuinely new
    // contribution; that is why a carried-over-only key must NOT take this
    // branch. This does not, by itself, make a replay whose event WINDOW has
    // since grown (new process_live rows arrived between the crash and the
    // retry, past what this pass's `new_hwm` covered) safe for the
    // OVERLAPPING portion, nor a same-key open-close-reopen-within-one-tick
    // pid reuse racing the crash window -- both residuals are bounded to the
    // width of events arriving in the crash's own brief window and are far
    // narrower than the unbounded-cumulative defect this closes; see the
    // file banner.
    for (const auto& d : final_guarded)
        stmts.push_back(build_daily_upsert(d, new_hwm, /*guarded=*/true));

    std::set<std::pair<int64_t, std::string>> touched_days; // (day_ts, exe_key)
    for (const auto& c : closed) {
        // Same bucketing rule as fold_daily() -- day_ts_for() (review M2:
        // keep usage_daily_user on the same day as usage_daily; adversarial
        // review, Wave 7 PR7.2: the previous hand-inlined copy of this
        // formula negated start_ts directly, overflowing UB on INT64_MIN).
        const int64_t day_ts = day_ts_for(c.start_ts);
        stmts.push_back(std::format(
            "INSERT OR IGNORE INTO usage_daily_user (day_ts, exe_key, user) VALUES ({}, {}, {})",
            day_ts, sql_str(c.exe_key), sql_str(c.user)));
        touched_days.insert({day_ts, c.exe_key});
    }
    for (const auto& [day_ts, exe_key] : touched_days) {
        stmts.push_back(std::format(
            "UPDATE usage_daily SET distinct_users = (SELECT COUNT(DISTINCT user) FROM "
            "usage_daily_user WHERE day_ts = {0} AND exe_key = {1}) WHERE day_ts = {0} AND "
            "exe_key = {1}",
            day_ts, sql_str(exe_key)));
    }

    // usage_live: remove every key this tick touched at all, then re-insert
    // only the ones still open at the end (see tar_usage.hpp banner / this
    // function's design: a key can be touched via a close, a fresh open, or
    // both in the same tick -- DELETE-then-selectively-INSERT handles every
    // case without a UNIQUE-index conflict).
    std::set<std::pair<uint32_t, std::string>> touched_keys = opened_this_tick;
    for (const auto& c : closed)
        touched_keys.insert({c.pid, c.exe_key});
    if (!touched_keys.empty()) {
        std::string in_list;
        for (const auto& [pid, exe_key] : touched_keys) {
            if (!in_list.empty())
                in_list += ",";
            in_list += std::format("({},{})", pid, sql_str(exe_key));
        }
        stmts.push_back(
            std::format("DELETE FROM usage_live WHERE (pid, exe_key) IN (VALUES {})", in_list));
        for (const auto& key : touched_keys) {
            auto it = state.open.find(key);
            if (it == state.open.end())
                continue; // touched but not open at the end -- delete only
            const auto& run = it->second;
            stmts.push_back(std::format(
                "INSERT INTO usage_live (ts, snapshot_id, action, pid, exe_key, user, start_ts) "
                "VALUES ({}, 0, 'open', {}, {}, {}, {})",
                run.start_ts, run.pid, sql_str(run.exe_key), sql_str(run.user), run.start_ts));
        }
    }

    // NOTE: usage_daily_user's own retention prune is NOT queued here -- it
    // runs under tar_aggregator.cpp's clock-guarded run_retention (see
    // docs/clock-guarded-retention.md's usage_daily_user register entry).
    // This fold only ever WRITES usage_daily_user, never prunes it.

    // ── tar_config counters (GATED on the data statements above) ────────────
    // usage_hwm_id is among these, so the durable pointer can only move once
    // the data it describes is durable too -- see execute_atomic_batch_gated
    // in tar_db.hpp for the two-call crash window this closes (Wave 7 PR7.2
    // governance re-review, fix-of-a-fix) and the file banner above for the
    // original Blocker 1 this still preserves the fix for.
    std::vector<std::string> config_stmts;
    auto upsert_config = [&](std::string_view key, std::string_view value) {
        config_stmts.push_back(std::format(
            "INSERT INTO tar_config (key, value) VALUES ({}, {}) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            sql_str(key), sql_str(value)));
    };
    upsert_config("usage_hwm_id", std::to_string(new_hwm));
    upsert_config("usage_lag_events", std::to_string(result.lag_events));
    upsert_config("usage_last_fold_ts", std::to_string(now));
    if (state.unmatched_stops > 0) {
        const int64_t prior = parse_i64(db.get_config("usage_unmatched_stops", "0"));
        upsert_config("usage_unmatched_stops", std::to_string(prior + state.unmatched_stops));
    }
    if (state.clock_anomalies > 0) {
        const int64_t prior = parse_i64(db.get_config("usage_clock_anomalies", "0"));
        upsert_config("usage_clock_anomalies", std::to_string(prior + state.clock_anomalies));
    }
    if (result.gap_detected) {
        const int64_t prior_count = parse_i64(db.get_config("usage_gap_count", "0"));
        const int64_t prior_lost = parse_i64(db.get_config("usage_gap_lost_events", "0"));
        upsert_config("usage_gap_count", std::to_string(prior_count + 1));
        upsert_config("usage_gap_lost_events", std::to_string(prior_lost + gap_lost));
        upsert_config("usage_gap_last_ts", std::to_string(now));
    }

    // ONE execute_atomic_batch_gated call, ONE COMMIT: `config_stmts` (hwm +
    // counters) is issued inside the SAME transaction as `stmts` (the data),
    // and ONLY if every entry of `stmts` completed with no per-statement
    // failure. That single commit point is what makes "the pointer only
    // advances once the data it describes is durable" true with NO interval
    // in which the data is committed but the pointer decision has not yet
    // been made -- a genuine process crash can only land before this one
    // COMMIT (nothing durable at all; SQLite's own WAL recovery rolls the
    // whole thing back) or after it (data AND hwm/counters durable
    // together). The former two-call shape (a data batch, then a SEPARATE
    // confirm batch) left exactly that window open: the data batch's own
    // COMMIT was a fully durable transaction on its own, so a crash between
    // the two calls durably applied the data while usage_hwm_id stayed
    // behind, and the next tick's retry re-derived and re-applied the SAME
    // deltas on top -- a silent, cumulative double-count of run_count/
    // total_seconds, not the "bounded overcount" the two-call split's own
    // commentary claimed (Wave 7 PR7.2 governance re-review).
    const auto batch = db.execute_atomic_batch_gated(stmts, config_stmts);
    const bool data_failed =
        std::any_of(batch.failed.begin(), batch.failed.begin() + static_cast<std::ptrdiff_t>(stmts.size()),
                    [](char f) { return f != 0; });
    if (!batch.committed || data_failed) {
        // BLOCKER 1 fix, unchanged: a transaction-preserving statement error
        // still leaves every OTHER statement in the batch durable
        // (TarDatabase::BatchResult's contract), so bailing here -- before
        // the gated counters are even attempted -- is what makes "no
        // partial advance" true rather than merely claimed.
        //
        // Governance round 5 (Blocker 3): `execute_atomic_batch_gated` now
        // forces the WHOLE transaction to roll back on ANY gated-statement
        // fault, including a persistent (non-crash) transaction-preserving
        // one on a single tar_config upsert -- see that method's own comment
        // in tar_db.cpp for why a partial "data committed, counter skipped"
        // outcome let a persistent fault re-fold and re-apply the same
        // closed-run deltas every tick, unboundedly. So `!batch.committed`
        // now also covers that case (`data_failed` stays false there --
        // `stmts` itself ran clean), and this branch is the ONE place both
        // land: hwm/counters are guaranteed unchanged, so the same events are
        // safely re-derived and re-applied next tick with no double-count.
        result.ok = false;
        result.error = !batch.committed
                          ? "usage fold transaction rolled back (data statement or gated "
                            "counter write failed); hwm/counters not advanced"
                          : "usage fold data transaction partially failed -- a statement was "
                            "skipped; hwm/counters not advanced";
        result.hwm_id = hwm; // unchanged -- report what is actually persisted
        return result;
    }

    // Defensive only: with the tar_db.cpp fix above, a clean `data_clean`
    // pass (reached this line, so `batch.committed == true`) can no longer
    // leave a gated statement flagged failed -- ANY gated fault now forces
    // the whole transaction to roll back, which the branch above already
    // catches via `!batch.committed`. Kept as a hard invariant check rather
    // than deleted: it costs nothing, and if `execute_atomic_batch_gated`'s
    // contract ever regresses (or a future caller misuses it), this fails
    // the tick instead of silently trusting an un-advanced pointer as if it
    // had moved.
    const bool gated_failed =
        !config_stmts.empty() &&
        (!batch.ran_gated ||
         std::any_of(batch.failed.begin() + static_cast<std::ptrdiff_t>(stmts.size()),
                     batch.failed.end(), [](char f) { return f != 0; }));
    if (gated_failed) {
        result.ok = false;
        result.error = "usage fold: gated counter write reported failed despite a committed "
                      "transaction -- execute_atomic_batch_gated invariant violation; hwm not "
                      "advanced";
        result.hwm_id = hwm; // unchanged
        return result;
    }

    result.ok = true;
    result.hwm_id = new_hwm;
    return result;
}

} // namespace yuzu::tar::usage
