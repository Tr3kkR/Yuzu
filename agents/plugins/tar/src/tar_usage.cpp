/**
 * tar_usage.cpp -- the SQLite shell for the `usage` derived fold (see
 * tar_usage.hpp for the pure pairing logic and the drain-arithmetic banner).
 *
 * run_usage_fold() is the ONE entry point tar_plugin.cpp's collect_fast_impl
 * calls, once per fast tick, after both process feeders (gap-free stream or
 * snapshot-diff poll) have inserted for that tick. It writes usage_daily,
 * usage_daily_user, and usage_live's open-run set in ONE execute_atomic_batch
 * transaction (the DATA batch); usage_daily_user's own RETENTION prune is
 * NOT here -- it runs under tar_aggregator.cpp's clock-guarded run_retention
 * instead (see docs/clock-guarded-retention.md). tar_config counters
 * (including usage_hwm_id) are then written in a SEPARATE, SECOND
 * execute_atomic_batch, issued ONLY when the data batch committed with ZERO
 * flagged statement failures (Wave 7 PR7.2 adversarial review, Blocker 1):
 * TarDatabase::execute_atomic_batch is documented as deliberately NOT
 * all-or-nothing on a transaction-preserving error -- a batch can commit
 * with one statement flagged `failed[i]` while every OTHER statement in that
 * SAME commit, including a tar_config upsert, is fully durable. Folding the
 * hwm advance into the data batch therefore let a broken usage_daily/
 * usage_daily_user write (e.g. a stuck-at-schema-5 migration with no
 * matching unique index for `ON CONFLICT`) get silently skipped while
 * usage_hwm_id still advanced past it, forever. Splitting the transaction
 * closes that: the durable pointer can only move once the data it is
 * supposed to describe is confirmed intact. The residual trade-off (data
 * batch commits, then the SEPARATE counter batch itself fails for an
 * unrelated reason) reprocesses the same already-folded events on the next
 * tick -- a bounded overcount, not the silent permanent loss this replaces.
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
 */

#include "tar_usage.hpp"

#include "tar_aggregator.hpp"       // source_enabled

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <format>
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

int64_t parse_i64(std::string_view s, int64_t def = 0) {
    if (s.empty())
        return def;
    int64_t v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p != s.data() + s.size())
        return def;
    return v;
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
    for (const auto& row : open_res->rows) {
        OpenRun run;
        run.pid = static_cast<uint32_t>(parse_i64(row[0]));
        run.exe_key = row[1];
        run.user = row[2];
        run.start_ts = parse_i64(row[3]);
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

    const auto deltas = fold_daily(closed);

    // ── Build the DATA transaction ──────────────────────────────────────────
    std::vector<std::string> stmts;

    for (const auto& d : deltas) {
        stmts.push_back(std::format(
            "INSERT INTO usage_daily (day_ts, exe_key, run_count, total_seconds, first_seen, "
            "last_seen, distinct_users, superseded_runs, expired_runs) VALUES ({}, {}, {}, {}, "
            "{}, {}, 0, {}, {}) ON CONFLICT(day_ts, exe_key) DO UPDATE SET "
            "run_count = run_count + excluded.run_count, "
            "total_seconds = total_seconds + excluded.total_seconds, "
            "first_seen = MIN(first_seen, excluded.first_seen), "
            "last_seen = MAX(last_seen, excluded.last_seen), "
            "superseded_runs = superseded_runs + excluded.superseded_runs, "
            "expired_runs = expired_runs + excluded.expired_runs",
            d.day_ts, sql_str(d.exe_key), d.run_count, d.total_seconds, d.first_seen, d.last_seen,
            d.superseded_runs, d.expired_runs));
    }

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

    // A quiet tick (no events, no expiries, no cap evictions) legitimately
    // produces an EMPTY data batch -- execute_atomic_batch's own
    // "statements.empty()" short-circuit returns committed=false with no
    // BEGIN attempted and no error logged (there is nothing to roll back),
    // which is a DIFFERENT thing from a real transaction failure. Skip the
    // call entirely in that case rather than misreading its default-false
    // BatchResult as a fold failure.
    if (!stmts.empty()) {
        const auto data_batch = db.execute_atomic_batch(stmts);
        const bool data_stmt_failed = std::any_of(
            data_batch.failed.begin(), data_batch.failed.end(), [](char f) { return f != 0; });
        if (!data_batch.committed || data_stmt_failed) {
            // BLOCKER 1 fix: a transaction-preserving statement error commits
            // every OTHER statement in the SAME batch (TarDatabase::BatchResult's
            // own contract) -- so if the counter upserts below were bundled into
            // this same batch, usage_hwm_id could advance past data that was
            // actually skipped. Bailing here, before the counter batch is even
            // built, is what makes "no partial advance" true rather than merely
            // claimed.
            result.ok = false;
            result.error = !data_batch.committed
                              ? "usage fold data transaction rolled back"
                              : "usage fold data transaction partially failed -- a statement was "
                                "skipped; hwm/counters not advanced";
            result.hwm_id = hwm; // unchanged -- report what is actually persisted
            return result;
        }
    }

    // ── tar_config counters, in a SEPARATE transaction ──────────────────────
    // Issued only now that every data statement above is confirmed intact
    // (see the file banner and BLOCKER 1 comment above). usage_hwm_id is
    // among these, so the durable pointer can only move once the data it
    // describes is durable too.
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

    const auto config_batch = db.execute_atomic_batch(config_stmts);
    const bool config_stmt_failed = std::any_of(
        config_batch.failed.begin(), config_batch.failed.end(), [](char f) { return f != 0; });
    if (!config_batch.committed || config_stmt_failed) {
        result.ok = false;
        result.error = "usage fold: data committed but counters failed to persist -- hwm not "
                      "advanced; the same events will be re-folded next tick";
        result.hwm_id = hwm; // unchanged
        return result;
    }

    result.ok = true;
    result.hwm_id = new_hwm;
    return result;
}

} // namespace yuzu::tar::usage
