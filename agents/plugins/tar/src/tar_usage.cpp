/**
 * tar_usage.cpp -- the SQLite shell for the `usage` derived fold (see
 * tar_usage.hpp for the pure pairing logic and the drain-arithmetic banner).
 *
 * run_usage_fold() is the ONE entry point tar_plugin.cpp's collect_fast_impl
 * calls, once per fast tick, after both process feeders (gap-free stream or
 * snapshot-diff poll) have inserted for that tick. Everything it writes --
 * usage_daily, usage_daily_user, usage_live's open-run set, and every
 * tar_config counter below -- commits as ONE execute_atomic_batch
 * transaction. On ANY failure the whole pass rolls back: usage_hwm_id is
 * UNCHANGED, so the next successful tick re-reads from the same point (a run
 * of failures cannot lose data silently -- the MIN(id) gap check on the next
 * successful fold reports whatever process_live's retention prune took
 * meanwhile, exactly as if this tick had never run at all).
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
#include "tar_schema_registry.hpp" // capture_sources (usage_daily retention lookup)

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

// The usage_daily granularity's retention window, read from the registry
// (integrator-owned row, IT-TAR-SOURCE) -- usage_daily_user has no tier of
// its own in the schema registry, so it is never reached by the generic
// run_retention() sweep, and its cutoff must match usage_daily's by hand.
// Falls back to process_daily's window (31 days) if the "usage" source or
// its "daily" granularity is not yet registered, so this file degrades
// gracefully rather than never pruning usage_daily_user at all.
constexpr int64_t kFallbackDailyRetentionSeconds = 2678400; // 31 days

int64_t usage_daily_retention_seconds() {
    for (const auto& src : capture_sources()) {
        if (src.name != "usage")
            continue;
        for (const auto& g : src.granularities) {
            if (g.suffix == "daily")
                return g.retention_default;
        }
    }
    return kFallbackDailyRetentionSeconds;
}

} // namespace

void usage_rebaseline(TarDatabase& db, int64_t now) {
    int64_t hwm = 0;
    if (auto res = db.execute_query("SELECT COALESCE(MAX(id), 0) FROM process_live", 1);
        res.has_value() && !res->rows.empty() && !res->rows[0].empty()) {
        hwm = parse_i64(res->rows[0][0]);
    }
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
    }
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

    int64_t hwm = parse_i64(db.get_config("usage_hwm_id", "0"));
    result.hwm_id = hwm;

    // ── Gap check FIRST, before any event is read ───────────────────────────
    auto range_res = db.execute_query(
        "SELECT COALESCE(MIN(id), 0), COALESCE(MAX(id), 0), COUNT(*) FROM process_live", 1);
    if (!range_res.has_value() || range_res->rows.empty()) {
        result.error = range_res.has_value() ? "process_live range query returned no row"
                                             : range_res.error();
        return result; // ok=false, hwm unchanged -- nothing written, retried next tick
    }
    const int64_t min_id = parse_i64(range_res->rows[0][0]);
    const int64_t max_id = parse_i64(range_res->rows[0][1]);
    const int64_t row_count = parse_i64(range_res->rows[0][2]);

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

    // ── Read new events beyond the (possibly re-baselined) hwm ──────────────
    std::vector<ProcessEvent> events;
    int64_t new_hwm = effective_hwm;
    if (row_count > 0) {
        auto ev_res = db.execute_query(
            std::format("SELECT id, ts, action, pid, name, user FROM process_live "
                        "WHERE id > {} ORDER BY id LIMIT {}",
                        effective_hwm, max_events_per_tick),
            static_cast<int>(max_events_per_tick) + 1);
        if (!ev_res.has_value()) {
            result.error = ev_res.error();
            return result; // ok=false, hwm unchanged
        }
        events.reserve(ev_res->rows.size());
        for (const auto& row : ev_res->rows) {
            const int64_t id = parse_i64(row[0]);
            ProcessEvent pe;
            pe.ts = parse_i64(row[1]);
            pe.action = row[2];
            pe.pid = static_cast<uint32_t>(parse_i64(row[3]));
            pe.name = row[4];
            pe.user = row[5];
            events.push_back(std::move(pe));
            new_hwm = std::max(new_hwm, id);
        }
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
    const int64_t daily_cutoff = now - usage_daily_retention_seconds();

    // ── Build the ONE transaction ────────────────────────────────────────────
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
        const int64_t day_ts = (c.start_ts / 86400) * 86400;
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

    // usage_daily_user retention -- mirrors usage_daily's own window; this
    // table carries no tier of its own so the generic run_retention() sweep
    // never reaches it (see usage_daily_retention_seconds() above).
    stmts.push_back(
        std::format("DELETE FROM usage_daily_user WHERE day_ts < {}", daily_cutoff));

    // tar_config counters -- written in the SAME transaction as the data
    // above, never as a separate best-effort write, so a failure here rolls
    // back the data too (no partial advance).
    auto upsert_config = [&](std::string_view key, std::string_view value) {
        stmts.push_back(std::format(
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

    const auto batch = db.execute_atomic_batch(stmts);
    if (!batch.committed) {
        result.ok = false;
        result.error = "usage fold transaction rolled back";
        result.hwm_id = hwm; // unchanged -- report what is actually persisted
        return result;
    }

    result.ok = true;
    result.hwm_id = new_hwm;
    return result;
}

} // namespace yuzu::tar::usage
