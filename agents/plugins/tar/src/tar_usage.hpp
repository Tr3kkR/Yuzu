#pragma once

/**
 * tar_usage.hpp -- pure process-event pairing fold for the TAR `usage` source
 * (machine-scope app-usage aggregate).
 *
 * Architect decision: `usage` is a DERIVED FOLD over process_live on the fast
 * tick, NOT a CursorSource. Its persisted state is a high-water mark over
 * process_live.id plus an open-run table (usage_live) -- both advanced
 * transactionally by run_usage_fold() (tar_usage.cpp). This header is the
 * PURE half: no SQLite, no clock reads -- every function takes `now`
 * injected, matching tar_cursor.hpp's own now-injection shape, so the
 * pairing logic is fully exercised by test_tar_usage.cpp against fixture
 * ProcessEvent sequences with no DB and no wall clock.
 *
 * DRAIN ARITHMETIC (why the gap check in tar_usage.cpp is load-bearing):
 * the fast tick runs every 60s (tar_plugin.cpp kFastIntervalDefault) and
 * run_usage_fold caps itself at max_events_per_tick=20000 rows/tick, i.e.
 * ~333 events/s sustained before the fold starts trailing the write rate.
 * process_live holds up to 100k rows (kRowCount, tar_schema_registry.cpp);
 * its row-cap prune runs on the rollup cadence and deletes at most 5000 of
 * the LOWEST ids per pass (tar_aggregator.cpp run_retention). So a fold that
 * falls behind by more than the prune's per-pass headroom can find its next
 * unprocessed id already gone -- that is a genuine capture gap, and
 * tar_usage.cpp's MIN(id) check against the persisted high-water mark is the
 * honesty backstop for exactly that tail: it turns a silent skip into a
 * counted, reported loss (usage_gap_count / usage_gap_lost_events) rather
 * than an unnoticed hole in usage_daily.
 *
 * exe_key normalisation: lowercase, basename after the last '/' or '\\',
 * trimmed of surrounding whitespace, empty -> "(unknown)". Windows keeps the
 * `.exe` suffix (never stripped). Linux `comm` (the `name` field ProcessEvent
 * carries for the process source) is already 15-char truncated by the kernel
 * before it ever reaches this function -- this function does not itself
 * truncate, so two Linux binaries whose names collide in the first 15 bytes
 * alias to the same exe_key; that is a kernel-imposed limit, not a defect
 * here. THIS FUNCTION IS THE SOURCE OF TRUTH for the rule: the forthcoming
 * `app_usage` plugin's app_usage_parsers.hpp (agents/plugins/app_usage/src/,
 * not yet landed) is planned to duplicate it byte-for-byte, since that
 * plugin cannot depend on tar's internal headers -- when it lands, its own
 * parity test should pin the duplication, and any change here must be
 * mirrored there by hand.
 */

#include "tar_db.hpp" // yuzu::tar::ProcessEvent

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <expected>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::tar::usage {

/// Lowercase, basename after the last '/' or '\\', trimmed, empty ->
/// "(unknown)". See the file banner for the Windows/.exe and Linux/comm
/// notes. Planned to be mirrored byte-for-byte in the forthcoming
/// agents/plugins/app_usage/src/app_usage_parsers.hpp (not yet landed) --
/// this is the source of truth for the rule.
[[nodiscard]] inline std::string normalise_exe_key(std::string_view raw) {
    std::string s{raw};
    if (const auto pos = s.find_last_of("/\\"); pos != std::string::npos)
        s = s.substr(pos + 1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.pop_back();
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (s.empty())
        return "(unknown)";
    return s;
}

/// An in-progress (pid, exe_key) run, not yet closed by a "stopped" event.
struct OpenRun {
    uint32_t pid{0};
    std::string exe_key;
    std::string user;
    int64_t start_ts{0};
};

/// A run that has ended, one way or another -- `kind` says why.
struct ClosedRun {
    enum class Kind {
        normal,     ///< closed by a matching "stopped" event
        superseded, ///< a NEW "started" for the same (pid, exe_key) arrived
                    ///< before this one's "stopped" -- pid reuse or a missed
                    ///< stop event; the old run is closed at the new start_ts
        expired,    ///< never closed; aged out past expire_open_runs' max_age
        capped,     ///< never closed; evicted by cap_open_runs to bound the
                    ///< open set (oldest start_ts first)
    };
    uint32_t pid{0}; // REQUIRED -- usage_live's unique key is (pid, exe_key)
                     // and the fold deletes closed rows by it.
    std::string exe_key;
    std::string user;
    int64_t start_ts{0};
    int64_t end_ts{0};
    Kind kind{Kind::normal};
};

/// In-memory fold state carried between ticks: the open-run table (mirrors
/// usage_live) plus two machine-scope counters that are NOT attributable to
/// any single exe_key (they live in tar_config, never as usage_daily
/// columns -- see tar_usage.cpp banner).
struct FoldState {
    std::map<std::pair<uint32_t, std::string>, OpenRun> open;
    int64_t unmatched_stops{0};
    int64_t clock_anomalies{0};
};

constexpr int64_t kDefaultMaxAgeSeconds = 604800; // 7 days
constexpr size_t kMaxOpenRuns = 20000;

/// `a - b`, saturating at the int64 range boundary instead of invoking UB on
/// overflow. Adversarial review (Wave 7 PR7.2): `now - start_ts` in
/// expire_open_runs overflows when `start_ts` is an extreme value (e.g.
/// INT64_MIN from a corrupt/adversarial process_live row) and `now` is a
/// plausible epoch second -- reproduced under UBSan. Every caller here only
/// ever compares the result against a small positive `max_age`, so
/// saturating (rather than, say, throwing) is the right degrade: a
/// saturated-to-max result still correctly reads as "older than max_age".
[[nodiscard]] constexpr int64_t saturating_sub(int64_t a, int64_t b) noexcept {
    if (b > 0 && a < std::numeric_limits<int64_t>::min() + b)
        return std::numeric_limits<int64_t>::min();
    if (b < 0 && a > std::numeric_limits<int64_t>::max() + b)
        return std::numeric_limits<int64_t>::max();
    return a - b;
}

/// Floor-toward-negative-infinity bucketing of `ts` into a UTC day boundary,
/// without ever negating `ts` directly -- negating INT64_MIN overflows
/// (adversarial review, Wave 7 PR7.2), which the previous
/// `-(((-ts) + 86399) / 86400) * 86400` formula did for exactly that input.
/// Shared by fold_daily() below and tar_usage.cpp's usage_daily_user
/// bucketing so both use the SAME, overflow-safe rule.
[[nodiscard]] constexpr int64_t day_ts_for(int64_t ts) noexcept {
    constexpr int64_t kDay = 86400;
    if (ts >= 0)
        return (ts / kDay) * kDay;
    // Guard the one region where the floor-adjusted bucket boundary would
    // itself be mathematically below INT64_MIN: INT64_MIN is not a multiple
    // of kDay, so its TRUE floor boundary is one day further negative than
    // int64 can represent. `ts` within one day-width of INT64_MIN hits
    // this; saturate to the smallest representable day-aligned bucket
    // rather than compute an unrepresentable value. An input this extreme
    // is already corrupt/adversarial, not a real epoch second.
    constexpr int64_t kMin = std::numeric_limits<int64_t>::min();
    if (ts <= kMin + kDay)
        return (kMin / kDay) * kDay;
    const int64_t q = ts / kDay; // truncates toward zero
    const int64_t r = ts % kDay;
    return (r == 0) ? q * kDay : (q - 1) * kDay;
}

/**
 * Apply one process event to the fold.
 *
 * "started": if an open run already exists for (pid, exe_key) -- pid reuse,
 * or a missed "stopped" -- it is closed `superseded` at end_ts = this
 * event's start_ts, and returned; the new run then opens. Otherwise nothing
 * closes and nullopt is returned.
 *
 * "stopped": pops the open run for (pid, exe_key), if any, and closes it
 * `normal` at this event's ts. Duration is clamped >= 0: if ts < start_ts
 * (a clock step backwards) end_ts is set to start_ts (0s duration) and
 * `clock_anomalies` is incremented. No matching open run -> `unmatched_stops`
 * increments and nullopt is returned -- there is nothing to close.
 *
 * Any other `action` value is ignored (returns nullopt, no state change) --
 * process_live's action column is "started"/"stopped" only, so this is
 * defensive, not a documented input.
 */
[[nodiscard]] inline std::optional<ClosedRun> apply_event(FoldState& state,
                                                          const ProcessEvent& ev) {
    const auto exe_key = normalise_exe_key(ev.name);
    const auto key = std::make_pair(ev.pid, exe_key);

    if (ev.action == "started") {
        std::optional<ClosedRun> superseded;
        if (auto it = state.open.find(key); it != state.open.end()) {
            ClosedRun closed;
            closed.pid = it->second.pid;
            closed.exe_key = it->second.exe_key;
            closed.user = it->second.user;
            closed.start_ts = it->second.start_ts;
            // Same clamp the "stopped" path below applies (adversarial
            // review, Wave 7 PR7.2): a backward clock step between this
            // run's start and the new "started" that supersedes it must not
            // produce a negative duration -- reproduced with
            // duration=-1000 and clock_anomalies never incremented before
            // this fix.
            if (ev.ts < closed.start_ts) {
                closed.end_ts = closed.start_ts; // clamp to 0s duration
                ++state.clock_anomalies;
            } else {
                closed.end_ts = ev.ts;
            }
            closed.kind = ClosedRun::Kind::superseded;
            superseded = closed;
            state.open.erase(it);
        }
        OpenRun run;
        run.pid = ev.pid;
        run.exe_key = exe_key;
        run.user = ev.user;
        run.start_ts = ev.ts;
        state.open[key] = std::move(run);
        return superseded;
    }

    if (ev.action == "stopped") {
        auto it = state.open.find(key);
        if (it == state.open.end()) {
            ++state.unmatched_stops;
            return std::nullopt;
        }
        ClosedRun closed;
        closed.pid = it->second.pid;
        closed.exe_key = it->second.exe_key;
        closed.user = it->second.user;
        closed.start_ts = it->second.start_ts;
        if (ev.ts < closed.start_ts) {
            closed.end_ts = closed.start_ts; // clamp to 0s duration
            ++state.clock_anomalies;
        } else {
            closed.end_ts = ev.ts;
        }
        closed.kind = ClosedRun::Kind::normal;
        state.open.erase(it);
        return closed;
    }

    return std::nullopt;
}

/// Close every open run older than `max_age` seconds as `expired`, end_ts =
/// start_ts (0s -- never fabricate a duration for a run whose stop was never
/// observed).
[[nodiscard]] inline std::vector<ClosedRun>
expire_open_runs(FoldState& state, int64_t now, int64_t max_age = kDefaultMaxAgeSeconds) {
    std::vector<ClosedRun> closed;
    for (auto it = state.open.begin(); it != state.open.end();) {
        if (saturating_sub(now, it->second.start_ts) > max_age) {
            ClosedRun c;
            c.pid = it->second.pid;
            c.exe_key = it->second.exe_key;
            c.user = it->second.user;
            c.start_ts = it->second.start_ts;
            c.end_ts = it->second.start_ts;
            c.kind = ClosedRun::Kind::expired;
            closed.push_back(std::move(c));
            it = state.open.erase(it);
        } else {
            ++it;
        }
    }
    return closed;
}

/// Bound the open set: while it exceeds `max_open`, close the OLDEST run (by
/// start_ts) as `capped` (0s -- never fabricated), so the open set is bounded
/// by the FOLD itself, not by the generic row-count prune.
[[nodiscard]] inline std::vector<ClosedRun> cap_open_runs(FoldState& state,
                                                          size_t max_open = kMaxOpenRuns) {
    std::vector<ClosedRun> closed;
    while (state.open.size() > max_open) {
        auto oldest = state.open.begin();
        for (auto it = state.open.begin(); it != state.open.end(); ++it) {
            if (it->second.start_ts < oldest->second.start_ts)
                oldest = it;
        }
        ClosedRun c;
        c.pid = oldest->second.pid;
        c.exe_key = oldest->second.exe_key;
        c.user = oldest->second.user;
        c.start_ts = oldest->second.start_ts;
        c.end_ts = oldest->second.start_ts;
        c.kind = ClosedRun::Kind::capped;
        closed.push_back(std::move(c));
        state.open.erase(oldest);
    }
    return closed;
}

/// One (day_ts, exe_key) aggregation delta, ready to upsert into usage_daily.
/// `expired_runs` counts BOTH `expired` and `capped` closures -- neither ever
/// observed a real stop, so they share a bucket distinct from `normal` and
/// `superseded`. user/pid are deliberately absent: usage_daily never carries
/// per-user or per-process identity (that lives in usage_daily_user / the
/// deleted usage_live rows only).
struct DailyDelta {
    int64_t day_ts{0};
    std::string exe_key;
    int64_t run_count{0};
    int64_t total_seconds{0};
    int64_t first_seen{0};
    int64_t last_seen{0};
    int64_t superseded_runs{0};
    int64_t expired_runs{0};
};

/// Attribute each closed run to the UTC day of its START (documented: a run
/// spanning midnight is booked entirely on the day it began, never split).
/// Aggregates by (day_ts, exe_key) across the whole input vector.
[[nodiscard]] inline std::vector<DailyDelta> fold_daily(const std::vector<ClosedRun>& runs) {
    std::map<std::pair<int64_t, std::string>, DailyDelta> acc;
    for (const auto& r : runs) {
        const int64_t day_ts = day_ts_for(r.start_ts);
        auto key = std::make_pair(day_ts, r.exe_key);
        auto [it, inserted] = acc.try_emplace(key);
        DailyDelta& d = it->second;
        if (inserted) {
            d.day_ts = day_ts;
            d.exe_key = r.exe_key;
            d.first_seen = r.start_ts;
            d.last_seen = r.start_ts;
        }
        const int64_t duration = r.end_ts - r.start_ts; // already clamped >= 0 by apply_event
        ++d.run_count;
        d.total_seconds += duration;
        d.first_seen = std::min(d.first_seen, r.start_ts);
        d.last_seen = std::max(d.last_seen, r.start_ts);
        if (r.kind == ClosedRun::Kind::superseded)
            ++d.superseded_runs;
        else if (r.kind == ClosedRun::Kind::expired || r.kind == ClosedRun::Kind::capped)
            ++d.expired_runs;
    }
    std::vector<DailyDelta> out;
    out.reserve(acc.size());
    for (auto& [k, v] : acc)
        out.push_back(std::move(v));
    return out;
}

/**
 * Outcome of one run_usage_fold() pass (tar_usage.cpp). `ok == false` means
 * the whole pass ROLLED BACK -- hwm_id is the value BEFORE the attempt (the
 * store's actual persisted hwm is unchanged), and every other field is
 * whatever was computed before the failing step, informational only.
 */
struct UsageFoldResult {
    bool ok{false};
    std::string error;
    int64_t events_seen{0};
    int64_t runs_closed{0};
    int64_t hwm_id{0};
    int64_t lag_events{0};
    bool gap_detected{false};
};

/**
 * Read process_live rows since the persisted `usage_hwm_id`, fold them
 * (pairing, expiry, cap) against the open-run table (usage_live), and
 * commit the whole result -- usage_daily/usage_daily_user upsert, usage_live
 * open-set update, and every tar_config counter -- as ONE transaction. See
 * tar_usage.cpp for the full contract (gap detection, gating, failure
 * semantics). Defined in tar_usage.cpp -- not pure (drives TarDatabase).
 */
[[nodiscard]] UsageFoldResult run_usage_fold(TarDatabase& db, int64_t now,
                                             int64_t max_events_per_tick = 20000);

/**
 * Re-baseline the fold to start capturing from NOW, forward-only: sets
 * usage_hwm_id = MAX(id) over process_live, clears every open run in
 * usage_live, and stamps usage_coverage_since = now. Called on the `usage`
 * source's false->true enable edge (tar_aggregator.cpp
 * apply_source_enabled_transition), once at plugin init when
 * usage_coverage_since is absent (first run after upgrade), and by
 * run_usage_fold() itself as a self-healing retry when the coverage marker
 * is still absent at fold time -- never a retrospective fold over history
 * the fold never covered.
 *
 * Returns a checked outcome (Wave 7 PR7.2 adversarial review, Blocker 3):
 * the previous `void` signature let a failed MAX(id) probe silently persist
 * hwm=0 alongside a FRESH usage_coverage_since marker, which disarms the one
 * retry path that gates on the marker's ABSENCE -- permanently defeating the
 * forward-only guarantee on a transient DB fault. On failure, NOTHING is
 * written (no hwm, no coverage marker, no usage_live clear): the caller must
 * retry, and the missing marker keeps the retry path armed.
 */
[[nodiscard]] std::expected<void, std::string> usage_rebaseline(TarDatabase& db, int64_t now);

} // namespace yuzu::tar::usage
