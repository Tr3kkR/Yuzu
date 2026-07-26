/**
 * tar_aggregator.cpp -- Rollup aggregation and retention engine
 *
 * Rollup chain: Live -> Hourly -> Daily -> Monthly
 * Each tier aggregates from the tier directly below it.
 * Rollup marks (last-processed timestamp) stored in tar_config.
 */

#include "tar_aggregator.hpp"
#include "tar_schema_registry.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <ctime>
#include <format>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace yuzu::tar {

namespace {

// Boundary computation helpers
int64_t hour_boundary(int64_t epoch) {
    return (epoch / 3600) * 3600;
}
int64_t day_boundary(int64_t epoch) {
    return (epoch / 86400) * 86400;
}

// M2: Use calendar-month boundary via gmtime instead of fixed 30-day approximation
int64_t month_boundary(int64_t epoch) {
    time_t t = static_cast<time_t>(epoch);
    struct tm tm_val {};
#ifdef _WIN32
    gmtime_s(&tm_val, &t);
#else
    gmtime_r(&t, &tm_val);
#endif
    tm_val.tm_mday = 1;
    tm_val.tm_hour = 0;
    tm_val.tm_min = 0;
    tm_val.tm_sec = 0;
#ifdef _WIN32
    return static_cast<int64_t>(_mkgmtime(&tm_val));
#else
    return static_cast<int64_t>(timegm(&tm_val));
#endif
}

// Maximum expected interval between rollup marks (H11: clock skew protection)
constexpr int64_t kMaxHourlyGap = 7200;     // 2 hours
constexpr int64_t kMaxDailyGap = 172800;    // 2 days
constexpr int64_t kMaxMonthlyGap = 5400000; // ~62 days

// Rollup one tier for one source.
// Returns true if any data was rolled up.
bool rollup_tier(TarDatabase& db, std::string_view source_name, std::string_view target_suffix,
                 int64_t now_epoch) {

    auto sql = rollup_sql(source_name, target_suffix);
    if (sql.empty())
        return false;

    int64_t boundary;
    int64_t max_gap;
    if (target_suffix == "hourly") {
        boundary = hour_boundary(now_epoch);
        max_gap = kMaxHourlyGap;
    } else if (target_suffix == "daily") {
        boundary = day_boundary(now_epoch);
        max_gap = kMaxDailyGap;
    } else if (target_suffix == "monthly") {
        boundary = month_boundary(now_epoch);
        max_gap = kMaxMonthlyGap;
    } else
        return false;

    auto mark_key = std::format("rollup_{}_{}_at", source_name, target_suffix);
    auto mark_str = db.get_config(mark_key, "0");
    int64_t last_mark = 0;
    try {
        last_mark = std::stoll(mark_str);
    } catch (...) {}

    if (last_mark >= boundary)
        return false;

    // H11: Clock skew protection — if the gap is abnormally large, clamp it
    if (boundary - last_mark > max_gap && last_mark > 0) {
        spdlog::warn("TAR rollup: {}_{} gap {}s exceeds max {}s, possible clock jump — clamping",
                     source_name, target_suffix, boundary - last_mark, max_gap);
        last_mark = boundary - max_gap;
    }

    bool ok = db.execute_sql_range(sql, last_mark, boundary);
    if (ok) {
        db.set_config(mark_key, std::to_string(boundary));
        spdlog::debug("TAR rollup: {}_{} processed [{}, {})", source_name, target_suffix, last_mark,
                      boundary);
    }

    return ok;
}

} // namespace

int run_aggregation(TarDatabase& db, int64_t now_epoch) {
    int ops = 0;

    // Data-driven over the registry — symmetric with run_retention() below, which
    // also walks capture_sources(). Every source's non-live granularities roll up
    // in declaration order (hourly → daily → monthly), so the Live→Hourly→Daily→
    // Monthly chain runs in dependency order within a tick (daily reads hourly,
    // monthly reads daily). rollup_tier() is a no-op when the (source, tier) pair
    // has no rollup_sql, so a source that lacks a tier — or has none, e.g. the
    // single-tier netqual — is skipped automatically. This replaces a
    // hand-maintained steps[] array that silently omitted any newly-registered
    // source: the $Module rollup SQL was dead until this loop (governance UP-1).
    for (const auto& src : capture_sources()) {
        for (const auto& g : src.granularities) {
            if (g.suffix == "live")
                continue;
            if (rollup_tier(db, src.name, g.suffix, now_epoch))
                ++ops;
        }
    }

    return ops;
}

bool apply_source_enabled_transition(TarDatabase& db, std::string_view source,
                                     std::string_view new_value, int64_t now_epoch) {
    auto enabled_key = std::format("{}_enabled", source);
    // Default `prev` to the source's declared default so the first-ever set on a
    // fresh DB is only a transition when it differs from that default. For an
    // opt-in source (module/procperf/netqual, default false) the first
    // `<src>_enabled=false` is therefore NOT an enabled→disabled transition and
    // does not write a spurious paused_at. The `_enabled` flag itself is written
    // below (in-branch), not here, so the #538 fail-safe ordering holds: on a
    // disable the flag flips only after the baseline clear persists.
    const char* prev_def = source_default_enabled(source) ? "true" : "false";
    std::string prev = db.get_config(enabled_key, prev_def);
    // Canonicalise `prev` to the strict tri-state before BOTH transition checks
    // (#560 / fjarvis review). do_configure only ever writes "true"/"false"; a
    // corrupt or tampered value canonicalises to "errored", which is neither
    // "true" nor "false". The two legs must agree on what "errored" means:
    //   - disable leg already fired on any non-"false" prev (errored included),
    //   - the re-enable leg used to reset paused_at ONLY on prev == "false",
    // so recovering a tampered source via `configure <src>_enabled=true` from an
    // "errored" value resumed collection but left a STALE paused_at — `status`
    // then reported enabled=true alongside a paused timestamp and the dashboard
    // rendered a collecting source as paused. Gating both legs on the canonical
    // tri-state ("errored" is "not validly enabled") makes the recovery clear it.
    const std::string_view prev_canon = canonical_source_enabled(prev);
    auto paused_at_key = std::format("{}_paused_at", source);

    if (new_value == "false" && prev_canon != "false") {
        // Enable→disable. #538/UP-1: clear the diff baseline FIRST and flip the
        // `_enabled` flag only if the clear actually persisted. `set_state` can
        // fail silently (SQLITE_BUSY / disk full); if we flipped the flag first
        // and the clear then failed, we'd have a DISABLED source with a STALE
        // baseline — and a later re-enable would emit exactly the ghost "stopped"
        // events this fix exists to prevent, while the operator saw success.
        // Clearing first makes the disable fail-safe: a failed clear leaves the
        // source ENABLED (its baseline still valid, collection continues) and we
        // report failure so the operator can retry. No-op for sources without a
        // snapshot-diff baseline (perf/procperf/netqual). The caller serialises
        // this whole call against the collectors via collect_mu_ (see do_configure).
        if (auto key = diff_state_key(source); !key.empty()) {
            if (!db.set_state(std::string{key}, ""))
                return false; // baseline NOT cleared → do not disable
        }
        // KNOWN GAP, deliberately not fixed here (tracked in #2490). This write's
        // result is discarded, so a failed persist reports a successful pause
        // while collection and retention keep running on data the operator
        // believes is frozen -- and because the caller sees success it ALSO fires
        // the edge-gated nstat drain, discarding live TCP lifecycle events on a
        // source that is still enabled.
        //
        // Be precise about why a bare `return false` here is not the fix, because
        // an earlier version of this comment got it backwards. The baseline has
        // already been cleared above, so the source is left ENABLED with a WIPED
        // baseline and the next tick emits a ghost `started` for every process --
        // but that happens with the CURRENT code too, so it is not a reason to
        // prefer the current code. The early return is in fact strictly better on
        // the false-success and nstat-drain counts. What it gets wrong is the
        // report: do_configure's failure text says "could not clear collection
        // baseline", which would then describe the wrong failure.
        //
        // A real fix moves the flag and the baseline together (one transaction --
        // execute_atomic_batch now exists), gives the flag-write failure its own
        // operator message, and gates the nstat drain on the write having
        // actually persisted. Out of scope for the retention clock guard; the
        // full analysis is in #2490.
        db.set_config(enabled_key, std::string{new_value});
        db.set_config(paused_at_key, std::to_string(now_epoch));
        return true;
    }

    // All other transitions (idempotent set, disable/errored→enable, first set):
    // no baseline clear, so the flag write cannot leave inconsistent state.
    db.set_config(enabled_key, std::string{new_value});
    // Clear paused_at whenever we become enabled from a NOT-validly-enabled state
    // — "false" (paused) OR "errored" (corrupt/tampered). `prev_canon != "true"`
    // is the mirror of the disable leg's `prev_canon != "false"`, so an
    // errored→true recovery no longer leaves a stale paused_at. An idempotent
    // true→true is a no-op here (paused_at is already "0").
    if (new_value == "true" && prev_canon != "true") {
        db.set_config(paused_at_key, "0");
    }
    return true;
}

std::string_view diff_state_key(std::string_view source) {
    // Mapping is NOT 1:1 with the source name: tcp's baseline lives under
    // "network" (historical). Keep this the ONE home for the mapping — the
    // collectors (collect_fast/slow) and apply_source_enabled_transition both
    // route through here so the on-disable clear can never target the wrong key.
    if (source == "process")
        return "process";
    if (source == "tcp")
        return "network";
    if (source == "service")
        return "service";
    if (source == "user")
        return "user";
    // software is a snapshot-diff source too: collect_software keeps an installed-
    // inventory baseline under this exact key (get_state/set_state "software"), so
    // the on-disable clear must reach it or a re-enable would emit ghost
    // install/remove/upgrade events for everything that changed while paused (#538).
    if (source == "software")
        return "software";
    // ADR-0015 — arp/dns are snapshot-diff sources too: the collect legs keep a
    // baseline under these exact keys (get_state/set_state "arp"/"dns"), so the
    // on-disable clear must reach them or a re-enable would emit ghost
    // removed/added neighbour + cache deltas for the paused window (#538).
    if (source == "arp")
        return "arp";
    if (source == "dns")
        return "dns";
    // §3.8 — mapdrive is a snapshot-diff source: the collect_slow leg keeps a
    // baseline under get_state/set_state "mapdrive", so the on-disable clear must
    // reach it or a re-enable would emit ghost appeared/removed mapping deltas for
    // the paused window (#538). (The one-time historical backfill does NOT use this
    // baseline — it inserts directly, gated by the mapdrive_backfill_done key.)
    if (source == "mapdrive")
        return "mapdrive";
    // perf/procperf keep an in-memory previous reading; netqual holds only a
    // wall-clock-guarded in-memory baseline (re-anchored on a long gap, never a
    // stored diff); netconn is high-water-mark based (its only state is the
    // netconn_backfill_hwm config key, deliberately kept across a disable so the
    // OS event log recovers the paused window); module is stream-drained. None
    // of these has a snapshot-diff baseline to clear here.
    return {};
}

namespace {
// The effective match core of a pattern: should_redact strips only leading and
// trailing '*' and treats an interior '*' as a literal, so "*a*" matches the
// 1-char substring "a". The min-core floor (#541 / gov UP-2) must measure this
// stripped core, not the raw length, or it is trivially bypassed. Shared by
// validate_config_pattern (configure path) and parse_pattern_config (load path)
// so both enforce an identical floor.
std::string_view stripped_core(std::string_view pattern) {
    while (!pattern.empty() && pattern.front() == '*')
        pattern.remove_prefix(1);
    while (!pattern.empty() && pattern.back() == '*')
        pattern.remove_suffix(1);
    return pattern;
}
} // namespace

std::optional<std::string> validate_config_pattern(std::string_view pattern,
                                                   bool require_min_core_len) {
    if (pattern.size() > kMaxPatternLength) {
        return std::format("pattern exceeds the {}-character limit", kMaxPatternLength);
    }
    if (require_min_core_len && stripped_core(pattern).size() < kMinExclusionCoreLength) {
        return std::format("exclusion pattern '{}' has an effective substring shorter than {} "
                           "characters and would match almost every process — use a longer "
                           "substring (leading/trailing '*' do not count)",
                           pattern, kMinExclusionCoreLength);
    }
    return std::nullopt;
}

std::optional<std::vector<std::string>> parse_pattern_config(std::string_view json_text,
                                                             bool require_min_core_len) {
    // Runtime defense-in-depth (#541 / gov UP-1): the configure path caps the
    // array at write time, but load_*/collect read whatever is stored every fast
    // cycle. A value written before the cap existed, or mutated outside the
    // plugin, must still be bounded here so it can't degrade the per-process
    // redaction scan. Parse, drop non-string / empty / over-long elements, and
    // truncate to the element cap. Returns nullopt only when the stored value is
    // not a JSON array at all (caller falls back to its own default).
    //
    // Cap the raw text BEFORE parsing (gov MEDIUM): the element/length caps only
    // bite after the array is materialised, so without this a multi-MB tampered or
    // legacy value would be fully parsed + copied every fast cycle. A blob over the
    // cap is treated as unparseable → caller's safe default.
    if (json_text.size() > kMaxPatternConfigBytes)
        return std::nullopt;
    nlohmann::json arr;
    try {
        arr = nlohmann::json::parse(json_text);
    } catch (...) {
        return std::nullopt;
    }
    if (!arr.is_array())
        return std::nullopt;
    std::vector<std::string> patterns;
    for (const auto& elem : arr) {
        if (patterns.size() >= kMaxPatternArrayElements)
            break; // element cap — ignore the overflow tail
        if (!elem.is_string())
            continue;
        // get_ref avoids copying the element until it has passed the length check.
        const auto& s = elem.get_ref<const std::string&>();
        if (s.empty() || s.size() > kMaxPatternLength)
            continue; // skip empty / over-long elements rather than failing
        // #541 load-path floor: drop a sub-floor exclusion the same way configure
        // rejects it, so a value persisted before the floor existed (no-tamper
        // upgrade) or written out of band can't reach should_redact and silently
        // suppress most process events. Off for redaction patterns (a short core
        // only over-redacts a command line; it never drops an event).
        if (require_min_core_len && stripped_core(s).size() < kMinExclusionCoreLength)
            continue;
        patterns.push_back(s); // copy: `s` is a borrowed ref into the json element
    }
    return patterns;
}

std::string_view canonical_source_enabled(std::string_view stored_value) {
    if (stored_value == "true")
        return "true";
    if (stored_value == "false")
        return "false";
    return "errored"; // anything else was written outside the plugin
}

// #560 — gate on the canonical tri-state, not `!= "false"`. A value the plugin
// never writes ("maybe", "1", "", a bit-flip) maps to "errored", which is NOT
// "true", so collection STOPS (fail closed). The bare `!= "false"` treated every
// such value as enabled, so a source an operator paused for forensics whose
// `_enabled` value was corrupted or tampered kept collecting — and disagreed
// with the tri-state `status` reports. run_retention() shares the same canonical
// gate so an "errored" source's rows are preserved, not pruned. Also the
// authoritative paused-guard for the Phase 15.A `tar.purge_source` action.
bool source_enabled(TarDatabase& db, std::string_view source) {
    const char* def = source_default_enabled(source) ? "true" : "false";
    return canonical_source_enabled(db.get_config(std::format("{}_enabled", source), def)) ==
           "true";
}

namespace {

// Durable last-pass clock reading. Persisted for the same reason the audit store
// persists its own: the elapsed-time check is the only half of the guard that
// still works once a write has landed after the clock moved, and held in memory
// alone it compares against zero on the first pass of a process -- so an agent
// that BOOTS with a wrong RTC would never see a step at all, which is the case
// this guard exists for. The per-table decline latch stays in memory on purpose;
// re-declining once after a reboot is the safe direction.
constexpr std::string_view kRetentionLastPassKey = "retention_guard_last_pass";

// Reported on the `tar status` failure surface when the durable clock reading
// cannot be written. Deliberately not a table name -- the surface is keyed by
// table, and this failure belongs to the guard itself, so it gets a name no
// warehouse table can collide with.
constexpr std::string_view kClockStateFailureKey = "__clock_state__";

// Does any row match? Runs through the TRUSTED connection. `execute_user_query`
// is the authorizer-sandboxed path for untrusted operator SQL (tar.sql, #760)
// and is deliberately NOT used here: this SQL is built from registry constants
// and integer-formatted timestamps, never operator input.
//
// EXISTS, not COUNT(*). A COUNT has to walk every matching row, and the
// `datable` predicate matches essentially the whole table, so on a 400k-row
// procperf_live it measured ~7.8ms -- times two probes times twenty granularities
// every 900 seconds, on a user's laptop, against a previous cost of zero reads.
// The guard only ever asks yes/no questions, and EXISTS short-circuits on the
// first hit: ~0.004ms.
//
// Returns nullopt on any query error, so the caller can fail closed rather than
// read a false and mistake a broken query for an empty table.
std::optional<bool> exists_where(TarDatabase& db, std::string_view table,
                                 std::string_view predicate) {
    auto res = db.execute_query(
        std::format("SELECT EXISTS(SELECT 1 FROM {} WHERE {})", table, predicate), /*max_rows=*/1);
    if (!res.has_value() || res->rows.empty() || res->rows[0].empty())
        return std::nullopt;
    const std::string& cell = res->rows[0][0];
    int64_t v = 0;
    const auto* first = cell.data();
    const auto* last = cell.data() + cell.size();
    // from_chars rather than stoll: non-throwing, so it cannot swallow a
    // bad_alloc in a catch-all the way the previous parse did.
    if (auto [p, ec] = std::from_chars(first, last, v); ec != std::errc{} || p != last)
        return std::nullopt;
    return v != 0;
}


// ONE aggregate line per pass, never one per table. A real clock anomaly trips
// every time-based table at once and a broken database fails all of them, so
// per-table warns would bury the signal ~20 lines deep on an endpoint nobody is
// tailing. Per-table detail is at debug; the durable operator surface is the
// `tar status` counters, since the agent has no /metrics endpoint.
void warn_if_degraded(int declined, int unreadable, int total, bool persist_failed) {
    if (declined > 0)
        spdlog::warn("TAR retention: clock guard declined {} of {} time-based tables this pass. "
                     "More than the retention threshold elapsed since the last pass, or the whole "
                     "window would have gone at once -- a forward clock jump, OR this endpoint "
                     "was off/suspended that long. Deletion resumes, paced, once it clears.",
                     declined, total);
    if (unreadable > 0)
        spdlog::warn("TAR retention: could not read {} of {} time-based tables this pass; they "
                     "were skipped and are NOT being retained (see retention_guard_failed in "
                     "`tar status`)",
                     unreadable, total);
    if (persist_failed)
        spdlog::warn("TAR retention: could not persist the clock reading; after a restart this "
                     "agent will have no comparison point and the elapsed-time check will not "
                     "fire (see retention_guard_failed|__clock_state__ in `tar status`)");
}

} // namespace

RetentionGuardCounters retention_guard_counters(const RetentionGuardState& guard) {
    std::lock_guard lock(guard.mu);
    // Probe failures and delete failures are merged: both mean "this table is
    // not being retained", which is the only distinction the operator surface
    // needs to draw against a clock decline.
    RetentionGuardCounters out{guard.declines, guard.failures};
    for (const auto& [table, count] : guard.delete_failures)
        out.failures[table] += count;
    return out;
}

std::vector<std::string> format_retention_guard_lines(const RetentionGuardState& guard) {
    const auto counters = retention_guard_counters(guard);
    std::vector<std::string> lines;
    int64_t total_declines = 0, total_failures = 0;
    for (const auto& [table, count] : counters.declines) {
        if (count <= 0)
            continue;
        total_declines += count;
        lines.push_back(std::format("retention_guard|{}|{}", table, count));
    }
    for (const auto& [table, count] : counters.failures) {
        if (count <= 0)
            continue;
        total_failures += count;
        lines.push_back(std::format("retention_guard_failed|{}|{}", table, count));
    }
    // Both totals are ALWAYS emitted, including zeros: an absent line is
    // ambiguous between "no declines" and "an agent too old to report", and the
    // failures total is what stops a zero declines total from being read as
    // "this endpoint's clock is fine" when retention has actually stopped.
    lines.push_back(std::format("retention_guard_declines_total|{}", total_declines));
    lines.push_back(std::format("retention_guard_failures_total|{}", total_failures));
    return lines;
}

void run_retention(TarDatabase& db, int64_t now_epoch, RetentionGuardState& guard) {
    // A closed store makes every read below return its DEFAULT, so the pass would
    // walk the whole registry, queue plans against a null connection, fail every
    // one, and warn that a restart will cost the clock comparison point -- when a
    // restart is precisely what recovers a closed store. Say the true thing once
    // and stop (#2361 Gate 8).
    if (!db.is_open()) {
        spdlog::warn("TAR retention: skipped, the TAR database is closed. Storage is offline on "
                     "this endpoint until the agent restarts (see `tar status`).");
        return;
    }

    // #2361 read/decide phase, deliberately BEFORE the transaction. Every
    // statement executed inside the transaction below is a string built HERE, so
    // nothing that can throw (std::format, map/vector growth) runs between BEGIN
    // and COMMIT -- a bad_alloc there would unwind past the trigger engine and
    // leave the shared connection wedged in an open write transaction.
    //
    // The reads are slightly stale by the time the deletes run, which is
    // conservative-safe in both directions: the per-table cap bounds every delete
    // regardless of what the probes said, and a row inserted in between is newer
    // than the cutoff, so it is not a candidate. (This is NOT a shorter
    // write-lock window -- SQLite's BEGIN is DEFERRED, so the reads never held
    // the write lock. It avoids a regression rather than winning anything.)
    struct Plan {
        std::string table; // for failure attribution; both strings are pre-built
        std::string sql;
    };
    std::vector<Plan> plans;
    int declined_tables = 0, time_based_tables = 0, unreadable_tables = 0;
    bool persist_failed = false;

    // Durable across restarts, so the elapsed-time check still fires on the
    // first pass of a process that booted with an already-wrong clock.
    std::optional<int64_t> prev_pass_now;
    bool prev_implausible = false;
    {
        const std::string stored = db.get_config(std::string{kRetentionLastPassKey}, "");
        const auto* first = stored.data();
        const auto* last = stored.data() + stored.size();
        int64_t v = 0;
        if (auto [p, ec] = std::from_chars(first, last, v); ec == std::errc{} && p == last)
            prev_pass_now = v;
        // SANITISE before doing arithmetic. This row lives in tar_config on a
        // device the user may control, and even without tampering an earlier pass
        // that ran while the clock was skewed FORWARD leaves a reading ahead of
        // now -- which would make `now - prev` negative until real time catches
        // up, silently killing the only detector that survives a reboot.
        // (`now - INT64_MIN` also overflows; `now - INT64_MAX` does not, for a
        // normal positive epoch.)
        //
        // EVERY implausible shape is an anomaly, not a quiet reset: ahead of now,
        // negative, or unparseable. None can arise from a pass this code ran, so
        // each means the state was corrupted or tampered with -- and on a
        // user-controlled endpoint, quietly accepting one is exactly how an
        // adversary disables the step check while `tar status` reports healthy.
        if (!stored.empty() && !prev_pass_now)
            prev_implausible = true; // present but unparseable
        if (prev_pass_now && (*prev_pass_now < 0 || *prev_pass_now > now_epoch)) {
            prev_implausible = true;
            prev_pass_now.reset();
        }
    }
    // Record the reading for the NEXT pass before any early exit: it is an honest
    // observation of the clock whatever this pass goes on to do, and re-anchoring
    // here is what lets a poisoned or stale value self-heal.
    if (!db.set_config(std::string{kRetentionLastPassKey}, std::to_string(now_epoch))) {
        // The restart-surviving half of the guard silently degrades if this keeps
        // failing, and on an endpoint an adversary can ARRANGE for it to fail. It
        // is a guard failure, reported like any other, not a log line.
        std::lock_guard lock(guard.mu);
        ++guard.failures[std::string{kClockStateFailureKey}];
        persist_failed = true;
    }

    for (const auto& src : capture_sources()) {
        // #539: Skip retention for disabled sources. The configure docstring and
        // user-manual promise that disabling a collector "leaves existing rows
        // queryable." Without this guard, time-based retention drains hourly
        // within 24h, daily within 31d, monthly within ~365d after disable —
        // breaking the forensic-preservation use case. See issue #539.
        // #539/#560 — preserve rows whenever the source is NOT actively-and-
        // validly enabled. Gating on the canonical tri-state (not `== "false"`)
        // means a paused source ("false") AND a corrupt/tampered one ("errored")
        // both skip retention, so the forensic window an operator paused — or one
        // whose `_enabled` value was clobbered — is never pruned. This matches the
        // collect-time source_enabled() gate, which also fails closed on "errored".
        //
        // This gate stays STRICTLY AHEAD of any guard bookkeeping: a paused or
        // errored source whose rows are all past their cutoff must neither
        // delete nor decline. Declining would burn a per-table decline counter
        // (and an operator-facing warn) on a source that was never going to be
        // pruned in the first place.
        auto enabled_key = std::format("{}_enabled", src.name);
        if (canonical_source_enabled(
                db.get_config(enabled_key, src.default_enabled ? "true" : "false")) != "true") {
            // Clear this source's latches while it is skipped. A latch left armed
            // across a pause is spent: the first pass after the operator
            // re-enables the source would delete capped with no decline, no
            // counter and no warn, even if the anomaly that armed it is still
            // live. Counters are cumulative and deliberately survive.
            std::lock_guard lock(guard.mu);
            for (const auto& g : src.granularities)
                guard.latched[std::format("{}_{}", src.name, g.suffix)] = false;
            continue;
        }
        for (const auto& g : src.granularities) {
            auto table_name = std::format("{}_{}", src.name, g.suffix);
            // Row-count retention needs no CLOCK guard -- it trims only the
            // excess over a fixed ceiling, computed with no clock at all, so no
            // reading can make it delete more than it always would. It does need
            // the same per-pass BOUND, for a different reason: the whole batch
            // now runs under one held database mutex, so an uncapped
            // `DELETE ... WHERE id <= (... OFFSET ceiling)` over a large excess
            // would stall every collector, `tar status` and config write on this
            // connection for as long as it takes (#2361 Gate 8 / Sol).
            //
            // Rerouted at the caller, exactly as the time-based branch is, so
            // `retention_sql`'s pinned SQL text stays byte-identical. In steady
            // state the excess is one tick's inflow, far below the cap, so this
            // is a no-op; it only bites after a long disable or an upgrade
            // backlog, which then drains over a few ticks instead of stalling
            // the plugin once.
            if (g.retention_type != RetentionType::kTimeBased) {
                if (retention_sql(table_name, now_epoch).empty())
                    continue; // not a retention-bearing table
                plans.push_back(Plan{
                    table_name,
                    std::format("DELETE FROM {} WHERE id IN ("
                                "SELECT id FROM {} WHERE id <= "
                                "(SELECT id FROM {} ORDER BY id DESC LIMIT 1 OFFSET {}) "
                                "ORDER BY id ASC LIMIT {})",
                                table_name, table_name, table_name, g.retention_default,
                                kMaxTarDeletesPerTablePerPass)});
                continue;
            }

            ++time_based_tables;
            const int64_t cutoff = now_epoch - g.retention_default;
            const std::string ts_col{ts_column_for_suffix(g.suffix)};
            const int64_t horizon = now_epoch + kTarRetentionFutureSlackSec;

            // Two yes/no questions, not two counts.
            //
            // `would_wipe` was `datable > 0 && expired == datable`. Since a row
            // older than `cutoff` is necessarily at or below `now + slack`
            // (cutoff < now < horizon), every expired row is also datable -- so
            // `datable > 0` is implied by `expired > 0` and was dead, and
            // `expired == datable` is exactly "no datable row survives the
            // cutoff". That reduces to a single EXISTS over the half-open band
            // [cutoff, horizon], which short-circuits on the first survivor
            // instead of counting the whole table.
            //
            // The upper bound is what excludes rows stamped implausibly far
            // ahead: they can never be too old, so letting one answer the
            // question would disarm the guard for the life of the endpoint.
            auto has_expired = exists_where(db, table_name, std::format("{} < {}", ts_col, cutoff));
            auto has_survivor = exists_where(
                db, table_name, std::format("{} BETWEEN {} AND {}", ts_col, cutoff, horizon));

            std::lock_guard lock(guard.mu);
            bool& latched = guard.latched[table_name];
            if (!has_expired || !has_survivor) {
                // Fail closed: a probe we could not read is not evidence that
                // deleting is safe. Skip the table this pass, count the failure,
                // and RE-ARM the guard -- carrying a set latch across a failed
                // pass would let the next pass that really would wipe the table
                // delete with no decline and no counter. Same rule the audit
                // store applies to its own probe failures.
                ++guard.failures[table_name];
                latched = false;
                ++unreadable_tables; // aggregated into ONE warn below
                continue;
            }
            if (!*has_expired) {
                // Nothing to delete, so nothing to guard against -- and the
                // anomaly this table latched for is over. Same rule the accepting
                // path applies below.
                latched = false;
                continue;
            }

            const bool would_wipe = !*has_survivor;
            // Supplement, not a replacement. The outcome test only fires when a
            // jump exceeds this table's WHOLE retention window, AND it is
            // defeated by any row written after the jump -- which `do_rollup`
            // reliably produces, since run_aggregation runs first and mints rows
            // into these very tables. The step check is durable across restarts
            // (see above), so it is what actually covers the wrong-RTC case.
            // ABSOLUTE, not derived from the tier's retention window -- same
            // correction as the audit sibling. max(window, floor) made the
            // threshold a YEAR on the monthly tier, so the check could never fire
            // there. How far the clock moved is unrelated to how long that tier
            // keeps rows.
            const int64_t step_threshold = kTarMinBigStepSec;
            const bool big_step =
                prev_pass_now && now_epoch - *prev_pass_now > step_threshold;

            if ((would_wipe || big_step || prev_implausible) && !latched) {
                latched = true;
                ++guard.declines[table_name];
                ++declined_tables;
                spdlog::debug("TAR retention: declining {} (wipe={}, bad_state={}, {}s since last "
                              "pass, threshold {}s)",
                              table_name, would_wipe, prev_implausible,
                              prev_pass_now ? now_epoch - *prev_pass_now : 0, step_threshold);
                continue;
            }
            // Hold the latch only while an anomaly is STILL BEING WORKED OFF:
            // the wipe condition held AND the cap will leave rows behind. The
            // second half is what an earlier round got wrong -- latching purely
            // on `would_wipe` left the latch armed after a pass that drained the
            // whole backlog, so a real anomaly arriving before the next tick
            // deleted with no decline and no counter (#2361 Gate 8 / Sol).
            //
            // "Will the cap bind?" is answered by asking whether a (cap+1)th
            // expired row exists -- bounded, index-driven, and only for a table
            // that is actually in the wipe condition, so the healthy path pays
            // nothing. An unreadable answer is treated as "yes", keeping the
            // latch armed, which is the conservative direction.
            bool cap_will_bind = false;
            if (would_wipe) {
                const auto more = exists_where(
                    db, table_name,
                    std::format("{} < {} LIMIT 1 OFFSET {}", ts_col, cutoff,
                                kMaxTarDeletesPerTablePerPass));
                cap_will_bind = !more || *more;
            }
            latched = would_wipe && cap_will_bind;
            // Capped, oldest-first. Every warehouse table has `id INTEGER PRIMARY
            // KEY` plus an `idx_{table}_{ts_col}` index (generate_warehouse_ddl),
            // so the subquery is an index scan, not a sort.
            plans.push_back(Plan{table_name,
                                 std::format("DELETE FROM {} WHERE id IN ("
                                             "SELECT id FROM {} WHERE {} < {} "
                                             "ORDER BY {} ASC, id ASC LIMIT {})",
                                             table_name, table_name, ts_col, cutoff, ts_col,
                                             kMaxTarDeletesPerTablePerPass)});
        }
    }


    if (plans.empty()) {
        warn_if_degraded(declined_tables, unreadable_tables, time_based_tables, persist_failed);
        return; // nothing queued: no BEGIN, no COMMIT.
        // NOTE this is emptiness of the PLAN list, which is not the same as
        // "every time-based table declined": row-count tiers are queued
        // whenever they are retention-bearing, without regard to whether they
        // have anything to delete. So a real device with an enabled _live tier
        // still issues a BEGIN/COMMIT even while every time-based table is
        // declining. Cheap (0-row deletes), but the earlier comment here
        // claimed a guarantee that does not hold in practice (Gate 4 happy-path).
    }

    // Hand the whole batch to the store so it runs under ONE held lock. The
    // previous shape drove BEGIN/COMMIT through execute_sql, which releases the
    // database mutex between statements -- so a concurrent collector INSERT or
    // `set_config` joined the retention transaction, and the rollback this pass
    // performs on failure then discarded that write after its caller had already
    // been told it succeeded (#2361 Gate 8 / Kimi). Silent collateral data loss,
    // widened by the deliberate rollback rather than caused by it.
    std::vector<std::string> sql;
    sql.reserve(plans.size());
    for (auto& p : plans)
        sql.push_back(std::move(p.sql)); // `.table` is all the caller reads afterwards
    const auto batch = db.execute_atomic_batch(sql);

    {
        std::lock_guard lock(guard.mu);
        for (std::size_t i = 0; i < plans.size(); ++i) {
            if (!batch.failed[i])
                continue;
            ++guard.delete_failures[plans[i].table];
            // Re-arm, exactly as the audit sibling does on its delete-failure
            // path. Nothing was deleted, so the pass learned nothing about the
            // clock; carrying a set latch forward would let the next pass accept
            // a real anomaly with no decline and no counter. Only for tables that
            // HAVE a latch -- row-count tables share this batch but no guard.
            if (auto it = guard.latched.find(plans[i].table); it != guard.latched.end())
                it->second = false;
        }
    }
    if (!batch.committed) {
        // `began` distinguishes the two shapes: a BEGIN that never opened means
        // nothing was rolled back because no transaction existed. Reporting a
        // rollback either way is the kind of small untruth this branch has spent
        // three rounds removing.
        if (batch.began)
            spdlog::warn("TAR retention: the delete transaction did not commit; {} queued table "
                         "prunes were rolled back and nothing was retained this pass",
                         plans.size());
        else
            spdlog::warn("TAR retention: could not open a transaction; {} queued table prunes "
                         "were not attempted and nothing was retained this pass",
                         plans.size());
    }
    warn_if_degraded(declined_tables, unreadable_tables, time_based_tables, persist_failed);
}

} // namespace yuzu::tar
