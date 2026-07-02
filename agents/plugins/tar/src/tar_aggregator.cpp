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

#include <chrono>
#include <ctime>
#include <format>
#include <optional>
#include <string>
#include <string_view>
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
    // perf/procperf keep an in-memory previous reading; netqual is stateless;
    // module is a stream-drained source (no snapshot-diff baseline).
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

void run_retention(TarDatabase& db, int64_t now_epoch) {
    // M17: Wrap all retention deletes in a single transaction to amortize fsync cost
    db.execute_sql("BEGIN TRANSACTION");

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
        auto enabled_key = std::format("{}_enabled", src.name);
        if (canonical_source_enabled(
                db.get_config(enabled_key, src.default_enabled ? "true" : "false")) != "true")
            continue;
        for (const auto& g : src.granularities) {
            auto table_name = std::format("{}_{}", src.name, g.suffix);
            auto sql = retention_sql(table_name, now_epoch);
            if (!sql.empty()) {
                db.execute_sql(sql);
            }
        }
    }

    db.execute_sql("COMMIT");
}

} // namespace yuzu::tar
