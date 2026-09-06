#pragma once

/**
 * app_usage_parsers.hpp — pure sqlite seam for the app_usage plugin
 * (summary / last_used over TAR's usage_daily / usage_daily_user /
 * usage_live tables inside tar.db).
 *
 * ALL SQL and formatting live here, taking an already-open `sqlite3*` — the
 * shell (app_usage_plugin.cpp) owns opening/closing the connection and
 * reading params/config; this header owns query construction, row mapping,
 * and pipe-delimited formatting, so the fixture-db tests
 * (test_app_usage_parsers.cpp) exercise the real query text against a
 * `:memory:` sqlite db with no OS dependency at all (firewall_parsers.hpp /
 * power_health_parsers.hpp precedent).
 *
 * Reads allowed, and ONLY these: usage_daily, usage_daily_user
 * (COUNT(DISTINCT user) only — user names never leave SQLite),
 * `SELECT COUNT(*) FROM usage_live` (open-run count only — no pid/exe
 * column is ever selected from usage_live), and the named tar_config keys
 * below. Never TAR's raw process-event table or any command-line column —
 * a grep of the plugin sources for those two forbidden identifiers is a
 * test in its own right (test_app_usage_parsers.cpp).
 *
 * Time cutoffs (`since_day_ts`) are computed by the shell and injected in —
 * this header never reads the system clock, matching tar_usage.hpp's own
 * `now`-injection shape (apply_event/expire_open_runs) so every query is
 * driven off values the fixture tests fully control.
 */

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <map>
#include <optional>
#include <sqlite3.h>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::app_usage {

// ─────────────────────────────────────────────────────── window params ────

struct WindowParams {
    int days{30};
    int top{25};
    enum class By { run_time, run_count, unmodelled } by{By::run_time};
};

constexpr int kMinDays = 1, kMaxDays = 365, kDefaultDays = 30;
constexpr int kMinTop = 1, kMaxTop = 500, kDefaultTop = 25;

namespace detail {
[[nodiscard]] inline int clamp_int(std::string_view s, int def, int lo, int hi) {
    int v = def;
    if (!s.empty()) {
        auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
        if (ec != std::errc{} || ptr != s.data() + s.size())
            v = def;
    }
    return std::clamp(v, lo, hi);
}
} // namespace detail

/// `by_str` empty defaults to `run_time`; any non-empty value that is
/// neither "run_time" nor "run_count" parses to `By::unmodelled` — the
/// shell reports `error|bad_param|by` for that case and never runs a query.
[[nodiscard]] inline WindowParams parse_window_params(std::string_view days_str,
                                                       std::string_view top_str,
                                                       std::string_view by_str) {
    WindowParams w;
    w.days = detail::clamp_int(days_str, kDefaultDays, kMinDays, kMaxDays);
    w.top = detail::clamp_int(top_str, kDefaultTop, kMinTop, kMaxTop);
    if (by_str.empty() || by_str == "run_time")
        w.by = WindowParams::By::run_time;
    else if (by_str == "run_count")
        w.by = WindowParams::By::run_count;
    else
        w.by = WindowParams::By::unmodelled;
    return w;
}

// ─────────────────────────────────────────────── exe_key normalisation ────

/// Mirrors tar_usage.hpp's `normalise_exe_key()` byte-for-byte — tar_usage
/// .hpp (agents/plugins/tar/src/tar_usage.hpp, P21/wave 2) is the SOURCE OF
/// TRUTH for this rule. Duplicated rather than shared: this plugin cannot
/// depend on the tar plugin's internal header (P21/P22 have no dependency
/// ordering between them), so the rule is copied here and pinned by
/// test_app_usage_parsers.cpp's 10-input parity test — any future drift in
/// tar_usage.hpp's rule must be mirrored here by hand, and that parity test
/// is what catches a missed mirror.
///
/// Rule: lowercase, basename after the last '/' or '\\', trimmed of
/// surrounding whitespace, empty → "(unknown)". Windows keeps the `.exe`
/// suffix (never stripped); Linux `comm` is already 15-char truncated by
/// the kernel before it ever reaches this function — this function does
/// not itself truncate.
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

// ───────────────────────────────────────────────────────────── errors ─────

struct QueryError {
    std::string detail;
};

// ─────────────────────────────────────────────────────────────── rows ─────

struct UsageRow {
    std::string exe_key;
    int64_t run_count{0};
    int64_t total_seconds{0};
    int64_t first_seen{0};
    int64_t last_seen{0};
    int64_t distinct_users{0};
    int64_t superseded_runs{0};
    int64_t expired_runs{0};
};

struct SummaryResult {
    std::vector<UsageRow> rows;
};

struct LastUsedRow {
    std::string exe_key;
    int64_t last_seen{0};
    int64_t first_seen{0};
    int64_t run_count_30d{0};
    int64_t total_seconds_30d{0};
};

struct MetaInfo {
    std::string coverage_since{"-"};
    int64_t days_present{0};
    int64_t open_runs{0};
    int64_t unmatched_stops{0};
    int64_t clock_anomalies{0};
    int64_t gap_count{0};
    int64_t gap_lost_events{0};
    std::string gap_last_ts{"-"};
    int64_t lag_events{0};
    bool feeder_enabled{true};
    std::string last_fold_ts{"-"};
};

// ─────────────────────────────────────────────────── SQL builders (pinned)──

// Pinned by text (test_app_usage_parsers.cpp): the `<by>` ORDER BY target is
// the same aggregate expression selected, so a plain `ORDER BY <column>`
// alias ambiguity across sqlite versions is never relied on.
inline constexpr std::string_view kSummarySqlByRunTime =
    "SELECT exe_key, SUM(run_count), SUM(total_seconds), MIN(first_seen), MAX(last_seen), "
    "SUM(superseded_runs), SUM(expired_runs) FROM usage_daily WHERE day_ts >= ? "
    "GROUP BY exe_key ORDER BY SUM(total_seconds) DESC LIMIT ?";
inline constexpr std::string_view kSummarySqlByRunCount =
    "SELECT exe_key, SUM(run_count), SUM(total_seconds), MIN(first_seen), MAX(last_seen), "
    "SUM(superseded_runs), SUM(expired_runs) FROM usage_daily WHERE day_ts >= ? "
    "GROUP BY exe_key ORDER BY SUM(run_count) DESC LIMIT ?";
inline constexpr std::string_view kDistinctUsersSql =
    "SELECT exe_key, COUNT(DISTINCT user) FROM usage_daily_user WHERE day_ts >= ? "
    "GROUP BY exe_key";
inline constexpr std::string_view kOpenRunsSql = "SELECT COUNT(*) FROM usage_live";
inline constexpr std::string_view kUsageDailyExistsSql =
    "SELECT name FROM sqlite_master WHERE type='table' AND name='usage_daily'";
inline constexpr std::string_view kLastUsedSqlAll =
    "SELECT exe_key, MAX(last_seen), MIN(first_seen), "
    "SUM(CASE WHEN day_ts >= ? THEN run_count ELSE 0 END), "
    "SUM(CASE WHEN day_ts >= ? THEN total_seconds ELSE 0 END) "
    "FROM usage_daily GROUP BY exe_key ORDER BY exe_key";
inline constexpr std::string_view kLastUsedSqlOne =
    "SELECT exe_key, MAX(last_seen), MIN(first_seen), "
    "SUM(CASE WHEN day_ts >= ? THEN run_count ELSE 0 END), "
    "SUM(CASE WHEN day_ts >= ? THEN total_seconds ELSE 0 END) "
    "FROM usage_daily WHERE exe_key = ? GROUP BY exe_key";

// tar_config keys this plugin is allowed to read — nothing else.
inline constexpr std::string_view kConfigUsageEnabled = "usage_enabled";
inline constexpr std::string_view kConfigProcessEnabled = "process_enabled";
inline constexpr std::string_view kConfigFeederEnabled = "usage_feeder_enabled";
inline constexpr std::string_view kConfigCoverageSince = "usage_coverage_since";
inline constexpr std::string_view kConfigUnmatchedStops = "usage_unmatched_stops";
inline constexpr std::string_view kConfigClockAnomalies = "usage_clock_anomalies";
inline constexpr std::string_view kConfigGapCount = "usage_gap_count";
inline constexpr std::string_view kConfigGapLostEvents = "usage_gap_lost_events";
inline constexpr std::string_view kConfigGapLastTs = "usage_gap_last_ts";
inline constexpr std::string_view kConfigLagEvents = "usage_lag_events";
inline constexpr std::string_view kConfigLastFoldTs = "usage_last_fold_ts";

// ───────────────────────────────────────────────────────── sqlite helpers ─

namespace detail {

class Stmt {
public:
    Stmt(sqlite3* db, std::string_view sql) noexcept {
        sqlite3_prepare_v2(db, sql.data(), static_cast<int>(sql.size()), &stmt_, nullptr);
    }
    ~Stmt() {
        if (stmt_)
            sqlite3_finalize(stmt_);
    }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;
    [[nodiscard]] sqlite3_stmt* get() const noexcept { return stmt_; }
    [[nodiscard]] explicit operator bool() const noexcept { return stmt_ != nullptr; }

private:
    sqlite3_stmt* stmt_{nullptr};
};

[[nodiscard]] inline std::string col_text(sqlite3_stmt* stmt, int i) {
    const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
    return text ? std::string{text} : std::string{};
}

} // namespace detail

// ────────────────────────────────────────────────────────── read_meta() ───

/// `since_day_ts` (default 0 — the whole table) drives `days_present`, the
/// only meta field that is itself window-scoped; every other field is a
/// tar_config scalar or the current `usage_live` open-run count and is not
/// affected by the caller's window.
[[nodiscard]] inline std::expected<MetaInfo, QueryError> read_meta(sqlite3* db,
                                                                    int64_t since_day_ts = 0) {
    if (!db)
        return std::unexpected(QueryError{"read_meta: null db"});

    MetaInfo meta;

    {
        detail::Stmt stmt{db, kOpenRunsSql};
        if (!stmt)
            return std::unexpected(QueryError{sqlite3_errmsg(db)});
        if (sqlite3_step(stmt.get()) == SQLITE_ROW)
            meta.open_runs = sqlite3_column_int64(stmt.get(), 0);
    }
    {
        detail::Stmt stmt{db, "SELECT COUNT(DISTINCT day_ts) FROM usage_daily WHERE day_ts >= ?"};
        if (!stmt)
            return std::unexpected(QueryError{sqlite3_errmsg(db)});
        sqlite3_bind_int64(stmt.get(), 1, since_day_ts);
        if (sqlite3_step(stmt.get()) == SQLITE_ROW)
            meta.days_present = sqlite3_column_int64(stmt.get(), 0);
    }

    const auto get_config = [&](std::string_view key, std::string_view def) -> std::string {
        detail::Stmt stmt{db, "SELECT value FROM tar_config WHERE key = ?"};
        if (!stmt)
            return std::string{def};
        sqlite3_bind_text(stmt.get(), 1, key.data(), static_cast<int>(key.size()),
                          SQLITE_TRANSIENT);
        if (sqlite3_step(stmt.get()) == SQLITE_ROW)
            return detail::col_text(stmt.get(), 0);
        return std::string{def};
    };
    const auto get_config_i64 = [&](std::string_view key, int64_t def) -> int64_t {
        const auto v = get_config(key, "");
        if (v.empty())
            return def;
        int64_t out = def;
        std::from_chars(v.data(), v.data() + v.size(), out);
        return out;
    };

    meta.coverage_since = get_config(kConfigCoverageSince, "-");
    meta.unmatched_stops = get_config_i64(kConfigUnmatchedStops, 0);
    meta.clock_anomalies = get_config_i64(kConfigClockAnomalies, 0);
    meta.gap_count = get_config_i64(kConfigGapCount, 0);
    meta.gap_lost_events = get_config_i64(kConfigGapLostEvents, 0);
    meta.gap_last_ts = get_config(kConfigGapLastTs, "-");
    meta.lag_events = get_config_i64(kConfigLagEvents, 0);
    meta.feeder_enabled = get_config(kConfigFeederEnabled, "true") != "false";
    meta.last_fold_ts = get_config(kConfigLastFoldTs, "-");

    return meta;
}

// ─────────────────────────────────────────────────────────── run_summary ──

[[nodiscard]] inline std::expected<SummaryResult, QueryError>
run_summary(sqlite3* db, const WindowParams& w, int64_t since_day_ts) {
    if (!db)
        return std::unexpected(QueryError{"run_summary: null db"});

    const std::string_view sql =
        w.by == WindowParams::By::run_count ? kSummarySqlByRunCount : kSummarySqlByRunTime;

    SummaryResult result;
    {
        detail::Stmt stmt{db, sql};
        if (!stmt)
            return std::unexpected(QueryError{sqlite3_errmsg(db)});
        sqlite3_bind_int64(stmt.get(), 1, since_day_ts);
        sqlite3_bind_int(stmt.get(), 2, w.top);
        int rc;
        while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
            UsageRow row;
            row.exe_key = detail::col_text(stmt.get(), 0);
            row.run_count = sqlite3_column_int64(stmt.get(), 1);
            row.total_seconds = sqlite3_column_int64(stmt.get(), 2);
            row.first_seen = sqlite3_column_int64(stmt.get(), 3);
            row.last_seen = sqlite3_column_int64(stmt.get(), 4);
            row.superseded_runs = sqlite3_column_int64(stmt.get(), 5);
            row.expired_runs = sqlite3_column_int64(stmt.get(), 6);
            result.rows.push_back(std::move(row));
        }
        if (rc != SQLITE_DONE)
            return std::unexpected(QueryError{sqlite3_errmsg(db)});
    }

    // Merge in distinct-user counts (usage_daily_user — COUNT(DISTINCT user)
    // only; the user names themselves never leave this function).
    std::map<std::string, int64_t> distinct_users;
    {
        detail::Stmt stmt{db, kDistinctUsersSql};
        if (!stmt)
            return std::unexpected(QueryError{sqlite3_errmsg(db)});
        sqlite3_bind_int64(stmt.get(), 1, since_day_ts);
        int rc;
        while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
            distinct_users[detail::col_text(stmt.get(), 0)] = sqlite3_column_int64(stmt.get(), 1);
        }
        if (rc != SQLITE_DONE)
            return std::unexpected(QueryError{sqlite3_errmsg(db)});
    }
    for (auto& row : result.rows) {
        if (const auto it = distinct_users.find(row.exe_key); it != distinct_users.end())
            row.distinct_users = it->second;
    }

    return result;
}

// ───────────────────────────────────────────────────────── run_last_used ──

[[nodiscard]] inline std::expected<std::vector<LastUsedRow>, QueryError>
run_last_used(sqlite3* db, std::optional<std::string_view> exe, int64_t since_30d_ts) {
    if (!db)
        return std::unexpected(QueryError{"run_last_used: null db"});

    const std::optional<std::string> normalised_exe =
        exe ? std::optional<std::string>(normalise_exe_key(*exe)) : std::nullopt;

    std::vector<LastUsedRow> out;
    detail::Stmt stmt{db, normalised_exe ? kLastUsedSqlOne : kLastUsedSqlAll};
    if (!stmt)
        return std::unexpected(QueryError{sqlite3_errmsg(db)});
    sqlite3_bind_int64(stmt.get(), 1, since_30d_ts);
    sqlite3_bind_int64(stmt.get(), 2, since_30d_ts);
    if (normalised_exe)
        sqlite3_bind_text(stmt.get(), 3, normalised_exe->c_str(),
                          static_cast<int>(normalised_exe->size()), SQLITE_TRANSIENT);

    int rc;
    while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
        LastUsedRow row;
        row.exe_key = detail::col_text(stmt.get(), 0);
        row.last_seen = sqlite3_column_int64(stmt.get(), 1);
        row.first_seen = sqlite3_column_int64(stmt.get(), 2);
        row.run_count_30d = sqlite3_column_int64(stmt.get(), 3);
        row.total_seconds_30d = sqlite3_column_int64(stmt.get(), 4);
        out.push_back(std::move(row));
    }
    if (rc != SQLITE_DONE)
        return std::unexpected(QueryError{sqlite3_errmsg(db)});

    return out;
}

// ───────────────────────────────────────────────────────── schema check ───

[[nodiscard]] inline bool usage_daily_table_exists(sqlite3* db) {
    if (!db)
        return false;
    detail::Stmt stmt{db, kUsageDailyExistsSql};
    if (!stmt)
        return false;
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

// ─────────────────────────────────────────────────────────── formatting ───

[[nodiscard]] inline std::string format_meta_line(const WindowParams& w, const MetaInfo& m) {
    char buf[512];
    std::snprintf(buf, sizeof buf,
                 "meta|window_days|%d|coverage_since|%s|days_present|%lld|open_runs|%lld|"
                 "unmatched_stops|%lld|clock_anomalies|%lld|gap_count|%lld|gap_lost_events|%lld|"
                 "gap_last_ts|%s|lag_events|%lld|feeder_enabled|%d|last_fold_ts|%s",
                 w.days, m.coverage_since.c_str(), static_cast<long long>(m.days_present),
                 static_cast<long long>(m.open_runs), static_cast<long long>(m.unmatched_stops),
                 static_cast<long long>(m.clock_anomalies), static_cast<long long>(m.gap_count),
                 static_cast<long long>(m.gap_lost_events), m.gap_last_ts.c_str(),
                 static_cast<long long>(m.lag_events), m.feeder_enabled ? 1 : 0,
                 m.last_fold_ts.c_str());
    return buf;
}

[[nodiscard]] inline std::string format_usage_row(const UsageRow& r) {
    char buf[512];
    std::snprintf(buf, sizeof buf, "usage|%s|%lld|%lld|%lld|%lld|%lld|%lld|%lld",
                 r.exe_key.c_str(), static_cast<long long>(r.run_count),
                 static_cast<long long>(r.total_seconds), static_cast<long long>(r.first_seen),
                 static_cast<long long>(r.last_seen), static_cast<long long>(r.distinct_users),
                 static_cast<long long>(r.superseded_runs),
                 static_cast<long long>(r.expired_runs));
    return buf;
}

[[nodiscard]] inline std::string format_last_used_row(const LastUsedRow& r) {
    char buf[320];
    std::snprintf(buf, sizeof buf, "last_used|%s|%lld|%lld|%lld|%lld", r.exe_key.c_str(),
                 static_cast<long long>(r.last_seen), static_cast<long long>(r.first_seen),
                 static_cast<long long>(r.run_count_30d),
                 static_cast<long long>(r.total_seconds_30d));
    return buf;
}

} // namespace yuzu::app_usage
