/**
 * app_usage_plugin.cpp — read-only Forensics-gated view over TAR's
 * usage_daily / usage_daily_user / usage_live tables inside tar.db.
 *
 * Actions:
 *   "summary"    — one `usage|` row per exe_key over a window (params:
 *                  days [1-365, default 30], top [1-500, default 25], by
 *                  [run_time|run_count, default run_time]), preceded by one
 *                  `meta|` row carrying the fold's health counters.
 *   "last_used"  — per-exe_key last/first-seen (all-time) plus a 30-day
 *                  run_count/total_seconds window. Optional `exe=<key>`
 *                  param narrows to one executable (normalised the same
 *                  way tar_usage.hpp normalises exe_key on write).
 *   "foreground" — always UNAVAILABLE/CONSTRAINED: per-session focus-time
 *                  attribution is not captured by this source (see
 *                  app_usage_parsers.hpp and app_usage.yaml).
 *
 * SEAM DECISION (see this package's spec): CommandContext (the type
 * execute() receives) has no get_config — only PluginContext (init()'s
 * argument) does, and no test ever runs a plugin's init(). So init()
 * caches `agent.data_dir` (same platform fallback as tar_plugin.cpp's
 * init() applies when it is empty), and every execute() call re-resolves
 * `<dir>/tar.db` through resolve_db_dir(), which reapplies the identical
 * fallback when the cached value is still empty — i.e. when a test (or any
 * other caller) drives execute() directly without ever calling init(),
 * this plugin still finds the platform-default tar.db, not a null path.
 *
 * ALL SQL lives in app_usage_parsers.hpp, which takes an already-open
 * `sqlite3*` — this file only opens the connection (read-only, WAL-aware —
 * tar.db is always WAL, tar_db.cpp) and formats the typed outcome into the
 * CC-07 result status + exit code contract.
 *
 * Reads ONLY usage_daily, usage_daily_user (COUNT(DISTINCT user) only),
 * `SELECT COUNT(*) FROM usage_live` (count only — never a pid/exe column),
 * and the named tar_config keys. NEVER TAR's raw process-event table or
 * any command-line column — see app_usage_parsers.hpp's file header and
 * the grep-based test that enforces this.
 */

#include <yuzu/plugin.hpp>

#include <cstdio>
#include <ctime>
#include <filesystem>
#include <optional>
#include <sqlite3.h>
#include <string>
#include <string_view>

#include "app_usage_parsers.hpp"

namespace {

namespace fs = std::filesystem;

// Same platform fallback tar_plugin.cpp's init() applies when
// `agent.data_dir` is empty (tar_plugin.cpp:565-580) — kept in sync by
// inspection, not by shared code, since app_usage cannot depend on tar's
// internal sources.
std::string platform_default_data_dir() {
#ifdef _WIN32
    return "C:\\ProgramData\\yuzu\\agent";
#else
    return "/var/lib/yuzu/agent";
#endif
}

// Opens tar.db read-only (SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX per this
// package's spec), sets a 2s busy timeout, and forces query_only — tar.db
// is always WAL (tar_db.cpp:430); same process/user, so the -shm sidecar is
// usable read-only. Returns nullptr and fills `out_err` on failure; the
// caller owns the returned handle (sqlite3_close()) on success.
sqlite3* open_readonly(const fs::path& path, std::string& out_err) {
    sqlite3* db = nullptr;
    const int rc = sqlite3_open_v2(path.string().c_str(), &db,
                                   SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nullptr);
    if (rc != SQLITE_OK) {
        out_err = db ? sqlite3_errmsg(db) : "sqlite3_open_v2 failed";
        if (db)
            sqlite3_close(db);
        return nullptr;
    }
    sqlite3_busy_timeout(db, 2000);
    sqlite3_exec(db, "PRAGMA query_only=1", nullptr, nullptr, nullptr);
    return db;
}

// Aligns a unix timestamp down to the start of its UTC day — usage_daily's
// day_ts column is day-aligned (tar_usage.hpp, P21).
constexpr int64_t kSecondsPerDay = 86400;
int64_t align_to_day(int64_t ts) {
    return ts - (ts % kSecondsPerDay);
}

std::string get_tar_config(sqlite3* db, std::string_view key, std::string_view def) {
    sqlite3_stmt* stmt = nullptr;
    static constexpr std::string_view kSql = "SELECT value FROM tar_config WHERE key = ?";
    if (sqlite3_prepare_v2(db, kSql.data(), static_cast<int>(kSql.size()), &stmt, nullptr) !=
        SQLITE_OK)
        return std::string{def};
    sqlite3_bind_text(stmt, 1, key.data(), static_cast<int>(key.size()), SQLITE_TRANSIENT);
    std::string out{def};
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (text)
            out = text;
    }
    sqlite3_finalize(stmt);
    return out;
}

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "summary",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "tar.db usage_daily (derived from TAR process/procfs)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "tar.db usage_daily (derived from TAR process/endpoint_security or sysctl poll)",
         "inherits the process source's names-only constraint; ES entitlement absent -> poll "
         "granularity"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "tar.db usage_daily (derived from TAR process/etw)", nullptr},
    },
    {
        /* .action      = */ "last_used",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "tar.db usage_daily (derived from TAR process/procfs)",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "tar.db usage_daily (derived from TAR process/endpoint_security or sysctl poll)",
         "inherits the process source's names-only constraint; ES entitlement absent -> poll "
         "granularity"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "tar.db usage_daily (derived from TAR process/etw)", nullptr},
    },
    {
        /* .action      = */ "foreground",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "not captured",
         "foreground/focus time and per-session attribution are not captured; promoted by the "
         "user-context-bridge roadmap without a schema change"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "not captured",
         "foreground/focus time and per-session attribution are not captured; promoted by the "
         "user-context-bridge roadmap without a schema change"},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "not captured",
         "foreground/focus time and per-session attribution are not captured; promoted by the "
         "user-context-bridge roadmap without a schema change"},
    },
};

} // namespace

class AppUsagePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "app_usage"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Read-only machine-scope app usage inventory derived from TAR's usage fold "
               "(no pid, command line, or user names in output)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"summary", "last_used", "foreground", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        const auto configured = ctx.get_config("agent.data_dir");
        data_dir_ = configured.empty() ? platform_default_data_dir() : std::string{configured};
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "summary")
            return do_summary(ctx, params);
        if (action == "last_used")
            return do_last_used(ctx, params);
        if (action == "foreground")
            return do_foreground(ctx);

        ctx.write_output(std::string{"unknown action: "} + std::string{action});
        return 1;
    }

private:
    // No env-var/param override of the db path — an operator-supplied path
    // would be an arbitrary-file read (this package's spec, "boundaries").
    // When init() never ran (every dispatcher test drives execute()
    // directly — see this file's header), data_dir_ is still empty here,
    // so the platform fallback is reapplied on every call.
    fs::path resolve_db_path() const {
        const std::string dir = data_dir_.empty() ? platform_default_data_dir() : data_dir_;
        return fs::path{dir} / "tar.db";
    }

    int do_summary(yuzu::CommandContext& ctx, yuzu::Params& params) {
        const auto path = resolve_db_path();
        std::string err;
        sqlite3* db = open_readonly(path, err);
        if (!db) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, err);
            ctx.write_output("constrained|tar_db_unavailable|" + path.string() + "|" + err);
            return 1;
        }

        const int result = do_summary_on(ctx, params, db);
        sqlite3_close(db);
        return result;
    }

    int do_summary_on(yuzu::CommandContext& ctx, yuzu::Params& params, sqlite3* db) {
        if (get_tar_config(db, yuzu::app_usage::kConfigUsageEnabled, "true") == "false") {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, "usage_enabled=false");
            ctx.write_output("constrained|usage_source_disabled");
            return 0;
        }
        if (!yuzu::app_usage::usage_daily_table_exists(db)) {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "usage_daily table absent (older TAR schema)");
            ctx.write_output("constrained|usage_schema_missing");
            return 0;
        }

        const auto window = yuzu::app_usage::parse_window_params(
            params.get("days"), params.get("top"), params.get("by"));
        if (window.by == yuzu::app_usage::WindowParams::By::unmodelled) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "unrecognised 'by' param");
            ctx.write_output("error|bad_param|by");
            return 1;
        }

        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        const int64_t since_day_ts = align_to_day(now) - static_cast<int64_t>(window.days - 1) * kSecondsPerDay;

        const auto meta = yuzu::app_usage::read_meta(db, since_day_ts);
        if (!meta) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, meta.error().detail);
            ctx.write_output("unavailable|query_failed|" + meta.error().detail);
            return 1;
        }
        const auto summary = yuzu::app_usage::run_summary(db, window, since_day_ts);
        if (!summary) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, summary.error().detail);
            ctx.write_output("unavailable|query_failed|" + summary.error().detail);
            return 1;
        }

        ctx.write_output(yuzu::app_usage::format_meta_line(window, *meta));
        for (const auto& row : summary->rows)
            ctx.write_output(yuzu::app_usage::format_usage_row(row));

        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        return 0;
    }

    int do_last_used(yuzu::CommandContext& ctx, yuzu::Params& params) {
        const auto path = resolve_db_path();
        std::string err;
        sqlite3* db = open_readonly(path, err);
        if (!db) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, err);
            ctx.write_output("constrained|tar_db_unavailable|" + path.string() + "|" + err);
            return 1;
        }

        const int result = do_last_used_on(ctx, params, db);
        sqlite3_close(db);
        return result;
    }

    int do_last_used_on(yuzu::CommandContext& ctx, yuzu::Params& params, sqlite3* db) {
        if (get_tar_config(db, yuzu::app_usage::kConfigUsageEnabled, "true") == "false") {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, "usage_enabled=false");
            ctx.write_output("constrained|usage_source_disabled");
            return 0;
        }
        if (!yuzu::app_usage::usage_daily_table_exists(db)) {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "usage_daily table absent (older TAR schema)");
            ctx.write_output("constrained|usage_schema_missing");
            return 0;
        }

        std::optional<std::string_view> exe;
        if (params.has("exe"))
            exe = params.get("exe");

        const int64_t now = static_cast<int64_t>(std::time(nullptr));
        const int64_t since_30d_ts = align_to_day(now) - 29 * kSecondsPerDay;

        const auto rows = yuzu::app_usage::run_last_used(db, exe, since_30d_ts);
        if (!rows) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                  YUZU_RESULT_COMPLETENESS_PARTIAL, rows.error().detail);
            ctx.write_output("unavailable|query_failed|" + rows.error().detail);
            return 1;
        }

        for (const auto& row : *rows)
            ctx.write_output(yuzu::app_usage::format_last_used_row(row));

        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        return 0;
    }

    int do_foreground(yuzu::CommandContext& ctx) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "foreground/focus attribution not captured by this source");
        ctx.write_output(
            "constrained|foreground_not_captured|user-context-bridge roadmap (session-scope "
            "attribution)");
        return 1;
    }

    std::string data_dir_;
};

YUZU_PLUGIN_EXPORT(AppUsagePlugin)
