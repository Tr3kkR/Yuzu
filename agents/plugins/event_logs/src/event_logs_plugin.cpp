/**
 * event_logs_plugin.cpp — Event log viewer plugin for Yuzu
 *
 * Actions:
 *   "errors" — Recent error events from a specified log.
 *              Params: log (optional, default "System"),
 *                      hours (optional, default "24").
 *   "query"  — Search events by keyword.
 *              Params: log (required), filter (required),
 *                      count (optional, default "50").
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   error|timestamp|event_id|source|message      (Windows)
 *   error|timestamp|unit|message                 (Linux/macOS)
 *   event|timestamp|level|event_id|source|message (Windows)
 *   event|timestamp|unit|message                 (Linux/macOS)
 *
 * Acquisition (Wave-4 PR4.2, ADR-3002):
 *   Windows — wevtapi EvtQuery/EvtRender (rung 1; the users plugin's
 *             #3244 precedent). The former PowerShell Get-WinEvent _popen
 *             leg is gone.
 *   Linux   — sd_journal bounded read (rung 1) behind the shared
 *             `systemd_guard` meson feature, falling back to a bounded
 *             `journalctl` argv invocation (rung 2, pre-split argv, no
 *             shell) when compiled out or the journal is unreachable. The
 *             former `/bin/sh -c` leg is gone.
 *   macOS   — `log show` pre-split argv through the bounded runner
 *             (rung 2, shipped earlier; event_logs_macos.hpp owns the
 *             result decision).
 *
 * Parsing/formatting is pure and lives in event_logs_parsers.hpp
 * (fixture-tested on every host); sd_journal I/O lives in
 * event_logs_journal.hpp. This file is the thin OS-facing shell.
 */

#include "event_logs_macos.hpp"
#include "event_logs_parsers.hpp"

#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <iterator> // std::size (EvtNext batch array bound)
#include <windows.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <winevt.h>    // EvtQuery / EvtNext / EvtRender / EvtClose
#pragma comment(lib, "wevtapi.lib")
#endif

#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)
#include "event_logs_journal.hpp"
#endif

namespace {

namespace parsers = yuzu::event_logs_parsers;

#ifdef __APPLE__
// Hard wall-clock bound on macOS `log show`: it has no built-in timeout and
// GNU `timeout` isn't available on macOS, so an unbounded shell-out could
// otherwise block the collection thread indefinitely (#2273).
constexpr auto kLogShowDeadline = std::chrono::milliseconds(10000);
#endif

// ── Windows wevtapi reader ─────────────────────────────────────────────────

#ifdef _WIN32

// EVT_HANDLE must be closed with EvtClose, not CloseHandle — a local
// single-owner guard, same shape as users_plugin.cpp's / tar_netconn_win
// .cpp's EvtGuard (deliberately file-local per the plugin-isolation
// precedent).
struct EvtGuard {
    EVT_HANDLE h{nullptr};
    explicit EvtGuard(EVT_HANDLE handle) : h{handle} {}
    ~EvtGuard() {
        if (h)
            ::EvtClose(h);
    }
    EvtGuard(const EvtGuard&) = delete;
    EvtGuard& operator=(const EvtGuard&) = delete;
    explicit operator bool() const { return h != nullptr; }
};

// Render one event to UTF-8 XML (size-then-fill, users/tar shape).
std::string render_event_xml(EVT_HANDLE event) {
    DWORD used = 0, props = 0;
    ::EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &used, &props);
    if (used == 0)
        return {};
    std::wstring buf(used / sizeof(wchar_t) + 1, L'\0');
    if (!::EvtRender(nullptr, event, EvtRenderEventXml, used, buf.data(), &used, &props))
        return {};
    return yuzu::win::from_wide(buf.c_str());
}

// ADR-3002 rung-1 bounded-broker-call requirement: EvtNext is a
// daemon-mediated call (the Event Log service) with a bounded wait mode, so
// INFINITE is not an option — a wedged/heavily-contended service would
// otherwise pin the instruction worker forever. Same 10s ceiling as the
// users plugin.
constexpr DWORD kEvtNextTimeoutMs = 10'000;

// Distinguishes WHY a channel query failed so the operator gets an honest
// message and the correct ABI4 result status (the users plugin's
// chaos-injector-driven shape) instead of one collapsed error string.
enum class EvtQueryOutcome { kOk, kAccessDenied, kChannelNotFound, kTimeout, kOtherError };

struct EvtQueryFailureInfo {
    const char* message;
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    const char* provenance;
};

EvtQueryFailureInfo describe_evt_query_failure(EvtQueryOutcome outcome) {
    switch (outcome) {
    case EvtQueryOutcome::kAccessDenied:
        return {"Cannot access the event log channel (requires elevated privileges)",
                YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                "event_logs_win:access_denied"};
    case EvtQueryOutcome::kChannelNotFound:
        return {"Event log channel not found or unavailable", YUZU_RESULT_STATUS_UNAVAILABLE,
                YUZU_RESULT_COMPLETENESS_PARTIAL, "event_logs_win:channel_not_found"};
    case EvtQueryOutcome::kTimeout:
        return {"Event log query timed out (service may be degraded)",
                YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                "event_logs_win:evt_next_timeout"};
    case EvtQueryOutcome::kOk:
    case EvtQueryOutcome::kOtherError:
    default:
        return {"Event log query failed", YUZU_RESULT_STATUS_UNAVAILABLE,
                YUZU_RESULT_COMPLETENESS_PARTIAL, "event_logs_win:evt_query_failed"};
    }
}

// Queries `channel` with `xpath`, newest-first, rendering up to `cap` events
// and folding each through parsers::parse_win_events into `out`. Modeled on
// users_plugin.cpp::query_logon_events: a non-kOk outcome means EvtQuery
// itself failed OR EvtNext failed mid-query (incl. a timeout against a
// wedged service) — never reported as a clean-but-empty success. kOk with
// an empty `out` is the distinct, honest "queried fine, nothing there".
// Every EVT_HANDLE — including batch handles seen after the cap — is owned
// by an EvtGuard.
EvtQueryOutcome query_win_events(const wchar_t* channel, const wchar_t* xpath, std::size_t cap,
                                 std::vector<parsers::WinEvent>& out) {
    EvtGuard q{::EvtQuery(nullptr, channel, xpath,
                          EvtQueryChannelPath | EvtQueryReverseDirection)};
    if (!q) {
        switch (::GetLastError()) {
        case ERROR_ACCESS_DENIED:
            return EvtQueryOutcome::kAccessDenied;
        case ERROR_EVT_CHANNEL_NOT_FOUND:
        case ERROR_FILE_NOT_FOUND:
            return EvtQueryOutcome::kChannelNotFound;
        default:
            return EvtQueryOutcome::kOtherError;
        }
    }

    std::size_t taken = 0;
    while (taken < cap) {
        EVT_HANDLE raw[64]{};
        DWORD got = 0;
        if (!::EvtNext(q.h, static_cast<DWORD>(std::size(raw)), raw, kEvtNextTimeoutMs, 0,
                       &got)) {
            const DWORD err = ::GetLastError();
            if (err != ERROR_NO_MORE_ITEMS) {
                // Unlike the users plugin's fixed Security channel, the
                // channel here is operator-selected, and a bad name can
                // surface at EvtNext rather than EvtQuery on some builds —
                // map it to the same honest outcome either way.
                if (err == ERROR_EVT_CHANNEL_NOT_FOUND || err == ERROR_FILE_NOT_FOUND)
                    return EvtQueryOutcome::kChannelNotFound;
                return err == ERROR_TIMEOUT ? EvtQueryOutcome::kTimeout
                                            : EvtQueryOutcome::kOtherError;
            }
            break; // legitimately exhausted
        }
        for (DWORD i = 0; i < got; ++i) {
            EvtGuard ev{raw[i]};
            if (taken >= cap)
                continue; // keep closing remaining handles in this batch
            const std::string xml = render_event_xml(ev.h);
            if (xml.empty())
                continue;
            for (auto& parsed : parsers::parse_win_events(xml)) {
                out.push_back(std::move(parsed));
                if (++taken >= cap)
                    break;
            }
        }
    }
    return EvtQueryOutcome::kOk;
}

#endif // _WIN32

// ── Linux journal legs ─────────────────────────────────────────────────────

#ifdef __linux__

// Wall-clock budget for one native journal read — matches the macOS
// `log show` deadline; the journalctl argv fallback runs under the runner's
// own 20s deadline.
constexpr auto kJournalReadBudget = std::chrono::milliseconds(10'000);

// Bound on entries examined by a native `query` scan (a rare filter must
// not walk an entire large journal; with the wall-clock budget this is the
// ADR-3002 bound for the read).
constexpr std::size_t kJournalScanCap = 50'000;

#if defined(YUZU_HAVE_LIBSYSTEMD)

namespace journal = yuzu::event_logs_journal;

// Emits `out` (newest-first collection) as oldest-first rows, or the
// clean-empty sentinel. Shared by both native actions.
void emit_journal_entries(yuzu::CommandContext& ctx, std::string_view prefix,
                          std::vector<journal::Entry>& entries, std::string_view empty_message,
                          bool truncated, const char* truncated_provenance) {
    if (truncated) {
        spdlog::warn("event_logs: native journal read hit its bound (partial result)");
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              truncated_provenance);
    }
    if (entries.empty()) {
        ctx.write_output(std::format("{}|none|-|{}", prefix, empty_message));
        return;
    }
    std::reverse(entries.begin(), entries.end());
    for (const auto& e : entries) {
        parsers::JournalRow row{journal::format_short_iso(e.realtime_usec),
                                parsers::journal_unit_string(e.identifier, e.pid,
                                                             e.systemd_unit),
                                e.message};
        ctx.write_output(parsers::journal_row(prefix, row));
    }
}

// Native sd_journal legs. Return true when the read was handled natively
// (including the honest-empty and honest-partial cases); false ONLY when the
// journal could not be opened/read at all, so the caller falls through to
// the journalctl argv fallback — an sd_journal failure is never reported as
// "no events" (device_identity's sd-bus fallback contract).
bool try_journal_errors(yuzu::CommandContext& ctx, int hours) {
    std::vector<journal::Entry> entries;
    const auto res = journal::read_errors(hours, 100, kJournalReadBudget, entries);
    if (res.status != journal::ReadStatus::kOk)
        return false;
    emit_journal_entries(ctx, "error", entries, "No error events found", res.truncated,
                         "event_logs_journal:errors_truncated");
    return true;
}

bool try_journal_query(yuzu::CommandContext& ctx, std::string_view filter, int count) {
    std::vector<journal::Entry> entries;
    const auto res = journal::read_matches(filter, static_cast<std::size_t>(count),
                                           kJournalScanCap, kJournalReadBudget, entries);
    if (res.status != journal::ReadStatus::kOk)
        return false;
    emit_journal_entries(ctx, "event", entries, "No matching events found", res.truncated,
                         "event_logs_journal:query_truncated");
    return true;
}

#else // !YUZU_HAVE_LIBSYSTEMD

// systemd_guard compiled the native leg out: always fall through to the
// journalctl argv fallback (firewall_plugin.cpp's stub-seam pattern — the
// call sites stay #if-free).
bool try_journal_errors(yuzu::CommandContext&, int) { return false; }
bool try_journal_query(yuzu::CommandContext&, std::string_view, int) { return false; }

#endif // YUZU_HAVE_LIBSYSTEMD

// Bounded `journalctl` argv fallback (rung 2 — pre-split argv through the
// shared runner, no shell, no redirection: the old leg's `2>/dev/null` is
// merge_stderr=false and its shell string is gone). `-q` suppresses the
// "-- No entries --" info line the old parser would have mis-read as a row.
int run_journalctl_fallback(yuzu::CommandContext& ctx, std::vector<std::string> argv,
                            std::string_view prefix, std::string_view empty_message,
                            const char* unavailable_provenance) {
    auto result = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{20},
                                             .max_lines = 500,
                                             .merge_stderr = false,
                                             .stop_after_max_lines = true});
    if (!result.tool_ran) {
        // journalctl absent (non-systemd distro with the native leg also
        // unavailable): an honest typed status, never a fabricated
        // "no events".
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              unavailable_provenance);
        ctx.write_output(std::format("{}|none|-|{}", prefix, empty_message));
        return 0;
    }
    if (result.timed_out) {
        spdlog::warn("event_logs: journalctl fallback timed out (partial result)");
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              unavailable_provenance);
    }
    if (result.lines.empty()) {
        ctx.write_output(std::format("{}|none|-|{}", prefix, empty_message));
        return 0;
    }
    for (const auto& line : result.lines) {
        if (line.empty())
            continue;
        ctx.write_output(parsers::journal_row(prefix, parsers::parse_short_iso_line(line)));
    }
    return 0;
}

#endif // __linux__

// ── errors action ──────────────────────────────────────────────────────────

int do_errors(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto log_name = yuzu::util::sanitize_input(params.get("log"));
    if (log_name.empty())
        log_name = "System";
    const int hours = parsers::clamp_int_param(params.get("hours"), 24, 1, 720);

#ifdef _WIN32
    // Level=2 (Error) events in the last `hours` hours, newest-first —
    // byte-for-byte the old Get-WinEvent -FilterHashtable semantics.
    // `hours` is an already-clamped integer and the channel comes from the
    // allowlist sanitizer + to_wide, passed as the EvtQuery Path argument —
    // operator input is never spliced into the XPath.
    const std::wstring channel = yuzu::win::to_wide(log_name);
    const long long window_ms = static_cast<long long>(hours) * 3'600'000LL;
    const std::wstring xpath = yuzu::win::to_wide(std::format(
        "*[System[(Level=2) and TimeCreated[timediff(@SystemTime) <= {}]]]", window_ms));
    std::vector<parsers::WinEvent> events;
    const auto outcome = query_win_events(channel.c_str(), xpath.c_str(), 100, events);
    if (outcome != EvtQueryOutcome::kOk) {
        const auto info = describe_evt_query_failure(outcome);
        ctx.set_result_status(info.status, info.completeness, info.provenance);
        ctx.write_output(std::format("error|none|{}|-|-", info.message));
        return 0;
    }
    if (events.empty()) {
        ctx.write_output("error|none|No error events found|-|-");
        return 0;
    }
    for (const auto& ev : events)
        ctx.write_output(parsers::win_error_row(ev));

#elif defined(__linux__)
    if (try_journal_errors(ctx, hours))
        return 0;
    return run_journalctl_fallback(
        ctx,
        {"/usr/bin/journalctl", "-q", "-p", "err", "--since",
         std::format("{} hours ago", hours), "-n", "100", "--no-pager", "-o", "short-iso"},
        "error", "No error events found", "event_logs_journalctl:errors_unavailable");

#elif defined(__APPLE__)
    constexpr std::size_t kMaxLines = 100;
    std::vector<std::string> argv{"/usr/bin/log", "show",
                                   "--predicate",  "messageType == error",
                                   "--last",       std::format("{}h", hours),
                                   "--style",      "compact"};
    auto result = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = kLogShowDeadline,
                                              .max_lines = kMaxLines,
                                              .merge_stderr = false,
                                              .stop_after_max_lines = true});

    // Surface degraded `log show` runs to operators: the sentinel row + rc are
    // honest but only visible by parsing returned rows, so a hung/failed/
    // truncated shell-out would otherwise be silent in the agent log.
    if (result.timed_out || !result.tool_ran || result.exit_code != 0 || result.output_truncated) {
        spdlog::warn("event_logs errors: macOS 'log show' {} (timed_out={}, tool_ran={}, "
                     "exit_code={}, output_truncated={})",
                     result.timed_out         ? "timed out"
                     : !result.tool_ran       ? "unavailable"
                     : result.exit_code != 0  ? "failed"
                                              : "output truncated",
                     result.timed_out, result.tool_ran, result.exit_code, result.output_truncated);
    }

    // decide_log_show_output is the single source of truth for the
    // SubprocessResult -> (rows, rc) decision (BR-08) -- this shell only
    // calls it and emits whatever it returns.
    auto decision = yuzu::event_logs_macos::decide_log_show_output(result, "error",
                                                                     "No error events found");
    for (const auto& row : decision.rows)
        ctx.write_output(row);
    return decision.rc;

#else
    ctx.write_output("error|platform not supported|-|-");
#endif
    return 0;
}

// ── query action ───────────────────────────────────────────────────────────

int do_query(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto log_name = yuzu::util::sanitize_input(params.get("log"));
    if (log_name.empty()) {
        ctx.write_output("error|'log' parameter is required");
        return 1;
    }

    auto filter = yuzu::util::sanitize_input(params.get("filter"));
    if (filter.empty()) {
        ctx.write_output("error|'filter' parameter is required");
        return 1;
    }

    const int count = parsers::clamp_int_param(params.get("count"), 50, 1, 500);

#ifdef _WIN32
    // Newest `count` events from the channel, filtered in-process by
    // case-insensitive keyword — the old Get-WinEvent -MaxEvents N |
    // Where-Object Message -like pattern: the filter applies WITHIN the
    // newest `count` events, and never reaches the XPath (operator input is
    // data, not query text).
    const std::wstring channel = yuzu::win::to_wide(log_name);
    std::vector<parsers::WinEvent> events;
    const auto outcome =
        query_win_events(channel.c_str(), L"*", static_cast<std::size_t>(count), events);
    if (outcome != EvtQueryOutcome::kOk) {
        const auto info = describe_evt_query_failure(outcome);
        ctx.set_result_status(info.status, info.completeness, info.provenance);
        ctx.write_output(std::format("event|none|-|-|-|{}", info.message));
        return 0;
    }
    bool any = false;
    for (const auto& ev : events) {
        if (!parsers::win_event_matches(ev, filter))
            continue;
        ctx.write_output(parsers::win_event_row(ev));
        any = true;
    }
    if (!any)
        ctx.write_output("event|none|-|-|-|No matching events found");

#elif defined(__linux__)
    if (try_journal_query(ctx, filter, count))
        return 0;
    return run_journalctl_fallback(
        ctx,
        {"/usr/bin/journalctl", "-q", std::format("--grep={}", filter), "-n",
         std::format("{}", count), "--no-pager", "-o", "short-iso"},
        "event", "No matching events found", "event_logs_journalctl:query_unavailable");

#elif defined(__APPLE__)
    std::vector<std::string> argv{"/usr/bin/log",
                                   "show",
                                   "--predicate",
                                   std::format("eventMessage contains \"{}\"", filter),
                                   "--last",
                                   "24h",
                                   "--style",
                                   "compact"};
    auto result = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = kLogShowDeadline,
                                              .max_lines = static_cast<std::size_t>(count),
                                              .merge_stderr = false,
                                              .stop_after_max_lines = true});

    // Surface degraded `log show` runs to operators: the sentinel row + rc are
    // honest but only visible by parsing returned rows, so a hung/failed/
    // truncated shell-out would otherwise be silent in the agent log.
    if (result.timed_out || !result.tool_ran || result.exit_code != 0 || result.output_truncated) {
        spdlog::warn("event_logs query: macOS 'log show' {} (timed_out={}, tool_ran={}, "
                     "exit_code={}, output_truncated={})",
                     result.timed_out         ? "timed out"
                     : !result.tool_ran       ? "unavailable"
                     : result.exit_code != 0  ? "failed"
                                              : "output truncated",
                     result.timed_out, result.tool_ran, result.exit_code, result.output_truncated);
    }

    // decide_log_show_output is the single source of truth for the
    // SubprocessResult -> (rows, rc) decision (BR-08) -- this shell only
    // calls it and emits whatever it returns.
    auto decision = yuzu::event_logs_macos::decide_log_show_output(result, "event",
                                                                     "No matching events found");
    for (const auto& row : decision.rows)
        ctx.write_output(row);
    return decision.rc;

#else
    ctx.write_output("error|platform not supported");
#endif
    return 0;
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// windows: wevtapi EvtQuery/EvtRender against the operator-selected channel
// -- rung 1 (native broker API, bounded EvtNext wait; users #3244
// precedent). The PowerShell Get-WinEvent _popen leg is deleted.
// linux: sd_journal bounded local read -- rung 1 -- behind the shared
// `systemd_guard` feature (the same knob device_identity and firewall
// consume; never a second option), with a declared bounded `journalctl`
// pre-split-argv fallback (rung 2) when compiled out or the journal is
// unreachable at runtime. The `/bin/sh -c` leg is deleted. (Contrast
// agents/core/src/dex_linux_journal.hpp, which deliberately keeps a
// journalctl shell-out to stay musl-buildable with no feature-gate
// coupling: this plugin's siblings already couple to systemd_guard, and the
// argv fallback preserves the musl/no-systemd story.)
// macos: /usr/bin/log show invoked with a pre-split argv (never /bin/sh -c)
// through run_bounded_subprocess -- rung 2, ships via event_logs_macos.hpp.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"errors",
     /* linux   = */
     {YUZU_SUPPORT_SUPPORTED, 1, "sd_journal (bounded local read, PRIORITY<=err)",
      "falls back to a bounded journalctl argv invocation (rung 2) when libsystemd is "
      "compiled out (-Dsystemd_guard) or the journal is unreachable"},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "log_show", nullptr},
     /* windows = */
     {YUZU_SUPPORT_SUPPORTED, 1, "wevtapi (EvtQuery/EvtRender, Level=2, bounded EvtNext)",
      nullptr}},
    {"query",
     /* linux   = */
     {YUZU_SUPPORT_SUPPORTED, 1, "sd_journal (bounded local read, keyword match)",
      "falls back to a bounded journalctl argv invocation (rung 2) when libsystemd is "
      "compiled out (-Dsystemd_guard) or the journal is unreachable"},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "log_show", nullptr},
     /* windows = */
     {YUZU_SUPPORT_SUPPORTED, 1, "wevtapi (EvtQuery/EvtRender, bounded EvtNext)", nullptr}},
};

} // namespace

class EventLogsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "event_logs"; }
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Queries system event logs for errors and filtered events";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"errors", "query", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "errors")
            return do_errors(ctx, params);
        if (action == "query")
            return do_query(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(EventLogsPlugin)
