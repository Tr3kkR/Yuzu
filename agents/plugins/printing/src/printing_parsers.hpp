// printing_parsers.hpp — PURE row types, IPP -> row mappers, winspool
// bit -> row mappers, and pipe-delimited output formatting for the
// `printing` plugin. No OS headers, no I/O — every symbol here is usable by
// the unit tests on every host, per printing_ipp.hpp's own posture.
//
// DOCUMENT-TITLE POSTURE (decided): `jobs` ships `document` (the job's
// name/title) because it is the identifier an operator needs to read in
// order to pick which job a subsequent `clear_queue` call should target —
// there is no other operator-facing way to distinguish two jobs from the
// same owner on the same printer. This is user content (an end user's
// document name reaches the operator's screen), so it carries the same
// posture as any other instruction-result field: retained only as part of
// the server's ordinary instruction-result history, never forwarded to
// daily-sync, TAR, or DEX. Retaining COMPLETED job history beyond a single
// `jobs` call is explicitly deferred (D4) — this plugin has no history
// store of its own.
#pragma once

#include "printing_ipp.hpp"

#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <ctime>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::printing {

struct PrinterRow {
    std::string name;
    std::string state;         // idle | processing | stopped | unknown
    std::string state_reasons; // comma-joined values, or "-"
    bool is_default = false;
    std::string make_model;
    std::string uri;
    int64_t queued_jobs = -1; // -1 = unknown
};

struct JobRow {
    std::string printer;
    int64_t job_id = 0;
    std::string owner;
    std::string document; // see file banner — DOCUMENT-TITLE POSTURE
    std::string status;   // pending|held|processing|stopped|canceled|aborted|completed|unknown
    std::string submitted_at; // ISO-8601 UTC, or "-"
    int64_t size_bytes = -1;  // -1 = unknown
};

namespace detail {

[[nodiscard]] inline const ipp::Attr* find_attr(const std::vector<ipp::Attr>& attrs,
                                                  std::string_view name) {
    for (const auto& a : attrs) {
        if (a.name == name)
            return &a;
    }
    return nullptr;
}

[[nodiscard]] inline std::string first_value(const ipp::Attr* a, std::string_view fallback = {}) {
    if (a != nullptr && !a->values.empty())
        return a->values.front();
    return std::string(fallback);
}

// RFC 8010 §3.5.2: the `integer`/`enum` value tags carry a 4-byte, two's
// complement, BIG-ENDIAN binary integer — never decimal ASCII text. The
// wire bytes land in `Attr::values` as a `std::string` purely as a byte
// container (decode()/encode_request() never interpret its content), so
// this reads it back as the 4 raw bytes it is.
[[nodiscard]] inline std::optional<int64_t> first_int(const ipp::Attr* a) {
    if (a == nullptr || a->values.empty())
        return std::nullopt;
    const std::string& s = a->values.front();
    if (s.size() != 4)
        return std::nullopt;
    const int32_t v = (static_cast<int32_t>(static_cast<uint8_t>(s[0])) << 24) |
                       (static_cast<int32_t>(static_cast<uint8_t>(s[1])) << 16) |
                       (static_cast<int32_t>(static_cast<uint8_t>(s[2])) << 8) |
                       static_cast<int32_t>(static_cast<uint8_t>(s[3]));
    return static_cast<int64_t>(v);
}

[[nodiscard]] inline std::string printer_state_from_ipp_enum(std::optional<int64_t> state) {
    if (!state)
        return "unknown";
    switch (*state) {
    case 3:
        return "idle";
    case 4:
        return "processing";
    case 5:
        return "stopped";
    default:
        return "unknown";
    }
}

[[nodiscard]] inline std::string job_state_from_ipp_enum(std::optional<int64_t> state) {
    if (!state)
        return "unknown";
    switch (*state) {
    case 3:
        return "pending";
    case 4:
        return "held";
    case 5:
        return "processing";
    case 6:
        return "stopped";
    case 7:
        return "canceled";
    case 8:
        return "aborted";
    case 9:
        return "completed";
    default:
        return "unknown";
    }
}

/// RFC 2911 §4.1.14 `dateTime` — 11 raw octets: year (uint16 BE), month,
/// day, hour, minute, second, deci-second, direction-from-UTC ('+'/'-'),
/// hours-from-UTC, minutes-from-UTC. This is the wire value IPP attributes
/// like `date-time-at-creation` carry, distinct from `time-at-creation`
/// (a plain `integer` relative to the printer's own `printer-up-time`, NOT
/// Unix epoch — using it as epoch seconds silently produces a bogus
/// near-1970 timestamp on any implementation whose uptime counter is not
/// coincidentally close to the real epoch). Converts to the real UTC
/// instant by undoing the printer's reported UTC offset, never assuming
/// the printer's local clock is itself UTC.
[[nodiscard]] inline std::string iso8601_from_ipp_datetime(std::string_view raw) {
    if (raw.size() != 11)
        return "-";
    const auto b = [&](std::size_t i) { return static_cast<unsigned char>(raw[i]); };
    const int year = (b(0) << 8) | b(1);
    const int month = b(2), day = b(3), hour = b(4), minute = b(5), second = b(6);
    const char direction = raw[8];
    const int off_hours = b(9), off_minutes = b(10);
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60 ||
        (direction != '+' && direction != '-'))
        return "-";

    std::tm tm{};
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;
    // Interpret tm as a UTC-naive wall clock (the printer's local time at
    // its reported offset) without consulting any local timezone database.
#if defined(_WIN32)
    const std::time_t naive = _mkgmtime(&tm);
#else
    const std::time_t naive = timegm(&tm);
#endif
    if (naive == static_cast<std::time_t>(-1))
        return "-";
    const int off_seconds = (off_hours * 3600) + (off_minutes * 60);
    const std::time_t utc = (direction == '-') ? (naive + off_seconds) : (naive - off_seconds);

    std::tm out_tm{};
#if defined(_WIN32)
    if (gmtime_s(&out_tm, &utc) != 0)
        return "-";
#else
    if (gmtime_r(&utc, &out_tm) == nullptr)
        return "-";
#endif
    char buf[32];
    const std::size_t n = std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &out_tm);
    if (n == 0)
        return "-";
    return std::string(buf, n);
}

} // namespace detail

/// Maps every printer-attributes group (0x04) in a CUPS-Get-Printers
/// response into a `PrinterRow`. `default_name`, when non-empty, marks the
/// one row whose `printer-name` matches it as `is_default` — the plugin
/// resolves that name from a separate CUPS-Get-Default call.
[[nodiscard]] inline std::vector<PrinterRow>
printers_from_ipp(const ipp::Message& msg, std::string_view default_name = {}) {
    std::vector<PrinterRow> out;
    for (const auto& [group_tag, attrs] : msg.groups) {
        if (group_tag != ipp::kTagPrinterAttributes)
            continue;
        const std::string name = detail::first_value(detail::find_attr(attrs, "printer-name"));
        if (name.empty())
            continue; // defensive: a real CUPS response always sends this

        PrinterRow row;
        row.name = name;
        row.state =
            detail::printer_state_from_ipp_enum(detail::first_int(detail::find_attr(attrs, "printer-state")));
        if (const auto* reasons = detail::find_attr(attrs, "printer-state-reasons");
            reasons != nullptr && !reasons->values.empty()) {
            std::string joined;
            for (std::size_t i = 0; i < reasons->values.size(); ++i) {
                if (i != 0)
                    joined += ",";
                joined += reasons->values[i];
            }
            row.state_reasons = joined;
        } else {
            row.state_reasons = "-";
        }
        row.make_model = detail::first_value(detail::find_attr(attrs, "printer-make-and-model"), "-");
        row.uri = detail::first_value(detail::find_attr(attrs, "printer-uri-supported"), "-");
        row.queued_jobs = detail::first_int(detail::find_attr(attrs, "queued-job-count")).value_or(-1);
        row.is_default = !default_name.empty() && row.name == default_name;
        out.push_back(std::move(row));
    }
    return out;
}

/// Maps every job-attributes group (0x02) in a Get-Jobs response into a
/// `JobRow`. A group with no parseable `job-id` is skipped defensively
/// (never fabricated as job 0).
[[nodiscard]] inline std::vector<JobRow> jobs_from_ipp(const ipp::Message& msg) {
    std::vector<JobRow> out;
    for (const auto& [group_tag, attrs] : msg.groups) {
        if (group_tag != ipp::kTagJobAttributes)
            continue;
        const auto id = detail::first_int(detail::find_attr(attrs, "job-id"));
        if (!id)
            continue;

        JobRow row;
        row.job_id = *id;
        row.printer = detail::first_value(detail::find_attr(attrs, "job-printer-uri"), "-");
        row.owner = detail::first_value(detail::find_attr(attrs, "job-originating-user-name"), "-");
        row.document = detail::first_value(detail::find_attr(attrs, "job-name"), "-");
        row.status =
            detail::job_state_from_ipp_enum(detail::first_int(detail::find_attr(attrs, "job-state")));
        row.submitted_at =
            detail::iso8601_from_ipp_datetime(detail::first_value(detail::find_attr(attrs, "date-time-at-creation")));
        const auto k_octets = detail::first_int(detail::find_attr(attrs, "job-k-octets"));
        row.size_bytes = k_octets ? (*k_octets * 1024) : -1;
        out.push_back(std::move(row));
    }
    return out;
}

// ── winspool bit -> row mappers ─────────────────────────────────────────────
//
// Reproduced <winspool.h> bit values here (not #included) so this header
// stays platform-pure and its mapper functions are usable by the unit tests
// on every host. `kPrinterStatusPaused` (0x1) is REAL CAPTURE the-rig —
// P93-2/P93-3 observed it live on `Microsoft Print to PDF` under both admin
// and SYSTEM (tests/unit/fixtures/wave9/printing/windows/enum_printers.txt).
// The remaining bits were never exercised by that printer (no error/
// offline/not-available printer, no non-pending job state, was available to
// probe) and stay RECONSTRUCTION against the documented PRINTER_STATUS_*/
// JOB_STATUS_* bit meanings.
namespace winspool_bits {

inline constexpr uint32_t kPrinterStatusPaused = 0x00000001;
inline constexpr uint32_t kPrinterStatusError = 0x00000002;
inline constexpr uint32_t kPrinterStatusOffline = 0x00000080;
inline constexpr uint32_t kPrinterStatusNotAvailable = 0x00001000;

inline constexpr uint32_t kJobStatusPaused = 0x00000001;
inline constexpr uint32_t kJobStatusError = 0x00000002;
inline constexpr uint32_t kJobStatusSpooling = 0x00000008;
inline constexpr uint32_t kJobStatusPrinting = 0x00000010;
inline constexpr uint32_t kJobStatusOffline = 0x00000020;
inline constexpr uint32_t kJobStatusPaperout = 0x00000040;
inline constexpr uint32_t kJobStatusPrinted = 0x00000080;
inline constexpr uint32_t kJobStatusDeleted = 0x00000100;
inline constexpr uint32_t kJobStatusBlockedDevq = 0x00000200;
inline constexpr uint32_t kJobStatusUserIntervention = 0x00000400;
inline constexpr uint32_t kJobStatusRestart = 0x00000800;

} // namespace winspool_bits

/// PRINTER_INFO_2's `Status`/`cJobs` -> the same idle/processing/stopped/
/// unknown vocabulary the IPP leg reports (never a fourth Windows-only
/// state) — an error/offline/not-available/paused printer reports
/// "stopped", a printer with queued jobs and no such flag reports
/// "processing", otherwise "idle".
[[nodiscard]] inline std::string printer_state_from_winspool(uint32_t status, uint32_t c_jobs) {
    using namespace winspool_bits;
    if ((status & (kPrinterStatusError | kPrinterStatusOffline | kPrinterStatusNotAvailable |
                   kPrinterStatusPaused)) != 0)
        return "stopped";
    if (c_jobs > 0)
        return "processing";
    return "idle";
}

/// JOB_INFO_2's `Status` -> the same pending/held/processing/stopped/
/// canceled/aborted/completed/unknown vocabulary the IPP leg reports.
[[nodiscard]] inline std::string job_status_from_winspool(uint32_t status) {
    using namespace winspool_bits;
    if ((status & kJobStatusDeleted) != 0)
        return "canceled";
    if ((status & kJobStatusError) != 0)
        return "aborted";
    if ((status & kJobStatusPrinted) != 0)
        return "completed";
    if ((status & kJobStatusPrinting) != 0)
        return "processing";
    if ((status & (kJobStatusPaused | kJobStatusUserIntervention | kJobStatusPaperout |
                   kJobStatusBlockedDevq | kJobStatusOffline | kJobStatusRestart)) != 0)
        return "held";
    if ((status & kJobStatusSpooling) != 0 || status == 0)
        return "pending";
    return "unknown";
}

// ── output formatting ───────────────────────────────────────────────────────

[[nodiscard]] inline std::string format_printer_row(const PrinterRow& r) {
    return std::format("printer|{}|{}|{}|{}|{}|{}|{}", yuzu::util::safe_output_field(r.name), r.state,
                        yuzu::util::safe_output_field(r.state_reasons), r.is_default ? 1 : 0,
                        yuzu::util::safe_output_field(r.make_model), yuzu::util::safe_output_field(r.uri),
                        r.queued_jobs);
}

[[nodiscard]] inline std::string format_job_row(const JobRow& r) {
    return std::format("job|{}|{}|{}|{}|{}|{}|{}", yuzu::util::safe_output_field(r.printer), r.job_id,
                        yuzu::util::safe_output_field(r.owner), yuzu::util::safe_output_field(r.document),
                        r.status, r.submitted_at, r.size_bytes);
}

/// `outcome`: canceled | not_found | refused | error. An empty `printer`
/// (the `missing_printer` row) is emitted as "-", matching the definition's
/// documented "-" when the param itself was missing.
[[nodiscard]] inline std::string format_clear_queue_row(std::string_view printer, int64_t job_id,
                                                          std::string_view outcome,
                                                          std::string_view detail) {
    return std::format("clear_queue|{}|{}|{}|{}", printer.empty() ? "-" : yuzu::util::safe_output_field(printer),
                        job_id, outcome, yuzu::util::safe_output_field(detail));
}

/// How a CUPS Cancel-Job response status maps onto a `clear_queue` outcome.
enum class CancelStatusClass { canceled, not_found, refused, error };

/// Pure so the mapping is unit-testable without a cupsd. Status values are
/// RFC 8011 §4.1.6 (client-error-*) and RFC 8010 §3.1.6.1 (successful-*):
///   0x0000-0x00FF successful-*            -> canceled
///   0x0406 client-error-not-found         -> not_found
///   0x0401 client-error-forbidden         -> refused
///   0x0402 client-error-not-authenticated -> refused
///   0x0403 client-error-not-authorized    -> refused
/// Everything else, deliberately including 0x0400 client-error-bad-request
/// (a malformed request is a protocol fault, not an authorization decision),
/// is `error` so it surfaces as `unexpected_status` rather than a false
/// "refused".
[[nodiscard]] inline CancelStatusClass classify_cancel_job_status(uint16_t status) noexcept {
    if (status <= 0x00FF)
        return CancelStatusClass::canceled;
    switch (status) {
    case 0x0406:
        return CancelStatusClass::not_found;
    case 0x0401:
    case 0x0402:
    case 0x0403:
        return CancelStatusClass::refused;
    default:
        return CancelStatusClass::error;
    }
}

/// How a failed Windows `OpenPrinterW` maps onto a `clear_queue` outcome.
enum class OpenPrinterFailure { not_found, refused, error };

/// `last_error` is `GetLastError()` read immediately after the failed call.
/// Win32 values are stable ABI, restated here (winerror.h) so the mapping
/// stays in the pure header: 5 ERROR_ACCESS_DENIED -> refused (the printer
/// exists but the caller may not open its queue), 1801
/// ERROR_INVALID_PRINTER_NAME -> not_found. Every other failure (spooler
/// stopped, RPC unavailable, ...) is `error`: reporting it as not_found would
/// tell an operator a printer is gone when the spooler is merely down.
[[nodiscard]] inline OpenPrinterFailure classify_open_printer_error(uint32_t last_error) noexcept {
    constexpr uint32_t kErrorAccessDenied = 5;
    constexpr uint32_t kErrorInvalidPrinterName = 1801;
    if (last_error == kErrorAccessDenied)
        return OpenPrinterFailure::refused;
    if (last_error == kErrorInvalidPrinterName)
        return OpenPrinterFailure::not_found;
    return OpenPrinterFailure::error;
}

/// True only for a plain local printer name: none of `\`, `/` or `:`. Those
/// characters can make OpenPrinterW reach a remote server (`\\server\queue`,
/// the `//server/queue` form `safe_output_field` renders it as in the
/// `printers`/`jobs` rows, `http://host/printers/x/.printer`, ...), and
/// OpenPrinterW returns the SAME 1801 for an unreachable server as for a missing
/// local printer, so a not-found is definitive only for a plain name. An
/// allowlist on purpose: enumerating remote-capable name shapes is open-ended.
[[nodiscard]] inline bool printer_name_is_plain_local(std::string_view name) noexcept {
    return name.find_first_of("\\/:") == std::string_view::npos;
}

/// Operation attributes of the Get-Jobs that lists ONE printer's not-completed
/// jobs, asking only for the job ids. `clear_queue` sends it before Cancel-Job
/// because cupsd's Cancel-Job looks a job up by id alone and ignores which
/// printer was named. A nonexistent printer makes cupsd answer not-found.
[[nodiscard]] inline std::vector<ipp::OperationAttr> job_binding_check_attrs(std::string_view printer) {
    std::vector<ipp::OperationAttr> attrs;
    attrs.push_back({ipp::kTagUri, "printer-uri", "ipp://localhost/printers/" + std::string(printer), {}});
    attrs.push_back({ipp::kTagKeyword, "which-jobs", "not-completed", {}});
    attrs.push_back({ipp::kTagKeyword, "requested-attributes", "job-id", {}});
    return attrs;
}

/// True when `job_id` is one of the listed jobs.
[[nodiscard]] inline bool job_is_listed(const std::vector<JobRow>& rows, int64_t job_id) noexcept {
    return std::any_of(rows.begin(), rows.end(), [job_id](const JobRow& r) { return r.job_id == job_id; });
}

/// Accepts ONLY `^[0-9]{1,9}$` with value >= 1 — a printer job id is never
/// negative, never zero, never hex/scientific notation, and a 10+-digit
/// string is refused outright rather than risking a silent 64-bit wrap on a
/// platform where `int64_t` parsing of a huge digit run could overflow. The
/// PUBLISHED definition pattern `^[1-9][0-9]{0,8}$` is deliberately stricter
/// (no leading zeros): the agent still accepts "007" as job 7, which is safe.
[[nodiscard]] inline std::optional<int64_t> parse_job_id(std::string_view s) {
    if (s.empty() || s.size() > 9)
        return std::nullopt;
    for (const char c : s) {
        if (c < '0' || c > '9')
            return std::nullopt;
    }
    int64_t v = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || ptr != s.data() + s.size())
        return std::nullopt;
    if (v < 1)
        return std::nullopt;
    return v;
}

} // namespace yuzu::printing
