/**
 * printing_plugin.cpp — printer and print-job inventory.
 *
 * Actions:
 *   "printers"    — one row per printer: name, state (idle/processing/
 *                    stopped/unknown), state reasons, is_default, make and
 *                    model, uri, queued job count.
 *   "jobs"        — one row per queued job, optionally filtered to one
 *                    `printer`: printer, job id, owner, document (the job's
 *                    name/title — see printing_parsers.hpp's file banner for
 *                    the retention posture), status, submitted_at (ISO-8601
 *                    UTC), size in bytes.
 *
 * Read-only: this file contains no mutating action. A single narrowly-scoped
 * `clear_queue` cancellation (Destructive/Irreversible) lands in a focused
 * follow-up PR on top of this one, matching this workstream's
 * read-only-then-destructive split.
 *
 * No libcups, no vcpkg cups entry (verified absent from vcpkg.json) — the
 * IPP codec (printing_ipp.hpp) is a from-scratch minimal RFC 8010 encoder/
 * decoder built for this plugin alone. No OpenSSL — the CUPS Unix domain
 * socket carries no TLS. This is deliberately NOT http_client_plugin.cpp's
 * SSRF-guarded HTTP client: only `httplib_dep` is used directly, against a
 * fixed local socket path or `localhost:631`, never an operator-supplied
 * URL.
 *
 * Windows: EnumPrintersW/EnumJobsW/OpenPrinterW/GetJobW (winspool.h).
 * `kReadDesiredAccess` below is RECONCILED against P93-2's the-rig
 * measurement (both admin and SYSTEM, against `Microsoft Print to PDF`).
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field

#include <atomic>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "printing_ipp.hpp"
#include "printing_parsers.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <winspool.h>
#pragma comment(lib, "winspool.lib")

#include "win_str.hpp" // yuzu::win::from_wide/to_wide — ../../shared include dir
#else
#include <httplib.h>

#include <cstdio>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

using namespace yuzu::printing;

std::atomic<uint32_t> g_request_id{1};

uint32_t next_request_id() {
    return g_request_id.fetch_add(1, std::memory_order_relaxed);
}

#ifdef _WIN32

// Used to open the handle for every read (EnumJobsW/GetJobW). Confirmed by
// P93-2's the-rig measurement.
constexpr DWORD kReadDesiredAccess = PRINTER_ACCESS_USE;

// Move-only RAII owner for an HPRINTER (PH-015-style ownership rule, same
// shape as power_health's DirHandle / the repo's other Scoped* wrappers):
// takes ownership only once OpenPrinterW has actually succeeded, and
// ClosePrinter()s exactly once on every exit path.
class PrinterHandle {
public:
    PrinterHandle() = default;
    explicit PrinterHandle(HANDLE h) noexcept : h_{h} {}
    ~PrinterHandle() {
        if (h_ != nullptr)
            ClosePrinter(h_);
    }
    PrinterHandle(const PrinterHandle&) = delete;
    PrinterHandle& operator=(const PrinterHandle&) = delete;
    PrinterHandle(PrinterHandle&& other) noexcept : h_{other.h_} { other.h_ = nullptr; }
    PrinterHandle& operator=(PrinterHandle&& other) noexcept {
        if (this != &other) {
            if (h_ != nullptr)
                ClosePrinter(h_);
            h_ = other.h_;
            other.h_ = nullptr;
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const noexcept { return h_; }
    [[nodiscard]] bool valid() const noexcept { return h_ != nullptr; }

private:
    HANDLE h_ = nullptr;
};

[[nodiscard]] std::optional<PrinterHandle> open_printer(const std::wstring& name, DWORD access) {
    PRINTER_DEFAULTSW defaults{};
    defaults.DesiredAccess = access;
    HANDLE raw = nullptr;
    if (!OpenPrinterW(const_cast<LPWSTR>(name.c_str()), &raw, &defaults) || raw == nullptr)
        return std::nullopt;
    return PrinterHandle{raw};
}

// PRINTER_INFO_2W/JOB_INFO_2W are fixed-size structs whose string members
// (pPrinterName, pDriverName, pUserName, pDocument, ...) are pointers INTO
// the flat marshaled buffer EnumPrintersW/EnumJobsW filled — copying the
// struct by value does not copy what it points to. Bundling the backing
// buffer alongside the parsed structs (moved, so the heap block's address
// is unchanged) keeps every one of those pointers valid for as long as the
// caller holds this result; returning the structs alone left every pointer
// dangling into a buffer freed at function return (heap-use-after-free on
// every field read by do_printers/do_jobs — fixed here, the-rig build).
struct PrinterEnumRaw {
    std::vector<PRINTER_INFO_2W> items;
    std::vector<std::byte> backing;
};

struct JobEnumRaw {
    std::vector<JOB_INFO_2W> items;
    std::vector<std::byte> backing;
};

// EnumPrintersW's standard two-call pattern: size, allocate, fill.
[[nodiscard]] PrinterEnumRaw enum_printers_raw() {
    DWORD needed = 0, returned = 0;
    EnumPrintersW(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, nullptr, 2, nullptr, 0, &needed,
                  &returned);
    if (needed == 0)
        return {};
    std::vector<std::byte> buf(needed);
    if (!EnumPrintersW(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, nullptr, 2,
                        reinterpret_cast<LPBYTE>(buf.data()), needed, &needed, &returned))
        return {};
    std::vector<PRINTER_INFO_2W> out;
    out.reserve(returned);
    auto* items = reinterpret_cast<PRINTER_INFO_2W*>(buf.data());
    for (DWORD i = 0; i < returned; ++i)
        out.push_back(items[i]);
    return PrinterEnumRaw{std::move(out), std::move(buf)};
}

[[nodiscard]] std::wstring default_printer_name_raw() {
    DWORD size = 0;
    GetDefaultPrinterW(nullptr, &size);
    if (size == 0)
        return {};
    std::vector<wchar_t> buf(size, L'\0');
    if (!GetDefaultPrinterW(buf.data(), &size))
        return {};
    return std::wstring(buf.data());
}

// EnumJobsW's standard two-call pattern over an already-open printer handle.
[[nodiscard]] JobEnumRaw enum_jobs_raw(HANDLE h) {
    DWORD needed = 0, returned = 0;
    EnumJobsW(h, 0, 0xFFFFFFFFu, 2, nullptr, 0, &needed, &returned);
    if (needed == 0)
        return {};
    std::vector<std::byte> buf(needed);
    if (!EnumJobsW(h, 0, 0xFFFFFFFFu, 2, reinterpret_cast<LPBYTE>(buf.data()), needed, &needed, &returned))
        return {};
    std::vector<JOB_INFO_2W> out;
    out.reserve(returned);
    auto* items = reinterpret_cast<JOB_INFO_2W*>(buf.data());
    for (DWORD i = 0; i < returned; ++i)
        out.push_back(items[i]);
    return JobEnumRaw{std::move(out), std::move(buf)};
}

// JOB_INFO_2W's `Submitted` is the spooler's local wall-clock time at
// submission (matches the "Submitted" column the Windows print-queue UI
// shows), not UTC — converted here before formatting so `submitted_at`
// keeps the same ISO-8601 UTC contract as the IPP leg's `time-at-creation`.
// A zeroed or unconvertible SYSTEMTIME (job info with no submission stamp)
// falls back to "-", same as the IPP leg's absent-attribute case.
[[nodiscard]] std::string iso8601_utc_from_local_systemtime(const SYSTEMTIME& local) {
    if (local.wYear == 0)
        return "-";
    SYSTEMTIME utc{};
    if (!TzSpecificLocalTimeToSystemTime(nullptr, &local, &utc))
        return "-";
    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", utc.wYear, utc.wMonth, utc.wDay,
                        utc.wHour, utc.wMinute, utc.wSecond);
}

[[nodiscard]] JobRow job_row_from_info(std::string_view printer_name, const JOB_INFO_2W& j) {
    JobRow row;
    row.printer = std::string(printer_name);
    row.job_id = static_cast<int64_t>(j.JobId);
    row.owner = j.pUserName != nullptr ? yuzu::win::from_wide(j.pUserName) : "-";
    row.document = j.pDocument != nullptr ? yuzu::win::from_wide(j.pDocument) : "-";
    row.status = job_status_from_winspool(j.Status);
    row.submitted_at = iso8601_utc_from_local_systemtime(j.Submitted);
    // JOB_INFO_2W::Size is a DWORD -- always non-negative, so there is no
    // winspool "unknown size" sentinel to detect here (unlike the IPP leg's
    // absent job-k-octets attribute, which does have one). `j.Size >= 0` was
    // a tautology (MinGW -Wsign-conversion et al.: "comparison of unsigned
    // expression in '>= 0' is always true"), so the -1 fallback was dead
    // code -- report the byte count verbatim.
    row.size_bytes = static_cast<int64_t>(j.Size);
    return row;
}

int do_printers(yuzu::CommandContext& ctx) {
    const auto raw = enum_printers_raw();
    const std::wstring default_name = default_printer_name_raw();

    if (raw.items.empty()) {
        ctx.write_output("printer|none");
        return 0;
    }

    for (const auto& pi : raw.items) {
        PrinterRow row;
        row.name = pi.pPrinterName != nullptr ? yuzu::win::from_wide(pi.pPrinterName) : "-";
        row.state = printer_state_from_winspool(pi.Status, pi.cJobs);
        row.state_reasons = "-"; // winspool has no state-reasons vocabulary
        row.is_default = !default_name.empty() && pi.pPrinterName != nullptr &&
                          default_name == pi.pPrinterName;
        row.make_model = pi.pDriverName != nullptr ? yuzu::win::from_wide(pi.pDriverName) : "-";
        row.uri = pi.pPortName != nullptr ? yuzu::win::from_wide(pi.pPortName) : "-";
        row.queued_jobs = static_cast<int64_t>(pi.cJobs);
        ctx.write_output(format_printer_row(row));
    }
    return 0;
}

int do_jobs(yuzu::CommandContext& ctx, const yuzu::Params& params) {
    const std::string filter_printer{params.get("printer")};
    const auto raw_printers = enum_printers_raw();

    bool any = false;
    for (const auto& pi : raw_printers.items) {
        const std::string name = pi.pPrinterName != nullptr ? yuzu::win::from_wide(pi.pPrinterName) : "";
        if (!filter_printer.empty() && name != filter_printer)
            continue;

        auto handle = open_printer(pi.pPrinterName != nullptr ? pi.pPrinterName : L"", kReadDesiredAccess);
        if (!handle)
            continue; // this printer's jobs are simply unavailable; not a whole-action failure
        const auto jobs = enum_jobs_raw(handle->get());
        for (const auto& j : jobs.items) {
            any = true;
            ctx.write_output(format_job_row(job_row_from_info(name, j)));
        }
    }

    if (!any)
        ctx.write_output("job|none");
    return 0;
}

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "printers",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP CUPS-Get-Printers over the CUPS Unix socket (cpp-httplib)",
         "localhost:631 fallback for reads when no socket is found"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP CUPS-Get-Printers over the CUPS Unix socket (cpp-httplib)",
         "localhost:631 fallback for reads when no socket is found"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "winspool EnumPrintersW level 2", nullptr},
    },
    {
        /* .action      = */ "jobs",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP Get-Jobs (which-jobs=not-completed) over the CUPS Unix socket",
         "localhost:631 fallback for reads when no socket is found"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP Get-Jobs (which-jobs=not-completed) over the CUPS Unix socket",
         "localhost:631 fallback for reads when no socket is found"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "winspool EnumJobsW level 2", nullptr},
    },
};

#else // POSIX (macOS + Linux) — one leg for both, per this plugin's failure-token split below

// ── failure tokens — <os>:<source>:<detail> string literals ────────────────
// The POSIX leg below is ONE #else block shared by macOS and Linux, so the
// concrete token text is split by #if defined(__APPLE__) here — both literal
// sets are present in this file's text, and the leg picks the right one at
// compile time (never a runtime string substitution).
#if defined(__APPLE__)
constexpr std::string_view kTokConnectFailed = "macos:cups:connect_failed";
constexpr std::string_view kTokDecodeFailed = "macos:cups:decode_failed";
constexpr std::string_view kTokUnexpectedStatus = "macos:cups:unexpected_status";
#else
constexpr std::string_view kTokConnectFailed = "linux:cups:connect_failed";
constexpr std::string_view kTokDecodeFailed = "linux:cups:decode_failed";
constexpr std::string_view kTokUnexpectedStatus = "linux:cups:unexpected_status";
#endif

constexpr int kConnectTimeoutSec = 2;
constexpr int kReadTimeoutSec = 5;

// First existing candidate is the CUPS Unix domain socket this plugin talks
// to; `/private/var/run/cupsd` is the measured path on this Mac.
[[nodiscard]] std::optional<std::string> find_cups_socket() {
    static constexpr const char* kCandidates[] = {
        "/private/var/run/cupsd",
        "/var/run/cupsd",
        "/run/cups/cups.sock",
        "/var/run/cups/cups.sock",
    };
    for (const char* path : kCandidates) {
        struct stat st{};
        if (::stat(path, &st) == 0 && S_ISSOCK(st.st_mode))
            return std::string(path);
    }
    return std::nullopt;
}

struct IppResult {
    bool transport_ok = false;
    long http_status = 0;
    std::optional<ipp::Message> message;
};

// Issues one IPP POST over the CUPS Unix socket (set_address_family(AF_UNIX)
// BEFORE the first Post — httplib 0.37.1 only emits `Host: localhost` once
// address_family_ == AF_UNIX, and cupsd 400s a path-shaped Host otherwise).
[[nodiscard]] IppResult post_ipp_unix(const std::string& socket_path, const std::string& body,
                                       const httplib::Headers& extra_headers) {
    httplib::Client cli(socket_path);
    cli.set_address_family(AF_UNIX);
    cli.set_connection_timeout(kConnectTimeoutSec, 0);
    cli.set_read_timeout(kReadTimeoutSec, 0);

    IppResult result;
    auto res = cli.Post("/", extra_headers, body, "application/ipp");
    if (!res)
        return result;
    result.transport_ok = true;
    result.http_status = res->status;
    if (res->status == 200) {
        const auto* bytes = reinterpret_cast<const uint8_t*>(res->body.data());
        result.message = ipp::decode(std::span<const uint8_t>(bytes, res->body.size()));
    }
    return result;
}

[[nodiscard]] IppResult post_ipp_tcp_localhost(const std::string& body) {
    httplib::Client cli("localhost", 631);
    cli.set_connection_timeout(kConnectTimeoutSec, 0);
    cli.set_read_timeout(kReadTimeoutSec, 0);

    IppResult result;
    auto res = cli.Post("/", httplib::Headers{}, body, "application/ipp");
    if (!res)
        return result;
    result.transport_ok = true;
    result.http_status = res->status;
    if (res->status == 200) {
        const auto* bytes = reinterpret_cast<const uint8_t*>(res->body.data());
        result.message = ipp::decode(std::span<const uint8_t>(bytes, res->body.size()));
    }
    return result;
}

// Shared by "printers" and "jobs": a READ-only IPP round trip, preferring
// the Unix socket and falling back to TCP localhost:631 when no socket is
// found.
[[nodiscard]] IppResult do_read_ipp(const std::string& body) {
    if (const auto socket_path = find_cups_socket())
        return post_ipp_unix(*socket_path, body, httplib::Headers{});
    return post_ipp_tcp_localhost(body);
}

int do_printers(yuzu::CommandContext& ctx) {
    const auto req = ipp::encode_request(ipp::kCupsGetPrinters, next_request_id(), {});
    const auto result = do_read_ipp(req);

    if (!result.transport_ok) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "CUPS-Get-Printers: transport failed");
        ctx.write_output(std::format("printer|unavailable|{}", kTokConnectFailed));
        return 0;
    }
    if (!result.message) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "CUPS-Get-Printers: response did not decode");
        ctx.write_output(std::format("printer|unavailable|{}", kTokDecodeFailed));
        return 0;
    }
    // 0x0406 (client-error-not-found) is CUPS's own vendor convention for
    // CUPS-Get-Printers with zero configured destinations -- REAL CAPTURE
    // confirmed (real_cups_get_printers_empty.ipp: status-message "No
    // destinations added."). This request never names a specific printer,
    // so 0x0406 here can only mean "none exist", never "the one you asked
    // about is missing" (contrast Get-Jobs, where the same code names a
    // bad printer-uri and is a genuine failure) -- fall through to the
    // ordinary empty-rows path rather than reporting CONSTRAINED.
    if (result.message->op_or_status > 0x00FF && result.message->op_or_status != 0x0406) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               std::format("CUPS-Get-Printers: unexpected status 0x{:04x}",
                                           result.message->op_or_status));
        ctx.write_output(std::format("printer|unavailable|{}", kTokUnexpectedStatus));
        return 0;
    }

    // Best-effort default-printer resolution — a failure here just means no
    // row gets is_default=1, never a whole-action failure.
    std::string default_name;
    {
        const auto default_req = ipp::encode_request(ipp::kCupsGetDefault, next_request_id(), {});
        if (const auto default_result = do_read_ipp(default_req);
            default_result.transport_ok && default_result.message) {
            for (const auto& [tag, attrs] : default_result.message->groups) {
                if (tag != ipp::kTagPrinterAttributes)
                    continue;
                for (const auto& a : attrs) {
                    if (a.name == "printer-name" && !a.values.empty()) {
                        default_name = a.values.front();
                    }
                }
            }
        }
    }

    const auto rows = printers_from_ipp(*result.message, default_name);
    if (rows.empty()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        ctx.write_output("printer|none");
        return 0;
    }
    ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
    for (const auto& row : rows)
        ctx.write_output(format_printer_row(row));
    return 0;
}

int do_jobs(yuzu::CommandContext& ctx, const yuzu::Params& params) {
    const std::string printer{params.get("printer")};

    std::vector<ipp::OperationAttr> attrs;
    // Server-root URI ("ipp://localhost/") is CUPS's own idiom for "every
    // printer" here -- verified against a real cupsd: the seemingly-obvious
    // "ipp://localhost/jobs/" is NOT recognised and is refused outright with
    // client-error-not-found ("The printer or class does not exist"), which
    // the status check below now catches instead of silently reporting an
    // empty queue.
    const std::string uri =
        printer.empty() ? std::string("ipp://localhost/") : ("ipp://localhost/printers/" + printer);
    attrs.push_back({ipp::kTagUri, "printer-uri", uri, {}});
    attrs.push_back({ipp::kTagKeyword, "which-jobs", "not-completed", {}});
    // Get-Jobs' server-chosen default attribute set is minimal (verified
    // against a real cupsd: just job-id/job-uri) -- every field jobs_from_ipp
    // reads must be requested explicitly or it silently comes back absent.
    attrs.push_back({ipp::kTagKeyword,
                      "requested-attributes",
                      "job-id",
                      {"job-printer-uri", "job-originating-user-name", "job-name", "job-state",
                       "job-k-octets", "date-time-at-creation"}});

    const auto req = ipp::encode_request(ipp::kGetJobs, next_request_id(), attrs);
    const auto result = do_read_ipp(req);

    if (!result.transport_ok) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "Get-Jobs: transport failed");
        ctx.write_output(std::format("printer|unavailable|{}", kTokConnectFailed));
        return 0;
    }
    if (!result.message) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               "Get-Jobs: response did not decode");
        ctx.write_output(std::format("printer|unavailable|{}", kTokDecodeFailed));
        return 0;
    }
    // RFC 8010 successful-* is 0x0000-0x00FF -- a status outside that range
    // (e.g. client-error-not-found) must never be read as "zero job rows".
    if (result.message->op_or_status > 0x00FF) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                               std::format("Get-Jobs: unexpected status 0x{:04x}", result.message->op_or_status));
        ctx.write_output(std::format("printer|unavailable|{}", kTokUnexpectedStatus));
        return 0;
    }

    const auto rows = jobs_from_ipp(*result.message);
    if (rows.empty()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        ctx.write_output("job|none");
        return 0;
    }
    ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
    for (const auto& row : rows)
        ctx.write_output(format_job_row(row));
    return 0;
}

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "printers",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP CUPS-Get-Printers over the CUPS Unix socket (cpp-httplib)",
         "localhost:631 fallback for reads when no socket is found"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP CUPS-Get-Printers over the CUPS Unix socket (cpp-httplib)",
         "localhost:631 fallback for reads when no socket is found"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "winspool EnumPrintersW level 2", nullptr},
    },
    {
        /* .action      = */ "jobs",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP Get-Jobs (which-jobs=not-completed) over the CUPS Unix socket",
         "localhost:631 fallback for reads when no socket is found"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IPP Get-Jobs (which-jobs=not-completed) over the CUPS Unix socket",
         "localhost:631 fallback for reads when no socket is found"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "winspool EnumJobsW level 2", nullptr},
    },
};

#endif // _WIN32

} // namespace

class PrintingPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "printing"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Printer and print-job inventory";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"printers", "jobs", nullptr};
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
        if (action == "printers")
            return do_printers(ctx);
        if (action == "jobs")
            return do_jobs(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(PrintingPlugin)
