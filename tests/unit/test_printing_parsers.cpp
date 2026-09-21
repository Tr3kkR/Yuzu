/**
 * test_printing_parsers.cpp — printing_ipp.hpp codec round-trips,
 * printing_parsers.hpp mappers, and decode of the fixture .ipp captures
 * under tests/unit/fixtures/wave9/printing/macos/.
 *
 * FIXTURE PROVENANCE — two tiers, honestly named (see each fixture's own
 * <name>.ipp.provenance.txt for the full detail):
 *   - Tier A, `real_*.ipp` (7 files): REAL CAPTURE against the live
 *     `/private/var/run/cupsd` socket on this Mac (uid 501, no sudo).
 *     Five were taken unprivileged with no queue by
 *     `tests/unit/fixtures/wave9/printing/macos/capture.sh` Phase A. The two
 *     `real_get_jobs_binding_check.ipp` / `real_get_jobs_all_printers.ipp`
 *     captures (2026-09-21) were taken with curl against scratch queues made
 *     with `lpadmin` and removed afterwards -- see their provenance files.
 *     The tests below assert the RECORDED status and status-message (or job
 *     ids) each fixture's own provenance file states, not a hardcoded table
 *     independent of the capture.
 *   - Tier B, `synthetic_*.ipp` (3 files): SYNTHETIC, hand-assembled
 *     against printing_ipp.hpp's own wire grammar to exercise decoder
 *     shapes (a populated printer row, a populated job row, a successful
 *     cancel) that the unprivileged, queue-less Phase A captures could not
 *     reach. NOT evidence of cupsd wire behaviour;
 *     never cited as such anywhere in this plugin.
 *   - Tier C, the winspool bit-mapper cases below: split per-case into
 *     REAL CAPTURE the-rig (a literal (status, cJobs)/Status triplet
 *     copied from tests/unit/fixtures/wave9/printing/windows/enum_*.txt,
 *     P93-2/P93-3) and RECONSTRUCTION (a bit this host's spooler was never
 *     observed to set — documented PRINTER_STATUS_ / JOB_STATUS_ meaning
 *     only).
 *   - Tier D, `cancel_job_*.ipp` (3 files, tests/unit/fixtures/wave9/
 *     printing/linux/): REAL CAPTURE, taken inside a throwaway ubuntu:26.04
 *     cupsd container (I93-7) — the identity-mismatch control no macOS
 *     capture can provide (every local macOS account is a print operator).
 *     See each fixture's own .provenance.txt.
 */

#include "printing_ipp.hpp"
#include "printing_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <vector>

using namespace yuzu::printing;
namespace fs = std::filesystem;

namespace {

std::vector<uint8_t> read_fixture(const std::string& name, const std::string& os_dir = "macos") {
    std::vector<fs::path> candidates{
        fs::path{"tests/unit/fixtures/wave9/printing"} / os_dir / name,
        fs::path{".."} / "tests" / "unit" / "fixtures" / "wave9" / "printing" / os_dir / name,
    };
    if (const char* src_root = std::getenv("MESON_SOURCE_ROOT")) {
        candidates.emplace_back(fs::path{src_root} / "tests" / "unit" / "fixtures" / "wave9" /
                                "printing" / os_dir / name);
    }
    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec) {
            std::ifstream in(p, std::ios::binary);
            REQUIRE(in.is_open());
            std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                        std::istreambuf_iterator<char>());
            return bytes;
        }
    }
    FAIL("fixture not found: " << name);
    return {};
}

std::string status_message(const ipp::Message& msg) {
    for (const auto& [tag, attrs] : msg.groups) {
        if (tag != ipp::kTagOperationAttributes)
            continue;
        for (const auto& a : attrs) {
            if (a.name == "status-message" && !a.values.empty())
                return a.values.front();
        }
    }
    return {};
}

} // namespace

// ─────────────────────────────────────────────────────── codec round-trips ──

TEST_CASE("encode_request/decode round-trip: a request with no extra operation attributes",
          "[printing][ipp][codec]") {
    const auto req = ipp::encode_request(ipp::kCupsGetPrinters, 7, {});
    const auto decoded =
        ipp::decode(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(req.data()), req.size()));
    REQUIRE(decoded.has_value());
    CHECK(decoded->version == ipp::kVersion);
    CHECK(decoded->op_or_status == ipp::kCupsGetPrinters);
    CHECK(decoded->request_id == 7);
    REQUIRE(decoded->groups.size() == 1);
    CHECK(decoded->groups[0].first == ipp::kTagOperationAttributes);
    REQUIRE(decoded->groups[0].second.size() == 2);
    CHECK(decoded->groups[0].second[0].name == "attributes-charset");
    CHECK(decoded->groups[0].second[0].values == std::vector<std::string>{"utf-8"});
    CHECK(decoded->groups[0].second[1].name == "attributes-natural-language");
    CHECK(decoded->groups[0].second[1].values == std::vector<std::string>{"en"});
}

TEST_CASE("encode_request/decode round-trip: Cancel-Job with printer-uri/job-id/"
          "requesting-user-name",
          "[printing][ipp][codec]") {
    const std::vector<ipp::OperationAttr> attrs{
        {ipp::kTagUri, "printer-uri", "ipp://localhost/printers/yuzu_test"},
        {ipp::kTagInteger, "job-id", ipp::encode_int32(42)},
        {ipp::kTagNameWithoutLanguage, "requesting-user-name", "alex"},
    };
    const auto req = ipp::encode_request(ipp::kCancelJob, 99, attrs);
    const auto decoded =
        ipp::decode(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(req.data()), req.size()));
    REQUIRE(decoded.has_value());
    CHECK(decoded->op_or_status == ipp::kCancelJob);
    CHECK(decoded->request_id == 99);
    REQUIRE(decoded->groups.size() == 1);
    const auto& op_attrs = decoded->groups[0].second;
    REQUIRE(op_attrs.size() == 5); // 2 mandatory + 3 given
    CHECK(op_attrs[2].name == "printer-uri");
    CHECK(op_attrs[2].values == std::vector<std::string>{"ipp://localhost/printers/yuzu_test"});
    CHECK(op_attrs[3].name == "job-id");
    CHECK(op_attrs[3].values == std::vector<std::string>{ipp::encode_int32(42)});
    CHECK(op_attrs[4].name == "requesting-user-name");
    CHECK(op_attrs[4].values == std::vector<std::string>{"alex"});
}

TEST_CASE("decode: additional-value continuation appends to the preceding attribute",
          "[printing][ipp][codec]") {
    // Hand-built: header + operation-attributes group + one keyword attr
    // with two values (the second via an empty-name continuation) + end.
    std::vector<uint8_t> bytes;
    const auto push_u16 = [&](uint16_t v) {
        bytes.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        bytes.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    const auto push_u32 = [&](uint32_t v) {
        bytes.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        bytes.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        bytes.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        bytes.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    const auto push_str = [&](const std::string& s) {
        for (char c : s)
            bytes.push_back(static_cast<uint8_t>(c));
    };

    push_u16(ipp::kVersion);
    push_u16(0x0000);
    push_u32(1);
    bytes.push_back(ipp::kTagPrinterAttributes);
    // printer-state-reasons (first value)
    bytes.push_back(ipp::kTagKeyword);
    push_u16(21);
    push_str("printer-state-reasons");
    push_u16(4);
    push_str("none");
    // continuation (second value, empty name)
    bytes.push_back(ipp::kTagKeyword);
    push_u16(0);
    push_u16(9);
    push_str("other-one");
    bytes.push_back(ipp::kTagEndOfAttributes);

    const auto decoded = ipp::decode(std::span<const uint8_t>(bytes));
    REQUIRE(decoded.has_value());
    REQUIRE(decoded->groups.size() == 1);
    REQUIRE(decoded->groups[0].second.size() == 1);
    CHECK(decoded->groups[0].second[0].name == "printer-state-reasons");
    REQUIRE(decoded->groups[0].second[0].values.size() == 2);
    CHECK(decoded->groups[0].second[0].values[0] == "none");
    CHECK(decoded->groups[0].second[0].values[1] == "other-one");
}

TEST_CASE("decode: truncation at every possible cut point returns nullopt, never UB",
          "[printing][ipp][codec]") {
    const auto req = ipp::encode_request(ipp::kGetJobs, 1,
                                          {{ipp::kTagUri, "printer-uri", "ipp://localhost/printers/x"}});
    for (std::size_t cut = 0; cut < req.size(); ++cut) {
        const auto truncated = std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(req.data()), cut);
        const auto decoded = ipp::decode(truncated);
        // A cut that lands exactly on end-of-attributes-tag having already
        // been consumed is the ONE valid short prefix (a message can be
        // legitimately empty of any group); every other prefix must decode
        // to nullopt.
        if (decoded.has_value()) {
            INFO("cut=" << cut);
            CHECK(decoded->groups.empty());
        }
    }
    // The full, untruncated message must decode successfully.
    const auto full = ipp::decode(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(req.data()), req.size()));
    CHECK(full.has_value());
}

TEST_CASE("decode: fewer than 8 bytes is always nullopt", "[printing][ipp][codec]") {
    const uint8_t tiny[4] = {0x02, 0x00, 0x40, 0x02};
    CHECK_FALSE(ipp::decode(std::span<const uint8_t>(tiny, 4)).has_value());
    CHECK_FALSE(ipp::decode(std::span<const uint8_t>{}).has_value());
}

TEST_CASE("decode: a value tag before any group has opened is malformed -> nullopt",
          "[printing][ipp][codec]") {
    std::vector<uint8_t> bytes;
    const auto push_u16 = [&](uint16_t v) {
        bytes.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        bytes.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    const auto push_u32 = [&](uint32_t v) {
        bytes.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        bytes.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        bytes.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        bytes.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    push_u16(ipp::kVersion);
    push_u16(0);
    push_u32(1);
    bytes.push_back(ipp::kTagKeyword); // a value tag with no group opened
    bytes.push_back(0);
    bytes.push_back(0);
    bytes.push_back(0);
    bytes.push_back(0);
    CHECK_FALSE(ipp::decode(std::span<const uint8_t>(bytes)).has_value());
}

// ───────────────────────────────────────────────────────────── mappers ──

TEST_CASE("printers_from_ipp / jobs_from_ipp: SYNTHETIC fixture decode + row mapping "
          "(decoder-shape coverage only — see the fixtures' own provenance)",
          "[printing][ipp][fixtures]") {
    {
        const auto bytes = read_fixture("synthetic_printers_populated.ipp");
        const auto decoded = ipp::decode(std::span<const uint8_t>(bytes));
        REQUIRE(decoded.has_value());
        CHECK(decoded->op_or_status == 0x0000);
        const auto rows = printers_from_ipp(*decoded, "yuzu_test");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].name == "yuzu_test");
        CHECK(rows[0].state == "idle");
        CHECK(rows[0].is_default);
        CHECK(rows[0].queued_jobs == 1);
    }
    {
        const auto bytes = read_fixture("synthetic_jobs_populated.ipp");
        const auto decoded = ipp::decode(std::span<const uint8_t>(bytes));
        REQUIRE(decoded.has_value());
        CHECK(decoded->op_or_status == 0x0000);
        const auto rows = jobs_from_ipp(*decoded);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].job_id == 2);
        CHECK(rows[0].owner == "alex");
        CHECK(rows[0].document == "hosts");
        CHECK(rows[0].status == "processing");
        CHECK(rows[0].submitted_at == "2026-09-08T12:00:00Z");
        CHECK(rows[0].size_bytes == 1024);
    }
}

TEST_CASE("iso8601_from_ipp_datetime: RFC 2911 dateTime (11 raw octets) decodes to the real UTC "
          "instant, undoing a non-zero UTC offset -- never treated as already-UTC local time",
          "[printing][ipp][datetime]") {
    // 2026-09-08T12:00:00, printer-local, UTC (+00:00) -> unchanged in UTC.
    {
        const std::string raw = std::string("\x07\xea\x09\x08\x0c\x00\x00\x00+\x00\x00", 11);
        CHECK(detail::iso8601_from_ipp_datetime(raw) == "2026-09-08T12:00:00Z");
    }
    // 2026-09-08T12:00:00, printer-local, UTC+05:30 -> 06:30 UTC (subtract
    // the printer's offset to recover the real instant).
    {
        const std::string raw = std::string("\x07\xea\x09\x08\x0c\x00\x00\x00+\x05\x1e", 11);
        CHECK(detail::iso8601_from_ipp_datetime(raw) == "2026-09-08T06:30:00Z");
    }
    // 2026-09-08T12:00:00, printer-local, UTC-08:00 -> 20:00 UTC (add the
    // printer's offset back).
    {
        const std::string raw = std::string("\x07\xea\x09\x08\x0c\x00\x00\x00-\x08\x00", 11);
        CHECK(detail::iso8601_from_ipp_datetime(raw) == "2026-09-08T20:00:00Z");
    }
    // Malformed input: wrong length, out-of-range fields, or a bogus
    // direction byte -- honest "-", never UB, never a fabricated date.
    CHECK(detail::iso8601_from_ipp_datetime("") == "-");
    CHECK(detail::iso8601_from_ipp_datetime(std::string(10, '\0')) == "-");
    CHECK(detail::iso8601_from_ipp_datetime(std::string("\x07\xea\x0d\x08\x0c\x00\x00\x00+\x00\x00", 11)) ==
          "-"); // month=13
    CHECK(detail::iso8601_from_ipp_datetime(std::string("\x07\xea\x09\x08\x0c\x00\x00\x00?\x00\x00", 11)) ==
          "-"); // direction '?'
}

TEST_CASE("job_state_from_ipp_enum: every IPP job-state integer 3..9 maps to its distinct named "
          "status (direct call, not just the single job-state=5 fixture group)",
          "[printing][ipp][job-state]") {
    // jobs_from_ipp's only fixture coverage is one job-attributes group at
    // job-state=5 ("processing") — this exercises the other six branches of
    // job_state_from_ipp_enum directly so a swapped case label anywhere in
    // 3..9 cannot go undetected.
    CHECK(detail::job_state_from_ipp_enum(3) == "pending");
    CHECK(detail::job_state_from_ipp_enum(4) == "held");
    CHECK(detail::job_state_from_ipp_enum(5) == "processing");
    CHECK(detail::job_state_from_ipp_enum(6) == "stopped");
    CHECK(detail::job_state_from_ipp_enum(7) == "canceled");
    CHECK(detail::job_state_from_ipp_enum(8) == "aborted");
    CHECK(detail::job_state_from_ipp_enum(9) == "completed");
    CHECK(detail::job_state_from_ipp_enum(std::nullopt) == "unknown");
    CHECK(detail::job_state_from_ipp_enum(2) == "unknown");
    CHECK(detail::job_state_from_ipp_enum(10) == "unknown");
}

TEST_CASE("synthetic_cancel_job_ok.ipp decodes to successful-ok (decoder-shape coverage only)",
          "[printing][ipp][fixtures]") {
    const auto bytes = read_fixture("synthetic_cancel_job_ok.ipp");
    const auto decoded = ipp::decode(std::span<const uint8_t>(bytes));
    REQUIRE(decoded.has_value());
    CHECK(decoded->op_or_status == 0x0000);
}

TEST_CASE("Tier A REAL CAPTURE fixtures decode to their recorded status + status-message",
          "[printing][ipp][fixtures][real-capture]") {
    // Every expectation below is the value each fixture's own
    // .provenance.txt records as REAL CAPTURE — not a table hardcoded
    // independently of the capture.
    {
        const auto bytes = read_fixture("real_cups_get_printers_empty.ipp");
        const auto decoded = ipp::decode(std::span<const uint8_t>(bytes));
        REQUIRE(decoded.has_value());
        CHECK(decoded->op_or_status == 0x0406);
        CHECK(status_message(*decoded) == "No destinations added.");
    }
    {
        const auto bytes = read_fixture("real_cups_get_default_none.ipp");
        const auto decoded = ipp::decode(std::span<const uint8_t>(bytes));
        REQUIRE(decoded.has_value());
        CHECK(decoded->op_or_status == 0x0406);
        CHECK(status_message(*decoded) == "No default printer.");
    }
    {
        const auto bytes = read_fixture("real_get_jobs_no_printer.ipp");
        const auto decoded = ipp::decode(std::span<const uint8_t>(bytes));
        REQUIRE(decoded.has_value());
        CHECK(decoded->op_or_status == 0x0406);
        CHECK(status_message(*decoded) == "The printer or class does not exist.");
    }
    {
        const auto bytes = read_fixture("real_cancel_job_not_found.ipp");
        const auto decoded = ipp::decode(std::span<const uint8_t>(bytes));
        REQUIRE(decoded.has_value());
        CHECK(decoded->op_or_status == 0x0406);
        CHECK(status_message(*decoded) == "Job #424242 does not exist.");
    }
    {
        const auto bytes = read_fixture("real_cancel_job_not_found_peercred.ipp");
        const auto decoded = ipp::decode(std::span<const uint8_t>(bytes));
        REQUIRE(decoded.has_value());
        CHECK(decoded->op_or_status == 0x0406);
        CHECK(status_message(*decoded) == "Job #424242 does not exist.");
    }
}

TEST_CASE("real_cancel_job_not_found[_peercred].ipp are byte-identical — the header-framing "
          "control (proves framing only, NOT authorisation outcome; see provenance)",
          "[printing][ipp][fixtures][real-capture]") {
    const auto without_header = read_fixture("real_cancel_job_not_found.ipp");
    const auto with_header = read_fixture("real_cancel_job_not_found_peercred.ipp");
    CHECK(without_header == with_header);
}

// ─────────────────────────────── REAL CAPTURE ubuntu:26.04 cupsd container ──
// The identity-mismatch control macOS could not provide (P93-1's capture.sh
// banner: every local macOS account is a print operator via _lpoperator's
// nested groups, so no principal there can be refused purely by identity).
// I93-7 captured these against a real Debian/Ubuntu cupsd (2.4.16) in a
// throwaway ubuntu:26.04 container: `Require user @OWNER @SYSTEM` on
// Cancel-Job, `SystemGroup root lpadmin` — see each fixture's own
// .provenance.txt for the exact command, decoded status, and what each
// capture does/does not prove.
TEST_CASE("REAL CAPTURE ubuntu:26.04 cupsd container 2026-09-08: root (real uid 0, "
          "@SYSTEM via SystemGroup root lpadmin) cancelling a job it does not own "
          "(owned by nobody) succeeds, WITH the PeerCred header",
          "[printing][ipp][fixtures][real-capture][linux]") {
    const auto bytes = read_fixture("cancel_job_root_vs_nobody.ipp", "linux");
    const auto decoded = ipp::decode(std::span<const uint8_t>(bytes));
    REQUIRE(decoded.has_value());
    CHECK(decoded->op_or_status == 0x0000); // successful-ok
}

TEST_CASE("REAL CAPTURE ubuntu:26.04 cupsd container 2026-09-08: root (real uid 0, "
          "@SYSTEM) cancelling another user's job succeeds even with NO "
          "Authorization header at all — cupsd resolves the real SO_PEERCRED "
          "identity off the Unix socket, not the header",
          "[printing][ipp][fixtures][real-capture][linux]") {
    const auto bytes = read_fixture("cancel_job_root_no_peercred.ipp", "linux");
    const auto decoded = ipp::decode(std::span<const uint8_t>(bytes));
    REQUIRE(decoded.has_value());
    CHECK(decoded->op_or_status == 0x0000); // successful-ok
}

TEST_CASE("REAL CAPTURE ubuntu:26.04 cupsd container 2026-09-08: nobody (real uid "
          "65534, neither @OWNER nor @SYSTEM) cancelling root's job is refused at "
          "the HTTP layer (403 Forbidden) before ever reaching the IPP handler — "
          "the body is cupsd's HTML error page, not an IPP message, so decode() "
          "safely returns nullopt (the same non-IPP shape "
          "printing_plugin.cpp's do_clear_queue short-circuits on via "
          "result.http_status before ever calling decode())",
          "[printing][ipp][fixtures][real-capture][linux]") {
    const auto bytes = read_fixture("cancel_job_nobody_vs_root.ipp", "linux");
    const auto decoded = ipp::decode(std::span<const uint8_t>(bytes));
    CHECK_FALSE(decoded.has_value());
}

// ────────────────────────────────────────────────── winspool bit mappers ──

// REAL CAPTURE the-rig (P93-2/P93-3): the literal (status, cJobs) triplets
// below are copied verbatim from
// tests/unit/fixtures/wave9/printing/windows/enum_printers.txt's
// `EnumPrintersW(LOCAL|CONNECTIONS, level 2)` section — the-rig
// (desktop-04dnsig), captured under BOTH the admin SSH identity and the
// SYSTEM scheduled task, byte-identical in shape either way (see
// enum_printers.txt.provenance.txt). `Microsoft Print to PDF` is the only
// printer this host had paused with a nonzero queue, so it is the only
// live triplet exercising `kPrinterStatusPaused`; the other three rows
// (`OneNote (Desktop)`, `Microsoft XPS Document Writer`, `Fax`) are all
// status=0x0/cJobs=0.
TEST_CASE("printer_state_from_winspool: REAL CAPTURE the-rig triplets", "[printing][winspool]") {
    using namespace winspool_bits;
    CHECK(printer_state_from_winspool(0x00000000, 0) == "idle");                  // OneNote (Desktop)
    CHECK(printer_state_from_winspool(kPrinterStatusPaused, 2) == "stopped");      // Microsoft Print to PDF
}

// RECONSTRUCTION: bits `Microsoft Print to PDF` never exercised on the-rig
// (no error/offline/not-available printer was available to probe, and no
// idle printer with a nonzero queue was observed) — documented
// PRINTER_STATUS_* meaning only, not a live capture.
TEST_CASE("printer_state_from_winspool: RECONSTRUCTION (untested bits)", "[printing][winspool]") {
    using namespace winspool_bits;
    CHECK(printer_state_from_winspool(0, 3) == "processing");
    CHECK(printer_state_from_winspool(kPrinterStatusError, 0) == "stopped");
    CHECK(printer_state_from_winspool(kPrinterStatusOffline, 0) == "stopped");
}

// REAL CAPTURE the-rig (P93-2/P93-3): both queued jobs against `Microsoft
// Print to PDF` (tests/unit/fixtures/wave9/printing/windows/enum_jobs.txt,
// JobId 7 and 8) reported `status=0x00000000` under both admin and SYSTEM —
// the only Status value this host's spooler was observed to emit for a
// queued job.
TEST_CASE("job_status_from_winspool: REAL CAPTURE the-rig triplet", "[printing][winspool]") {
    CHECK(job_status_from_winspool(0x00000000) == "pending"); // JobId 7 / JobId 8
}

// RECONSTRUCTION: every other Status bit — this printer's paused queue
// never produced a printing/completed/canceled/aborted/held job, and the
// cancelled jobs (setjob_cancel.txt) were removed from the queue outright
// rather than left in a readable cancelled state (GetJobW readback failed
// ERROR_INVALID_PARAMETER) — documented JOB_STATUS_* meaning only.
TEST_CASE("job_status_from_winspool: RECONSTRUCTION (untested bits)", "[printing][winspool]") {
    using namespace winspool_bits;
    CHECK(job_status_from_winspool(kJobStatusSpooling) == "pending");
    CHECK(job_status_from_winspool(kJobStatusPrinting) == "processing");
    CHECK(job_status_from_winspool(kJobStatusPrinted) == "completed");
    CHECK(job_status_from_winspool(kJobStatusDeleted) == "canceled");
    CHECK(job_status_from_winspool(kJobStatusError) == "aborted");
    CHECK(job_status_from_winspool(kJobStatusPaused) == "held");
    CHECK(job_status_from_winspool(kJobStatusUserIntervention) == "held");
}

// ─────────────────────────────────────────────────────────── parse_job_id ──

TEST_CASE("parse_job_id: accepts ^[0-9]{1,9}$ with value >= 1", "[printing][parse_job_id]") {
    CHECK(parse_job_id("1") == 1);
    CHECK(parse_job_id("42") == 42);
    CHECK(parse_job_id("999999999") == 999999999);
}

TEST_CASE("parse_job_id: rejects every documented non-match", "[printing][parse_job_id]") {
    CHECK_FALSE(parse_job_id("all").has_value());
    CHECK_FALSE(parse_job_id("*").has_value());
    CHECK_FALSE(parse_job_id("-a").has_value());
    CHECK_FALSE(parse_job_id("0").has_value());
    CHECK_FALSE(parse_job_id("-1").has_value());
    CHECK_FALSE(parse_job_id("1e3").has_value());
    CHECK_FALSE(parse_job_id("0x10").has_value());
    CHECK_FALSE(parse_job_id("").has_value());
    CHECK_FALSE(parse_job_id("1234567890").has_value()); // 10 digits
}

// ───────────────────────────────────────────────────────── row formatting ──

TEST_CASE("format_printer_row / format_job_row / format_clear_queue_row shapes",
          "[printing][format]") {
    PrinterRow p;
    p.name = "Office-LaserJet";
    p.state = "idle";
    p.state_reasons = "-";
    p.is_default = true;
    p.make_model = "HP LaserJet";
    p.uri = "ipp://localhost/printers/Office-LaserJet";
    p.queued_jobs = 0;
    CHECK(format_printer_row(p) ==
          "printer|Office-LaserJet|idle|-|1|HP LaserJet|ipp://localhost/printers/Office-LaserJet|0");

    JobRow j;
    j.printer = "Office-LaserJet";
    j.job_id = 5;
    j.owner = "alex";
    j.document = "hosts";
    j.status = "pending";
    j.submitted_at = "-";
    j.size_bytes = 512;
    CHECK(format_job_row(j) == "job|Office-LaserJet|5|alex|hosts|pending|-|512");

    CHECK(format_clear_queue_row("Office-LaserJet", 5, "canceled", "-") ==
          "clear_queue|Office-LaserJet|5|canceled|-");
}

TEST_CASE("format_clear_queue_row: an empty printer (the missing_printer row) is emitted as \"-\"",
          "[printing][format]") {
    CHECK(format_clear_queue_row("", 0, "error", "missing_printer") ==
          "clear_queue|-|0|error|missing_printer");
}

// ────────────────────────────────────── Cancel-Job / OpenPrinterW mapping ──

// Status values are RFC 8010 §3.1.6.1 / RFC 8011 §4.1.6, not captures: the
// only real-capture statuses in the tree are 0x0000 and 0x0406 (asserted
// against the decoded fixtures above); the rest are protocol constants.
TEST_CASE("classify_cancel_job_status: successful-* (0x0000-0x00FF) is canceled",
          "[printing][classify]") {
    CHECK(classify_cancel_job_status(0x0000) == CancelStatusClass::canceled);
    CHECK(classify_cancel_job_status(0x0001) == CancelStatusClass::canceled);
    CHECK(classify_cancel_job_status(0x00FF) == CancelStatusClass::canceled);
}

TEST_CASE("classify_cancel_job_status: not-found, and the three auth-related client errors",
          "[printing][classify]") {
    CHECK(classify_cancel_job_status(0x0406) == CancelStatusClass::not_found);
    CHECK(classify_cancel_job_status(0x0401) == CancelStatusClass::refused); // forbidden
    CHECK(classify_cancel_job_status(0x0402) == CancelStatusClass::refused); // not-authenticated
    CHECK(classify_cancel_job_status(0x0403) == CancelStatusClass::refused); // not-authorized
}

TEST_CASE("classify_cancel_job_status: bad-request is a protocol fault, never a false 'refused'",
          "[printing][classify]") {
    CHECK(classify_cancel_job_status(0x0400) == CancelStatusClass::error); // bad-request
    CHECK(classify_cancel_job_status(0x0404) == CancelStatusClass::error); // not-possible
    CHECK(classify_cancel_job_status(0x0500) == CancelStatusClass::error); // server-error-*
    CHECK(classify_cancel_job_status(0x0100) == CancelStatusClass::error); // just past successful-*
    CHECK(classify_cancel_job_status(0x0405) == CancelStatusClass::error); // neighbours of the
    CHECK(classify_cancel_job_status(0x0407) == CancelStatusClass::error); // 0x0406 not-found
    CHECK(classify_cancel_job_status(0xFFFF) == CancelStatusClass::error);
}

// Win32 values (winerror.h) are likewise constants. 1801 was ALSO observed
// live on the-rig (OpenPrinterW on a nonexistent printer, and on an
// unreachable UNC server); 5 (ERROR_ACCESS_DENIED) was never provoked on real
// hardware; 87 and 1722 are unobserved as OpenPrinterW results (87 was seen
// live from GetJobW/SetJobW on a nonexistent job, a different call).
TEST_CASE("classify_open_printer_error: access-denied and invalid-printer-name are distinguished",
          "[printing][classify]") {
    CHECK(classify_open_printer_error(5) == OpenPrinterFailure::refused);      // ERROR_ACCESS_DENIED
    CHECK(classify_open_printer_error(1801) == OpenPrinterFailure::not_found); // ERROR_INVALID_PRINTER_NAME
}

TEST_CASE("classify_open_printer_error: every other failure is an error, never a false not_found",
          "[printing][classify]") {
    CHECK(classify_open_printer_error(0) == OpenPrinterFailure::error);
    CHECK(classify_open_printer_error(87) == OpenPrinterFailure::error);   // ERROR_INVALID_PARAMETER
    CHECK(classify_open_printer_error(1722) == OpenPrinterFailure::error); // RPC_S_SERVER_UNAVAILABLE
    CHECK(classify_open_printer_error(1800) == OpenPrinterFailure::error); // neighbours of 1801
    CHECK(classify_open_printer_error(1802) == OpenPrinterFailure::error);
    CHECK(classify_open_printer_error(4) == OpenPrinterFailure::error);    // neighbours of 5
    CHECK(classify_open_printer_error(6) == OpenPrinterFailure::error);
}

TEST_CASE("printer_name_is_plain_local: only names with none of backslash, slash or colon",
          "[printing][classify]") {
    CHECK(printer_name_is_plain_local("Microsoft Print to PDF"));
    CHECK(printer_name_is_plain_local("HP LaserJet 4"));
    CHECK(printer_name_is_plain_local("Office-Floor_2"));
}

TEST_CASE("printer_name_is_plain_local: every remote-capable or separator-bearing shape is not plain",
          "[printing][classify]") {
    CHECK_FALSE(printer_name_is_plain_local("\\\\server\\queue"));          // UNC
    CHECK_FALSE(printer_name_is_plain_local("//server/queue"));              // the form the rows render
    CHECK_FALSE(printer_name_is_plain_local("\\/server/queue"));            // mixed prefixes
    CHECK_FALSE(printer_name_is_plain_local("/\\server/queue"));
    CHECK_FALSE(printer_name_is_plain_local("\\\\"));                      // bare separators
    CHECK_FALSE(printer_name_is_plain_local("//"));
    CHECK_FALSE(printer_name_is_plain_local("\\\\?\\UNC\\server\\queue")); // extended-length UNC
    CHECK_FALSE(printer_name_is_plain_local("http://host/printers/x/.printer")); // URL form
    CHECK_FALSE(printer_name_is_plain_local("\\queue"));                    // a single backslash
    CHECK_FALSE(printer_name_is_plain_local("/queue"));                     // a single slash
    CHECK_FALSE(printer_name_is_plain_local("Office/Floor2"));              // an interior slash
    CHECK_FALSE(printer_name_is_plain_local("HP: Floor 2"));                // a colon
}

// ─────────────────────────────────── job-to-printer binding (POSIX clear_queue) ──
//
// cupsd's Cancel-Job looks a job up by id alone, so run_clear_queue() must prove the
// job is on the NAMED printer before it sends one. The responses below are REAL
// captures (see each provenance file); the transport is a recording fake, so every
// test can assert exactly which IPP operations were sent.

namespace {

IppResult result_from_fixture(const std::string& name, const std::string& os_dir = "macos") {
    const auto bytes = read_fixture(name, os_dir);
    return IppResult{true, 200, ipp::decode(std::span<const uint8_t>(bytes))};
}

IppResult result_with_status(uint16_t status) {
    ipp::Message m;
    m.op_or_status = status;
    return IppResult{true, 200, m};
}

struct FakeTransport {
    IppResult listing;
    IppResult cancel;
    std::vector<uint16_t> ops;
    std::vector<std::vector<ipp::OperationAttr>> sent;
    IppResult operator()(uint16_t op, const std::vector<ipp::OperationAttr>& attrs) {
        ops.push_back(op);
        sent.push_back(attrs);
        return op == ipp::kGetJobs ? listing : cancel;
    }
};

const ClearQueueTokens kTestTokens{"os:connect_failed", "os:decode_failed", "os:access_denied", "os:not_found",
                                   "os:unexpected_status"};
const std::vector<uint16_t> kListOnly{ipp::kGetJobs};
const std::vector<uint16_t> kListThenCancel{ipp::kGetJobs, ipp::kCancelJob};

} // namespace

TEST_CASE("run_clear_queue: a job listed on the named printer is cancelled -- Get-Jobs first, then "
          "Cancel-Job with the encoded printer, the job id and the caller's identity",
          "[printing][binding]") {
    // REAL: jobs 16 and 17 on yuzu4616a; REAL Linux cupsd successful-ok for the Cancel-Job.
    FakeTransport t{result_from_fixture("real_get_jobs_binding_check.ipp"),
                    result_from_fixture("cancel_job_root_vs_nobody.ipp", "linux"), {}, {}};
    const auto d = run_clear_queue("yuzu4616a", 16, "alex", kTestTokens, t);
    CHECK(t.ops == kListThenCancel);
    CHECK(d.rc == 0);
    CHECK(d.status == ClearQueueStatus::ok);
    CHECK(d.full);
    CHECK(d.row == "clear_queue|yuzu4616a|16|canceled|-");
    REQUIRE(t.sent.size() == 2);
    const auto& cancel = t.sent[1];
    REQUIRE(cancel.size() == 3);
    CHECK(cancel[0].name == "printer-uri");
    CHECK(cancel[0].value == "ipp://localhost/printers/yuzu4616a");
    CHECK(cancel[1].name == "job-id");
    CHECK(cancel[1].value == ipp::encode_int32(16));
    CHECK(cancel[2].name == "requesting-user-name");
    CHECK(cancel[2].value == "alex");
}

TEST_CASE("run_clear_queue: a job id that is not on the printer's active queue sends NO Cancel-Job",
          "[printing][binding]") {
    FakeTransport t{result_from_fixture("real_get_jobs_binding_check.ipp"), result_with_status(0x0000), {}, {}};
    const auto d = run_clear_queue("yuzu4616a", 99, "alex", kTestTokens, t);
    CHECK(t.ops == kListOnly);
    CHECK(d.rc == 1);
    CHECK(d.status == ClearQueueStatus::unavailable);
    CHECK(d.full);
    CHECK(d.row == "clear_queue|yuzu4616a|99|not_found|os:not_found");
}

TEST_CASE("run_clear_queue: a job that belongs to ANOTHER queue is never cancelled, even when the "
          "listing spans every queue (REAL all-printers listing)",
          "[printing][binding]") {
    // REAL: the listing cupsd returned for printer-uri ipp://localhost/printers/%00 -- jobs 16, 17
    // on yuzu4616a and job 18 on yuzu4616b. Before the name was encoded and the job's own
    // job-printer-uri checked, this made every job id pass.
    const auto all = result_from_fixture("real_get_jobs_all_printers.ipp");
    {
        FakeTransport t{all, result_with_status(0x0000), {}, {}};
        const auto d = run_clear_queue("yuzu4616a", 18, "alex", kTestTokens, t); // 18 is on yuzu4616b
        CHECK(t.ops == kListOnly);
        CHECK(d.row == "clear_queue|yuzu4616a|18|not_found|os:not_found");
    }
    {
        FakeTransport t{all, result_with_status(0x0000), {}, {}};
        const auto d = run_clear_queue("yuzu4616b", 16, "alex", kTestTokens, t); // 16 is on yuzu4616a
        CHECK(t.ops == kListOnly);
        CHECK(d.row == "clear_queue|yuzu4616b|16|not_found|os:not_found");
    }
    {
        FakeTransport t{all, result_from_fixture("cancel_job_root_vs_nobody.ipp", "linux"), {}, {}};
        const auto d = run_clear_queue("yuzu4616b", 18, "alex", kTestTokens, t); // the right pair
        CHECK(t.ops == kListThenCancel);
        CHECK(d.row == "clear_queue|yuzu4616b|18|canceled|-");
    }
}

TEST_CASE("run_clear_queue: a '%00' printer name is sent ENCODED and cancels nothing (the exploit)",
          "[printing][binding]") {
    FakeTransport t{result_from_fixture("real_get_jobs_all_printers.ipp"), result_with_status(0x0000), {}, {}};
    const auto d = run_clear_queue("%00", 18, "alex", kTestTokens, t);
    REQUIRE(t.sent.size() == 1);
    CHECK(t.sent[0][0].value == "ipp://localhost/printers/%2500"); // never a raw %00
    CHECK(t.ops == kListOnly);
    CHECK(d.row == "clear_queue|%00|18|not_found|os:not_found");
}

TEST_CASE("run_clear_queue: a nonexistent printer (REAL 0x0406 answer) is not_found and sends no Cancel-Job",
          "[printing][binding]") {
    FakeTransport t{result_from_fixture("real_get_jobs_no_printer.ipp"), result_with_status(0x0000), {}, {}};
    const auto d = run_clear_queue("no_such_queue", 3, "alex", kTestTokens, t);
    CHECK(t.ops == kListOnly);
    CHECK(d.status == ClearQueueStatus::unavailable);
    CHECK(d.full);
    CHECK(d.detail == "Get-Jobs: printer not found");
    CHECK(d.row == "clear_queue|no_such_queue|3|not_found|os:not_found");
}

TEST_CASE("run_clear_queue: every failure of the Get-Jobs step is reported and sends no Cancel-Job",
          "[printing][binding]") {
    {
        FakeTransport t{IppResult{true, 403, std::nullopt}, {}, {}, {}};
        const auto d = run_clear_queue("q", 1, "alex", kTestTokens, t);
        CHECK(t.ops == kListOnly);
        CHECK(d.status == ClearQueueStatus::permission_denied);
        CHECK(d.full);
        CHECK(d.row == "clear_queue|q|1|refused|os:access_denied");
    }
    {
        FakeTransport t{IppResult{}, {}, {}, {}}; // transport failure
        const auto d = run_clear_queue("q", 1, "alex", kTestTokens, t);
        CHECK(t.ops == kListOnly);
        CHECK_FALSE(d.full);
        CHECK(d.row == "clear_queue|q|1|error|os:connect_failed");
    }
    {
        FakeTransport t{IppResult{true, 200, std::nullopt}, {}, {}, {}}; // undecodable body
        const auto d = run_clear_queue("q", 1, "alex", kTestTokens, t);
        CHECK(t.ops == kListOnly);
        CHECK(d.row == "clear_queue|q|1|error|os:decode_failed");
    }
    {
        FakeTransport t{result_with_status(0x0403), {}, {}, {}}; // not-authorized
        const auto d = run_clear_queue("q", 1, "alex", kTestTokens, t);
        CHECK(t.ops == kListOnly);
        CHECK(d.row == "clear_queue|q|1|refused|os:access_denied");
    }
    {
        FakeTransport t{result_with_status(0x0400), {}, {}, {}}; // bad-request: a fault, not a denial
        const auto d = run_clear_queue("q", 1, "alex", kTestTokens, t);
        CHECK(t.ops == kListOnly);
        CHECK_FALSE(d.full);
        CHECK(d.detail == "Get-Jobs: unexpected status 0x0400");
        CHECK(d.row == "clear_queue|q|1|error|os:unexpected_status");
    }
}

TEST_CASE("run_clear_queue: cupsd's own Cancel-Job answer after a passing listing is reported honestly",
          "[printing][binding]") {
    const auto listing = result_from_fixture("real_get_jobs_binding_check.ipp");
    {
        FakeTransport t{listing, result_from_fixture("real_cancel_job_not_found.ipp"), {}, {}}; // REAL 0x0406
        const auto d = run_clear_queue("yuzu4616a", 16, "alex", kTestTokens, t);
        CHECK(t.ops == kListThenCancel);
        CHECK(d.row == "clear_queue|yuzu4616a|16|not_found|os:not_found");
    }
    {
        FakeTransport t{listing, IppResult{true, 403, std::nullopt}, {}, {}};
        const auto d = run_clear_queue("yuzu4616a", 16, "alex", kTestTokens, t);
        CHECK(d.status == ClearQueueStatus::permission_denied);
        CHECK(d.row == "clear_queue|yuzu4616a|16|refused|os:access_denied");
    }
    {
        FakeTransport t{listing, result_with_status(0x0404), {}, {}}; // already terminal
        const auto d = run_clear_queue("yuzu4616a", 16, "alex", kTestTokens, t);
        CHECK(d.status == ClearQueueStatus::unavailable);
        CHECK_FALSE(d.full);
        CHECK(d.row == "clear_queue|yuzu4616a|16|error|os:unexpected_status");
    }
}

TEST_CASE("run_clear_queue: a printer name the agent will not build a request for sends NOTHING",
          "[printing][binding]") {
    for (const std::string& bad : {std::string(128, 'x'),                 // over the IPP name limit
                                  std::string("a\x01b"),                 // control character
                                  std::string("a\x7F"),                  // DEL
                                  std::string("ipp://localhost:631/printers/%00")}) { // decodes to NUL
        FakeTransport t{result_from_fixture("real_get_jobs_binding_check.ipp"), result_with_status(0x0000), {}, {}};
        const auto d = run_clear_queue(bad, 16, "alex", kTestTokens, t);
        CHECK(t.ops.empty());
        CHECK(d.row == "clear_queue|-|16|error|invalid_printer");
    }
    FakeTransport t{result_from_fixture("real_get_jobs_binding_check.ipp"), result_with_status(0x0000), {}, {}};
    const auto d = run_clear_queue(std::string(127, 'x'), 16, "alex", kTestTokens, t); // exactly at the limit
    CHECK_FALSE(t.ops.empty());
}

TEST_CASE("run_clear_queue: the destination URI the `jobs` action prints is accepted as the printer",
          "[printing][binding]") {
    FakeTransport t{result_from_fixture("real_get_jobs_binding_check.ipp"),
                    result_from_fixture("cancel_job_root_vs_nobody.ipp", "linux"), {}, {}};
    const auto d = run_clear_queue("ipp://localhost:631/printers/yuzu4616a", 17, "alex", kTestTokens, t);
    REQUIRE(t.sent.size() == 2);
    CHECK(t.sent[0][0].value == "ipp://localhost/printers/yuzu4616a");
    CHECK(d.row == "clear_queue|ipp://localhost:631/printers/yuzu4616a|17|canceled|-"); // echoed as given
}

TEST_CASE("job_is_listed_on: a job matches only by id AND its own job-printer-uri (REAL captures)",
          "[printing][binding]") {
    const auto a_bytes = read_fixture("real_get_jobs_binding_check.ipp");
    const auto a = ipp::decode(std::span<const uint8_t>(a_bytes));
    REQUIRE(a.has_value());
    CHECK(classify_cancel_job_status(a->op_or_status) == CancelStatusClass::canceled);
    const auto a_rows = jobs_from_ipp(*a);
    REQUIRE(a_rows.size() == 2);
    CHECK(job_is_listed_on(a_rows, 16, "yuzu4616a"));
    CHECK(job_is_listed_on(a_rows, 17, "yuzu4616a"));
    CHECK_FALSE(job_is_listed_on(a_rows, 16, "yuzu4616b")); // right id, wrong printer
    CHECK_FALSE(job_is_listed_on(a_rows, 18, "yuzu4616a")); // job of another queue
    CHECK_FALSE(job_is_listed_on(a_rows, 0, "yuzu4616a"));

    const auto all_bytes = read_fixture("real_get_jobs_all_printers.ipp");
    const auto all = ipp::decode(std::span<const uint8_t>(all_bytes));
    REQUIRE(all.has_value());
    const auto all_rows = jobs_from_ipp(*all);
    REQUIRE(all_rows.size() == 3);
    CHECK(job_is_listed_on(all_rows, 18, "yuzu4616b"));
    CHECK_FALSE(job_is_listed_on(all_rows, 18, "yuzu4616a"));
    CHECK_FALSE(job_is_listed_on(all_rows, 18, "%00"));
}

TEST_CASE("job_is_listed_on: a row without a job-printer-uri never matches; an empty listing lists nothing",
          "[printing][binding]") {
    JobRow no_uri;
    no_uri.job_id = 5;
    no_uri.printer = "-"; // jobs_from_ipp's placeholder for an absent attribute
    CHECK_FALSE(job_is_listed_on({no_uri}, 5, "-"));
    CHECK_FALSE(job_is_listed_on({}, 1, "yuzu4616a"));
}

TEST_CASE("job_binding_check_attrs: one printer's not-completed jobs, encoded name, ids and printer URIs only",
          "[printing][binding]") {
    const auto attrs = job_binding_check_attrs("Office-LaserJet");
    REQUIRE(attrs.size() == 3);
    CHECK(attrs[0].tag == ipp::kTagUri);
    CHECK(attrs[0].name == "printer-uri");
    CHECK(attrs[0].value == "ipp://localhost/printers/Office-LaserJet");
    CHECK(attrs[1].tag == ipp::kTagKeyword);
    CHECK(attrs[1].name == "which-jobs");
    CHECK(attrs[1].value == "not-completed");
    CHECK(attrs[2].tag == ipp::kTagKeyword);
    CHECK(attrs[2].name == "requested-attributes");
    CHECK(attrs[2].value == "job-id");
    REQUIRE(attrs[2].additional_values.size() == 1);
    CHECK(attrs[2].additional_values[0] == "job-printer-uri");
    CHECK(job_binding_check_attrs("a b/c%")[0].value == "ipp://localhost/printers/a%20b%2Fc%25");
}

TEST_CASE("percent_encode_path_segment / percent_decode: unreserved bytes pass, everything else is %XX",
          "[printing][binding]") {
    CHECK(percent_encode_path_segment("Az09-._~") == "Az09-._~");
    CHECK(percent_encode_path_segment("%00") == "%2500");
    CHECK(percent_encode_path_segment("a b") == "a%20b");
    CHECK(percent_encode_path_segment("a/b") == "a%2Fb");
    CHECK(percent_encode_path_segment("a?b#c") == "a%3Fb%23c");
    CHECK(percent_encode_path_segment("\xC3\xA9") == "%C3%A9"); // UTF-8 bytes each encoded
    CHECK(percent_encode_path_segment(std::string("a\0b", 3)) == "a%00b");
    CHECK(percent_decode("a%20b") == "a b");
    CHECK(percent_decode("%2500") == "%00");
    CHECK(percent_decode("%zz") == "%zz");   // not hex: stays literal
    CHECK(percent_decode("x%4") == "x%4");   // truncated: stays literal
    CHECK(percent_decode("%00") == std::string("\0", 1));
}

TEST_CASE("printer_name_from_operand / printer_name_is_valid_posix", "[printing][binding]") {
    CHECK(printer_name_from_operand("yuzu_test") == "yuzu_test");
    CHECK(printer_name_from_operand("ipp://localhost:631/printers/yuzu_test") == "yuzu_test");
    CHECK(printer_name_from_operand("ipps://host/printers/a%20b") == "a b");
    CHECK(printer_name_from_operand("ipp://localhost:631/classes/xp3cls") == "xp3cls");
    CHECK(printer_name_from_operand("ipp://host/printers/a/b") == "ipp://host/printers/a/b"); // not a name
    CHECK(printer_name_from_operand("ipp://host/other/x") == "ipp://host/other/x");
    CHECK(printer_name_from_operand("http://host/printers/x") == "http://host/printers/x");
    CHECK(printer_name_is_valid_posix("yuzu_test"));
    CHECK(printer_name_is_valid_posix(std::string(127, 'x')));
    CHECK_FALSE(printer_name_is_valid_posix(std::string(128, 'x')));
    CHECK_FALSE(printer_name_is_valid_posix(""));
    CHECK_FALSE(printer_name_is_valid_posix("a\x01"));
    CHECK_FALSE(printer_name_is_valid_posix("a\x7F"));
}

TEST_CASE("encode_request refuses a value that does not fit the 16-bit IPP length (no attribute injection)",
          "[printing][ipp][codec]") {
    const std::string big(65536, 'x');
    const std::string edge(65535, 'x');
    CHECK(ipp::encode_request(ipp::kGetJobs, 1, {{ipp::kTagUri, "printer-uri", big, {}}}).empty());
    CHECK_FALSE(ipp::encode_request(ipp::kGetJobs, 1, {{ipp::kTagUri, "printer-uri", edge, {}}}).empty());
    CHECK(ipp::encode_request(ipp::kGetJobs, 1, {{ipp::kTagKeyword, "requested-attributes", "job-id", {big}}}).empty());
    CHECK(ipp::encode_request(ipp::kGetJobs, 1, {{ipp::kTagUri, big, "v", {}}}).empty());
}
