/**
 * test_printing_parsers.cpp — printing_ipp.hpp codec round-trips,
 * printing_parsers.hpp mappers, and decode of the fixture .ipp captures
 * under tests/unit/fixtures/wave9/printing/macos/.
 *
 * FIXTURE PROVENANCE — two tiers, honestly named (see each fixture's own
 * <name>.ipp.provenance.txt for the full detail):
 *   - Tier A, `real_*.ipp` (3 files): REAL CAPTURE, taken unprivileged
 *     (uid 501, no sudo) against the live `/private/var/run/cupsd` socket
 *     on this Mac. The tests below assert the RECORDED status and
 *     status-message each fixture's own provenance file states, not a
 *     hardcoded table independent of the capture.
 *   - Tier B, `synthetic_*.ipp` (2 files): SYNTHETIC, hand-assembled
 *     against printing_ipp.hpp's own wire grammar to exercise decoder
 *     shapes (a populated printer row, a populated job row) that no real
 *     capture on this host can reach — this host has no configured print
 *     queues. NOT evidence of cupsd wire behaviour; never cited as such
 *     anywhere in this plugin.
 *   - Tier C, the winspool bit-mapper cases below: split per-case into
 *     REAL CAPTURE the-rig (a literal (status, cJobs)/Status triplet
 *     copied from tests/unit/fixtures/wave9/printing/windows/enum_*.txt,
 *     P93-2/P93-3) and RECONSTRUCTION (a bit this host's spooler was never
 *     observed to set — documented PRINTER_STATUS_ / JOB_STATUS_ meaning
 *     only).
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
}

// ────────────────────────────────────────────────── winspool bit mappers ──

// REAL CAPTURE the-rig (P93-2/P93-3): the literal (status, cJobs) triplets
// below are copied verbatim from
// tests/unit/fixtures/wave9/printing/windows/enum_printers.txt's
// `EnumPrintersW(LOCAL|CONNECTIONS, level 2)` section — the-rig
// (desktop-04dnsig), captured under BOTH the admin SSH identity and the
// SYSTEM scheduled task, byte-identical in shape either way.
// `Microsoft Print to PDF` is the only printer this host had paused with a
// nonzero queue, so it is the only live triplet exercising
// `kPrinterStatusPaused`; the other three rows (`OneNote (Desktop)`,
// `Microsoft XPS Document Writer`, `Fax`) are all status=0x0/cJobs=0.
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
// never produced a printing/completed/canceled/aborted/held job —
// documented JOB_STATUS_* meaning only.
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

// ───────────────────────────────────────────────────────── row formatting ──

TEST_CASE("format_printer_row / format_job_row shapes",
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
}
