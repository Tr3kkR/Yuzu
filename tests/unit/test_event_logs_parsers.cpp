/**
 * test_event_logs_parsers.cpp -- pure parse/format helpers
 * (event_logs_parsers.hpp, Wave-4 PR4.2 native-acquisition migration).
 *
 * Every OS-facing acquisition leg (wevtapi, sd_journal, the journalctl argv
 * fallback, `log show`) hands captured text to this header and emits
 * whatever it returns -- so the decision-shaped work (XML walking, entity
 * decoding, row formatting, sanitization) is pinned here on every host, the
 * firewall_parsers.hpp/users_win_events.hpp precedent. No OS headers, no
 * I/O, no subprocess calls: this file compiles and runs unconditionally.
 */

#include "event_logs_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <format>
#include <string>
#include <vector>

using namespace yuzu::event_logs_parsers;

namespace {

// Hand-builds one <Event>...</Event> XML block matching the shape
// EvtRenderEventXml produces, trimmed to the elements parse_win_events
// reads. Passing an empty string for event_id/level/system_time/provider
// OMITS that element entirely (absence, not an empty value) so
// absence-handling cases (e.g. "Level missing -> defaults to 4", "no
// EventID -> block skipped") are directly expressible. data_fragments are
// caller-supplied raw <Data ...>...</Data> / <Data/> fragments, so every
// Data shape (named/bare/empty-element) can be exercised per test.
//
// Provenance: synthetic -- hand-built from the EvtRenderEventXml schema; no
// wevtutil-captured event_logs fixture exists yet (unlike
// users_win_events.hpp's Security-channel captures via SSH to the-rig) --
// real captures to be folded in from the-rig.
std::string make_event(std::string_view event_id, std::string_view level,
                       std::string_view system_time, std::string_view provider,
                       std::vector<std::string> data_fragments = {}) {
    std::string out = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>";
    out += "<System>";
    if (!provider.empty())
        out += std::format("<Provider Name='{}'/>", provider);
    if (!event_id.empty())
        out += std::format("<EventID>{}</EventID>", event_id);
    if (!level.empty())
        out += std::format("<Level>{}</Level>", level);
    if (!system_time.empty())
        out += std::format("<TimeCreated SystemTime='{}'/>", system_time);
    out += "</System><EventData>";
    for (const auto& d : data_fragments)
        out += d;
    out += "</EventData></Event>";
    return out;
}

// Two-event fixture standing in for a real capture (see make_event's
// provenance note above): a disk-controller error followed by a
// Service-Control-Manager warning, each shaped like a genuine System-channel
// event -- exercises EventID/Level/TimeCreated/Provider extraction and all
// three <Data> forms (named, bare, empty-element/empty-content) together.
const std::string kRealisticFixture =
    make_event("7", "2", "2026-08-14T20:10:49.1234567Z", "disk",
               {"<Data Name='ErrorCode'>0x8007045D</Data>",
                "<Data Name='Device'>\\Device\\Harddisk0</Data>"}) +
    make_event("1000", "", "2026-08-14T20:11:03.0000000Z", "Service Control Manager",
               {"<Data>Spooler &amp; Fax</Data>", "<Data/>", "<Data Name='Reason'></Data>",
                "<Data Name='Detail'>timed &lt;out&gt;</Data>"});

// Counts pipe-delimited fields in a safe_output_field-sanitized row: an
// UNESCAPED '|' (not preceded by '\') is a real field delimiter; an escaped
// "\|" is data. Mirrors the split rule the shared server decoder
// (result_parsing.hpp) applies, and test_users_win_events.cpp's own check.
int unescaped_field_count(std::string_view row) {
    int fields = 1;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '|' && (i == 0 || row[i - 1] != '\\'))
            ++fields;
    }
    return fields;
}

} // namespace

// ---------------------------------------------------------------------------
// clamp_int_param
// ---------------------------------------------------------------------------

TEST_CASE("clamp_int_param: empty/invalid/trailing-garbage input yields the default",
          "[event_logs][parsers]") {
    CHECK(clamp_int_param("", 24, 1, 720) == 24);
    CHECK(clamp_int_param("abc", 24, 1, 720) == 24);
    CHECK(clamp_int_param("12x", 24, 1, 720) == 24); // trailing garbage after valid digits
    CHECK(clamp_int_param("  5", 24, 1, 720) == 24); // leading whitespace is also invalid
}

TEST_CASE("clamp_int_param: clamps below lo and above hi", "[event_logs][parsers]") {
    CHECK(clamp_int_param("-100", 24, 1, 720) == 1);
    CHECK(clamp_int_param("0", 24, 1, 720) == 1);
    CHECK(clamp_int_param("99999", 24, 1, 720) == 720);
}

TEST_CASE("clamp_int_param: exact bounds pass through unchanged", "[event_logs][parsers]") {
    CHECK(clamp_int_param("1", 24, 1, 720) == 1);
    CHECK(clamp_int_param("720", 24, 1, 720) == 720);
    CHECK(clamp_int_param("50", 24, 1, 720) == 50);
}

// ---------------------------------------------------------------------------
// contains_ci
// ---------------------------------------------------------------------------

TEST_CASE("contains_ci: case-insensitive substring match", "[event_logs][parsers]") {
    CHECK(contains_ci("Hello World", "world"));
    CHECK(contains_ci("Hello World", "WORLD"));
    CHECK(contains_ci("Hello World", "Hello"));
}

TEST_CASE("contains_ci: empty needle always matches", "[event_logs][parsers]") {
    CHECK(contains_ci("anything", ""));
    CHECK(contains_ci("", ""));
}

TEST_CASE("contains_ci: needle longer than haystack never matches", "[event_logs][parsers]") {
    CHECK_FALSE(contains_ci("ab", "abc"));
    CHECK_FALSE(contains_ci("", "x"));
}

TEST_CASE("contains_ci: a genuine miss returns false", "[event_logs][parsers]") {
    CHECK_FALSE(contains_ci("Hello World", "xyz"));
}

// ---------------------------------------------------------------------------
// parse_win_events
// ---------------------------------------------------------------------------

TEST_CASE("parse_win_events: empty/non-XML input yields an empty vector, never throws",
          "[event_logs][parsers]") {
    CHECK(parse_win_events("").empty());
    CHECK(parse_win_events("not xml at all").empty());
}

TEST_CASE("parse_win_events: a realistic two-event fixture extracts every field",
          "[event_logs][parsers]") {
    auto events = parse_win_events(kRealisticFixture);
    REQUIRE(events.size() == 2);

    const auto& disk = events[0];
    CHECK(disk.event_id == 7);
    CHECK(disk.level == 2);
    CHECK(disk.time_created == "2026-08-14T20:10:49.1234567Z");
    CHECK(disk.provider == "disk");
    CHECK(disk.message == "0x8007045D \\Device\\Harddisk0");

    const auto& scm = events[1];
    CHECK(scm.event_id == 1000);
    CHECK(scm.level == 4); // <Level> absent -> defaults to Information
    CHECK(scm.time_created == "2026-08-14T20:11:03.0000000Z");
    CHECK(scm.provider == "Service Control Manager");
    // bare (kept) + empty-element (skipped) + empty-content named (skipped)
    // + named entity-bearing (kept), space-joined, entity-decoded.
    CHECK(scm.message == "Spooler & Fax timed <out>");
}

TEST_CASE("parse_win_events: an attribute-bearing <EventID Qualifiers='...'> tag is parsed",
          "[event_logs][parsers]") {
    const std::string xml =
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><Provider Name='disk'/>"
        "<EventID Qualifiers='16384'>7</EventID>"
        "<TimeCreated SystemTime='t'/></System>"
        "<EventData><Data Name='Msg'>controller error</Data></EventData></Event>";
    auto events = parse_win_events(xml);
    REQUIRE(events.size() == 1);
    CHECK(events[0].event_id == 7);
    CHECK(events[0].message == "controller error");
}

TEST_CASE("parse_win_events: an absent <Level> defaults to 4 (Information)",
          "[event_logs][parsers]") {
    auto events = parse_win_events(make_event("1", "", "t", "prov"));
    REQUIRE(events.size() == 1);
    CHECK(events[0].level == 4);
}

TEST_CASE("parse_win_events: space-joins named/bare/empty-element <Data> forms, skipping empties",
          "[event_logs][parsers]") {
    const std::string xml =
        make_event("1", "4", "t", "prov",
                   {"<Data Name='k'>named</Data>", "<Data>bare</Data>", "<Data/>",
                    "<Data Name='empty'></Data>"});
    auto events = parse_win_events(xml);
    REQUIRE(events.size() == 1);
    CHECK(events[0].message == "named bare");
}

TEST_CASE("parse_win_events: entity decoding covers all five predefined entities + numeric refs",
          "[event_logs][parsers]") {
    const std::string xml = make_event(
        "1", "4", "t", "prov",
        {"<Data>&lt;a&gt;&amp;&apos;b&apos;&quot;c&quot;&#65;&#x42;</Data>"});
    auto events = parse_win_events(xml);
    REQUIRE(events.size() == 1);
    CHECK(events[0].message == "<a>&'b'\"c\"AB");
}

TEST_CASE("parse_win_events: an unrecognised entity passes through unchanged",
          "[event_logs][parsers]") {
    auto events = parse_win_events(make_event("1", "4", "t", "prov", {"<Data>weird&nbsp;name</Data>"}));
    REQUIRE(events.size() == 1);
    CHECK(events[0].message == "weird&nbsp;name");
}

TEST_CASE("parse_win_events: a truncated final block keeps the earlier complete event",
          "[event_logs][parsers]") {
    const std::string xml =
        make_event("42", "2", "t", "disk", {"<Data>complete</Data>"}) +
        "<Event xmlns='...'><System><EventID>99"; // never closes
    std::vector<WinEvent> events;
    CHECK_NOTHROW(events = parse_win_events(xml));
    REQUIRE(events.size() == 1);
    CHECK(events[0].event_id == 42);
}

TEST_CASE("parse_win_events: a block with no <EventID> is skipped, not fabricated",
          "[event_logs][parsers]") {
    const std::string xml =
        make_event("", "2", "t", "disk", {"<Data>orphan</Data>"}) + // no EventID at all
        make_event("42", "2", "t2", "disk", {"<Data>real</Data>"});
    auto events = parse_win_events(xml);
    REQUIRE(events.size() == 1);
    CHECK(events[0].event_id == 42);
}

TEST_CASE("parse_win_events: a leading '<EventData' text is not mistaken for the next '<Event'",
          "[event_logs][parsers]") {
    // "<EventData" shares the "<Event" prefix that the top-level block scan
    // matches on; the after-prefix guard (next byte must be '>' or ' ') must
    // reject this false match and keep scanning to find the real event.
    const std::string xml = "<EventData>stray text, not a real block</EventData>" +
                            make_event("5", "3", "t", "app", {"<Data>real</Data>"});
    auto events = parse_win_events(xml);
    REQUIRE(events.size() == 1);
    CHECK(events[0].event_id == 5);
}

// ---------------------------------------------------------------------------
// detail::collect_data_values -- byte cap
// ---------------------------------------------------------------------------

TEST_CASE("collect_data_values: stops growing at the byte cap, never exceeds it",
          "[event_logs][parsers]") {
    const std::string xml = "<EventData><Data>abcde</Data><Data>fghij</Data><Data>klmno</Data>"
                            "</EventData>";
    // cap (8) < the full joined length (17) but > one 5-byte value, so the
    // second value is partially collected and the third never reached.
    auto joined = detail::collect_data_values(xml, 0, xml.size(), /*byte_cap=*/8);
    CHECK(joined.size() == 8);
    CHECK(joined == "abcde fg");
}

TEST_CASE("collect_data_values: the default cap truncates a single oversized value",
          "[event_logs][parsers]") {
    const std::string big_value(2000, 'x');
    const std::string xml = std::format("<EventData><Data>{}</Data></EventData>", big_value);
    auto joined = detail::collect_data_values(xml, 0, xml.size()); // default byte_cap = 1024
    CHECK(joined.size() == 1024);
    // A second value after the cap is already exhausted must add nothing.
    const std::string xml_two =
        std::format("<EventData><Data>{}</Data><Data>more</Data></EventData>", big_value);
    auto joined_two = detail::collect_data_values(xml_two, 0, xml_two.size());
    CHECK(joined_two.size() == 1024);
}

// ---------------------------------------------------------------------------
// win_level_display
// ---------------------------------------------------------------------------

TEST_CASE("win_level_display: 0 and 4 both map to Information", "[event_logs][parsers]") {
    CHECK(win_level_display(0) == "Information");
    CHECK(win_level_display(4) == "Information");
}

TEST_CASE("win_level_display: documented levels 1/2/3/5", "[event_logs][parsers]") {
    CHECK(win_level_display(1) == "Critical");
    CHECK(win_level_display(2) == "Error");
    CHECK(win_level_display(3) == "Warning");
    CHECK(win_level_display(5) == "Verbose");
}

TEST_CASE("win_level_display: an unknown value formats as LevelN", "[event_logs][parsers]") {
    CHECK(win_level_display(6) == "Level6");
    CHECK(win_level_display(255) == "Level255");
}

// ---------------------------------------------------------------------------
// win_event_matches
// ---------------------------------------------------------------------------

TEST_CASE("win_event_matches: message hit, provider hit, miss, case-insensitive",
          "[event_logs][parsers]") {
    WinEvent ev;
    ev.provider = "Service Control Manager";
    ev.message = "The Spooler service entered the stopped state";
    CHECK(win_event_matches(ev, "spooler"));          // message hit, case-insensitive
    CHECK(win_event_matches(ev, "SERVICE CONTROL"));  // provider hit, case-insensitive
    CHECK_FALSE(win_event_matches(ev, "nonexistent"));
}

// ---------------------------------------------------------------------------
// win_error_row / win_event_row
// ---------------------------------------------------------------------------

TEST_CASE("win_error_row: exact shape, dashes for empty fields", "[event_logs][parsers]") {
    WinEvent ev;
    ev.event_id = 1002;
    CHECK(win_error_row(ev) == "error|-|1002|-|-");
}

TEST_CASE("win_error_row: populated fields render verbatim", "[event_logs][parsers]") {
    WinEvent ev;
    ev.time_created = "2026-08-14T20:10:49Z";
    ev.provider = "Disk";
    ev.event_id = 7;
    ev.message = "disk failure";
    CHECK(win_error_row(ev) == "error|2026-08-14T20:10:49Z|7|Disk|disk failure");
}

TEST_CASE("win_event_row: exact shape, dashes for empty fields (level defaults to Information)",
          "[event_logs][parsers]") {
    WinEvent ev;
    ev.event_id = 55;
    CHECK(win_event_row(ev) == "event|-|Information|55|-|-");
}

TEST_CASE("win_event_row: populated fields render verbatim", "[event_logs][parsers]") {
    WinEvent ev;
    ev.time_created = "t";
    ev.provider = "Prov";
    ev.event_id = 9;
    ev.level = 2; // Error
    ev.message = "boom";
    CHECK(win_event_row(ev) == "event|t|Error|9|Prov|boom");
}

TEST_CASE("win_event_row: message truncated at the 200-char display cap",
          "[event_logs][parsers]") {
    WinEvent ev;
    ev.message = std::string(250, 'x');
    auto row = win_event_row(ev);
    auto last_pipe = row.rfind('|');
    REQUIRE(last_pipe != std::string::npos);
    std::string msg_field = row.substr(last_pipe + 1);
    CHECK(msg_field.size() == kMessageDisplayCap);
    CHECK(msg_field == std::string(200, 'x'));
}

TEST_CASE("win_event_row: a message with '|'/CR/LF cannot forge extra fields",
          "[event_logs][parsers]") {
    WinEvent ev;
    ev.time_created = "t";
    ev.provider = "Prov";
    ev.event_id = 3;
    ev.message = "bad|value\r\nwith newline";
    auto row = win_event_row(ev);
    // safe_output_field folds CR and LF INDIVIDUALLY to a space each (not
    // the "\r\n" pair to one), so this leaves two spaces; '|' pipe-escapes
    // to "\|".
    CHECK(row.find('\r') == std::string::npos);
    CHECK(row.find('\n') == std::string::npos);
    CHECK(row.find("bad\\|value  with newline") != std::string::npos);
    CHECK(unescaped_field_count(row) == 6); // event|ts|level|id|provider|message
}

TEST_CASE("win_error_row: a message with '|'/CR/LF cannot forge extra fields",
          "[event_logs][parsers]") {
    WinEvent ev;
    ev.time_created = "t";
    ev.provider = "Prov";
    ev.event_id = 3;
    ev.message = "bad|value\r\nwith newline";
    auto row = win_error_row(ev);
    // See win_event_row's identical case above: CR and LF fold individually,
    // leaving two spaces where "\r\n" was.
    CHECK(row.find('\r') == std::string::npos);
    CHECK(row.find('\n') == std::string::npos);
    CHECK(row.find("bad\\|value  with newline") != std::string::npos);
    CHECK(unescaped_field_count(row) == 5); // error|ts|id|provider|message
}

// ---------------------------------------------------------------------------
// journal_unit_string
// ---------------------------------------------------------------------------

TEST_CASE("journal_unit_string: ident+pid, ident-only, unit fallback, dash",
          "[event_logs][parsers]") {
    CHECK(journal_unit_string("sshd", "123", "") == "sshd[123]");
    CHECK(journal_unit_string("sshd", "", "") == "sshd");
    CHECK(journal_unit_string("", "", "cron.service") == "cron.service");
    CHECK(journal_unit_string("", "", "") == "-");
    // A pid with no identifier carries no meaning on its own -- falls
    // through to the systemd_unit / "-" tiers exactly as if pid were absent.
    CHECK(journal_unit_string("", "123", "cron.service") == "cron.service");
}

// ---------------------------------------------------------------------------
// journal_row
// ---------------------------------------------------------------------------

TEST_CASE("journal_row: exact shape, dashes for empty fields", "[event_logs][parsers]") {
    JournalRow row;
    CHECK(journal_row("error", row) == "error|-|-|-");
}

TEST_CASE("journal_row: populated fields render verbatim", "[event_logs][parsers]") {
    JournalRow row{"2026-08-14T20:10:49+0000", "sshd[123]", "session opened"};
    CHECK(journal_row("event", row) == "event|2026-08-14T20:10:49+0000|sshd[123]|session opened");
}

TEST_CASE("journal_row: message truncated at the 200-char display cap",
          "[event_logs][parsers]") {
    JournalRow row{"t", "u", std::string(250, 'y')};
    auto r = journal_row("event", row);
    auto last_pipe = r.rfind('|');
    REQUIRE(last_pipe != std::string::npos);
    CHECK(r.substr(last_pipe + 1).size() == kMessageDisplayCap);
}

TEST_CASE("journal_row: a message with '|'/CR/LF cannot forge extra fields",
          "[event_logs][parsers]") {
    JournalRow row{"t", "u", "m|sg\r\nwith break"};
    auto r = journal_row("error", row);
    // safe_output_field folds CR and LF INDIVIDUALLY (not the "\r\n" pair to
    // one space), so this leaves two spaces; '|' pipe-escapes to "\|".
    CHECK(r.find('\r') == std::string::npos);
    CHECK(r.find('\n') == std::string::npos);
    CHECK(r.find("m\\|sg  with break") != std::string::npos);
    CHECK(unescaped_field_count(r) == 4); // error|ts|unit|message
}

// ---------------------------------------------------------------------------
// parse_short_iso_line
// ---------------------------------------------------------------------------

TEST_CASE("parse_short_iso_line: full 'ts host unit[pid]: msg' line", "[event_logs][parsers]") {
    auto row = parse_short_iso_line("2026-08-14T20:10:49+0000 myhost sshd[123]: session opened");
    CHECK(row.timestamp == "2026-08-14T20:10:49+0000");
    CHECK(row.unit == "sshd[123]");
    CHECK(row.message == "session opened");
}

TEST_CASE("parse_short_iso_line: no space -- the whole line is both timestamp and message",
          "[event_logs][parsers]") {
    auto row = parse_short_iso_line("nospacehere");
    CHECK(row.timestamp == "nospacehere");
    CHECK(row.message == "nospacehere");
    CHECK(row.unit == "-");
}

TEST_CASE("parse_short_iso_line: no ': ' after the hostname leaves unit at '-'",
          "[event_logs][parsers]") {
    auto row = parse_short_iso_line("2026-08-14T20:10:49+0000 myhost message with no colon-space");
    CHECK(row.timestamp == "2026-08-14T20:10:49+0000");
    CHECK(row.unit == "-");
    CHECK(row.message == "message with no colon-space");
}

TEST_CASE("parse_short_iso_line: hostname (second token) is always skipped",
          "[event_logs][parsers]") {
    auto row = parse_short_iso_line("ts hostA unit[1]: msg");
    CHECK(row.timestamp == "ts");
    CHECK(row.unit == "unit[1]");
    CHECK(row.message == "msg");
    CHECK(row.unit.find("hostA") == std::string::npos);
    CHECK(row.message.find("hostA") == std::string::npos);
}

// ---------------------------------------------------------------------------
// journal_message_matches
// ---------------------------------------------------------------------------

TEST_CASE("journal_message_matches: hit, case-insensitive hit, and miss",
          "[event_logs][parsers]") {
    CHECK(journal_message_matches("Connection refused", "refused"));
    CHECK(journal_message_matches("Connection REFUSED", "refused"));
    CHECK_FALSE(journal_message_matches("all good", "refused"));
}
