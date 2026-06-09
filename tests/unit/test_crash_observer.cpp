/**
 * test_crash_observer.cpp — Guardian DEX slice 1 (fleet-wide crash recorder).
 *
 * Covers the cross-platform, pure pieces (testable on every host even though real
 * data only flows on Windows):
 *   - symbolic_exception_name() NTSTATUS mapping
 *   - extract_named_data() + parse_application_error() by-name parse (real Event 1000) + tolerance
 *   - crash_observation_to_event() maps to a RULELESS DEX event (sentinel rule_id +
 *     event_type, no guard_category, no expected_value) — pins the taxonomy decision
 *   - make_crash_observer() is never null; off-Windows it is a no-op (start()==false)
 */

#include <yuzu/agent/crash_observer.hpp>

#include "crash_event.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::agent;

TEST_CASE("symbolic_exception_name maps known NTSTATUS codes", "[crash][parse]") {
    CHECK(symbolic_exception_name(0xC0000005) == "ACCESS_VIOLATION");
    CHECK(symbolic_exception_name(0xC0000409) == "STACK_BUFFER_OVERRUN");
    CHECK(symbolic_exception_name(0xC0000602) == "FAIL_FAST_EXCEPTION");
    CHECK(symbolic_exception_name(0x80000003) == "BREAKPOINT");
    CHECK(symbolic_exception_name(0xE0434352) == "CLR_EXCEPTION"); // managed (.NET) escape
    CHECK(symbolic_exception_name(0x00000001).empty()); // unknown -> ""
}

// A REAL Application Error (Event ID 1000) record captured from a Win11 box
// (10.0.26100) via `wevtutil qe Application "/q:*[System[(EventID=1000)]]"`. The
// Data elements are NAMED (not unnamed positional) and ProcessId is hex with a
// 0x prefix — exactly the assumptions this verifies end-to-end (XML -> fields ->
// CrashObservation), the path that never runs off a live event log.
constexpr const char* kRealEvent1000Xml =
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Application Error'/><EventID>1000</EventID><Level>2</Level>"
    "<TimeCreated SystemTime='2026-05-12T11:41:12.8358842Z'/><Channel>Application</Channel>"
    "</System><EventData>"
    "<Data Name='AppName'>AOTListenerService.exe</Data>"
    "<Data Name='AppVersion'>25.11.10.8</Data>"
    "<Data Name='AppTimeStamp'>684a0000</Data>"
    "<Data Name='ModuleName'>KERNELBASE.dll</Data>"
    "<Data Name='ModuleVersion'>10.0.26100.8246</Data>"
    "<Data Name='ModuleTimeStamp'>2614674e</Data>"
    "<Data Name='ExceptionCode'>c0000005</Data>"
    "<Data Name='FaultingOffset'>00164644</Data>"
    "<Data Name='ProcessId'>0x297c</Data>"
    "<Data Name='ProcessCreationTime'>0x1dce20439beaba3</Data>"
    "<Data Name='AppPath'>C:\\Program Files (x86)\\Citrix\\ICA Client\\AOTListenerService.exe</Data>"
    "<Data Name='ModulePath'>C:\\WINDOWS\\System32\\KERNELBASE.dll</Data>"
    "<Data Name='IntegratorReportId'>d2848160-2b5d-4ac6-b12e-5d430fe29fff</Data>"
    "<Data Name='PackageFullName'></Data>"
    "<Data Name='PackageRelativeAppId'></Data>"
    "</EventData></Event>";

TEST_CASE("extract_named_data + parse_application_error on a real Event 1000 XML",
          "[crash][parse]") {
    const auto fields = extract_named_data(kRealEvent1000Xml);
    // 15 named Data elements (incl. two empty package fields).
    REQUIRE(fields.size() == 15);
    CHECK(fields[0].first == "AppName");
    CHECK(fields[0].second == "AOTListenerService.exe");
    CHECK(fields.back().first == "PackageRelativeAppId");
    CHECK(fields.back().second.empty()); // empty <Data Name='...'></Data>

    const auto o = parse_application_error(fields);
    CHECK(o.process_name == "AOTListenerService.exe");      // AppName (bare, not "name ver ts")
    CHECK(o.faulting_module == "KERNELBASE.dll");           // ModuleName (index 3, by name)
    CHECK(o.termination.kind == "exception");
    CHECK(o.termination.code == 0xC0000005u);               // ExceptionCode (index 6)
    CHECK(o.termination.symbolic == "ACCESS_VIOLATION");
    CHECK(o.pid == 0x297cu);                                // ProcessId "0x297c" -> hex
    CHECK(o.image_path == "C:\\Program Files (x86)\\Citrix\\ICA Client\\AOTListenerService.exe");
    CHECK(o.platform == "windows");
}

TEST_CASE("parse_application_error tolerates missing fields", "[crash][parse]") {
    const auto empty = parse_application_error({});
    CHECK(empty.process_name.empty());
    CHECK(empty.pid == 0u);
    CHECK(empty.termination.code == 0u);

    // Only some names present -> the rest stay default, no throw.
    const std::vector<std::pair<std::string, std::string>> few = {
        {"AppName", "svc.exe"}, {"ModuleName", "svc.dll"}};
    const auto o = parse_application_error(few);
    CHECK(o.process_name == "svc.exe");
    CHECK(o.faulting_module == "svc.dll");
    CHECK(o.termination.code == 0u);
    CHECK(o.pid == 0u);
}

TEST_CASE("extract_named_data handles double-quoted attrs and self-closing Data",
          "[crash][parse]") {
    // EvtRender may use either quote style; a self-closing empty Data must not break.
    const auto f = extract_named_data(
        "<EventData><Data Name=\"AppName\">a.exe</Data><Data Name=\"X\"/></EventData>");
    REQUIRE(f.size() == 2);
    CHECK(f[0].first == "AppName");
    CHECK(f[0].second == "a.exe");
    CHECK(f[1].first == "X");
    CHECK(f[1].second.empty());
}

TEST_CASE("extract_named_data tolerates malformed XML without crashing", "[crash][parse]") {
    // The Application channel is world-writable: any local process can emit a crafted
    // Event 1000. The parser must never crash on malformed input — it returns what it
    // could parse (or nothing) and the caller defaults the rest.
    CHECK(extract_named_data("").empty());                         // empty input
    CHECK(extract_named_data("<EventData></EventData>").empty());  // no Data elements
    // Unterminated tag (no closing '>') — stop, don't read out of bounds.
    CHECK_NOTHROW(extract_named_data("<EventData><Data Name='X'"));
    // Missing </Data> — return what was parsed so far without overrunning.
    CHECK_NOTHROW(extract_named_data("<EventData><Data Name='X'>val"));
    // A Data element with no Name= attribute -> empty name, value preserved.
    const auto noname = extract_named_data("<EventData><Data>v</Data></EventData>");
    REQUIRE(noname.size() == 1);
    CHECK(noname[0].first.empty());
    CHECK(noname[0].second == "v");
}

TEST_CASE("parse_application_error defaults garbage hex fields to 0", "[crash][parse]") {
    // ProcessId / ExceptionCode are hex; a non-hex value (forged or locale-variant
    // event) must default to 0, not throw out of the OS callback.
    const std::vector<std::pair<std::string, std::string>> garbage = {
        {"AppName", "x.exe"}, {"ProcessId", "not-a-pid"}, {"ExceptionCode", "0xZZZZ"}};
    const auto o = parse_application_error(garbage);
    CHECK(o.process_name == "x.exe");
    CHECK(o.pid == 0u);
    CHECK(o.termination.code == 0u);
    // Empty hex strings likewise default rather than throw.
    const auto e = parse_application_error({{"ProcessId", ""}, {"ExceptionCode", ""}});
    CHECK(e.pid == 0u);
    CHECK(e.termination.code == 0u);
}

TEST_CASE("crash_observation_to_event maps to a ruleless DEX event", "[crash][event]") {
    CrashObservation o;
    o.process_name = "notepad.exe";
    o.pid = 1234;
    o.termination = {"exception", 0xC0000005u, "ACCESS_VIOLATION"};
    o.faulting_module = "ntdll.dll";
    o.timestamp_unix = 1718000000;
    o.platform = "windows";

    const auto ev = crash_observation_to_event(o, "evt-id-1");
    CHECK(ev.event_id() == "evt-id-1");
    CHECK(ev.rule_id() == std::string(kObservationRuleSentinel)); // ruleless sentinel
    CHECK(ev.event_type() == "process.crashed");
    CHECK(ev.guard_type() == "process");
    CHECK(ev.severity() == "info");
    CHECK(ev.guard_category().empty()); // the discriminator is NOT a category field
    CHECK(ev.expected_value().empty()); // a crash has no desired state
    CHECK(ev.detected_value().find("0xC0000005") != std::string::npos);
    CHECK(ev.detected_value().find("ACCESS_VIOLATION") != std::string::npos);
    CHECK(ev.detected_value().find("ntdll.dll") != std::string::npos);
    CHECK(ev.timestamp().seconds() == 1718000000);
    CHECK(ev.platform() == "windows");
}

TEST_CASE("crash_observation_to_event leaves timestamp unset when unknown", "[crash][event]") {
    CrashObservation o;
    o.process_name = "svc.exe";
    o.termination = {"exception", 0xC0000409u, "STACK_BUFFER_OVERRUN"};
    // timestamp_unix left 0 -> server stamps ingest time (mirrors drift events).
    const auto ev = crash_observation_to_event(o, "evt-id-2");
    CHECK_FALSE(ev.has_timestamp());
}

TEST_CASE("make_crash_observer is never null", "[crash][factory]") {
    auto obs = make_crash_observer();
    REQUIRE(obs != nullptr);
#if !defined(_WIN32)
    // Off Windows the collector is a no-op until the Linux/macOS collector slices
    // land (gated behind broader Guardian Linux/macOS work).
    bool fired = false;
    CHECK_FALSE(obs->start([&](const CrashObservation&) { fired = true; }));
    obs->stop();
    CHECK_FALSE(fired);
#endif
}
