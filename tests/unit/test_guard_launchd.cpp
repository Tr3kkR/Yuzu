/**
 * test_guard_launchd.cpp — pure state-mapping logic for the macOS launchd service
 * guard (LaunchdServiceGuard).
 *
 * The helpers are compiled on EVERY platform (only the kqueue engine is
 * Apple-gated), so these cases run and assert identically on Windows, macOS and
 * Linux CI — the guard_systemd.cpp discipline. The landmines this pins down:
 * (1) `launchctl print` output nests blocks that carry their own `state = active`
 * lines even when the JOB is not running — the parser must read top-level fields
 * only; (2) only the definitive "Could not find service" marker may read as
 * absence — a transient failure must never fabricate an Absent (false "stopped"
 * drift); (3) launchd's state vocabulary collapses onto the two published tokens
 * {running, stopped} WITHOUT a schema enum change.
 *
 * Fixtures are captured from a real box (macOS 26.5.2 / build 25F84), trimmed to
 * the structural shape the parser must survive.
 */

#include <yuzu/agent/guard_launchd.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <string>
#include <type_traits>
#include <vector>

using namespace yuzu::agent;
using Desired = ServiceGuard::Desired;

namespace {
// A fixed steady_clock instant at `ms` milliseconds past the epoch — lets the
// decision-machine tests drive the debounce window deterministically (the absolute
// origin is irrelevant; only deltas matter to launchd_decide_emit).
std::chrono::steady_clock::time_point at(long long ms) {
    return std::chrono::steady_clock::time_point{std::chrono::milliseconds(ms)};
}

// Captured from `launchctl print system/com.apple.tccd.system` (macOS 26.5.2),
// trimmed: a RUNNING job. Keeps the structures the parser must not trip on —
// multi-line nested blocks (arguments / environment / endpoints), a single-line
// brace block (resource coalition), spaced keys ("last exit code"), and a nested
// `pid`-adjacent numeric field inside endpoints.
constexpr const char* kRunningFixture =
    "system/com.apple.tccd.system = {\n"
    "\tactive count = 2\n"
    "\tpath = /System/Library/LaunchDaemons/com.apple.tccd.system.plist\n"
    "\ttype = LaunchDaemon\n"
    "\tstate = running\n"
    "\n"
    "\tprogram = /System/Library/PrivateFrameworks/TCC.framework/Support/tccd\n"
    "\targuments = {\n"
    "\t\t/System/Library/PrivateFrameworks/TCC.framework/Support/tccd\n"
    "\t\tsystem\n"
    "\t}\n"
    "\n"
    "\tenvironment = {\n"
    "\t\tXPC_SERVICE_NAME => com.apple.tccd.system\n"
    "\t}\n"
    "\n"
    "\tdomain = system\n"
    "\tpid = 608\n"
    "\tlast exit code = (never exited)\n"
    "\n"
    "\tendpoints = {\n"
    "\t\t\"com.apple.tccd.system\" = {\n"
    "\t\t\tport = 0x14b03\n"
    "\t\t\tactive = 1\n"
    "\t\t}\n"
    "\t}\n"
    "\n"
    "\tresource coalition = { ID = 361  type = resource  state = active  name = com.apple.tccd.system }\n"
    "\n"
    "\tspawn type = adaptive (6)\n"
    "\tproperties = supports transactions | system service\n"
    "}\n";

// Captured from `launchctl print system/com.apple.newsyslog` (macOS 26.5.2),
// trimmed: a loaded but NOT-running job. The load-bearing detail (observed live):
// nested coalition blocks report `state = active` at depth 2 while the job's own
// top-level state is "not running" — depth tracking is what keeps this honest.
constexpr const char* kNotRunningFixture =
    "system/com.apple.newsyslog = {\n"
    "\tpath = /System/Library/LaunchDaemons/com.apple.newsyslog.plist\n"
    "\tstate = not running\n"
    "\tprogram = /usr/sbin/newsyslog\n"
    "\tlast exit code = 0\n"
    "\tresource coalition = {\n"
    "\t\tID = 512\n"
    "\t\tstate = active\n"
    "\t}\n"
    "\tjetsam coalition = {\n"
    "\t\tstate = active\n"
    "\t}\n"
    "}\n";

// Captured from `launchctl print system/com.yuzu.does-not-exist` (exit code 113).
constexpr const char* kAbsentOutput =
    "Bad request.\n"
    "Could not find service \"com.yuzu.does-not-exist\" in domain for system\n";
} // namespace

// Ownership contract (cpp-safety): the core owns a kqueue fd + a std::thread; the
// guard owns the core. Copy or move would double-close / double-join. Non-copyable
// AND non-movable, exactly like the other guards.
static_assert(!std::is_copy_constructible_v<LaunchdWatchCore>);
static_assert(!std::is_copy_assignable_v<LaunchdWatchCore>);
static_assert(!std::is_move_constructible_v<LaunchdWatchCore>);
static_assert(!std::is_move_assignable_v<LaunchdWatchCore>);
static_assert(!std::is_copy_constructible_v<LaunchdServiceGuard>);
static_assert(!std::is_copy_assignable_v<LaunchdServiceGuard>);
static_assert(!std::is_move_constructible_v<LaunchdServiceGuard>);
static_assert(!std::is_move_assignable_v<LaunchdServiceGuard>);

TEST_CASE("parse_launchctl_print reads a running job's top-level fields",
          "[guardian][guard][launchd][parse]") {
    const LaunchdJobInfo info = parse_launchctl_print(kRunningFixture);
    CHECK(info.state == LaunchdState::Running);
    REQUIRE(info.pid.has_value());
    CHECK(*info.pid == 608);
    CHECK(info.path == "/System/Library/LaunchDaemons/com.apple.tccd.system.plist");
    CHECK(info.program == "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd");
}

TEST_CASE("parse_launchctl_print: nested `state = active` never overrides a not-running job",
          "[guardian][guard][launchd][parse]") {
    const LaunchdJobInfo info = parse_launchctl_print(kNotRunningFixture);
    // The coalition sub-blocks say "active"; the JOB says "not running". Reading
    // the nested lines would fabricate a false compliant for a service-running
    // rule (or mask a real drift) — observed on a live box, not hypothetical.
    CHECK(info.state == LaunchdState::NotRunning);
    CHECK_FALSE(info.pid.has_value()); // a not-running job has no top-level pid
    CHECK(info.program == "/usr/sbin/newsyslog");
}

TEST_CASE("parse_launchctl_print maps the state vocabulary",
          "[guardian][guard][launchd][parse]") {
    CHECK(parse_launchctl_print("x = {\n\tstate = running\n}\n").state == LaunchdState::Running);
    CHECK(parse_launchctl_print("x = {\n\tstate = not running\n}\n").state ==
          LaunchdState::NotRunning);
    CHECK(parse_launchctl_print("x = {\n\tstate = waiting\n}\n").state == LaunchdState::Waiting);
    // Unrecognised / missing state never throws and never masquerades as real.
    CHECK(parse_launchctl_print("x = {\n\tstate = spawning\n}\n").state == LaunchdState::Unknown);
    CHECK(parse_launchctl_print("x = {\n\ttype = LaunchDaemon\n}\n").state ==
          LaunchdState::Unknown);
    CHECK(parse_launchctl_print("").state == LaunchdState::Unknown);
    CHECK(parse_launchctl_print("}}}{{{ total garbage = = = {").state == LaunchdState::Unknown);
    // Stray closing braces drive brace-depth negative; the clamp must recover so a
    // real job block AFTER the underflow still parses at depth 1 (not depth 0,
    // where its `state` line would be skipped as top-level noise).
    CHECK(parse_launchctl_print("}\n}\nx = {\n\tstate = running\n}\n").state ==
          LaunchdState::Running);
}

TEST_CASE("parse_launchctl_print: a brace in a field value does not corrupt depth",
          "[guardian][guard][launchd][parse]") {
    // A job-controlled field value (program path / argument) containing a stray
    // '{' or '}' must NOT be counted as a block open/close — structural tracking
    // keys on line-END '{' and lone '}', so the top-level `state` after it is
    // still read at depth 1 (UP-7: char-counting would hide `state` and the job
    // would evade a service-stopped rule / hold silently).
    CHECK(parse_launchctl_print("x = {\n\tprogram = /opt/w{eird/bin\n\tstate = running\n}\n")
              .state == LaunchdState::Running);
    CHECK(parse_launchctl_print("x = {\n\tpath = /a}b{c\n\tstate = not running\n}\n").state ==
          LaunchdState::NotRunning);
    // A real single-line block before `state` is still net-zero (self-balancing).
    CHECK(parse_launchctl_print(
              "x = {\n\tresource coalition = { ID = 5  state = active }\n\tstate = running\n}\n")
              .state == LaunchdState::Running);
}

TEST_CASE("parse_launchctl_print: a malformed pid is ignored, a valid one is read",
          "[guardian][guard][launchd][parse]") {
    CHECK_FALSE(parse_launchctl_print("x = {\n\tpid = (none)\n}\n").pid.has_value());
    CHECK_FALSE(parse_launchctl_print("x = {\n\tpid = -5\n}\n").pid.has_value());
    const auto info = parse_launchctl_print("x = {\n\tstate = running\n\tpid = 12345\n}\n");
    REQUIRE(info.pid.has_value());
    CHECK(*info.pid == 12345);
}

TEST_CASE("classify_launchctl_print: absence needs the marker AND a failing exit",
          "[guardian][guard][launchd][absence]") {
    // Genuine absence ships BOTH signals (marker + exit 113, observed live).
    CHECK(classify_launchctl_print(113, kAbsentOutput).state == LaunchdState::Absent);
    CHECK(classify_launchctl_print(1, kAbsentOutput).state == LaunchdState::Absent);
    // A SUCCESSFUL print whose output contains the marker must NOT read as
    // absent — a root-planted marker in job-controlled fields would otherwise
    // mask a running job as absent (false-compliant for service-stopped;
    // adversarial-review C5). It parses normally instead.
    CHECK(classify_launchctl_print(0, kAbsentOutput).state == LaunchdState::Unknown);
    const std::string spoofed =
        std::string("system/com.yuzu.spoof = {\n\tstate = running\n\tpid = 4242\n"
                    "\tnote = Could not find service\n}\n");
    CHECK(classify_launchctl_print(0, spoofed).state == LaunchdState::Running);
    // Transient failures must NOT read as absence — else a fork/permission blip
    // fabricates a false "stopped" drift (the systemd_error_name_is_absence rule).
    CHECK(classify_launchctl_print(-1, "").state == LaunchdState::Unknown);  // popen failed
    // A signal-killed launchctl (exit_code -1, !WIFEXITED) is transient even if
    // its partial output already carried the marker — absence needs a REAL exit.
    CHECK(classify_launchctl_print(-1, kAbsentOutput).state == LaunchdState::Unknown);
    CHECK(classify_launchctl_print(1, "Bad request.\n").state == LaunchdState::Unknown);
    CHECK(classify_launchctl_print(0, "").state == LaunchdState::Unknown);   // empty output
    // A failing exit with a FULL, parseable job block still holds — never trust
    // a job block from a failing launchctl (the classifier gates on exit first).
    CHECK(classify_launchctl_print(1, kRunningFixture).state == LaunchdState::Unknown);
    // A clean exit parses through.
    CHECK(classify_launchctl_print(0, kRunningFixture).state == LaunchdState::Running);
    CHECK(classify_launchctl_print(0, kNotRunningFixture).state == LaunchdState::NotRunning);
}

TEST_CASE("only Unknown is transitional (held)", "[guardian][guard][launchd][state]") {
    CHECK(launchd_state_is_transitional(LaunchdState::Unknown));
    CHECK_FALSE(launchd_state_is_transitional(LaunchdState::Running));
    CHECK_FALSE(launchd_state_is_transitional(LaunchdState::NotRunning));
    CHECK_FALSE(launchd_state_is_transitional(LaunchdState::Waiting));
    CHECK_FALSE(launchd_state_is_transitional(LaunchdState::Absent));
}

TEST_CASE("service-running is satisfied only by running", "[guardian][guard][launchd][compliance]") {
    CHECK(launchd_is_compliant(Desired::Running, LaunchdState::Running));
    CHECK_FALSE(launchd_is_compliant(Desired::Running, LaunchdState::NotRunning));
    CHECK_FALSE(launchd_is_compliant(Desired::Running, LaunchdState::Waiting));
    CHECK_FALSE(launchd_is_compliant(Desired::Running, LaunchdState::Absent));
}

TEST_CASE("service-stopped is satisfied by not-running, waiting, or absent",
          "[guardian][guard][launchd][compliance]") {
    CHECK(launchd_is_compliant(Desired::Stopped, LaunchdState::NotRunning));
    CHECK(launchd_is_compliant(Desired::Stopped, LaunchdState::Waiting)); // idle ⇒ not running
    CHECK(launchd_is_compliant(Desired::Stopped, LaunchdState::Absent));  // gone ⇒ not running
    CHECK_FALSE(launchd_is_compliant(Desired::Stopped, LaunchdState::Running));
}

TEST_CASE("detected_value token stays in the cross-platform vocabulary",
          "[guardian][guard][launchd][token]") {
    // running/stopped/absent reuse the Windows guard's words so the dashboard
    // renders uniformly; the launchd-native word is kept where Windows has none.
    CHECK(launchd_state_token(LaunchdState::Running) == "running");
    CHECK(launchd_state_token(LaunchdState::NotRunning) == "stopped");
    CHECK(launchd_state_token(LaunchdState::Absent) == "absent");
    CHECK(launchd_state_token(LaunchdState::Waiting) == "waiting");
    CHECK(launchd_state_token(LaunchdState::Unknown) == "unknown");
}

TEST_CASE("valid_launchd_label mirrors the server authoring charset",
          "[guardian][guard][launchd][label]") {
    CHECK(valid_launchd_label("com.apple.tccd.system")); // reverse-DNS is the norm
    CHECK(valid_launchd_label("com.yuzu.agent"));
    CHECK(valid_launchd_label("my-app_1@host"));
    CHECK(valid_launchd_label(std::string(256, 'a')));    // exactly at the 256 cap
    CHECK_FALSE(valid_launchd_label(""));                 // empty
    CHECK_FALSE(valid_launchd_label("com apple tccd"));   // space
    CHECK_FALSE(valid_launchd_label("system/com.apple")); // '/' — no domain smuggling
    CHECK_FALSE(valid_launchd_label("evil;rm -rf"));      // shell metachars (injection gate)
    CHECK_FALSE(valid_launchd_label("a$(reboot)"));
    CHECK_FALSE(valid_launchd_label(std::string(257, 'a'))); // over the 256 cap
}

// ── launchd_decide_emit — the transition state machine (pure, runs everywhere) ──
// Identical commit rules to systemd_decide_emit; mirrored cases pin the shared
// contract (a divergence between the two guards' dedup behaviour is a bug).

TEST_CASE("launchd_decide_emit: terminal-change machine", "[guardian][guard][launchd][emit]") {
    LaunchdEmitState st;
    constexpr std::uint64_t deb = 1000;
    CHECK(launchd_decide_emit(Desired::Running, LaunchdState::Unknown, st, deb, at(0)).action ==
          EmitAction::Hold); // not understood → held, no commit
    CHECK(launchd_decide_emit(Desired::Running, LaunchdState::Running, st, deb, at(10)).action ==
          EmitAction::CompliantSilent); // compliant edge committed, silent
    CHECK(launchd_decide_emit(Desired::Running, LaunchdState::Running, st, deb, at(20)).action ==
          EmitAction::NoChange); // same terminal — silent
    const auto d = launchd_decide_emit(Desired::Running, LaunchdState::NotRunning, st, deb, at(40));
    CHECK(d.action == EmitAction::Emit); // drift edge
    CHECK(d.collapsed_count == 0);
    // A mid-stream Unknown (a transient popen blip — launchd's most common real
    // perturbation) is held and must NOT disturb the committed terminal: the next
    // observation of the SAME committed state is still NoChange, not a re-emit.
    CHECK(launchd_decide_emit(Desired::Running, LaunchdState::Unknown, st, deb, at(50)).action ==
          EmitAction::Hold);
    CHECK(launchd_decide_emit(Desired::Running, LaunchdState::NotRunning, st, deb, at(60)).action ==
          EmitAction::NoChange);
}

TEST_CASE("launchd_decide_emit: a debounce-suppressed drift is never lost",
          "[guardian][guard][launchd][emit]") {
    LaunchdEmitState st;
    constexpr std::uint64_t deb = 1000;
    CHECK(launchd_decide_emit(Desired::Running, LaunchdState::NotRunning, st, deb, at(0)).action ==
          EmitAction::Emit);
    // A DIFFERENT drift state inside the window is folded — and crucially NOT
    // committed, so the same state recurring inside the window stays foldable.
    CHECK(launchd_decide_emit(Desired::Running, LaunchdState::Absent, st, deb, at(100)).action ==
          EmitAction::Suppressed);
    CHECK(launchd_decide_emit(Desired::Running, LaunchdState::Absent, st, deb, at(200)).action ==
          EmitAction::Suppressed);
    // Past the window the Absent drift re-surfaces with its collapsed count.
    const auto d = launchd_decide_emit(Desired::Running, LaunchdState::Absent, st, deb, at(1500));
    CHECK(d.action == EmitAction::Emit);
    CHECK(d.collapsed_count == 2);
    // The collapsed count MUST reset on emit — a fresh drift after recovery reports
    // 0, not a running total (a reset regression would double-count collapse forever).
    CHECK(launchd_decide_emit(Desired::Running, LaunchdState::Running, st, deb, at(3000)).action ==
          EmitAction::CompliantSilent);
    const auto d2 = launchd_decide_emit(Desired::Running, LaunchdState::NotRunning, st, deb, at(4100));
    CHECK(d2.action == EmitAction::Emit);
    CHECK(d2.collapsed_count == 0);
}

TEST_CASE("launchd_decide_emit: re-drift after recovery still reports",
          "[guardian][guard][launchd][emit]") {
    LaunchdEmitState st;
    constexpr std::uint64_t deb = 100;
    CHECK(launchd_decide_emit(Desired::Running, LaunchdState::NotRunning, st, deb, at(0)).action ==
          EmitAction::Emit);
    // Recovery commits the compliant state...
    CHECK(launchd_decide_emit(Desired::Running, LaunchdState::Running, st, deb, at(2000)).action ==
          EmitAction::CompliantSilent);
    // ...so a later relapse into the SAME stopped state is a genuine change.
    CHECK(launchd_decide_emit(Desired::Running, LaunchdState::NotRunning, st, deb, at(4000)).action ==
          EmitAction::Emit);
}

TEST_CASE("launchd_decide_emit: service-stopped compliance direction",
          "[guardian][guard][launchd][emit]") {
    LaunchdEmitState st;
    constexpr std::uint64_t deb = 1000;
    CHECK(launchd_decide_emit(Desired::Stopped, LaunchdState::NotRunning, st, deb, at(0)).action ==
          EmitAction::CompliantSilent); // stopped is compliant for want-stopped
    CHECK(launchd_decide_emit(Desired::Stopped, LaunchdState::Running, st, deb, at(10)).action ==
          EmitAction::Emit);            // running is the drift
    CHECK(launchd_decide_emit(Desired::Stopped, LaunchdState::Waiting, st, deb, at(2000)).action ==
          EmitAction::CompliantSilent); // idle ⇒ not running ⇒ compliant
}

TEST_CASE("LaunchdServiceGuard rejects an invalid label on every platform",
          "[guardian][guard][launchd][start]") {
    ServiceGuard::Config cfg;
    cfg.rule_id = "rule-launchd-1";
    cfg.rule_name = "bad label";
    cfg.service_name = "evil;rm -rf"; // fails the charset gate before any subprocess
    LaunchdServiceGuard g(std::move(cfg), [](const GuardDrift&) {});
    CHECK_FALSE(g.start());
    CHECK(g.rule_id() == "rule-launchd-1");
}

#if !defined(__APPLE__)
TEST_CASE("LaunchdServiceGuard: no-op on unsupported platforms",
          "[guardian][guard][launchd][platform]") {
    ServiceGuard::Config cfg;
    cfg.rule_id = "rule-launchd-2";
    cfg.rule_name = "off-mac stub";
    cfg.service_name = "com.yuzu.agent"; // valid label; the core stub is what refuses
    LaunchdServiceGuard g(std::move(cfg), [](const GuardDrift&) {});
    CHECK_FALSE(g.start());
    g.stop(); // idempotent, must not crash without a start
}
#endif

#if defined(__APPLE__)
// Engine lifecycle — runs on any mac, no live I/O (zero watches ⇒ the worker
// thread only ever waits on the idle timer; no launchctl is ever spawned). Pins
// the one-shot + running-gate contract cpp-safety flagged.
TEST_CASE("LaunchdWatchCore: one-shot lifecycle + running-gate",
          "[guardian][guard][launchd][lifecycle]") {
    LaunchdWatchCore core;
    core.start([](const LaunchdWatchEvent&) {}, [](const std::string&, const std::string&) {});
    core.stop(); // clean stop of a started-but-watchless core: joins, no crash
    // After stop the core is dead — watch() must fail its running-gate, never
    // report a dead core as armed.
    const auto after_stop = core.watch("k", "com.apple.newsyslog");
    CHECK_FALSE(after_stop.has_value());
    core.stop(); // idempotent second stop
}

TEST_CASE("LaunchdWatchCore: destructor without start is clean",
          "[guardian][guard][launchd][lifecycle]") {
    // No start() ever ran: dtor → stop() must short-circuit on !started and hold
    // no fd/thread (would otherwise UB on the unjoinable thread).
    { LaunchdWatchCore core; }
    SUCCEED("destroyed a never-started core without crashing");
}

TEST_CASE("LaunchdServiceGuard: a valid label arms and disarms cleanly on macOS",
          "[guardian][guard][launchd][lifecycle]") {
    // The macOS factory product really arms (unlike the off-mac stub). newsyslog
    // exists on every mac; desired=stopped keeps it compliant/silent so the test
    // asserts lifecycle, not drift. No sink assertions — just clean start/stop.
    ServiceGuard::Config cfg;
    cfg.rule_id = "rule-launchd-lifecycle";
    cfg.service_name = "com.apple.newsyslog";
    cfg.desired = Desired::Stopped;
    auto g = make_service_guard(cfg, [](const GuardDrift&) {});
    REQUIRE(g != nullptr);
    CHECK(g->start()); // real arm through the macOS launchd core
    g->stop();
}

// LIVE integration test — exercises the paths the pure cases cannot: the poll →
// classify → decide → sink chain and the NOTE_EXIT overlay against a REAL job.
// Gated on YUZU_LAUNCHD_LIVE_LABEL so normal CI skips it; runs on a real mac.
// Recipe (drift within one 30s poll cycle):
//   sudo launchctl submit -l yuzu-probe -- /bin/sleep 3600     # running job
//   ( sleep 4; sudo launchctl remove yuzu-probe ) &            # transition it
//   YUZU_LAUNCHD_LIVE_LABEL=yuzu-probe ./yuzu_agent_tests "[launchd][live]"
// Arms desired=running: the running job is compliant (silent) until it is
// removed/stopped, when the guard must emit an "absent" (remove) or "stopped"
// (plain stop) drift.
TEST_CASE("live: LaunchdServiceGuard detects a real job transition",
          "[guardian][guard][launchd][live]") {
    const char* label = std::getenv("YUZU_LAUNCHD_LIVE_LABEL");
    if (!label || !*label) {
        SUCCEED("YUZU_LAUNCHD_LIVE_LABEL unset — skipping live launchd integration test");
        return;
    }
    struct Collector {
        std::mutex m;
        std::condition_variable cv;
        std::vector<GuardDrift> drifts;
        void push(const GuardDrift& d) {
            std::lock_guard lk(m);
            drifts.push_back(d);
            cv.notify_all();
        }
        bool wait_for_stop_drift(std::chrono::milliseconds to) {
            std::unique_lock lk(m);
            return cv.wait_for(lk, to, [&] {
                for (const auto& d : drifts)
                    if (d.detected_value == "stopped" || d.detected_value == "absent")
                        return true;
                return false;
            });
        }
    } col;

    ServiceGuard::Config cfg;
    cfg.rule_id = "live-launchd-1";
    cfg.rule_name = "live transition probe";
    cfg.service_name = label;
    cfg.desired = Desired::Running; // running = compliant; a stop/remove must drift
    cfg.enforce = false;
    cfg.event_debounce_ms = 0; // observe every transition (no collapse) in the test
    LaunchdServiceGuard g(std::move(cfg), [&](const GuardDrift& d) { col.push(d); });
    REQUIRE(g.start());
    // The job is running at arm (compliant → silent). The external remove/stop is
    // caught by NOTE_EXIT (~0ms as root) or the 30s poll backstop (unprivileged).
    const bool drifted = col.wait_for_stop_drift(std::chrono::seconds(45));
    g.stop();
    CHECK(drifted);
}
#endif
