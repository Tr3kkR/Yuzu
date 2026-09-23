#!/usr/bin/env python3
"""Run Erlang gateway tests via rebar3.

Used by Meson test() because Ninja quotes compound shell commands
as a single argument, which breaks cmd.exe on Windows.

Three responsibilities beyond the bare rebar3 invocation:
  1. Retry the rebar3 test command up to 4 times when hex.pm fetch
     fails. hex.pm is intermittently flaky and an HTTP 502 / TCP RST
     on a single fetch attempt would otherwise fail the test even
     though Yuzu is fine. The retry helper detects the
     "Failed to fetch and copy dep:" sentinel and backs off
     exponentially (5s, 10s, 20s) between attempts. After any
     successful attempt rebar3's user-level hex cache holds the deps
     so subsequent runs find them locally without a network
     round-trip — on the persistent self-hosted Windows runner this
     means hex.pm is only touched on the very first run.
  2. OTP 25 CT I/O race detection — see comment block below.
  3. Live-streamed output under a hard wall-clock deadline
     (`_run_streamed`, `_RUN_DEADLINE_SECS`) BELOW meson's own
     suite-level test timeout. A prior version of this wrapper called
     `subprocess.run(..., stdout=PIPE)` and only wrote the captured
     output after the child fully exited — its own docstring claimed
     output was "teed... live", which was false (a rule-3 truth
     finding: the comment described intended behaviour, not what the
     code did). When a Windows CI hang left that child never exiting,
     every failed run showed "zero output" — which told us nothing
     about where the hang occurred and cost three blind CI rounds
     chasing the wrong mechanism (HA WS-4 4.3a, PR #4573). Streaming
     plus a deadline that dumps the process tree and force-kills it
     means a future hang is diagnosed HERE, in this log, instead of
     reported as a featureless timeout by the outer harness.

A previous iteration (b33f1df) added an explicit pre-fetch step
running `rebar3 as test compile --deps_only` ahead of the actual
test invocation, intending to populate the hex cache earlier. On
Windows this turned out to leave `_build/test/lib/yuzu_gw/` in a
state where the subsequent `rebar3 as test eunit` compile race-d
with cover instrumentation, and cover would error with
`{cover,get_abstract_code,...,enoent,gateway_pb.beam}` on the
gpb-generated proto module — sometimes during gateway eunit,
sometimes during gateway ct, depending on which test ran first.
The pre-fetch was redundant on persistent runners (cache already
warm) so it was removed in favor of the simpler retry-on-test
flow. Linux and macOS were unaffected throughout.

Usage:
    test_gateway.py <gateway_dir> eunit   # EUnit tests
    test_gateway.py <gateway_dir> ct      # Common Test suites
"""
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from erlang_toolchain import base_env, rebar3_prefix  # noqa: E402

# Ensure locally-installed OTP 28 and rebar3 are on PATH (Meson inherits
# system PATH which may still point at the distro's older OTP 25 packages).
_extra_paths = [
    os.path.expanduser("~/.cache/rebar3/bin"),  # rebar3 local install
    "/usr/local/bin",                            # OTP 28 from source
]
_path = os.environ.get("PATH", "")
for p in reversed(_extra_paths):
    if os.path.isdir(p) and p not in _path:
        _path = p + ":" + _path
os.environ["PATH"] = _path

gateway_dir = sys.argv[1]
suite = sys.argv[2]  # "eunit" or "ct"

# Clean the app's beam directory to prevent stale beam files from crashing
# Erlang's cover module during instrumentation.  Only the app ebin is
# removed — dependency beams (meck, proper, grpcbox, …) are kept so they
# don't need to be recompiled on every run.
#
# REBAR_BASE_DIR selects the rebar3 `_build/` root; meson.build sets
# it per-suite (`_build_eunit` vs `_build_ct`) so the two gateway
# suites never race on the same ebin tree. Absolute paths win over
# relative — meson hands us an absolute `_build_<suite>`; fall back to
# `<gateway>/_build` when the env var is unset (e.g. direct script
# invocation for local debugging).
_base = os.environ.get("REBAR_BASE_DIR") or str(Path(gateway_dir) / "_build")
app_ebin = Path(_base) / "test" / "lib" / "yuzu_gw" / "ebin"
if app_ebin.exists():
    shutil.rmtree(app_ebin)

cmd = rebar3_prefix() + ["as", "test", suite]
if suite == "ct":
    # Every CT suite lives in apps/yuzu_gw/test/ct/. `rebar3 ct` with no
    # `--dir` (or with `--dir apps/yuzu_gw/test`, which ct does NOT recurse)
    # discovers ZERO suites, prints "All 0 tests passed." and exits 0 --
    # the #4800 false green that hid #4707 and #4708 from every Meson/CI
    # run. The zero-executed guard at the bottom of this file fails the run
    # if a future path move ever recreates that.
    cmd += ["--dir", "apps/yuzu_gw/test/ct"]
elif suite == "eunit":
    cmd += ["--dir", "apps/yuzu_gw/test"]

    # Pre-create the eunit_surefire report dir (gateway/rebar.config
    # eunit_opts `{dir, "_build/test/eunit"}`, resolved relative to the
    # rebar3 CWD = gateway_dir). Belt-and-suspenders only: OTP 26+
    # eunit_surefire:init/1 already self-creates this dir via
    # filelib:ensure_dir + file:make_dir, so the dir's existence is not
    # the failure mode it was once thought to be (#1403).
    #
    # NOTE on the `eunit_surefire:write_report ... {error,enoent}` crash
    # seen in Windows eunit logs: that is a SEPARATE, HARMLESS artifact,
    # not a build-breaker. With `--dir`, eunit's top-level group is named
    # `directory "<abs path>"`; eunit_surefire:escape_suitename/1 turns
    # the path's `/` into `:`, producing a filename like
    # `TEST-directory_C::...:test.xml`. `:` is illegal in a Windows
    # filename, so file:open fails with enoent on every Windows run. It
    # does NOT affect the exit code: eunit's result comes from the
    # eunit_tty listener, and eunit:test waits for listeners to terminate
    # with ANY exit reason (see lib/eunit/src/eunit.erl). The surefire XML
    # is not consumed by CI, so the broken report is moot. The actual
    # intermittent #1403 failure was an unrelated test-isolation ETS race
    # (yuzu_gw_test_registry now serialises registry start across modules)
    # — its crash cancelled tests, which DID fail the build, and happened
    # to print alongside the always-present surefire noise.
    surefire_dir = Path(gateway_dir) / "_build" / "test" / "eunit"
    surefire_dir.mkdir(parents=True, exist_ok=True)

# For CT runs, set minimal perf parameters so the heavyweight perf suite
# finishes quickly.  The perf suite defaults to 10k agents, 50k heartbeats,
# and a 300-second endurance test — far too long for CI.
# Run full perf tests explicitly with default env vars:
#   cd gateway && rebar3 ct --suite=yuzu_gw_perf_SUITE
# base_env() carries the Windows temp-dir fix (TEMP/TMP/TMPDIR -> a native
# path) so the test path's cold _build can't hit the gpb-plugin \\tmp\
# robocopy hang either. See scripts/erlang_toolchain.py.
env = base_env()
if suite == "ct":
    env["YUZU_PERF_AGENTS"] = "10"
    env["YUZU_PERF_HEARTBEATS"] = "100"
    env["YUZU_PERF_FANOUT"] = "10"
    env["YUZU_PERF_CHURN_AGENTS"] = "10"
    env["YUZU_PERF_CHURN_CYCLES"] = "1"
    env["YUZU_PERF_ENDURANCE_AGENTS"] = "10"
    env["YUZU_PERF_ENDURANCE_SECS"] = "1"

# ──────────────────────────────────────────────────────────────────────
# hex.pm flake retry helper
# ──────────────────────────────────────────────────────────────────────
HEX_FAIL_PATTERN = "Failed to fetch and copy dep:"

# PER SUITE, and each value must stay BELOW that suite's own meson
# `timeout:` in the root meson.build `test('gateway eunit'|'gateway ct')`
# definitions, so a hang is diagnosed HERE — with a process-tree dump and a
# targeted kill — rather than reported as featureless "TIMEOUT, zero output"
# by the outer harness. This gap between the two timeouts is itself
# load-bearing: it is what makes the marker+dump below reachable before
# meson's own kill fires. A single 540s value used to serve both suites
# while `gateway ct` had a 300s meson timeout, so for ct meson always killed
# first and the dump was unreachable (#4800). Change a meson timeout and
# its value here together.
_SUITE_DEADLINE_SECS = {
    "eunit": 540,  # meson timeout 600
    "ct": 540,     # meson timeout 600
}
_RUN_DEADLINE_SECS = _SUITE_DEADLINE_SECS[suite]


class _ProcessDeadlineExceeded(Exception):
    pass


def _dump_process_tree():
    """Best-effort process listing, for diagnosing a hung child tree."""
    try:
        if os.name == "nt":
            subprocess.run(["tasklist", "/V"], check=False)
        else:
            subprocess.run(["ps", "-ef"], check=False)
    except Exception as exc:  # noqa: BLE001 - diagnostic path, never fatal
        print(f"[test_gateway.py] process-tree dump failed: {exc}", file=sys.stderr)


def _kill_process_tree(proc):
    """Kill the whole child tree, not just the immediate rebar3 process."""
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)], check=False
            )
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception as exc:  # noqa: BLE001 - best-effort; proc.kill() below backstops
        print(f"[test_gateway.py] process-tree kill failed: {exc}", file=sys.stderr)
    finally:
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


def _run_streamed(args, deadline_secs):
    """Run a subprocess with output TEED LIVE to our stdout (not buffered
    until exit, unlike a bare `subprocess.run(..., stdout=PIPE)`), under a
    hard wall-clock deadline.

    Returns (returncode, captured_output_str). On a deadline breach, dumps
    a process listing, force-kills the whole child tree, and returns
    returncode -1 with whatever output was captured up to that point —
    the hang is then located in the log instead of silent.

    POSIX: the child runs in its own process group (`start_new_session`)
    so `_kill_process_tree` can reach grandchildren (e.g. a `peer`-spawned
    BEAM) the same way an outer job-object/process-tree kill would.
    """
    popen_kwargs = dict(
        cwd=gateway_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(args, **popen_kwargs)
    lines = []
    line_queue: "queue.Queue[str | None]" = queue.Queue()

    def _reader():
        try:
            for line in iter(proc.stdout.readline, ""):
                line_queue.put(line)
        finally:
            line_queue.put(None)

    reader_thread = threading.Thread(target=_reader, daemon=True)
    reader_thread.start()

    start = time.monotonic()
    deadline_hit = False
    while True:
        remaining = deadline_secs - (time.monotonic() - start)
        if remaining <= 0:
            deadline_hit = True
            break
        try:
            line = line_queue.get(timeout=remaining)
        except queue.Empty:
            continue
        if line is None:
            break
        sys.stdout.write(line)
        sys.stdout.flush()
        lines.append(line)

    if deadline_hit:
        print(
            f"\n[test_gateway.py] DEADLINE EXCEEDED after {deadline_secs}s — "
            "dumping process tree and killing the child before meson's own "
            "suite-level timeout fires blind:",
            file=sys.stderr,
        )
        _dump_process_tree()
        _kill_process_tree(proc)
        # Drain whatever the reader thread already queued.
        while True:
            try:
                line = line_queue.get_nowait()
            except queue.Empty:
                break
            if line is None:
                break
            sys.stdout.write(line)
            lines.append(line)
        try:
            returncode = proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            returncode = -1
    else:
        returncode = proc.wait()

    return returncode, "".join(lines)


def run_with_retry(args, label, max_attempts=4):
    """Run a rebar3 command with retry on hex.pm fetch flakes.

    Returns an object with `.returncode`/`.stdout`, matching the subset of
    `subprocess.CompletedProcess` this script's callers use. Output is
    streamed live (see `_run_streamed`) and also captured for the hex.pm
    sentinel check below.

    Backoff: 5s, 10s, 20s between attempts (exponential). Total worst
    case is ~35s of waits across 4 attempts, plus the actual rebar3
    runtime per attempt.
    """

    class _Result:
        def __init__(self, returncode, stdout):
            self.returncode = returncode
            self.stdout = stdout

    result = _Result(-1, "")
    for attempt in range(1, max_attempts + 1):
        returncode, output = _run_streamed(args, _RUN_DEADLINE_SECS)
        result = _Result(returncode, output)
        if returncode == 0:
            return result
        if HEX_FAIL_PATTERN in output and attempt < max_attempts:
            backoff = 5 * (2 ** (attempt - 1))
            print(
                f"\n[test_gateway.py] {label}: hex.pm fetch failure detected "
                f"(attempt {attempt}/{max_attempts}) — sleeping {backoff}s and retrying",
                file=sys.stderr,
            )
            time.sleep(backoff)
            continue
        # Non-hex failure or last attempt — surface it.
        return result
    return result


# Capture output to detect OTP 25 CT I/O race, but also tee to console.
# run_with_retry handles hex.pm fetch flakes by detecting the
# "Failed to fetch and copy dep:" sentinel and backing off between
# attempts. 4 attempts × ~35s of waits at most before giving up.
result = run_with_retry(cmd, suite, max_attempts=4)
output = result.stdout or ""

# ──────────────────────────────────────────────────────────────────────
# Zero-executed guard (#4800)
# ──────────────────────────────────────────────────────────────────────
# rebar3 exits 0 when it discovers nothing to run, so a green exit code
# alone proves nothing. A run is only a pass if its final summary line
# reports at least one EXECUTED (passed + failed) test. Summary shapes:
#   ct:    "All 52 tests passed."
#          "Failed 6 tests. Skipped 2 (0, 2) tests. Passed 44 tests."
#   eunit: "All 311 tests passed."
#          "Failed: 2.  Skipped: 0.  Passed: 309."
#          "There were no tests to run."
# The LAST summary wins (rebar3 prints one per run; anything earlier is
# test-emitted noise). No recognisable summary on an otherwise-green run
# is ALSO a failure: we cannot confirm anything ran.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_SUMMARY_RE = re.compile(
    # ct and eunit, all green
    r"All (?P<all>\d+) tests? passed\."
    # eunit, exactly one test
    r"|(?P<one>\bTest passed\.)"
    # ct: each clause is printed only when its count is non-zero, except
    # "Passed", which is always printed
    r"|(?:Failed (?P<cf>\d+) tests?\. )?(?:Skipped \d+ \(\d+, \d+\) tests?\. )?"
    r"Passed (?P<cp>\d+) tests?\."
    # eunit, any failure/skip
    r"|Failed: (?P<ef>\d+)\.\s+Skipped: \d+\.\s+Passed: (?P<ep>\d+)\."
    r"|(?P<none>There were no tests to run)"
)


def _executed_count(text):
    """Executed (passed + failed) count from the last summary, or None."""
    last = None
    for m in _SUMMARY_RE.finditer(_ANSI_RE.sub("", text)):
        last = m
    if last is None:
        return None
    g = last.group
    if g("all") is not None:
        return int(g("all"))
    if g("one") is not None:
        return 1
    if g("none") is not None:
        return 0
    if g("cp") is not None:
        return int(g("cf") or 0) + int(g("cp"))
    return int(g("ef")) + int(g("ep"))


def _require_tests_executed(text, label, returncode):
    """Turn a green exit with zero executed tests into a failure."""
    if returncode != 0:
        return returncode
    executed = _executed_count(text)
    if executed is None:
        print(f"\n[test_gateway.py] {label}: rebar3 exited 0 but printed no "
              "recognisable test summary -- cannot confirm any test ran. "
              "Failing (#4800).", file=sys.stderr)
        return 1
    if executed == 0:
        print(f"\n[test_gateway.py] {label}: rebar3 exited 0 but executed ZERO "
              "tests -- the suite directory or --dir is wrong. Failing so this "
              "cannot pass as a false green (#4800).", file=sys.stderr)
        return 1
    print(f"\n[test_gateway.py] {label}: {executed} tests executed.")
    return 0

# OTP 25 has a known race where the CT I/O handler (test_server_io)
# terminates before all suite completion messages are written, causing
# rebar3 to exit with code 1 even though all tests passed.  Detect this
# by checking if the output contains "0 failed" and the crash signature.
if result.returncode != 0 and suite == "ct":
    has_io_crash = "ct_util_server got EXIT" in output or "test_server_io" in output
    # Count failed tests from CT output lines like "N ok, M failed"
    fail_counts = re.findall(r"(\d+)\s+failed", output)
    all_zero_fails = fail_counts and all(int(n) == 0 for n in fail_counts)
    if has_io_crash and all_zero_fails:
        print("\n[test_gateway.py] OTP 25 CT I/O race detected — "
              "all tests passed but CT runner crashed on teardown. "
              "Treating as success.")
        sys.exit(_require_tests_executed(output, suite, 0))

sys.exit(_require_tests_executed(output, suite, result.returncode))
