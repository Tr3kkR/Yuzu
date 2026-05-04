#!/usr/bin/env python3
"""Run Erlang gateway tests via rebar3.

Used by Meson test() because Ninja quotes compound shell commands
as a single argument, which breaks cmd.exe on Windows.

Two responsibilities beyond the bare rebar3 invocation:
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
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

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

cmd = ["rebar3", "as", "test", suite]
if suite == "eunit":
    cmd += ["--dir", "apps/yuzu_gw/test"]

    # eunit_surefire writes its XML report to the literal path declared
    # in gateway/rebar.config eunit_opts (`{dir, "_build/test/eunit"}`),
    # which resolves relative to the rebar3 CWD = gateway_dir. That
    # path is NOT auto-created — `eunit_surefire:write_report/2` calls
    # `file:open` directly and crashes with `{error,enoent}` if the
    # directory is missing. On Linux runners with a long-lived gateway
    # checkout the dir often pre-exists from older non-REBAR_BASE_DIR
    # runs, hiding the bug. On the Windows runner — and on any fresh
    # checkout — REBAR_BASE_DIR redirects rebar3's own `_build` to
    # `_build_eunit`, so `_build/test/eunit` is never created and the
    # surefire listener crashes after every test passes (exit 1 on the
    # gateway eunit test even with 0 actual test failures).
    surefire_dir = Path(gateway_dir) / "_build" / "test" / "eunit"
    surefire_dir.mkdir(parents=True, exist_ok=True)

# For CT runs, set minimal perf parameters so the heavyweight perf suite
# finishes quickly.  The perf suite defaults to 10k agents, 50k heartbeats,
# and a 300-second endurance test — far too long for CI.
# Run full perf tests explicitly with default env vars:
#   cd gateway && rebar3 ct --suite=yuzu_gw_perf_SUITE
env = None
if suite == "ct":
    import os
    env = os.environ.copy()
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


def run_with_retry(args, label, max_attempts=4):
    """Run a rebar3 command with retry on hex.pm fetch flakes.

    Returns the final CompletedProcess. Stdout is teed to our stdout
    on every attempt so the operator sees what's happening live.

    Backoff: 5s, 10s, 20s between attempts (exponential). Total worst
    case is ~35s of waits across 4 attempts, plus the actual rebar3
    runtime per attempt.
    """
    for attempt in range(1, max_attempts + 1):
        result = subprocess.run(
            args,
            cwd=gateway_dir,
            env=env if env is not None else os.environ,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        output = result.stdout or ""
        sys.stdout.write(output)
        if result.returncode == 0:
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
        sys.exit(0)

sys.exit(result.returncode)
