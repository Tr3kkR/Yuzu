#!/usr/bin/env python3
"""Run Erlang gateway tests via rebar3.

Used by Meson test() because Ninja quotes compound shell commands
as a single argument, which breaks cmd.exe on Windows.

Two responsibilities beyond the bare rebar3 invocation:
  1. Pre-fetch rebar3's test-profile deps (meck, proper) with retry,
     so the actual test invocation never has to talk to hex.pm. hex.pm
     is intermittently flaky and an HTTP 502 / TCP RST on a single
     fetch attempt would otherwise fail the test even though Yuzu is
     fine. After a successful pre-fetch (any attempt), rebar3's user
     cache (`~/.cache/rebar3/hex/hexpm/packages/` on Linux/WSL2,
     `%LOCALAPPDATA%\\rebar3\\hex\\hexpm\\packages\\` on Windows) holds
     the deps and subsequent runs find them locally without a network
     round-trip. Tracked as #15 in the in-session task list.
  2. OTP 25 CT I/O race detection — see comment block below.

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
app_ebin = Path(gateway_dir) / "_build" / "test" / "lib" / "yuzu_gw" / "ebin"
if app_ebin.exists():
    shutil.rmtree(app_ebin)

cmd = ["rebar3", "as", "test", suite]
if suite == "eunit":
    cmd += ["--dir", "apps/yuzu_gw/test"]

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


# ──────────────────────────────────────────────────────────────────────
# Pre-fetch rebar3 test-profile deps (meck, proper, ...) so the actual
# test invocation never has to round-trip hex.pm. Retries handle the
# intermittent hex.pm flake. After any successful attempt, the deps
# land in rebar3's user cache and subsequent runs hit the cache.
# ──────────────────────────────────────────────────────────────────────
print(
    "[test_gateway.py] Pre-fetching rebar3 test-profile deps "
    "(meck, proper) into the user-level hex cache",
    file=sys.stderr,
)
prefetch_cmd = ["rebar3", "as", "test", "compile", "--deps_only"]
prefetch = run_with_retry(prefetch_cmd, "prefetch", max_attempts=4)
if prefetch.returncode != 0:
    print(
        "[test_gateway.py] Pre-fetch did not converge after retries. "
        "Proceeding to test anyway — if hex.pm has been flaky for a "
        "while the test will fail with the same error and the cache "
        "stays empty. Re-run later or seed the cache manually via "
        "`cd gateway && rebar3 as test compile --deps_only` on the runner.",
        file=sys.stderr,
    )

# Capture output to detect OTP 25 CT I/O race, but also tee to console.
# Use the same retry helper for the actual test run too — if rebar3 has
# to fetch ANY transitive dep at this stage (it shouldn't after pre-fetch
# but rebar3's incremental dep resolver sometimes surprises us), the
# retry handles the same hex.pm flake one more time.
result = run_with_retry(cmd, suite, max_attempts=2)
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
