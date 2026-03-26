#!/usr/bin/env python3
"""Run Erlang gateway tests via rebar3.

Used by Meson test() because Ninja quotes compound shell commands
as a single argument, which breaks cmd.exe on Windows.

Usage:
    test_gateway.py <gateway_dir> eunit   # EUnit tests
    test_gateway.py <gateway_dir> ct      # Common Test suites
"""
import os
import re
import shutil
import subprocess
import sys
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

# Capture output to detect OTP 25 CT I/O race, but also tee to console.
result = subprocess.run(cmd, cwd=gateway_dir, env=env,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True)
output = result.stdout or ""
sys.stdout.write(output)

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
