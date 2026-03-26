#!/usr/bin/env python3
"""Run Erlang gateway tests via rebar3.

Used by Meson test() because Ninja quotes compound shell commands
as a single argument, which breaks cmd.exe on Windows.

Usage:
    test_gateway.py <gateway_dir> eunit   # EUnit tests
    test_gateway.py <gateway_dir> ct      # Common Test suites
"""
import shutil
import subprocess
import sys
from pathlib import Path

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

result = subprocess.run(cmd, cwd=gateway_dir, env=env)
sys.exit(result.returncode)
