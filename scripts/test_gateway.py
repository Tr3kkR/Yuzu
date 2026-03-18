#!/usr/bin/env python3
"""Run Erlang gateway tests via rebar3.

Used by Meson test() because Ninja quotes compound shell commands
as a single argument, which breaks cmd.exe on Windows.

Usage:
    test_gateway.py <gateway_dir> eunit   # EUnit tests
    test_gateway.py <gateway_dir> ct      # Common Test suites
"""
import subprocess
import sys

gateway_dir = sys.argv[1]
suite = sys.argv[2]  # "eunit" or "ct"

result = subprocess.run(
    ["rebar3", "as", "test", suite],
    cwd=gateway_dir,
)
sys.exit(result.returncode)
