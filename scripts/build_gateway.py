#!/usr/bin/env python3
"""Build the Erlang gateway using rebar3.

Used by Meson custom_target because Ninja quotes compound shell commands
(e.g. 'cd /d path && rebar3 compile') as a single argument, which breaks
cmd.exe on Windows.  This script works on all platforms.
"""
import subprocess
import sys

gateway_dir = sys.argv[1]
result = subprocess.run(["rebar3", "compile"], cwd=gateway_dir)
sys.exit(result.returncode)
