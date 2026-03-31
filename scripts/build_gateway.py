#!/usr/bin/env python3
"""Build the Erlang gateway using rebar3.

Used by Meson custom_target because Ninja quotes compound shell commands
(e.g. 'cd /d path && rebar3 compile') as a single argument, which breaks
cmd.exe on Windows.  This script works on all platforms.
"""
import os
import shutil
import subprocess
import sys
import tempfile

gateway_dir = sys.argv[1]
env = None

if sys.platform == "win32":
    # MSYS2 sets TEMP/TMP to "/tmp" which native Windows programs resolve to
    # "\tmp\" — a nonexistent path that breaks file moves (e.g. rebar3 dep fetch).
    real_temp = tempfile.gettempdir()
    env = os.environ.copy()
    env["TEMP"] = real_temp
    env["TMP"] = real_temp

    # Bypass the Chocolatey shim for rebar3 — it can lose env vars.
    # Use escript.exe directly via the C:\Erlang junction (space-free path).
    erlang_junction = r"C:\Erlang"
    escript = os.path.join(erlang_junction, "bin", "escript.exe")
    rebar3_escript = r"C:\ProgramData\chocolatey\lib\rebar3\tools\rebar3"
    if os.path.isfile(escript) and os.path.isfile(rebar3_escript):
        cmd = [escript, rebar3_escript, "compile"]
    else:
        cmd = ["rebar3", "compile"]
else:
    cmd = ["rebar3", "compile"]

result = subprocess.run(cmd, cwd=gateway_dir, env=env)
sys.exit(result.returncode)
