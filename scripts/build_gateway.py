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

    # Prefer the chocolatey rebar3 shim — it works under Python
    # subprocess invocation. Direct escript.exe + rebar3-escript invocation
    # crashes with STATUS_ACCESS_VIOLATION (0xC0000005) when launched via
    # Python subprocess.run on this Windows host (reproducible from any
    # cwd, with a clean env, no stdin attached). The shim escapes whatever
    # console-handle / startup-info quirk causes the crash.
    rebar3_shim = r"C:\ProgramData\chocolatey\bin\rebar3.exe"
    if os.path.isfile(rebar3_shim):
        cmd = [rebar3_shim, "compile"]
    else:
        cmd = ["rebar3", "compile"]
else:
    cmd = ["rebar3", "compile"]

result = subprocess.run(cmd, cwd=gateway_dir, env=env)
sys.exit(result.returncode)
