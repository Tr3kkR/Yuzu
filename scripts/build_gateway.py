#!/usr/bin/env python3
"""Build the Erlang gateway using rebar3.

Used by Meson custom_target because Ninja quotes compound shell commands
(e.g. 'cd /d path && rebar3 compile') as a single argument, which breaks
cmd.exe on Windows.  This script works on all platforms.
"""
import glob
import os
import shutil
import signal
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

    # Resolve the Erlang toolchain WITHOUT hardcoding one host's layout. The
    # proven-good invocation is `<real escript.exe> <rebar3 escript file>
    # compile`: it bypasses the Chocolatey shim (which can lose env vars) and
    # the OTP 28 top-level launcher stub at <root>\bin\escript.exe (no useful
    # output non-interactively; can segfault with access violation 0xC0000005
    # under the choco path). The real escript.exe lives at
    # <root>\erts-*\bin\escript.exe across modern (Erlang OTP\) and legacy
    # (erl-<ver>\) layouts. We just resolve the PATHS portably instead of
    # assuming Shulgi's C:\Erlang junction + Chocolatey path.
    #
    # Resolution precedence (per the runner provisioning contract — see
    # deploy/windows/Provision-Windows-Runner.ps1 + toolchain-manifest.json):
    #   1. explicit env vars (YUZU_ESCRIPT / ESCRIPT, YUZU_REBAR3 / REBAR3)
    #   2. the real erts escript globbed across common OTP install roots
    #   3. PATH (shutil.which)
    def _env_file(*names):
        for n in names:
            v = os.environ.get(n)
            if v and os.path.isfile(v):
                return v
        return None

    escript = _env_file("YUZU_ESCRIPT", "ESCRIPT")
    if not escript:
        roots = [r"C:\Erlang"]
        roots += glob.glob(r"C:\Program Files\Erlang*")
        roots += glob.glob(r"C:\Program Files\erl*")
        candidates = []
        for root in roots:
            candidates += sorted(
                glob.glob(os.path.join(root, "erts-*", "bin", "escript.exe")),
                reverse=True,
            )
            candidates.append(os.path.join(root, "bin", "escript.exe"))
        escript = next((c for c in candidates if os.path.isfile(c)), None)
    if not escript:
        escript = shutil.which("escript")

    rebar3_escript = _env_file("YUZU_REBAR3", "REBAR3")
    if not rebar3_escript:
        rebar3_escript = next(
            (
                c
                for c in (
                    r"C:\tools\rebar3\rebar3",
                    r"C:\ProgramData\chocolatey\lib\rebar3\tools\rebar3",
                )
                if os.path.isfile(c)
            ),
            None,
        )

    if escript and rebar3_escript:
        cmd = [escript, rebar3_escript, "compile"]
    else:
        # Last resort: a PATH-resolved rebar3 launcher. shutil.which returns the
        # full path incl. extension (.cmd/.bat), which subprocess CAN exec — a
        # bare "rebar3" cannot be exec'd on Windows (no PATHEXT resolution), the
        # old FileNotFoundError trap.
        rebar3_launcher = shutil.which("rebar3")
        if rebar3_launcher:
            cmd = [rebar3_launcher, "compile"]
        else:
            sys.stderr.write(
                "build_gateway: could not locate the Erlang toolchain on Windows.\n"
                "  Set YUZU_ESCRIPT and YUZU_REBAR3 (see "
                "deploy/windows/toolchain-manifest.json), or put escript.exe and\n"
                "  rebar3 on PATH.\n"
                f"  escript={escript!r} rebar3={rebar3_escript!r} "
                f"which(rebar3)={shutil.which('rebar3')!r}\n"
            )
            sys.exit(1)
else:
    cmd = ["rebar3", "compile"]

# Bound the rebar3 compile so a hung gateway build fails fast instead of
# burning the whole CI job's timeout (a stuck dep fetch or an orphaned
# erl.exe/epmd.exe holding a lock once silently ate 120 min). Default 15 min;
# override with YUZU_GATEWAY_BUILD_TIMEOUT (seconds; 0 or negative disables).
# rebar3 spawns escript -> erl -> beam, so on timeout we must kill the whole
# process tree — a bare proc.kill() leaves those grandchildren orphaned
# (especially on Windows), which is the very lock-holder we're guarding against.
try:
    timeout_s = int(os.environ.get("YUZU_GATEWAY_BUILD_TIMEOUT", "900"))
except ValueError:
    timeout_s = 900

popen_kwargs = {"cwd": gateway_dir, "env": env}
if sys.platform != "win32":
    # New session so the whole tree shares a process group we can signal.
    popen_kwargs["start_new_session"] = True


def _kill_tree(p):
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(p.pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            p.kill()


proc = subprocess.Popen(cmd, **popen_kwargs)
try:
    sys.exit(proc.wait(timeout=timeout_s if timeout_s > 0 else None))
except subprocess.TimeoutExpired:
    sys.stderr.write(
        f"\nbuild_gateway: rebar3 compile exceeded {timeout_s}s "
        "(YUZU_GATEWAY_BUILD_TIMEOUT) — killing the process tree and failing.\n"
        f"  cmd: {cmd}\n"
        "  Likely a hung dep fetch or an orphaned erl.exe/epmd.exe holding a "
        "lock; see docs/erlang-gateway-build.md.\n"
    )
    sys.stderr.flush()
    _kill_tree(proc)
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        pass
    sys.exit(124)  # conventional timeout exit code (matches GNU `timeout`)
except KeyboardInterrupt:
    _kill_tree(proc)
    raise
