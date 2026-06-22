#!/usr/bin/env python3
r"""Shared Erlang toolchain resolution for the Meson gateway wrappers.

Both build_gateway.py and test_gateway.py invoke rebar3 from Meson on every
platform, and both must handle two Windows-specific hazards *identically* —
when they drift, things break. (They did: build_gateway.py was de-hardcoded
in #1606, test_gateway.py was not, so gateway ct/eunit failed with
FileNotFoundError [WinError 2] on the Wee Tam runners while the build passed.)

  1. `subprocess.run(["rebar3", ...])` cannot exec a bare/extensionless
     `rebar3` or a `.CMD` shim on Windows — CreateProcess does not apply
     PATHEXT to the program name — so it raises FileNotFoundError [WinError 2]
     even though `rebar3` is on PATH. Resolve the real escript + rebar3
     escript (the proven `<escript.exe> <rebar3-escript> ...` invocation,
     which also bypasses the choco shim / OTP launcher-stub segfault), and
     fall back to a shutil.which() launcher path *with* its extension.

  2. MSYS2 exports TEMP/TMP=/tmp, which native programs resolve to the bogus
     UNC path \\tmp\. On a cold _build, rebar3's gpb-plugin install then runs
     `robocopy /move \\tmp\... <dest>` and hangs ~forever retrying a
     nonexistent SMB host. Force a real native temp dir, and set TMPDIR too
     (rebar3's system_tmpdir() reads ["TMPDIR","TEMP","TMP"] in that order).

Resolution precedence mirrors the runner provisioning contract — see
deploy/windows/Provision-Windows-Runner.ps1 + toolchain-manifest.json.
"""
import glob
import os
import shutil
import sys
import tempfile


def rebar3_prefix():
    """Return the argv prefix that runs rebar3 portably.

    Callers append their own subcommand, e.g.
        rebar3_prefix() + ["compile"]
        rebar3_prefix() + ["as", "test", "eunit", "--dir", "..."]
    On non-Windows this is just ["rebar3"]; on Windows it resolves the real
    escript + rebar3 escript (or a which()-resolved launcher with extension).
    Exits 1 with an actionable message if the toolchain can't be located.
    """
    if sys.platform != "win32":
        return ["rebar3"]

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
        return [escript, rebar3_escript]

    # Last resort: a PATH-resolved launcher WITH its extension (.cmd/.bat),
    # which subprocess CAN exec — a bare "rebar3" cannot.
    launcher = shutil.which("rebar3")
    if launcher:
        return [launcher]

    sys.stderr.write(
        "erlang_toolchain: could not locate the Erlang toolchain on Windows.\n"
        "  Set YUZU_ESCRIPT and YUZU_REBAR3 (see "
        "deploy/windows/toolchain-manifest.json), or put escript.exe and\n"
        "  rebar3 on PATH.\n"
        f"  escript={escript!r} rebar3={rebar3_escript!r} "
        f"which(rebar3)={shutil.which('rebar3')!r}\n"
    )
    sys.exit(1)


def base_env():
    """A copy of os.environ with a sane native temp dir on Windows.

    Prefer RUNNER_TEMP (guaranteed-native, per-runner, e.g. D:\\ci\\work-N\\
    _temp); validate it's a real drive-letter dir (never trust a "/tmp" that
    tempfile.gettempdir() may echo back); set TEMP/TMP/TMPDIR. No-op off
    Windows (returns a plain os.environ copy).
    """
    env = os.environ.copy()
    if sys.platform == "win32":
        real_temp = os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
        if not (len(real_temp) >= 2 and real_temp[1] == ":" and os.path.isdir(real_temp)):
            real_temp = os.path.join(os.environ.get("LOCALAPPDATA", r"C:\Windows"), "Temp")
            os.makedirs(real_temp, exist_ok=True)
        env["TEMP"] = real_temp
        env["TMP"] = real_temp
        env["TMPDIR"] = real_temp
    return env
