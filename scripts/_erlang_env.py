"""Self-healing Erlang environment preparation for Python build/test wrappers.

`scripts/ensure-erlang.sh` is the canonical bash helper that probes for an
Erlang/OTP install (kerl → asdf → Homebrew → MSYS2 Windows installer) and
prepends its `bin/` directory to PATH. The C++ build system relies on
operators sourcing it before invoking `meson compile` so `escript`, `erl`,
and `rebar3` are all on PATH when Meson's `custom_target` for the
Erlang gateway fires.

But `meson compile` is sometimes invoked in a fresh shell — by the
governance pipeline, by a CI runner, by an operator who forgot — and
the Python wrappers (`build_gateway.py`, `test_gateway.py`) then exec
`rebar3`, whose `#!/usr/bin/env escript` shebang dies with
`/usr/bin/env: 'escript': No such file or directory`. This module
closes that gap defensively: each Python wrapper calls
`ensure_erlang_on_path()` at startup, and if `escript` isn't already
visible we source the bash helper in a subprocess and import its
mutated PATH back into our own `os.environ`.

Why source the bash helper instead of re-implementing the probe in
Python? Single source of truth. The probe is non-trivial (kerl
parsing, asdf compatibility across the 0.16 rewrite, macOS Apple
Silicon vs Intel Homebrew prefix, OTP installer version sorting on
Windows) and we don't want two copies drifting. bash is mandatory on
every supported platform (Linux, macOS, WSL2, MSYS2 on Windows; native
cmd.exe / PowerShell are explicitly out of scope per CLAUDE.md).
"""
import os
import shutil
import subprocess
from pathlib import Path


def ensure_erlang_on_path() -> None:
    """Prepend an Erlang/OTP bin dir to PATH if escript is not already visible.

    No-op when `escript` resolves via the current PATH. Otherwise runs
    `bash -c "source scripts/ensure-erlang.sh && printf '%s' \"$PATH\""`
    and overwrites `os.environ['PATH']` with the result. The helper
    script always exits 0; if it didn't actually find Erlang, our
    post-check `shutil.which('escript')` stays None and the caller
    can decide what to do (typically: let the subsequent `rebar3` fail
    with a more informative error than the bare ENOENT shebang abort).
    """
    if shutil.which("escript"):
        return

    script_dir = Path(__file__).resolve().parent
    ensure_script = script_dir / "ensure-erlang.sh"
    if not ensure_script.is_file():
        return

    # Resolve bash. On MSYS2 Windows it lives at /usr/bin/bash exposed
    # via the MSYS shim; on Linux/macOS/WSL2 it's just `bash` on PATH.
    bash = shutil.which("bash")
    if not bash:
        return

    try:
        result = subprocess.run(
            [bash, "-c", f"source '{ensure_script}' >/dev/null 2>&1 && printf '%s' \"$PATH\""],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError):
        return

    if result.returncode == 0 and result.stdout:
        os.environ["PATH"] = result.stdout
