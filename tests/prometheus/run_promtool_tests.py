#!/usr/bin/env python3
r"""Run the Prometheus alert-rule unit tests under promtool.

THIS SCRIPT IS THE ONLY HOME for the promtool invocation and for the pinned
image. `.github/workflows/docs-lint.yml`'s `prometheus-rules` job calls it with
`YUZU_TEST_ENABLE_PROMTOOL_DOCKER=1` and `meson test --suite docs` calls it
without, so CI and a local run are provably the same code. That follows the
pattern this repo already uses for a CI-pulled image — `PROBE_IMAGE` in
`scripts/ci/verify-healthcheck-invariants.sh`, `PG_IMAGE` in
`scripts/ci/ensure-postgres.sh`: the pin lives in the script and the workflows
carry zero copies of it.

An alert rule is code that runs in production and never compiles, and
`promtool check rules` proves only that the PromQL parses. A rule that parses
perfectly and can never fire for the case it was written for passes it — which
is how `YuzuAuditRetentionNotRunning` shipped blind to a crash-looping server
(#2553). `test rules` is the behaviour gate.

WHY DOCKER IS OPT-IN. `scripts/ci/flake-retry.py` runs `meson test` with NO
`--suite` filter on three REQUIRED build legs, so a docker-dependent test in the
`docs` suite would put a container-registry dependency on all three. An earlier
version of this wiring did exactly that and was reverted (#2553). With the
opt-in unset and no usable native promtool this exits 77 (meson SKIP), so an
unattended leg cannot reach a registry at all.

SKIP-vs-FAIL contract, mirroring the repo's `YUZU_TEST_ENABLE_PG` convention:

  - opt-in UNSET and no usable native promtool -> exit 77 (meson SKIP). A
    developer without the toolchain is not blocked by it.
  - opt-in SET but docker unusable            -> FAIL. The operator asked for
    this path; a broken one is a real failure, never a quiet skip.
  - a usable promtool, either way             -> run it, and FAIL on a bad rule.

The opt-in takes PRECEDENCE over a native promtool, so "the opt-in runs the
pinned image" is true rather than nearly-true: a stray 3.x binary on a
self-hosted box cannot silently answer for it.

VERSION CHECK. Prometheus 3.0 made range selectors left-open, which shifts
`increase()` and `resets()` by a sample at window edges — exactly what these
cases measure — so the MAJOR is load-bearing. A `promtool` that prints no
parseable version is treated as unusable rather than trusted: without that, a
stub which only `exit 0`s reports success for every rule (measured on the
reverted first attempt). It raises the bar from any exit-0 binary named
`promtool` to one that also prints a plausible banner; it does NOT authenticate
the binary, and anyone who can place that binary already has code execution
here. The authoritative gate is the CI job, which always uses the pinned image.

Unverified and deliberately unreached: on Windows the docker branch would mount
`C:\...:/w:ro` under LOCAL SYSTEM, which nobody has tested. The opt-in keeps CI
out of that path; if you enable it there, that mount is what you are testing.

`--selftest` exercises the pure logic (version parse, argv construction) with no
promtool, no docker and no network, matching `scripts/ci/flake-retry.py
--selftest` and `scripts/ci/check-plugin-spawn-lexical.sh --selftest`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SKIP = 77

# Pinned as tag@digest, the form this repo uses elsewhere (`busybox:1.37@sha256:`,
# `postgres:18.4-bookworm@sha256:`): the tag keeps the version readable for a
# human and an updater, the digest is what actually gets pulled. This is
# promtool 3.13.1, the build these cases were written and mutation-checked
# against. Note `prom/prometheus:3.13.1` is not a tag Docker Hub publishes — the
# registry uses a `v` prefix.
PROMTOOL_IMAGE = (
    "prom/prometheus:v3.13.1@sha256:"
    "3c42b892cf723fa54d2f262c37a0e1f80aa8c8ddb1da7b9b0df9455a35a7f893"
)

# The only major whose range-selector semantics these cases were validated
# against. A different major SKIPs rather than silently passing.
PINNED_MAJOR = 3

DOCKER_OPT_IN = "YUZU_TEST_ENABLE_PROMTOOL_DOCKER"

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES = "docs/prometheus/yuzu-alerts.yml"
TESTS = "tests/prometheus/yuzu-alerts.test.yml"

# Namespace/resource limits: the container parses a test file a fork PR can
# control. The mount is read-only and no credential is present, so the bound is
# runner CPU and time, but there is no reason for this to have a network.
#
# The `--tmpfs /tmp` is REQUIRED, not belt-and-braces: `promtool test rules`
# creates a `/tmp/test_storage<n>` TSDB per case, so `--read-only` alone fails
# every case with "read-only file system". Measured, not predicted. Keeping the
# rootfs read-only and giving `/tmp` an ephemeral noexec mount is the pairing
# that actually works.
DOCKER_HARDENING = [
    "--network", "none",
    "--read-only",
    "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
    "--pids-limit", "256",
    "--memory", "1g",
]


def run(argv: list[str]) -> int:
    print("+ " + " ".join(argv), flush=True)
    return subprocess.run(argv, cwd=REPO_ROOT).returncode


def parse_major(version_output: str) -> int | None:
    """Major version from a `promtool --version` banner, or None if unparseable.

    Split out from the subprocess call so `--selftest` can exercise it.
    """
    m = re.search(r"version (\d+)\.(\d+)\.(\d+)", version_output)
    return int(m.group(1)) if m else None


def native_promtool() -> tuple[str, int] | None:
    """`(path, major)` for a usable promtool on PATH, else None.

    Returns the RESOLVED path, and the caller executes that same path — not the
    bare name — so a PATH change between the check and the run cannot swap the
    binary, and Windows' application-directory search order does not apply.
    """
    exe = shutil.which("promtool")
    if not exe:
        return None
    try:
        proc = subprocess.run(
            [exe, "--version"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError) as ex:
        print(f"note: `{exe} --version` could not be run ({ex})", flush=True)
        return None
    # The banner lands on stderr in some builds, stdout in others.
    major = parse_major(proc.stdout + proc.stderr)
    if major is None:
        print(
            f"note: `{exe} --version` printed no parseable version; treating it "
            f"as unusable rather than trusting its exit code",
            flush=True,
        )
        return None
    return exe, major


def docker_usable() -> bool:
    """`docker info`, not `which docker`.

    The binary is frequently present where the daemon is down or the user is not
    in the docker group.
    """
    if not shutil.which("docker"):
        return False
    return subprocess.run(
        ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0


def pull_with_retry() -> bool:
    """Retry a transient registry hiccup rather than call it a broken rule."""
    import time

    for attempt in (1, 2, 3):
        if run(["docker", "pull", "--quiet", PROMTOOL_IMAGE]) == 0:
            return True
        if attempt < 3:
            print(f"pull attempt {attempt} failed, retrying in 10s", flush=True)
            time.sleep(10)
    return False


def docker_argv() -> list[str]:
    return [
        "docker", "run", "--rm",
        "-v", f"{REPO_ROOT}:/w:ro",
        *DOCKER_HARDENING,
        "--entrypoint", "/bin/promtool", PROMTOOL_IMAGE,
    ]


def selftest() -> int:
    """Pure logic only: no promtool, no docker, no network, no filesystem."""
    failures = []

    def check(name: str, got, want):
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    # Version parsing is what stops a stub binary reporting success.
    check("real banner",
          parse_major("promtool, version 3.13.1 (branch: HEAD, revision: abc)"), 3)
    check("stderr banner", parse_major("promtool, version 2.55.1 (branch: HEAD)"), 2)
    check("major 4", parse_major("promtool, version 4.0.0"), 4)
    check("silent stub", parse_major(""), None)
    check("no version token", parse_major("promtool\nusage: ..."), None)
    check("truncated version", parse_major("promtool, version 3.13"), None)

    # The container must never gain a network or a writable rootfs.
    argv = docker_argv()
    for flag in ("--network", "none", "--read-only", "--pids-limit", "--memory",
                 "--tmpfs"):
        if flag not in argv:
            failures.append(f"docker argv missing {flag}")
    if "--rm" not in argv:
        failures.append("docker argv missing --rm")
    # `--read-only` without a writable /tmp fails every promtool case; the two
    # must move together.
    if "--read-only" in argv and not any(a.startswith("/tmp:") for a in argv):
        failures.append("--read-only without a /tmp tmpfs breaks promtool test rules")
    ro_mounts = [a for a in argv if a.endswith(":/w:ro")]
    if len(ro_mounts) != 1:
        failures.append(f"expected exactly one read-only mount, got {ro_mounts}")

    # The pin must stay tag@digest so the version stays readable.
    if "@sha256:" not in PROMTOOL_IMAGE or ":v" not in PROMTOOL_IMAGE:
        failures.append(f"image pin is not tag@digest: {PROMTOOL_IMAGE}")
    if f"v{PINNED_MAJOR}." not in PROMTOOL_IMAGE:
        failures.append(
            f"pinned image {PROMTOOL_IMAGE} disagrees with PINNED_MAJOR={PINNED_MAJOR}"
        )

    for f in failures:
        print(f"SELFTEST FAIL: {f}", flush=True)
    print(f"selftest: {'FAIL' if failures else 'ok'}", flush=True)
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()

    opted_in = bool(os.environ.get(DOCKER_OPT_IN))

    # The opt-in takes precedence: an explicit request for the pinned image must
    # not be answered by whatever happens to be on PATH.
    if not opted_in:
        native = native_promtool()
        if native is not None:
            exe, major = native
            if major != PINNED_MAJOR:
                print(
                    f"SKIP: {exe} is major {major}; these cases are validated only "
                    f"against major {PINNED_MAJOR} (Prometheus 3.0 made range "
                    f"selectors left-open, which moves increase()/resets() at "
                    f"window edges — the exact thing these cases measure). Install "
                    f"a {PINNED_MAJOR}.x promtool, or set {DOCKER_OPT_IN}=1 to use "
                    f"the pinned image.",
                    flush=True,
                )
                return SKIP
            print(f"using native promtool: {exe} (major {major})", flush=True)
            return run([exe, "check", "rules", RULES]) or \
                run([exe, "test", "rules", TESTS])

        print(
            f"SKIP: no usable promtool on PATH and {DOCKER_OPT_IN} is unset. Set "
            f"{DOCKER_OPT_IN}=1 to run them via the pinned image, or install a "
            f"promtool {PINNED_MAJOR}.x. CI runs these in the `prometheus-rules` "
            f"job either way.",
            flush=True,
        )
        return SKIP

    # Opt-in SET: a broken docker is now a FAILURE, not a skip.
    if not docker_usable():
        sys.exit(
            f"FAIL: {DOCKER_OPT_IN} is set but docker is not usable (not "
            f"installed, daemon down, or no permission). Unset it to skip these "
            f"tests instead."
        )

    if not pull_with_retry():
        sys.exit(f"FAIL: could not pull {PROMTOOL_IMAGE} after 3 attempts.")

    base = docker_argv()
    return run(base + ["check", "rules", f"/w/{RULES}"]) or \
        run(base + ["test", "rules", f"/w/{TESTS}"])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
