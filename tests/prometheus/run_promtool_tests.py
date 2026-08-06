#!/usr/bin/env python3
"""Run the Prometheus alert-rule unit tests under promtool.

Exists so `meson test --suite docs` and `/test` can exercise the same cases CI
runs in `.github/workflows/docs-lint.yml` (job `prometheus-rules`). Without it
the promtool cases run ONLY in cloud CI, and every self-hosted leg -- which is
where most pre-push verification actually happens -- skips them silently.

THIS HARNESS IS THE SECOND ATTEMPT. The first was reverted (#2553) with four
defects, and each one is why a specific rule below exists rather than the
obvious simpler thing:

  1. It registered a DOCKER-DEPENDENT test in the meson `docs` suite, and
     `scripts/ci/flake-retry.py` runs `meson test` with NO `--suite` filter on
     three REQUIRED build legs. That put a Docker Hub dependency on all three --
     strictly worse than the problem the registration was meant to solve. Docker
     is therefore OPT-IN here (`YUZU_TEST_ENABLE_PROMTOOL_DOCKER`), so an
     unattended leg that never sets it cannot reach a registry at all.
  2. It preferred whatever `promtool` was on PATH with no version check, while
     the test file it runs says -- in the same commit -- to run under the pinned
     digest and not whatever is on PATH. A stub `promtool` that only `exit 0`s
     turned the gate GREEN. Hence `_native_promtool_version`: an unusable or
     wrong-major promtool SKIPS loudly, and a skip is never reported as a pass.
  3. The meson path had no pull retry (the workflow's did).
  4. The pinned digest lived in two files under a "keep in step" comment with
     nothing enforcing it. `assert_digest_in_step()` makes drift a FAILURE, and
     it is a pure file read -- no network, safe on every leg.

Unverified and deliberately unreached: the Windows leg would mount `C:\\...:/w:ro`
under LOCAL SYSTEM, which nobody has tested. The opt-in gate keeps CI out of
that path; if you enable it on Windows, that mount is what you are testing.

SKIP-vs-FAIL contract, mirroring the repo's `YUZU_TEST_ENABLE_PG` convention:

  - Docker opt-in UNSET and no usable native promtool -> exit 77 (meson SKIP).
    A developer without the toolchain is not blocked by it.
  - Docker opt-in SET but docker unusable                 -> FAIL. The operator
    asked for this path; a broken one is a real failure, never a quiet skip.
  - A usable promtool of the pinned major, either way     -> run it, and FAIL on
    a bad rule. Once the toolchain is real, a broken rule is a real failure.

Prometheus 3.0 made range selectors left-open, which shifts `increase()` and
`resets()` by a sample at window edges -- exactly what these cases measure. The
MAJOR is therefore load-bearing, which is what the version check enforces.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SKIP = 77

# Pinned by DIGEST, matching how this repo pins actions by SHA: a floating tag
# would mean a local run and a CI run test under different Prometheus majors.
# This digest IS promtool 3.13.1, the build these cases were written and
# mutation-checked against.
PROMTOOL_IMAGE = (
    "prom/prometheus@sha256:"
    "3c42b892cf723fa54d2f262c37a0e1f80aa8c8ddb1da7b9b0df9455a35a7f893"
)

# The only major whose range-selector semantics these cases were validated
# against. A different major is a SKIP, not a silent pass -- see the docstring.
PINNED_MAJOR = 3

DOCKER_OPT_IN = "YUZU_TEST_ENABLE_PROMTOOL_DOCKER"

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES = "docs/prometheus/yuzu-alerts.yml"
TESTS = "tests/prometheus/yuzu-alerts.test.yml"
WORKFLOW = ".github/workflows/docs-lint.yml"


def run(argv: list[str]) -> int:
    print("+ " + " ".join(argv), flush=True)
    return subprocess.run(argv, cwd=REPO_ROOT).returncode


def assert_digest_in_step() -> None:
    """FAIL if the workflow's pinned image has drifted from this file's.

    Defect 4 above: two copies under a comment asking a human to keep them in
    step. Pure file read, so this runs on every leg including ones that will
    then skip -- drift is caught even where the tests themselves cannot run.
    """
    workflow = REPO_ROOT / WORKFLOW
    text = workflow.read_text(encoding="utf-8")
    found = set(re.findall(r"prom/prometheus@sha256:[0-9a-f]{64}", text))
    if not found:
        sys.exit(
            f"FAIL: no pinned prom/prometheus digest found in {WORKFLOW}. "
            f"This harness and that workflow must pin the same image; if the "
            f"job was renamed or removed, update {Path(__file__).name}."
        )
    if found != {PROMTOOL_IMAGE}:
        sys.exit(
            "FAIL: pinned promtool image has drifted.\n"
            f"  {WORKFLOW}: {', '.join(sorted(found))}\n"
            f"  {Path(__file__).name}: {PROMTOOL_IMAGE}\n"
            "Both must pin the same digest, or a local run and a CI run test "
            "under different Prometheus builds."
        )


def native_promtool_major() -> int | None:
    """The major version of the `promtool` on PATH, or None if unusable.

    Defect 2 above: without this, a stub that only `exit 0`s reports success for
    every rule. Anything that does not print a parseable version is treated as
    no promtool at all.
    """
    exe = shutil.which("promtool")
    if not exe:
        return None
    try:
        proc = subprocess.run(
            [exe, "--version"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError) as ex:
        print(f"note: `promtool --version` could not be run ({ex})", flush=True)
        return None
    # promtool prints its banner on stderr in some builds, stdout in others.
    m = re.search(r"version (\d+)\.(\d+)\.(\d+)", proc.stdout + proc.stderr)
    if not m:
        print(
            "note: `promtool --version` printed no parseable version; treating "
            "it as unusable rather than trusting its exit code",
            flush=True,
        )
        return None
    return int(m.group(1))


def docker_usable() -> bool:
    """`docker info`, not `which docker`.

    The binary is frequently present on a box where the daemon is down or the
    user is not in the docker group.
    """
    if not shutil.which("docker"):
        return False
    return subprocess.run(
        ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0


def pull_with_retry() -> bool:
    """Defect 3 above: the workflow retried its pull, this path did not."""
    for attempt in (1, 2, 3):
        if run(["docker", "pull", "--quiet", PROMTOOL_IMAGE]) == 0:
            return True
        if attempt < 3:
            print(f"pull attempt {attempt} failed, retrying", flush=True)
    return False


def main() -> int:
    assert_digest_in_step()

    major = native_promtool_major()
    if major is not None and major != PINNED_MAJOR:
        print(
            f"SKIP: promtool on PATH is major {major}, these cases are validated "
            f"only against major {PINNED_MAJOR} (Prometheus 3.0 made range "
            f"selectors left-open, which moves increase()/resets() at window "
            f"edges -- the exact thing these cases measure). Install a {PINNED_MAJOR}.x "
            f"promtool, or set {DOCKER_OPT_IN}=1 to use the pinned image.",
            flush=True,
        )
        return SKIP

    if major == PINNED_MAJOR:
        rc = run(["promtool", "check", "rules", RULES])
        return rc or run(["promtool", "test", "rules", TESTS])

    # No usable native promtool. Docker is opt-in: an unattended CI leg that
    # never sets this cannot reach a registry, which is defect 1.
    if not os.environ.get(DOCKER_OPT_IN):
        print(
            f"SKIP: no usable promtool on PATH and {DOCKER_OPT_IN} is unset. "
            f"Set {DOCKER_OPT_IN}=1 to run them via the pinned image, or install "
            f"a promtool {PINNED_MAJOR}.x. CI runs these in the `prometheus-rules` "
            f"job either way.",
            flush=True,
        )
        return SKIP

    # Opt-in SET: a broken docker is now a FAILURE, not a skip -- the operator
    # asked for this path (the YUZU_TEST_ENABLE_PG convention).
    if not docker_usable():
        sys.exit(
            f"FAIL: {DOCKER_OPT_IN} is set but docker is not usable (not "
            f"installed, daemon down, or no permission). Unset it to skip these "
            f"tests instead."
        )

    if not pull_with_retry():
        sys.exit(f"FAIL: could not pull {PROMTOOL_IMAGE} after 3 attempts.")

    base = [
        "docker", "run", "--rm", "-v", f"{REPO_ROOT}:/w:ro",
        "--entrypoint", "/bin/promtool", PROMTOOL_IMAGE,
    ]
    rc = run(base + ["check", "rules", f"/w/{RULES}"])
    return rc or run(base + ["test", "rules", f"/w/{TESTS}"])


if __name__ == "__main__":
    sys.exit(main())
