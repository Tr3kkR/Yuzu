#!/usr/bin/env python3
r"""Run the Prometheus alert-rule unit tests under promtool.

THIS SCRIPT IS THE ONLY HOME for the promtool invocation and for the pinned
image. `.github/workflows/docs-lint.yml`'s `prometheus-rules` job calls it with
`YUZU_TEST_ENABLE_PROMTOOL_DOCKER=1` and `meson test --suite docs` calls it
without, so CI and a local run are provably the same code. That follows the
pattern this repo already uses for a CI-pulled image - `PROBE_IMAGE` in
`scripts/ci/verify-healthcheck-invariants.sh`, `PG_IMAGE` in
`scripts/ci/ensure-postgres.sh`: the pin lives in the script and the workflows
carry zero copies of it.

An alert rule is code that runs in production and never compiles, and
`promtool check rules` proves only that the PromQL parses. A rule that parses
perfectly and can never fire for the case it was written for passes it - which
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
`increase()` and `resets()` by a sample at window edges - exactly what these
cases measure - so the MAJOR is load-bearing. A `promtool` that prints no
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
# against. Note `prom/prometheus:3.13.1` is not a tag Docker Hub publishes - the
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
    # Belt-and-braces: the image already runs as uid 65534 with no effective
    # capabilities, so there is nothing here to escalate to. Cheap to state.
    "--security-opt", "no-new-privileges",
]


def gh_error(msg: str) -> None:
    """Surface a failure as a GitHub Actions annotation when running in one."""
    if os.environ.get("GITHUB_ACTIONS"):
        print(f"::error::{msg}", flush=True)


def run(argv: list[str], timeout: int = 300) -> tuple[int, str]:
    """Run promtool, echo its output, and return `(rc, combined output)`.

    The output is returned because promtool's exit code is not sufficient
    evidence on its own - see `check_gate_output`.
    """
    print("+ " + " ".join(argv), flush=True)
    # errors="replace": a decode error in promtool's output must not become an
    # uncaught traceback in place of a clean pass/fail.
    # timeout: output is captured, not streamed, so a wedged registry or
    # container would otherwise print NOTHING until the job's own 10-minute
    # timeout killed it -- reporting as "the gate timed out" rather than naming
    # what hung.
    try:
        proc = subprocess.run(argv, cwd=REPO_ROOT, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        msg = f"timed out after {timeout}s: {' '.join(argv)}"
        print(f"FAIL: {msg}", flush=True)
        gh_error(msg)
        return 1, ""
    out = proc.stdout + proc.stderr
    if out:
        print(out, end="" if out.endswith("\n") else "\n", flush=True)
    return proc.returncode, out


def check_gate_output(check_out: str, test_out: str, declared_cases: int | None,
                      rules_bound: bool | None = True) -> str | None:
    """The reason this run proves nothing, or None if it is real evidence.

    PROMTOOL EXITS 0 ON AN EMPTY RUN, and that is the whole reason this function
    exists. Measured on 3.13.1:

      `test rules` against a `rule_files:` glob matching no file prints
      "WARNING: no file match pattern <path>" and then "SUCCESS", rc 0.
      A test file whose `tests:` list is empty also prints "SUCCESS", rc 0.

    So a rules file renamed without updating the test file's relative
    `rule_files:` - exactly the edit that would also carry a rule change -
    turns this gate green having loaded zero rules and asserted nothing. A
    green check that proves nothing is worse than no check, because it is
    reported as evidence.
    """
    if "no file match pattern" in test_out:
        return ("`test rules` matched NO rule file - its `rule_files:` path is "
                "stale, so zero rules were loaded and every case vacuously "
                "passed. promtool exits 0 for this; the gate must not.")
    if rules_bound is False:
        return (f"`test rules` did not load {RULES} - nothing in the test file's "
                f"`rule_files:` resolves to it (it is missing, or it names some "
                f"OTHER file), so the cases asserted nothing about the rules "
                f"`check rules` just validated. promtool reports no warning for "
                f"this, because from its side nothing is wrong.")
    m = re.search(r"SUCCESS:\s*(\d+)\s+rules found", check_out)
    if not m:
        return ("`check rules` did not report a rule count; cannot confirm any "
                "rule was loaded.")
    if int(m.group(1)) == 0:
        return "`check rules` loaded 0 rules - nothing was validated."
    if declared_cases is not None and declared_cases == 0:
        return f"{TESTS} declares no test cases - nothing was asserted."
    return None


def inspect_test_file() -> tuple[int | None, bool | None]:
    """`(declared case count, whether it loads RULES)`; None where unknowable.

    A MISSING PARSER AND AN UNPARSEABLE FILE ARE DIFFERENT. Without PyYAML we
    genuinely cannot answer, and must not redden the gate for it (the
    `no file match pattern` check does not need a parser). But if the file is
    present and does not parse, the suite promtool just ran is not the suite this
    repo thinks it has, and that IS a failure.

    The `rule_files` read exists because `check rules` validates a hardcoded path
    while `test rules` loads whatever the test file names. Repointing that at
    another EXISTING rules file produces no promtool warning at all, so nothing
    else notices the cases stopped covering the rules that were validated.
    """
    try:
        import yaml  # noqa: PLC0415 - optional, see docstring
    except ImportError:
        print("note: PyYAML unavailable; skipping case-count and rule_files checks",
              flush=True)
        return None, None
    try:
        with (REPO_ROOT / TESTS).open(encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as ex:
        sys.exit(f"FAIL: {TESTS} is present but could not be parsed ({ex}).")
    if not isinstance(doc, dict):
        sys.exit(f"FAIL: {TESTS} did not parse to a mapping (got {type(doc).__name__}).")
    cases = len(doc.get("tests") or [])
    base = (REPO_ROOT / TESTS).parent
    want = (REPO_ROOT / RULES).resolve()
    bound = any(resolves_to_rules(base, want, str(p))
                for p in doc.get("rule_files") or [])
    return cases, bound


def resolves_to_rules(base: Path, want: Path, pattern: str) -> bool:
    """Does this `rule_files:` entry load `want`, by PROMTOOL's rules?

    Split out and parameterised so `--selftest` can exercise it. It previously
    could not: the shipped test file's single entry is a literal, the literal
    branch returns True, `any()` short-circuits, and the glob branch was never
    executed on any leg.

    `**` IS NOT RECURSIVE HERE, and that is the whole subtlety. promtool uses Go's
    `filepath.Glob`, where `**` is just two adjacent `*` inside ONE path segment;
    Python's `Path.glob` recurses. Left alone, that gap runs the wrong way: a
    `**` pattern promtool does NOT match would look bound to us, and the gate
    would pass having asserted nothing about the rules it validated - the exact
    false-green this check exists to stop. Collapsing `**` to `*` restores Go's
    semantics. MEASURED against promtool 3.13.1, from `tests/prometheus`:
    `../../docs/**/*.yml` matches, `../../**/*.yml` does not, and this agrees
    with the collapsed form in both directions.
    """
    # Literal first: it handles `..` segments and plain paths, and `Path.glob`
    # rejects some of what a literal join accepts.
    try:
        if base.joinpath(pattern).resolve() == want:
            return True
    except (OSError, ValueError):
        pass
    while "**" in pattern:
        pattern = pattern.replace("**", "*")
    try:
        return any(q.resolve() == want for q in base.glob(pattern))
    except (OSError, ValueError, IndexError, NotImplementedError, RecursionError):
        return False


def gate(promtool_argv: list[str], rules: str, tests: str) -> int:
    """`check rules` then `test rules`, then prove the run was not vacuous."""
    rc, check_out = run(promtool_argv + ["check", "rules", rules])
    if rc:
        return rc
    rc, test_out = run(promtool_argv + ["test", "rules", tests])
    if rc:
        return rc
    cases, bound = inspect_test_file()
    reason = check_gate_output(check_out, test_out, cases, bound)
    if reason:
        sys.exit(f"FAIL: promtool exited 0 but the run proves nothing - {reason}")
    return 0


def parse_major(version_output: str) -> int | None:
    """Major version from a `promtool --version` banner, or None if unparseable.

    Split out from the subprocess call so `--selftest` can exercise it.
    """
    m = re.search(r"version (\d+)\.(\d+)\.(\d+)", version_output)
    return int(m.group(1)) if m else None


def native_promtool() -> tuple[str, int] | None:
    """`(path, major)` for a usable promtool on PATH, else None.

    Returns the RESOLVED path, and the caller executes that same path - not the
    bare name - so a PATH change between the check and the run cannot swap the
    binary, and Windows' application-directory search order does not apply.
    """
    exe = shutil.which("promtool")
    if not exe:
        return None
    try:
        proc = subprocess.run(
            [exe, "--version"], capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
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
    # Bounded: a wedged dockerd is a routine self-hosted failure, and without a
    # timeout `docker info` blocks until meson's own 600s timeout kills the run,
    # which reports as "the gate timed out" rather than "docker is wedged".
    try:
        return subprocess.run(
            ["docker", "info"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=60,
        ).returncode == 0
    except subprocess.TimeoutExpired:
        print("note: `docker info` timed out after 60s (daemon wedged?)", flush=True)
        return False


def pull_with_retry() -> bool:
    """Retry a transient registry hiccup rather than call it a broken rule."""
    import time

    # Backoff widens rather than repeating a fixed 10s: a transient blip clears
    # in seconds, but the realistic failure here is an anonymous Docker Hub rate
    # limit, and 3x10s never outlasts one of those. This does not pretend to
    # either - a quota window is hours - it just stops three near-simultaneous
    # attempts being reported as a considered retry.
    for attempt, delay in ((1, 10), (2, 30), (3, 0)):
        rc, _ = run(["docker", "pull", "--quiet", PROMTOOL_IMAGE])
        if rc == 0:
            return True
        if delay:
            print(f"pull attempt {attempt} failed, retrying in {delay}s", flush=True)
            time.sleep(delay)
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

    # The vacuity check is the reason a green run is evidence at all. promtool
    # exits 0 on a suite that loaded no rules, so these are the cases that stop
    # this gate grading itself.
    ok_check = "Checking rules\n  SUCCESS: 61 rules found\n"
    check("real run accepted", check_gate_output(ok_check, "  SUCCESS\n", 9, True), None)
    stale = check_gate_output(
        ok_check, "  WARNING: no file match pattern /w/docs/gone.yml\n  SUCCESS\n",
        9, True)
    if stale is None:
        failures.append("unresolved rule_files glob was accepted as a pass")
    if check_gate_output("SUCCESS: 0 rules found\n", "  SUCCESS\n", 9, True) is None:
        failures.append("a zero-rule check run was accepted as a pass")
    if check_gate_output(ok_check, "  SUCCESS\n", 0, True) is None:
        failures.append("a test file declaring no cases was accepted as a pass")
    if check_gate_output("some other output\n", "  SUCCESS\n", 9, True) is None:
        failures.append("a check run with no rule count was accepted as a pass")
    # The decoy case: rule_files names a DIFFERENT existing file, so promtool
    # emits no warning at all and only this check can see it.
    if check_gate_output(ok_check, "  SUCCESS\n", 9, False) is None:
        failures.append("a test file loading the WRONG rules file was accepted")
    # Unknowable (no PyYAML) must NOT redden the gate on its own.
    check("unknowable binding still passes",
          check_gate_output(ok_check, "  SUCCESS\n", None, None), None)

    # The real test file must actually bind to the real rules file.
    cases, bound = inspect_test_file()
    if bound is False:
        failures.append(f"{TESTS} does not load {RULES}")
    if cases == 0:
        failures.append(f"{TESTS} declares no cases")

    # resolves_to_rules against promtool's OWN behaviour. The `**` rows are the
    # ones that matter: Python recurses and Go does not, and getting that wrong
    # turns a vacuous run into a pass. Expectations MEASURED against promtool
    # 3.13.1, not reasoned - see the function docstring.
    b = (REPO_ROOT / TESTS).parent
    w = (REPO_ROOT / RULES).resolve()
    for pattern, want_bound, why in [
        ("../../docs/prometheus/yuzu-alerts.yml", True, "the literal, as shipped"),
        ("../../docs/prometheus/*.yml", True, "single-segment glob promtool matches"),
        ("../../docs/*/*.yml", True, "two single-segment globs promtool matches"),
        ("../../docs/**/*.yml", True, "** is ONE segment in Go; promtool matches"),
        ("../../**/*.yml", False, "** is ONE segment in Go; promtool does NOT match"),
        ("../../docs/prometheus/decoy.yml", False, "names another file"),
        ("../../../outside-the-repo.yml", False, "escapes the repo"),
        ("", False, "empty pattern"),
        ("[", False, "malformed pattern must not raise"),
    ]:
        got = resolves_to_rules(b, w, pattern)
        if got != want_bound:
            failures.append(
                f"resolves_to_rules({pattern!r}) = {got}, want {want_bound} ({why})")

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
                    f"window edges - the exact thing these cases measure). Install "
                    f"a {PINNED_MAJOR}.x promtool, or set {DOCKER_OPT_IN}=1 to use "
                    f"the pinned image.",
                    flush=True,
                )
                return SKIP
            print(f"using native promtool: {exe} (major {major})", flush=True)
            return gate([exe], RULES, TESTS)

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

    return gate(docker_argv(), f"/w/{RULES}", f"/w/{TESTS}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
