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

THE PUBLISHED STATUS CHECK IS NAMED "Prometheus alert rules", not
`prometheus-rules`. The latter is the JOB ID; branch protection matches on the
name. CLAUDE.md points here for this fact, so it must stay.

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
from typing import NamedTuple

SKIP = 77


class CaseFacts(NamedTuple):
    """What the test file declares. `assertions` is the load-bearing one."""
    cases: int
    assertions: int
    caseless: int

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

# (attempt, sleep-after) - one home, so the failure message cannot drift from it.
PULL_LADDER = ((1, 15), (2, 0))
PULL_ATTEMPTS = len(PULL_LADDER)

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


def check_gate_output(check_out: str, test_out: str,
                      facts: CaseFacts | None) -> str | None:
    """The reason this run proves nothing, or None if it is real evidence.

    PROMTOOL EXITS 0 ON AN EMPTY RUN, and that is the whole reason this function
    exists. Measured on 3.13.1:

      `test rules` against a `rule_files:` glob matching no file prints
      "WARNING: no file match pattern <path>" and then "SUCCESS", rc 0.
      A test file whose `tests:` list is empty also prints "SUCCESS", rc 0.
      A test file whose cases have NO ASSERTION BLOCKS also prints "SUCCESS",
      rc 0 - and that one got through an earlier version of this function,
      which counted cases (#2553, Gate 5).

    So an edit that leaves the cases in place but removes what they assert -
    commented out while debugging, lost in a merge - turns this gate green
    having validated 62 rules and checked none of them. A green check that
    proves nothing is worse than no check, because it is reported as evidence.

    NOTE the decoy case - `rule_files:` naming some OTHER existing rules file -
    needs no check here. It is self-detecting: the suite asserts specific
    alertnames FIRE, those alertnames do not exist in another file, and promtool
    exits non-zero on its own. An earlier revision reimplemented Go's
    `filepath.Glob` to catch it and that seam produced FOUR findings of its own
    (a false-PASS, a decoy widening, a case-sensitivity bug and the boundary
    objection itself). Deleted rather than maintained.
    """
    if "no file match pattern" in test_out:
        return ("`test rules` matched NO rule file - its `rule_files:` path is "
                "stale, so zero rules were loaded and every case vacuously "
                "passed. promtool exits 0 for this; the gate must not.")
    m = re.search(r"SUCCESS:\s*(\d+)\s+rules found", check_out)
    if not m:
        return ("`check rules` did not report a rule count; cannot confirm any "
                "rule was loaded.")
    if int(m.group(1)) == 0:
        return "`check rules` loaded 0 rules - nothing was validated."
    if facts is not None:
        if facts.cases == 0:
            return f"{TESTS} declares no test cases - nothing was asserted."
        if facts.assertions == 0:
            return (f"{TESTS} declares {facts.cases} case(s) and ZERO assertions "
                    f"- promtool exits 0 on that, so the run validated the rules "
                    f"and checked none of them.")
        if facts.caseless:
            return (f"{TESTS} has {facts.caseless} case(s) with no assertion "
                    f"block; each is dead weight that reads as coverage.")
    return None


def inspect_test_file() -> CaseFacts | None:
    """What the test file actually asserts, or None if it cannot be read.

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
        import yaml  # noqa: PLC0415 - see below
    except ImportError:
        # FAIL CLOSED WHEN OPTED IN. Without PyYAML the case-count and
        # rule_files-binding checks are skipped, and those are what stop a
        # vacuous run reporting success - so degrading them silently is worst
        # exactly where the gate is authoritative. The `docs-lint` job runs this
        # script DIRECTLY, with no `meson setup`, so the repo's PyYAML build
        # dependency does NOT vouch for that environment (external review,
        # #2553: the reviewer who checked the runner image rejected the
        # meson-implies-PyYAML argument, and was right).
        #
        # Unset opt-in = a developer running it by hand: skip, do not block.
        if os.environ.get(DOCKER_OPT_IN):
            sys.exit(
                "FAIL: PyYAML is unavailable, so the case-count and rule_files "
                "binding checks cannot run - and those are what stop a vacuous "
                f"run passing. Refusing to report success from the {DOCKER_OPT_IN} "
                "path on a weakened gate. Install PyYAML (`pip install pyyaml`)."
            )
        print("note: PyYAML unavailable; skipping the assertion-count checks",
              flush=True)
        return None
    try:
        with (REPO_ROOT / TESTS).open(encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as ex:
        sys.exit(f"FAIL: {TESTS} is present but could not be parsed ({ex}).")
    if not isinstance(doc, dict):
        sys.exit(f"FAIL: {TESTS} did not parse to a mapping (got {type(doc).__name__}).")
    return count_assertions(doc)


def count_assertions(doc: dict) -> CaseFacts:
    """COUNT ASSERTIONS, NOT CASES.

    A case whose `promql_expr_test:` block is removed still counts as a case,
    and promtool still exits 0. MEASURED (#2553, Gate 5): stripping every
    assertion block while keeping all the cases produced `SUCCESS: 62 rules
    found`, `test rules` SUCCESS and rc 0 - the exact false-green this guard
    exists to stop, reached through the guard itself.

    SPLIT OUT SO `--selftest` CAN EXERCISE IT, and that split is the finding
    that forced it. The first version of this guard was tested only through
    `check_gate_output` with HAND-BUILT `CaseFacts`, so the counting loop - the
    half that actually broke - had no coverage at all: re-injecting the
    count-the-cases bug left `--selftest` printing `ok`. Shape assertions
    against the real file cannot catch it either, because the buggy counter
    produces the same shape. Only a synthetic doc with a KNOWN answer can.

    SCOPE, stated because the name overpromises: this counts the structural
    PRESENCE of assertion blocks. It does not and will not judge their content.
    A case asserting `exp_samples: []` against an alertname that does not exist
    is vacuous and counts here as a real assertion. Validating content means
    reimplementing promtool's semantics, which is the seam that produced a
    false-PASS and was deleted; the defence against vacuous assertions is that
    the suite carries positive FIRE assertions, which redden on a rename.
    """
    tests = doc.get("tests") or []
    assertions = 0
    caseless = 0
    for case in tests:
        if not isinstance(case, dict):
            continue
        n = (len(case.get("promql_expr_test") or [])
             + len(case.get("alert_rule_test") or []))
        assertions += n
        if n == 0:
            caseless += 1
    return CaseFacts(cases=len(tests), assertions=assertions, caseless=caseless)


def gate(promtool_argv: list[str], rules: str, tests: str) -> int:
    """`check rules` then `test rules`, then prove the run was not vacuous."""
    rc, check_out = run(promtool_argv + ["check", "rules", rules], timeout=120)
    if rc:
        return rc
    rc, test_out = run(promtool_argv + ["test", "rules", tests], timeout=120)
    if rc:
        return rc
    reason = check_gate_output(check_out, test_out, inspect_test_file())
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
            stderr=subprocess.DEVNULL, timeout=30,
        ).returncode == 0
    except subprocess.TimeoutExpired:
        print("note: `docker info` timed out after 30s (daemon wedged?)", flush=True)
        return False


def pull_with_retry() -> bool:
    """Retry a transient registry hiccup rather than call it a broken rule."""
    import time

    # THE LADDER MUST FIT INSIDE THE TIMEOUTS THAT ENCLOSE IT. An earlier
    # version was 3 attempts x run()'s 300s default plus 10s+30s of sleeping =
    # 940s, against a `timeout-minutes: 10` job and a meson `timeout: 600` - so
    # a slow-but-failing registry got killed from outside and reported as "the
    # job timed out", which is the exact diagnosis the per-call timeout was
    # added to prevent (#2553, Gate 5). Worst case is now 2x90 + 15 = 195s here,
    # ~30s for the daemon probe and 2x120s for the two promtool runs: ~465s.
    # That is comfortable against meson's 600s, which starts at script launch.
    # It is NOT comfortable against the workflow's `timeout-minutes: 10`, which
    # is a JOB budget covering checkout too - ~495-555s of 600. Size any
    # addition against the job budget, not this number.
    #
    # Two attempts, not three: a transient blip clears in seconds and a second
    # try covers it. This still does not pretend to outlast an anonymous Docker
    # Hub quota window - that is hours - and nothing here should imply it does.
    for attempt, delay in PULL_LADDER:
        t0 = time.monotonic()
        rc, _ = run(["docker", "pull", "--quiet", PROMTOOL_IMAGE], timeout=90)
        # Print the elapsed time so the 90s ceiling is MEASURABLE rather than
        # argued: nobody can currently say how close a real pull runs to it.
        print(f"pull attempt {attempt} took {time.monotonic() - t0:.1f}s (ceiling 90s)",
              flush=True)
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
    """No promtool, no docker, no network. It DOES read the repo tree:
    `inspect_test_file()` opens the shipped test file and can exit on a broken
    one. An earlier version of this line claimed "no filesystem", which is the
    sentence a reviewer would use to conclude this is platform-independent."""
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
    real = CaseFacts(cases=9, assertions=14, caseless=0)
    check("real run accepted", check_gate_output(ok_check, "  SUCCESS\n", real), None)
    stale = check_gate_output(
        ok_check, "  WARNING: no file match pattern /w/docs/gone.yml\n  SUCCESS\n", real)
    if stale is None:
        failures.append("unresolved rule_files glob was accepted as a pass")
    if check_gate_output("SUCCESS: 0 rules found\n", "  SUCCESS\n", real) is None:
        failures.append("a zero-rule check run was accepted as a pass")
    if check_gate_output("some other output\n", "  SUCCESS\n", real) is None:
        failures.append("a check run with no rule count was accepted as a pass")
    if check_gate_output(ok_check, "  SUCCESS\n",
                         CaseFacts(0, 0, 0)) is None:
        failures.append("a test file declaring no cases was accepted as a pass")
    # THE GATE-5 CASE: cases present, every assertion block stripped. promtool
    # exits 0 on this and the previous case-counting version accepted it.
    if check_gate_output(ok_check, "  SUCCESS\n",
                         CaseFacts(cases=13, assertions=0, caseless=13)) is None:
        failures.append("a suite with ZERO assertions was accepted as a pass")
    # One stripped case among many is the realistic edit, and must also fail.
    if check_gate_output(ok_check, "  SUCCESS\n",
                         CaseFacts(cases=13, assertions=20, caseless=1)) is None:
        failures.append("a single assertion-less case was accepted as a pass")
    # Unknowable (no PyYAML) must NOT redden the gate on its own.
    check("unknowable facts still pass",
          check_gate_output(ok_check, "  SUCCESS\n", None), None)

    # THE COUNTING LOOP ITSELF, against synthetic docs with KNOWN answers.
    # Shape assertions against the real file cannot catch a broken counter - the
    # bug that shipped (one per case instead of counting entries) produces the
    # same shape on a file whose cases all have exactly one block. These rows
    # are the ones that redden when it is reintroduced.
    for doc, want, why in [
        ({"tests": []}, CaseFacts(0, 0, 0), "no cases"),
        ({}, CaseFacts(0, 0, 0), "no tests key at all"),
        ({"tests": [{"promql_expr_test": [1, 2, 3]}]}, CaseFacts(1, 3, 0),
         "THREE assertions in ONE case - a per-case counter reports 1 here"),
        ({"tests": [{"promql_expr_test": []}]}, CaseFacts(1, 0, 1),
         "the chaos-B2 shape: a case with its block emptied"),
        ({"tests": [{"name": "x"}]}, CaseFacts(1, 0, 1), "no block at all"),
        ({"tests": [{"alert_rule_test": [1]}, {"promql_expr_test": [1, 1]}]},
         CaseFacts(2, 3, 0), "both assertion kinds, mixed"),
        ({"tests": [{"promql_expr_test": [1]}, "not-a-mapping"]},
         CaseFacts(2, 1, 0), "a non-mapping entry is skipped, not crashed on"),
    ]:
        got = count_assertions(doc)
        if got != want:
            failures.append(f"count_assertions({why}) = {got}, want {want}")

    # And the shipped file must itself carry assertions in every case.
    facts = inspect_test_file()
    if facts is not None:
        if facts.cases == 0:
            failures.append(f"{TESTS} declares no cases")
        if facts.assertions == 0:
            failures.append(f"{TESTS} declares no assertions")
        if facts.caseless:
            failures.append(
                f"{TESTS} has {facts.caseless} case(s) with no assertion block")

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
        sys.exit(f"FAIL: could not pull {PROMTOOL_IMAGE} after {PULL_ATTEMPTS} attempts.")

    return gate(docker_argv(), f"/w/{RULES}", f"/w/{TESTS}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
