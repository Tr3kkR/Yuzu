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

`--selftest` exercises the pure logic - version parsing, docker argv
construction, the vacuity verdict, and the assertion COUNTER itself against
synthetic docs with known answers - with no promtool, no docker and no network, matching `scripts/ci/flake-retry.py
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


def run(argv: list[str], timeout: int = 300, quiet: bool = False) -> tuple[int, str]:
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
    if out and not quiet:
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
    needs no check HERE, but not because it is inherently self-detecting. It is
    caught TODAY because the suite happens to assert that specific alertnames
    FIRE, and those do not exist in another file, so promtool exits non-zero on
    its own. NOTHING ENFORCES THAT PROPERTY - 10 of the 23 current assertions are
    negative (`exp_samples: []`) and pass against any rules at all, including
    none. Measured: a decoy glob plus negative-only assertions passes this whole
    function. What actually closes it is the canary in `gate()`, not this
    paragraph. An earlier revision reimplemented Go's
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


def inspect_test_file(*, strict: bool = True) -> CaseFacts | None:
    """What the test file actually asserts. `strict` decides the no-parser case.

    STRICT IS KEYWORD-ONLY ON PURPOSE. The two mistakes are not symmetric: a new
    GATE caller that forgot the flag would ship a silent false green - the defect
    this branch has now had four times - while a new TEST caller that forgot it
    would break a leg loudly on its own PR. Silent-and-indefinite is the worse
    failure, so the default is strict and the parameter cannot be passed by
    position at all.

    A MISSING PARSER AND AN UNPARSEABLE FILE ARE DIFFERENT. Without PyYAML the
    assertion counts genuinely cannot be answered. Under `strict` that FAILS -
    `gate()` is about to call a promtool exit 0 evidence and must not do so on a
    disabled guard. An earlier revision said instead that a missing parser "must
    not redden the gate", and that sentence is exactly what both external
    reviewers blocked on; it is quoted here only so nobody restores it. Under
    `strict=False` - `--selftest`, which must need no toolchain - it returns None
    with a note. Either way, a file that is PRESENT and does not parse is a
    failure: the suite promtool just ran is not the suite this repo thinks it has.

    The `rule_files` read exists because `check rules` validates a hardcoded path
    while `test rules` loads whatever the test file names. Repointing that at
    another EXISTING rules file produces no promtool warning at all, so nothing
    else notices the cases stopped covering the rules that were validated.
    """
    try:
        import yaml  # noqa: PLC0415 - see below
    except ImportError:
        # FAIL CLOSED ON THE GATE PATH. Without PyYAML the assertion-count checks
        # cannot run, and those are the whole reason a green promtool exit counts
        # as evidence - promtool itself exits 0 on a suite that asserts nothing.
        #
        # An earlier revision fail-closed only when the docker opt-in was set, on
        # the reasoning that an unset opt-in meant a developer running it by hand
        # who should not be blocked. That was wrong, and BOTH external reviewers
        # blocked on it independently (#2553): a native promtool of the pinned
        # major reaches this function with the opt-in UNSET, so the guard
        # switched itself off on exactly the path the docstring promises will
        # "run it, and FAIL on a bad rule". Reproduced three times - a fake
        # major-3 promtool, PyYAML blocked, a case with no assertion blocks, and
        # the harness exited 0.
        #
        # STRICT IS THE GATE PATH ONLY. `gate()` is about to call a promtool exit
        # 0 evidence, so a disabled guard there must fail. `--selftest` asserts
        # pure logic and is registered as its own meson entry that runs on all
        # three REQUIRED legs with no toolchain at all - making THAT depend on
        # PyYAML would break a leg, which is the policy floor. The first cut of
        # this fix did exactly that: measured, `--selftest` exited 1 with the
        # import blocked. All three legs happen to install PyYAML via
        # requirements-ci.txt today, so it was not live - but the selftest is
        # supposed to need nothing, and a fix that survives only by luck is not
        # a fix.
        if not strict:
            print("note: PyYAML unavailable; skipping the shipped-file checks",
                  flush=True)
            return None
        sys.exit(
            "FAIL: PyYAML is unavailable, so the assertion-count checks cannot "
            "run - and those are what stop a suite that asserts nothing from "
            "reporting success. Refusing to call a promtool exit 0 evidence on a "
            "weakened gate. Install PyYAML (`pip install pyyaml`), or unset any "
            "promtool from PATH to skip these tests instead."
        )
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


# The canary mutation. `unless` is what makes the young-server grace an
# EXCLUSION; `and` inverts it, so every case asserting the alert FIRES must go
# red. Measured against this suite (#2553 pass 13, quality-engineer's M3).
CANARY_FROM = "unless ("
CANARY_TO = "and ("


def build_canary_tree(dest: Path) -> None:
    """Mirror RULES + TESTS under `dest`, with RULES deliberately broken.

    The layout MIRRORS the repo because promtool resolves a test file's
    `rule_files:` relative to THE TEST FILE, not to cwd. Copying the test file
    byte-unchanged is the whole point: its own glob is the thing under test.
    """
    for rel in (RULES, TESTS):
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(REPO_ROOT / TESTS, dest / TESTS)
    text = (REPO_ROOT / RULES).read_text(encoding="utf-8")
    if CANARY_FROM not in text:
        sys.exit(
            f"FAIL: canary anchor {CANARY_FROM!r} is no longer in {RULES}, so the "
            f"canary would pass without proving anything - silently inert, which "
            f"is the exact failure it exists to catch. Choose a new anchor whose "
            f"removal MUST redden this suite, and update CANARY_FROM/CANARY_TO."
        )
    (dest / RULES).write_text(text.replace(CANARY_FROM, CANARY_TO, 1),
                              encoding="utf-8")
    # The container runs as uid 65534 with the tree mounted read-only. Under a
    # restrictive umask (077 is a common hardened-shell and CI default) these
    # files are created 0600/0700 and promtool cannot stat them - it exits
    # non-zero on a PERMISSION error, which the caller must not mistake for the
    # suite reddening. MEASURED: without these chmods, `umask 077` makes the
    # canary print "suite reddens against broken rules" while promtool never
    # opened the file.
    for path in [dest, *dest.rglob("*")]:
        path.chmod(0o755 if path.is_dir() else 0o644)


def gate(promtool_argv: list[str], rules: str, tests: str, canary_for=None) -> int:
    """`check rules`, `test rules`, prove the run was not vacuous, then prove
    the behaviour suite is testing THE SHIPPED RULES.

    THAT LAST STEP EXISTS BECAUSE THE FIRST TWO VALIDATE DIFFERENT FILES.
    `check rules` is handed `RULES` by this script. `test rules` is handed the
    TEST file, and promtool then loads whatever THAT file's own `rule_files:`
    glob names. Nothing tied the two together. MEASURED on 3.13.1 (#2553 pass
    13): point the glob at a real-but-wrong rules file and make the assertions
    negative-only, and the whole gate exits 0 while printing "SUCCESS: 62 rules
    found" - a count that came from a file the behaviour run never opened.

    The vacuity guard above cannot see it: there ARE cases, there ARE
    assertions, and not one of them is empty. So instead we break a COPY of the
    shipped rules and require the suite to notice. A suite that stays green
    against deliberately broken rules is not testing them.

    Note what this deliberately does NOT do: parse the glob or canonicalise
    paths. An earlier revision reimplemented Go's `filepath.Glob` in Python to
    answer this same question and produced FOUR findings doing it - Python's
    `**` recurses and Go's does not. Ask promtool instead of modelling it.
    """
    rc, check_out = run(promtool_argv + ["check", "rules", rules], timeout=120)
    if rc:
        return rc
    rc, test_out = run(promtool_argv + ["test", "rules", tests], timeout=120)
    if rc:
        return rc
    reason = check_gate_output(check_out, test_out, inspect_test_file(strict=True))
    if reason:
        sys.exit(f"FAIL: promtool exited 0 but the run proves nothing - {reason}")
    if canary_for is None:
        return 0
    tmp = REPO_ROOT / ".promtool-canary"
    shutil.rmtree(tmp, ignore_errors=True)
    try:
        build_canary_tree(tmp)
        canary_argv, canary_tests, canary_rules = canary_for(tmp)
        # Quiet on purpose: a PASSING canary means promtool printed a wall of
        # `FAILED:` detail, which above the reassuring line reads as a broken
        # build. The output is still captured and is printed on every failure
        # arm below.
        canary_rc, canary_out = run(canary_argv + ["test", "rules", canary_tests],
                                    timeout=120, quiet=True)
        canary_check_rc, canary_check_out = run(
            canary_argv + ["check", "rules", canary_rules], timeout=120, quiet=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # PROVE THE MUTATED COPY WAS ACTUALLY READ, before trusting any redden.
    #
    # An exit code alone is not evidence: promtool exits non-zero for "I could
    # not read that file" too, and reading THAT as success is a false green -
    # measured under `umask 077`, where the mounted tree is unreadable to uid
    # 65534 and an earlier revision printed "suite reddens against broken rules".
    #
    # BUT NEITHER IS THE `FAILED` TOKEN, which is where the first fix for that
    # stopped. promtool prints the same `FAILED:` banner with every assertion
    # `got: nil` when it cannot OPEN the rules file, and again when the glob
    # matched nothing - measured with `chmod 000` on the copied rules file and
    # on its directory. Both are indistinguishable from a genuine redden by
    # substring. So the only sound premise is a positive rule count read back
    # off the mutated copy itself: if promtool can parse it and load rules from
    # it, a `FAILED` from the suite is about the mutation rather than about I/O.
    #
    # The sweep instrument (blind_band_sweep.py) had the root form of this bug
    # and its `silent()` states the rule this keeps re-learning: an instrument
    # that cannot run must say so, never return a value.
    loaded = re.search(r"SUCCESS:\s*(\d+)\s+rules found", canary_check_out)
    if canary_check_rc != 0 or not loaded or int(loaded.group(1)) == 0:
        sys.exit(
            f"FAIL: the canary's mutated copy of {RULES} could not be read back "
            f"(rc {canary_check_rc}, "
            f"{'no rule count reported' if not loaded else loaded.group(1) + ' rules'}), "
            f"so a `FAILED` from the suite would prove only that promtool could "
            f"not open a file. This is not a pass.\n"
            f"{canary_check_out.strip()[:500]}"
        )
    if canary_rc != 0 and "FAILED" not in canary_out:
        sys.exit(
            f"FAIL: the canary could not be MEASURED - promtool exited "
            f"{canary_rc} against the mutated copy without reporting a test "
            f"failure, so we do not know whether the suite would have caught it. "
            f"This is not a pass.\n{canary_out.strip()[:500]}"
        )
    if canary_rc == 0:
        sys.exit(
            f"FAIL: the suite stayed GREEN against a deliberately broken copy of "
            f"{RULES} ({CANARY_FROM!r} -> {CANARY_TO!r}), so it is not testing "
            f"the shipped rules. TWO causes produce this, both measured:\n"
            f"  1. `rule_files:` in {TESTS} names a different file. That is what "
            f"the behaviour run loads; `check rules` above validated {RULES}, so "
            f"the two halves can disagree silently.\n"
            f"  2. Every assertion is negative (`exp_samples: []`). Those pass "
            f"whatever the rules say - including against no rules at all - so the "
            f"suite has cases and assertions but proves nothing. At least one "
            f"assertion must expect a sample to EXIST."
        )
    print("canary: suite reddens against broken rules - it is testing them",
          flush=True)
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


def docker_argv(root: Path = REPO_ROOT) -> list[str]:
    """`root` is the tree mounted at /w. It is a parameter ONLY so the canary
    can mount its own mirror tree; every other caller wants the repo."""
    return [
        "docker", "run", "--rm",
        "-v", f"{root}:/w:ro",
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
        # BOTH block kinds in ONE case. The row above puts them in SEPARATE
        # cases, which an `elif` between the two lookups still counts correctly -
        # so without this row a mutually-exclusive counter passes silently. The
        # shipped file happens to have no combined case either, so nothing else
        # would catch it. Found by breaking the loop, not by reading it (#2553).
        ({"tests": [{"promql_expr_test": [1, 1], "alert_rule_test": [1]}]},
         CaseFacts(1, 3, 0), "both kinds in ONE case must SUM, not pick one"),
        # An explicit YAML null block, as distinct from an absent one. `or []`
        # already handles it; this row is what stops a future edit from deciding
        # a null block counts for one.
        ({"tests": [{"promql_expr_test": None}]},
         CaseFacts(1, 0, 1), "an explicit null block is not an assertion"),
    ]:
        got = count_assertions(doc)
        if got != want:
            failures.append(f"count_assertions({why}) = {got}, want {want}")

    # And the shipped file must itself carry assertions in every case.
    facts = inspect_test_file(strict=False)
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
            # Native resolves the canary tree by absolute path; `run()`'s cwd is
            # REPO_ROOT, which is the wrong root for the mirror.
            return gate([exe], RULES, TESTS,
                        canary_for=lambda root: ([exe], str(root / TESTS),
                                                       str(root / RULES)))

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

    return gate(docker_argv(), f"/w/{RULES}", f"/w/{TESTS}",
                canary_for=lambda root: (docker_argv(root), f"/w/{TESTS}",
                                                 f"/w/{RULES}"))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
