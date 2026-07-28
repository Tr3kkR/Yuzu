#!/usr/bin/env python3
"""Hermetic integration test for flake-retry.py.

Drives the *real* flake-retry.py CLI as a subprocess against fake `meson` and
fake Catch2 stubs on PATH, exercising the orchestration the unit `--selftest`
can't reach: `meson test` -> meson suite-level junit -> `meson introspect` ->
re-run the suite binary with Catch2's junit reporter -> isolated case retries.

Scenarios: green pass (including an unavailable telemetry-report path), a
listed flake that recovers on retry, a listed flake that fails all retries
(blocks), an unlisted failure (blocks), and a non-classifiable (non-Catch2)
suite (blocks).

The GitHub-output adapter checks run on every platform. The fake-process
scenarios are POSIX-only (chmod +x shebang scripts) and are skipped on Windows,
where the real CI exercises the binary-execution mechanics.

Run: python3 scripts/ci/test_flake_retry.py   (exit 0 = pass)
"""
import importlib.util
import io
import json
import os
import platform
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.join(HERE, "flake-retry.py")

# Import detect_os from the wrapper so the test lists the flake for THIS OS.
_spec = importlib.util.spec_from_file_location("flake_retry", WRAPPER)
_fr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fr)
THIS_OS = _fr.detect_os()

from github_output import GitHubOutput  # noqa: E402 - HERE must be importable first

FAKE_MESON = r"""#!/usr/bin/env python3
import os, sys, json
a = sys.argv[1:]
marker = os.environ.get("FAKE_MESON_CALLED")
if marker:
    open(marker, "w").write("called")
if a and a[0] == "introspect":
    builddir = a[1]
    if os.environ.get("FAKE_NONCATCH2") == "1":
        cmd = ["/bin/echo"]                 # basename not yuzu_*_tests -> unclassifiable
    else:
        cmd = [os.environ["FAKE_CATCH2_BIN"]]
        if os.environ.get("FAKE_SHARD_SPEC"):   # sharded entry (#2092): tag filter in cmd
            cmd.append(os.environ["FAKE_SHARD_SPEC"])
        cmd += json.loads(os.environ.get("FAKE_CATCH2_OPTIONS", "[]"))
    print(json.dumps([{"name": "fake unit tests", "cmd": cmd, "env": {}, "workdir": None,
                       "suite": ["yuzu:fake"]}]))
    sys.exit(0)
if a and a[0] == "test":
    builddir = a[a.index("-C") + 1]
    logs = os.path.join(builddir, "meson-logs"); os.makedirs(logs, exist_ok=True)
    j = os.path.join(logs, "testlog.junit.xml")
    if os.environ.get("FAKE_MESON_TEST_PASS") == "1":
        open(j, "w").write('<testsuites><testsuite><testcase name="fake - yuzu:fake unit tests" time="1.0"/></testsuite></testsuites>')
        if os.environ.get("FAKE_REPORT_PATH_IS_FILE") == "1":
            os.remove(j)
            os.rmdir(logs)
            open(logs, "w").write("not a directory")
        sys.exit(0)
    open(j, "w").write('<testsuites><testsuite><testcase name="fake - yuzu:fake unit tests" time="1.0">'
                       '<failure>boom</failure></testcase></testsuite></testsuites>')
    sys.exit(1)
sys.exit(0)
"""

FAKE_CATCH2 = r"""#!/usr/bin/env python3
import os, re, sys
a = sys.argv[1:]
fail = [c for c in os.environ.get("FAKE_FAIL_CASES", "").split(";") if c]
always = [c for c in os.environ.get("FAKE_ALWAYS_FAIL", "").split(";") if c]
expected_options = __import__("json").loads(os.environ.get("FAKE_CATCH2_OPTIONS", "[]"))
TAG_SPEC = re.compile(r"^~?(\[[^\[\]]+\])+$")
if any(option not in a for option in expected_options):
    sys.exit(1)
if "--reporter" in a:                       # enumeration run -> emit Catch2 junit
    # A sharded entry's tag filter must SURVIVE into the enumeration run
    # (#2092: only the isolated retry strips it) — a missing spec means the
    # wrapper stripped too much, so emit nothing (-> unclassifiable -> block).
    spec = os.environ.get("FAKE_SHARD_SPEC")
    if spec and spec not in a:
        sys.exit(1)
    out = a[a.index("--out") + 1]
    tcs = "".join('<testcase classname="c" name="%s"><failure>boom</failure></testcase>' % c
                  for c in fail)
    open(out, "w").write('<testsuites><testsuite name="fake">%s</testsuite></testsuites>' % tcs)
    sys.exit(1 if fail else 0)
# Isolated retry of one case by name. A leftover tag spec means the wrapper
# failed to strip the shard filter (real Catch2 would OR it with the case and
# re-run the whole shard) -> hard fail so the recovery scenario can't pass.
if any(TAG_SPEC.match(x) for x in a):
    sys.exit(1)
case = next((candidate for candidate in fail + always if candidate in a), "")
sys.exit(1 if case in always else 0)
"""


def _write_exe(path, body):
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def run_scenario(
    label,
    env_extra,
    known_flaky,
    expect_zero,
    *,
    summary_unavailable=False,
    output_contains=(),
    output_excludes=(),
    expected_evidence_complete=None,
    degradation_contains=(),
):
    with tempfile.TemporaryDirectory() as d:
        binroot = os.path.join(d, "bin"); os.makedirs(binroot)
        meson = os.path.join(binroot, "meson")
        catch2 = os.path.join(binroot, "yuzu_fake_tests")
        _write_exe(meson, FAKE_MESON)
        _write_exe(catch2, FAKE_CATCH2)
        builddir = os.path.join(d, "build"); os.makedirs(builddir)
        kf = os.path.join(d, "known-flaky.json")
        with open(kf, "w") as f:
            json.dump(known_flaky, f)
        env = dict(os.environ)
        # The wrapper's summary() writes bypass capture_output — never let a
        # fake scenario append to a real Actions job summary.
        env.pop("GITHUB_STEP_SUMMARY", None)
        env.pop("GITHUB_ACTIONS", None)
        if summary_unavailable:
            # A directory is a deterministic cross-platform open-for-append
            # failure; unlike chmod, it also fails when the test runs as root.
            env["GITHUB_STEP_SUMMARY"] = d
            env["GITHUB_ACTIONS"] = "true"
        env["PATH"] = binroot + os.pathsep + env["PATH"]
        env["FAKE_CATCH2_BIN"] = catch2
        env.update(env_extra)
        r = subprocess.run(
            [sys.executable, WRAPPER, "--builddir", builddir, "--known-flaky", kf],
            env=env, capture_output=True,
        )
        stdout = r.stdout.decode("utf-8", errors="replace")
        stderr = r.stderr.decode("utf-8", errors="replace")
        combined = stdout + stderr
        receipt_ok = True
        report_path = os.path.join(builddir, "meson-logs", "flake-retry.json")
        if expected_evidence_complete is not None:
            try:
                with open(report_path, encoding="utf-8") as report_file:
                    report = json.load(report_file)
                degradations = report.get("evidence_degradations")
                receipt_ok = (
                    report.get("evidence_complete") is expected_evidence_complete
                    and isinstance(degradations, list)
                    and all(fragment in "\n".join(degradations)
                            for fragment in degradation_contains)
                )
            except (OSError, ValueError, TypeError):
                receipt_ok = False
        ok = (
            (r.returncode == 0) == expect_zero
            and all(fragment in combined for fragment in output_contains)
            and all(fragment not in combined for fragment in output_excludes)
            and receipt_ok
        )
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {label}: exit={r.returncode} (expected {'0' if expect_zero else 'nonzero'})")
        if not ok:
            print("  stdout:", stdout.strip().replace("\n", "\n  "))
            print("  stderr:", stderr.strip().replace("\n", "\n  "))
        return ok


def run_validation_failure(label, known_flaky):
    """An invalid registry must fail before it invokes the Meson executable."""
    with tempfile.TemporaryDirectory() as d:
        binroot = os.path.join(d, "bin"); os.makedirs(binroot)
        meson = os.path.join(binroot, "meson")
        catch2 = os.path.join(binroot, "yuzu_fake_tests")
        _write_exe(meson, FAKE_MESON)
        _write_exe(catch2, FAKE_CATCH2)
        builddir = os.path.join(d, "build"); os.makedirs(builddir)
        kf = os.path.join(d, "known-flaky.json")
        with open(kf, "w") as f:
            json.dump(known_flaky, f)
        marker = os.path.join(d, "meson-called")
        env = dict(os.environ)
        env.pop("GITHUB_STEP_SUMMARY", None)
        env.pop("GITHUB_ACTIONS", None)
        env["PATH"] = binroot + os.pathsep + env["PATH"]
        env["FAKE_CATCH2_BIN"] = catch2
        env["FAKE_MESON_CALLED"] = marker
        r = subprocess.run(
            [sys.executable, WRAPPER, "--builddir", builddir, "--known-flaky", kf],
            env=env, capture_output=True, text=True,
        )
        report_path = os.path.join(builddir, "meson-logs", "flake-retry.json")
        try:
            with open(report_path, encoding="utf-8") as report_file:
                receipt = json.load(report_file)
        except (OSError, ValueError):
            receipt = {}
        ok = (
            r.returncode == 2
            and not os.path.exists(marker)
            and "known-flaky list invalid" in r.stdout
            and receipt.get("evidence_complete") is True
            and "known-flaky list invalid" in "\n".join(receipt.get("blocked", []))
        )
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {label}: exit={r.returncode} (expected 2; meson not invoked)")
        if not ok:
            print("  stdout:", r.stdout.strip().replace("\n", "\n  "))
            print("  stderr:", r.stderr.strip().replace("\n", "\n  "))
        return ok


class _StrictCp1252Stream:
    """Text-only stream: no binary buffer, strict legacy encoding."""

    encoding = "cp1252"

    def __init__(self):
        self.value = ""

    def write(self, value):
        value.encode(self.encoding, errors="strict")
        self.value += value

    def flush(self):
        pass


class _BrokenStream:
    encoding = "utf-8"

    def write(self, _value):
        raise OSError("synthetic closed pipe")

    def flush(self):
        raise OSError("synthetic closed pipe")


class _BrokenStr:
    def __str__(self):
        raise RuntimeError("synthetic __str__ failure")


def test_github_output_adapter():
    """Exercise the Windows encoding path without requiring a Windows host."""

    failures = []

    def check(condition, label):
        if not condition:
            failures.append(label)

    message = "Dependency A \u2192 B is 100%\r\nsecond line"
    expected = "::error::Dependency A \u2192 B is 100%25%0D%0Asecond line\n"

    # This is the #2359 shape: a strict CP1252 stdout wrapper cannot encode
    # U+2192. The adapter must use its binary buffer to emit protocol-required
    # UTF-8, while also escaping %, CR, and LF as workflow-command data.
    raw = io.BytesIO()
    cp1252 = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", write_through=True)
    reporter = GitHubOutput(command_stream=cp1252, diagnostic_stream=io.StringIO())
    check(reporter.annotation("error", message), "CP1252 wrapper accepts UTF-8 annotation")
    check(raw.getvalue().decode("utf-8") == expected, "annotation is UTF-8 and protocol-escaped")
    check(not reporter.degradations, "binary UTF-8 path is lossless")

    # Some injected/redirected text streams expose no binary buffer. In that
    # case a readable command plus an explicit degradation warning is better
    # than an exception that replaces the test verdict.
    text_only = _StrictCp1252Stream()
    reporter = GitHubOutput(command_stream=text_only, diagnostic_stream=io.StringIO())
    check(not reporter.annotation("error", message), "lossy text-only fallback reports false")
    check("\\u2192" in text_only.value, "lossy fallback preserves Unicode as an escape")
    check("100%25%0D%0Asecond line" in text_only.value, "lossy fallback retains protocol escaping")
    check("CI evidence degraded" in text_only.value, "lossy fallback is visibly degraded")
    check(bool(reporter.degradations), "lossy fallback is machine-inspectable")

    diagnostic = io.StringIO()
    reporter = GitHubOutput(command_stream=_BrokenStream(), diagnostic_stream=diagnostic)
    check(not reporter.annotation("error", message), "broken annotation stream never raises")
    check("CI evidence degraded" in diagnostic.getvalue(), "broken stream falls back to stderr")

    with tempfile.TemporaryDirectory() as directory_summary:
        annotations = io.StringIO()
        reporter = GitHubOutput(command_stream=annotations, summary_path=directory_summary)
        check(not reporter.job_summary("summary"), "unwritable summary reports false")
        check("::warning::CI evidence degraded" in annotations.getvalue(),
              "unwritable summary emits an annotation")

    local_annotations = io.StringIO()
    reporter = GitHubOutput(
        command_stream=local_annotations,
        summary_path=None,
        github_actions=False,
    )
    check(reporter.job_summary("local"), "local missing summary is not a degradation")
    check(reporter.evidence_complete, "local missing summary keeps evidence complete")

    for missing_path in (None, ""):
        actions_annotations = io.StringIO()
        reporter = GitHubOutput(
            command_stream=actions_annotations,
            summary_path=missing_path,
            github_actions=True,
        )
        check(not reporter.job_summary("actions"),
              "Actions absent/empty summary is a degradation")
        check(not reporter.evidence_complete
              and "GITHUB_STEP_SUMMARY is absent or empty" in reporter.degradations[0],
              "Actions summary degradation is retained")

    rendering_annotations = io.StringIO()
    reporter = GitHubOutput(command_stream=rendering_annotations)
    check(not reporter.annotation(_BrokenStr(), "message"),
          "annotation kind __str__ failure never raises")
    check(not reporter.annotation("error", _BrokenStr()),
          "annotation message __str__ failure never raises")
    check(reporter.degradation_count == 2,
          "both annotation rendering failures are retained")

    bounded_annotations = io.StringIO()
    reporter = GitHubOutput(
        command_stream=bounded_annotations,
        summary_path=None,
        github_actions=True,
    )
    for _ in range(24):
        reporter.job_summary("missing")
    check(reporter.degradation_count == 24, "total degradation count is retained")
    check(len(reporter.degradations) == 16, "degradation detail list is bounded")
    check(all(len(reason) <= 512 for reason in reporter.degradations),
          "degradation reasons are length-bounded")
    with tempfile.TemporaryDirectory() as report_root:
        check(_fr.write_retry_report(report_root, THIS_OS, [], [], reporter),
              "bounded durable evidence receipt writes")
        with open(os.path.join(report_root, "meson-logs", "flake-retry.json"),
                  encoding="utf-8") as report_file:
            receipt = json.load(report_file)
        check(receipt["evidence_complete"] is False,
              "durable receipt marks degraded evidence")
        check(receipt["evidence_degradation_count"] == 24,
              "durable receipt retains total degradation count")
        check(len(receipt["evidence_degradations"]) == 16,
              "durable receipt keeps bounded degradation details")

    if failures:
        print("GitHub output adapter failures:", *failures, sep="\n  ")
        return False
    print("[PASS] GitHub output adapter: CP1252, escaping, and I/O degradation")
    return True


def main():
    adapter_ok = test_github_output_adapter()
    if platform.system() == "Windows":
        print("test_flake_retry: POSIX fake-process scenarios skipped on Windows")
        return 0 if adapter_ok else 1

    listed = [{
        "case": "FlakeA",
        "platforms": [THIS_OS],
        "reason": "test flake",
        "issue": "#test",
        "owner": "ci",
        "added": "2026-06-23",
        "expires": "2099-12-31",
    }]
    unicode_case = "Dependency A \u2192 B is 100%"
    unicode_listed = [{
        "case": unicode_case,
        "platforms": [THIS_OS],
        "reason": "encoding regression",
        "issue": "#2359",
        "owner": "ci",
        "added": "2026-07-27",
        "expires": "2099-12-31",
    }]
    results = [
        adapter_ok,
        run_scenario("green pass", {"FAKE_MESON_TEST_PASS": "1"}, listed, True,
                     expected_evidence_complete=True),
        run_scenario(
            "Actions missing summary is retained in durable receipt",
            {"FAKE_MESON_TEST_PASS": "1", "GITHUB_ACTIONS": "true"},
            listed,
            True,
            output_contains=(
                "::warning::CI evidence degraded: GITHUB_STEP_SUMMARY is absent or empty",
            ),
            expected_evidence_complete=False,
            degradation_contains=("GITHUB_STEP_SUMMARY is absent or empty",),
        ),
        run_scenario("green pass survives unavailable retry-report path",
                     {"FAKE_MESON_TEST_PASS": "1", "FAKE_REPORT_PATH_IS_FILE": "1"},
                     listed, True),
        run_scenario("listed flake recovers on retry", {"FAKE_FAIL_CASES": "FlakeA"}, listed, True),
        run_scenario("listed flake fails all retries -> block",
                     {"FAKE_FAIL_CASES": "FlakeA", "FAKE_ALWAYS_FAIL": "FlakeA"}, listed, False),
        run_scenario("unlisted failure -> block", {"FAKE_FAIL_CASES": "RealBug"}, listed, False),
        run_scenario("non-Catch2 suite -> block",
                     {"FAKE_FAIL_CASES": "FlakeA", "FAKE_NONCATCH2": "1"}, listed, False),
        run_scenario("sharded suite (#2092): retry replaces tag filter",
                     {"FAKE_FAIL_CASES": "FlakeA", "FAKE_SHARD_SPEC": "~[pg]"}, listed, True),
        run_scenario(
            "aggregate TAR retry keeps deterministic Catch2 options",
            {
                "FAKE_FAIL_CASES": "FlakeA",
                "FAKE_CATCH2_OPTIONS": json.dumps(
                    ["--order", "lex", "--rng-seed", "1"]
                ),
            },
            listed,
            True,
        ),
        # Suite red under meson, but the solo enumeration re-run reproduces
        # ZERO failing cases (order/contention-dependent failure, or a stale
        # junit from a crashed run). Nothing is attributable to a listed
        # flake, so the wrapper must block — returning 0 here is the
        # masked-green hole governance UP-1 closed.
        run_scenario("suite fails, enumeration reproduces nothing -> block",
                     {"FAKE_FAIL_CASES": ""}, listed, False),
        run_validation_failure("expired registry entry blocks before Meson",
                               [{**listed[0], "added": "1999-01-01", "expires": "2000-01-01"}]),
        run_scenario(
            "#2359 Unicode case under strict CP1252 keeps recovered verdict",
            {"FAKE_FAIL_CASES": unicode_case, "PYTHONIOENCODING": "cp1252:strict"},
            unicode_listed,
            True,
            summary_unavailable=True,
            output_contains=(
                "::notice::known flake recovered on retry: Dependency A \u2192 B is 100%25",
                "::warning::CI evidence degraded: job summary could not be written",
            ),
            output_excludes=("UnicodeEncodeError", "Traceback"),
            expected_evidence_complete=False,
            degradation_contains=("job summary could not be written",),
        ),
    ]
    if all(results):
        print(f"\nflake-retry integration test: OK ({len(results)} scenarios)")
        return 0
    print(f"\nflake-retry integration test: {results.count(False)} FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
