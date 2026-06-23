#!/usr/bin/env python3
"""Hermetic integration test for flake-retry.py.

Drives the *real* flake-retry.py CLI as a subprocess against fake `meson` and
fake Catch2 stubs on PATH, exercising the orchestration the unit `--selftest`
can't reach: `meson test` -> meson suite-level junit -> `meson introspect` ->
re-run the suite binary with Catch2's junit reporter -> isolated case retries.

Scenarios: green pass, a listed flake that recovers on retry, a listed flake
that fails all retries (blocks), an unlisted failure (blocks), and a
non-classifiable (non-Catch2) suite (blocks).

POSIX-only (the fakes are chmod +x shebang scripts); skipped on Windows, where
the real CI exercises the binary-execution mechanics anyway.

Run: python3 scripts/ci/test_flake_retry.py   (exit 0 = pass)
"""
import importlib.util
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

FAKE_MESON = r"""#!/usr/bin/env python3
import os, sys, json
a = sys.argv[1:]
if a and a[0] == "introspect":
    builddir = a[1]
    if os.environ.get("FAKE_NONCATCH2") == "1":
        cmd = ["/bin/echo"]                 # basename not yuzu_*_tests -> unclassifiable
    else:
        cmd = [os.environ["FAKE_CATCH2_BIN"]]
    print(json.dumps([{"name": "fake unit tests", "cmd": cmd, "env": {}, "workdir": None,
                       "suite": ["yuzu:fake"]}]))
    sys.exit(0)
if a and a[0] == "test":
    builddir = a[a.index("-C") + 1]
    logs = os.path.join(builddir, "meson-logs"); os.makedirs(logs, exist_ok=True)
    j = os.path.join(logs, "testlog.junit.xml")
    if os.environ.get("FAKE_MESON_TEST_PASS") == "1":
        open(j, "w").write('<testsuites><testsuite><testcase name="fake - yuzu:fake unit tests"/></testsuite></testsuites>')
        sys.exit(0)
    open(j, "w").write('<testsuites><testsuite><testcase name="fake - yuzu:fake unit tests">'
                       '<failure>boom</failure></testcase></testsuite></testsuites>')
    sys.exit(1)
sys.exit(0)
"""

FAKE_CATCH2 = r"""#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
fail = [c for c in os.environ.get("FAKE_FAIL_CASES", "").split(";") if c]
always = [c for c in os.environ.get("FAKE_ALWAYS_FAIL", "").split(";") if c]
if "--reporter" in a:                       # enumeration run -> emit Catch2 junit
    out = a[a.index("--out") + 1]
    tcs = "".join('<testcase classname="c" name="%s"><failure>boom</failure></testcase>' % c
                  for c in fail)
    open(out, "w").write('<testsuites><testsuite name="fake">%s</testsuite></testsuites>' % tcs)
    sys.exit(1 if fail else 0)
case = a[0] if a else ""                     # isolated retry of one case by name
sys.exit(1 if case in always else 0)
"""


def _write_exe(path, body):
    with open(path, "w") as f:
        f.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def run_scenario(label, env_extra, known_flaky, expect_zero):
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
        env["PATH"] = binroot + os.pathsep + env["PATH"]
        env["FAKE_CATCH2_BIN"] = catch2
        env.update(env_extra)
        r = subprocess.run(
            [sys.executable, WRAPPER, "--builddir", builddir, "--known-flaky", kf],
            env=env, capture_output=True, text=True,
        )
        ok = (r.returncode == 0) == expect_zero
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {label}: exit={r.returncode} (expected {'0' if expect_zero else 'nonzero'})")
        if not ok:
            print("  stdout:", r.stdout.strip().replace("\n", "\n  "))
            print("  stderr:", r.stderr.strip().replace("\n", "\n  "))
        return ok


def main():
    if platform.system() == "Windows":
        print("test_flake_retry: skipped on Windows (POSIX fakes); real CI covers it")
        return 0

    listed = [{"case": "FlakeA", "platforms": [THIS_OS], "reason": "test flake", "added": "2026-06-23"}]
    results = [
        run_scenario("green pass", {"FAKE_MESON_TEST_PASS": "1"}, listed, True),
        run_scenario("listed flake recovers on retry", {"FAKE_FAIL_CASES": "FlakeA"}, listed, True),
        run_scenario("listed flake fails all retries -> block",
                     {"FAKE_FAIL_CASES": "FlakeA", "FAKE_ALWAYS_FAIL": "FlakeA"}, listed, False),
        run_scenario("unlisted failure -> block", {"FAKE_FAIL_CASES": "RealBug"}, listed, False),
        run_scenario("non-Catch2 suite -> block",
                     {"FAKE_FAIL_CASES": "FlakeA", "FAKE_NONCATCH2": "1"}, listed, False),
    ]
    if all(results):
        print(f"\nflake-retry integration test: OK ({len(results)} scenarios)")
        return 0
    print(f"\nflake-retry integration test: {results.count(False)} FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
