#!/usr/bin/env python3
"""check-suite-input-closure.py — prove, against the real build, the class table that
scripts/ci/affected-suites.sh uses to let a pull request skip test suites.

affected-suites.sh skips the SERVER suites when no changed path is server-side and the AGENT
suites when none is agent-side. That is sound only while the two families really are separate in
the build, so this reads the compiler's own dependency records (`ninja -t deps`: every header and
source each object was compiled from) and checks the two claims the class table rests on:

  R-A  no object built for the AGENT family depends on server/, content/ or tests/unit/server/.
       Agent objects are everything under agents/ and the objects of the agent/tar test binaries.
       If one did, a server-only pull request could change an agent test's result and the agent
       suites would be skipped for it.
  R-S  no object built for the SERVER family depends on an agent test: a top-level
       tests/unit/*.cpp (other than the shared test_runner_main.cpp) or anything in
       tests/unit/agent/. Server objects are everything under server/ and the objects of the
       server test binary. If one did, an agent-test-only pull request could change a server
       suite's result and the server suites would be skipped for it.

Which binaries belong to which family is read from `meson introspect --tests` (a test entry whose
suite is server* is the server family, agent/tar the agent family), so a new test binary is picked
up without editing this file.

A family with no dependency records at all is a FAILURE, not a pass: an unbuilt or wiped build dir
would otherwise prove nothing and look identical to a clean result.

What this does not cover: a file a test reads at RUN time. That is affected-suites.sh's
mention-scan (see its header for the rule and its blind spot).

Pure logic (`parse_ninja_deps`, `object_family`, `test_binary_prefixes`, `check_closure`) is
separated from I/O (`main`) the same way check-pg-shard-partition.py is, so
test_check_suite_input_closure.py exercises it with synthetic dependency text and no build.

Run:  python3 scripts/ci/check-suite-input-closure.py --builddir build-linux-gcc-15-debug
Runs after Build on the Linux and macOS legs (POSIX dependency paths; the Windows legs' MSVC
records are not read here, and share the same source tree).
"""
import argparse
import json
import os
import re
import subprocess
import sys

SERVER_SUITES = {"server", "server-nonpg", "server-pg", "server-pg-smoke", "server-checks"}
AGENT_SUITES = {"agent", "tar"}

# Repo-relative prefixes. `agents/` and `server/` also name the OBJECT directories, because meson
# mirrors a target's source directory in its build directory (server/core/libX.a.p/...).
SERVER_TREES = ("server/", "content/", "tests/unit/server/")
SHARED_TEST_MAIN = "tests/unit/test_runner_main.cpp"

MAX_REPORTED = 20


def gh(kind, msg):
    print(f"::{kind}::{msg}", flush=True)


def parse_ninja_deps(lines, repo_root=None):
    """`ninja -t deps` -> {object: [dependency, ...]}. Blocks are `<object>: #deps N, ...`
    followed by four-space-indented dependencies, separated by a blank line. `lines` is a string or
    any iterable of lines (so the ~100 MB real dump can be streamed). With `repo_root`, an
    ABSOLUTE dependency outside it (a system header) is dropped at parse time — it can never be a
    family violation, and a full build has ~1M of them."""
    if isinstance(lines, str):
        lines = lines.splitlines()
    prefix = repo_root + os.sep if repo_root else None
    deps, cur = {}, None
    for line in lines:
        if not line.strip():
            cur = None
        elif not line.startswith(" "):
            cur = line.split(": #deps", 1)[0]
            deps[cur] = []
        elif cur is not None:
            d = line.strip()
            if prefix and os.path.isabs(d) and not d.startswith(prefix):
                continue
            deps[cur].append(d)
    return deps


def _bare(suites):
    return {s.split(":", 1)[1] if ":" in s else s for s in suites}


def test_binary_prefixes(tests, builddir_abs):
    """(server_prefixes, agent_prefixes): the object-directory prefixes, relative to the build
    dir, of the test binaries named by `meson introspect --tests`. A binary `<b>/tests/x` has its
    objects in `tests/x.p/` (`tests/x.exe.p/` where meson names it with a suffix)."""
    server, agent = set(), set()
    for t in tests:
        cmd = t.get("cmd") or []
        if not cmd:
            continue
        exe = os.path.normpath(cmd[0])
        if not os.path.isabs(exe):
            exe = os.path.normpath(os.path.join(builddir_abs, exe))
        if not exe.startswith(builddir_abs + os.sep):
            continue  # python3, rebar3, ... — not a binary this build produced
        rel = os.path.relpath(exe, builddir_abs).replace(os.sep, "/")
        rel = re.sub(r"\.exe$", "", rel)
        suites = _bare(t.get("suite", []))
        prefixes = (f"{rel}.p/", f"{rel}.exe.p/")
        if suites & SERVER_SUITES:
            server.update(prefixes)
        if suites & AGENT_SUITES:
            agent.update(prefixes)
    return server, agent


def object_family(obj, server_prefixes, agent_prefixes):
    """'server' | 'agent' | None for an object path relative to the build dir. None (sdk/,
    proto/, tools/, and anything else) is shared or irrelevant and is not checked."""
    if any(obj.startswith(p) for p in server_prefixes) or obj.startswith("server/"):
        return "server"
    if any(obj.startswith(p) for p in agent_prefixes) or obj.startswith("agents/"):
        return "agent"
    return None


def repo_relative(dep, builddir_abs, repo_root):
    """A dependency as recorded (relative to the build dir, or absolute) -> its path relative to
    the repo root, or None when it is outside the repo (system headers) — vcpkg_installed/ is
    inside the repo but matches no family prefix, so it is harmlessly returned as such."""
    p = dep if os.path.isabs(dep) else os.path.join(builddir_abs, dep)
    p = os.path.normpath(p)
    if not p.startswith(repo_root + os.sep):
        return None
    return os.path.relpath(p, repo_root).replace(os.sep, "/")


def _is_agent_test_file(rel):
    if rel == SHARED_TEST_MAIN:
        return False
    if rel.startswith("tests/unit/agent/"):
        return True
    # a top-level tests/unit/<name>.cpp; a header there is a shared helper and stays allowed
    return rel.startswith("tests/unit/") and rel.count("/") == 2 and rel.endswith(".cpp")


def check_closure(deps, server_prefixes, agent_prefixes, builddir_abs, repo_root):
    """Pure. Returns (ok, failures, stats). `deps` is parse_ninja_deps output."""
    failures = []
    stats = {"server_objects": 0, "agent_objects": 0}
    for obj, dep_list in deps.items():
        fam = object_family(obj, server_prefixes, agent_prefixes)
        if fam is None:
            continue
        stats[f"{fam}_objects"] += 1
        for dep in dep_list:
            rel = repo_relative(dep, builddir_abs, repo_root)
            if rel is None:
                continue
            if fam == "agent" and rel.startswith(SERVER_TREES):
                failures.append(f"R-A: agent-side object {obj} depends on {rel} (server side)")
            elif fam == "server" and _is_agent_test_file(rel):
                failures.append(f"R-S: server-side object {obj} depends on {rel} (an agent test)")
    for fam in ("server", "agent"):
        if stats[f"{fam}_objects"] == 0:
            failures.append(f"no {fam}-family object has dependency records — the build dir is "
                            f"unbuilt or wiped, so nothing was proven")
    return not failures, failures, stats


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--builddir", required=True)
    ap.add_argument("--repo-root", default=os.getcwd())
    args = ap.parse_args(argv)
    builddir_abs = os.path.abspath(args.builddir)
    repo_root = os.path.abspath(args.repo_root)

    tests = json.loads(subprocess.run(
        ["meson", "introspect", args.builddir, "--tests"],
        capture_output=True, text=True, check=True).stdout)
    # Streamed, not captured: a full build's dependency log is ~100 MB of text.
    with subprocess.Popen(["ninja", "-C", args.builddir, "-t", "deps"],
                          stdout=subprocess.PIPE, text=True) as proc:
        deps = parse_ninja_deps(proc.stdout, repo_root)
    if proc.returncode != 0:
        gh("error", f"check-suite-input-closure: `ninja -t deps` exited {proc.returncode}")
        return 1
    server_prefixes, agent_prefixes = test_binary_prefixes(tests, builddir_abs)
    if not server_prefixes or not agent_prefixes:
        gh("error", "check-suite-input-closure: could not identify the server and agent test "
                    "binaries from `meson introspect --tests` — nothing was proven")
        return 1

    ok, failures, stats = check_closure(
        deps, server_prefixes, agent_prefixes, builddir_abs, repo_root)
    if not ok:
        for f in failures[:MAX_REPORTED]:
            gh("error", f"check-suite-input-closure: {f}")
        if len(failures) > MAX_REPORTED:
            gh("error", f"check-suite-input-closure: ... and {len(failures) - MAX_REPORTED} more")
        gh("error", "check-suite-input-closure: the class table in scripts/ci/affected-suites.sh "
                    "no longer matches the build. Either remove the dependency, or reclassify the "
                    "path there (making the PR run both families) in the same change.")
        return 1
    print(f"check-suite-input-closure: OK — {stats['server_objects']} server-family and "
          f"{stats['agent_objects']} agent-family objects; no agent object reads server/, "
          f"content/ or tests/unit/server/, no server object compiles an agent test")
    return 0


if __name__ == "__main__":
    sys.exit(main())
