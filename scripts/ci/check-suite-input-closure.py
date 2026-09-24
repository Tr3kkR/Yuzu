#!/usr/bin/env python3
"""check-suite-input-closure.py — prove, against the real build, the class table that
scripts/ci/affected-suites.sh uses to let a pull request skip test suites.

affected-suites.sh skips the SERVER suites when no changed path can reach them, and the AGENT
suites likewise. That is sound only while its class table matches the build. This reads the
compiler's own dependency records (`ninja -t deps`: every header and source each object was
compiled from), classifies every in-repo input with the SAME table (`affected-suites.sh
--classify-many`, so the table has one home) and fails when

  - an object built for the AGENT family depends on a path classed `server` or `none`, or
  - an object built for the SERVER family depends on a path classed `agent` or `none`.

`both` is fine for either family; `server` for a server object and `agent` for an agent object are
its own inputs. A failure means a pull request touching that path could change a family's result
while the classifier says the family cannot be reached, so its suites would be skipped. Either
remove the dependency, or reclassify the path in affected-suites.sh (making PRs that touch it run
both families) in the same change. The class table is therefore proven per build, and a table edit
that breaks the proof fails here rather than skipping a suite silently.

Object families: everything under `agents/` and the objects of the agent/tar test binaries are the
agent family; everything under `server/` and the objects of the server test binaries are the server
family. Which binaries are which is read from `meson introspect --tests`: a built test binary with
any suite label starting `server` is in the server family, one starting `agent` or `tar` in the
agent family, so a new test binary or a new label such as `server-e2e` is picked up without editing
this file. Objects under sdk/, proto/, tools/ and anything else are shared or irrelevant and are not
checked.

A family with no dependency records at all is a FAILURE, not a pass: an unbuilt or wiped build dir
would otherwise prove nothing and look identical to a clean result. So is a family whose records
resolve to no in-repo input (every dependency path fell outside --repo-root): that too proves nothing.

What this does NOT cover (each is also affected-suites.sh's documented limit):
  - a file a test reads at RUN time: affected-suites.sh's mention-scan owns that;
  - the preprocessor branches this build did not take (`#ifdef _WIN32` includes) — it runs on the
    Linux and macOS legs only, because MSVC's dependency records are Windows-shaped, so a Windows-only
    include of a server file from agent code is invisible here;
  - inputs that are not compiler-visible: a custom_target that reads content/ into an object shows
    up as a build-dir path, and an agent test compiled into a helper library under tests/ has an
    object directory this script does not classify.

Pure logic (`parse_ninja_deps`, `test_binary_prefixes`, `object_family`, `family_inputs`,
`find_violations`, `parse_classify_output`) is separated from I/O (`main`) the same way
check-pg-shard-partition.py is, and works on POSIX-shaped path strings on EVERY platform (it uses
posixpath deliberately): its self-test is registered in the `docs` suite, which the Windows leg
runs. test_check_suite_input_closure.py exercises it with synthetic dependency text and no build.

Run:  python3 scripts/ci/check-suite-input-closure.py --builddir build-linux-gcc-15-debug
"""
import argparse
import json
import os
import posixpath as pp
import re
import subprocess
import sys

# A built test binary is in a family when any of its suite labels starts with one of these.
SERVER_SUITE_PREFIXES = ("server",)
AGENT_SUITE_PREFIXES = ("agent", "tar")

# A family may depend on a path of its own class or `both`; anything else is a violation.
FORBIDDEN_CLASSES = {"server": {"agent", "none"}, "agent": {"server", "none"}}

# In-repo but not source inputs: the build tree and the vcpkg install tree.
NOT_SOURCES = ("build-", "vcpkg_installed/")

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
    prefix = repo_root + "/" if repo_root else None
    deps, cur = {}, None
    for line in lines:
        if not line.strip():
            cur = None
        elif not line.startswith(" "):
            cur = line.split(": #deps", 1)[0]
            deps[cur] = []
        elif cur is not None:
            d = line.strip()
            if prefix and pp.isabs(d) and not d.startswith(prefix):
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
        exe = pp.normpath(cmd[0])
        if not pp.isabs(exe):
            exe = pp.normpath(pp.join(builddir_abs, exe))
        if not exe.startswith(builddir_abs + "/"):
            continue  # python3, rebar3, ... — not a binary this build produced
        rel = re.sub(r"\.exe$", "", pp.relpath(exe, builddir_abs))
        suites = _bare(t.get("suite", []))
        prefixes = (f"{rel}.p/", f"{rel}.exe.p/")
        if any(s.startswith(SERVER_SUITE_PREFIXES) for s in suites):
            server.update(prefixes)
        if any(s.startswith(AGENT_SUITE_PREFIXES) for s in suites):
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
    the repo root, or None when it is outside the repo (system headers)."""
    p = pp.normpath(dep if pp.isabs(dep) else pp.join(builddir_abs, dep))
    if not p.startswith(repo_root + "/"):
        return None
    return pp.relpath(p, repo_root)


def family_inputs(deps, server_prefixes, agent_prefixes, builddir_abs, repo_root):
    """({family: {repo-relative source path: first object that depends on it}}, object counts).
    Build-tree and vcpkg paths are not source inputs and are left out."""
    inputs = {"server": {}, "agent": {}}
    counts = {"server": 0, "agent": 0}
    for obj, dep_list in deps.items():
        fam = object_family(obj, server_prefixes, agent_prefixes)
        if fam is None:
            continue
        counts[fam] += 1
        for dep in dep_list:
            rel = repo_relative(dep, builddir_abs, repo_root)
            if rel is None or rel.startswith(NOT_SOURCES):
                continue
            inputs[fam].setdefault(rel, obj)
    return inputs, counts


def find_violations(inputs, classes):
    """Pure. `inputs` is family_inputs' first result; `classes` maps every path in it to its
    class. Returns the failure messages (empty when the table holds)."""
    failures = []
    for fam in ("server", "agent"):
        for path, obj in sorted(inputs[fam].items()):
            cls = classes[path]
            if cls in FORBIDDEN_CLASSES[fam]:
                failures.append(
                    f"{fam}-family object {obj} depends on {path}, which the class table says "
                    f"cannot affect the {fam} family (class {cls})")
    return failures


def parse_classify_output(text, wanted):
    """`affected-suites.sh --classify-many` output -> {path: class}. Every wanted path must come
    back with a valid class: a short or malformed reply is an error, never a silent pass."""
    classes = {}
    for line in text.splitlines():
        path, sep, cls = line.rpartition("\t")
        if sep and cls in {"both", "server", "agent", "none"}:
            classes[path] = cls
    missing = [p for p in wanted if p not in classes]
    if missing:
        raise ValueError(f"the classifier returned no class for {len(missing)} of {len(wanted)} "
                         f"paths, e.g. {missing[:3]!r}")
    return classes


def classify_with_script(script, paths):
    """One subprocess for the whole set — the classifier is bash, and a full build has ~1.7k
    distinct inputs."""
    text = subprocess.run(["bash", script, "--classify-many"], input="\n".join(paths) + "\n",
                          capture_output=True, text=True, check=True).stdout
    return parse_classify_output(text, paths)


def check_closure(deps, server_prefixes, agent_prefixes, builddir_abs, repo_root, classify):
    """Pure given `classify` (a callable: list of paths -> {path: class}). Returns
    (ok, failures, stats)."""
    inputs, counts = family_inputs(deps, server_prefixes, agent_prefixes, builddir_abs, repo_root)
    failures = []
    for fam in ("server", "agent"):
        if counts[fam] == 0:
            failures.append(f"no {fam}-family object has dependency records — the build dir is "
                            f"unbuilt or wiped, so nothing was proven")
        elif not inputs[fam]:
            failures.append(f"the {counts[fam]} {fam}-family objects record no source input under "
                            f"the repo root ({repo_root}) — the dependency paths do not resolve "
                            f"there, so nothing was proven")
    paths = sorted(set(inputs["server"]) | set(inputs["agent"]))
    classes = classify(paths) if paths else {}
    violations = find_violations(inputs, classes)
    failures += violations
    stats = {"server_objects": counts["server"], "agent_objects": counts["agent"],
             "inputs": len(paths), "violations": len(violations)}
    return not failures, failures, stats


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--builddir", required=True)
    ap.add_argument("--repo-root", default=os.getcwd())
    args = ap.parse_args(argv)
    if os.name == "nt":
        gh("error", "check-suite-input-closure: POSIX dependency records only; this guard is "
                    "not run on the Windows legs (see the module docstring)")
        return 2
    builddir_abs = os.path.abspath(args.builddir)
    repo_root = os.path.abspath(args.repo_root)
    script = os.path.join(repo_root, "scripts", "ci", "affected-suites.sh")

    try:
        tests = json.loads(subprocess.run(
            ["meson", "introspect", args.builddir, "--tests"],
            capture_output=True, text=True, check=True).stdout)
        # Streamed, not captured: a full build's dependency log is ~100 MB of text.
        with subprocess.Popen(["ninja", "-C", args.builddir, "-t", "deps"],
                              stdout=subprocess.PIPE, text=True) as proc:
            deps = parse_ninja_deps(proc.stdout, repo_root)
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, "ninja -t deps")
    except (subprocess.CalledProcessError, OSError, ValueError) as e:
        gh("error", f"check-suite-input-closure: could not read the build: {e}")
        return 1
    server_prefixes, agent_prefixes = test_binary_prefixes(tests, builddir_abs)
    if not server_prefixes or not agent_prefixes:
        gh("error", "check-suite-input-closure: could not identify the server and agent test "
                    "binaries from `meson introspect --tests` — nothing was proven")
        return 1

    def classify(paths):
        return classify_with_script(script, paths)

    try:
        ok, failures, stats = check_closure(
            deps, server_prefixes, agent_prefixes, builddir_abs, repo_root, classify)
    except (subprocess.CalledProcessError, OSError, ValueError) as e:
        detail = (getattr(e, "stderr", None) or "").strip()
        gh("error", f"check-suite-input-closure: could not classify the inputs: {e}"
                    + (f" — {detail}" if detail else ""))
        return 1
    if not ok:
        for f in failures[:MAX_REPORTED]:
            gh("error", f"check-suite-input-closure: {f}")
        if len(failures) > MAX_REPORTED:
            gh("error", f"check-suite-input-closure: ... and {len(failures) - MAX_REPORTED} more")
        if stats["violations"]:
            gh("error", "check-suite-input-closure: the class table in scripts/ci/affected-suites.sh "
                        "no longer matches the build. Either remove the dependency, or reclassify the "
                        "path there (making a PR that touches it run both families) in the same change. "
                        "Two merged changes can cause this together (one adds the include, another "
                        "moves the file), so it can appear on a PR that touched neither; the fix is the "
                        "same.")
        return 1
    print(f"check-suite-input-closure: OK — {stats['server_objects']} server-family and "
          f"{stats['agent_objects']} agent-family objects, {stats['inputs']} distinct source "
          f"inputs, every one classed consistently with the family that compiles it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
