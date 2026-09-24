#!/usr/bin/env python3
"""Unit test for check-suite-input-closure.py's own detection logic — synthetic `ninja -t deps` text,
`meson introspect --tests` entries and a table-driven stand-in for the classifier, no real build.
Same pure/IO split precedent as test_check_pg_shard_partition.py and test_assert_suite_cover.py.

A guard that can pass vacuously is worse than none, so "a violation IS reported" and "a hollow
run is NOT a pass" get as many cases as the clean one. It runs in the `docs` suite on Windows too,
so it must not depend on the host's path flavour (test_host_path_flavour_is_irrelevant).

Run: python3 scripts/ci/test_check_suite_input_closure.py   (exit 0 = pass)
"""
import importlib.util
import ntpath
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "check_suite_input_closure", os.path.join(HERE, "check-suite-input-closure.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

ROOT = "/repo"
BUILD = "/repo/build-linux-gcc-15-debug"
SERVER_P = {"tests/yuzu_server_tests.p/", "tests/yuzu_server_tests.exe.p/"}
AGENT_P = {"tests/yuzu_agent_tests.p/", "tests/yuzu_agent_tests.exe.p/"}

# The class every path used below has in the REAL table (scripts/ci/affected-suites.sh). Explicit
# here, on purpose: the guard is tested against a stand-in so that a change to the real table cannot
# silently rewrite what these cases assert. The real table is exercised by the shell self-test and
# by the guard's own run against the real build.
TABLE = {
    "tests/unit/server/test_x.cpp": "server", "server/core/src/x.hpp": "server",
    "server/core/src/totp.hpp": "server", "server/core/src/server.cpp": "server",
    "content/definitions/x.yaml": "server",
    "tests/unit/test_y.cpp": "agent", "tests/unit/agent/test_b.cpp": "agent",
    "tests/unit/test_helpers.hpp": "both", "tests/unit/test_runner_main.cpp": "both",
    "tests/unit/test_log_capture.hpp": "both", "tests/unit/tls_probe.hpp": "both",
    "agents/core/src/spark_heartbeat.hpp": "both", "agents/core/src/y.hpp": "both",
    "agents/core/src/agent.cpp": "both", "common/include/yuzu/z.hpp": "both",
    "sdk/include/yuzu/plugin.h": "both",
    "docs/user-manual/x.md": "none", "deploy/windows/x.ps1": "none",
}


def check(cond, label, failures):
    if cond:
        print(f"  ok       {label}")
    else:
        print(f"  FAIL     {label}")
        failures.append(label)


def _classify(paths):
    return {p: TABLE[p] for p in paths}   # strict: an unlisted path is a typo in the test


def _run(deps, classify=_classify):
    return _mod.check_closure(deps, SERVER_P, AGENT_P, BUILD, ROOT, classify)


# a minimal clean build: server and agent objects with real dependencies
CLEAN = {
    "tests/yuzu_server_tests.p/unit_server_test_x.cpp.o":
        ["../tests/unit/server/test_x.cpp", "../server/core/src/x.hpp",
         "../tests/unit/test_helpers.hpp", "../agents/core/src/spark_heartbeat.hpp",
         "/usr/include/c++/v1/chrono", "../vcpkg_installed/x64-linux/include/spdlog/spdlog.h"],
    "tests/yuzu_agent_tests.p/unit_test_y.cpp.o":
        ["../tests/unit/test_y.cpp", "../agents/core/src/y.hpp", "../common/include/yuzu/z.hpp",
         "../tests/unit/test_helpers.hpp"],
    "agents/core/libyuzu_agent_core.so.p/src_agent.cpp.o":
        ["../agents/core/src/agent.cpp", "../sdk/include/yuzu/plugin.h"],
    "server/core/libyuzu_server_core_lib.a.p/src_server.cpp.o":
        ["../server/core/src/server.cpp", "../common/include/yuzu/z.hpp"],
}
SERVER_OBJ = "tests/yuzu_server_tests.p/unit_server_test_x.cpp.o"
AGENT_OBJ = "tests/yuzu_agent_tests.p/unit_test_y.cpp.o"
AGENT_CORE_OBJ = "agents/core/libyuzu_agent_core.so.p/src_agent.cpp.o"


def _with(obj, deps):
    d = dict(CLEAN)
    d[obj] = deps
    return d


def test_clean(failures):
    ok, msgs, stats = _run(CLEAN)
    check(ok and msgs == [], "clean build: ok, no messages", failures)
    check(stats == {"server_objects": 2, "agent_objects": 2, "inputs": 10, "violations": 0},
          "clean build: object and input counts", failures)


def test_server_family_may_depend_on_agents_core_headers(failures):
    # The real coupling that made the class table coarse: the server test binary compiles 15
    # agents/core headers. Those are class `both`, so the guard must NOT flag them; only a path
    # the table calls agent-only or inert would be a contradiction.
    check("../agents/core/src/spark_heartbeat.hpp" in CLEAN[SERVER_OBJ] and _run(CLEAN)[0],
          "a server object depending on an agents/core header (class both) is allowed", failures)


def test_agent_object_depends_on_server_class_path(failures):
    ok, msgs, stats = _run(_with(AGENT_OBJ, ["../tests/unit/test_y.cpp", "../server/core/src/totp.hpp"]))
    check(not ok, "agent test including a server header fails", failures)
    check(stats["violations"] == 1, "a violation is counted (main() names the class table only then)",
          failures)
    check(any("agent-family object" in m and "server/core/src/totp.hpp" in m and "class server" in m
              for m in msgs), "message names the family, the file and its class", failures)


def test_agent_core_object_depends_on_content(failures):
    ok, msgs, _ = _run(_with(AGENT_CORE_OBJ, ["../content/definitions/x.yaml"]))
    check(not ok and any("content/definitions/x.yaml" in m for m in msgs),
          "an agents/ object depending on content/ fails", failures)


def test_agent_object_depends_on_server_test(failures):
    ok, msgs, _ = _run(_with(AGENT_OBJ, ["../tests/unit/server/test_x.cpp"]))
    check(not ok and any("tests/unit/server/test_x.cpp" in m for m in msgs),
          "an agent test depending on tests/unit/server/ fails", failures)


def test_server_object_depends_on_agent_class_path(failures):
    ok, msgs, _ = _run(_with(SERVER_OBJ, ["../tests/unit/test_y.cpp"]))
    check(not ok and any("server-family object" in m and "tests/unit/test_y.cpp" in m
                         and "class agent" in m for m in msgs),
          "server object depending on a top-level agent test fails", failures)


def test_server_object_uses_tests_unit_agent_dir(failures):
    ok, msgs, _ = _run(_with(SERVER_OBJ, ["../tests/unit/agent/test_b.cpp"]))
    check(not ok and any("tests/unit/agent/test_b.cpp" in m for m in msgs),
          "server object depending on tests/unit/agent/ fails", failures)


def test_inert_class_path_in_either_family_fails(failures):
    # The widest false skip: a PR touching only `none`-class paths skips BOTH families, so no
    # compiled object may depend on one.
    ok, msgs, _ = _run(_with(AGENT_OBJ, ["../docs/user-manual/x.md"]))
    check(not ok and any("docs/user-manual/x.md" in m and "class none" in m for m in msgs),
          "an agent object depending on an inert (none) path fails", failures)
    ok, msgs, _ = _run(_with(SERVER_OBJ, ["../deploy/windows/x.ps1"]))
    check(not ok and any("deploy/windows/x.ps1" in m and "class none" in m for m in msgs),
          "a server object depending on an inert (none) path fails", failures)


def test_shared_test_files_allowed(failures):
    # test_runner_main.cpp and the helper headers are class `both` by design.
    d = dict(CLEAN)
    d["tests/yuzu_server_tests.p/unit_test_runner_main.cpp.o"] = [
        "../tests/unit/test_runner_main.cpp", "../tests/unit/test_helpers.hpp",
        "../tests/unit/test_log_capture.hpp", "../tests/unit/tls_probe.hpp"]
    check(_run(d)[0], "test_runner_main.cpp and shared helper headers are allowed", failures)


def test_objects_outside_both_families_are_ignored(failures):
    d = dict(CLEAN)
    d["proto/libyuzu_proto.a.p/x.pb.cc.o"] = ["../server/core/src/x.hpp", "../tests/unit/test_y.cpp"]
    d["tools/capmatrix-gen/x.p/x.cpp.o"] = ["../docs/user-manual/x.md"]
    check(_run(d)[0], "shared/tool objects are not checked", failures)


def test_build_tree_and_vcpkg_are_not_source_inputs(failures):
    # An in-repo path that is not a source (generated headers in the build dir, the vcpkg tree)
    # must not reach the classifier at all — the strict test double would raise KeyError on it.
    d = _with(AGENT_OBJ, ["../tests/unit/test_y.cpp", "proto/agent.pb.h",
                          "../build-macos/proto/agent.pb.h", "../vcpkg_installed/x64/include/a.h"])
    check(_run(d)[0], "build-tree and vcpkg paths are skipped before classification", failures)


def test_hollow_families_fail(failures):
    ok, msgs, _ = _run({k: v for k, v in CLEAN.items() if "agent" not in k})
    check(not ok and any("no agent-family object" in m for m in msgs),
          "no agent objects with deps: FAILS (an unbuilt dir proves nothing)", failures)
    ok, msgs, _ = _run({k: v for k, v in CLEAN.items() if "server" not in k})
    check(not ok and any("no server-family object" in m for m in msgs),
          "no server objects with deps: FAILS", failures)
    ok, msgs, _ = _run({})
    check(not ok and len(msgs) == 2, "empty dependency log: both families reported hollow", failures)
    # objects exist, but every dependency path falls outside the repo root (a wrong --repo-root)
    outside = {k: ["/elsewhere/x.hpp"] for k in CLEAN}
    ok, msgs, _ = _run(outside)
    check(not ok and sum("record no source input" in m for m in msgs) == 2,
          "objects whose deps resolve outside the repo: FAILS for both families", failures)
    check(_run(outside)[2]["violations"] == 0, "a hollow run is not reported as a table mismatch",
          failures)


def test_classifier_is_not_called_without_inputs(failures):
    called = []

    def spy(paths):
        called.append(paths)
        return {}
    _run({}, classify=spy)
    check(called == [], "no inputs -> no classifier call", failures)


def test_paths_outside_repo_ignored(failures):
    # A system header can never be a family violation, even one containing a server-looking segment.
    d = _with(AGENT_OBJ, ["../tests/unit/test_y.cpp", "/opt/other/server/core/src/x.hpp",
                          "/usr/include/server/x.h"])
    check(_run(d)[0], "paths outside the repo root are ignored", failures)


def test_absolute_paths_inside_repo_are_normalised(failures):
    ok, msgs, _ = _run(_with(AGENT_OBJ, ["/repo/server/core/src/x.hpp"]))
    check(not ok and any("server/core/src/x.hpp" in m for m in msgs),
          "an absolute in-repo dependency is caught the same as a relative one", failures)


def test_dotdot_normalisation(failures):
    check(not _run(_with(AGENT_OBJ, ["../agents/../server/core/src/x.hpp"]))[0],
          "a ../ detour into server/ is normalised before matching", failures)


def test_every_violation_reported(failures):
    d = dict(CLEAN)
    d[AGENT_OBJ] = ["../server/core/src/totp.hpp", "../content/definitions/x.yaml"]
    d[SERVER_OBJ] = ["../tests/unit/test_y.cpp"]
    ok, msgs, _ = _run(d)
    check(not ok and len(msgs) == 3, "all violations are collected, not just the first", failures)


def test_parse_ninja_deps(failures):
    text = ("tests/yuzu_server_tests.p/a.cpp.o: #deps 3, deps mtime 1 (VALID)\n"
            "    ../tests/unit/server/a.cpp\n"
            "    ../server/core/src/a.hpp\n"
            "    /usr/include/x.h\n"
            "\n"
            "agents/core/x.p/b.cpp.o: #deps 1, deps mtime 2 (VALID)\n"
            "    ../agents/core/src/b.cpp\n"
            "\n")
    d = _mod.parse_ninja_deps(text)
    check(list(d) == ["tests/yuzu_server_tests.p/a.cpp.o", "agents/core/x.p/b.cpp.o"],
          "parse: object names", failures)
    check(d["tests/yuzu_server_tests.p/a.cpp.o"] ==
          ["../tests/unit/server/a.cpp", "../server/core/src/a.hpp", "/usr/include/x.h"],
          "parse: dependency lists", failures)
    check(_mod.parse_ninja_deps("") == {}, "parse: empty input", failures)
    # an iterable of lines (the streamed real dump) parses the same as a string
    check(_mod.parse_ninja_deps(iter(text.splitlines())) == d, "parse: streamed lines", failures)
    # with a repo root, absolute paths outside it are dropped at parse time, in-repo ones kept
    kept = _mod.parse_ninja_deps(text + "x.o: #deps 2, deps mtime 3 (VALID)\n"
                                 "    /repo/server/core/src/a.hpp\n    /usr/lib/x.h\n", repo_root=ROOT)
    check(kept["x.o"] == ["/repo/server/core/src/a.hpp"] and
          kept["tests/yuzu_server_tests.p/a.cpp.o"] ==
          ["../tests/unit/server/a.cpp", "../server/core/src/a.hpp"],
          "parse: system headers dropped, relative and in-repo deps kept", failures)


def _t(name, cmd0, suites):
    return {"name": name, "cmd": [cmd0], "suite": [f"yuzu:{s}" for s in suites]}


def test_binary_prefixes(failures):
    tests = [
        _t("server shard", BUILD + "/tests/yuzu_server_tests", ["server", "server-pg"]),
        _t("agent", BUILD + "/tests/yuzu_agent_tests", ["agent"]),
        _t("tar", "tests/yuzu_tar_tests", ["tar"]),                      # relative to the build dir
        _t("docs", "/usr/bin/python3", ["docs"]),                        # not built here
        _t("gateway", "/usr/local/bin/rebar3", ["gateway"]),
        _t("winexe", BUILD + "/tests/yuzu_win_tests.exe", ["agent"]),
    ]
    tests.append({"name": "no cmd", "suite": ["yuzu:agent"]})
    server, agent = _mod.test_binary_prefixes(tests, BUILD)
    check(server == {"tests/yuzu_server_tests.p/", "tests/yuzu_server_tests.exe.p/"},
          "prefixes: server binary", failures)
    check("tests/yuzu_agent_tests.p/" in agent and "tests/yuzu_tar_tests.p/" in agent,
          "prefixes: agent and tar binaries (absolute and build-relative cmd[0])", failures)
    check("tests/yuzu_win_tests.p/" in agent,
          "prefixes: a .exe suffix maps to the meson .p directory", failures)
    check(not any("python" in p or "rebar3" in p for p in server | agent),
          "prefixes: interpreters are not test binaries", failures)
    # a family is any label with the family's prefix, so a new label cannot hide a binary
    more = [_t("e2e", BUILD + "/tests/yuzu_e2e_tests", ["server-e2e"]),
            _t("agent2", BUILD + "/tests/yuzu_agent2_tests", ["agent-extra"]),
            _t("checks", "/usr/bin/python3", ["server", "server-checks"]),
            _t("other", BUILD + "/tests/yuzu_other_tests", ["docs"])]
    server2, agent2 = _mod.test_binary_prefixes(more, BUILD)
    check("tests/yuzu_e2e_tests.p/" in server2 and "tests/yuzu_agent2_tests.p/" in agent2,
          "prefixes: a label that starts with the family name is in the family", failures)
    check(not any("python" in p for p in server2) and not any("other" in p for p in server2 | agent2),
          "prefixes: an interpreter in a server suite, and a binary in neither family, are not", failures)


def test_object_family(failures):
    f = lambda o: _mod.object_family(o, SERVER_P, AGENT_P)
    check(f("tests/yuzu_server_tests.p/x.o") == "server", "family: server test object", failures)
    check(f("server/core/libx.a.p/y.o") == "server", "family: server library object", failures)
    check(f("tests/yuzu_agent_tests.p/x.o") == "agent", "family: agent test object", failures)
    check(f("agents/plugins/p/libp.so.p/y.o") == "agent", "family: plugin object", failures)
    check(f("proto/libyuzu_proto.a.p/z.o") is None, "family: proto is shared", failures)
    check(f("tests/other_tests.p/x.o") is None, "family: an unknown test binary is unclassified",
          failures)


def test_parse_classify_output(failures):
    wanted = ["server/x", "docs/a b.md", "agents/y"]
    out = "server/x\tserver\ndocs/a b.md\tnone\nagents/y\tboth\n"
    check(_mod.parse_classify_output(out, wanted) ==
          {"server/x": "server", "docs/a b.md": "none", "agents/y": "both"},
          "classify reply: parsed, including a path with a space", failures)
    for label, bad in (("short reply", "server/x\tserver\n"),
                       ("invalid class name", "server/x\tserver\ndocs/a b.md\tnone\nagents/y\tweird\n"),
                       ("empty reply", "")):
        try:
            _mod.parse_classify_output(bad, wanted)
            check(False, f"classify reply: {label} must raise", failures)
        except ValueError:
            check(True, f"classify reply: {label} raises, never a silent pass", failures)


def test_host_path_flavour_is_irrelevant(failures):
    # The Windows leg runs this file (the `docs` suite). The pure functions must give the same
    # answer whatever os.path is, so run them with the module's `os` replaced by a Windows one: if
    # a pure function ever reaches for os.path/os.sep again, this is where it shows.
    def outcomes():
        return (_run(CLEAN)[0], _run(_with(AGENT_OBJ, ["../server/core/src/totp.hpp"]))[0],
                _mod.repo_relative("../server/core/src/x.hpp", BUILD, ROOT),
                _mod.test_binary_prefixes([_t("a", BUILD + "/tests/yuzu_agent_tests", ["agent"])],
                                          BUILD),
                _mod.parse_ninja_deps("o: #deps 1\n    /repo/a.hpp\n    /usr/x.h\n", ROOT))

    posix = outcomes()
    real_os = _mod.os
    _mod.os = types.SimpleNamespace(path=ntpath, sep="\\", name="nt", getcwd=real_os.getcwd)
    try:
        windows = outcomes()
    finally:
        _mod.os = real_os
    check(posix == windows and posix[0] is True and posix[1] is False,
          "pure functions give identical results under Windows os.path semantics", failures)


def main():
    failures = []
    for fn in (test_clean, test_server_family_may_depend_on_agents_core_headers,
               test_agent_object_depends_on_server_class_path, test_agent_core_object_depends_on_content,
               test_agent_object_depends_on_server_test, test_server_object_depends_on_agent_class_path,
               test_server_object_uses_tests_unit_agent_dir, test_inert_class_path_in_either_family_fails,
               test_shared_test_files_allowed, test_objects_outside_both_families_are_ignored,
               test_build_tree_and_vcpkg_are_not_source_inputs, test_hollow_families_fail,
               test_classifier_is_not_called_without_inputs, test_paths_outside_repo_ignored,
               test_absolute_paths_inside_repo_are_normalised, test_dotdot_normalisation,
               test_every_violation_reported, test_parse_ninja_deps, test_binary_prefixes,
               test_object_family, test_parse_classify_output, test_host_path_flavour_is_irrelevant):
        fn(failures)
    if failures:
        print(f"\ncheck-suite-input-closure selftest: {len(failures)} FAILED")
        return 1
    print("\ncheck-suite-input-closure selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
