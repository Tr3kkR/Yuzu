#!/usr/bin/env python3
"""Unit test for check-suite-input-closure.py's own detection logic — synthetic `ninja -t deps` text
and `meson introspect --tests` entries, no real build. Same pure/IO split precedent as
test_check_pg_shard_partition.py and test_assert_suite_cover.py.

A guard that can pass vacuously is worse than none, so the cases below spend as much effort on
"a real violation IS reported" and "an empty build dir is NOT a pass" as on the clean case.

Run: python3 scripts/ci/test_check_suite_input_closure.py   (exit 0 = pass)
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "check_suite_input_closure", os.path.join(HERE, "check-suite-input-closure.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

ROOT = "/repo"
BUILD = "/repo/build-linux-gcc-15-debug"
SERVER_P = {"tests/yuzu_server_tests.p/", "tests/yuzu_server_tests.exe.p/"}
AGENT_P = {"tests/yuzu_agent_tests.p/", "tests/yuzu_agent_tests.exe.p/"}


def check(cond, label, failures):
    if cond:
        print(f"  ok       {label}")
    else:
        print(f"  FAIL     {label}")
        failures.append(label)


def _deps(**objs):
    """{object: [deps]} — keys use `__` for `/` so they can be kwargs."""
    return {k.replace("__", "/"): v for k, v in objs.items()}


def _run(deps):
    return _mod.check_closure(deps, SERVER_P, AGENT_P, BUILD, ROOT)


# a minimal clean build: one server object, one agent object, both with real deps
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


def test_clean(failures):
    ok, msgs, stats = _run(CLEAN)
    check(ok and msgs == [], "clean build: ok, no messages", failures)
    check(stats == {"server_objects": 2, "agent_objects": 2}, "clean build: object counts", failures)


def test_server_test_may_include_agent_headers(failures):
    # The real coupling that made the class table coarse: the server test binary compiles 15
    # agents/core headers. That is server -> agent, which is allowed and is exactly why agents/ is
    # class `both`. The guard must NOT flag it.
    ok, msgs, _ = _run(CLEAN)
    check(ok, "server -> agents/core header is allowed", failures)


def test_r_a_agent_object_includes_server_header(failures):
    d = dict(CLEAN)
    d["tests/yuzu_agent_tests.p/unit_test_y.cpp.o"] = ["../tests/unit/test_y.cpp",
                                                       "../server/core/src/totp.hpp"]
    ok, msgs, _ = _run(d)
    check(not ok, "R-A: agent test including a server header fails", failures)
    check(any("R-A" in m and "server/core/src/totp.hpp" in m for m in msgs),
          "R-A: message names the object side and the file", failures)


def test_r_a_agent_core_object_includes_content(failures):
    d = dict(CLEAN)
    d["agents/core/libyuzu_agent_core.so.p/src_agent.cpp.o"] = ["../content/definitions/x.yaml"]
    ok, msgs, _ = _run(d)
    check(not ok and any("content/definitions/x.yaml" in m for m in msgs),
          "R-A: an agents/ object depending on content/ fails", failures)


def test_r_a_agent_object_includes_server_test(failures):
    d = dict(CLEAN)
    d["tests/yuzu_agent_tests.p/unit_test_y.cpp.o"] = ["../tests/unit/server/test_x.cpp"]
    ok, msgs, _ = _run(d)
    check(not ok and any("tests/unit/server/test_x.cpp" in m for m in msgs),
          "R-A: an agent test depending on tests/unit/server/ fails", failures)


def test_r_s_server_object_compiles_agent_test(failures):
    d = dict(CLEAN)
    d["tests/yuzu_server_tests.p/unit_server_test_x.cpp.o"] = ["../tests/unit/test_y.cpp"]
    ok, msgs, _ = _run(d)
    check(not ok and any("R-S" in m and "tests/unit/test_y.cpp" in m for m in msgs),
          "R-S: server object depending on a top-level agent test fails", failures)


def test_r_s_server_object_uses_tests_unit_agent_dir(failures):
    d = dict(CLEAN)
    d["tests/yuzu_server_tests.p/unit_server_test_x.cpp.o"] = ["../tests/unit/agent/test_b.cpp"]
    ok, msgs, _ = _run(d)
    check(not ok and any("tests/unit/agent/test_b.cpp" in m for m in msgs),
          "R-S: server object depending on tests/unit/agent/ fails", failures)


def test_r_s_shared_test_files_allowed(failures):
    # test_runner_main.cpp and the helper headers are shared by design.
    d = dict(CLEAN)
    d["tests/yuzu_server_tests.p/unit_test_runner_main.cpp.o"] = [
        "../tests/unit/test_runner_main.cpp", "../tests/unit/test_helpers.hpp",
        "../tests/unit/test_log_capture.hpp", "../tests/unit/tls_probe.hpp"]
    ok, msgs, _ = _run(d)
    check(ok, "R-S: test_runner_main.cpp and shared helper headers are allowed", failures)


def test_objects_outside_both_families_are_ignored(failures):
    d = dict(CLEAN)
    d["proto/libyuzu_proto.a.p/x.pb.cc.o"] = ["../server/core/src/x.hpp", "../tests/unit/test_y.cpp"]
    d["tools/capmatrix-gen/x.p/x.cpp.o"] = ["../server/core/src/x.hpp"]
    ok, _, _ = _run(d)
    check(ok, "shared/tool objects are not checked", failures)


def test_hollow_agent_family_fails(failures):
    d = {k: v for k, v in CLEAN.items() if "agent" not in k}
    ok, msgs, _ = _run(d)
    check(not ok and any("no agent-family object" in m for m in msgs),
          "no agent objects with deps: FAILS (an unbuilt dir proves nothing)", failures)


def test_hollow_server_family_fails(failures):
    d = {k: v for k, v in CLEAN.items() if "server" not in k}
    ok, msgs, _ = _run(d)
    check(not ok and any("no server-family object" in m for m in msgs),
          "no server objects with deps: FAILS", failures)


def test_empty_deps_fails(failures):
    ok, msgs, _ = _run({})
    check(not ok and len(msgs) == 2, "empty dependency log: both families reported hollow", failures)


def test_paths_outside_repo_ignored(failures):
    # A system header or a vcpkg path can never be a family violation, even one containing a
    # server-looking segment.
    d = dict(CLEAN)
    d["tests/yuzu_agent_tests.p/unit_test_y.cpp.o"] = [
        "/opt/other/server/core/src/x.hpp", "/usr/include/server/x.h"]
    ok, _, _ = _run(d)
    check(ok, "paths outside the repo root are ignored", failures)


def test_absolute_paths_inside_repo_are_normalised(failures):
    d = dict(CLEAN)
    d["tests/yuzu_agent_tests.p/unit_test_y.cpp.o"] = ["/repo/server/core/src/x.hpp"]
    ok, msgs, _ = _run(d)
    check(not ok and any("server/core/src/x.hpp" in m for m in msgs),
          "an absolute in-repo dependency is caught the same as a relative one", failures)


def test_dotdot_normalisation(failures):
    d = dict(CLEAN)
    d["tests/yuzu_agent_tests.p/unit_test_y.cpp.o"] = ["../agents/../server/core/src/x.hpp"]
    ok, _, _ = _run(d)
    check(not ok, "a ../ detour into server/ is normalised before matching", failures)


def test_every_violation_reported(failures):
    d = dict(CLEAN)
    d["tests/yuzu_agent_tests.p/unit_test_y.cpp.o"] = ["../server/core/src/a.hpp",
                                                       "../content/b.yaml"]
    d["tests/yuzu_server_tests.p/unit_server_test_x.cpp.o"] = ["../tests/unit/test_y.cpp"]
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


def test_object_family(failures):
    f = lambda o: _mod.object_family(o, SERVER_P, AGENT_P)
    check(f("tests/yuzu_server_tests.p/x.o") == "server", "family: server test object", failures)
    check(f("server/core/libx.a.p/y.o") == "server", "family: server library object", failures)
    check(f("tests/yuzu_agent_tests.p/x.o") == "agent", "family: agent test object", failures)
    check(f("agents/plugins/p/libp.so.p/y.o") == "agent", "family: plugin object", failures)
    check(f("proto/libyuzu_proto.a.p/z.o") is None, "family: proto is shared", failures)
    check(f("tests/other_tests.p/x.o") is None, "family: an unknown test binary is unclassified",
          failures)


def main():
    failures = []
    for fn in (test_clean, test_server_test_may_include_agent_headers,
               test_r_a_agent_object_includes_server_header, test_r_a_agent_core_object_includes_content,
               test_r_a_agent_object_includes_server_test, test_r_s_server_object_compiles_agent_test,
               test_r_s_server_object_uses_tests_unit_agent_dir, test_r_s_shared_test_files_allowed,
               test_objects_outside_both_families_are_ignored, test_hollow_agent_family_fails,
               test_hollow_server_family_fails, test_empty_deps_fails, test_paths_outside_repo_ignored,
               test_absolute_paths_inside_repo_are_normalised, test_dotdot_normalisation,
               test_every_violation_reported, test_parse_ninja_deps, test_binary_prefixes,
               test_object_family):
        fn(failures)
    if failures:
        print(f"\ncheck-suite-input-closure selftest: {len(failures)} FAILED")
        return 1
    print("\ncheck-suite-input-closure selftest: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
