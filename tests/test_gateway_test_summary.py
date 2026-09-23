#!/usr/bin/env python3
"""Pin the Meson gateway test wrapper's #4800 guarantees.

#4800: the `gateway ct` Meson test ran `rebar3 ct` with no `--dir`, so it
discovered zero suites, printed "All 0 tests passed." and exited 0 on every
platform, hiding #4707 and #4708. This file pins three things so that
cannot silently come back:

  1. scripts/gateway_test_summary.py's summary parser and zero-executed
     guard, against every rebar3 ct/eunit summary shape it must handle;
  2. scripts/test_gateway.py still points ct at the directory the CT suites
     actually live in, and still routes every exit through the guard;
  3. each suite's wrapper deadline stays BELOW its meson timeout, so the
     wrapper's pre-kill process-tree dump is reachable.

Hermetic: parses sources, runs nothing.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

import gateway_test_summary as gts  # noqa: E402

WRAPPER = os.path.join(ROOT, 'scripts', 'test_gateway.py')
MESON = os.path.join(ROOT, 'meson.build')
CT_DIR = os.path.join(ROOT, 'gateway', 'apps', 'yuzu_gw', 'test', 'ct')


def _read(path):
    with open(path, encoding='utf-8') as f:
        return f.read()


class ExecutedCount(unittest.TestCase):

    def test_summary_shapes(self):
        cases = {
            # ct
            'All 52 tests passed.': 52,
            'Failed 6 tests. Skipped 2 (0, 2) tests. Passed 44 tests. ': 50,
            'Skipped 2 (2, 0) tests. Passed 44 tests.': 44,
            'Failed 5 tests. Passed 0 tests.': 5,
            'Failed 1 test. Passed 51 tests.\r\n': 52,
            # eunit
            '  All 324 tests passed.': 324,
            '  Failed: 2.  Skipped: 0.  Passed: 309.': 311,
            '  Test passed.': 1,
            '  2 tests passed.': 2,
            'There were no tests to run.': 0,
            # the #4800 false green itself
            '\x1b[0mAll 0 tests passed.\r\n': 0,
            # ANSI colouring around the summary (rebar3 default)
            '\x1b[0;32mAll 52 tests passed.\x1b[0m\r\n': 52,
        }
        for text, want in cases.items():
            with self.subTest(text=text):
                self.assertEqual(gts.executed_count(text), want)

    def test_no_summary_is_none(self):
        self.assertIsNone(gts.executed_count('===> Compiling yuzu_gw\n'))
        self.assertIsNone(gts.executed_count(''))

    def test_truncated_capture_fails_closed(self):
        # #4800 Gate 5 CH-1: output cut before rebar3's summary must never
        # read as a pass, including when a test's own log text CONTAINS a
        # summary-shaped phrase (anchoring), a line is cut mid-way, or an
        # ANSI escape is split by the cut.
        real = ('%%% yuzu_gw_e2e_SUITE: ....\n'
                '*** log: All 5 tests passed. (fixture noise)\n'
                'agent said "Passed 3 tests." earlier\n'
                '\x1b[0mAll 52 tests passed.\n')
        cut = real.index('\x1b[0mAll 52')
        for n in range(0, cut + 1):
            with self.subTest(cut=n):
                self.assertEqual(gts.require_tests_executed(real[:n], 'ct', 0), 1)
        for partial in ('All 5', '\x1b[0mAll 52 tests pass', '\x1b[', '\x1b[0'):
            with self.subTest(partial=partial):
                self.assertEqual(
                    gts.require_tests_executed(real[:cut] + partial, 'ct', 0), 1)
        self.assertEqual(gts.require_tests_executed(real, 'ct', 0), 0)

    def test_last_summary_wins(self):
        self.assertEqual(
            gts.executed_count('All 3 tests passed.\n...\n  All 311 tests passed.\n'), 311)


class RequireTestsExecuted(unittest.TestCase):

    def test_zero_executed_fails_a_green_run(self):
        self.assertEqual(gts.require_tests_executed('All 0 tests passed.', 'ct', 0), 1)
        self.assertEqual(gts.require_tests_executed('There were no tests to run.', 'eunit', 0), 1)

    def test_missing_summary_fails_a_green_run(self):
        self.assertEqual(gts.require_tests_executed('===> Running Common Test suites...', 'ct', 0), 1)

    def test_real_run_passes(self):
        self.assertEqual(gts.require_tests_executed('All 52 tests passed.', 'ct', 0), 0)

    def test_nonzero_rc_passes_through_unchanged(self):
        self.assertEqual(gts.require_tests_executed('Failed 6 tests. Passed 44 tests.', 'ct', 1), 1)
        self.assertEqual(gts.require_tests_executed('', 'ct', -1), -1)


class CancelTolerantVerdict(unittest.TestCase):
    # The verdict /test's eunit-gate.sh and the release workflow's EUnit step
    # both take from scripts/gateway_test_summary.py (#1005 tolerance +
    # #4800 zero-executed rule).

    def test_matrix(self):
        cases = [
            # (log, rc, expected exit, why)
            ('  All 300 tests passed.', 0, 0, 'green'),
            ('  2 tests passed.', 0, 0, 'two tests'),
            ('  Test passed.', 0, 0, 'one test'),
            ('  Failed: 0.  Skipped: 0.  Passed: 309.\nOne or more tests were cancelled.', 1, 0,
             'some sets cancelled (#1005)'),
            ('  Failed: 0.  Skipped: 0.  Passed: 0.\nOne or more tests were cancelled.', 1, 1,
             'ALL cancelled (#4800 C-1)'),
            ('  Failed: 2.  Skipped: 0.  Passed: 307.', 1, 1, 'real failure'),
            ('  There were no tests to run.', 0, 1, 'nothing discovered'),
            ('===> Compilation failed', 1, 1, 'rebar3 failed before tests'),
            ('*** log: All 5 tests passed. (noise)\n', 0, 1, 'embedded noise only'),
            ('  All 300 tests passed.', 1, 1, 'rc!=0 without a Failed: line'),
        ]
        for log, rc, want, why in cases:
            with self.subTest(why=why):
                self.assertEqual(gts.cancel_tolerant_verdict(log, rc)[0], want)

    def test_cli(self):
        script = os.path.join(ROOT, 'scripts', 'gateway_test_summary.py')
        with tempfile.TemporaryDirectory(prefix='yuzu_test_') as d:
            log = os.path.join(d, 'eunit.log')
            for text, rc, want in [('  All 3 tests passed.\n', '0', 0),
                                   ('  Failed: 0.  Skipped: 0.  Passed: 0.\n', '1', 1)]:
                with open(log, 'w', encoding='utf-8') as f:
                    f.write(text)
                p = subprocess.run([sys.executable, script, 'cancel-tolerant', rc, log, '--github'],
                                   capture_output=True, text=True)
                self.assertEqual(p.returncode, want, p.stdout + p.stderr)
            p = subprocess.run([sys.executable, script], capture_output=True, text=True)
            self.assertEqual(p.returncode, 2)

    def test_shell_gates_use_this_parser(self):
        # A hand-written regex copy in either gate is how the CH-1 anchoring
        # fix reached only one of three gates; keep them on the shared parser.
        for path in (os.path.join(ROOT, 'scripts', 'test', 'eunit-gate.sh'),
                     os.path.join(ROOT, '.github', 'workflows', 'release.yml')):
            with self.subTest(path=path):
                self.assertRegex(_read(path), r'gateway_test_summary\.py"?\s+cancel-tolerant')


class WrapperWiring(unittest.TestCase):

    def test_ct_dir_points_at_the_suites(self):
        src = _read(WRAPPER)
        m = re.search(r'if suite == "ct":\s*\n(?:\s*#.*\n)*\s*cmd \+= \["--dir", "([^"]+)"\]', src)
        self.assertIsNotNone(m, 'test_gateway.py no longer passes --dir for ct (#4800)')
        ct_dir = os.path.join(ROOT, 'gateway', *m.group(1).split('/'))
        self.assertEqual(os.path.normpath(ct_dir), os.path.normpath(CT_DIR))
        suites = [f for f in os.listdir(CT_DIR) if f.endswith('_SUITE.erl')]
        self.assertTrue(suites, f'no *_SUITE.erl under {CT_DIR}')

    def test_every_exit_goes_through_the_guard(self):
        src = _read(WRAPPER)
        exits = re.findall(r'^\s*sys\.exit\((.*)\)\s*$', src, re.M)
        self.assertTrue(exits)
        for e in exits:
            with self.subTest(exit=e):
                self.assertIn('_require_tests_executed(', e)

    def test_deadline_is_below_meson_timeout(self):
        m = re.search(r'_SUITE_DEADLINE_SECS = \{(.*?)\}', _read(WRAPPER), re.S)
        self.assertIsNotNone(m)
        deadlines = {k: int(v) for k, v in re.findall(r'"(\w+)":\s*(\d+)', m.group(1))}
        meson = _read(MESON)
        for suite in ('eunit', 'ct'):
            with self.subTest(suite=suite):
                t = re.search(r"test\('gateway %s',.*?timeout:\s*(\d+)" % suite, meson, re.S)
                self.assertIsNotNone(t, f"meson test 'gateway {suite}' not found")
                self.assertIn(suite, deadlines)
                # Leave room for the dump + kill + 15s wait in _run_streamed.
                self.assertLessEqual(deadlines[suite] + 30, int(t.group(1)))


if __name__ == '__main__':
    unittest.main()
