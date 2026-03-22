#!/usr/bin/env python3
"""Functional tests for gen_proto.py protoc version validation.

Creates mock protoc executables that return controlled version strings,
then verifies gen_proto.py accepts valid versions and rejects invalid ones.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GEN_PROTO = os.path.join(SCRIPT_DIR, '..', 'proto', 'gen_proto.py')


class TestProtocVersionCheck(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='yuzu_proto_test_')
        self.outdir = os.path.join(self.tmpdir, 'out')
        os.makedirs(self.outdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_mock_protoc(self, version_output, version_rc=0, compile_rc=0):
        """Create a mock protoc script that returns a controlled version string."""
        mock_path = os.path.join(self.tmpdir, 'mock_protoc')
        with open(mock_path, 'w') as f:
            f.write('#!/usr/bin/env python3\n')
            f.write('import sys\n')
            f.write('if "--version" in sys.argv:\n')
            f.write(f'    print({version_output!r})\n')
            f.write(f'    sys.exit({version_rc})\n')
            f.write(f'sys.exit({compile_rc})\n')
        os.chmod(mock_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
        return mock_path

    def _run_gen_proto(self, mock_protoc_path):
        """Run gen_proto.py with mock protoc and no proto files.

        With no protos in argv[5:], the compilation loop is skipped.
        This isolates the version check logic.
        """
        return subprocess.run(
            [sys.executable, GEN_PROTO,
             self.outdir,          # outdir
             mock_protoc_path,     # protoc
             '/dev/null',          # grpc plugin (unused — no protos)
             self.tmpdir],         # proto_root  (unused — no protos)
            capture_output=True, text=True
        )

    # ── Acceptance tests: valid versions should pass ─────────────────────

    def test_accepts_protobuf_27(self):
        """protoc 27.x (current vcpkg) should be accepted."""
        mock = self._make_mock_protoc('libprotoc 27.3')
        result = self._run_gen_proto(mock)
        self.assertEqual(result.returncode, 0)
        self.assertIn('gen_proto.py: using libprotoc 27.3', result.stdout)

    def test_accepts_protobuf_5(self):
        """protoc 5.x should be accepted."""
        mock = self._make_mock_protoc('libprotoc 5.28.3')
        result = self._run_gen_proto(mock)
        self.assertEqual(result.returncode, 0)
        self.assertIn('using libprotoc 5.28.3', result.stdout)

    def test_accepts_protobuf_4(self):
        """protoc 4.x should be accepted."""
        mock = self._make_mock_protoc('libprotoc 4.25.1')
        result = self._run_gen_proto(mock)
        self.assertEqual(result.returncode, 0)

    def test_accepts_protobuf_3(self):
        """protoc 3.x should be accepted."""
        mock = self._make_mock_protoc('libprotoc 3.21.12')
        result = self._run_gen_proto(mock)
        self.assertEqual(result.returncode, 0)

    # ── Rejection tests: old/broken versions should fail ─────────────────

    def test_rejects_protobuf_2(self):
        """protoc 2.x is too old — must be rejected."""
        mock = self._make_mock_protoc('libprotoc 2.6.1')
        result = self._run_gen_proto(mock)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('too old', result.stderr)

    def test_rejects_protobuf_1(self):
        """protoc 1.x is ancient — must be rejected."""
        mock = self._make_mock_protoc('libprotoc 1.0.0')
        result = self._run_gen_proto(mock)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('too old', result.stderr)

    def test_rejects_version_command_failure(self):
        """If protoc --version returns non-zero, script should abort."""
        mock = self._make_mock_protoc('', version_rc=1)
        result = self._run_gen_proto(mock)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('protoc --version failed', result.stderr)

    # ── Edge cases ───────────────────────────────────────────────────────

    def test_accepts_unexpected_format_gracefully(self):
        """If version string has no recognizable version number, don't crash.

        The script prints the string but the regex won't match,
        so no major version check fires — it passes through.
        """
        mock = self._make_mock_protoc('protoc unknown-build')
        result = self._run_gen_proto(mock)
        self.assertEqual(result.returncode, 0)
        self.assertIn('using protoc unknown-build', result.stdout)

    def test_version_printed_to_stdout(self):
        """Verify the version banner is printed (build log visibility)."""
        mock = self._make_mock_protoc('libprotoc 27.3')
        result = self._run_gen_proto(mock)
        self.assertIn('gen_proto.py: using libprotoc 27.3', result.stdout)


if __name__ == '__main__':
    unittest.main()
