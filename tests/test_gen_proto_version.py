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
        if sys.platform == 'win32':
            # Windows: create a .bat wrapper that calls a .py script
            py_path = os.path.join(self.tmpdir, 'mock_protoc.py')
            with open(py_path, 'w') as f:
                f.write('import sys\n')
                f.write('if "--version" in sys.argv:\n')
                f.write(f'    print({version_output!r})\n')
                f.write(f'    sys.exit({version_rc})\n')
                f.write(f'sys.exit({compile_rc})\n')
            bat_path = os.path.join(self.tmpdir, 'mock_protoc.bat')
            with open(bat_path, 'w') as f:
                f.write(f'@"{sys.executable}" "{py_path}" %*\n')
            return bat_path
        else:
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
             os.devnull,           # grpc plugin (unused — no protos)
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


class TestIncludeFlatten(unittest.TestCase):
    """Flatten-include regex must only strip yuzu/ prefixes.

    The moment a Yuzu proto imports `google/protobuf/<something>.proto`
    (e.g. Timestamp), protoc emits `#include "google/protobuf/*.pb.h"` in
    the generated .pb.cc/.pb.h. Those includes must resolve via the
    vcpkg protobuf include root, so they cannot be flattened — a broader
    regex would rewrite them to `#include "<something>.pb.h"` and break
    the build on every target. Regression guard for this.
    """

    def setUp(self):
        # Re-derive the exact flatten logic from gen_proto.py by running it
        # against a synthetic input — avoids re-implementing the regex here.
        self.tmpdir = tempfile.mkdtemp(prefix='yuzu_flatten_test_')
        self.outdir = os.path.join(self.tmpdir, 'out')
        os.makedirs(self.outdir)
        self.sample_pb = os.path.join(self.outdir, 'sample.pb.cc')
        with open(self.sample_pb, 'w') as f:
            f.write(
                '// Generated sample\n'
                '#include "yuzu/common/v1/common.pb.h"\n'
                '#include "yuzu/agent/v1/agent.pb.h"\n'
                '#include "yuzu/guardian/v1/guaranteed_state.pb.h"\n'
                '#include "google/protobuf/timestamp.pb.h"\n'
                '#include "google/protobuf/descriptor.pb.h"\n'
            )

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run_flatten(self):
        """Invoke gen_proto.py's flatten pass by running it end-to-end.

        With no protos in argv[5:], the protoc-compilation loop is skipped
        but the post-processing flatten loop still runs over whatever
        *.pb.* files exist under outdir — so the pre-seeded sample.pb.cc
        gets rewritten.
        """
        # Use a mock protoc that returns a valid version (compilation loop
        # is skipped because argv[5:] is empty).
        mock = os.path.join(self.tmpdir, 'mock_protoc')
        if sys.platform == 'win32':
            mock = os.path.join(self.tmpdir, 'mock_protoc.bat')
            with open(mock, 'w') as f:
                f.write('@echo libprotoc 27.3\n@exit /B 0\n')
        else:
            with open(mock, 'w') as f:
                f.write('#!/usr/bin/env python3\n')
                f.write('import sys\n')
                f.write('if "--version" in sys.argv:\n')
                f.write('    print("libprotoc 27.3")\n')
                f.write('    sys.exit(0)\n')
                f.write('sys.exit(0)\n')
            os.chmod(mock, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)

        result = subprocess.run(
            [sys.executable, GEN_PROTO, self.outdir, mock,
             os.devnull, self.tmpdir],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        with open(self.sample_pb, 'r') as f:
            return f.read()

    def test_yuzu_includes_are_flattened(self):
        out = self._run_flatten()
        self.assertIn('#include "common.pb.h"', out)
        self.assertIn('#include "agent.pb.h"', out)
        self.assertIn('#include "guaranteed_state.pb.h"', out)

    def test_google_protobuf_includes_are_preserved(self):
        # Regression guard for the ci-B1 bug caught in PR 1 governance:
        # the prior regex was `(?:[^"/]+/)*` which stripped ALL prefixes
        # including `google/protobuf/`. That would cause every C++ target
        # to fail to compile guaranteed_state.pb.cc because
        # `#include "timestamp.pb.h"` doesn't resolve anywhere.
        out = self._run_flatten()
        self.assertIn('#include "google/protobuf/timestamp.pb.h"', out)
        self.assertIn('#include "google/protobuf/descriptor.pb.h"', out)


if __name__ == '__main__':
    unittest.main()
