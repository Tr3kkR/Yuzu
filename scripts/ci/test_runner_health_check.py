#!/usr/bin/env python3
"""Regression tests for runner-health-check.py.

Run directly; no runner access or GitHub credentials are used.
"""

from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("runner-health-check.py")
ROOT = SCRIPT.parents[2]
SPEC = importlib.util.spec_from_file_location("runner_health_check", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner_health = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner_health
SPEC.loader.exec_module(runner_health)


def runner(name: str, labels: list[str], status: str = "online") -> dict[str, object]:
    return {
        "name": name,
        "status": status,
        "busy": False,
        "labels": [{"name": label} for label in labels],
    }


class QueryRunnersTests(unittest.TestCase):
    def query(self, *, returncode: int = 0, stdout: str = "", stderr: str = ""):
        completed = subprocess.CompletedProcess([], returncode, stdout, stderr)
        with mock.patch.object(runner_health.subprocess, "run", return_value=completed):
            with redirect_stdout(io.StringIO()):
                return runner_health.query_runners()

    def test_auth_failure_is_distinct_from_api_failure(self) -> None:
        auth = self.query(returncode=1, stderr="HTTP 403: Resource not accessible")
        api = self.query(returncode=1, stderr="dial tcp: network unreachable")

        self.assertEqual(auth.state, runner_health.QueryState.AUTH_ERROR)
        self.assertEqual(api.state, runner_health.QueryState.API_ERROR)

    def test_rate_limit_is_distinct_from_authentication_failure(self) -> None:
        result = self.query(returncode=1, stderr="HTTP 403: API rate limit exceeded")
        self.assertEqual(result.state, runner_health.QueryState.RATE_LIMIT)
        self.assertIn("rate limit", result.report.lower())

    def test_transient_api_failure_retries_three_times(self) -> None:
        payload = {"runners": [runner("linux-0", ["self-hosted", "Linux", "X64"])]}
        responses = [
            subprocess.CompletedProcess([], 1, "", "network unreachable"),
            subprocess.CompletedProcess([], 1, "", "temporary gateway error"),
            subprocess.CompletedProcess([], 0, json.dumps(payload), ""),
        ]
        with (
            mock.patch.object(runner_health.subprocess, "run", side_effect=responses) as run,
            mock.patch.object(runner_health.time, "sleep") as sleep,
        ):
            result = runner_health.query_runners()

        self.assertEqual(result.state, runner_health.QueryState.OK)
        self.assertEqual(run.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])

    def test_invalid_json_is_malformed_response(self) -> None:
        result = self.query(stdout="not-json")
        self.assertEqual(result.state, runner_health.QueryState.MALFORMED_RESPONSE)

    def test_transport_timeout_is_api_error(self) -> None:
        timeout = subprocess.TimeoutExpired(["gh", "api"], 30)
        with mock.patch.object(runner_health.subprocess, "run", side_effect=timeout):
            result = runner_health.query_runners()
        self.assertEqual(result.state, runner_health.QueryState.API_ERROR)
        self.assertIn("timed out", result.report)

    def test_missing_gh_executable_is_api_error(self) -> None:
        with mock.patch.object(
            runner_health.subprocess,
            "run",
            side_effect=FileNotFoundError("gh not found"),
        ):
            result = runner_health.query_runners()
        self.assertEqual(result.state, runner_health.QueryState.API_ERROR)
        self.assertIn("could not start", result.report)

    def test_missing_runner_schema_is_malformed_response(self) -> None:
        result = self.query(stdout=json.dumps({"total_count": 1}))
        self.assertEqual(result.state, runner_health.QueryState.MALFORMED_RESPONSE)

    def test_valid_response_is_ok(self) -> None:
        payload = {"runners": [runner("linux-0", ["self-hosted", "Linux", "X64"])]}
        result = self.query(stdout=json.dumps(payload))
        self.assertEqual(result.state, runner_health.QueryState.OK)
        self.assertEqual(result.payload, payload)

    def test_invalid_field_types_and_duplicate_names_are_rejected(self) -> None:
        malformed = {"runners": [runner("linux-0", []), runner("linux-0", [])]}
        duplicate = self.query(stdout=json.dumps(malformed))
        self.assertEqual(duplicate.state, runner_health.QueryState.MALFORMED_RESPONSE)
        malformed["runners"][0]["busy"] = "false"
        malformed["runners"].pop()
        wrong_type = self.query(stdout=json.dumps(malformed))
        self.assertEqual(wrong_type.state, runner_health.QueryState.MALFORMED_RESPONSE)


class MainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        root = Path(self.tempdir.name)
        self.inventory = root / "inventory.json"
        self.output = root / "github-output"
        self.expected = [
            {
                "name": "linux-0",
                "labels": ["self-hosted", "Linux", "X64", "yuzu-bigtam-linux"],
            },
            {
                "name": "windows-0",
                "labels": ["self-hosted", "Windows", "X64", "yuzu-weetam-windows"],
            },
        ]
        self.inventory.write_text(
            json.dumps({"strict_unknown_runners": True, "expected_runners": self.expected}),
            encoding="utf-8",
        )

    def run_main(self, result, *args: str) -> tuple[int, str]:
        self.output.write_text("", encoding="utf-8")
        env = {"GITHUB_OUTPUT": str(self.output)}
        with (
            mock.patch.object(runner_health, "INVENTORY_PATH", str(self.inventory)),
            mock.patch.object(runner_health, "query_runners", return_value=result),
            mock.patch.dict(os.environ, env, clear=True),
            redirect_stdout(io.StringIO()),
        ):
            code = runner_health.main(list(args))
        return code, self.output.read_text(encoding="utf-8")

    def test_control_failure_is_red_and_emits_typed_false_outputs(self) -> None:
        result = runner_health.QueryResult(
            runner_health.QueryState.AUTH_ERROR,
            report="token rejected",
        )
        code, output = self.run_main(result, "--mode", "preflight", "--require-pool", "bigtam")

        self.assertEqual(code, 1)
        self.assertIn("bigtam_pool_healthy=false\n", output)
        self.assertIn("control_state=auth_error\n", output)
        self.assertIn("failure_kind=runner_control_error\n", output)
        self.assertIn("failure_report=token rejected\n", output)

    def test_unavailable_required_pool_is_red(self) -> None:
        payload = {
            "runners": [
                runner("linux-0", self.expected[0]["labels"], status="offline"),
                runner("windows-0", self.expected[1]["labels"]),
            ]
        }
        result = runner_health.QueryResult(runner_health.QueryState.OK, payload=payload)
        code, output = self.run_main(
            result, "--mode", "preflight", "--require-pool", "bigtam"
        )

        self.assertEqual(code, 1)
        self.assertIn("failure_kind=required_pool_unavailable\n", output)
        self.assertIn("bigtam_pool_healthy=false\n", output)

    def test_automatic_fork_preflight_is_red_and_never_queries(self) -> None:
        with (
            mock.patch.object(runner_health, "INVENTORY_PATH", str(self.inventory)),
            mock.patch.object(runner_health, "query_runners") as query,
            mock.patch.dict(
                os.environ,
                {
                    "GITHUB_OUTPUT": str(self.output),
                    "GITHUB_EVENT_NAME": "pull_request",
                    "GITHUB_REPOSITORY": "Tr3kkR/Yuzu",
                    "GITHUB_HEAD_REPOSITORY": "contributor/Yuzu",
                },
                clear=True,
            ),
            redirect_stdout(io.StringIO()),
        ):
            code = runner_health.main(["--mode", "preflight"])

        query.assert_not_called()
        self.assertEqual(code, 1)
        output = self.output.read_text(encoding="utf-8")
        self.assertIn("control_state=auth_error\n", output)
        self.assertIn("bigtam_pool_healthy=false\n", output)
        self.assertIn("weetam_pool_healthy=false\n", output)

    def test_healthy_required_pools_pass(self) -> None:
        payload = {
            "runners": [
                runner("linux-0", self.expected[0]["labels"]),
                runner("windows-0", self.expected[1]["labels"]),
            ]
        }
        result = runner_health.QueryResult(runner_health.QueryState.OK, payload=payload)
        code, output = self.run_main(
            result,
            "--mode", "preflight",
            "--require-pool", "bigtam",
            "--require-pool", "weetam",
        )

        self.assertEqual(code, 0)
        self.assertIn("bigtam_pool_healthy=true\n", output)
        self.assertIn("weetam_pool_healthy=true\n", output)
        self.assertIn("control_state=ok\n", output)

    def test_sentinel_drift_emits_issue_ready_report(self) -> None:
        payload = {
            "runners": [
                runner("linux-0", self.expected[0]["labels"], status="offline"),
                runner("windows-0", self.expected[1]["labels"]),
            ]
        }
        result = runner_health.QueryResult(runner_health.QueryState.OK, payload=payload)
        code, output = self.run_main(result, "--mode", "sentinel")

        self.assertEqual(code, 1)
        self.assertIn("failure_kind=inventory_drift\n", output)
        self.assertIn("failure_count=1\n", output)
        self.assertIn("OFFLINE", output)

    def test_malformed_inventory_is_red_with_typed_report(self) -> None:
        self.inventory.write_text('{"expected_runners": "not-a-list"}', encoding="utf-8")

        code, output = self.run_main(
            runner_health.QueryResult(runner_health.QueryState.OK, payload={"runners": []}),
            "--mode",
            "sentinel",
        )

        self.assertEqual(code, 1)
        self.assertIn("control_state=config_error\n", output)
        self.assertIn("failure_kind=runner_control_error\n", output)
        self.assertIn("failure_report=Runner inventory cannot be trusted:", output)

    def test_non_boolean_strict_mode_is_a_config_error(self) -> None:
        self.inventory.write_text(
            json.dumps({"strict_unknown_runners": [], "expected_runners": self.expected}),
            encoding="utf-8",
        )

        code, output = self.run_main(
            runner_health.QueryResult(runner_health.QueryState.OK, payload={"runners": []}),
            "--mode",
            "sentinel",
        )

        self.assertEqual(code, 1)
        self.assertIn("control_state=config_error\n", output)

    def test_shulgi_does_not_satisfy_the_weetam_pool(self) -> None:
        self.expected[1]["labels"] = ["self-hosted", "Windows", "X64"]
        self.inventory.write_text(
            json.dumps({"strict_unknown_runners": True, "expected_runners": self.expected}),
            encoding="utf-8",
        )
        payload = {
            "runners": [
                runner("linux-0", self.expected[0]["labels"]),
                runner("windows-0", self.expected[1]["labels"]),
            ]
        }

        code, output = self.run_main(
            runner_health.QueryResult(runner_health.QueryState.OK, payload=payload),
            "--mode",
            "preflight",
            "--require-pool",
            "weetam",
        )

        self.assertEqual(code, 1)
        self.assertIn("weetam_pool_healthy=false\n", output)


class WorkflowWiringTests(unittest.TestCase):
    @staticmethod
    def job(workflow: str, name: str) -> str:
        text = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
        match = re.search(
            rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            text,
        )
        if not match:
            raise AssertionError(f"job {name!r} not found in {workflow}")
        return match.group(1)

    def test_weetam_gate_matches_every_windows_consumer(self) -> None:
        for workflow, job_name in (("ci.yml", "windows"), ("nightly.yml", "windows-asan")):
            with self.subTest(workflow=workflow, job=job_name):
                job = self.job(workflow, job_name)
                self.assertRegex(
                    job,
                    r"(?m)^    runs-on: \[self-hosted, Windows, X64, yuzu-weetam-windows\]$",
                )
                self.assertIn("needs.preflight.outputs.weetam_pool_healthy == 'true'", job)

        for workflow in ("ci.yml", "nightly.yml"):
            with self.subTest(workflow=workflow):
                preflight = self.job(workflow, "preflight")
                self.assertIn("--require-pool weetam", preflight)
                self.assertIn("weetam_pool_healthy", preflight)

    def test_preflight_context_names_are_unique(self) -> None:
        expected = {
            "ci.yml": 'name: "Preflight (runner health)"',
            "nightly.yml": 'name: "Nightly preflight (runner health)"',
            "sanitizer-tests.yml": 'name: "Sanitizer preflight (runner health)"',
        }
        for workflow, name_line in expected.items():
            with self.subTest(workflow=workflow):
                self.assertIn(name_line, self.job(workflow, "preflight"))

    def test_sentinel_opens_an_issue_for_untyped_failures(self) -> None:
        sentinel = (ROOT / ".github" / "workflows" / "runner-inventory-sentinel.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "if: ${{ always() && steps.check.outcome == 'failure' }}",
            sentinel,
        )
        self.assertIn("runner_control_crash", sentinel)
        self.assertIn("failed before it could emit typed evidence", sentinel)


if __name__ == "__main__":
    unittest.main()
