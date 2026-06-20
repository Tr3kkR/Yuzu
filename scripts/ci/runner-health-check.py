#!/usr/bin/env python3
"""runner-health-check.py — query GitHub /actions/runners and report health.

Two consumers (do not duplicate the logic):

1. .github/workflows/runner-inventory-sentinel.yml
   Uses --mode sentinel (default). Compares actual to .github/runner-inventory.json,
   prints drift, writes drift_count + drift_report to $GITHUB_OUTPUT, exits
   non-zero on any drift. This is the "loud failure" path that opens issues.

2. .github/workflows/ci.yml — preflight job (PR-7 of CI overhaul plan).
   Uses --mode preflight. Same query, but reports per-runner-name health to
   $GITHUB_OUTPUT as <name>_healthy=true|false (slugified) and exits 0
   regardless. Downstream jobs gate on these outputs with explicit `==
   'true'` checks (fail-closed: an absent or false value skips the job).
   Also emits `linux_pool_healthy` — true iff >=1 runner eligible for the
   [self-hosted, Linux, X64] job pool is online (see LINUX_POOL_LABELS). The
   proto-compat + linux jobs gate on the pool rather than a single named runner,
   so any free pool member (yuzu-bigtam-* or the Shulgi fallback) keeps them
   running, while a wholly-offline pool still skips them fast.

The fall-closed contract is intentional: a degraded sentinel must NOT
silently accept "I don't know" as healthy. Always check `== 'true'`,
never `!= 'false'`.

PAT requirement: /repos/.../actions/runners requires admin scope, which
the default GITHUB_TOKEN cannot grant. Set RUNNER_INVENTORY_TOKEN as a
fine-grained PAT with Administration:read and pass it as GH_TOKEN.
Without it, the script prints actionable setup instructions and:
  - mode=sentinel: exits 1 (loud failure)
  - mode=preflight: emits all_healthy=false, exits 0 (fail-closed skip)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Any


INVENTORY_PATH = ".github/runner-inventory.json"

# The self-hosted Linux job pool. ci.yml's proto-compat + linux jobs use
# runs-on: [self-hosted, Linux, X64], so any declared runner whose labels are a
# superset of this set is eligible to run them. In preflight mode the script
# emits `linux_pool_healthy=true` iff >=1 such runner is online+labelled
# (fail-closed: zero online -> the Linux jobs skip fast, exactly as the old
# single-named gate did when that one runner was down). This includes Shulgi
# (yuzu-wsl2-linux) as a fallback during the BigTam cutover; Shulgi drops out of
# the pool automatically when it is later removed from the inventory, leaving the
# yuzu-bigtam-* runners as the pool. Per-runner `<slug>_healthy` outputs are still
# emitted unchanged (the sentinel and any pinned-runner gates rely on them).
LINUX_POOL_LABELS = frozenset({"self-hosted", "Linux", "X64"})

# The Big Tam Linux pool. The ci.yml `linux` compile job pins
# runs-on: [self-hosted, Linux, X64, yuzu-bigtam-linux] because its toolchain
# (GCC 15 / Clang 21) exists only on Big Tam's Ubuntu 26.04 — Shulgi (24.04)
# cannot build it. preflight emits `bigtam_pool_healthy=true` iff >=1 such
# runner is online, so the pinned job skips fast (fail-closed) instead of
# queueing forever against an offline Big Tam. The compiler-agnostic
# proto-compat job stays on the broader linux_pool gate.
BIGTAM_POOL_LABELS = frozenset({"self-hosted", "Linux", "X64", "yuzu-bigtam-linux"})


def linux_pool_members(expected: dict[str, Any]) -> list[str]:
    """Declared runners eligible for the [self-hosted, Linux, X64] job pool."""
    return [
        name for name, exp in expected.items()
        if LINUX_POOL_LABELS.issubset(set(exp["labels"]))
    ]


def bigtam_pool_members(expected: dict[str, Any]) -> list[str]:
    """Declared runners eligible for the Big Tam (yuzu-bigtam-linux) job pool."""
    return [
        name for name, exp in expected.items()
        if BIGTAM_POOL_LABELS.issubset(set(exp["labels"]))
    ]


def slug(name: str) -> str:
    """Convert a runner name to a GitHub-Actions-output-safe slug.

    e.g. "yuzu-wsl2-linux" -> "yuzu_wsl2_linux"
    The leading char must be a letter (GHA constraint).
    """
    s = re.sub(r"[^a-zA-Z0-9]+", "_", name).strip("_")
    if not s:
        return "runner"
    if not s[0].isalpha():
        s = "r_" + s
    return s


def write_output(key: str, value: str) -> None:
    """Append key=value to $GITHUB_OUTPUT (no-op outside Actions)."""
    out = os.environ.get("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a", encoding="utf-8") as f:
        # Multi-line values use the heredoc form. For single-line
        # values the simple form is fine.
        if "\n" in value:
            f.write(f"{key}<<EOF\n{value}\nEOF\n")
        else:
            f.write(f"{key}={value}\n")


def query_runners() -> dict[str, Any] | None:
    """Return parsed /actions/runners payload, or None on auth failure."""
    result = subprocess.run(
        ["gh", "api", "/repos/Tr3kkR/Yuzu/actions/runners"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        if any(s in stderr for s in ("403", "Resource not accessible", "Must have admin")):
            print("::error::Runner health check needs a PAT.")
            print()
            print("The default GITHUB_TOKEN cannot list /actions/runners — that endpoint")
            print("requires admin access to the repository, which is not grantable via")
            print("workflow permissions (no `administration` key at workflow scope).")
            print()
            print("To enable, create a PAT and store it as a repo secret:")
            print("  1. github.com → Settings → Developer settings → Personal access tokens")
            print("     → Fine-grained tokens → Generate new token")
            print("  2. Repository access = Tr3kkR/Yuzu only")
            print("  3. Permissions: 'Administration' = Read-only")
            print("  4. gh secret set RUNNER_INVENTORY_TOKEN --body <token>")
            print()
            print("Raw error from gh api:")
            print(stderr)
            return None
        print("::error::Unexpected error querying /actions/runners")
        print(stderr)
        return None
    return json.loads(result.stdout)


def is_healthy(actual: dict[str, Any] | None, expected_labels: list[str]) -> bool:
    """A runner is healthy iff registered, online, and all expected labels present."""
    if not actual:
        return False
    if actual["status"] != "online":
        return False
    return set(expected_labels).issubset(set(actual["labels"]))


def is_fork_pr() -> bool:
    """True iff this run is a pull_request from a fork (no secrets available).

    GHA strips repo secrets on fork PRs, so RUNNER_INVENTORY_TOKEN resolves
    empty and the /actions/runners query 403s on the GITHUB_TOKEN fallback.
    The fork PR cannot mutate runner state either way, so the inventory
    check is moot — matrix jobs will surface real runner unavailability via
    normal queue timeout. See issue #818 for the full root cause.

    Detection requires BOTH GITHUB_REPOSITORY and GITHUB_HEAD_REPOSITORY to
    be set and differ; if HEAD is empty/missing we fall through to the
    normal fail-closed code path rather than guessing.
    """
    if os.environ.get("GITHUB_EVENT_NAME") != "pull_request":
        return False
    base = os.environ.get("GITHUB_REPOSITORY", "")
    head = os.environ.get("GITHUB_HEAD_REPOSITORY", "")
    return bool(base and head and base != head)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--mode",
        choices=("sentinel", "preflight"),
        default="sentinel",
        help="sentinel: loud failure on drift (issue-opening). "
             "preflight: per-runner health booleans to GITHUB_OUTPUT, exit 0.",
    )
    args = parser.parse_args()

    with open(INVENTORY_PATH, encoding="utf-8") as f:
        inventory = json.load(f)
    expected = {r["name"]: r for r in inventory["expected_runners"]}
    strict = inventory.get("strict_unknown_runners", True)

    # Fork PR short-circuit (preflight only). Sentinel mode never runs on
    # pull_request, so its fail-closed contract is unaffected.
    if args.mode == "preflight" and is_fork_pr():
        print("::notice::Fork PR detected — skipping runner inventory check")
        print("(fork PRs have no access to RUNNER_INVENTORY_TOKEN; runner state")
        print(" cannot be changed by a fork PR; matrix jobs will surface real")
        print(" runner unavailability via normal queue timeout.)")
        for name in expected:
            write_output(f"{slug(name)}_healthy", "true")
        write_output("linux_pool_healthy", "true")
        write_output("bigtam_pool_healthy", "true")
        write_output("all_healthy", "true")
        return 0

    payload = query_runners()
    if payload is None:
        if args.mode == "preflight":
            # Fail closed — every gated job sees healthy=false and skips.
            for name in expected:
                write_output(f"{slug(name)}_healthy", "false")
            write_output("linux_pool_healthy", "false")
            write_output("bigtam_pool_healthy", "false")
            write_output("all_healthy", "false")
            return 0
        return 1

    actual = {
        r["name"]: {
            "name": r["name"],
            "labels": sorted(label_obj["name"] for label_obj in r["labels"]),
            "status": r["status"],
            "busy": r["busy"],
        }
        for r in payload["runners"]
    }

    print("=== Expected (.github/runner-inventory.json) ===")
    print(json.dumps(list(expected.values()), indent=2))
    print()
    print("=== Actual (GitHub /actions/runners) ===")
    print(json.dumps(list(actual.values()), indent=2))
    print()

    drift: list[str] = []
    healthy_map: dict[str, bool] = {}

    for name, exp in expected.items():
        act = actual.get(name)
        ok = is_healthy(act, exp["labels"])
        healthy_map[name] = ok
        if act is None:
            drift.append(f"MISSING: expected runner '{name}' not registered with GitHub")
            continue
        if act["status"] != "online":
            drift.append(f"OFFLINE: runner '{name}' reports status '{act['status']}'")
        missing_labels = set(exp["labels"]) - set(act["labels"])
        if missing_labels:
            drift.append(
                f"MISSING_LABEL: runner '{name}' missing expected labels {sorted(missing_labels)} "
                f"(actual: {sorted(act['labels'])})"
            )

    if strict:
        for name in actual:
            if name not in expected:
                drift.append(
                    f"UNKNOWN: unexpected runner '{name}' is registered "
                    f"but not declared in {INVENTORY_PATH} — either deregister it "
                    f"or add it to the inventory in a PR"
                )

    if args.mode == "preflight":
        # Emit one boolean per declared runner. Downstream jobs use
        # `if: needs.preflight.outputs.<slug>_healthy == 'true'`.
        all_healthy = True
        for name in expected:
            v = "true" if healthy_map.get(name, False) else "false"
            write_output(f"{slug(name)}_healthy", v)
            if v != "true":
                all_healthy = False
        # Pool gate: the [self-hosted, Linux, X64] job pool is healthy iff >=1
        # eligible runner is online (fail-closed). proto-compat + linux gate on
        # this instead of a single named runner.
        pool = linux_pool_members(expected)
        pool_ok = any(healthy_map.get(n, False) for n in pool)
        write_output("linux_pool_healthy", "true" if pool_ok else "false")
        # Big Tam sub-pool gate for the gcc-15/clang-21 compile job (26.04-only).
        bigtam_pool = bigtam_pool_members(expected)
        bigtam_ok = any(healthy_map.get(n, False) for n in bigtam_pool)
        write_output("bigtam_pool_healthy", "true" if bigtam_ok else "false")
        write_output("all_healthy", "true" if all_healthy else "false")
        if drift:
            print("=== HEALTH ISSUES (preflight mode — non-fatal) ===")
            for d in drift:
                print(f"  - {d}")
        else:
            print("=== ALL RUNNERS HEALTHY ===")
        return 0

    # sentinel mode: loud failure on drift, write report to $GITHUB_OUTPUT
    if drift:
        print("=== DRIFT DETECTED ===")
        for d in drift:
            print(f"  - {d}")
        write_output("drift_count", str(len(drift)))
        write_output("drift_report", "\n".join(f"- {d}" for d in drift))
        return 1

    print("=== RUNNER INVENTORY OK ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
