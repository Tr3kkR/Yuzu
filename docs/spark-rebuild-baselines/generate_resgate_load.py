#!/usr/bin/env python3
"""Arm fixed Guardian loads against a running rig via the real REST surface.

Committed 2026-08-18 (F11, #2298; D1 ruling 2026-08-05: port-lite) - previously a
local-only spike, same posture as .uat-seed/guardian/seed-baselines.py. Companion to
resource_sampler.cpp and stage11-resource-gate-runbook.md.

Two independent load profiles, each with its own rule-id prefix so `arm`/`teardown` and
`arm-errored`/`teardown-errored` never collide and can run standalone or together:

  arm / teardown (prefix "resgate-"):
    20 registry + 20 file + 20 service guards, all Known/compliant targets - the
    ORIGINAL resource-gate load (rung-2 legacy-vs-spark A/B, still blocked on the
    flip's --spark-disable; this script is ready, the gate itself is not run here).

  arm-errored / teardown-errored (prefix "resgate-err-"):
    20 registry + 20 file guards (no service profile - see below) whose watched
    targets exist but are unreadable by the agent's service account, so every
    evaluation reads Unknown. This is the flood-measurement load for F11: it drives
    the errored-refresh (F5 6b) and priority-lane-demotion (F5 6c) paths this script's
    original profile never touches (a Known/compliant target never goes Unknown).
    No service variant: per agents/core/src/guardian_state_reader.cpp,
    ERROR_SERVICE_DOES_NOT_EXIST resolves to Known(Stopped), not Unknown - a
    nonexistent service cannot produce the errored path this profile needs, and the
    service lane shares the registry lane's 60s cadence so no coverage is lost by
    omitting it.

    This script does NOT create the deny-ACL state the errored targets need - that is
    an OS-level admin action, deliberately kept out of a script that talks to the REST
    API, not the filesystem/registry. Run the icacls/PowerShell one-liners in
    stage11-resource-gate-runbook.md FIRST, then arm-errored.

    arm-errored also creates + deploys a Baseline containing all 40 errored rules
    (and teardown-errored deletes it). This is not optional decoration: every push
    -- including this script's own full_sync -- funnels through
    guardian_push_fn_'s filter_deployed_members() gate (server.cpp:~17601-17640),
    which keeps only rules that are members of a *deployed* Baseline
    (docs/guardian-baseline-model.md). A rule that exists in the Guard store but
    belongs to no deployed Baseline is silently dropped from every push, no error
    either side -- the 2026-08-18 F11 live run hit exactly this (40 rules created
    and confirmed stored via REST, zero ever reached the agent's reconcile; see
    "Live DGRHP window" / forward action item 4 in f11-flood-measurement-run.md).

All guards in both profiles are enforcement_mode="audit" + remediation.type="alert-only"
- Observe only, matching the .uat-seed/guardian/README-cis-observe.md convention
(CLAUDE.md flags dangerous-enforce paths as a single chokepoint; a resource/flood
measurement has no business anywhere near it). Resource/flood cost comes from ARMING
the watch and evaluating it, not from remediation, so audit mode is the correct posture
for this measurement, not just the safe one.

Registry guards in the original profile watch synthetic HKCU test keys (no real system
state). File guards watch synthetic files under a scratch directory this script
creates. Service guards watch real, already-present Windows services in Observe mode -
read-only status watches, nothing is started/stopped/changed.

Errored-profile registry guards watch HKLM keys (NOT HKCU - the agent runs as a service
account, and an admin-created HKCU key would be missing from the agent's own hive,
which reads as Known-absent, not Unknown; see guardian_state_reader.cpp). Errored-
profile file guards watch files under a deny-ACL directory.

Usage:
    python generate_resgate_load.py arm              # original: create 60 rules + full_sync
    python generate_resgate_load.py teardown          # original: delete 60 rules + full_sync
    python generate_resgate_load.py arm-errored       # errored: create 40 rules + full_sync
    python generate_resgate_load.py teardown-errored  # errored: delete 40 rules + full_sync

Config via env (matches seed-baselines.py):
    YUZU_BASE, YUZU_ADMIN_USER, YUZU_ADMIN_PASS
"""
import html
import http.cookiejar
import json
import os
import re
import sys
import urllib.parse
import urllib.request

BASE = os.environ.get("YUZU_BASE", "http://localhost:8080").rstrip("/")
USER = os.environ.get("YUZU_ADMIN_USER", "admin")
PASS = os.environ.get("YUZU_ADMIN_PASS", "YuzuUatAdmin1!")

RULE_PREFIX = "resgate-"
ERR_RULE_PREFIX = "resgate-err-"
N = 20

# Fixed name so arm-errored/teardown-errored can find the SAME Baseline across
# separate script invocations without persisting its id anywhere (BaselineStore
# enforces unique names, so re-running arm-errored without a teardown in between
# is detected as "already exists" and reused, not duplicated).
ERR_BASELINE_NAME = "resgate-err-baseline"

# Real, near-universally-present Windows services. Observe-only - never
# started/stopped/reconfigured, just watched.
SERVICE_NAMES = [
    "Spooler", "Themes", "AudioSrv", "BITS", "wuauserv", "Schedule",
    "EventLog", "PlugPlay", "Power", "ProfSvc", "Dnscache", "Dhcp",
    "LanmanServer", "LanmanWorkstation", "W32Time", "WinDefend", "wscsvc",
    "CryptSvc", "Winmgmt", "RpcSs",
][:N]


def registry_rule(i):
    rid = f"{RULE_PREFIX}reg-{i:02d}"
    return {
        "rule_id": rid,
        "name": rid,
        "enabled": True,
        "enforcement_mode": "audit",
        "severity": "low",
        "os_target": "windows",
        "scope": "",
        "spark": {
            "type": "registry-change",
            "params": {"hive": "HKCU", "key": f"SOFTWARE\\YuzuResGate\\Key{i:02d}"},
        },
        "assertion": {
            "type": "registry-value-equals",
            "params": {
                "hive": "HKCU",
                "key": f"SOFTWARE\\YuzuResGate\\Key{i:02d}",
                "value_name": "Flag",
                "value_type": "REG_DWORD",
                "expected": "1",
            },
        },
        "remediation": {"type": "alert-only", "params": {}},
    }


def file_rule(i, scratch_dir):
    rid = f"{RULE_PREFIX}file-{i:02d}"
    path = f"{scratch_dir}\\watch-{i:02d}.txt"
    return {
        "rule_id": rid,
        "name": rid,
        "enabled": True,
        "enforcement_mode": "audit",
        "severity": "low",
        "os_target": "windows",
        "scope": "",
        "spark": {"type": "file-change", "params": {"path": path}},
        "assertion": {"type": "file-exists", "params": {"path": path, "expected": "present"}},
        "remediation": {"type": "alert-only", "params": {}},
    }


def service_rule(i):
    rid = f"{RULE_PREFIX}svc-{i:02d}"
    name = SERVICE_NAMES[i - 1]
    return {
        "rule_id": rid,
        "name": rid,
        "enabled": True,
        "enforcement_mode": "audit",
        "severity": "low",
        "os_target": "windows",
        "scope": "",
        "spark": {"type": "service-status-change", "params": {"service_name": name}},
        "assertion": {"type": "service-running", "params": {"service_name": name}},
        "remediation": {"type": "alert-only", "params": {}},
    }


def registry_rule_errored(i, denied_hive_key):
    """Watches an HKLM key that EXISTS but denies read to the agent's account - reads
    Unknown (ERROR_ACCESS_DENIED), never Known-absent. Caller must have already created
    the key + deny ACE per the runbook before arming."""
    rid = f"{ERR_RULE_PREFIX}reg-{i:02d}"
    key = f"{denied_hive_key}\\Key{i:02d}"
    return {
        "rule_id": rid,
        "name": rid,
        "enabled": True,
        "enforcement_mode": "audit",
        "severity": "low",
        "os_target": "windows",
        "scope": "",
        "spark": {"type": "registry-change", "params": {"hive": "HKLM", "key": key}},
        "assertion": {
            "type": "registry-value-equals",
            "params": {
                "hive": "HKLM",
                "key": key,
                "value_name": "Flag",
                "value_type": "REG_DWORD",
                "expected": "1",
            },
        },
        "remediation": {"type": "alert-only", "params": {}},
    }


def file_rule_errored(i, denied_dir):
    """Watches a file that EXISTS but denies read to the agent's account - reads
    Unknown (EACCES/ERROR_ACCESS_DENIED), never Known-absent. Caller must have already
    created the file + deny ACE per the runbook before arming."""
    rid = f"{ERR_RULE_PREFIX}file-{i:02d}"
    path = f"{denied_dir}\\watch-{i:02d}.txt"
    return {
        "rule_id": rid,
        "name": rid,
        "enabled": True,
        "enforcement_mode": "audit",
        "severity": "low",
        "os_target": "windows",
        "scope": "",
        "spark": {"type": "file-change", "params": {"path": path}},
        "assertion": {"type": "file-exists", "params": {"path": path, "expected": "present"}},
        "remediation": {"type": "alert-only", "params": {}},
    }


def make_opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def login(op):
    data = urllib.parse.urlencode({"username": USER, "password": PASS}).encode()
    op.open(BASE + "/login", data=data, timeout=15)


def post_rule(op, rule):
    body = json.dumps(rule).encode("utf-8")
    req = urllib.request.Request(
        BASE + "/api/v1/guaranteed-state/rules",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    return op.open(req, timeout=15).read().decode("utf-8", "replace")


def delete_rule(op, rule_id):
    req = urllib.request.Request(
        BASE + f"/api/v1/guaranteed-state/rules/{rule_id}",
        method="DELETE",
    )
    try:
        op.open(req, timeout=15)
        return True
    except urllib.error.HTTPError as e:
        print(f"[resgate-load] DELETE {rule_id}: HTTP {e.code}", file=sys.stderr)
        return False


def push_full_sync(op):
    req = urllib.request.Request(
        BASE + "/api/v1/guaranteed-state/push",
        data=json.dumps({"full_sync": True}).encode(),
        headers={"Content-Type": "application/json"},
    )
    op.open(req, timeout=15)


# -- Baseline plumbing (arm-errored/teardown-errored only) -------------------
#
# No JSON REST route exists for Baseline create/deploy/delete yet (dashboard
# fragment-only, form-urlencoded HTML responses) - these helpers drive the same
# form-fragment surface .uat-seed/guardian/seed-baselines.py uses for the create
# call, plus deploy/delete/lookup, which that script doesn't need.


def create_baseline_form(op, name, member_names):
    fields = [("name", name), ("description", "F11 flood-measurement errored-load baseline")]
    fields += [("guards", n) for n in member_names]
    body = urllib.parse.urlencode(fields, encoding="utf-8").encode("utf-8")
    req = urllib.request.Request(
        BASE + "/fragments/guardian/baselines",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
    )
    return op.open(req, timeout=15).read().decode("utf-8", "replace")


def list_baselines_html(op):
    req = urllib.request.Request(BASE + "/fragments/guardian/baselines", method="GET")
    return op.open(req, timeout=15).read().decode("utf-8", "replace")


def find_baseline_id(html_text, name):
    # Matches render_baselines_fragment()'s per-card anchor:
    # <a class="baseline-name" href="/guardian/baseline/{ID}" ...>{ESCAPED NAME}</a>
    pattern = re.compile(
        r'href="/guardian/baseline/([A-Za-z0-9._\-]+)"[^>]*>' + re.escape(html.escape(name)) + r"</a>"
    )
    m = pattern.search(html_text)
    return m.group(1) if m else None


def deploy_baseline_form(op, baseline_id):
    req = urllib.request.Request(
        BASE + f"/fragments/guardian/baseline/{baseline_id}/deploy",
        data=b"",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return op.open(req, timeout=15).read().decode("utf-8", "replace")


def delete_baseline_form(op, baseline_id):
    req = urllib.request.Request(
        BASE + f"/fragments/guardian/baseline/{baseline_id}/delete",
        data=b"",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    return op.open(req, timeout=15).read().decode("utf-8", "replace")


def ensure_deployed_baseline_errored(op):
    """Creates (or reuses, if arm-errored ran before without a teardown) the fixed-
    name Baseline covering every resgate-err- rule, and deploys it. Without this,
    the 40 errored rules exist in the Guard store but reach no agent - see the
    module docstring's guardian_push_fn_ note."""
    member_names = [f"{ERR_RULE_PREFIX}reg-{i:02d}" for i in range(1, N + 1)]
    member_names += [f"{ERR_RULE_PREFIX}file-{i:02d}" for i in range(1, N + 1)]
    resp = create_baseline_form(op, ERR_BASELINE_NAME, member_names)
    if "gs-error-banner" in resp and "already exists" not in resp.lower():
        raise RuntimeError(f"baseline create failed: {resp[:300]}")
    baseline_id = find_baseline_id(resp, ERR_BASELINE_NAME)
    if not baseline_id:
        baseline_id = find_baseline_id(list_baselines_html(op), ERR_BASELINE_NAME)
    if not baseline_id:
        raise RuntimeError(f"could not find baseline id for '{ERR_BASELINE_NAME}' after create")
    deploy_baseline_form(op, baseline_id)  # deploy itself fires a fleet-wide full_sync
    return baseline_id


def teardown_deployed_baseline_errored(op):
    """Deletes the errored-load Baseline if present. delete_baseline_action fires
    its own fleet-wide full_sync when the deleted Baseline was deployed, so this
    is the actual agent-side disarm step - do it BEFORE deleting the 40 rule
    definitions themselves."""
    baseline_id = find_baseline_id(list_baselines_html(op), ERR_BASELINE_NAME)
    if not baseline_id:
        print(f"[resgate-load] no '{ERR_BASELINE_NAME}' baseline found, nothing to remove")
        return
    delete_baseline_form(op, baseline_id)
    print(f"[resgate-load] deleted baseline '{ERR_BASELINE_NAME}' ({baseline_id}), fleet reconciled")


def all_rules(scratch_dir):
    rules = [registry_rule(i) for i in range(1, N + 1)]
    rules += [file_rule(i, scratch_dir) for i in range(1, N + 1)]
    rules += [service_rule(i) for i in range(1, N + 1)]
    return rules


def all_rules_errored(denied_dir, denied_hive_key):
    rules = [registry_rule_errored(i, denied_hive_key) for i in range(1, N + 1)]
    rules += [file_rule_errored(i, denied_dir) for i in range(1, N + 1)]
    return rules


def cmd_arm(op, scratch_dir):
    # Pre-create the scratch dir + the 20 watched files so the initial
    # assertion state is "present" (compliant) - quieter dashboard, and
    # ReadDirectoryChangesW needs the parent dir to exist regardless.
    os.makedirs(scratch_dir, exist_ok=True)
    for i in range(1, N + 1):
        open(os.path.join(scratch_dir, f"watch-{i:02d}.txt"), "a", encoding="utf-8").close()

    failed = 0
    for rule in all_rules(scratch_dir):
        try:
            post_rule(op, rule)
        except Exception as e:  # noqa: BLE001
            print(f"[resgate-load] FAIL {rule['rule_id']}: {e}", file=sys.stderr)
            failed += 1
    push_full_sync(op)
    print(f"[resgate-load] armed {3*N - failed}/{3*N} guards, pushed full_sync")
    return 1 if failed else 0


def cmd_teardown(op):
    failed = 0
    for rule in all_rules("C:\\YuzuResGate"):
        if not delete_rule(op, rule["rule_id"]):
            failed += 1
    push_full_sync(op)
    print(f"[resgate-load] deleted {3*N - failed}/{3*N} guards, pushed full_sync "
          f"(scratch dir + registry keys NOT auto-removed - clean up by hand if desired)")
    return 1 if failed else 0


def cmd_arm_errored(op, denied_dir, denied_hive_key):
    # Deliberately does NOT create denied_dir, its files, the HKLM key, or any ACE -
    # that is the runbook's job (an OS-level admin action, not a REST-surface one).
    # Arming against targets the runbook hasn't yet prepared will just read Unknown
    # for the wrong reason (missing, not denied) - verify the deny-ACL setup is done
    # (a manual read as the agent's own account should fail) before arming.
    failed = 0
    for rule in all_rules_errored(denied_dir, denied_hive_key):
        try:
            post_rule(op, rule)
        except Exception as e:  # noqa: BLE001
            print(f"[resgate-load] FAIL {rule['rule_id']}: {e}", file=sys.stderr)
            failed += 1
    push_full_sync(op)
    baseline_id = ensure_deployed_baseline_errored(op)
    print(f"[resgate-load] armed-errored {2*N - failed}/{2*N} guards, deployed baseline "
          f"'{ERR_BASELINE_NAME}' ({baseline_id}), pushed full_sync")
    return 1 if failed else 0


def cmd_teardown_errored(op, denied_dir, denied_hive_key):
    teardown_deployed_baseline_errored(op)
    failed = 0
    for rule in all_rules_errored(denied_dir, denied_hive_key):
        if not delete_rule(op, rule["rule_id"]):
            failed += 1
    push_full_sync(op)
    print(f"[resgate-load] deleted-errored {2*N - failed}/{2*N} guards, pushed full_sync "
          f"(deny-ACL dir/key NOT auto-removed - clean up by hand)")
    return 1 if failed else 0


def main():
    valid = ("arm", "teardown", "arm-errored", "teardown-errored")
    if len(sys.argv) != 2 or sys.argv[1] not in valid:
        print(__doc__)
        return 1
    scratch_dir = os.environ.get("YUZU_RESGATE_SCRATCH_DIR", "C:\\YuzuResGate")
    denied_dir = os.environ.get("YUZU_RESGATE_DENIED_DIR", "C:\\YuzuResGateDenied")
    denied_hive_key = os.environ.get(
        "YUZU_RESGATE_DENIED_HIVE_KEY", "SOFTWARE\\YuzuResGateDenied")
    op = make_opener()
    try:
        login(op)
    except Exception as e:  # noqa: BLE001
        print(f"[resgate-load] ERROR: cannot reach rig at {BASE}: {e}", file=sys.stderr)
        return 1
    if sys.argv[1] == "arm":
        return cmd_arm(op, scratch_dir)
    if sys.argv[1] == "teardown":
        return cmd_teardown(op)
    if sys.argv[1] == "arm-errored":
        return cmd_arm_errored(op, denied_dir, denied_hive_key)
    return cmd_teardown_errored(op, denied_dir, denied_hive_key)


if __name__ == "__main__":
    sys.exit(main())
