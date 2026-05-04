# Yuzu Policy Engine

## Table of Contents

- [Overview](#overview)
- [Policy Fragments](#policy-fragments)
- [Policies](#policies)
- [Compliance Tracking](#compliance-tracking)
- [Fleet Compliance Summary](#fleet-compliance-summary)
- [Cache Invalidation](#cache-invalidation)
- [CEL Expressions](#cel-expressions)
- [REST API Endpoints](#rest-api-endpoints)
- [YAML Schema Reference](#yaml-schema-reference)

---

## Overview

The policy engine provides **Guaranteed State** -- a desired-state enforcement
system where the server declares what state endpoints should be in, and agents
continuously evaluate and remediate drift.

The system is built on two primitives:

1. **PolicyFragment** -- a single check/fix/postCheck pattern that tests one
   condition and optionally remediates it.
2. **Policy** -- a named binding of a fragment to a set of devices via scope
   expressions, triggers, management group bindings, and input parameters.

Policies are defined in YAML using the `yuzu.io/v1alpha1` DSL (the same schema
used for instruction definitions) and are managed through the REST API and the
compliance dashboard.

The implementation is backed by `PolicyStore` (SQLite WAL), which stores
fragments, policies, triggers, group bindings, input parameters, and per-agent
compliance status. A mutex protects the database handle for thread-safe access.

---

## Policy Fragments

A PolicyFragment is the atomic unit of compliance. It contains:

- **Check instruction** -- an instruction definition that evaluates the current
  state. The check compliance expression (CEL) determines pass/fail.
- **Fix instruction** (optional) -- an instruction definition that remediates
  drift when the check fails.
- **Post-check instruction** (optional) -- a follow-up check to verify the fix
  was successful.

### Fragment Structure

Each fragment stores:

| Field | Description |
|---|---|
| `id` | Auto-generated unique identifier |
| `name` | Human-readable fragment name |
| `description` | What this fragment checks and fixes |
| `yaml_source` | Verbatim YAML source (source of truth) |
| `check_instruction` | Instruction definition ID for the check step |
| `check_compliance` | CEL expression evaluated against check results |
| `check_parameters` | JSON parameter bindings for the check instruction |
| `fix_instruction` | Instruction definition ID for the fix step |
| `fix_parameters` | JSON parameter bindings for the fix instruction |
| `post_check_instruction` | Instruction definition ID for the post-check step |
| `post_check_compliance` | CEL expression for post-check evaluation |
| `post_check_parameters` | JSON parameter bindings for post-check |

### Example Fragment YAML

```yaml
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
metadata:
  name: ensure-defender-enabled
  description: Verify Windows Defender real-time protection is active
spec:
  check:
    plugin: security
    action: defender-status
    compliance: "result.realtime_protection == true"
  fix:
    plugin: security
    action: enable-defender
  postCheck:
    plugin: security
    action: defender-status
    compliance: "result.realtime_protection == true"
```

---

## Policies

A Policy binds a fragment to devices, defining when and where compliance
checks run.

### Policy Structure

| Field | Description |
|---|---|
| `id` | Auto-generated unique identifier |
| `name` | Human-readable policy name |
| `description` | What this policy enforces |
| `yaml_source` | Verbatim YAML source (source of truth) |
| `fragment_id` | Reference to the PolicyFragment |
| `scope_expression` | Scope engine expression for device targeting |
| `enabled` | Whether the policy is active (can be toggled) |
| `inputs` | Key-value parameters passed to the fragment's instructions |
| `triggers` | When to evaluate (interval, file_change, event_log, etc.) |
| `management_groups` | Group IDs this policy is scoped to |

### Trigger Configuration

Triggers are stored per-policy with type-specific JSON configuration:

| Trigger Type | Config Example |
|---|---|
| `interval` | `{"interval_seconds": 300}` |
| `file_change` | `{"path": "/etc/hosts"}` |
| `service_status` | `{"service": "sshd"}` |
| `event_log` | `{"log": "Security", "event_id": 4625}` |
| `registry` | `{"hive": "HKLM", "key": "SOFTWARE\\..."}` |
| `startup` | `{}` |

> **Trigger limit:** The agent's trigger engine enforces a configurable maximum trigger count (default: 2000). Triggers beyond this limit are rejected with a warning log message. This prevents runaway policy deployments from exhausting agent resources. The limit can be configured via the agent API.

### Management Group Bindings

Policies can be scoped to specific management groups. When a policy is bound
to a group, only agents that are members of that group (or its descendant
groups) are subject to the policy's compliance checks.

### Example Policy YAML

```yaml
apiVersion: yuzu.io/v1alpha1
kind: Policy
metadata:
  name: baseline-security
  description: Enforce security baseline on production servers
spec:
  fragment: ensure-defender-enabled
  scope: "tag:environment = 'production'"
  triggers:
    - type: interval
      interval: 300
  managementGroups:
    - eu-production-servers
  inputs:
    severity_threshold: "high"
```

---

## Compliance Tracking

The policy engine tracks compliance status per agent per policy. Each
`PolicyAgentStatus` record contains:

| Field | Description |
|---|---|
| `policy_id` | The policy being tracked |
| `agent_id` | The agent being evaluated |
| `status` | Current compliance state |
| `last_check_at` | Unix timestamp of last check evaluation |
| `last_fix_at` | Unix timestamp of last fix execution |
| `check_result` | JSON output from the last check instruction |

### Status Values

| Status | Meaning |
|---|---|
| `compliant` | Check passed -- the endpoint is in the desired state |
| `non_compliant` | Check failed -- the endpoint is not in the desired state |
| `unknown` | Not yet evaluated or status invalidated |
| `fixing` | Fix instruction is currently running |
| `error` | Check or fix instruction failed to execute |

---

## Fleet Compliance Summary

The `FleetCompliance` aggregate provides a fleet-wide view:

- **compliance_pct** -- percentage of (policy, agent) pairs that are compliant
- **total_checks** -- total number of tracked (policy, agent) pairs
- Breakdown by status: compliant, non_compliant, unknown, fixing, error

Per-policy summaries (`ComplianceSummary`) provide the same breakdown scoped
to a single policy.

The compliance dashboard (accessible at the Policies page in the web UI)
displays:

- Fleet compliance percentage with a color-coded bar
- Count of active policies
- Per-policy compliance percentage with drill-down to agent-level detail
- Per-agent status with last check time and check result

---

## Cache Invalidation

When a policy's check instruction or compliance expression changes, agents
need to re-evaluate. The policy engine supports:

- **Per-policy invalidation** -- Reset all agent statuses to `pending` for a
  specific policy, forcing re-evaluation on the next trigger.
- **Fleet-wide invalidation** -- Reset all agent statuses across all policies.
  Use sparingly, primarily after bulk configuration changes or server upgrades.

Both operations are available via the REST API.

---

## CEL Expressions

Compliance expressions use [Common Expression Language (CEL)](https://github.com/google/cel-spec),
a non-Turing-complete expression language designed for security policies. CEL
provides strong typing, compile-time checks, and no side effects.

Compliance expressions are stored in `check_compliance` and
`post_check_compliance` fields. They are evaluated against the check
instruction's result data to determine pass/fail.

Example expressions:

```
result.realtime_protection == true
result.value == "expected" && result.type == "REG_SZ"
result.signature_age < duration('24h')
```

---

## REST API Endpoints

All policy engine endpoints are under `/api/` (legacy prefix). They require
the `Policy:Read` or `Policy:Write` RBAC permission.

### Policy Fragments

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/policy-fragments` | List all fragments. Query params: `name`, `limit`. |
| `POST` | `/api/policy-fragments` | Create a fragment from YAML. Body must be a complete YAML document or a JSON envelope `{"yaml_source": "<full YAML>"}` — see worked example below. |
| `DELETE` | `/api/policy-fragments/{id}` | Delete a fragment by ID. |

#### Worked example — `POST /api/policy-fragments`

The `kind` is a **YAML field** inside the body, not an HTTP query
parameter or top-level JSON key. The server checks `kind: PolicyFragment`
on the parsed YAML; sending `?kind=PolicyFragment` in the URL or
`{"kind":"PolicyFragment"}` outside `yaml_source` is silently ignored. If
the YAML is missing the `kind:` line you'll get an HTTP 400 with the full
expected schema in the error body.

**JSON envelope (recommended for programmatic callers):**

```bash
curl -X POST http://localhost:8080/api/policy-fragments \
  -H "Content-Type: application/json" \
  -b cookie -d '{
    "yaml_source": "apiVersion: yuzu.io/v1alpha1\nkind: PolicyFragment\nmetadata:\n  name: ssh-disabled\nspec:\n  check:\n    plugin: services\n    action: status\n    parameters: { name: sshd }\n    compliance: \"result.state != \\\"running\\\"\"\n"
  }'
```

**Raw YAML body (alternative — content-type other than `application/json`):**

```bash
curl -X POST http://localhost:8080/api/policy-fragments \
  -H "Content-Type: application/yaml" \
  -b cookie --data-binary @- <<'EOF'
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
metadata:
  name: ssh-disabled
spec:
  check:
    plugin: services
    action: status
    parameters: { name: sshd }
    compliance: 'result.state != "running"'
EOF
```

Both forms produce a 201 with `{"id": "<fragment-id>", "status": "created"}`.

### Policies

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/policies` | List all policies. Query params: `name`, `fragment_id`, `enabled_only`, `limit`. |
| `POST` | `/api/policies` | Create a policy from YAML. Body: same shape as `POST /api/policy-fragments` — full YAML in `yaml_source`, with `kind: Policy`. |
| `GET` | `/api/policies/{id}` | Get policy detail including compliance summary. |
| `DELETE` | `/api/policies/{id}` | Delete a policy and its compliance data. |
| `POST` | `/api/policies/{id}/enable` | Enable a disabled policy. |
| `POST` | `/api/policies/{id}/disable` | Disable an active policy. |
| `POST` | `/api/policies/{id}/invalidate` | Invalidate agent-side cache for this policy. |
| `POST` | `/api/policies/invalidate-all` | Invalidate cache for all policies (fleet-wide). |

### Compliance

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/compliance` | Fleet compliance summary (total, compliant, non_compliant, etc.). |
| `GET` | `/api/compliance/{policy_id}` | Per-policy compliance detail with per-agent statuses. |

### HTMX Fragments

| Route | Description |
|---|---|
| `/fragments/compliance/summary` | Compliance dashboard summary fragment |
| `/fragments/compliance/{policy_id}` | Per-policy compliance detail fragment |

---

## YAML Schema Reference

Both policy kinds use `apiVersion: yuzu.io/v1alpha1`. The full DSL
specification is in `docs/yaml-dsl-spec.md`.

### PolicyFragment

```yaml
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
metadata:
  name: <unique-name>
  description: <human-readable description>
  labels:
    category: <security|compliance|performance|custom>
spec:
  check:
    plugin: <plugin-name>
    action: <action-name>
    compliance: <CEL expression>
    parameters:             # optional
      <key>: <value>
  fix:                      # optional -- omit for check-only rules
    plugin: <plugin-name>
    action: <action-name>
    parameters:             # optional
      <key>: <value>
  postCheck:                # optional -- verify fix was successful
    plugin: <plugin-name>
    action: <action-name>
    compliance: <CEL expression>
    parameters:             # optional
      <key>: <value>
```

### Policy

```yaml
apiVersion: yuzu.io/v1alpha1
kind: Policy
metadata:
  name: <unique-name>
  description: <human-readable description>
spec:
  fragment: <fragment-name-or-id>
  scope: <scope-expression>
  triggers:
    - type: <interval|file_change|service_status|event_log|registry|startup>
      interval: <seconds>     # for type: interval
      path: <file-path>       # for type: file_change
      service: <service-name> # for type: service_status
  managementGroups:
    - <group-name-or-id>
  inputs:
    <key>: <value>
```
