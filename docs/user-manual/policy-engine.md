# Yuzu Policy Engine

> **Status: PLANNED -- NOT YET IMPLEMENTED**
>
> The policy engine is Phase 5 of the Yuzu roadmap. This document describes
> the planned design based on the architecture blueprint. All features
> described here are subject to change during implementation.

## Table of Contents

- [Overview](#overview)
- [Policy Rules and Fragments (Issue 5.1)](#policy-rules-and-fragments-issue-51) -- PLANNED
- [Policy Assignment and Deployment (Issue 5.2)](#policy-assignment-and-deployment-issue-52) -- PLANNED
- [Compliance Dashboard (Issue 5.3)](#compliance-dashboard-issue-53) -- PLANNED
- [Policy Cache Invalidation (Issue 5.4)](#policy-cache-invalidation-issue-54) -- PLANNED
- [CEL Adoption (Issue 5.5)](#cel-adoption-issue-55) -- PLANNED
- [YAML Schema Reference](#yaml-schema-reference) -- PLANNED

---

## Overview

> **NOT YET IMPLEMENTED**

The policy engine provides **Guaranteed State** -- a desired-state enforcement
system where the server declares what state endpoints should be in, and agents
continuously evaluate and remediate drift.

The system is built on two primitives:

1. **PolicyFragment** -- a single check/fix pair that tests one condition and
   optionally remediates it.
2. **Policy** -- a named collection of fragments assigned to a set of devices
   via management groups.

Policies are defined in YAML using the `yuzu.io/v1alpha1` DSL (the same schema
used for instruction definitions) and are evaluated agent-side on configurable
triggers.

---

## Policy Rules and Fragments (Issue 5.1)

> **NOT YET IMPLEMENTED**

### PolicyFragment

A PolicyFragment is the atomic unit of compliance. It contains:

- **Check instruction** -- an instruction definition that evaluates the current
  state and returns a pass/fail result.
- **Fix instruction** (optional) -- an instruction definition that remediates
  drift when the check fails.
- **Trigger** -- when to evaluate (interval, file change, service status,
  event log entry, registry change, or startup).

```yaml
# PLANNED YAML schema -- not yet accepted by the server
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
metadata:
  name: ensure-defender-enabled
  description: Verify Windows Defender real-time protection is active
spec:
  check:
    plugin: security
    action: defender-status
    expect:
      field: realtime_protection
      operator: equals
      value: true
  fix:
    plugin: security
    action: enable-defender
  trigger:
    type: interval
    interval: 300   # seconds
```

### Rule Types

Each fragment operates as one of two rule types:

| Type | Behavior |
|---|---|
| **Check** | Evaluates condition only. Reports pass/fail but does not remediate. |
| **Fix** | Evaluates condition, and if failed, executes the fix instruction and re-checks. |

### Status Codes

Each rule evaluation produces a status code:

| Status | Meaning |
|---|---|
| `Received` | Rule delivered to agent, evaluation not yet started |
| `CheckErrored` | Check instruction failed to execute (plugin error, timeout) |
| `CheckFailed` | Check instruction executed successfully but the condition is not met |
| `CheckPassed` | Check instruction executed successfully and the condition is met |
| `FixErrored` | Fix instruction failed to execute |
| `FixPassed` | Fix instruction executed and subsequent re-check passed |
| `FixFailed` | Fix instruction executed but subsequent re-check still failed |

### Agent-Side Evaluation

Policy evaluation happens on the agent, not the server. The agent:

1. Receives the policy definition (fragments + triggers) from the server.
2. Registers triggers with the local trigger engine.
3. On each trigger firing, executes the check instruction.
4. If the check fails and a fix is defined, executes the fix and re-checks.
5. Reports the result status back to the server.

This design ensures policies are enforced even when the agent is temporarily
disconnected from the server.

---

## Policy Assignment and Deployment (Issue 5.2)

> **NOT YET IMPLEMENTED**

### Assignment Model

Policies are assigned to **management groups**, not individual agents. When
an agent is a member of a management group (statically or dynamically), it
receives all policies assigned to that group and its ancestor groups.

```
Management Group Hierarchy        Policies
================================  ================
All Devices                       baseline-security
  +-- EU Production               eu-compliance
  |     +-- EU Web Servers        web-hardening
  +-- US Staging                  (none)
```

In this example, an agent in "EU Web Servers" receives three policies:
`baseline-security`, `eu-compliance`, and `web-hardening`.

### Pending Changes

Policy changes are not applied immediately. Instead they enter a **pending
changes** queue:

1. Operator modifies a policy or its group assignment.
2. The change appears in the pending changes list with a diff view.
3. An authorized user reviews and approves the deployment.
4. The server pushes the updated policy set to affected agents.

This prevents accidental fleet-wide changes and provides an audit trail.

### Deployment Push

Once approved, the server:

1. Computes the effective policy set for each affected agent.
2. Sends the updated policy definition over the Subscribe bidi stream.
3. Waits for agent acknowledgment.
4. Records the deployment event in the audit log.

---

## Compliance Dashboard (Issue 5.3)

> **NOT YET IMPLEMENTED**

The compliance dashboard provides fleet-wide visibility into policy
enforcement status.

### Planned Views

**Per-device compliance status:**
- Shows each device with its assigned policies and current evaluation status.
- Color-coded: green (all passing), amber (fix in progress), red (check failed
  or fix failed), grey (not yet evaluated).

**Fleet posture summary:**
- Aggregate compliance percentage across all devices.
- Breakdown by policy, management group, OS, and location tag.

**Rule evaluation history:**
- Timeline view of check/fix results for a specific device and policy fragment.
- Useful for diagnosing intermittent compliance failures.

**Effectiveness metrics:**
- Auto-fix success rate per fragment.
- Mean time to remediation.
- Most frequently failing rules.
- Devices that consistently fail despite fix attempts.

### Data Model

Compliance data is stored in the response store (SQLite) with typed columns
matching the instruction definition result schema. This enables:

- Filtering and aggregation via the REST API.
- Export to external analytics (ClickHouse, Splunk) via the existing
  data export pipeline.
- Prometheus metrics for compliance percentages (gauge per policy).

---

## Policy Cache Invalidation (Issue 5.4)

> **NOT YET IMPLEMENTED**

### Problem

Agents cache their assigned policy set locally to enable offline evaluation.
When a policy is modified server-side, agents must be notified to refresh
their cache.

### Planned Approach

- **Version vector** -- each policy has a monotonically increasing version
  number. The agent reports its cached versions during heartbeat.
- **Delta push** -- if the server detects a version mismatch, it pushes only
  the changed fragments over the Subscribe stream.
- **Full reset** -- an operator can force a full policy re-evaluation on a
  device via:
  ```
  POST /api/v1/policies/{agent_id}/reset
  ```
  This clears the agent's policy cache and forces a complete re-download.
- **Heartbeat protocol extension** -- the `HeartbeatRequest` message will
  include a `policy_version_map` field mapping policy IDs to cached versions.

---

## CEL Adoption (Issue 5.5)

> **NOT YET IMPLEMENTED**

### Motivation

The current scope engine uses a custom expression language for device
targeting. Policy evaluation conditions (the `expect` block in
PolicyFragment) would benefit from a more expressive, typed language.

### Planned Approach

[Common Expression Language (CEL)](https://github.com/google/cel-spec) is a
non-Turing-complete expression language designed for security policies. It
provides:

- Strong typing with compile-time checks.
- A well-defined evaluation model (no side effects).
- Native support in the Google ecosystem (used by Kubernetes, Envoy, Firebase).
- C++ reference implementation (`cel-cpp`).

### Usage in Yuzu

CEL expressions would replace the `expect` block in PolicyFragment:

```yaml
# Current (planned) -- simple field comparison
spec:
  check:
    plugin: security
    action: defender-status
    expect:
      field: realtime_protection
      operator: equals
      value: true

# Future (with CEL) -- arbitrary typed expressions
spec:
  check:
    plugin: security
    action: defender-status
    expect_cel: "result.realtime_protection == true && result.signature_age < duration('24h')"
```

CEL would also be evaluated agent-side, with the `cel-cpp` library embedded
in the agent binary.

---

## YAML Schema Reference

> **NOT YET IMPLEMENTED**

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
    parameters:             # optional
      <key>: <value>
    expect:
      field: <result-field>
      operator: <equals|not_equals|greater_than|less_than|contains|matches>
      value: <expected-value>
  fix:                      # optional -- omit for check-only rules
    plugin: <plugin-name>
    action: <action-name>
    parameters:             # optional
      <key>: <value>
  trigger:
    type: <interval|file_change|service_status|event_log|registry|startup>
    interval: <seconds>     # for type: interval
    path: <file-path>       # for type: file_change
    service: <service-name> # for type: service_status
```

### Policy

```yaml
apiVersion: yuzu.io/v1alpha1
kind: Policy
metadata:
  name: <unique-name>
  description: <human-readable description>
spec:
  fragments:
    - <fragment-name-1>
    - <fragment-name-2>
  assignment:
    management_groups:
      - <group-name-or-id>
  deployment:
    require_approval: <true|false>
    rollout_strategy: <all_at_once|phased>
    phased_percentage: <1-100>    # for phased rollout
```
