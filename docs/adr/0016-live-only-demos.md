# ADR-0016: Yuzu Demos Run Live — No Fabricated-Data Demo Mode

**Date:** 2026-06-29
**Status:** Accepted
**Component:** MCP agentic layer / Demo environment
**Authors:** Nathan (with Claude)

## Context

PR #1653 ("MCP agentic demo layer") shipped a `prepare_demo_scenario` MCP tool
with a `mode=curated` path that returned **synthetic, hard-coded findings**
labelled `DEMO DATA` (e.g. "18% of Windows laptops show pending reboot risk")
for a CEO-style demo. The intent was a deterministic, always-impressive pitch
that doesn't depend on what a live fleet happens to be doing.

This collides head-on with Yuzu's stated cornerstone. `CONTEXT.md` repeats it in
several forms — "a metric nobody reported is absent, **never a fabricated
zero**"; "**Yuzu never fabricates** it"; "trustworthy, low-false-positive
results are **the product's cornerstone**." Curated mode was the one place in
the codebase that deliberately manufactured a finding with no observation behind
it. It also violated the **agentic-first principle** (`docs/agentic-first-principle.md`,
A1): a demo-only fabrication surface has no operator equivalent.

A live demo fleet already exists — the Cedar & Vale stack
(`docs/demo-environment.md`) stands up a real server, gateway, and agents. So
"run live" was not a missing capability; curated mode was faking a story the
real (idle, homogeneous) fleet could not yet tell.

## Decision

**Yuzu demonstrates against a live fleet and never fabricates findings,
including in demos.** Concretely:

1. **Retire `prepare_demo_scenario` and the `mode=curated` "DEMO DATA" path.**
   The tool is removed entirely (not kept as a live-only variant) — even its
   live branch was redundant with `get_incident_playbook` and the golden-prompt
   pack.
2. **The demo entry point is a prompt, not a tool.** The
   `ceo_demo_agentic_endpoint_management` prompt drives the live flow over the
   four surviving read/advisory tools (`get_fleet_posture_fast`,
   `classify_operational_question`, `get_incident_playbook`,
   `summarize_working_set`).
3. **Realism is staged in the environment, not the server.** A demo's
   interesting conditions are *real* conditions on real (staged) endpoints —
   built as **immutable "golden demo images"** with the condition baked in at
   boot (a real pending reboot, a really-degraded link, a really-crashing
   service), rebuilt/restored per run to preserve the demo-environment stability
   contract. Distinguishing fabricating the *finding* (banned) from constructing
   a real *environment* that genuinely exhibits the condition (the honest path).
4. **Remediation is observed and fixed live — through the full gates.** The fix
   runs through the same `execute_instruction` / `execute_bundle` → real agent
   path a customer uses, and the agentic worker executes **only after explicit
   operator approval** via the normal tier/RBAC + approval workflow. There is
   **no demo bypass** (a demo-only write path would violate agentic-first the
   same way a fabricated read does).

"Take the risk," as the decision was framed, means accepting that a live run may
not behave exactly like a canned script — **not** relaxing any safety gate.

## Considered Options

- **Keep curated mode (rejected).** Deterministic and flashy, but fabricates
  findings — directly against the "never fabricate" cornerstone and the
  product's trust pitch. A competitor can fake a slick dashboard; Yuzu's
  differentiator is showing the *real* fleet.
- **Keep `prepare_demo_scenario` as live-only (rejected).** Its live branch was a
  hardcoded tool sequence + an agent count, redundant with `get_incident_playbook`
  and the golden prompts, and it remained a demo-only tool with no operator
  equivalent (A1/A2 anti-pattern).
- **Stage only Linux-observable conditions on the current container fleet first
  (deferred).** Achievable immediately but a thinner story; chosen instead to
  pursue a genuinely cross-platform fleet (real Windows/macOS/workload endpoints)
  so the enterprise narrative is observed for real. Tracked as a follow-up
  workstream.

## Consequences

- **The four live/advisory tools stay** and keep their PR #1653 hardening
  (posture cache race fix, `summarize_working_set` group-scoping, classifier
  advisory framing, exact playbook matching, length caps). Only the
  curated-specific work (the `mode` enum validation, the curated fleet-size
  scope, the demo-mode injection normalisation) is removed with the tool.
- **The demo's realism becomes a real engineering workstream**: per-platform
  immutable golden images that boot with a staged condition, enrolled via the
  agent-bundle, rebuilt per run. This is tracked as a follow-up (touches
  `deploy/`, `scripts/start-demo.sh`, image provisioning, and a runner/lab
  decision — macOS reproducibility is the known-hard corner).
- **A live demo can fail or look unpolished in front of an audience.** That risk
  is accepted and mitigated by the ephemeral/immutable demo fleet (a bad live
  fix costs a `start-demo.sh` re-run, not a production box).
- **Connector-gap honesty is unchanged**: enterprise scenarios Yuzu can't see
  end-to-end (OpenShift internals, DB waits, Teams telemetry) are presented as
  endpoint evidence + an explicit external-connector requirement, never as a
  fabricated internal finding.
