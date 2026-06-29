# Agentic MCP Demo Runbook

This runbook is for demonstrating Yuzu through MCP to an agentic worker or an executive audience. It covers the v1 endpoint-evidence layer only; it does not add native OpenShift, KVM/libvirt, database, SaaS, registry, or APM connectors.

## Principle — live, never canned (ADR-0016)

Yuzu's cornerstone is that it **never fabricates data**. That rule holds in demos: there is **no curated / "DEMO DATA" mode**. A Yuzu demo runs **live against a real fleet**. The realism that a scripted demo would fake is instead made *real* — we construct a real environment that genuinely exhibits a condition, then observe it live and fix it live.

**"Take the risk"** means accepting that a live run may not behave exactly like a canned script would — not relaxing any safety gate.

## How realism is staged

The demo's interesting conditions are **real conditions on real (staged) endpoints**, not strings in the server:

- The Cedar & Vale stack (`docs/demo-environment.md`) brings up a real server + gateway + fleet.
- The fleet includes **immutable "golden demo images"** — per-platform endpoint images (Windows, macOS, workload hosts) with the staged condition **baked in at boot**: a real pending-reboot marker, a security-client pinned to the "bad" version, a real flapping service, a real netem-degraded NIC. The conditions are genuinely observable; they are deterministic because they're baked, not improvised. Images are rebuilt/restored per run so the stack "comes up identically every time."
- Endpoints enrol via the agent-bundle (all three triplets) pointed at the demo gateway.

*(The cross-platform golden-image fleet is a tracked follow-up workstream — see the demo-environment docs and the linked issue.)*

## Recommended flow

The presenter fires the `ceo_demo_agentic_endpoint_management` prompt (no arguments); the agentic worker then drives the **real tools** against the staged condition:

1. Read `yuzu://about` and `yuzu://capabilities`.
2. `get_fleet_posture_fast` — real, cached fleet posture.
3. `classify_operational_question` — classify the operator's incident question (advisory only; not a security gate).
4. `get_incident_playbook` — the matching scenario's workflow, first tool, and connector gaps.
5. `summarize_working_set` — bound the evidence into a model-ready narrative before presenting.
6. **Remediate live** — propose the fix and execute it via `execute_instruction` / `execute_bundle`, **only after explicit operator approval** through the normal tier/RBAC + approval path.

## Safety contract

The demo runs through the **real** safety machinery — it is not a bypass.

- **Remediation is fully gated.** Patching, rebooting, quarantine, certificate revocation, service restart, package change, and security-client remediation require explicit approval and the correct MCP tier. The agentic worker executes a fix **only after a human approves** it; there is no demo-only write path. Watching the guardrails run *is* part of the pitch.
- **Connector gaps are never hidden.** Questions about cluster operators, pods, routes, database waits/locks/sessions, libvirt VM internals, Teams/Zoom tenant telemetry, or registry/build-cache internals are answered as Yuzu endpoint evidence **plus an explicit external-connector requirement** — never as a fabricated internal finding.

## Golden Prompt Pack

The built-in `enterprise-it-v1` pack is exposed at `yuzu://golden-prompts/enterprise-it-v1` (a prompt-evaluation fixture set, distinct from demo output). It covers OpenShift, KVM/libvirt, Chisel/Ubuntu containers, Docker buildx, Node, Spring Cloud Gateway/Java, Postgres/Oracle, Teams/Zoom, Windows/macOS endpoint operations, and security-client incidents.

Pass criteria: the model chooses `classify_operational_question` first, stays within real endpoint evidence, labels connector gaps explicitly, never presents canned findings, and remediates only after explicit approval through the correct MCP tier.
