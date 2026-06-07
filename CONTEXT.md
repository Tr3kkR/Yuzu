# Yuzu Context

Yuzu is an agentic enterprise endpoint management platform. It provides one control plane where humans and agentic workers can query, command, scan, patch, and enforce policy compliance across Windows, Linux, and macOS fleets.

## Agent daemon

The C++ endpoint process under `agents/core/` that runs on a managed device, maintains server or gateway connectivity, executes plugin actions, reports results, and enforces local policy.

## Governance agent

A review role used during the governance pipeline. In Claude these roles live under `.claude/agents/`; in Codex they are compact role prompts in `.codex/skills/governance/SKILL.md`.

## Agentic worker

An external LLM-driven client that operates Yuzu through MCP, REST, or the dashboard. Agentic workers need stable discovery, consistent error envelopes, auditable actions, and operator-equivalent workflows.

## Instruction

A typed unit of endpoint work. Instructions are defined as YAML-backed `InstructionDefinition` content, grouped into instruction sets and product packs, dispatched through the command protocol, and persisted with audit and response data.

## Product pack

A packaged set of instruction content that represents a coherent operational capability. Product packs are build-time embedded from `content/packs/*.yaml` and seed the server's instruction store on first boot.

## Scope

The device target expression for an instruction, policy, query, or workflow. Scopes compose filters such as tags, OS, management groups, and prior result sets; they are part of the authorization and audit boundary.

## Guardian

The Guaranteed State policy enforcement system. Guardian evaluates desired-state policy fragments, triggers checks or remediation, and can route sensitive actions through approval or quarantine flows.

## Guard

A single Guaranteed-State rule: a trigger (Spark), a desired-state check (Assertion), and an optional remediation. A Guard has its own enabled/disabled state, an Observe-or-Enforce mode, and optional Prerequisites. A Guard is a building block — on its own it is a definition only and is never deployed; it reaches devices only as a member of a Baseline.

## Baseline

A named, deployable collection of one or more Guards, targeted at devices via an **assignment**: a set of *included* management groups minus a set of *excluded* management groups (exclusion wins — a device in both an included and an excluded group is not targeted). The Baseline is the only deployable unit in Guardian — **individual Guards are never deployed on their own** (the same shape as a Jamf Configuration Profile, an Intune baseline, or a GPO). Deploying a Baseline applies its enabled member Guards to the assigned devices, subject to each Guard's Prerequisites.

## Assignment

A Baseline's device targeting: a set of *included* management groups minus a set of *excluded* management groups, where **exclusion wins** (a device in both an included and an excluded group is not targeted). Targeting is at whole-Baseline granularity — the same shape as a Jamf Configuration Profile's Scope (Targets − Exclusions) or an Intune assignment. A management group may be static (explicit members) or dynamic (criteria-defined, the equivalent of a Jamf Smart Group). Distinct from a Guard's **Prerequisites**, which gate applicability one level finer, per-Guard.

## Prerequisites

A Guard's technical applicability condition — a Scope expression over device facts (e.g. OS version, form factor, installed software) that must hold for the Guard to apply on a given device. Prerequisites are distinct from a Baseline's management-group targeting: a Guard applies on a device when the device is in the Baseline's management groups **and** the device satisfies the Guard's Prerequisites.

## Mode (Observe / Enforce)

A Guard's response posture. **Observe** detects and alerts on drift without writing back (the user-facing term; it replaces the earlier "Watch", and the still-older "audit" — the stored/wire value remains `audit`). **Enforce** additionally remediates — writing the expected state back, governed by the Guard's resilience policy. Mode is fixed when the Guard is authored; a different posture is a different Guard.

## Deploy

Applying Guardian policy to devices. Deploying a Baseline **converges every assigned device to its complete desired guard set** — the per-device union of the enabled member Guards of all deployed Baselines whose assignment includes that device, each gated by the device's Prerequisites. Convergence is to a device's *total* policy (as in Puppet/DSC/GPO), not to one Baseline's fragment; so removing a Guard from a Baseline and re-deploying actually removes it from any device no other deployed Baseline still delivers it to.

## TAR

Timeline Activity Record. TAR captures ordered endpoint activity and response history so operators and agentic workers can reconstruct what happened during investigation, remediation, and audit workflows.

## Gateway

The Erlang service under `gateway/` that scales agent connectivity and command fanout. It proxies registration and heartbeat traffic upstream to the server, exposes agent-facing gRPC, and provides management forwarding for server-dispatched commands.
