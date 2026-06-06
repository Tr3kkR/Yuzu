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

## TAR

Timeline Activity Record. TAR captures ordered endpoint activity and response history so operators and agentic workers can reconstruct what happened during investigation, remediation, and audit workflows.

## Gateway

The Erlang service under `gateway/` that scales agent connectivity and command fanout. It proxies registration and heartbeat traffic upstream to the server, exposes agent-facing gRPC, and provides management forwarding for server-dispatched commands.
