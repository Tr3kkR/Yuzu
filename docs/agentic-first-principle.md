# Agentic-First Principle

**Version:** 1.0 | **Date:** 2026-05-01 | **Status:** Architectural rule (proposed)

## What this document is

A four-rule architectural principle. Every operation an authorised human can perform via the dashboard must be performable by an authenticated agentic worker through a documented, discoverable, machine-readable surface. Every signal a human can see must be available to that worker. Every error must be machine-actionable.

This is the canonical reference for the A1–A4 invariants. The audit at `docs/capability-agentic-audit-2026-05.md` references and applies these rules.

## Glossary

The word "agent" is overloaded in Yuzu. To stay precise:

- **Agent daemon** — the C++ binary in `agents/core/` that runs on each managed endpoint and executes plugins.
- **Governance agent** — the `.claude/agents/*.md` review actors run during the `/governance` pipeline.
- **Agentic worker** — an external LLM-driven client (Claude, GPT, in-house) that drives Yuzu through MCP, REST, or the dashboard.

The four invariants below apply to **agentic workers** consuming Yuzu's surfaces.

## A1 — Dashboard parity

Every new `/fragments/*` route ships with either (a) a parallel JSON variant via `Accept: application/json` content negotiation on the same URL, or (b) a sibling REST endpoint in `/api/v1/*` that returns the same data as a structured object.

**Why this matters.** Today most `/fragments/*` routes return only `text/html` for HTMX consumption. An agentic worker reading the dashboard either has to parse HTML (brittle, lossy on dynamic content, no schema) or re-implement the dashboard logic against a separate REST endpoint that may not exist for admin surfaces (user management, enrollment-token administration, settings). Parity removes that asymmetry.

**Scope.** Existing fragments are not retroactively required to comply — backfilling them is tracked separately. New fragment routes are gated by this rule from the date of adoption. The audit lists which admin surfaces are dashboard-only today and earmarks them for the proposed Phase 17 (Agentic Surface Hardening).

**Enforced by.** `consistency-auditor` agent — A1 is added to its trigger list as a post-merge invariant check on any new `/fragments/*` route.

## A2 — Discovery

Every MCP tool, REST route, plugin action, scope kind, RBAC permission, and instruction definition is enumerable through a documented, authenticated discovery endpoint. An agentic worker should be able to learn what is possible from the live server alone, without a side-channel doc fetch.

**Today.** MCP `tools/list` enumerates 23 MCP tools with input schemas. `/api/v1/openapi.json` (`rest_api_v1.cpp:165`) enumerates the REST surface. Both are read-only and partial: there is no introspection for plugin actions, scope kinds, RBAC permission catalog, or live instruction definitions.

**Future.** A `/api/v1/discover/*` family will expose:
- `/api/v1/discover/routes` — REST + dashboard route catalog with method, scope, RBAC requirement
- `/api/v1/discover/plugins` — every plugin loaded across the fleet with action surface and parameter schemas
- `/api/v1/discover/scope-kinds` — every scope DSL kind, syntax, examples
- `/api/v1/discover/permissions` — RBAC permission catalog (securable_type × operation)
- `/api/v1/discover/instructions` — published `InstructionDefinition` set with parameter and result schemas

Each is mirrored as an MCP tool (`discover_routes`, `discover_plugins`, etc.) so the LLM-native flow does not require an out-of-band fetch.

**Enforced by.** `architect` and `consistency-auditor` on any new MCP tool, REST route, plugin action, or scope kind — the change is incomplete until the relevant `/discover/*` is updated.

## A3 — Observability

Every long-running operation emits Server-Sent Events on a documented, authenticated, agent-accessible channel. Events are JSON envelopes (not HTML fragments). Every event carries an `execution_id` and a deterministic step name from a published taxonomy.

**Today.** The dashboard SSE channel (`server.cpp:2200-2228`, route `/events`) emits events designed for HTMX `sse-swap` HTML targets — they drive `<div hx-target>` updates, not machine consumption. The same `event_bus_` underlies them, so a parallel JSON channel can be added without duplicating the bus. The audit also flags that `/events` is unauthenticated today — see audit §Security follow-ups.

**Future.** A new authenticated `/api/v1/events?since=…&filter=execution_id:X|agent_id:Y` channel emits structured JSON envelopes. The `ExecutionEventBus` referenced in `docs/executions-history-ladder.md` is the canonical source. No new bus.

**Enforced by.** `architect` on any change that introduces a new long-running operation — the operation is incomplete without the corresponding event taxonomy and SSE wiring.

## A4 — Error envelope

Every failure response — REST, MCP, gRPC error — includes:

- `code` — machine-readable error code (HTTP status for REST, JSON-RPC code for MCP, gRPC status for gRPC)
- `message` — human-readable summary (one sentence)
- `correlation_id` — server-issued ID that ties the error to the audit log entry
- `retry_after_ms` — nullable; if non-null, the agent should wait at least this long before retrying
- `remediation` — nullable URL or natural-language hint (e.g. `"request the missing permission via POST /api/v1/approvals"`)

Two specialisations:

- On `kPermissionDenied` (-32003 / HTTP 403), the envelope names the missing permission as `securable_type:operation` (e.g. `Tag:Write`).
- On `kApprovalRequired` (-32006 / HTTP 202), the envelope returns `approval_id` and `status_url` so the agent can poll the approval workflow rather than re-issuing the same request.

**Why this matters.** Today errors give a code and message; nothing else. An agentic worker hitting `Permission denied` cannot tell which permission, who can grant it, or whether to retry. A4 closes that loop and makes self-recovery feasible.

**Enforced by.** `security-guardian` and `consistency-auditor` on any change to error-emitting code paths.

## Where these invariants are referenced

- The audit at `docs/capability-agentic-audit-2026-05.md` cites this doc and applies the invariants to current state.
- `CLAUDE.md` routes consistency-auditor to this doc on every PR.
- The proposed Phase 17 in `docs/roadmap.md` (Agentic Surface Hardening) implements the gaps identified by A1–A4.

## Open question — backfill policy

A1–A4 apply forward from adoption. The audit identifies a backlog of existing surfaces that do not satisfy them (most dashboard fragments, most error sites, the existing `/events` SSE). Backfill is tracked as proposed Phase 17 issues 17.1–17.5; this principle doc does not mandate retroactive compliance, but agents reviewing PRs that touch existing non-compliant code should encourage a partial backfill of the touched paths rather than perpetuating the gap.
