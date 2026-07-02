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

**Shipped (roadmap Issue 17.1).** The `GET /api/v1/discover/*` family exists, gated `Infrastructure:Read` (`/discover/instructions` gates `InstructionDefinition:Read` instead — it matches the existing definitions RBAC surface more closely than the generic `Infrastructure` type):
- `GET /api/v1/discover/permissions` — RBAC securable_type × operation catalog + the full role → allowed-operations grid (`RbacStore::list_securable_types`/`list_operations`/`list_roles`/`get_role_permissions`, a cheap pass-through).
- `GET /api/v1/discover/instructions` — published (`enabled_only=true`) `InstructionDefinition` subset `{id, name, plugin, action, description, parameter_schema, platforms, approval_mode}`; `parameter_schema` is a nested JSON Schema object when the stored value parses, else `null` (unreachable through the normal authoring path today — `InstructionStore::create_definition` defaults an empty schema to `"{}"` — but kept as a defensive branch for a future direct-write path).
- `GET /api/v1/discover/routes` — subsets the SAME hand-maintained OpenAPI document `GET /api/v1/openapi.json` serves (via the newly-exposed `yuzu::server::openapi_spec_json()`, `server/core/src/openapi_spec_access.hpp`), so the two can never disagree. Carries `"source":"openapi"` plus an explicit caveat: it is NOT generated from the live route table and can under-report an undocumented route. Per-route RBAC requirement is embedded in each entry's free-text `description` (no structured field yet).
- `GET /api/v1/discover/scope-kinds` — fully static (answers even when every store is down, like `/guaranteed-state/schemas`): the two GROUND kinds (`__all__`, `group:<name>`) that short-circuit per-device evaluation, every ATTRIBUTE kind `AgentRegistry::evaluate_scope`'s resolver answers (from `yuzu::server::detail::scope_kind_catalog()`, colocated with the resolver in `agent_registry.hpp`/`.cpp` — a DRIFT CONTRACT comment on the resolver lambda requires any new branch to get a matching catalog entry), the `CompOp` comparison operators (via `yuzu::scope::operator_token`, an exhaustive `switch` with no `default` case so a missed enum value is a `-Wswitch` build-log signal), and the `EXISTS`/`LEN(...)`/`STARTSWITH(...)` extended forms.
- `GET /api/v1/discover/plugins` — wraps `AgentRegistry::help_json()` (deduplicated plugin/action metadata observed across currently-connected agents) with a discovery envelope. NOT a build-time manifest of every plugin that could ever load. The response explicitly documents that per-action PARAMETER schemas are unavailable here (agents report bare action names only) — pair with `/discover/instructions` for the subset of actions that also have a published `InstructionDefinition`.

All five follow the `/guaranteed-state/schemas` precedent's caching contract: a content-derived `ETag` + `Cache-Control: public, max-age=300` + `If-None-Match` → `304`.

Each is mirrored as a **read-only MCP tool** (`discover_permissions`, `discover_instructions`, `discover_routes`, `discover_scope_kinds`, `discover_plugins`, appended at the end of `kTools[]` in `mcp_server.cpp`) sharing the SAME builder functions as their REST siblings — REST and MCP cannot drift from each other by construction. Implementation: `server/core/src/discover_routes.{hpp,cpp}` (module named `DiscoverRoutes`/`discover_routes.*`, singular, to avoid colliding with the pre-existing unrelated `DiscoveryRoutes`/`discovery_routes.*` — directory sync / patch / deployment / network-discovery routes at `/api/directory/*`, `/api/patches/*`, `/api/deployments/*`, `/api/discovery/*`).

**Enforced by.** `architect` and `consistency-auditor` on any new MCP tool, REST route, plugin action, or scope kind — the change is incomplete until the relevant `/discover/*` is updated. This is now an enforceable claim: the five endpoints exist, so a reviewer can actually check a new surface landed in the right catalog instead of only citing this doc's intent.

## A3 — Observability

Every long-running operation emits Server-Sent Events on a documented, authenticated, agent-accessible channel. Events are JSON envelopes (not HTML fragments). Every event carries an `execution_id` and a deterministic step name from a published taxonomy.

**Today.** The dashboard SSE channel (`server.cpp:2200-2228`, route `/events`) emits events designed for HTMX `sse-swap` HTML targets — they drive `<div hx-target>` updates, not machine consumption. The same `event_bus_` underlies them, so a parallel JSON channel can be added without duplicating the bus. The audit also flags that `/events` is unauthenticated today — see audit §Security follow-ups.

**Future.** A new authenticated `/api/v1/events?since=…&filter=execution_id:X|agent_id:Y` channel emits structured JSON envelopes. The `ExecutionEventBus` referenced in `docs/executions-history-ladder.md` is the canonical source. No new bus.

**Status (2026-05-18 — sprint W5.1).** Skeleton shipped at `GET /api/v1/events?execution_id=<id>` (`rest_api_v1.cpp`). Requires `Execution:Read`, replays via `?since=<event_id>` or `Last-Event-ID`, audits `api.v1.events.subscribe` with a correlation id, surfaces partial audit-persist failure via `Sec-Audit-Failed: true` (CC6.6 contract from PR #883), and is enumerated under `/api/v1/openapi.json`. The shape contract for the JSON envelope and the A4 error envelope is testable in isolation via `server/core/src/rest_a4_envelope.hpp` so future MCP / discovery surfaces can reuse it. Multi-execution / `?filter=execution_id:X|agent_id:Y` syntax is W5.2.

**Enforced by.** `architect` on any change that introduces a new long-running operation — the operation is incomplete without the corresponding event taxonomy and SSE wiring.

## A4 — Error envelope

Every failure response — REST, MCP, gRPC error — includes:

- `code` — machine-readable error code (HTTP status for REST, JSON-RPC code for MCP, gRPC status for gRPC)
- `message` — human-readable summary (one sentence)
- `correlation_id` — server-issued ID that ties the error to the audit log entry
- `retry_after_ms` — nullable; if non-null, the agent should wait at least this long before retrying
- `remediation` — optional/nullable URL or natural-language hint (e.g. `"request the missing permission via POST /api/v1/approvals"`). When there is no hint, a surface MAY either emit `"remediation": null` (the MCP envelopes) or omit the key entirely (the REST envelope — absence carries the same "no recovery hint" meaning); both are conformant for this nullable field.

Two specialisations:

- On `kPermissionDenied` (-32003 / HTTP 403), the envelope names the missing permission as `securable_type:operation` (e.g. `Tag:Write`).
- On `kApprovalRequired` (-32006 / HTTP 202) — **shipped (#289)** — the envelope returns `approval_id` and `status_url` so the agent can poll the approval workflow, then re-issue the same call with the `approval_id` (ticket-then-recall) rather than blindly retrying. An approval-gated MCP operation now emits `-32006`; the `kTierDenied` (-32004) fallback applies only to the degraded case where the server has no `ApprovalManager` and cannot mint a pollable approval (a `-32006` with no pollable approval would violate this very contract); see `docs/mcp-server.md`.

**Why this matters.** Today errors give a code and message; nothing else. An agentic worker hitting `Permission denied` cannot tell which permission, who can grant it, or whether to retry. A4 closes that loop and makes self-recovery feasible.

**Status (2026-07 — R2 A4 completion).** The REST surface is now A4-complete end to end:

- **One envelope builder.** `detail::error_json_a4(code, message, correlation_id, const A4ErrorOpts&)` in `server/core/src/rest_a4_envelope.hpp` is the single wire-shape authority. `A4ErrorOpts` carries the nullable `retry_after_ms`, optional `remediation`, the `permission` specialisation, and the `approval_id`/`status_url` pair. The two legacy `error_json_a4` overloads delegate to it (byte-compatible). The httplib-coupled wrapper (`detail::a4_denial` / `detail::a4_error`) lives in the sibling `rest_a4_envelope_http.hpp` so the pure builder stays testable in isolation.
- **Denial patchwork unified.** `auth_routes.cpp`'s three former denial shapes (the raw admin-gate strings, the `require_permission` legacy objects, and the `{"error":"forbidden","detail":…}` service-scope shape) all emit the one envelope now — every **authorization-gate** 401/403 carries a `correlation_id` (echoed on `X-Correlation-Id`) and, where a permission is known, the structured `securable_type:operation` field. (The login/MFA *authentication*-failure bodies keep their deliberately-terse anti-enumeration shape — they are outside the denial-gate scope this sentence enumerates.)
- **`error_json` retired in `rest_api_v1.cpp`.** All ~156 `/api/v1/*` error bodies (the #1470 debt in this file) route through `detail::a4_error(res, msg)` — body `code` derived from `res.status`, `correlation_id` + `retry_after_ms` always present. Other files' `error_json` sites remain on the #1552 backlog.
- **`status_url` target shipped.** `GET /api/v1/approvals/{id}` (gate `Approval:Read`) returns the approval state an A4 `kApprovalRequired` envelope points at, so a worker can poll rather than re-issue. The **MCP tool gate** now populates that pointer end to end (the ticket-then-recall flow above, #289): an approval-gated tool call mints an approval and returns `-32006` with `approval_id`/`status_url`. The **REST auth-gate approval denials** (`auth_routes.cpp` `require_permission`) are the remaining gap — they still carry `permission` + `remediation` only, since no REST-side re-dispatch consumes a REST-minted ticket; wiring that is a follow-up, and until then a fabricated pointer there would violate this section's own contract.

**Enforced by.** `security-guardian` and `consistency-auditor` on any change to error-emitting code paths.

## Where these invariants are referenced

- The audit at `docs/capability-agentic-audit-2026-05.md` cites this doc and applies the invariants to current state.
- `CLAUDE.md` routes consistency-auditor to this doc on every PR.
- The proposed Phase 17 in `docs/roadmap.md` (Agentic Surface Hardening) implements the gaps identified by A1–A4.

## Open question — backfill policy

A1–A4 apply forward from adoption. The audit identifies a backlog of existing surfaces that do not satisfy them (most dashboard fragments, most error sites, the existing `/events` SSE). Backfill is tracked as proposed Phase 17 issues 17.1–17.5; this principle doc does not mandate retroactive compliance, but agents reviewing PRs that touch existing non-compliant code should encourage a partial backfill of the touched paths rather than perpetuating the gap.
