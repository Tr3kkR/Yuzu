# Agentic-First Principle

**Version:** 1.1 | **Date:** 2026-05-01 (A1–A4), 2026-07-11 (A5 added) | **Status:** Architectural rule (proposed)

## What this document is

A five-rule architectural principle. Every operation an authorised human can perform via the dashboard must be performable by an authenticated agentic worker through a documented, discoverable, machine-readable surface. Every signal a human can see must be available to that worker. Every error must be machine-actionable.

This is the canonical reference for the A1–A5 invariants. The audit at `docs/capability-agentic-audit-2026-05.md` references and applies these rules.

## Glossary

The word "agent" is overloaded in Yuzu. To stay precise:

- **Agent daemon** — the C++ binary in `agents/core/` that runs on each managed endpoint and executes plugins.
- **Governance agent** — the `.claude/agents/*.md` review actors run during the `/governance` pipeline.
- **Agentic worker** — an external LLM-driven client (Claude, GPT, in-house) that drives Yuzu through MCP, REST, or the dashboard.

The five invariants below apply to **agentic workers** consuming Yuzu's surfaces.

## A1 — Dashboard parity

Every new `/fragments/*` route ships with either (a) a parallel JSON variant via `Accept: application/json` content negotiation on the same URL, or (b) a sibling REST endpoint in `/api/v1/*` that returns the same data as a structured object.

**Why this matters.** Today most `/fragments/*` routes return only `text/html` for HTMX consumption. An agentic worker reading the dashboard either has to parse HTML (brittle, lossy on dynamic content, no schema) or re-implement the dashboard logic against a separate REST endpoint that may not exist for admin surfaces (user management, enrollment-token administration, settings). Parity removes that asymmetry.

**Scope.** Existing fragments are not retroactively required to comply — backfilling them is tracked separately. New fragment routes are gated by this rule from the date of adoption. The audit lists which admin surfaces are dashboard-only today and earmarks them for the proposed Phase 17 (Agentic Surface Hardening).

**Enforced by.** `consistency-auditor` agent — A1 is added to its trigger list as a post-merge invariant check on any new `/fragments/*` route.

**Hardened by ADR-1005.** The headless-platform decision (`docs/adr/1005-headless-platform-use-case-engines.md`) promotes A1 from a fragments rule to a platform-wide invariant: every behavior of every **new or changed** capability must be reachable via versioned REST **and** MCP, or carry a recorded exception in ADR-1005's exception ledger — prospective from acceptance; this section's existing grandfather scope clause remains in force. Under that reading, option (a) alone — a JSON variant on a fragment endpoint — is not a twin: a fragment URL is not a versioned, discoverable API surface. New capabilities need both the REST and MCP twins; the standing review question is wired into the governance pipeline by execution-plan PR 0.1 (Gate 4 consistency-auditor preamble). Phase status: `docs/adr-1005-execution-plan.md`.

## A2 — Discovery

Every MCP tool, REST route, plugin action, scope kind, RBAC permission, and instruction definition is enumerable through a documented, authenticated discovery endpoint. An agentic worker should be able to learn what is possible from the live server alone, without a side-channel doc fetch.

**Shipped (roadmap Issue 17.1).** The `GET /api/v1/discover/*` family exists, gated `Infrastructure:Read` (`/discover/instructions` gates `InstructionDefinition:Read` instead — it matches the existing definitions RBAC surface more closely than the generic `Infrastructure` type):
- `GET /api/v1/discover/permissions` — RBAC securable_type × operation catalog + the full role → allowed-operations grid (`RbacStore::list_securable_types`/`list_operations`/`list_roles`/`get_role_permissions`, a cheap pass-through).
- `GET /api/v1/discover/instructions` — published (`enabled_only=true`) `InstructionDefinition` subset `{id, name, plugin, action, description, parameter_schema, platforms, approval_mode}`; `parameter_schema` is a nested JSON Schema object when the stored value parses, else `null` (unreachable through the normal authoring path today — `InstructionStore::create_definition` defaults an empty schema to `"{}"` — but kept as a defensive branch for a future direct-write path).
- `GET /api/v1/discover/routes` — subsets the SAME hand-maintained OpenAPI document `GET /api/v1/openapi.json` serves (via the newly-exposed `yuzu::server::openapi_spec_json()`, `server/core/src/openapi_spec_access.hpp`), so the two can never disagree. Carries `"source":"openapi"` plus an explicit caveat: it is NOT generated from the live route table and can under-report an undocumented route. Per-route RBAC requirement is embedded in each entry's free-text `description` (no structured field yet).
- `GET /api/v1/discover/scope-kinds` — fully static (answers even when every store is down, like `/guaranteed-state/schemas`): the two GROUND kinds (`__all__`, `group:<name>`) that short-circuit per-device evaluation, every ATTRIBUTE kind `AgentRegistry::evaluate_scope`'s resolver answers (from `yuzu::server::detail::scope_kind_catalog()`, colocated with the resolver in `agent_registry.hpp`/`.cpp` — a DRIFT CONTRACT comment on the resolver lambda requires any new branch to get a matching catalog entry), the `CompOp` comparison operators (via `yuzu::scope::operator_token`, an exhaustive `switch` with no `default` case so a missed enum value is a `-Wswitch` build-log signal), and the `EXISTS`/`LEN(...)`/`STARTSWITH(...)` extended forms.
- `GET /api/v1/discover/plugins` — wraps `AgentRegistry::help_json()` (deduplicated plugin/action metadata observed across currently-connected agents) with a discovery envelope (catalog `version: 2`). NOT a build-time manifest of every plugin that could ever load. Each action carries an inline `parameter_schema` when it has a published `InstructionDefinition` (matched on plugin+action) **and** the caller holds `InstructionDefinition:Read`; otherwise name+description only (an `Infrastructure:Read`-only caller gets no schemas). A top-level `actions_enriched_with_schema` counts the enriched actions — pair with `/discover/instructions` for the full schema-bearing catalog.

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
- **Denial patchwork unified.** `auth_routes.cpp`'s three former denial shapes (the raw admin-gate strings, the `require_permission` legacy objects, and the `{"error":"forbidden","detail":…}` service-scope shape) all emit the one envelope now — every **authorization-gate** 401/403/503 carries a `correlation_id` (echoed on `X-Correlation-Id`) and, where a permission is known, the structured `securable_type:operation` field. (The login/MFA *authentication*-failure bodies keep their deliberately-terse anti-enumeration shape — they are outside the denial-gate scope this sentence enumerates.)
- **`error_json` retired in `rest_api_v1.cpp`.** The ~156 `/api/v1/*` error sites (the #1470 debt in this file) now emit the A4 envelope: every error body carries `code` (derived from `res.status`), `correlation_id`, and `retry_after_ms` (always present, null unless retryable), and the response carries the matching `X-Correlation-Id` header. Bodies are built either via `detail::a4_error(res, msg)` (which also sets the header) or, in a few handlers, the lower-level `detail::error_json_a4(...)` builder alongside an explicit `X-Correlation-Id` header set — the invariant is the emitted *outcome* (A4 body + header), not a single call path. Other files' `error_json` sites remain on the #1552 backlog.
- **`status_url` target shipped.** `GET /api/v1/approvals/{id}` (gate `Approval:Read`) returns the approval state an A4 `kApprovalRequired` envelope points at, so a worker can poll rather than re-issue. The **MCP tool gate** now populates that pointer end to end (the ticket-then-recall flow above, #289): an approval-gated tool call mints an approval and returns `-32006` with `approval_id`/`status_url`. The **REST auth-gate approval denials** (`auth_routes.cpp` `require_permission`) are the remaining gap — they still carry `permission` + `remediation` only, since no REST-side re-dispatch consumes a REST-minted ticket; wiring that is a follow-up, and until then a fabricated pointer there would violate this section's own contract.

**Enforced by.** `security-guardian` and `consistency-auditor` on any change to error-emitting code paths.

## A5 — Agentic context contract

Every machine-consumer surface carries gold-standard, **machine-readable** context — an agentic worker relying on spec metadata (annotations, schemas, handshake instructions) must learn as much as one that parses the English prose. Adopted by ADR-1005 execution-plan Decision 16; delivered/backfilled by track 2g.

**The contract.** A new or materially changed in-scope surface (an MCP tool, or a capability whose ADR-1005 twin includes an MCP tool) ships with ALL of:

1. **Standard spec annotations** — `title`, `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` (spec keys, not house-invented ones). Destructiveness and idempotency are machine-readable, never prose-only: a client that renders a confirmation UI off `destructiveHint` must catch `quarantine_device`-class tools.
2. **Decision-grade description** — what it does, when to use it (and when not), workflow chaining (what should precede/follow it — e.g. the poll target for an async dispatch), the meaning of an empty/ambiguous result (the `query_responses` "empty may mean still running" pattern is the bar), and — once the Phase 0.3 cross-surface versioning policy lands — any deprecation/succession state, stated in machine-checkable form, not prose alone.
3. **Bounded, documented input schema** — per-property `description`; `maxLength` on every free-text string; `minimum`/`maximum`/`enum`/`default` where applicable.
4. **Typed output schema** for structured results — the generic `{"type":"object","additionalProperties":true}` placeholder does not satisfy this for a tool whose result shape is stable.
5. **Self-recovering errors** — the A4 envelope on every error path with honest `retry_after_ms` (populated whenever a retry hint genuinely exists — e.g. result-not-ready polling — not hardcoded null; values are server-controlled with a minimum floor, never derived from client input — a too-small value fans out to a fleet of spec-obedient clients as a poll storm), `remediation` on denials, `approval_id`/`status_url` on approval gates.
6. **Handshake orientation maintained** — the server's `initialize` result carries an `instructions` blob orienting a fresh client (what Yuzu is, the operating model, where discovery starts); a change that adds a tool family or reshapes the operating model updates it in the same PR. The blob is operator/developer-authored **static** content only — fleet-derived or agent-reported data (hostnames, tag names, device strings) is never interpolated into it; templating untrusted data into the handshake would be a prompt-injection channel into every fresh client, bypassing the `untrusted_prompt_argument` discipline.
7. **Specs as resources** — machine-readable references an agent needs (OpenAPI document, scope-DSL catalog, capability summary) are enumerable via `resources/list`, not reachable only by already knowing the right tool to call.

Items 1–5 bind per-tool; items 6–7 bind per-capability (the PR that changes the surface owns the update). The same bar extends to the other MCP primitives: prompts carry decision-grade descriptions and complete argument metadata (`name`/`description`/`required`); resources carry a description and a correct `mimeType`. Dashboards and human-only surfaces are out of scope; the REST twin's OpenAPI entry is covered by A2's existing requirements.

**Materiality.** A tool is "materially changed" — re-triggering the full contract check, annotations first — whenever its tier, securable/operation mapping, dispatch behavior, or side-effect set changes, or its `tools/list`/`initialize` spec-visible output changes; a byte-identical refactor is not material. This is per-se, not arguable case-by-case: a tool that silently gains a mutating side effect under an unchanged name is the #1 stale-`readOnlyHint` hazard.

**Today (2026-07-11 survey).** Prose is strong (chaining hints, blast-radius warnings, A4 `remediation`/`status_url`); machine metadata is thin: `initialize.instructions` unused; `destructiveHint`/`idempotentHint` absent everywhere (destructive tools signal danger in prose only); ~40 core tools carry no annotations and no output schema; the ~10 annotated tools use a non-standard `"safety"` key; `retry_after_ms` is hardcoded null on the MCP tool gate; OpenAPI/scope-DSL specs sit behind tools, invisible to `resources/list`; `protocolVersion` is pinned to 2025-03-26 while 2025-06-18 output schemas are already served.

**Enforced by.** `consistency-auditor` on every capability-adding PR (same wiring as A1–A4 and the ADR-1005 standing question — the governance Gate 4 preamble asks the A5 conformance question on any new/changed MCP tool); `security-guardian` co-checks item 1's truthfulness across `readOnlyHint`, `destructiveHint`, **and `idempotentHint`** against the tool's tier and dispatch behavior. A false safe-direction hint — `readOnlyHint: true` or `destructiveHint: false` on a mutating/destructive tool, or `idempotentHint: true` on a non-idempotent dispatch (it invites the blind re-POST Decision 15(g) forbids) — is a **BLOCKING (HIGH) finding**: clients build confirmation UIs and retry policy off these flags. Annotations are advisory client UX (the MCP spec says clients should not rely on them) — the tier/approval/RBAC gate is the only enforcement; an annotation is never accepted as mitigation for weakening a server-side gate. A pure wording fix that changes no annotation, schema, tier, or behavior re-triggers only item 2's description review, not the full seven-item pass.

**Exceptions.** A5 exceptions are recorded here, in this section's own ledger - deliberately distinct from ADR-1005's twin-existence exception ledger (one control question per ledger: that one answers "does the twin exist", this one answers "is the metadata gold-standard"). Each entry names the surface, the waived item(s), an issue number, and a revisit-by date; `enterprise-readiness` reviews this list at every Gate 6 pass and flags stale or undated entries.

*Ledger:*

| Date | Surface | Waived item | Issue | Revisit by |
|---|---|---|---|---|
| 2026-07-24 | `execute_instruction` (MCP tool) | Typed output schema / `structuredContent` - input bounds backfilled in 2f PR 3a (enforcement is SPLIT since #2405: ENFORCED pre-mint on the approval-gated/supervised path by the C8 input-schema gate, schema-advisory on the operator/readonly path; full every-path enforcement is tracked in #2437), and the stable output identifiers (`command_id`/`execution_id`/`agents_reached`) remain in `result.content[0].text` prose. Owned by track 2g's typed-schema sweep. | #2436 | 2026-10-31 |
| 2026-07-24 | `execute_instruction` progress (MCP GET channel) | Progress-lifecycle ordering deviation: for the 2f 3a GET-only rung, `notifications/progress` for a `progressToken` are delivered on the session's GET channel *after* the `tools/call` JSON-RPC response has retired the request (a strict reading of the MCP progress lifecycle expects progress before/during an in-flight request). Authorized as an interim deviation via the PR #2424 adversarial review; `docs/mcp-server.md` "Progress bridge (2f PR 3a)" documents the interim GET shape; stock SDK clients drop (not reject) the frames with the documented poll fallback. Closed by the 2f 3b streamed-POST rung's progress-before-response shape. | #2439 | 2026-10-31 |
| 2026-08-04 | `list_pending_approvals` (MCP tool) | Typed output omits `origin`, the field that decides whether a ticket can be redeemed at all since #2442's consume-side guard. A reviewer deciding on an approval cannot see it over MCP, and the A1-parity halves of the same gap are `GET /api/v1/approvals/{id}`, its OpenAPI schema, and the dashboard approve fragment. | #2763 | 2026-10-31 |

**Backfill.** A5 applies forward from adoption, per this doc's standing backfill policy. The existing ~50-tool backlog is owned by execution-plan track 2g (annotations sweep, typed schemas, instructions blob, specs-as-resources); PRs touching a non-compliant tool for other reasons should backfill that tool rather than perpetuate the gap.

## Where these invariants are referenced

- The audit at `docs/capability-agentic-audit-2026-05.md` cites this doc and applies the invariants to current state.
- `CLAUDE.md` routes consistency-auditor to this doc on every PR.
- The proposed Phase 17 in `docs/roadmap.md` (Agentic Surface Hardening) implements the gaps identified by A1–A4.

## Open question — backfill policy

A1–A4 apply forward from adoption. The audit identifies a backlog of existing surfaces that do not satisfy them (most dashboard fragments, most error sites, the existing `/events` SSE). Backfill is tracked as proposed Phase 17 issues 17.1–17.5; this principle doc does not mandate retroactive compliance, but agents reviewing PRs that touch existing non-compliant code should encourage a partial backfill of the touched paths rather than perpetuating the gap. A5's backlog (adopted 2026-07-11, after the audit) is tracked separately — see A5 §Backfill and execution-plan track 2g.
