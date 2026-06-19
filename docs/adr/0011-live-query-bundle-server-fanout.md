---
status: accepted
date: 2026-06-19
owner: Dave Rae
deciders: HITL session 2026-06-19
scope: server — one operator instruction → several plugin actions on one device → collated results
builds-on: docs/executions-history-ladder.md (execution_id / query_by_execution substrate), docs/agentic-first-principle.md (REST/MCP parity), docs/mcp-server.md
supersedes: the agent-side `__bundle__` multiplex explored on branch `feat/live-query-bundle` (5 commits, never merged)
---

# 0011 — Live-query bundle: server-side async fan-out

## Context

Operators (and the ServiceNow integration in particular) need to read several live signals
from one device in a single logical action — e.g. "refresh this CI" pulls OS name/version, RAM,
uptime, logged-on user, agent version, RDP state (7 plugin actions). Today that is N separate
`execute_instruction` dispatches, each its own round-trip + poll loop. The goal is **one
instruction in, all results collated out**, to cut that latency.

This was first built as an **agent-side multiplex**: a reserved `__bundle__` command carrying N
steps, interpreted *on the agent*, which fanned the plugins onto the agent thread pool and
streamed the results back. That approach was implemented, live-fired, and put through the full
governance pipeline — and the review surfaced that the agent-side path carries most of the cost
and risk:

- a non-UTF-8 plugin output crashed the agent (envelope `.dump()` threw out of a pool worker);
- a single 32-step bundle of hung steps could seize the whole agent command pool (one-call DoS);
- correctness depended on an implicit gateway frame contract (RUNNING frames kept, first
  terminal closes — the gateway drops later frames), which a live fire had already tripped once;
- per-step results had to ride a JSON envelope inside `output` because all steps shared one
  `command_id` (the response store derives `plugin` from the command_id and has no `action`
  column), i.e. a bespoke demux carrier.

## Decision

Replace the agent-side multiplex with **server-side async fan-out**. The agent is unchanged —
it only ever sees ordinary single commands.

1. **The server expands one instruction into N individual plugin commands.** The instruction
   carries an explicit list of `{plugin, action, params}` steps (a thin expander, not a named
   catalog — the "device refresh" *semantic* stays in the agentic/MCP layer, which composes the
   step list). One correlation id is minted; each step is dispatched via the existing
   `dispatch_fn` under that shared id, so each step is an ordinary command with its own
   `command_id` (correct plugin prefix) and the responses are stampable + `query_by_execution`-able.

2. **Async.** Dispatch returns the correlation id immediately and does not wait. The caller
   collects results from a **collate** operation that the server groups on demand. Async was
   chosen over sync for two concrete reasons: **progressive delivery** (the fast steps are
   available immediately; a slow plugin no longer withholds the whole response) and
   **non-blocking** (the server holds no worker open for the wait — eliminating the inline-poll
   worker-exhaustion class of findings). Async does *not* make a slow plugin faster; it makes
   the rest available now and frees the server.

3. **Two operations, on both REST and MCP.** `dispatch` and `collate` are surfaced as REST
   routes (the GUI / automation / ServiceNow path — ServiceNow drives Yuzu over REST, so this
   is the primary surface) **and** as MCP tools (the agentic-AI path), both thin wrappers over
   one shared server core. This satisfies agentic-first REST/MCP parity by construction rather
   than deferring it.

4. **Demux by command_id, ordered by the step map.** Each response row is attributed to its
   step by `command_id` (plugin from the prefix; `action` from the persisted step map). The
   collate op returns steps in request order — duplicate `(plugin, action)` and same-plugin /
   different-action are unambiguous, which the envelope/arrival-order agent-side model was not.

5. **Bundle state lives in a dedicated bundle record, NOT the executions tracker (Option F).**
   The correlation id is used purely as a row-stamping / `query_by_execution` token; the bundle's
   ordered step↔command_id map, `expected` count, `dispatched_by`, and per-step dispatch outcome
   live in one small bundle record. The server does **not** create an executions-tracker row for
   a bundle. Rationale: the executions tracker completes on *agents* (`agents_responded >=
   agents_targeted`); a bundle is N commands to **one** agent, so an agent-counted execution
   would mark complete after the first step. Keeping bundles out of the tracker leaves the
   governed executions-history ladder untouched and makes the collate op the single
   authoritative source of bundle completion (`received >= expected`).

   **v1 storage is an in-memory map + TTL** (the TTL doubles as the abandoned-bundle sweep). It
   matches the instance-locality of `response_store` (still per-instance SQLite), so it is no
   less durable than the responses during normal operation; an in-memory map is not a "store"
   per ADR-0006, so no new-store ADR is required for v1. **This is a deliberate v1 simplification
   with a committed migration target — see "Future: durable manifest in Postgres" below.**

## Options considered

- **Agent-side `__bundle__` multiplex** — implemented + governed, then superseded (see Context).
- **Sync collate** (wait-then-return in one call) — rejected: a slow plugin withholds the whole
  response and the server holds a worker for the wait.
- **Tracker representation** for the umbrella bundle:
  - **F (chosen)** — bundle is not a tracker execution; own bundle record; lightest; ladder
    untouched; bundles are queryable + audited + metered but **not shown in the live executions
    drawer**.
  - **B (deferred — see Future)** — bundle is a tracker execution with a *command-count*
    completion mode; live + accurate in the drawer; costs a scoped change to the governed
    executions-ladder.
  - **A** (tracker row, completion suppressed, collate drives status) — collapses into B once
    `notify_exec_tracker` must be made bundle-aware; strictly worse than B.
  - **C** (N tracker executions grouped by a bundle_id) — floods the drawer, new correlation
    key; rejected.

## Consequences

- **Zero agent change.** The agent-side bundle code, the `__bundle__` reserved name, the
  `BundleFrameEmitter`, the envelope carrier, and the gateway frame contract are all dropped —
  and with them nearly every agent-side governance finding (UTF-8 crash, pool exhaustion).
- **Reuse:** the `execution_id` / `cmd_execution_ids_` / `query_by_execution` substrate; the
  existing `dispatch_fn`; step validation + caps; the per-step audit verbs (`mcp.bundle.<plugin>.<action>`,
  `target_type="Agent"`); the `bundle_collect` aggregation (adapted to build from ordinary
  response rows rather than envelopes).
- **New:** a shared `bundle_service` core (dispatch + collate); a small bundle record holding the
  step map + status; REST routes + MCP tools.
- **Bundles are not in the live executions drawer.** They remain fully observable via the audit
  log (per-step verbs), responses queryable by the correlation id, and `yuzu_mcp_bundle_*`
  metrics. The caller's collate poll is its own live view. (See Future for the drawer option.)
- **Residuals to handle:** collate must ownership-check the correlation id against the bundle
  record's `dispatched_by` (IDOR); partial-dispatch failure must be recorded per step so a
  step that never reached the agent reads as failed, not pending-forever; abandoned bundle
  records (a hung step that never responds) need a sweep/TTL.
- **Carried forward, not bundle-specific:** the agent has no per-plugin execution watchdog, so a
  hung plugin holds one agent worker until it returns — but a bundle is N *ordinary* commands,
  so this is the pre-existing agent-wide limitation reachable via N calls anyway, not a new
  capability. Filed as an agent-wide follow-up.

## Future — durable manifest in Postgres (committed, not optional)

v1's in-memory step-map is acceptable *only* because bundles are short-lived and the data is
ephemeral. It has a real gap: a server restart mid-bundle loses the in-flight manifests
(`command_id→action` + `expected` + `dispatched_by`), so those bundles cannot be collated
(the responses survive in `response_store`, but attribution and `complete` do not) and the
caller must re-dispatch. **For high availability and assurance this is not acceptable long-term:
the bundle manifest MUST move to a durable Postgres store** (a `bundles` table under its own
schema via `PgMigrationRunner`, per ADR-0006's "new server stores default to Postgres"). This
makes a mid-bundle restart survivable, and — once `response_store` itself migrates off
per-instance SQLite — is a prerequisite for serving dispatch and collate from different server
instances (true HA). This migration is a **committed direction recorded here so it is not lost**,
deferred from v1 by scope only, not by doubt. The in-memory implementation must carry a code
comment at the store pointing back to this ADR section.

## Future — Option B (deliberately deferred)

If bundles need to be **first-class, live, in the executions drawer** (an operator watching a
bundle's steps complete in the dashboard), promote the bundle to a tracker execution with a
**command-count completion mode**: add `kind=bundle` + `expected_responses=N` to the execution
row and have `notify_exec_tracker`, for bundle executions, count distinct `command_id`s
responded toward `expected_responses` instead of distinct agents. This is the correct long-term
model but touches the governed executions-history ladder (schema field + a second completion
mode + a ladder-doc update + governance review), which is why it is deferred until a concrete
operator need for live drawer visibility exists. For machine-driven, single-device,
caller-polled bundles, the audit log + queryable responses + metrics meet the observed needs.
