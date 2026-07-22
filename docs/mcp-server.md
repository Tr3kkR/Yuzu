# MCP (Model Context Protocol) Server

Yuzu embeds an MCP server at `POST /mcp/v1/` using JSON-RPC 2.0 transport. This allows AI models (e.g., Claude Desktop) to securely query fleet status, check compliance, investigate agents, and — with appropriate authorization — execute instructions on endpoints.

CLAUDE.md keeps only the load-bearing invariants (embed point, tier-before-RBAC ordering, kill switches, audit pattern). This document is the full architecture and tool reference.

## Architecture

- **Embedded in existing server** — MCP runs inside the same cpp-httplib server as the REST API and dashboard. It reuses auth middleware, RBAC, rate limiting, CORS, and audit logging with zero duplication.
- **Module:** `server/core/src/mcp_server.hpp` / `mcp_server.cpp` — mirrors `RestApiV1` pattern (injected store pointers, same callback signatures).
- **JSON-RPC helpers:** `mcp_jsonrpc.hpp` (header-only) — parse/build JSON-RPC 2.0 envelopes.
- **Tier policy:** `mcp_policy.hpp` (header-only) — static allow-lists per tier, checked before RBAC.
- **Output serialization:** Uses local `JObj`/`JArr` string builders (same pattern as `rest_api_v1.cpp`) to avoid the 56GB nlohmann template bloat. `nlohmann::json` is used for parsing only.

## Security Model

- **Three authorization tiers** enforced *before* RBAC: `readonly` (read only), `operator` (+ tag writes, auto-approved executions), `supervised` (all ops via approval workflow).
- **MCP tokens** use the existing API token system (`api_token_store`) with a new `mcp_tier` column. MCP tokens require mandatory expiration (max 90 days).
- **Approval workflow** — Operations that `requires_approval(tier, type, op)` returns true for are routed to the `ApprovalManager`. Admins approve/reject via Settings UI or REST API. All admins see all pending approvals (both AI-initiated and human-initiated).
- **Kill switch:** `--mcp-disable` rejects all `/mcp/v1/` requests with `kMcpDisabled` JSON-RPC error. `--mcp-read-only` blocks non-read tools.
- **Reserved on-behalf-of headers rejected (ADR-1005):** MCP registers on the same httplib instance as REST, so the pre-routing chokepoint rejects any `/mcp/v1/` request carrying a reserved on-behalf-of header with `403` before the JSON-RPC layer runs — see `docs/auth-architecture.md` ("On-behalf-of assertions rejected") for the reserved-name list.
- **Audit:** Every MCP tool call logged with `action: "mcp.<tool_name>"` and `mcp_tool` field on `AuditEvent`.
- **Response-collection scope (`query_responses`) — #1634, PARTIAL.** A per-agent `check_scoped_permission` filter is applied to the returned rows, **but it is INERT under the current global `Response:Read` gate** — a holder of global `Response:Read` (the only principal that passes the gate) admits every agent, so no rows are dropped and a caller currently **does** see other operators' execution rows by id; a management-group-confined operator is 403'd at the gate before the filter runs. So this does **not** yet provide cross-operator isolation; its only active effect today is failing **closed** (zero rows) on a corrupt/load-failed `rbac.db`. Effective isolation needs the admit-then-filter gate change tracked in #1634. When a row IS dropped (the corrupt-store path), `query_responses` emits a **second** audit row `result=denied` (`detail` carries the distinct dropped-agent count) **in addition to** the `result=success` row — a SIEM rule must treat the two as a pair for one call (informational access-boundary evidence for CC6.1, not a failed call); under normal operation this `denied` row does not fire. RBAC-off → no filter (legacy-open). The result object carries `audit_persisted:false` if any of that call's audit rows could not persist, and `result_truncated_by_cap:true` if the raw query hit the row cap before filtering (incomplete page). *(The same inert per-agent filter + corrupt-store fail-closed now also covers `aggregate_responses`, REST `/executions/{id}/visualization` + `/api/responses/*`; the dashboard `/fragments/results` family and workflow execution-detail reader remain flat-`Response:Read` and **fail OPEN on a corrupt `rbac.db`** — all tracked in #1634.)*

## Error envelope

JSON-RPC error responses from the tier-denied paths (read-only mode, tier policy, approval-required) carry a structured `error.data` field (A4, per `docs/agentic-first-principle.md`):

```json
{ "correlation_id": "req-<hex-ms>-<hex-seq>", "retry_after_ms": null, "remediation": "use a higher-tier MCP token, or the REST API / dashboard" }
```

> **Supervised-tier / approval-gated operations — ticket-then-recall (#289).**
> An operation for which `requires_approval(tier, type, op)` is true is answered
> with `kApprovalRequired` (-32006). Its `error.data` extends the A4 envelope
> with two extra fields:
>
> ```json
> { "correlation_id": "req-<hex-ms>-<hex-seq>", "retry_after_ms": null,
>   "remediation": "an admin must approve this approval_id (see status_url), then re-call this tool with the approval_id argument to execute",
>   "approval_id": "<32-hex>", "status_url": "/api/v1/approvals/<32-hex>" }
> ```
>
> The **first** call mints an `ApprovalManager` approval (`definition_id =
> "mcp.<tool>"`, `submitted_by` = the caller, `scope_expression` = the
> canonical JSON of the tool arguments) and returns the envelope above. An admin
> approves it (Settings UI / REST `POST /api/approvals/{id}/approve`; reviewer ≠
> submitter is store-enforced, so self-approval is impossible). The caller then
> **re-calls the same tool** passing the returned `approval_id` as an argument;
> the server verifies the approval is (a) approved, (b) for this exact tool
> (`definition_id`), (c) for these exact arguments (canonical-args match,
> `approval_id` excluded from the comparison), and (d) not yet consumed, then
> **atomically consumes it** (one-time; a replay of a consumed ticket, or a
> concurrent second recall, is rejected — the mutating op runs at most once) and
> lets the call through to the handler. A recall against a still-**pending**
> ticket returns the same `kApprovalRequired` envelope (keep polling
> `status_url`); a rejected/expired/mismatched/consumed ticket returns
> `kPermissionDenied` (-32003). This generic gate governs every approval-gated
> tool — the supervised tier's `execute_instruction` / `revoke_certificate` /
> `execute_bundle`, plus `delete_tag` (operator + supervised) and
> `quarantine_device` (supervised). **Degraded path:** if the server has no
> `ApprovalManager` (a stripped deploy / test harness), it cannot mint a pollable
> ticket, so it falls back to a `kTierDenied` (-32004) with no `approval_id`.
> **Note:** the per-tool RBAC check (`perm_fn`) runs on the *recall*, after the
> ticket is consumed, so a token that passes the MCP tier check but fails RBAC
> can mint→approve→then 403 (burning the ticket) — a rare consequence of the
> deliberate tier-then-RBAC two-gate split.

`correlation_id` is a per-error token (`req-<hex-ms>-<hex-seq>`, the same format as the REST `X-Correlation-Id` header) returned to the caller in the error body, so a client can cite a stable handle when reporting a failure. **It is not persisted to the audit log today** — the audit row for a denied call (`mcp.<tool>`) is written separately and does not carry the token — so server-side correlation relies on any `spdlog` line the handler emits at that moment, not on `audit.db`. `retry_after_ms` is `null` on tier/approval-denial errors (the denial is not retryable as-is); `remediation` carries an actionable hint — escalate to a higher-tier token, or use the REST API / dashboard. Per-tool validation errors (e.g. the dex-perf tools) populate `correlation_id`, a `null` `retry_after_ms`, and a field-specific `remediation`. Parse `error.code` for the error class and `error.data.correlation_id` for client-side traceability.

## Phase 1 (Implemented)

- Read-only tools (the **authoritative, complete table** is `docs/user-manual/mcp.md` — this list is illustrative, not a count): `list_agents`, `get_agent_details`, `query_audit_log`, `list_definitions`, `get_definition`, `query_responses`, `aggregate_responses`, `query_inventory`, `list_inventory_tables`, `get_agent_inventory`, `query_installed_software`, `get_tags`, `search_agents_by_tag`, `list_policies`, `get_compliance_summary`, `get_fleet_compliance`, `list_management_groups`, `get_execution_status`, `list_executions`, `list_schedules`, `validate_scope`, `preview_scope_targets`, `list_pending_approvals`, `get_guardian_schemas`, `list_dex_signals`, `get_dex_signal_scope`, `get_dex_signal_detail`, the DEX-perf + network tools, and `list_issued_certs`
  - **`query_installed_software`** is the typed daily-sync software-inventory read (ADR-0016), gated on `Inventory:Read` (with a per-agent management-group drop filter that is **not yet verified effective under the global gate — see ADR-0017 / #1716**) — distinct from the generic `query_inventory`/`get_agent_inventory` (generic blob store, `Infrastructure:Read`).
  - **DEX read tools (`list_dex_signals` / `get_dex_signal_scope` / `get_dex_signal_detail`)** are the MCP parity for the `/api/v1/dex/*` REST surface — same `GuaranteedStateStore` aggregations, gated on `GuaranteedState:Read`, with a `window` of `24h`/`7d`/`30d`/`all`. The audit boundary mirrors REST: the rollup and per-OS scope are fleet aggregates (only the generic `mcp.<tool>` tool-call audit), while `get_dex_signal_detail` returns a most-affected **devices** list (behavioral) and additionally emits a **`dex.signal.view`** audit (`target_type=ObsType`) so one SIEM filter catches the dashboard, REST and MCP behavioral-access surfaces alike. `obs_type` is validated against `[A-Za-z0-9._-]{1,64}` (malformed → `kInvalidParams`). When the `dex.signal.view` audit row cannot persist, `get_dex_signal_detail` **set-and-proceeds** and carries `audit_persisted:false` in the result (absent on success — consumers key on absence), matching the `query_responses` / `revoke_certificate` convention; JSON-RPC has no header channel, so this is the MCP equivalent of the REST `Sec-Audit-Failed` header (#1647). The REST `dex.signal.view` sibling instead fails closed — different surface, different posture.
- Write/execute tools (the authoritative table is `docs/user-manual/mcp.md`): `execute_instruction` — dispatches plugin commands to agents (auto-approved for `operator` tier; `supervised` tier is approval-gated via the ticket-then-recall flow; if neither `scope` nor `agent_ids` is provided, targets all agents) — `execute_bundle` (below), `revoke_certificate`, and the five Issue-13.5 write tools `set_tag`, `delete_tag`, `approve_request`, `reject_request`, `quarantine_device` (#289).
  - **The five write tools (#289 / Issue 13.5)** are the last-mile agentic write surface: `set_tag` (`Tag:Write`, fires the agent tag-push), `delete_tag` (`Tag:Delete`, approval-gated on operator + supervised), `approve_request` / `reject_request` (`Approval:Approve`, supervised tier — reviewer ≠ submitter store-enforced), and `quarantine_device` (`Security:Execute`, supervised, approval-gated — records the quarantine *and* dispatches the live quarantine-plugin isolation). The approval-gated members flow through the ticket-then-recall mechanism documented under **Error envelope** above.
- **Live-query bundle tools (`execute_bundle` / `get_bundle_result`)** — MCP parity for the `POST`/`GET /api/v1/bundles` REST surface (ADR-0011). `execute_bundle` (write/execute, `Execution:Execute`) fans one instruction into 1–32 plugin actions on **one** device via server-side async fan-out and returns `{execution_id, expected}` immediately; `get_bundle_result` (`Response:Read`) collates to `{complete, received, expected, steps[]}` in request order. Use instead of N `execute_instruction` calls when refreshing a device (N round-trips → 1). The agent is unchanged — each step is an ordinary command under one `bundle-…` correlation id; per-step `bundle.<plugin>.<action>` audit (`target_type=Agent`) mirrors REST, and collate enforces an ownership (IDOR) guard. Bundles are caller-polled, **not** in the executions drawer; v1 manifests are per-surface + in-memory (durable Postgres store is a committed follow-up — ADR-0011).
- 3 resources: `yuzu://server/health`, `yuzu://compliance/fleet`, `yuzu://audit/recent`
- 4 prompts: `fleet_overview`, `investigate_agent`, `compliance_report`, `audit_investigation`
- Settings UI section with enable/disable and read-only toggles

## Agentic Demo Layer

Yuzu also exposes a v1 MCP-native demo and incident-orientation layer for LLM clients. It is intentionally endpoint-evidence first: OpenShift, KVM/libvirt, Postgres/Oracle, Teams/Zoom, registry/build-cache, and similar platform internals are labelled as connector gaps unless the facts are already present in Yuzu inventory/responses or supplied by the user.

### Resources

- `yuzu://about` — product primer, glossary, and safe operating rules.
- `yuzu://capabilities` — what MCP can answer now, what may need live read-only dispatch, what requires external connectors, and what is unsafe without approval.
- `yuzu://operating-model` — classify → plan → read → narrow scope → dry run/read-only probe → request approval → execute → monitor.
- `yuzu://demo/playbooks` — deterministic incident/demo playbooks with live-fleet variants.
- `yuzu://golden-prompts/enterprise-it-v1` — versioned golden prompt/eval catalogue.

### High-level tools

These tools are read-only and available to the `readonly` MCP tier, subject to normal RBAC checks. They advertise `outputSchema` and return both legacy MCP `content[]` text and `structuredContent`.

- `get_fleet_posture_fast` — compact cached posture summary. The cache TTL defaults to 30 seconds and responses include `generated_at`, `data_age_seconds`, `partial`, and `missing_sources`. `data_age_seconds` reflects the **real age of the cached snapshot at read time** — it is recomputed per request, so a cache hit reports a non-zero age (it is not the value baked in at generation).
- `classify_operational_question` — classifies a question as `answerable_now`, `answerable_with_live_dispatch`, `requires_external_connector`, `unsafe_without_approval`, or `outside_yuzu_scope`. **This classification is advisory only — a UX hint for the agentic worker, not a security control.** It uses ASCII keyword matching that can be evaded by rephrasing or Unicode homoglyphs; never treat it as an authorization decision. Real enforcement is the MCP tier + RBAC check on each tool, and its `recommended_next_tools` are always read-only.
- `get_incident_playbook` — returns a scenario workflow, first tool, safe tool path, connector gaps, and approval boundaries. `scenario` is matched **exactly** against a playbook name, category, or curated tag (e.g. `openshift`, `teams`, `postgres`) — not by loose substring, so a short/generic query returns "unknown scenario" rather than the wrong playbook.
- `summarize_working_set` — summarizes a fleet, agent, execution, or result-set working set into a bounded model-ready narrative with resource links. The `agent` kind is management-group scoped (an out-of-scope agent is reported as not-present, never leaking its hostname/os); the `execution` kind additionally requires `Execution:Read`.

> **No fabricated-data demo mode (ADR-0016).** Yuzu demos run **live against the real fleet** and never return canned findings. The earlier `prepare_demo_scenario` tool and its `mode=curated` "DEMO DATA" path are **retired**. Realism comes from constructing a real environment that genuinely exhibits a condition (a staged device with a real pending reboot, a really-degraded link, a really-crashing service), then observing it live and remediating it live through the normal tier/RBAC + approval path. The `ceo_demo_agentic_endpoint_management` prompt drives that live flow.

### Prompts

Additional task-native prompts are exposed through `prompts/list`: `ceo_demo_agentic_endpoint_management`, `fleet_health_briefing`, `investigate_collaboration_quality_issue`, `investigate_endpoint_security_client_outage`, `investigate_patch_or_reboot_risk`, `investigate_container_or_build_failure`, `investigate_java_gateway_or_node_service_degradation`, `investigate_database_client_or_host_bottleneck`, and `prepare_remediation_plan`. User-supplied prompt arguments are wrapped as untrusted data; closed-enum prompt arguments (e.g. the CEO demo's `mode`) are instead normalized server-side to a known-safe value, so caller text never reaches the model as task instructions.

### Golden Prompt Pack

`enterprise-it-v1` covers enterprise incident topics: OpenShift, KVM/libvirt, Chisel/Ubuntu containers, Docker buildx, Node, Spring Cloud Gateway/Java, Postgres/Oracle, Teams/Zoom, Windows/macOS endpoint operations, and security clients such as CrowdStrike, Check Point, zScaler, and Cisco Secure Client. Each fixture records the expected first tool, allowed tool path, pass/fail rubric, safety behavior, and curated/live support.

## Phase 2 (Implemented — #289 / Issue 13.5)

- **5 write tools shipped:** `set_tag`, `delete_tag`, `approve_request`, `reject_request`, `quarantine_device` (dispatch handlers + `tools/list` entries + RBAC/tier mapping).
- **Approval workflow re-dispatch shipped** — supervised-tier (and operator-tier `delete_tag`) execution after admin approval, via the ticket-then-recall flow (`kApprovalRequired` → approve → recall with `approval_id`; one-time consumption). Documented under **Error envelope** above.
- **SSE streaming for execution progress** is available today via the shipped `GET /api/v1/events` endpoint (sprint W5.1) — an agentic worker bridges `execute_instruction`'s returned `execution_id` to that SSE stream (see the `execute_instruction` row in `docs/user-manual/mcp.md`); that bridge remains supported. **Direction change (2026-07-11):** a spec-compliant MCP **Streamable HTTP** transport (sessions, GET SSE channel, `notifications/progress` for long-running tools) is now a committed platform requirement — ADR-1005 execution plan **Decision 15 / track 2f** supersedes the earlier "no MCP-specific streaming transport is planned" stance recorded here.

## Phase 2.5 (Implemented — MCP Streamable HTTP transport, track 2f PR 1 + PR 2)

The session-lifecycle + transport pre-check half of the Streamable HTTP transport is **live** (ADR-1005 execution plan **Decision 15 / track 2f** PR 1). Shipped:

- **`Mcp-Session-Id` sessions.** `initialize` mints a principal-bound ≥128-bit CSPRNG session id and returns it as the additive `Mcp-Session-Id` response header. Sessions are never *required* (plain-POST clients are unaffected); when a client presents one on a later request it is validated (unknown / expired / bound-to-another-principal → `404`, indistinguishable from never-existed — no cross-principal oracle — and the client re-initializes). `DELETE /mcp/v1/` ends a session. State is in-memory and bounded (idle TTL, per-principal + global caps that **reject** rather than evict a live session); a server restart drops sessions and the client re-initializes, per spec.
- **`Origin` validation** on every method against a configured allowlist (`--mcp-allowed-origin`; absent Origin allowed on this credential-gated endpoint, empty allowlist rejects any present Origin).
- **`MCP-Protocol-Version` negotiation.** Supported revisions `2025-03-26` and `2025-06-18`; `initialize` echoes the client's requested version when supported, else the `2025-03-26` baseline. A present-but-unsupported header → `400`.
- **Notification POSTs answer `202`** (spec MUST; was `204`).
- **Kill switch** `--mcp-no-streaming` (no minting; `GET`/`DELETE` → `405`; plain JSON-RPC POST only) and audit verbs `mcp.session.open` / `mcp.session.close` / `mcp.session.reject` (the last on every denial — origin, unknown session, cap, protocol-version).
- New JSON-RPC error codes: `-32007` unknown session (`404`), `-32008` origin rejected (`403`), `-32009` bad protocol version (`400`), `-32010` session cap (`429`). Each carries the shared A4 `error.data` (a `correlation_id`, the always-present nullable `retry_after_ms`, and a `remediation`), built by the single `error_response_a4` helper so the transport denials match the REST/tool-call A4 envelope.

Session state is in-memory only and deliberately does **not** gate `/readyz`. Operator reference: `docs/user-manual/server-admin.md` (flags + Upgrade Notes) and `docs/user-manual/mcp.md`.

### The GET SSE channel (PR 2)

`GET /mcp/v1/` is the session's server→client channel. It replaces the PR-1 `405` placeholder:

- **Attach.** Requires the session's `Mcp-Session-Id` (absent → `400`; unknown / expired / another principal's → `404`) and `Accept: text/event-stream` (missing → `406`, `-32011`; wildcards like `*/*` deliberately do **not** opt in). Heartbeats every ~3 s keep intermediaries from idling the connection out; `X-Accel-Buffering: no` defeats reverse-proxy response buffering.
- **Resume.** Each session has its own bounded replay ring and its own event-id namespace starting at 1 (ids are **never** global, so a cursor from one session can never address another's frames). A reconnect with `Last-Event-ID` replays exactly the frames it missed. If the cursor's frames have already been evicted from the ring — or the cursor is one the server never issued — the session is **terminated** and the request `404`s: the client re-initializes, and durable results remain fetchable by `execution_id`. There is no silent gap, and the GET's answer is coherent with the client's next POST (which `404`s too).
- **Revocation.** The credential that opened a stream is re-validated on **every heartbeat tick**, so a revoked token or a signed-out session kills a *live* stream, not merely future attaches — the close frame says `credential_revoked`. Latency is one tick on a single server, but up to the 60 s token-cache TTL plus a tick across **replicas**: the cache and the session table are process-local, so a revoke handled by one replica reaches another replica's stream only when that replica re-reads the store. Treat CC6.2 revocation latency as bounded by that, not as instantaneous. An **unreachable** auth store is not a revocation: it is reported as indeterminate and buys a bounded 60 s grace window, after which the stream ends with the distinct reason `auth_unavailable`. That distinction exists so an auth-backend blip cannot cut every stream on the fleet at once, and so an operator can tell a security event from an outage.
- **Caps.** Every held-open SSE response pins one HTTP worker for its whole life, so concurrency is admission-controlled — and **every** streaming surface leases from the same budget (MCP GET, `GET /api/v1/events`, the dashboard executions drawer, the legacy `/events` stream), because the worker pool is what they all share (ADR-0034). Capacity is `--max-sse-streams` (default 128, and the worker pool is sized *from* it); `--mcp-max-streams-per-principal` (default 4) is an anti-monopoly policy for the MCP surface, not a capacity limit. A cap hit **rejects the newcomer** with `429` (`-32012`) carrying an honest `retry_after_ms` — it never evicts a live stream. Utilisation: `yuzu_http_held_open_responses / yuzu_http_held_open_capacity`.
- **Takeover.** A second GET on a session supersedes the first (the old stream closes with `superseded`) rather than being rejected: the common second GET is a client reconnecting across a zombie TCP the server has not noticed yet, and rejecting it would lock that client out for a full write-timeout. It is admitted without a cap check but still takes a lease — a superseded provider goes on pinning its HTTP worker until it drains, and an *uncounted* pinned worker is exactly the hole the budget exists to close. The pool is bounded structurally instead: a session holds at most one draining stream, so a *third* concurrent GET on the same session gets `429 stream_handover_pending` until the handover completes, and the budget reserves two workers for every stream it admits.
- **Close reasons** are wire-visible (a final `stream-closed` frame) and audited (`mcp.stream.attach` / `mcp.stream.close`): `client_disconnect`, `superseded`, `session_terminated`, `credential_revoked`, `auth_unavailable`.

In PR 2 the channel carries heartbeats and replayed frames; the producers arrive with PR 3 (`notifications/progress`). Metrics: `yuzu_mcp_sessions_active`, `yuzu_mcp_sessions_opened_total`, `yuzu_mcp_streams_active`, `yuzu_mcp_streams_handover_pending`, `yuzu_mcp_streams_cap` (the EFFECTIVE cap after the boot clamp), `yuzu_mcp_stream_replay_ring_evictions_total`, `yuzu_mcp_stream_frames_dropped_total`, `yuzu_mcp_stream_frames_too_large_total` (a frame exceeded the per-frame byte cap and was truncated before entering the ring — counted rather than only logged, because an unbounded warn-per-publish is a log-flood vector), `yuzu_mcp_stream_rejects_total{reason}`, `yuzu_mcp_stream_closes_total{reason}` (alert on `auth_unavailable` and `internal_error`).

**Shutdown:** httplib re-checks its shutdown flag between provider calls, so `stop()` drains live streams within about one heartbeat tick (~3 s, in parallel). A stream whose peer has stopped reading is bounded instead by the 30 s socket write timeout — size a container termination grace period above that if you run streaming clients.

## Phase 3 (Planned)

- Cross-surface / durable approval-ticket state (today the ticket lives in the shared `ApprovalManager` store, which is durable, but the MCP recall is stateless — no per-worker session).
- **MCP Streamable HTTP — progress bridge** (track 2f PR 3): `notifications/progress` for long-running tools (`_meta.progressToken`), published onto the GET channel above and onto SSE-on-POST. Same ADR-1005 Decision 15 / track 2f ladder; chaos merge-gate map: `docs/mcp-streamable-http-chaos-design.md`.
