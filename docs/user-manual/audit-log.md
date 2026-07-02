# Audit Log

Yuzu records every operator action as a structured audit event. The audit log
provides a tamper-evident trail suitable for compliance reporting, incident
investigation, and forwarding to external SIEM platforms such as Splunk or
Elastic.

> **Known issue in v0.9.0 (advisory YZA-2026-001):** audit rows for requests
> authenticated via `Authorization: Bearer` or `X-Yuzu-Token` (every MCP tool
> call and every REST automation using an API token) had an empty `principal`
> field. Cookie-authenticated dashboard activity was unaffected. Fixed forward
> in v0.10.0; pre-fix rows are not backfilled. Operators auditing a window that
> spans the v0.9.0 → v0.10.0 boundary should expect a bimodal `principal`
> distribution. See `CHANGELOG.md` for full remediation context.

## Storage

Audit events are persisted in a dedicated SQLite database using WAL
(Write-Ahead Logging) mode for high write throughput without blocking readers.

| Setting | Default | Description |
|---|---|---|
| Retention period | 365 days | Events older than this are deleted by background cleanup |
| Cleanup interval | 1 hour | How often the background thread prunes expired events |

## Event structure

Every audit event contains the following fields:

| Field | Type | Description |
|---|---|---|
| `timestamp` | integer (Unix epoch) | When the event occurred |
| `principal` | string | Username of the operator who performed the action |
| `principal_role` | string | Role of the principal at the time of the action (`admin`, `user`) |
| `action` | string | Dot-notated action identifier (see table below) |
| `target_type` | string | Category of the affected object (`Tag`, `Agent`, `Session`, etc.) |
| `target_id` | string | Identifier of the affected object |
| `detail` | string | Human-readable description or the new value |
| `source_ip` | string | IP address of the client that initiated the request |
| `user_agent` | string | HTTP User-Agent header value |
| `session_id` | string | Session cookie identifier (empty for API-token / Bearer / `X-Yuzu-Token` requests, which have no cookie) |
| `result` | string | Outcome: `success`, `denied`, or `failure`. See **Result vocabulary** below the actions table for the precise semantics of each value. |

## Logged actions

The following actions are recorded automatically. No operator configuration is
required.

> **MCP `mcp.query_responses` emits a pair of rows on a scope-filtered call.** When
> an agentic worker collects responses it is only partly entitled to (some agents
> outside its management groups), the tool writes a `result=denied` row (the
> access-boundary event — `detail` carries the distinct dropped-agent count) **and**
> a `result=success` row (the served, possibly-empty set), both under the same
> principal + correlation key. A SIEM rule must treat these as a pair for one call:
> the `denied` row is informational CC6.1 access-boundary evidence (an operator
> reached toward agents outside its scope and was filtered), **not** a failed call —
> do not alert on `mcp.query_responses` denials as errors on a scoped multi-operator
> deployment.

| Action | Target type | When |
|---|---|---|
| `auth.login` | Session | Operator logs in via the dashboard or API |
| `role.elevation.granted` | User | A pre-authorized operator activated a JIT admin elevation via `POST /api/v1/elevate` (SOC 2 CC6.3/CC6.6). `principal`=the operator, `principal_role=admin` (the effective role for the window), `result=ok`, `detail=duration_secs=<N> mfa=<oidc_amr\|local_totp> justification=<sanitised, ≤1KiB>` — `mfa=` is placed **before** the free-text `justification=` field so a crafted justification can never forge the factor token a first-match grep reads. The grant was MFA-step-up-gated; `mfa=oidc_amr` records that the second factor was an IdP-MFA assertion (OIDC `amr` claim) rather than local TOTP enrollment — an OIDC session's factor is NEVER a local namesake account's TOTP enrollment (the two identity sources are checked on disjoint code paths). |
| `role.elevation.denied` | User | `POST /api/v1/elevate` was refused. `result=denied`, `detail` names the reason, with **distinct reasons per identity source and cause** (never a single generic message): "not eligible" / "eligibility read failed" (fail-closed; also the outcome for an OIDC identity with no `users` row at all); for a **local** session, "no MFA enrolled" (no TOTP enrollment); for an **OIDC** session, "no MFA in SSO login (the IdP did not assert amr MFA)" (the current login carries no seeded `amr` proof) or "OIDC-amr elevation is disabled (--no-jit-oidc-amr-elevation)" (the toggle is off — OIDC sessions cannot elevate at all when disabled, they cannot fall back to a local TOTP step-up); "mfa_step_up_refused" (enrolled/proof present but stale). |
| `role.elevation.revoked` | User | An operator stepped their elevation down early via `POST /api/v1/elevate/revoke`. `result=ok`, `detail=was_elevated=<bool>`. (Passive expiry on window lapse is implicit from the `granted` row's `duration_secs` — no separate `role.elevation.expired` event in v1.) |
| `user.elevation_eligibility.set` | User | An admin set/cleared a user's JIT-elevation eligibility via `POST /api/v1/users/<name>/elevation-eligibility` (admin + MFA-step-up gated). `result=ok`, `detail=eligible=<bool>` (plus `elevations_cleared=<N>` when revoking dropped active windows); `result=denied`/`detail=self_grant_blocked` on a self-grant attempt; `result=error` on a store failure. |
| `audit.auth_sample.exported` | AuditLog | A caller pulled a pseudo-random authentication-surface evidence sample via `GET /api/v1/audit/auth-sample` (SOC 2 CC7.2). `target_id=auth-sample`; `detail=from=<epoch-or-0> to=<epoch-or-0> limit=<N> returned=<N>` so the window + sample size are on the chain. `result=success`. Permission gate: `AuditLog:Read`. Store-unavailable is a 503 (not an audited failure). If the audit-store write itself fails, the response carries `Sec-Audit-Failed: true` (the export still returns). |
| `auth.logout` | Session | Operator logs out |
| `auth.login_failed` | Session | Failed login attempt |
| `auth.breakglass.login` | User | The configured break-glass account (`--break-glass-user`) passed the password gate under `--auth-mode=sso-only` while **armed**. `result=ok` means the **password** was accepted — `detail` is explicit that no session is minted yet (the mandatory TOTP challenge still runs). Emitted at `Severity::kCritical`; paired with the metric `yuzu_auth_break_glass_login_total`. SOC 2 CC6.6. (Note: the sso-only denial of a *non*-break-glass local login is **not** audited per-attempt — it is the metric `yuzu_auth_local_disabled_total` only, to avoid audit-flood under credential spray; the boot-posture log is the activation evidence.) |
| `auth.breakglass.denied` | User | A break-glass login was **hard-denied** because the account has no MFA enrolled (cleared out-of-band after boot). `result=denied`, `Severity::kCritical`. Enrollment is deliberately **not** offered (it would defeat the second factor) — re-enroll the break-glass account out of band. SOC 2 CC6.6. |
| `auth.breakglass.armed` | User | `yuzu-server --break-glass-arm` armed the break-glass account for the configured window. `principal` = the **kernel OS identity** that ran the CLI (not the forgeable `USER` env var), `principal_role=break-glass`, `result=success`, `detail` carries the `armed_until` timestamp + window. The audit store is verified writable **before** the arm mutates, so the exemption is never granted without a record. SOC 2 CC6.6. |
| `session.revoke_all` | User | An admin force-logged out every active cookie session for a named user via `DELETE /api/v1/sessions?username=<name>`. `target_id=<username>`; `detail=count=<N>` (in-memory cookies wiped). `result=partial` with `detail=count=<N> db_error=true` if the AuthDB DELETE failed (operator should retry or restart). API tokens belonging to the user are NOT revoked by this action. |
| `session.revoke_all.self` | User | A user wiped all their own sessions via `DELETE /api/v1/sessions/me`, OR an admin supplied their own username to the admin path. The `/me` flow also revokes API tokens; `detail=count=<N> api_tokens_revoked=<M>`. `result=denied` if a non-interactive credential (MCP token, service-scoped token) attempted self-revoke. |
| `session.peer_mismatch` | Session | A gRPC Subscribe whose agent peer IP did not match the IP recorded at Register time. **Two outcomes share this action.** *Rejected* (`result=denied`, #1059 — a stolen-session signal): `detail` carries `agent_id=<id> register_ip=<ip> subscribe_ip=<ip> gateway_mode=<bool>` (plus `raw_peer=<peer>` when the presented peer was malformed and `subscribe_ip` is empty); the SIEM signal is `yuzu_grpc_subscribe_peer_mismatch_total{event="security"}`. *Tolerated* (`result=ok`, #1128 — a NAT-aware relaxation downgraded it): `detail` carries `agent_id=<id> outcome=advisory reason=<mtls_identity_match\|trusted_nat_cidr> register_ip=<ip> subscribe_ip=<ip>`; the SIEM signal is `yuzu_grpc_subscribe_peer_advisory_total{event="security",reason=…}`. `principal=agent:<agent_id>`; `target_id` is the `session_id`. SOC 2 CC7.2: the *denied* form is a high-signal security event; the *advisory* form is expected operational telemetry in NAT-traversal deployments (a spike there alone is benign; correlated with a *denied* spike it warrants investigation — see `docs/observability-conventions.md`). Security events route to the SIEM via Prometheus, not by tailing the audit store; this row is the paired forensic evidence. If the audit-store write fails, the gRPC response carries trailing metadata `x-yuzu-audit-failed: true` (see **gRPC audit-failure signal** below). |
| `session.identity_mismatch` | Session | A gRPC Subscribe was rejected because the mTLS client identity (cert CN/SAN) did not overlap the identity bound at Register time (#1118 — a stolen-session signal, the mTLS sibling of `session.peer_mismatch`). `principal=agent:<agent_id>`; `target_id` is the `session_id`; `detail` carries `agent_id=<id> reason=mtls_identity_mismatch presented=[<cert CN/SANs at Subscribe>] bound=[<cert CN/SANs at Register>]` so an auditor can identify the cert used in the attempt. `result=denied`. SOC 2 CC7.2: high-signal security event. **The SIEM signal is the Prometheus counter** `yuzu_grpc_subscribe_identity_mismatch_total{event="security"}`; this audit row is the paired forensic evidence. On audit-store write failure the gRPC response carries `x-yuzu-audit-failed: true` (see **gRPC audit-failure signal** below). |
| `tag.set` | Tag | A tag is created or updated on an agent |
| `tag.delete` | Tag | A tag is removed from an agent |
| `instruction.execute` | Instruction | An instruction is dispatched to one or more agents |
| `instruction.approve` | Instruction | An instruction pending approval is approved |
| `instruction.deny` | Instruction | An instruction pending approval is denied |
| `instruction.import` | InstructionDefinition | An InstructionDefinition JSON envelope was submitted via `POST /api/instructions/import`. On `result=success`: `target_id` is the new definition's id; `detail` is empty. On `result=denied`: `target_id` is empty (no id assigned on rejection); `detail` carries the store-returned error string, which begins with a stable SIEM-keyable token — known tokens are `duplicate_id` (409 conflict), `signature verification failed for instruction — content may have been tampered with` (#1073 / W7.4), `instruction-import is unsigned and signature enforcement is enabled` (#1073), `instruction-import has incomplete signing metadata` (#1073), `instruction-import has signing field of wrong JSON type` (#1073 R1), `signature length invalid` / `publicKey length invalid` (#1073 R1 DoS amplification guard), `instruction-import has signature + publicKey but no yaml_source` (#1073). Permission gate: `InstructionDefinition:Write`. SOC 2 CC6.7: every import attempt is logged regardless of outcome; if the audit-store write itself fails, the response carries the `Sec-Audit-Failed: true` header AND an `audit_emitted=false` field in the JSON body (PR #883 evidence-chain pattern). |
| `enrollment.approve` | Agent | A pending agent enrollment is approved |
| `enrollment.deny` | Agent | A pending agent enrollment is denied |
| `enrollment.token_create` | EnrollmentToken | An enrollment token is generated |
| `enrollment.token_consumed` | EnrollmentToken | An agent auto-enrolled by presenting an enrollment token (gRPC Register — direct or gateway-proxied). `result=success` when the token is accepted; `result=failure` when rejected (invalid/expired/already-consumed). `target_id` is the token id (success) or the token-hash prefix (failure); `detail` carries `variant=<...>` and, on the gateway path, `source=gateway_proxy gateway_ip=<ip> [origin_observed=false]`. **Gateway-path `source_ip` caveat (#1064):** the server records the agent's origin IP as `source_ip` when the gateway populates `RegisterRequest.gateway_observed_peer`; until the gateway-side population follow-up ships, that field is empty and `source_ip` falls back to the gateway node's IP (flagged `origin_observed=false`) — see the gateway.md "gateway origin-IP attribution" known limitation. On audit-store write failure the gRPC response carries `x-yuzu-audit-failed: true` trailing metadata and the analytics severity escalates to error (#1063 / #1065). |
| `settings.update` | Setting | A server setting is changed |
| `rbac.role_assign` | Principal | A role is assigned to a principal |
| `rbac.role_revoke` | Principal | A role is revoked from a principal |
| `management_group.create` | ManagementGroup | A management group is created |
| `management_group.delete` | ManagementGroup | A management group is deleted |
| `management_group.add_member` | ManagementGroup | An agent is added to a management group |
| `management_group.remove_member` | ManagementGroup | An agent is removed from a management group |
| `management_group.assign_role` | ManagementGroup | A role is assigned to a principal on a management group |
| `management_group.unassign_role` | ManagementGroup | A role is unassigned from a principal on a management group |
| `api_token.create` | ApiToken | An API token is generated |
| `api_token.revoke` | ApiToken | An API token is revoked |
| `quarantine.enable` | Security | A device is placed in quarantine |
| `quarantine.disable` | Security | A device is released from quarantine |
| `policy.evaluate` | Policy | A forced compliance check was triggered via `POST /api/policies/{id}/evaluate`. `target_id` is the policy id; on `result=success` `detail` is `execution_id=<id>`. The `409` branch (no check instruction / no matching agents) rejects without an audit row. Permission gate: `Policy:Execute`. |
| `policy.remediate` | Policy | A manual remediation was triggered via `POST /api/policies/{id}/remediate`. `result` is `success` or `denied`. On success: `detail` is `execution_id=<id> agents=<N>`. On denied: `detail` is the rejection reason (no fix instruction / no in-scope agents / no non_compliant agents). Remediation is always operator-initiated, never automatic. Permission gate: `Policy:Execute`. |
| `preflight.run` | Scope | An operator ran a `/auto` pre-flight check via `POST /fragments/auto/run`. `target_id` is the management-group id scoped to the run, or `all-visible` when no group filter was applied; `detail` carries `run=<id> checks=<N> devices=<N>`. `result=success`, or `no_devices` when the chosen scope resolved to no visible devices (a no-op, not a denial). Permission gates: `Infrastructure:Read` + `Execution:Execute`. |
| `preflight.run.delete` | Scope | An operator deleted a pre-flight run from the saved-runs rail via `POST /fragments/auto/delete?run=<id>`. `target_id` is the run id; `detail` carries `run=<id> scope=<label>`. `result=success` when an owned row was removed, `noop` when the run id was unknown or not owner-visible (a no-op rather than a permission rejection — prevents cross-owner id enumeration). Permission gate: `Execution:Execute`; owner-scoped at the store seam (`created_by` must match). |
| `dex.app_perf.compare` | GuaranteedState | An operator ran a `/auto` **Verify** before/after app-performance **aggregate** comparison — REST `GET /api/v1/dex/perf/compare` or the dashboard VERIFY `/run` fragment. `target_id` is the cohort (management-group) id; `detail` carries `app=<name> base=<v> cand=<v> cohort=<N> paired=<N> view=aggregate cid=<cid>` (`paired=` so a singleton aggregate — effectively one machine's data — is distinguishable). **Operational, set-and-proceed**: the read is *recorded* (the accountability that stands in for the absent cohort floor — Verify deliberately has no minimum cohort size), but a dropped audit row sets the `Sec-Audit-Failed` response header rather than blocking the read. The aggregate carries **no per-machine identity**. Permission gate: `GuaranteedState:Read`. (Over MCP, the `compare_app_perf_versions` tool is recorded under the generic `mcp.compare_app_perf_versions` tool-call audit, not this verb — but its detail carries the same subject (`group=… app=… base=… cand=… cohort=… paired=…`), and a dropped row surfaces as `audit_persisted:false` in the result body since MCP has no `Sec-Audit-Failed` header. MCP exposes only the identity-free aggregate, no per-machine drill.) |
| `dex.app_perf.compare.drill` | GuaranteedState | An operator opened the **per-machine pairs** of a `/auto` Verify comparison (the dashboard `/fragments/auto/verify/drill`, reached by a deliberate "Show per-machine pairs" click). This is the per-device behavioural-PII view, so it carries its **own** verb (distinct from the identity-free aggregate above) to keep per-machine access independently countable. `target_id` is the cohort id; `detail` carries `app=<name> base=<v> cand=<v> cid=<cid>`. Operational set-and-proceed (the HTML surface renders even on a lost audit row, setting `Sec-Audit-Failed`). There is **no REST or MCP** twin of the drill — the per-machine pairs are dashboard-only. Permission gate: `GuaranteedState:Read`. |
| `deployment.create` | SoftwareDeployment | An operator deployed an installer to a pre-flight run's go-cohort via `POST /fragments/auto/deploy/run`. `target_id` is the new `deployment_id`; `detail` carries `run=<source_run_id> file=<filename> sha256=<hash> url=<url> devices=<N>` — the **SHA-256 is the content identity of the binary executed on the fleet**. `result=success` (deployment created + first advance), `resumed` (an in-flight deployment for this run already existed — re-attached, not re-created, so the installer is not run twice; `target_id` is the existing deployment), or `no_devices` (the go-cohort was empty after re-intersecting with the operator's current visible set — a no-op). Permission gates: `Infrastructure:Read` + `SoftwareDeployment:Execute`. |
| `deployment.advance` | SoftwareDeployment | The deployment engine was ticked via the result-poll `GET /fragments/auto/deploy/result`. Emitted on **every poll tick** while the page is open (up to ~600 ticks before the page stops self-polling); `result=success`. `target_id` is the `deployment_id`. SIEM: a burst of these rows with one `deployment_id` is a single open-page session, not repeated operator intent (auditing only ticks that actually dispatch is a tracked follow-up). Permission gates: `SoftwareDeployment:Read` + `SoftwareDeployment:Execute`. |
| `deployment.delete` | SoftwareDeployment | An operator deleted a deployment via `POST /fragments/auto/deploy/delete?dep=<id>`. `target_id` is the `deployment_id`. `result=success` when an owned row was removed, `noop` when the id was unknown or not owner-visible (prevents cross-owner enumeration — same posture as `preflight.run.delete`). Permission gate: `SoftwareDeployment:Execute`; owner-scoped at the store seam. |
| `cert.reload` | TlsCertificate | Certificate hot-reload attempted; detail contains outcome (success or failure reason) |
| `guaranteed_state.rule.create` | GuaranteedState | A Guaranteed State rule is created. On 400 (missing required fields), 409 (rule_id/name conflict), or RBAC rejection, emits `result=denied` with the store error in `detail`. |
| `guaranteed_state.rule.update` | GuaranteedState | A Guaranteed State rule is updated (version is incremented on every successful update). On 404 (rule not found), 400 (invalid JSON body — `detail` is the literal string `"invalid JSON body"`), 409 (name conflict), or RBAC rejection, emits `result=denied`. |
| `guaranteed_state.rule.delete` | GuaranteedState | A Guaranteed State rule is deleted. On 404 or RBAC rejection, emits `result=denied`. |
| `guaranteed_state.push` | GuaranteedState | A push of the active rule set to scoped agents is accepted. `target_id` is empty (pushes are fleet-level, not per-entity); `detail` carries `rules=<N> full_sync=<bool> scope="<sanitised-expr>" fan_out_deferred_pr3=true`. The scope value in `detail` is **sanitised before embedding**: `"` and `\` are backslash-escaped, C0 control bytes (0x00–0x1F, DEL) are dropped. SIEM parsers reconstructing the original scope expression must account for this normalisation — a raw operator input of `env="prod"` appears in the audit as `scope="env=\"prod\""`. The `fan_out_deferred_pr3=true` marker means the REST call is accepted and persisted server-side but agent fan-out is not wired until Guardian PR 3; SIEM rules that infer "rules were delivered to agents" from this event are premature until that flag disappears. Non-object JSON bodies are rejected with `result=denied` and `detail="invalid JSON body"`. |
| `guaranteed_state.baseline.create` | GuaranteedState | A Guardian Baseline (the deployable collection of Guards) is created from the dashboard. `detail` carries `<name> (members=<N>, draft)`. RBAC rejection (`GuaranteedState:Write`) is audited centrally under `auth.permission_required`. |
| `guaranteed_state.baseline.update` | GuaranteedState | A Baseline is renamed or its member set edited (`GuaranteedState:Write`). `detail` carries `<name> (members=<N>)`. For a *deployed* Baseline the change is staged — it reaches agents only on re-deploy. |
| `guaranteed_state.baseline.deploy` | GuaranteedState | A Baseline is deployed or re-deployed (`GuaranteedState:Push`): its member set is snapshotted and the fleet converges to the union of deployed Baselines' enabled members. `detail` carries `<name> deployed fleet-wide (agents=<N>, members=<M>)` — or `(push not wired/failed, members=<M>)` if the push fan-out is unavailable. Store-unavailable / no-such-baseline precondition failures emit `result=denied`. |
| `guaranteed_state.baseline.delete` | GuaranteedState | A Baseline is deleted (`GuaranteedState:Delete`); if it was deployed the fleet re-converges to remove its Guards where no other deployed Baseline still delivers them. `detail` carries `<name> (was deployed; reconciled agents=<N>)` (where `<N>` is `-2` if the push was not wired) or `<name> (draft)`. Store-unavailable / no-such-baseline emit `result=denied`. |
| `dex.device.view` | Agent | An operator opened a **single device's DEX signal history** — the behavioral view that reveals which applications a person runs. Emitted by the dashboard per-device drill-down (`GET /fragments/dex/device?id=<agent_id>`), by the **shared device page's DEX lens** (`GET /fragments/device/dex?id=<agent_id>`), **and** by the agent-scoped REST query (`GET /api/v1/guaranteed-state/events?agent_id=<agent_id>`, which returns that device's `detail_json`). `target_id` is the `agent_id`; permission gate `GuaranteedState:Read`. A bulk events query with no `agent_id` filter is *not* individual-identifying and is not audited here. Emitted `result=success` for the access attempt (access-transparency of the open). |
| `dex.observation.view` | Agent | An operator clicked a **single signal-history row** on a DEX device drill-down, loading the **per-event observation detail panel** (every captured projection field for that one event: subject / reason / symbolic / component / metric / platform / exact timestamp / event ID). Emitted by `GET /fragments/dex/observation?agent_id=<agent_id>&event_id=<event_id>`; the `event_id` is bound to the scoped `agent_id`, so a guessed or foreign event ID returns an **opaque 200 placeholder** (byte-identical to "no such event" — the route returns 200 not 404 so the dashboard's htmx swap:false-on-4xx still renders it) and reveals nothing. `target_id` is the `agent_id`; permission gate `GuaranteedState:Read`. The `detail` records the opened event's **obs_type and bound event_id**, so usage-class opens (e.g. `process.crashed` / `process.hung` — what a person ran) stay **separately countable** from machine-class opens for works-council access-audit purposes (same rationale as `dex.device.procperf.query`). Behavioral PII — reveals which specific application event a person's device generated at a given moment. As an HTML dashboard fragment it is **set-and-proceed** (not fail-closed like the REST per-device endpoints): if the audit row cannot persist the response carries `Sec-Audit-Failed: true` and the panel **still renders** (#1647 — the emit routes through the shared `emit_behavioral_audit` chokepoint, which also catches a throwing audit sink). |
| `guardian.device.view` | Agent | An operator opened the **Guardian lens** on the shared device page (`GET /fragments/device/guardian?id=<agent_id>`) — per-guard compliance state for that device. `target_id` is the `agent_id`; permission gate `GuaranteedState:Read`. |
| `device.live.uptime` | Agent | An operator clicked **Get live info** on a device page and the uptime panel dispatched a live `os_info/uptime` instruction to the device. Execute-gated (`Execution:Execute`, beyond `GuaranteedState:Read`); `target_id` is the `agent_id`, `detail` records the agent count reached and the `command_id`. Machine-health telemetry. **Two emitters, by design:** the dashboard panel audits **post-dispatch** (`result=dispatched`/`no_agents`); the REST endpoint (`POST /api/v1/dex/devices/{id}/live?kind=uptime`) audits **pre-dispatch** (`result=requested`, `detail` carries `cid=<correlation_id>`) and fails closed (`503` + `Sec-Audit-Failed`, no dispatch) if the row cannot persist. The dashboard live + lens sites also set `Sec-Audit-Failed` on a persist failure (#1585). Aligning the dashboard emitter to pre-dispatch is a tracked follow-up. |
| `device.live.processes` | Agent | An operator clicked **Get live info** and the running-process panel dispatched a live `processes/list_hashed` instruction (PID, name, and the SHA-256 of each on-disk executable image). **Usage-class behavioral telemetry** — reveals which programs a person is running. Deliberately a **separate verb** from `device.live.uptime` so usage-class reads stay separately countable for works-council access-audit purposes (same rationale as `dex.device.procperf.query`). Execute-gated; `target_id` is the `agent_id`, `detail` records the agent count and `command_id`. No hash/process data leaves the device until an operator explicitly dispatches this panel. **Persistence:** the dispatched result (process names, paths, SHA-256) is stored in `responses.db` for `response_retention_days` like any command result, so it is also a DSAR/data-inventory source and is retrievable via the standard response-store API under `Execution:Read` — the works-council "separately countable" guarantee covers the *dispatch* (this verb), not a later read-back of the persisted row. **Note:** the dashboard's Get-live-info Processes card now dispatches `process_tree` (parent PID + SHA-256 + connection join) instead; `device.live.processes` (flat `processes/list_hashed`) remains valid for REST/scripted callers dispatching that action directly. **SIEM / works-council migration:** a query previously keyed on `device.live.processes` to count dashboard process reads should add `device.live.process_tree`, or dashboard process reads will be silently undercounted from this release onward. **Two emitters** (same as `device.live.uptime`): the dashboard panel audits post-dispatch; the REST endpoint audits pre-dispatch (`result=requested`) and fails closed (`503` + `Sec-Audit-Failed`) on a persist failure. |
| `device.live.process_tree` | Agent | **Get live info** Processes card — dispatched `processes/list_tree` (PID, parent PID, name, SHA-256) **plus** `network_diag/connections` (joined to the tree by PID), reconstructed into a parent→child tree with per-process network endpoints. **Usage-class behavioral telemetry** (reveals what a person runs + where it connects); a separate verb from `device.live.uptime`. Execute-gated; `target_id` is the `agent_id`. The tree + connection results persist in `responses.db` like any command result (same DSAR/read-back note as `device.live.processes`). **Currently one emitter** — the dashboard `/run` route, post-dispatch (`result=dispatched`/`no_agents`); a `process_tree` card is dashboard-only until the REST/JSON A1 backfill (#1649), at which point a second pre-dispatch (`result=requested`) emitter will be added to match `device.live.uptime`. |
| `device.live.services` | Agent | **Get live info** Services card — dispatched `services/list` (service run state). Machine-health telemetry. Execute-gated; `target_id` is the `agent_id`. |
| `device.live.netconfig` | Agent | **Get live info** Adapters & IP card — dispatched `network_config/ip_addresses`. Machine-health telemetry. Execute-gated. |
| `device.live.arp` | Agent | **Get live info** ARP card — dispatched `network_config/arp` (host ARP / IPv6 neighbour table; Windows-only). Machine-health telemetry. Execute-gated. |
| `device.live.dns_cache` | Agent | **Get live info** DNS-cache card — dispatched `network_config/dns_cache` (resolver cache; Windows-only). DNS-cache is device-level usage-class telemetry (names a person resolved). Execute-gated. |
| `device.live.listening` | Agent | **Get live info** Listening-ports card — dispatched `network_diag/listening`. Machine-health telemetry. Execute-gated. |
| `device.live.connections` | Agent | **Get live info** Active-connections card — dispatched `network_diag/connections` (established TCP). Usage-class behavioral telemetry. Execute-gated. |
| `device.live.users` | Agent | **Get live info** Logged-in-users card — dispatched `users/logged_on`. Usage-class behavioral telemetry (who is signed in). Execute-gated. |
| `device.live.capture_sources` | Agent | **Get live info** Capture-sources card — dispatched `tar/status` to show which TAR warehouse sources are capturing locally (read-only; configuration stays on the TAR page). Machine-health/configuration telemetry. Execute-gated. |
| `device.live.disk` | Agent | **Get live info** Disk-space card — dispatched `disk_space/free` to report free/total bytes for the root volume. Machine-health telemetry (not behavioral — no per-user content). Execute-gated (`Execution:Execute`); `target_id` is the `agent_id`. Emitted post-dispatch by the dashboard `/run` route (`result=dispatched`/`no_agents`). |
| `dex.device.perf.query` | Agent | An operator clicked **Load performance** on a DEX device drill-down, dispatching a live read-only `$Perf_Hourly` TAR query to that device. Execute-gated (beyond `GuaranteedState:Read`); `target_id` is the `agent_id`, `detail` records the agent count reached and the `command_id`. Machine-health telemetry — distinct from the behavioral `dex.device.view`. |
| `dex.device.procperf.query` | Agent | An operator clicked **Load applications** on a DEX device drill-down, dispatching a live `$ProcPerf_Hourly` query (per-application image names — **usage-class telemetry**, observes what people run). Deliberately a **separate verb** from `dex.device.perf.query` so usage-class reads stay separately countable for works-council access-audit purposes. Execute-gated; `target_id` is the `agent_id`, `detail` records the agent count and `command_id`. The subsequent result polls require this dispatch's `command_id`, so no usage-class read occurs without a counted dispatch row. |
| `inventory.software.query` | Inventory | A **which-devices-run-X** fleet software query — emitted by the REST endpoint (`GET /api/v1/inventory/software`) **and** the `/inventory` dashboard **Find software** tab. Machine-scope installed-software data (no per-user/PII — lower sensitivity than the behavioral device lenses), so **set-and-proceed**. `target_id` is `name=<title>` / `agent=<id>` / `fleet`. `result=success` carries `rows=<n>` for the visible rows; a per-row management-group drop emits **both** a `result=denied` row (recording the dropped device count, for cross-operator isolation evidence) **and** the `result=success` row in the same request — a SIEM rule keying on `denied` must expect a paired `success`; a store degrade emits `result=failure` (REST returns `503`, the dashboard renders the "unavailable" banner — never a silent empty, ADR-0016 §7). Gate `Inventory:Read`. |
| `inventory.software.catalog` | Inventory | An operator opened the `/inventory` **Software** tab — the fleet software catalogue aggregate (title → install count → version count). **FLEET-WIDE: not management-group scoped** (ADR-0017 confinement is inert under the global `Inventory:Read` gate; the counts span all groups and the UI says so). Machine-scope, set-and-proceed. `target_id` is `fleet` or `q=<filter>`. `result=success` carries `titles=<n>`; a store degrade (incl. the aggregate's statement-timeout) emits `result=failure`. Gate `Inventory:Read`. |
| `inventory.software.versions` | Inventory | An operator drilled into one title's **installs per version** (`/inventory` Software tab → title click). Fleet-wide (same scope note as `inventory.software.catalog`). `target_id` is `name=<title>`; `result=success` carries `versions=<n>`, a degrade emits `result=failure`. Gate `Inventory:Read`. |
| `inventory.device.software` | Inventory | An operator opened **one device's installed software** (`/inventory` Devices tab → device click). Machine-scope software data, **set-and-proceed** (HTML fragment renders even if the audit row can't persist). `target_id` is `agent=<id>`; `result=success` carries `rows=<n>`, a store degrade emits `result=failure`. Gated **per device** on `Inventory:Read` for that device's management group (`scoped_perm_fn` — the tier + management-group chokepoint), so an operator only reads a device in their scope. |
| `inventory.devices` | Inventory | An operator opened the `/inventory` **Devices** tab — the device roster (hostnames + agent_ids + OS + online/last-seen), **plus the device-CI columns** (serial, model, CPU cores/threads, RAM) joined onto each row from `DeviceInventoryStore`. Because serial is a device-persistent identifier (GDPR personal data per ADR-0016), this verb is emitted via the **behavioural-PII audit tier** (`Sec-Audit-Failed` header on a persist failure) rather than the lighter machine-scope tier the other `inventory.*` list verbs use. The CI join is confinement-preserving relative to whatever roster the route renders (it only ever looks up an agent ID already present in that roster, so an out-of-scope device's CI is never attached or disclosed — regression-tested); **the roster itself gates on the global `Inventory:Read`, and per-operator management-group confinement of that roster is designed for, not yet verified effective** (ADR-0017 — the same inert-list-scoping class as the `inventory.software.query` Find verb above), not a per-device gate. `target_id` is `fleet`; `result=success` carries `devices=<n> (incl. CI columns: serial/model/cpu/ram)`; `result=failure` carries `devices=<n> (CI store degraded; roster rendered without CI columns)` when the CI-enrichment join degrades on a populated roster, or `devices=0 (device roster or CI store unavailable)` when the rendered roster is empty AND the CI-enrichment join degrades — reachable either from a legitimately empty visible fleet coinciding with a CI-store hiccup, or (practically unreachable, since ADR-0012 fails the server closed at boot) the roster provider itself being down — either way the roster still renders whatever it has, only the audit-fidelity signal changes. Set-and-proceed: the HTML fragment still renders on an audit-persist failure. (Distinct from `inventory.device.software`/`inventory.device.ci`, the per-device drill verbs, which are per-device scoped + audited.) |
| `inventory.device.ci` | Inventory | An operator opened **one device's CI record** (`/inventory` Devices tab → device click → CI panel: manufacturer, model, serial, system UUID, domain/OU, BIOS, CPU, memory, MAC addresses, NIC count, OS name/version/build, architecture, first/last-synced). Device-persistent identifiers (GDPR personal data per ADR-0016), so this uses the **behavioural-PII audit tier** — same as `dex.device.view`/`tar.dns.read`/`tar.arp.read` — rather than the lighter tier `inventory.device.software` (installed-software content, not a device-persistent identifier) uses. `target_id` is `agent=<id>`; `result=success` carries `detail=found` (a CI record exists) or `detail=absent` (the device hasn't completed its first `device_ci` sync yet — NOT a failure); `result=failure` carries `detail=store degraded` (the store itself could not be read). Gated **per device** on `Inventory:Read` for that device's management group (`scoped_perm_fn`), so an operator only reads a device in their scope. |
| `settings.dex_alerts.cohort_export` | RuntimeConfig | An admin set or cleared the cohort metrics export tag key via Settings → DEX alerts. `target_id` is `dex_cohort_export_key`; `detail` carries `export_key=<key>` or `export disabled`. The runtime-config store keeps no history, so this row is the change-management evidence for what cohort labels were exported when. |
| `tar.status.scan` | Infrastructure | An operator clicked **Scan fleet** on the TAR dashboard page (`/tar`). A `tar.status` command was dispatched to the operator's visible-agent set. `detail` carries the count of agents the dispatch reached (e.g. `dispatched to 47 agent(s) in scope`). One row per Scan button press; no row on page-load Refresh. |
| `tar.source.reenable` | Infrastructure | An operator clicked **Re-enable** on a row of the TAR retention-paused list and a `tar.configure` command with `<source>_enabled=true` was dispatched to a single device. `detail` carries `device=<id> source=<process|tcp|service|user>` on success. Failures emit `result=failure` with `detail` set to the real reason (`scope_violation source=<src>` for out-of-scope device IDs, `agent_not_connected source=<src>` for connected-but-zero-sent dispatches) so SIEM rules can distinguish a forged-form attempt from a transient connectivity issue — even though the HTTP response body is identical (`Agent not reachable.` 404) for both, to deny enumeration. |
| `tar.source.purge` | Infrastructure | An operator clicked **Purge data** on a row of the TAR retention-paused list (Phase 15.A) and a destructive `tar.purge_source` command was dispatched to a single device — dropping **all** warehouse rows for that source (`<source>_{live,hourly,daily,monthly}`) while leaving the collector **paused**. Gated on `Infrastructure:Delete` (a higher tier than re-enable) plus the operator's RBAC visibility on the device; the operator must type the device hostname to confirm. `detail` carries `device=<id> source=<process\|tcp\|service\|user>` on success (`rbac_denied` on the permission gate; `scope_violation`/`agent_not_connected` on failure, same 404-collapse as re-enable). The agent refuses (`source_not_paused`) if the source is still enabled. `rows_deleted` is computed agent-side and appears in the command's response record, not this dispatch row. The structured REST equivalent (`POST /api/v1/tar/retention-paused/purge`) writes this verb with `result=requested` **before** dispatch (audit-on-open, fail-closed — no dispatch if the row can't persist), plus `detail cid=<correlation-id>`. **Caveat:** a purge issued through the generic `POST /api/command` escape hatch is currently audited under the generic `command.dispatch` verb (with `detail` `tar:purge_source`), **not** this `tar.source.purge` verb — SIEM rules keyed only on `tar.source.purge` will miss that path (tracked in Tr3kkR/Yuzu#1787). |
| `tar.process_tree.read` | Agent | An operator reconstructed a process tree for one device from its local TAR warehouse via the TAR dashboard (`/tar`, Frame 3). **Usage-class behavioral telemetry** — surfaces process names + PIDs + owning user + per-process remote IP:port, and (on Linux/macOS) command lines. Emitted on **two** points so the access is recorded even on failure (parity with `device.live.*`): a **dispatch** row at the live-query send (`result=dispatched` when ≥1 agent reached, `result=no_agents` when offline; `detail` = `dispatch preset=<p> command_id=<id>`), and a **success** row after the tree renders (`detail` = `preset=<p> from=<epoch> to=<epoch> nodes=<n> anomalies=<n> os=<os> conns=<0|1>` — `os` distinguishes a names-only Windows read from a behavioral Linux/macOS read; `conns=1` means per-process connection data was shown). `target_id` is the `agent_id`. Viewing the frame needs `Infrastructure:Read`; reconstruction is Execute-gated (`Execution:Execute`) and scoped to the device's management group. The reconstruction is cached under a CSPRNG token bound to the originating operator. `preset` is canonicalized to a fixed allowlist and `os` is normalized to `{windows,linux,macos,?}` before interpolation, so neither agent- nor operator-controlled input can forge an audit field (#1290 posture). A **failure** row (`detail = csprng_unavailable`) is emitted if secure token generation fails (entropy exhaustion) — no tree is cached. |
| `tar.process_tree.detail` | Agent | An operator opened the detail panel for one process node from a cached reconstruction (a row click in `/tar` Frame 3). **Usage-class** — surfaces that node's path/command line (Linux/macOS), owning user, anomaly evidence, and full per-PID remote IP:port table. One row per drilldown (intentionally per-click, the works-council "who viewed which process" posture; mirrors `dex.signal.view`). `target_id` is the `agent_id`; `detail` = `node=<id> os=<windows\|linux\|macos\|?>`. Gated identically to a reconstruction — `Infrastructure:Read` + `Execution:Execute` scoped to the device — **and** bound to the originating session: a predicted or leaked cache token can't be replayed by a different operator. |
| `tar.dns.read` | Agent | The DNS-cache panel was rendered for a device in the TAR process-tree pane (`GET /fragments/tar/process-tree/device-net`, ADR-0015). **Usage-class telemetry** — the device DNS resolver cache reveals which domains the host resolved (device-level state; **no per-process attribution**). Emitted at **dispatch** (`result=dispatched` when ≥1 agent reached, `result=no_agents` when offline; `detail` = `command_id=<id>`). `target_id` is the `agent_id`. Requires `Infrastructure:Read` + `Execution:Execute` scoped to the device. **Separately countable from `tar.arp.read`** for works-council access-audit purposes. |
| `tar.arp.read` | Agent | The ARP-table panel was rendered for a device in the TAR process-tree pane (same route as `tar.dns.read`, ADR-0015). Surfaces the host ARP / neighbour table (IP↔MAC bindings per interface) — Layer-2 topology, lower sensitivity than DNS but security-relevant (ARP-spoofing forensics). Dispatch-time emission + gating identical to `tar.dns.read`; kept a distinct verb so DNS PII access stays separately countable. |
| `tar.sources.read` | Agent | An operator opened the TAR **Capture sources** frame for a device (`GET /fragments/tar/capture-sources/load`, ADR-0015), dispatching `tar.status` + `tar.compatibility` to read the device's per-source enable/support state. `detail` = `command_id=<id>`. `target_id` is the `agent_id`. Requires `Infrastructure:Read` + `Execution:Execute` scoped to the device. |
| `tar.sources.configure` | Infrastructure | An operator pushed staged capture-source enable/disable changes via the TAR Capture-sources frame (`POST /fragments/tar/capture-sources/push`, ADR-0015) — **one row per changed source** (each a `tar.configure <source>_enabled` dispatch). `detail` = `<source>_enabled=<true\|false> command_id=<id>`. Enabling `dns` (usage-class PII) is captured here for works-council evidence. Requires `Infrastructure:Read` + `Execution:Execute` scoped to the device. |
| `execution.visualization.fetch` | Execution | Chart-ready JSON was rendered for an execution's response set via `GET /api/v1/executions/{id}/visualization` (issue #253 / #587). `target_id` is the `command_id`; `detail` carries `<definition_id> index=<N>` on success — with ` scope_dropped=<N>` appended when out-of-scope agents' rows were dropped by the management-group filter (#1634) — or `<definition_id> reason=<r>` on the failure path where `<r>` is one of `missing_definition_id`, `malformed_definition_id`, `definition_not_found`, `no_visualization`, `index_oor`. Permission gate: `Response:Read`. **Management-group scoping is NOT yet effective for normal operators (#1634, partial)** — a per-agent filter runs before the chart transform but is inert under the current global gate (a global `Response:Read` holder sees all agents); `scope_dropped=<N>` is non-zero today only in the fail-closed corrupt-`rbac.db` path. `rows_capped` is computed pre-filter. The `command.dispatch` event (above, when emitted from the dashboard) appends `definition_id=<id>` to its `detail` when the dashboard reverse-resolves a chart-bearing definition, so SIEM can join `command.dispatch` to the subsequent `execution.visualization.fetch` by `definition_id`. |
| `response.read` | Execution | A management-group scope filter dropped one or more out-of-scope agents' rows from a legacy response read — `GET /api/responses/{id}` (`surface=get`), `GET /api/responses/{id}/aggregate` (`surface=aggregate`), or `GET /api/responses/{id}/export` (`surface=export`) (#1634). Emitted as `result=denied` ONLY when a drop occurred (the happy, nothing-dropped path is not separately audited on these legacy handlers); `target_id` is the `instruction_id`; `detail` carries `scope_dropped=<N> surface=<get\|aggregate\|export>` where `<N>` is the count of DISTINCT out-of-scope agents filtered out. The MCP `aggregate_responses` tool records the equivalent drop as its own `mcp.aggregate_responses` `result=denied` row; the visualization endpoint records it inline via `scope_dropped=<N>` on its `execution.visualization.fetch` success detail (above). Permission gate: `Response:Read`. **Current trigger scope (#1634, partial):** because per-management-group scoping is not yet effective for normal operators (a confined operator is 403'd at the global gate before the filter runs), under normal RBAC operation this verb fires only in the fail-closed corrupt-`rbac.db` path (all distinct agents dropped at once) — a SIEM alert keyed on it should not expect it during normal scoped reads until the #1634 gate lands. |
| `plugin_signing.bundle.uploaded` | PluginTrustBundle | An admin uploaded a PEM trust bundle via Settings → Plugin Code Signing. `detail` carries `<N> cert(s), sha256=<hex>` on success. On `result=failure` (PEM validation rejected the input — empty body, missing markers, no parsable cert, hashing failure, etc.) `detail` carries the validation error string. Audit row is emitted on both branches so a SIEM rule on `failure` can detect malformed-upload probing. |
| `plugin_signing.bundle.cleared` | PluginTrustBundle | An admin removed the trust bundle (Settings → Plugin Code Signing → Remove). `detail` carries `file removed` (a file existed and was deleted) or `no file present` (clear was a no-op). Always emits `success` unless the require-flag DB write fails first, in which case `result=failure` and `detail` carries the store error — and the file is **not** removed (two-phase commit prevents the disk/DB-flag desync). |
| `plugin_signing.require.changed` | RuntimeConfig | An admin toggled "Require signed plugins" via Settings. `target_id` is `plugin_signing_required`, `detail` carries the new value (`"true"` or `"false"`). Emitted on every change including no-op idempotent re-saves. |
| `response_template.create` | InstructionDefinition | A response-view template was created via `POST /api/v1/definitions/{id}/response-templates` (issue #254 / Phase 8.2). `target_id` is the definition id; `detail` is the new template id on success, or `reason=<r>` on the audit path. RBAC denials, 400 (malformed id / invalid JSON / validation), 404 (definition not found), and 413 (body too large) emit `result=denied`; 500 (persist failure) emits `result=failure`. Reasons: `malformed_definition_id`, `body_too_large`, `invalid_json`, `definition_not_found`, `validation_failed`, `persist_failure`. Permission gate: `InstructionDefinition:Write`. |
| `response_template.update` | InstructionDefinition | A response-view template was replaced via `PUT /api/v1/definitions/{id}/response-templates/{tid}` (issue #254). `target_id` is the definition id; `detail` is the template id on success, or `reason=<r>` on the audit path. 4xx branches emit `result=denied`; 500 persist failure emits `result=failure`. Reasons: `malformed_id`, `reserved_id`, `body_too_large`, `invalid_json`, `definition_not_found`, `template_not_found`, `validation_failed`, `persist_failure`. Permission gate: `InstructionDefinition:Write`. |
| `response_template.delete` | InstructionDefinition | A response-view template was removed via `DELETE /api/v1/definitions/{id}/response-templates/{tid}` (issue #254). `target_id` is the definition id; `detail` is the deleted template id on success, or `reason=<r>` on the audit path. 4xx branches emit `result=denied`; 500 persist failure emits `result=failure`. Reasons: `malformed_id`, `reserved_id`, `definition_not_found`, `template_not_found`, `persist_failure`. Permission gate: `InstructionDefinition:Write`. |
| `offload_target.create` | OffloadTarget | An offload target was created via `POST /api/v1/offload-targets` (issue #255 / Phase 8.3). On success: `target_id` is the assigned numeric id (string-form), `detail` is the target `name`, `result=success`. On 400 (validation failed — invalid URL scheme, empty name, batch_size < 1, control bytes in `auth_credential`, or duplicate name): `target_id` is the submitted name, `detail=validation_failed`, `result=denied`. RBAC denial is emitted by the permission gate before this handler is reached. Permission gate: `Infrastructure:Write`. |
| `offload_target.delete` | OffloadTarget | An offload target was deleted via `DELETE /api/v1/offload-targets/{id}` (issue #255). On success: `target_id` is the numeric id, `detail` is empty, `result=success`. On 404 (id not found, or numeric overflow on the path segment): `detail=not_found`, `result=denied` — the operator's attempt is recorded so SIEMs can surface probing of non-existent offload targets. Permission gate: `Infrastructure:Write`. |
| `viz.fleet_topology` | FleetTopology | Fleet topology snapshot was requested via `GET /api/v1/viz/fleet/topology` or `GET /fragments/viz/fleet/topology` (PR 3 of feat/viz-engine ladder). `target_id` is empty (the action operates on the whole fleet). On success: `detail` is `machines=<N> include_vuln=<0|1> [fresh=1] [fragment=1]`, `result=success`. On the `--viz-disable` kill switch: `detail=kill_switch`, `result=denied`. On 413 (snapshot exceeds `machines_max`): `detail=oversize machines=<N> cap=<M>`, `result=denied`. On 400 (`machines_max` non-numeric / out-of-range / overflow): `detail=bad_machines_max`, `result=denied`. On internal error (store null / fetcher threw / null sentinel): `detail` is `store_null` / `fetch_threw` / `snap_null`, `result=failure`. Permission gate: `Response:Read`. |
| `viz.fleet_topology.invalidate` | FleetTopology | The fleet topology cache was explicitly invalidated because `?fresh=1` was passed on the request. Emitted as a separate row immediately before the corresponding `viz.fleet_topology` row so the operator-driven flush is its own evidence event. `target_id` empty, `detail` empty, `result=success`. Permission gate: `Response:Read` (inherited from the parent request). |
| `product_pack.install` | ProductPack | A product pack install was attempted via `POST /api/product-packs`. On success: `target_id` is the new pack id, `detail` is empty, `result=success`. On rejection (#802 / W7.4): `target_id` is empty (install failed pre-id-generation; pack name is attacker-controlled YAML and is deliberately not echoed into `target_id`), `detail` is the operator-facing error message (`"pack '<name>' is unsigned and signature enforcement is enabled (set --allow-unsigned-packs / ... to bypass)"` / `"signature verification failed for pack '<name>' — content may have been tampered with"` / `"pack '<name>' has signature but no publicKey — cannot verify"`), `result=denied`. SOC 2 CC6.7: every install attempt is logged regardless of outcome. Permission gate: `ProductPack:Write`. |
| `product_pack.uninstall` | ProductPack | A product pack uninstall was issued via `DELETE /api/product-packs/{id}`. `target_id` is the pack id. Permission gate: `ProductPack:Delete`. |
| `server.viz_disabled` | FleetTopology | Emitted ONCE at server startup when `--viz-disable` / `YUZU_VIZ_DISABLE=1` is set. `principal=system`, `target_id=viz`, `detail` describes the flag source, `result=success`. The matching `[VIZ] viz endpoint disabled by configuration` warn line in operator logs covers the same event; the audit row makes the disabled posture recoverable from the audit store on a deployment with no viz traffic. |
| `server.unsigned_packs_allowed` | ProductPack | Emitted ONCE at server startup when `--allow-unsigned-packs` / `YUZU_ALLOW_UNSIGNED_PACKS=1` is set (#802 / W7.4). `principal=system`, `target_id=signature_enforcement`, `detail` describes the flag source, `result=success`. Pairs with the `[SECURITY] product pack signature enforcement DISABLED by configuration` warn line in operator logs. SIEM rules can detect a server running with the relaxed posture even on deployments with no pack-install traffic. |
| `server.unsigned_definitions_allowed` | InstructionDefinition | Sibling of `server.unsigned_packs_allowed`, emitted ONCE at server startup when `--allow-unsigned-definitions` / `YUZU_ALLOW_UNSIGNED_DEFINITIONS=1` is set (#1073 / W7.4 sibling-gap closure). `principal=system`, `target_id=signature_enforcement`, `detail` describes the flag source, `result=success`. Pairs with the `InstructionStore: signature enforcement DISABLED by configuration` warn line in operator logs. Same SIEM use case: identifies servers running with the relaxed instruction-import posture. |

**Result vocabulary.** Every action above emits `result` as `success` or `denied` (with the rare `failure` reserved for internal-error paths the handler does not itself audit). `denied` is used for RBAC rejections and for every 400/404/409 branch where the handler explicitly audits the failure — including Guardian `rule.create` (400 missing fields, 409 conflict), `rule.update` (400 invalid body, 404 not found, 409 conflict), `rule.delete` (404 not found), `push` (400 non-object body), and the Phase 8.3 `offload_target.create` (400 validation_failed) / `offload_target.delete` (404 not_found) handlers. SIEM rules that filter on `result == "success"` will match every completed mutation including `guaranteed_state.push` (which returns 202 rather than 201/200 because agent fan-out is asynchronous). To surface probe/fuzz traffic on the REST surface, filter on `result == "denied"` scoped to the actions you care about — every mutating branch produces a row.

The `/auto` pre-flight verbs add two non-denial outcomes: `no_devices` (a `preflight.run` whose scope resolved to no visible devices — an operator no-op, not a rejection) and `noop` (a `preflight.run.delete` whose run id was unknown or not owner-visible — a no-op rather than a permission denial, which keeps a non-owner from distinguishing "exists" from "doesn't exist"). Neither is a `denied`; SIEM rules counting denials should not include them.

The `/auto` deploy verbs share this pattern: `deployment.create` emits `resumed` (re-attached to an in-flight deployment for the same run instead of creating a duplicate) and `no_devices` (empty go-cohort after scope re-intersection); `deployment.delete` emits `noop` (unknown / not-owner-visible id). None is a `denied`. `deployment.advance` is high-volume (one row per poll tick); SIEM rules counting operator-initiated actions should treat a same-`deployment_id` burst as one session, not many.

**gRPC audit-failure signal.** REST surfaces set the `Sec-Audit-Failed: true` response header (and an `audit_emitted=false` body field) when an audit row fails to persist. The gRPC Register/Subscribe paths carry the equivalent as trailing metadata **`x-yuzu-audit-failed: true`** (#1063; the key is a shared constant in `grpc_audit_signal.hpp` so it cannot drift between the direct-agent and gateway-proxy services). In both transports the underlying operation still completes — enrollment proceeds, a peer-mismatch Subscribe is still rejected — only the SOC 2 evidence chain is degraded for that one request. SRE alerting should cover both signals; SIEM pipelines ingesting gRPC telemetry should watch for the `x-yuzu-audit-failed` trailer on Register/Subscribe RPCs.

## REST API

### GET /api/v1/audit

Query audit events with filtering and pagination. Maximum page size is 1000.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | integer | Number of events to return (default 100, max 1000) |
| `principal` | string | Filter by principal username |
| `action` | string | Filter by action (exact match) |

Note: the v1 endpoint supports `principal` and `action` filters only. For
additional filters (`target_type`, `target_id`, `since`, `until`, `offset`),
use the legacy `/api/audit` endpoint.

**Example --- fetch the 20 most recent events:**

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/v1/audit?limit=20' | jq .
```

**Response:**

```json
{
  "data": [
    {
      "timestamp": 1710849600,
      "principal": "admin",
      "action": "tag.set",
      "result": "success",
      "target_type": "Tag",
      "target_id": "agent-001:environment",
      "detail": "Production"
    }
  ],
  "pagination": {
    "total": 150,
    "start": 0,
    "page_size": 20
  },
  "meta": {
    "api_version": "v1"
  }
}
```

**Example --- filter by principal and action:**

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/v1/audit?principal=admin&action=auth.login&limit=50' | jq .
```

**Example --- find all failed login attempts:**

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/v1/audit?action=auth.login_failed' | jq .
```

### GET /api/audit (legacy)

The legacy endpoint supports the full set of query parameters and has no
hard-coded limit cap. New integrations should prefer `/api/v1/audit` once
additional filters are added there.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `limit` | integer | Number of events to return (default 100, no hard cap) |
| `offset` | integer | Offset for pagination (default 0) |
| `principal` | string | Filter by principal username |
| `action` | string | Filter by action (exact match) |
| `target_type` | string | Filter by target type |
| `target_id` | string | Filter by target identifier |
| `since` | integer | Only events after this Unix timestamp |
| `until` | integer | Only events before this Unix timestamp |

The legacy response envelope differs from v1:

```json
{
  "events": [ ... ],
  "count": 20,
  "total": 150
}
```

The legacy response includes additional fields per event not present in the v1
response: `id`, `principal_role`, `source_ip`.

```bash
curl -s -b cookies.txt \
  'http://localhost:8080/api/audit?limit=5000&principal=admin' | jq .
```

## Dashboard viewer

The Yuzu dashboard includes a built-in audit log viewer accessible from the
navigation menu. The viewer renders audit events as an HTMX-powered table with
live filtering by principal, action, and date range. No additional
configuration is required.

## Retention and cleanup

Audit events are retained for 365 days by default. A background thread runs
every hour and deletes events whose `timestamp` falls outside the retention
window. Deletion is permanent --- there is no soft-delete or archive step.

To preserve audit data beyond the retention window, export events periodically
using the REST API or forward them to an external system (see Planned Features
below).

## Integration patterns

### Export to CSV

Use the JSON-to-CSV export endpoint to convert audit query results into a
downloadable CSV file:

```bash
# 1. Fetch audit events as JSON
curl -s -b cookies.txt \
  'http://localhost:8080/api/v1/audit?limit=1000' | jq '.data' > audit.json

# 2. Convert to CSV
curl -s -b cookies.txt \
  -X POST \
  -H 'Content-Type: application/json' \
  -d @audit.json \
  'http://localhost:8080/api/export/json-to-csv' -o audit.csv
```

### Periodic export with cron

```bash
#!/bin/bash
# /etc/cron.daily/yuzu-audit-export
DATE=$(date +%Y-%m-%d)
curl -s -b /opt/yuzu/cookies.txt \
  "http://localhost:8080/api/v1/audit?limit=1000" \
  | jq '.data' > "/var/log/yuzu/audit-${DATE}.json"
```

### Splunk HTTP Event Collector

Poll the audit API and forward events to Splunk HEC:

```bash
# Fetch recent audit events and forward each to Splunk
curl -s -b cookies.txt \
  'http://localhost:8080/api/v1/audit?limit=100' \
  | jq -c '.data[]' \
  | while read -r event; do
      curl -s -X POST \
        -H "Authorization: Splunk YOUR-HEC-TOKEN" \
        -d "{\"event\": ${event}}" \
        https://splunk.example.com:8088/services/collector/event
    done
```

## Planned features

| Feature | Roadmap | Description |
|---|---|---|
| Event subscriptions / webhooks | Phase 7, Issue 7.12 | Push audit events to external HTTP endpoints in real time |
| System notifications | Phase 7, Issue 7.4 | Alerts for health, capacity, and compliance events |
