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

| Action | Target type | When |
|---|---|---|
| `auth.login` | Session | Operator logs in via the dashboard or API |
| `audit.auth_sample.exported` | AuditLog | A caller pulled a pseudo-random authentication-surface evidence sample via `GET /api/v1/audit/auth-sample` (SOC 2 CC7.2). `target_id=auth-sample`; `detail=from=<epoch-or-0> to=<epoch-or-0> limit=<N> returned=<N>` so the window + sample size are on the chain. `result=success`. Permission gate: `AuditLog:Read`. Store-unavailable is a 503 (not an audited failure). If the audit-store write itself fails, the response carries `Sec-Audit-Failed: true` (the export still returns). |
| `auth.logout` | Session | Operator logs out |
| `auth.login_failed` | Session | Failed login attempt |
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
| `cert.reload` | TlsCertificate | Certificate hot-reload attempted; detail contains outcome (success or failure reason) |
| `guaranteed_state.rule.create` | GuaranteedState | A Guaranteed State rule is created. On 400 (missing required fields), 409 (rule_id/name conflict), or RBAC rejection, emits `result=denied` with the store error in `detail`. |
| `guaranteed_state.rule.update` | GuaranteedState | A Guaranteed State rule is updated (version is incremented on every successful update). On 404 (rule not found), 400 (invalid JSON body — `detail` is the literal string `"invalid JSON body"`), 409 (name conflict), or RBAC rejection, emits `result=denied`. |
| `guaranteed_state.rule.delete` | GuaranteedState | A Guaranteed State rule is deleted. On 404 or RBAC rejection, emits `result=denied`. |
| `guaranteed_state.push` | GuaranteedState | A push of the active rule set to scoped agents is accepted. `target_id` is empty (pushes are fleet-level, not per-entity); `detail` carries `rules=<N> full_sync=<bool> scope="<sanitised-expr>" fan_out_deferred_pr3=true`. The scope value in `detail` is **sanitised before embedding**: `"` and `\` are backslash-escaped, C0 control bytes (0x00–0x1F, DEL) are dropped. SIEM parsers reconstructing the original scope expression must account for this normalisation — a raw operator input of `env="prod"` appears in the audit as `scope="env=\"prod\""`. The `fan_out_deferred_pr3=true` marker means the REST call is accepted and persisted server-side but agent fan-out is not wired until Guardian PR 3; SIEM rules that infer "rules were delivered to agents" from this event are premature until that flag disappears. Non-object JSON bodies are rejected with `result=denied` and `detail="invalid JSON body"`. |
| `guaranteed_state.baseline.create` | GuaranteedState | A Guardian Baseline (the deployable collection of Guards) is created from the dashboard. `detail` carries `<name> (members=<N>, draft)`. RBAC rejection (`GuaranteedState:Write`) is audited centrally under `auth.permission_required`. |
| `guaranteed_state.baseline.update` | GuaranteedState | A Baseline is renamed or its member set edited (`GuaranteedState:Write`). `detail` carries `<name> (members=<N>)`. For a *deployed* Baseline the change is staged — it reaches agents only on re-deploy. |
| `guaranteed_state.baseline.deploy` | GuaranteedState | A Baseline is deployed or re-deployed (`GuaranteedState:Push`): its member set is snapshotted and the fleet converges to the union of deployed Baselines' enabled members. `detail` carries `<name> deployed fleet-wide (agents=<N>, members=<M>)` — or `(push not wired/failed, members=<M>)` if the push fan-out is unavailable. Store-unavailable / no-such-baseline precondition failures emit `result=denied`. |
| `guaranteed_state.baseline.delete` | GuaranteedState | A Baseline is deleted (`GuaranteedState:Delete`); if it was deployed the fleet re-converges to remove its Guards where no other deployed Baseline still delivers them. `detail` carries `<name> (was deployed; reconciled agents=<N>)` (where `<N>` is `-2` if the push was not wired) or `<name> (draft)`. Store-unavailable / no-such-baseline emit `result=denied`. |
| `dex.device.view` | Agent | An operator opened a **single device's DEX signal history** — the behavioral view that reveals which applications a person runs. Emitted by the dashboard per-device drill-down (`GET /fragments/dex/device?id=<agent_id>`) **and** by the agent-scoped REST query (`GET /api/v1/guaranteed-state/events?agent_id=<agent_id>`, which returns that device's `detail_json`). `target_id` is the `agent_id`; permission gate `GuaranteedState:Read`. A bulk events query with no `agent_id` filter is *not* individual-identifying and is not audited here. Emitted `result=success` for the access attempt (access-transparency of the open). |
| `dex.device.perf.query` | Agent | An operator clicked **Load performance** on a DEX device drill-down, dispatching a live read-only `$Perf_Hourly` TAR query to that device. Execute-gated (beyond `GuaranteedState:Read`); `target_id` is the `agent_id`, `detail` records the agent count reached and the `command_id`. Machine-health telemetry — distinct from the behavioral `dex.device.view`. |
| `dex.device.procperf.query` | Agent | An operator clicked **Load applications** on a DEX device drill-down, dispatching a live `$ProcPerf_Hourly` query (per-application image names — **usage-class telemetry**, observes what people run). Deliberately a **separate verb** from `dex.device.perf.query` so usage-class reads stay separately countable for works-council access-audit purposes. Execute-gated; `target_id` is the `agent_id`, `detail` records the agent count and `command_id`. The subsequent result polls require this dispatch's `command_id`, so no usage-class read occurs without a counted dispatch row. |
| `settings.dex_alerts.cohort_export` | RuntimeConfig | An admin set or cleared the cohort metrics export tag key via Settings → DEX alerts. `target_id` is `dex_cohort_export_key`; `detail` carries `export_key=<key>` or `export disabled`. The runtime-config store keeps no history, so this row is the change-management evidence for what cohort labels were exported when. |
| `tar.status.scan` | Infrastructure | An operator clicked **Scan fleet** on the TAR dashboard page (`/tar`). A `tar.status` command was dispatched to the operator's visible-agent set. `detail` carries the count of agents the dispatch reached (e.g. `dispatched to 47 agent(s) in scope`). One row per Scan button press; no row on page-load Refresh. |
| `tar.source.reenable` | Infrastructure | An operator clicked **Re-enable** on a row of the TAR retention-paused list and a `tar.configure` command with `<source>_enabled=true` was dispatched to a single device. `detail` carries `device=<id> source=<process|tcp|service|user>` on success. Failures emit `result=failure` with `detail` set to the real reason (`scope_violation source=<src>` for out-of-scope device IDs, `agent_not_connected source=<src>` for connected-but-zero-sent dispatches) so SIEM rules can distinguish a forged-form attempt from a transient connectivity issue — even though the HTTP response body is identical (`Agent not reachable.` 404) for both, to deny enumeration. |
| `execution.visualization.fetch` | Execution | Chart-ready JSON was rendered for an execution's response set via `GET /api/v1/executions/{id}/visualization` (issue #253 / #587). `target_id` is the `command_id`; `detail` carries `<definition_id> index=<N>` on success, or `<definition_id> reason=<r>` on the failure path where `<r>` is one of `missing_definition_id`, `malformed_definition_id`, `definition_not_found`, `no_visualization`, `index_oor`. Permission gate: `Response:Read`. The `command.dispatch` event (above, when emitted from the dashboard) appends `definition_id=<id>` to its `detail` when the dashboard reverse-resolves a chart-bearing definition, so SIEM can join `command.dispatch` to the subsequent `execution.visualization.fetch` by `definition_id`. |
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
