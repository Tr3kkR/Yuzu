# Guaranteed State (Guardian)

Guardian is Yuzu's real-time policy enforcement engine. A **guaranteed-state rule** is a desired-state assertion about an endpoint — a registry value, a service status, a file presence, a configuration key — plus optional automatic remediation when the endpoint drifts. Unlike the server-side [Policy Engine](policy-engine.md), Guardian runs *inside the agent*, reacts to kernel-backed change notifications in sub-second time, and can repair drift without an operator in the loop.

> **PR 2 status — read this first.** The v0.12 release ships Guardian's **control plane + agent skeleton only**. Rules can be authored, stored, retrieved, and pushed through the REST API. The agent persists the pushed rule set into a reserved KV namespace (`__guardian__`). **No guards run yet** — every rule reports `errored` in `/api/v1/guaranteed-state/status` and dashboards will surface this as "Guardian installed but inert." Server-to-agent fan-out is audited as `result=success` with `fan_out_deferred_pr3=true` in the detail field, but does not actually deliver rules to agents until Guardian PR 3 lands. SIEM correlation rules that infer "rules were delivered to agents" from these events are premature until that marker disappears. Operators pilot-testing Guardian should treat this release as an API-shape preview, not working enforcement. Design reference: `docs/yuzu-guardian-design-v1.1.md`. Windows-first rollout plan: `docs/yuzu-guardian-windows-implementation-plan.md`.

## Concepts

| Term | Meaning |
|---|---|
| **Rule** | A YAML document describing a desired state, a detection strategy, and an optional remediation. Stored server-side with `yaml_source` as the authoritative form. |
| **Guard** | The agent-side component that watches a kernel signal (Windows registry change, service SCM transition, ETW event) and evaluates the rule. (PR 3+.) |
| **Event** | A record of detected drift, attempted remediation, or agent sync activity. Queried via `/api/v1/guaranteed-state/events`. |
| **Push** | An operator-initiated distribution of the active rule set to a scope of agents. Separates deploy authority (`Push`) from authoring authority (`Write`). |
| **Enforcement mode** | `enforce` (remediate on drift) or `audit` (log drift, do not remediate). |
| **Scope expression** | A Scope DSL expression (same engine as Instructions) selecting which agents a rule applies to. |

## Permissions

Guardian introduces a new securable type (`GuaranteedState`) and a new operation (`Push`). Seeded role grants:

| Role | Read | Write | Execute | Delete | Approve | Push |
|---|---|---|---|---|---|---|
| Administrator | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ITServiceOwner | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| PlatformEngineer | ✓ | ✓ | | ✓ | | ✓ |
| Operator | ✓ | | | | | ✓ |
| Viewer | ✓ | | | | | |

Administrator and ITServiceOwner inherit Execute and Approve on `GuaranteedState` from the cross-type CRUD seed in `rbac_store.cpp` — neither operation has an active handler on Guardian today, but the grants exist in the database and will surface in any role-permission export. PlatformEngineer's grants are explicit and narrower (Read/Write/Delete/Push only). `Push` is deliberately separated from `Write` so an operator can deploy a rule set authored by a platform engineer without being able to modify the rule body. See [RBAC](rbac.md) for the full securable-types matrix.

## Rule YAML schema

Guardian rules use the DSL framework documented in `docs/yaml-dsl-spec.md`:

```yaml
apiVersion: yuzu.io/v1alpha1
kind: GuaranteedStateRule
metadata:
  id: block-rdp-outbound
  name: "Block outbound RDP"
  severity: high
spec:
  os_target: windows
  enforcement_mode: enforce
  scope: "tag:env=prod"
  guard:
    type: windows_registry
    hive: HKLM
    path: "SYSTEM\\CurrentControlSet\\Services\\TermService"
    value_name: Start
    expected: 4   # Disabled
  remediation:
    action: registry_set
    hive: HKLM
    path: "SYSTEM\\CurrentControlSet\\Services\\TermService"
    value_name: Start
    value: 4
    value_type: REG_DWORD
```

Only the Windows `registry` guard ships in PR 3. Linux (inotify/netlink/D-Bus) and macOS (Endpoint Security) guards are on the roadmap.

## Workflow

### 1. Author a rule

```bash
curl -X POST https://yuzu.example.com/api/v1/guaranteed-state/rules \
  -H "Authorization: Bearer $YUZU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rule_id": "block-rdp-outbound",
    "name": "Block outbound RDP",
    "yaml_source": "apiVersion: yuzu.io/v1alpha1\nkind: GuaranteedStateRule\n...",
    "severity": "high",
    "os_target": "windows",
    "scope_expr": "tag:env=prod"
  }'
```

Requires `GuaranteedState:Write`. Response: `201 Created` with `data.rule_id`. Audits `guaranteed_state.rule.create`.

### 2. List or fetch rules

```bash
curl -H "Authorization: Bearer $YUZU_TOKEN" \
  https://yuzu.example.com/api/v1/guaranteed-state/rules
```

Requires `GuaranteedState:Read`.

### 3. Update a rule

```bash
curl -X PUT https://yuzu.example.com/api/v1/guaranteed-state/rules/block-rdp-outbound \
  -H "Authorization: Bearer $YUZU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

Version is auto-incremented on every successful update. Requires `GuaranteedState:Write`. Audits `guaranteed_state.rule.update`.

### 4. Push to agents

```bash
curl -X POST https://yuzu.example.com/api/v1/guaranteed-state/push \
  -H "Authorization: Bearer $YUZU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scope": "tag:env=prod", "full_sync": true}'
```

Requires `GuaranteedState:Push`. Returns `202 Accepted`. Audits `guaranteed_state.push` with `result=success` and `detail=rules=<N> full_sync=<bool> scope="<expr>" fan_out_deferred_pr3=true`.

**While PR 2 is in effect, no agent will actually receive the push** — the REST call is accepted and persisted but agent delivery is wired in Guardian PR 3. SIEM correlation rules should not infer "rules were delivered to agents" from this event until the `fan_out_deferred_pr3=true` flag disappears from the audit detail.

### 5. Query events and status

```bash
# Recent events, filtered by severity
curl -H "Authorization: Bearer $YUZU_TOKEN" \
  "https://yuzu.example.com/api/v1/guaranteed-state/events?severity=high&limit=50"

# Fleet rollup (placeholder in PR 2 — fleet aggregation lands in PR 4)
curl -H "Authorization: Bearer $YUZU_TOKEN" \
  https://yuzu.example.com/api/v1/guaranteed-state/status
```

Both require `GuaranteedState:Read`. `/status` response keys (`total_rules`, `compliant_rules`, `drifted_rules`, `errored_rules`) match the agent-side proto `GuaranteedStateStatus`.

## Retention

Guardian events are pruned on a rolling window. The default is 30 days. Override with `--guardian-event-retention-days` at server start (or set `YUZU_GUARDIAN_EVENT_RETENTION_DAYS`), or via `PUT /api/v1/config/guardian_event_retention_days` at runtime. See the [Retention Settings](server-administration.md#retention-settings) table in the server administration guide.

## Observability

Guardian surfaces readiness and event counts via the standard observability endpoints:

- `/healthz` (authenticated) now reports a `stores.guaranteed_state` key alongside the other store-health entries. If `guaranteed-state.db` fails to open, the server reports `status = "degraded"`.
- `/readyz` includes `guaranteed_state_store` in the per-store readiness conjunction. A failed store takes the pod out of rotation.
- Prometheus metrics for Guardian rule push counts, agent apply latency, and parse errors will land in Guardian PR 3+ alongside real enforcement.

## Related documentation

- [Design v1.1](../yuzu-guardian-design-v1.1.md) — the authoritative architecture document (engineering reference).
- [Windows implementation plan](../yuzu-guardian-windows-implementation-plan.md) — PR-by-PR delivery plan.
- [Policy Engine](policy-engine.md) — server-side desired-state rules and compliance checks (complementary to Guardian, not replaced by it).
- [Scope Engine](scope-engine.md) — expression language used by `scope_expr`.
- [RBAC](rbac.md) — role seeds and the `Push` operation.
- [Audit Log](audit-log.md) — complete list of Guardian audit actions.
