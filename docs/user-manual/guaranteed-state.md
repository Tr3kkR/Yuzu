# Guaranteed State (Guardian)

Guardian is Yuzu's real-time policy enforcement engine. A **guaranteed-state rule** is a desired-state assertion about an endpoint — a registry value, a service status, a file presence, a configuration key — plus optional automatic remediation when the endpoint drifts. Unlike the server-side [Policy Engine](policy-engine.md), Guardian runs *inside the agent*, reacts to kernel-backed change notifications in sub-second time, and can repair drift without an operator in the loop.

> **Status — read this first.** Guardian's control plane, the agent guard host, and the **Windows `registry` guard** are live and verified end-to-end. Rules are authored/stored/pushed via the REST API; a push is delivered to in-scope agents over both the direct gRPC stream and the Erlang gateway, the agent arms the guard, and drift is detected sub-second (`agent_id` is server/gateway-asserted, never self-reported). The registry guard runs in two modes: **`enforce`** — on drift the agent *writes the expected value back* via a single in-process `RegSetValueExW` syscall (tens of µs; emits `drift.remediated`, or `remediation.failed` if the write is denied) — and **`audit`** — detect and report only, no write-back. A restarted agent re-arms enforce guards from its local cache and enforces **pre-network** (heal-on-restart); drift in that pre-network window is enforced but not reported until reconnect (durable event buffering is Guardian A3).
>
> **Boundaries you must know before enabling `enforce`:** (1) `enforce` is **HKCU-demo-grade today** — HKLM writes need the agent service account to hold write access; a non-writable key **degrades to a read-only watch that reports `remediation.failed`, it does not silently disarm**. (2) The rule `signature` is **not yet verified** before a guard arms, so the integrity gate on what gets written where is **Push RBAC + mTLS**, not rule signing (deferred — contract G3). (3) Agent status is **fail-closed**: an armed guard reports `errored`/not-healthy, never a green "compliant", until the self-test lands — do not read the agent status proto as proof of enforcement. (4) `enforcement_mode` defaults to **`enforce`** on rule create — see the upgrade note below. Still on the roadmap: non-Windows guards, server-side Prometheus metrics, fight-loop rate-limiting, rule signing, and durable event buffering (A3). Gateway drift forwarding is best-effort (`yuzu_gw_guardian_forward_dropped_total`). Design: `docs/yuzu-guardian-design-v1.1.md`. Rollout plan: `docs/yuzu-guardian-windows-implementation-plan.md`.

## Concepts

| Term | Meaning |
|---|---|
| **Rule** | A YAML document describing a desired state, a detection strategy, and an optional remediation. Stored server-side with `yaml_source` as the authoritative form. |
| **Guard** | The agent-side component that watches a kernel signal (Windows registry change, service SCM transition, ETW event) and evaluates the rule. The Windows `registry`, `file`, and `service` (run-state) guards are live; service start-type, ETW, and non-Windows guards are on the roadmap. |
| **Event** | A record of detected drift, attempted remediation, or agent sync activity. Queried via `/api/v1/guaranteed-state/events`. Live `event_type` values from the registry guard: `drift.detected` (drift observed in **audit** mode — no write-back), `drift.remediated` (enforce write-back restored the expected value), `remediation.failed` (enforce attempted but the write was denied — e.g. a read-only-fallback key). |
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

Three Windows guard types ship today: the **registry** guard (above), the **file** guard (below), and the **service** guard (below). Linux (inotify/netlink/D-Bus) and macOS (Endpoint Security / FSEvents) guards are on the roadmap.

## File guards — detect a file changed or deleted, in realtime

A `file-change` spark watches a file via `ReadDirectoryChangesW` on its parent directory — kernel-notified, **no polling**, so detection is realtime. The watch is resilient: it survives the parent directory (and its whole ancestor chain) being deleted and recreated. Two assertions decide what counts as drift:

| Assertion | Drift when | Key params |
|---|---|---|
| `file-exists` | the file's presence differs from `expected` | `path` (required), `expected` = `present` (default → fires on **delete**) or `absent` (tripwire → fires on **create**) |
| `file-hash-equals` | the file's **content** differs from a baseline | `path` (required), `expected_hash` (64-char SHA-256 hex; **empty → baseline captured on arm**), `max_bytes` (hashing cap, default 64 MiB → larger files report `<oversize>`), `settle_ms` (quiescence window before hashing, default 750) |

`file-hash-equals` uses a size pre-filter then a **bounded SHA-256**, and waits for the file to quiesce before hashing (a write is not atomic), so a no-op rewrite of identical bytes is **not** reported as drift — only a real content change is. Absent / oversize / unreadable states are reported (`<absent>` / `<oversize>` / `<unreadable>`), never a silent "compliant". File guards are **detection-only** (file-content remediation is deferred); `enforcement_mode` still gates whether the rule is active, but there is no write-back.

```bash
# Alert if a sensitive config is modified OR deleted, in realtime.
curl -X POST https://yuzu.example.com/api/v1/guaranteed-state/rules \
  -H "Authorization: Bearer $YUZU_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "rule_id": "watch-hosts", "name": "hosts file integrity",
    "enforcement_mode": "audit",
    "spark":      {"type": "file-change", "params": {}},
    "assertion":  {"type": "file-hash-equals", "params": {"path": "C:\\Windows\\System32\\drivers\\etc\\hosts"}},
    "remediation":{"type": "alert-only", "params": {}}
  }'
```

The full type catalog — including these file types and the `expected_hash` format — is discoverable at `GET /api/v1/guaranteed-state/schemas` (see [Schema discovery](#schema-discovery)).

## Service guards — keep a Windows service running (or stopped), in realtime

A `service-status-change` spark watches one Windows service via `NotifyServiceStatusChange` — kernel-notified by the Service Control Manager, **no polling**, so a stop or start is detected in ~0 ms. The watch is resilient: it survives the service being deleted and recreated, and re-arms automatically. The assertion *type* encodes the desired run state; the only param is the service (key) name:

| Assertion | Drift when | Key params |
|---|---|---|
| `service-running` | the service is not Running (stopped, paused, or absent) | `service_name` (required) — the SCM **key** name, e.g. `Spooler`, not the display name |
| `service-stopped` | the service is Running or paused | `service_name` (required) |

In **enforce** mode the guard drives the service back to its desired state via the Windows service-control API (`StartService` / `ControlService` — never `sc.exe` or `net start`), gated by the same per-rule resilience policy as registry guards. In **audit** mode it only detects and reports. This is the canonical way to keep a security service alive — *Microsoft Defender must always be running; restart it if it stops* — or held down — *the Print Spooler must stay stopped*.

```bash
# Keep the Print Spooler stopped (PrintNightmare hardening), enforcing.
curl -X POST https://yuzu.example.com/api/v1/guaranteed-state/rules \
  -H "Authorization: Bearer $YUZU_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "rule_id": "spooler-stopped", "name": "Print Spooler held stopped",
    "enforcement_mode": "enforce",
    "spark":      {"type": "service-status-change", "params": {}},
    "assertion":  {"type": "service-stopped", "params": {"service_name": "Spooler"}},
    "remediation":{"type": "enforce", "params": {}}
  }'
```

> **`service-disabled` (start-type)** is not yet a native assertion — a service's *startup type* fires no SCM notification. Until a dedicated start-type guard lands, express "service must be disabled" as a **registry** guard on `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Start` = `4` (`REG_DWORD`). Like file guards, service guards are authored via the REST API or the seed rig today; a dashboard authoring form follows.

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

Requires `GuaranteedState:Push`. Returns `202 Accepted`. Audits `guaranteed_state.push` with `result=success` and `detail=rules=<N> full_sync=<bool> scope="<expr>" agents=<count>`, where `agents` is the number of in-scope agents the push was dispatched to (across the direct gRPC and gateway transports).

The push is dispatched to in-scope agents; the `agents=<count>` field records how many were targeted. Delivery is best-effort for gateway-connected agents under an upstream outage (durable buffering is Guardian A3), so a non-zero `agents` count records **dispatch, not a per-agent delivery receipt**. SIEM correlation should treat the count as "push fanned out to N agents," and corroborate actual enforcement against the drift/sync records at `/api/v1/guaranteed-state/events`.

### 5. Query events and status

```bash
# Recent events, filtered by severity
curl -H "Authorization: Bearer $YUZU_TOKEN" \
  "https://yuzu.example.com/api/v1/guaranteed-state/events?severity=high&limit=50"

# Fleet rollup (placeholder in PR 2 — fleet aggregation lands in PR 4)
curl -H "Authorization: Bearer $YUZU_TOKEN" \
  https://yuzu.example.com/api/v1/guaranteed-state/status
```

Both require `GuaranteedState:Read`. `/status` response keys (`total_rules`, `compliant_rules`, `drifted_rules`, `errored_rules`) match the agent-side proto `GuaranteedStateStatus`. **The agent status is fail-closed:** until the guard self-test lands, an armed guard reports `errored` / `guard_healthy=false`, never `compliant`. Treat the **events stream** (`drift.remediated` / `remediation.failed`), not `/status`, as the source of truth for whether enforcement is working.

### 6. Enable/disable and switch mode from the dashboard

The Guardian dashboard guard list (`/guardian`) exposes per-guard controls:

- **Enable / Disable** — toggles the rule's `enabled` flag. Disabling tears the guard down on agents (the next full-sync push omits it).
- **Switch to Audit / Switch to Enforce** — toggles `enforcement_mode` between `audit` (detect only) and `enforce` (write-back).

Both require **`GuaranteedState:Write` *and* `GuaranteedState:Push`** (they mutate the rule *and* deploy it). On change the server updates the rule, **auto-deploys a full-sync push to all in-scope agents** (so it takes effect live), audits the mutation under `guaranteed_state.rule.update`, and re-renders the list. These are dashboard HTMX fragments, not REST endpoints — for scripted control use `PUT /api/v1/guaranteed-state/rules/<id>` (`enforcement_mode` must be `enforce` or `audit`) then `POST .../push`.

> **Note:** the auto-deploy pushes only to the rule's own `scope_expr` (an empty scope = the whole fleet), so a single toggle does **not** fan out to agents outside that rule's targeting. `full_sync` is always set so an agent that had the rule enabled disarms it correctly on disable (the agent has no per-rule removal verb).
>
> **Dashboard reads require `GuaranteedState:Read`** — an authenticated user without it gets a 403 on each data panel (the page shell still loads). The status rollup shows the live guard count from the store, not a fabricated compliance percentage.
>
> **Offline convergence:** an agent that was offline or unreachable when a rule changed re-converges automatically on reconnect. It reports its applied policy generation (`yuzu.guardian_generation`) in each heartbeat; the server re-pushes when that generation is behind the current store generation (rate-limited per agent). No manual re-push is needed after a network partition.

### 7. Create a Guard from the dashboard

The **+ New Guard** button (top of `/guardian`) opens a structured create form for the Windows registry types: name, severity, enforcement mode, the `registry-value-equals` assertion (hive / key / value name / value type / expected), the remediation action (`alert-only` or `enforce`), and the [resilience policy](#resilience-policy-enforce-retry-behaviour) fieldset (mode + the mode-relevant tuning params; blanks use defaults). Submitting builds the same structured Guard the REST `POST /rules` endpoint accepts and runs it through the **same validation** (so an invalid resilience policy is rejected with an inline banner naming exactly what to fix). On success the Guard is created **unscoped (draft)** — device targeting is set at the Baseline, not per-Guard — and the guard list refreshes in place. Requires `GuaranteedState:Write`; audited under `guaranteed_state.rule.create`.

## Resilience policy (enforce-retry behaviour)

When a guard is enforcing and a competing writer keeps reverting the value, a **resilience policy** governs how the agent re-enforces. The policy travels as string entries in the structured Guard's `remediation.params` (no proto change) and is validated + canonicalised by the server on create/update.

| Param | Applies to mode | Default | Meaning |
|---|---|---|---|
| `mode` | all | `persist` | `persist` (re-enforce on every drift, sub-ms, never give up), `backoff` (exponential delay between re-enforcements, never gives up), or `bounded` (give up after N re-fix cycles in one fight; keep detecting + alerting). |
| `max_attempts` | bounded | `5` | Consecutive re-fix cycles before giving up. Must be ≥ 1 (`0` would never give up — use `persist` for that). |
| `quiet_reset_s` | backoff, bounded | `60` | Sustained no-drift gap (seconds) that resets the Bounded counter / Backoff exponent. |
| `resume_after_s` | bounded | `0` | After giving up, auto-resume this many seconds later. `0` = stay given up until an admin re-pushes. |
| `backoff_initial_ms` | backoff | `1000` | Initial re-enforcement delay; doubles up to `backoff_max_ms`. Must be ≤ `backoff_max_ms`. |
| `backoff_max_ms` | backoff | `60000` | Cap on the exponential delay. |
| `event_debounce_ms` | all | `1000` | Collapse-with-count window for repeated drift events. `0` = emit every event. |

```bash
curl -X POST https://yuzu.example.com/api/v1/guaranteed-state/rules \
  -H "Authorization: Bearer $YUZU_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "rule_id": "block-rdp-outbound", "name": "Block outbound RDP",
    "enforcement_mode": "enforce",
    "spark":      {"type": "registry-change",       "params": {}},
    "assertion":  {"type": "registry-value-equals", "params": {"hive": "HKLM", "key": "SYSTEM\\CurrentControlSet\\Services\\TermService", "value_name": "Start", "value_type": "REG_DWORD", "expected": "4"}},
    "remediation":{"type": "enforce", "params": {"mode": "bounded", "max_attempts": "3", "resume_after_s": "3600"}}
  }'
```

**Validation is lenient-in / canonical-out.** Only the chosen mode's load-bearing params are range-checked, so a `persist` rule that carries stray `backoff_*` values is accepted, not rejected. Values are stored canonical (`mode` lowercased, numerics as decimal strings), and `GET` echoes the form you would re-`POST`. An invalid value (e.g. `bounded` with `max_attempts: 0`, or `backoff_initial_ms` > `backoff_max_ms`) returns `400` with the structured **A4 error envelope** (`error.code` / `error.message` / `error.correlation_id` / `error.remediation`) so an agentic author can self-correct. The same validation runs on `PUT` — a structured update re-authors the Guard rather than silently dropping the blocks.

> Resilience modes apply **in enforce mode only** (an audit guard always just detects and alerts). `event_debounce_ms` applies in both modes.

## Schema discovery

`GET /api/v1/guaranteed-state/schemas` returns the static catalog of Guard `spark` / `assertion` / `remediation` types with per-type JSON Schemas — including the resilience subschema above and the discriminated `registry-value-equals` encoding (the `expected` format keyed on `value_type`). It is the machine-discoverable source dynamic authoring forms and agentic clients build against (the same schema the server validates with). Requires `GuaranteedState:Read`. The response is cacheable: it carries a content-derived `ETag`, and a conditional request (`If-None-Match`) returns `304 Not Modified`.

```bash
curl -H "Authorization: Bearer $YUZU_TOKEN" \
  https://yuzu.example.com/api/v1/guaranteed-state/schemas
```

## Upgrading from a detect-only build

> **Breaking behaviour change.** `enforcement_mode` defaults to **`enforce`**, and enforce mode now **writes to the endpoint registry** on drift. A rule authored on a pre-enforcement build (when Guardian was detect-only) will begin **remediating** on the next push after the agents are upgraded — with no further opt-in. Before upgrading agents: audit existing rules (`GET /api/v1/guaranteed-state/rules`), set `enforcement_mode: audit` on any rule you want to keep detect-only, and re-push. HKLM-scoped enforce rules require the agent service account to have write access to the key.

## Retention

Guardian events are pruned on a rolling window. The default is 30 days. Override with `--guardian-event-retention-days` at server start (or set `YUZU_GUARDIAN_EVENT_RETENTION_DAYS`), or via `PUT /api/v1/config/guardian_event_retention_days` at runtime. See the [Retention Settings](server-admin.md#retention-settings) table in the server administration guide.

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
