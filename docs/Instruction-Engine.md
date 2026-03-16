## Yuzu Revised Design Note

**Document status:** Proposed design note  
**Basis:** Review of the public `dev` branch of `Tr3kkR/Yuzu` as of 2026-03-16  
**Audience:** Yuzu platform architect / maintainer  

---

## 1. Epistemic status

### Verified from the repository

- Yuzu positions itself as an enterprise endpoint management platform for **Windows, Linux, and macOS** fleets, with real-time visibility, orchestration, and compliance. It explicitly describes command orchestration, continuous compliance, security response, and a plugin-extensible model.  
  Source: GitHub `dev` branch README.
- The current public architecture description includes a **REST API, Instruction Engine, Policy Engine, Response Store, RBAC/Auth, Audit Log, and Scheduler** in the target architecture diagram and feature description.  
  Source: GitHub `dev` branch README.
- The plugin ABI is intentionally stable and C-compatible, with a single exported plugin descriptor entrypoint for shared libraries.  
  Source: `sdk/include/yuzu/plugin.h`.
- The capability map states that ad-hoc `plugin + action + params` execution exists today, but **Instruction Templates/Definitions, Instruction Sets, Instruction Hierarchies, Scheduling, Approval Workflows, and Product Packs are not yet implemented**.  
  Source: `docs/capability-map.md`.
- The roadmap explicitly lists **Instruction Definitions, Instruction Sets, Instruction Scheduling, Instruction Approval Workflows, Instruction Hierarchies and Follow-Up Workflows, Policy Rules and Fragments, Trigger Framework, Desktop User Interaction, and Product Packs** as planned work items.  
  Source: `docs/roadmap.md`.
- The capability map lists the currently documented plugin coverage matrix, including 24 cross-platform plugins, 3 Windows-only plugins, and 2 test/debug plugins.  
  Source: `docs/capability-map.md`.

### Proposed in this design note

Everything in Sections 4 onward is a proposed design, not a claim that the repository already implements it.

---

## 2. Executive summary

Yuzu now has a credible **execution substrate** but still lacks a finished **content plane**.

The existing substrate appears sufficient for:

- endpoint discovery and targeting,
- plugin-based remote execution,
- streaming output,
- process / service / network / software / filesystem operations,
- basic security and inventory workloads.

The missing layer is what turns those primitives into a 1E-like platform:

- reusable **InstructionDefinitions**,
- grouped **InstructionSets**,
- declarative **PolicyFragments** and **Policies**,
- server-managed **TriggerTemplates**,
- signed, versioned **ProductPacks**,
- approval, scheduling, rollout, and audit semantics,
- typed result schemas and stable composition rules.

### Core recommendation

Yuzu should treat plugins as the **privileged execution substrate** and should build a separate **declarative content model** above them. Users should author instructions, policies, triggers, and packs against stable builtins and typed schemas, not against raw syscalls or ad-hoc plugin parameters.

---

## 3. Verified current-state assessment of Yuzu

### 3.1 What is already strong

The capability map shows strong T1 foundation coverage for:

- process enumeration and termination,
- service enumeration and control,
- logged-on user enumeration,
- installed application inventory,
- software uninstall,
- antivirus / firewall / BitLocker / vulnerability / event-log capabilities,
- filesystem listing, search, hashing, deletion, and path checks,
- a stable plugin SDK and gRPC management API.

This is enough to support a serious endpoint action runtime.

### 3.2 What is still missing

The same capability map explicitly says the following are not yet implemented:

- instruction templates / definitions,
- instruction sets,
- workflow hierarchies,
- scheduling,
- approval workflows,
- policy rules and enforcement,
- trigger framework,
- product packs,
- formal REST management API,
- audit trail of user actions,
- event subscriptions.

### 3.3 Architectural implication

Yuzu should not continue to scale primarily by adding bespoke plugins and ad-hoc commands. It should add a first-class content plane that makes the substrate composable, governable, and distributable.

---

## 4. Design principles

1. **Capabilities over syscalls**  
   Content authors should use stable builtins. Raw OS-specific APIs should stay behind plugins or core adapters.

2. **Typed content over ad-hoc params**  
   Every reusable instruction should have parameter schemas, output schemas, versioning, compatibility rules, and human-readable metadata.

3. **Idempotent remediation where possible**  
   Fixes and policies should prefer convergent desired-state semantics.

4. **Workflow composition without imperative sprawl**  
   Most endpoint logic should be expressed declaratively through composition, filtering, branching, retry, approval, and trigger binding.

5. **Signed, portable content bundles**  
   Product packs should distribute definitions and templates, not arbitrary native code.

6. **One execution model**  
   UI, API, scheduler, policy engine, and trigger engine should all execute the same instruction model.

7. **Structured output first**  
   Pipe-delimited output is serviceable for bootstrap but should be replaced with typed rowsets / JSON-native interchange as the canonical substrate.

---

## 5. Proposed content model

The proposed object model is:

- **InstructionDefinition**: reusable action or question template bound to a substrate primitive
- **InstructionSet**: grouped collection of definitions, workflows, and policy fragments; primary permission boundary
- **PolicyFragment**: reusable check/fix pair
- **Policy**: scope + desired state + trigger/schedule + remediation + compliance semantics
- **TriggerTemplate**: reusable event source template with parameterization and debounce semantics
- **ProductPack**: signed bundle of definitions, sets, fragments, policies, triggers, views, and metadata

### 5.1 Relationship summary

```text
ProductPack
âââ InstructionSet(s)
â   âââ InstructionDefinition(s)
â   âââ Workflow template(s)
â   âââ PolicyFragment reference(s)
âââ PolicyFragment(s)
âââ Policy(s)
âââ TriggerTemplate(s)
âââ Export / dashboard / documentation metadata
```

---

## 6. YAML schemas

These are proposed wire/storage schemas, not direct extracts from the repository.

### 6.1 InstructionDefinition

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: windows.service.restart
  displayName: Restart Windows Service
  version: 1.0.0
  description: Restart a named Windows service and return the post-action state.
  labels:
    domain: services
    os: windows
  annotations:
    owner: platform-core
    maturity: draft
spec:
  type: action            # action | question
  platforms:
    - windows
  substrate:
    primitive: service.restart
    builtin: service.restart
    plugin: services
    action: restart
  parameters:
    type: object
    required:
      - serviceName
    properties:
      serviceName:
        type: string
        title: Service name
        minLength: 1
      timeoutSeconds:
        type: integer
        minimum: 1
        maximum: 600
        default: 60
      requireRunningAfter:
        type: boolean
        default: true
  resultSchema:
    type: object
    required:
      - serviceName
      - stateBefore
      - stateAfter
      - success
    properties:
      serviceName:
        type: string
      stateBefore:
        type: string
      stateAfter:
        type: string
      success:
        type: boolean
      message:
        type: string
  execution:
    timeoutSeconds: 90
    idempotent: false
    concurrency: per-device
    approvalMode: inherit
    retry:
      maxAttempts: 1
  safety:
    risk: medium
    allowedScopes:
      - device
      - group
    rollback:
      supported: false
  observability:
    emitAuditEvent: true
    persistResponses: true
    defaultAggregation:
      mode: count_by
      field: stateAfter
status:
  phase: proposed
```

### 6.2 InstructionSet

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionSet
metadata:
  id: core.windows.services
  displayName: Windows Service Operations
  version: 1.0.0
  description: Group of reusable service interrogation and remediation definitions.
spec:
  platforms:
    - windows
  permissions:
    executeRoles:
      - endpoint-operator
      - endpoint-admin
    authorRoles:
      - content-author
      - endpoint-admin
    approveRoles:
      - endpoint-admin
  contents:
    instructionDefinitions:
      - windows.service.inspect
      - windows.service.start
      - windows.service.stop
      - windows.service.restart
    policyFragments:
      - fragment.windows.service.must_be_running
    workflowTemplates:
      - workflow.windows.restart_then_verify
  defaults:
    approvalMode: role-gated
    responseRetentionDays: 30
    targetEstimationRequiredAbove: 500
  publishing:
    signed: true
    visibility: org
status:
  phase: proposed
```

### 6.3 PolicyFragment

```yaml
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
metadata:
  id: fragment.windows.service.must_be_running
  displayName: Service must be running
  version: 1.0.0
  description: Reusable fragment that checks a service and optionally restarts it.
spec:
  platforms:
    - windows
  inputs:
    type: object
    required:
      - serviceName
    properties:
      serviceName:
        type: string
      autoRemediate:
        type: boolean
        default: true
  check:
    ref: windows.service.inspect
    with:
      serviceName: ${inputs.serviceName}
  compliance:
    expression: result.state == "running"
    states:
      compliant: result.state == "running"
      noncompliant: result.state != "running"
      error: result.error != null
  fix:
    when: ${inputs.autoRemediate} == true
    ref: windows.service.restart
    with:
      serviceName: ${inputs.serviceName}
  postCheck:
    ref: windows.service.inspect
    with:
      serviceName: ${inputs.serviceName}
  debounce:
    minIntervalSeconds: 300
  exceptionModel:
    allowTemporarySuppressions: true
status:
  phase: proposed
```

### 6.4 Policy

```yaml
apiVersion: yuzu.io/v1alpha1
kind: Policy
metadata:
  id: policy.windows.spooler.running
  displayName: Windows Print Spooler must be running
  version: 1.0.0
  description: Ensures the Spooler service remains in the running state.
spec:
  scope:
    selector:
      platform: windows
      tags:
        - print-enabled
  assignment:
    mode: dynamic
    managementGroups:
      - workstations
  fragment:
    ref: fragment.windows.service.must_be_running
    with:
      serviceName: Spooler
      autoRemediate: true
  triggers:
    - ref: trigger.interval.five_minutes
    - ref: trigger.windows.service_status_changed
      with:
        serviceName: Spooler
  schedule:
    cron: "*/15 * * * *"
    timezone: UTC
  rollout:
    strategy: gradual
    maxConcurrentPercent: 10
  approvals:
    requiredForInitialDeploy: true
    requiredForRemediationChange: true
  compliance:
    cacheTtlSeconds: 300
    responseRetentionDays: 90
    emitEventsOnStateChange: true
  exceptions:
    allowDeviceLevelExemption: true
    exemptionMaxDays: 14
status:
  phase: proposed
```

### 6.5 TriggerTemplate

```yaml
apiVersion: yuzu.io/v1alpha1
kind: TriggerTemplate
metadata:
  id: trigger.windows.eventlog.pattern
  displayName: Windows Event Log Pattern Trigger
  version: 1.0.0
  description: Fires when a matching Windows event log record appears.
spec:
  platforms:
    - windows
  source:
    type: windows-event-log    # interval | filesystem | service | windows-event-log | registry | agent-startup
  parameters:
    type: object
    required:
      - channel
    properties:
      channel:
        type: string
      provider:
        type: string
      eventIds:
        type: array
        items:
          type: integer
      messageRegex:
        type: string
  debounce:
    mode: keyed
    keyExpression: "${channel}:${provider}:${eventId}"
    minIntervalSeconds: 60
  delivery:
    mode: local-agent
    persistTriggerEvents: true
  outputs:
    type: object
    properties:
      timestamp:
        type: string
      channel:
        type: string
      provider:
        type: string
      eventId:
        type: integer
      computer:
        type: string
      message:
        type: string
status:
  phase: proposed
```

### 6.6 ProductPack

```yaml
apiVersion: yuzu.io/v1alpha1
kind: ProductPack
metadata:
  id: pack.core.endpoint-ops
  displayName: Core Endpoint Operations Pack
  version: 1.0.0
  description: Signed bundle of baseline operational content for core endpoint management.
spec:
  publisher:
    name: Yuzu Core
    contact: platform@example.invalid
  compatibility:
    minServerVersion: 0.9.0
    minAgentVersion: 0.9.0
    requiredApiVersions:
      - yuzu.io/v1alpha1
  contents:
    instructionSets:
      - core.windows.services
      - core.crossplatform.processes
    instructionDefinitions:
      - windows.service.inspect
      - windows.service.restart
      - crossplatform.process.list
      - crossplatform.process.kill
    policyFragments:
      - fragment.windows.service.must_be_running
    policies:
      - policy.windows.spooler.running
    triggerTemplates:
      - trigger.interval.five_minutes
      - trigger.windows.eventlog.pattern
    dashboards:
      - compliance.overview
    docs:
      - docs/pack-overview.md
  dependencies:
    plugins:
      - services
      - processes
      - event_logs
    packs: []
  security:
    signature:
      algorithm: ed25519
      keyId: yuzu-core-release
      value: <base64-signature>
    checksums:
      manifestSha256: <sha256>
  distribution:
    format: tar.zst
    importMode: staged
    allowPartialImport: false
status:
  phase: proposed
```

---

## 7. Proposed substrate primitives

This section enumerates the proposed stable primitives that the content plane should target.

### 7.1 System and identity

- `system.info`
- `system.status`
- `device.identity`
- `hardware.inventory`
- `device.tags.get`
- `device.tags.set`
- `agent.health`
- `agent.restart`
- `agent.sleep`
- `agent.log.read`

### 7.2 Process and execution

- `process.list`
- `process.inspect`
- `process.kill`
- `process.start`
- `script.run`
- `command.run`
- `execution.wait`
- `execution.timeout`

### 7.3 Services and daemons

- `service.list`
- `service.inspect`
- `service.start`
- `service.stop`
- `service.restart`
- `service.set_start_mode`

### 7.4 User, session, and identity context

- `user.list`
- `user.logged_on`
- `user.group_membership`
- `session.list`
- `session.active_user`
- `session.notify`
- `session.prompt`

### 7.5 Network

- `network.config.get`
- `network.route.list`
- `network.connection.list`
- `network.socket.owner`
- `network.dns.flush`
- `network.diagnostics.run`
- `network.adapter.enable`
- `network.adapter.disable`
- `network.quarantine`

### 7.6 Software and patching

- `software.inventory`
- `software.package.inventory`
- `software.uninstall`
- `software.install`
- `software.update`
- `patch.inventory`
- `patch.install`
- `patch.scan`

### 7.7 Filesystem and content staging

- `file.list`
- `file.search`
- `file.read`
- `file.write`
- `file.hash`
- `file.delete`
- `file.exists`
- `file.permissions.inspect`
- `file.signature.verify`
- `file.temp.create`
- `content.download`
- `content.upload`
- `content.stage`
- `content.execute`

### 7.8 Security and compliance

- `security.antivirus.status`
- `security.firewall.status`
- `security.firewall.rules.list`
- `security.disk_encryption.status`
- `security.vulnerability.scan`
- `security.event_log.query`
- `security.ioc.check`
- `security.certificate.inventory`
- `security.certificate.renew`

### 7.9 Data, shaping, and workflow

- `result.filter`
- `result.project`
- `result.join`
- `result.group_by`
- `result.count`
- `result.sort`
- `json.parse`
- `json.path`
- `string.regex_match`
- `string.regex_extract`
- `time.now`
- `time.window`
- `workflow.if`
- `workflow.switch`
- `workflow.foreach`
- `workflow.parallel`
- `workflow.retry`
- `workflow.fail`
- `workflow.assert`

### 7.10 Trigger and policy primitives

- `trigger.interval`
- `trigger.filesystem_change`
- `trigger.service_change`
- `trigger.windows_event_log`
- `trigger.registry_change`
- `trigger.agent_startup`
- `policy.check`
- `policy.fix`
- `policy.evaluate`
- `policy.suppress`
- `policy.exempt`
- `policy.recheck`

### 7.11 Approval, scope, and governance

- `scope.estimate_targets`
- `scope.resolve_devices`
- `approval.submit`
- `approval.approve`
- `approval.reject`
- `audit.emit`
- `response.persist`
- `response.aggregate`
- `response.export`

---

## 8. Mapping substrate primitives to current or proposed Yuzu builtins

### 8.1 Notes on interpretation

- **Mapped builtin/plugin** means the primitive can plausibly be backed by a documented existing plugin or clearly planned subsystem.
- **Status** values:
  - `Verified` = grounded in the public repo/capability map
  - `Planned` = grounded in roadmap/capability map but not implemented
  - `Proposed` = recommended here as an explicit builtin surface
- The tables below use Yuzu builtin names as the stable authoring surface. Internally, Yuzu can map them to plugins or OS adapters.

---

## 9. Windows builtin mapping

| Primitive | Yuzu builtin | Backing plugin / adapter | Status | Notes |
|---|---|---|---|---|
| `system.info` | `system.info` | `os_info` | Verified | Cross-platform inventory primitive |
| `system.status` | `system.status` | `status` | Verified | Device / agent status |
| `device.identity` | `device.identity` | `device_identity` | Verified | Agent/device identity |
| `hardware.inventory` | `hardware.inventory` | `hardware` | Verified | CPU, RAM, disks |
| `process.list` | `process.list` | `processes`, `procfetch` | Verified | `procfetch` adds formatted/hash-oriented view |
| `process.kill` | `process.kill` | `processes` | Verified | Basic kill supported |
| `process.start` | `process.start` | `script_exec` / future process adapter | Proposed | Current repo documents execution primitives, not a dedicated process-start contract |
| `service.list` | `service.list` | `services` | Verified | Cross-platform service enumeration |
| `service.inspect` | `service.inspect` | `services` | Proposed | Natural builtin over existing service plugin |
| `service.start` | `service.start` | `services` | Verified | Documented in capability map |
| `service.stop` | `service.stop` | `services` | Verified | Documented in capability map |
| `service.restart` | `service.restart` | `services` | Verified | Documented in capability map |
| `user.logged_on` | `user.logged_on` | `users` | Verified | Logged-on user enumeration |
| `user.group_membership` | `user.group_membership` | future users/groups plugin | Planned | Roadmap includes user sessions and group membership plugins |
| `network.config.get` | `network.config.get` | `network_config` | Verified | Adapter/IP configuration |
| `network.connection.list` | `network.connection.list` | `netstat` | Verified | Connections and listeners |
| `network.socket.owner` | `network.socket.owner` | `sockwho` | Verified | Socket-to-process ownership |
| `network.diagnostics.run` | `network.diagnostics.run` | `network_diag` | Verified | Ping/traceroute-style diagnostics surface |
| `network.adapter.enable` | `network.adapter.enable` | `network_actions` | Verified | Cross-platform network actions category |
| `network.adapter.disable` | `network.adapter.disable` | `network_actions` | Verified | Cross-platform network actions category |
| `network.quarantine` | `network.quarantine` | future quarantine subsystem | Planned | Roadmap issue exists |
| `software.inventory` | `software.inventory` | `installed_apps` | Verified | Cross-platform installed apps |
| `software.package.inventory` | `software.package.inventory` | `msi_packages` | Verified | Windows-only MSI inventory |
| `software.uninstall` | `software.uninstall` | `software_actions` | Verified | Capability map documents uninstall |
| `software.install` | `software.install` | content staging + installer execution | Planned | Needs content staging / execution path |
| `patch.inventory` | `patch.inventory` | `windows_updates` | Verified | Windows-only patch primitive |
| `patch.install` | `patch.install` | `windows_updates` / future workflow | Proposed | Likely needs richer workflow semantics |
| `file.list` | `file.list` | `filesystem` | Verified | Admin-required |
| `file.search` | `file.search` | `filesystem` | Verified | Search by name |
| `file.read` | `file.read` | `filesystem` | Verified | Basic read only |
| `file.write` | `file.write` | future filesystem advanced ops | Planned | Roadmap issue exists |
| `file.hash` | `file.hash` | `filesystem` | Verified | Hash computation |
| `file.delete` | `file.delete` | `filesystem` | Verified | Deletion supported |
| `file.exists` | `file.exists` | `filesystem` | Verified | Path existence check |
| `file.permissions.inspect` | `file.permissions.inspect` | ACL adapter | Planned | Capability map marks not implemented |
| `file.signature.verify` | `file.signature.verify` | Authenticode adapter | Planned | Capability map marks not implemented |
| `file.temp.create` | `file.temp.create` | secure temp-file helper | Planned | Foundation gap called out |
| `content.download` | `content.download` | agent HTTP transfer | Planned | Roadmap issue exists |
| `content.upload` | `content.upload` | agent HTTP transfer | Planned | Roadmap issue exists |
| `content.stage` | `content.stage` | content staging subsystem | Planned | Roadmap issue exists |
| `content.execute` | `content.execute` | `script_exec` + staging | Planned | Roadmap issue exists |
| `security.antivirus.status` | `security.antivirus.status` | `antivirus` | Verified | Cross-platform AV detection |
| `security.firewall.status` | `security.firewall.status` | `firewall` | Verified | Cross-platform firewall status/rules |
| `security.firewall.rules.list` | `security.firewall.rules.list` | `firewall` | Verified | Capability map mentions rule enumeration |
| `security.disk_encryption.status` | `security.disk_encryption.status` | `bitlocker` | Verified | Windows-only today |
| `security.vulnerability.scan` | `security.vulnerability.scan` | `vuln_scan` | Verified | NVD-backed scan workflow |
| `security.event_log.query` | `security.event_log.query` | `event_logs` | Verified | Event log collection |
| `security.ioc.check` | `security.ioc.check` | future IOC subsystem | Planned | Roadmap issue exists |
| `security.certificate.inventory` | `security.certificate.inventory` | future certificate plugin | Planned | Roadmap issue exists |
| `security.certificate.renew` | `security.certificate.renew` | cert-store / enrollment adapter | Proposed | Good high-value enterprise primitive |
| `trigger.interval` | `trigger.interval` | trigger framework | Planned | Capability map marks not implemented |
| `trigger.filesystem_change` | `trigger.filesystem_change` | filesystem watcher | Planned | Capability map marks not implemented |
| `trigger.service_change` | `trigger.service_change` | SCM/service watcher | Planned | Capability map marks not implemented |
| `trigger.windows_event_log` | `trigger.windows_event_log` | event-log subscription adapter | Planned | Capability map marks not implemented |
| `trigger.registry_change` | `trigger.registry_change` | registry watcher | Planned | Capability map marks not implemented |
| `trigger.agent_startup` | `trigger.agent_startup` | agent lifecycle hook | Planned | Capability map marks not implemented |
| `policy.check` | `policy.check` | policy engine | Planned | Capability map marks not implemented |
| `policy.fix` | `policy.fix` | policy engine | Planned | Capability map marks not implemented |
| `policy.evaluate` | `policy.evaluate` | policy engine | Planned | Capability map marks not implemented |
| `policy.recheck` | `policy.recheck` | policy engine | Planned | Capability map marks not implemented |
| `approval.submit` | `approval.submit` | instruction approval workflow | Planned | Roadmap issue exists |
| `response.persist` | `response.persist` | SQLite response store | Planned | Roadmap issue exists |
| `response.aggregate` | `response.aggregate` | aggregation engine | Planned | Roadmap issue exists |
| `response.export` | `response.export` | CSV/JSON export | Planned | Roadmap issue exists |

### 9.1 Recommended Windows native adapters behind builtins

These should remain internal implementation details, not direct content-author interfaces:

- Service Control Manager
- Event Log API / Windows Eventing
- Registry APIs
- WMI / CIM
- ReadDirectoryChangesW
- Task Scheduler
- Certificate Store / enrollment APIs
- Firewall APIs / NetSecurity surfaces
- BitLocker APIs / WMI bridges
- WinHTTP / BITS or equivalent download path
- session / notification APIs for user interaction
- SetupAPI / PnP for device and driver operations

---

## 10. Linux builtin mapping

| Primitive | Yuzu builtin | Backing plugin / adapter | Status | Notes |
|---|---|---|---|---|
| `system.info` | `system.info` | `os_info` | Verified | Cross-platform |
| `system.status` | `system.status` | `status` | Verified | Cross-platform |
| `device.identity` | `device.identity` | `device_identity` | Verified | Cross-platform |
| `hardware.inventory` | `hardware.inventory` | `hardware` | Verified | Cross-platform |
| `process.list` | `process.list` | `processes`, `procfetch` | Verified | Cross-platform |
| `process.kill` | `process.kill` | `processes` | Verified | Cross-platform |
| `process.start` | `process.start` | `script_exec` / future process adapter | Proposed | Same rationale as Windows |
| `service.list` | `service.list` | `services` | Verified | Likely systemd/service abstraction |
| `service.inspect` | `service.inspect` | `services` | Proposed | Natural structured wrapper |
| `service.start` | `service.start` | `services` | Verified | Supported |
| `service.stop` | `service.stop` | `services` | Verified | Supported |
| `service.restart` | `service.restart` | `services` | Verified | Supported |
| `user.logged_on` | `user.logged_on` | `users` | Verified | Cross-platform |
| `user.group_membership` | `user.group_membership` | future users/groups plugin | Planned | Roadmap issue exists |
| `network.config.get` | `network.config.get` | `network_config` | Verified | Cross-platform |
| `network.connection.list` | `network.connection.list` | `netstat` | Verified | Cross-platform |
| `network.socket.owner` | `network.socket.owner` | `sockwho` | Verified | Cross-platform |
| `network.diagnostics.run` | `network.diagnostics.run` | `network_diag` | Verified | Cross-platform |
| `network.adapter.enable` | `network.adapter.enable` | `network_actions` | Verified | Cross-platform |
| `network.adapter.disable` | `network.adapter.disable` | `network_actions` | Verified | Cross-platform |
| `network.quarantine` | `network.quarantine` | future quarantine subsystem | Planned | Requires Linux enforcement adapter |
| `software.inventory` | `software.inventory` | `installed_apps` | Verified | Cross-platform high-level inventory |
| `software.package.inventory` | `software.package.inventory` | distro-specific package adapter | Proposed | Useful explicit Linux primitive |
| `software.uninstall` | `software.uninstall` | `software_actions` | Verified | Cross-platform uninstall surface |
| `software.install` | `software.install` | staged package execution | Planned | Needs content staging |
| `software.update` | `software.update` | package-manager adapter | Proposed | High-value Linux builtin |
| `patch.scan` | `patch.scan` | vuln/package adapter | Proposed | Enterprise patch assessment |
| `file.list` | `file.list` | `filesystem` | Verified | Cross-platform |
| `file.search` | `file.search` | `filesystem` | Verified | Cross-platform |
| `file.read` | `file.read` | `filesystem` | Verified | Basic read |
| `file.write` | `file.write` | future filesystem advanced ops | Planned | Roadmap issue exists |
| `file.hash` | `file.hash` | `filesystem` | Verified | Supported |
| `file.delete` | `file.delete` | `filesystem` | Verified | Supported |
| `file.exists` | `file.exists` | `filesystem` | Verified | Supported |
| `file.permissions.inspect` | `file.permissions.inspect` | POSIX ACL / stat adapter | Planned | Not yet implemented in capability map |
| `file.signature.verify` | `file.signature.verify` | package/file signature adapter | Planned | Not yet implemented |
| `file.temp.create` | `file.temp.create` | secure temp-file helper | Planned | Foundation gap |
| `content.download` | `content.download` | agent HTTP transfer | Planned | Roadmap issue exists |
| `content.upload` | `content.upload` | agent HTTP transfer | Planned | Roadmap issue exists |
| `content.stage` | `content.stage` | content staging subsystem | Planned | Roadmap issue exists |
| `content.execute` | `content.execute` | `script_exec` + staging | Planned | Roadmap issue exists |
| `security.antivirus.status` | `security.antivirus.status` | `antivirus` | Verified | Cross-platform |
| `security.firewall.status` | `security.firewall.status` | `firewall` | Verified | Cross-platform |
| `security.firewall.rules.list` | `security.firewall.rules.list` | `firewall` | Verified | Cross-platform rule-oriented surface |
| `security.disk_encryption.status` | `security.disk_encryption.status` | LUKS adapter | Proposed | Capability map says Linux coverage absent today |
| `security.vulnerability.scan` | `security.vulnerability.scan` | `vuln_scan` | Verified | Cross-platform |
| `security.event_log.query` | `security.event_log.query` | `event_logs` | Verified | Likely journald/syslog abstraction |
| `security.ioc.check` | `security.ioc.check` | future IOC subsystem | Planned | Roadmap issue exists |
| `security.certificate.inventory` | `security.certificate.inventory` | future certificate plugin | Planned | Roadmap issue exists |
| `trigger.interval` | `trigger.interval` | trigger framework | Planned | Not implemented |
| `trigger.filesystem_change` | `trigger.filesystem_change` | filesystem watcher | Planned | Not implemented |
| `trigger.service_change` | `trigger.service_change` | service watcher | Planned | Not implemented |
| `trigger.agent_startup` | `trigger.agent_startup` | agent lifecycle hook | Planned | Not implemented |
| `policy.check` | `policy.check` | policy engine | Planned | Not implemented |
| `policy.fix` | `policy.fix` | policy engine | Planned | Not implemented |
| `policy.evaluate` | `policy.evaluate` | policy engine | Planned | Not implemented |
| `approval.submit` | `approval.submit` | instruction approval workflow | Planned | Roadmap issue exists |
| `response.persist` | `response.persist` | SQLite response store | Planned | Roadmap issue exists |
| `response.aggregate` | `response.aggregate` | aggregation engine | Planned | Roadmap issue exists |
| `response.export` | `response.export` | CSV/JSON export | Planned | Roadmap issue exists |

### 10.1 Recommended Linux native adapters behind builtins

- systemd / D-Bus
- inotify
- procfs / sysfs
- journald / syslog
- package managers (`apt`, `dnf`, `yum`, `zypper`, etc.)
- nftables / iptables or higher-level firewall APIs
- POSIX account / group management surfaces
- certificate store / OpenSSL / distro CA tooling as needed

---

## 11. macOS builtin mapping

| Primitive | Yuzu builtin | Backing plugin / adapter | Status | Notes |
|---|---|---|---|---|
| `system.info` | `system.info` | `os_info` | Verified | Cross-platform |
| `system.status` | `system.status` | `status` | Verified | Cross-platform |
| `device.identity` | `device.identity` | `device_identity` | Verified | Cross-platform |
| `hardware.inventory` | `hardware.inventory` | `hardware` | Verified | Cross-platform |
| `process.list` | `process.list` | `processes`, `procfetch` | Verified | Cross-platform |
| `process.kill` | `process.kill` | `processes` | Verified | Cross-platform |
| `process.start` | `process.start` | `script_exec` / future process adapter | Proposed | Same rationale as other OSes |
| `service.list` | `service.list` | `services` | Verified | Should abstract launchd/service concepts |
| `service.inspect` | `service.inspect` | `services` | Proposed | Natural wrapper |
| `service.start` | `service.start` | `services` | Verified | Supported |
| `service.stop` | `service.stop` | `services` | Verified | Supported |
| `service.restart` | `service.restart` | `services` | Verified | Supported |
| `user.logged_on` | `user.logged_on` | `users` | Verified | Cross-platform |
| `user.group_membership` | `user.group_membership` | future users/groups plugin | Planned | Roadmap issue exists |
| `network.config.get` | `network.config.get` | `network_config` | Verified | Cross-platform |
| `network.connection.list` | `network.connection.list` | `netstat` | Verified | Cross-platform |
| `network.socket.owner` | `network.socket.owner` | `sockwho` | Verified | Cross-platform |
| `network.diagnostics.run` | `network.diagnostics.run` | `network_diag` | Verified | Cross-platform |
| `network.adapter.enable` | `network.adapter.enable` | `network_actions` | Verified | Cross-platform |
| `network.adapter.disable` | `network.adapter.disable` | `network_actions` | Verified | Cross-platform |
| `software.inventory` | `software.inventory` | `installed_apps` | Verified | Cross-platform |
| `software.package.inventory` | `software.package.inventory` | pkg/app bundle adapter | Proposed | Desirable explicit builtin |
| `software.uninstall` | `software.uninstall` | `software_actions` | Verified | Cross-platform uninstall surface |
| `software.install` | `software.install` | staged pkg execution | Planned | Needs content staging |
| `software.update` | `software.update` | pkg / softwareupdate adapter | Proposed | High-value explicit builtin |
| `file.list` | `file.list` | `filesystem` | Verified | Cross-platform |
| `file.search` | `file.search` | `filesystem` | Verified | Cross-platform |
| `file.read` | `file.read` | `filesystem` | Verified | Basic read |
| `file.write` | `file.write` | future filesystem advanced ops | Planned | Roadmap issue exists |
| `file.hash` | `file.hash` | `filesystem` | Verified | Supported |
| `file.delete` | `file.delete` | `filesystem` | Verified | Supported |
| `file.exists` | `file.exists` | `filesystem` | Verified | Supported |
| `file.permissions.inspect` | `file.permissions.inspect` | ACL / stat adapter | Planned | Not yet implemented |
| `file.signature.verify` | `file.signature.verify` | codesign verification adapter | Planned | Not yet implemented |
| `file.temp.create` | `file.temp.create` | secure temp-file helper | Planned | Foundation gap |
| `content.download` | `content.download` | agent HTTP transfer | Planned | Roadmap issue exists |
| `content.upload` | `content.upload` | agent HTTP transfer | Planned | Roadmap issue exists |
| `content.stage` | `content.stage` | content staging subsystem | Planned | Roadmap issue exists |
| `content.execute` | `content.execute` | `script_exec` + staging | Planned | Roadmap issue exists |
| `security.antivirus.status` | `security.antivirus.status` | `antivirus` | Verified | Cross-platform |
| `security.firewall.status` | `security.firewall.status` | `firewall` | Verified | Cross-platform |
| `security.firewall.rules.list` | `security.firewall.rules.list` | `firewall` | Verified | Cross-platform surface |
| `security.disk_encryption.status` | `security.disk_encryption.status` | FileVault adapter | Proposed | Capability map says macOS encryption coverage absent today |
| `security.vulnerability.scan` | `security.vulnerability.scan` | `vuln_scan` | Verified | Cross-platform |
| `security.event_log.query` | `security.event_log.query` | `event_logs` | Verified | macOS logging abstraction |
| `security.certificate.inventory` | `security.certificate.inventory` | future certificate plugin | Planned | Roadmap issue exists |
| `trigger.interval` | `trigger.interval` | trigger framework | Planned | Not implemented |
| `trigger.filesystem_change` | `trigger.filesystem_change` | filesystem watcher | Planned | Not implemented |
| `trigger.service_change` | `trigger.service_change` | launchd/service watcher | Planned | Not implemented |
| `trigger.agent_startup` | `trigger.agent_startup` | agent lifecycle hook | Planned | Not implemented |
| `policy.check` | `policy.check` | policy engine | Planned | Not implemented |
| `policy.fix` | `policy.fix` | policy engine | Planned | Not implemented |
| `policy.evaluate` | `policy.evaluate` | policy engine | Planned | Not implemented |
| `approval.submit` | `approval.submit` | instruction approval workflow | Planned | Roadmap issue exists |
| `response.persist` | `response.persist` | SQLite response store | Planned | Roadmap issue exists |
| `response.aggregate` | `response.aggregate` | aggregation engine | Planned | Roadmap issue exists |
| `response.export` | `response.export` | CSV/JSON export | Planned | Roadmap issue exists |

### 11.1 Recommended macOS native adapters behind builtins

- launchd
- FSEvents
- unified logging
- system profiler / package inventory surfaces
- `softwareupdate` / package installation surfaces
- `codesign` / notarization verification surfaces
- FileVault status interfaces
- user notification frameworks

---

## 12. Recommended builtin surface for content authors

These are the names content authors should see, regardless of OS:

### 12.1 Core action builtins

- `system.info`
- `hardware.inventory`
- `process.list`
- `process.kill`
- `service.inspect`
- `service.restart`
- `software.inventory`
- `software.uninstall`
- `patch.inventory`
- `file.exists`
- `file.hash`
- `security.firewall.status`
- `security.disk_encryption.status`
- `security.vulnerability.scan`

### 12.2 Workflow builtins

- `workflow.if`
- `workflow.switch`
- `workflow.foreach`
- `workflow.parallel`
- `workflow.retry`
- `workflow.assert`
- `result.filter`
- `result.join`
- `result.group_by`
- `response.aggregate`

### 12.3 Governance builtins

- `scope.estimate_targets`
- `approval.submit`
- `audit.emit`
- `response.persist`
- `policy.evaluate`
- `policy.recheck`

### 12.4 Trigger builtins

- `trigger.interval`
- `trigger.filesystem_change`
- `trigger.service_change`
- `trigger.windows_event_log`
- `trigger.agent_startup`

---

## 13. Data model and result-shaping recommendations

Because the capability map notes that plugin output is currently pipe-delimited, Yuzu should define a canonical structured result format before building a full instruction ecosystem.

### 13.1 Proposed canonical result envelope

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionResult
metadata:
  instructionRunId: irun_01J...
  instructionDefinitionId: windows.service.inspect
  agentId: 28d5...
  deviceId: 28d5...
  timestamp: 2026-03-16T18:20:00Z
spec:
  status: success        # success | failure | partial | timeout | cancelled
  durationMs: 182
  columns:
    - name: serviceName
      type: string
    - name: state
      type: string
    - name: startupType
      type: string
  rows:
    - serviceName: Spooler
      state: running
      startupType: automatic
  diagnostics:
    stdout: ""
    stderr: ""
    warnings: []
```

### 13.2 Why this matters

Without a typed result envelope, the following become fragile:

- workflow chaining,
- filtering and pagination,
- aggregate progress views,
- policy evaluation,
- data export,
- pack portability,
- dashboard composition.

---

## 14. Recommended implementation order

### Phase A â make responses first-class

1. Server-side response persistence  
2. Filtering, pagination, sorting  
3. Aggregation engine  
4. Canonical structured result envelope  
5. CSV/JSON export

### Phase B â build the instruction plane

6. InstructionDefinition store  
7. InstructionSet model  
8. Parameter schemas  
9. Result schemas  
10. Signing/versioning  
11. Target estimation

### Phase C â add governed execution

12. Scheduling  
13. Approval workflows  
14. Progress/statistics  
15. Rerun/cancel semantics  
16. Audit trail

### Phase D â add policy and triggers

17. Trigger framework  
18. PolicyFragments  
19. Policy assignment  
20. Compliance views  
21. Suppression/exemption model  
22. Re-evaluation controls

### Phase E â add distribution

23. ProductPack format  
24. Signatures/checksums  
25. Import/export workflow  
26. Dependency resolution  
27. Staged rollout and pack promotion

---

## 15. Concrete design judgments

### 15.1 What Yuzu should expose

Expose:

- stable builtins,
- typed schemas,
- result-shaping operators,
- trigger templates,
- governance primitives,
- content-pack metadata.

### 15.2 What Yuzu should not expose directly

Do **not** expose directly to content authors:

- Win32/SCM/Registry/WMI syscalls,
- Linux `ioctl` / `procfs` / `dbus-send` level details,
- macOS FSEvents / launchd / codesign invocation details,
- arbitrary shell text as the primary authoring model.

Those should remain internal adapters behind stable builtins.

### 15.3 What the principal permission boundary should be

Use **InstructionSet** as the main operational permission boundary:

- users execute sets or definitions within sets,
- authors publish to sets,
- approvers approve set-governed actions,
- packs distribute sets as units of capability.

This is cleaner than per-plugin ACLs as the user-facing governance model.

---

## 16. Minimal viable v1 content plane

A pragmatic MVP would include only:

- `InstructionDefinition`
- `InstructionSet`
- `PolicyFragment`
- `Policy`
- `TriggerTemplate`
- `ProductPack`
- structured result envelope
- response store
- scheduling
- approval workflow

That is enough to move Yuzu from âplugin executorâ to âgoverned endpoint instruction platformâ.

---

## 17. Final recommendation

The repository now clearly points toward the correct product destination, but most of that destination is still roadmap rather than implementation.

The right move is therefore:

- **freeze a stable builtin surface**,
- **build the content plane above it**,
- **keep OS-specific complexity inside adapters/plugins**,
- **ship signed packs of definitions and policies rather than more bespoke plugin logic**.

That is the path that best matches Yuzuâs stated architecture, current plugin substrate, and future ambition.

---

## 18. Source notes

This design note was grounded in the following public sources from the Yuzu `dev` branch:

1. Repository README / architecture and positioning
2. `docs/capability-map.md`
3. `docs/roadmap.md`
4. `sdk/include/yuzu/plugin.h`