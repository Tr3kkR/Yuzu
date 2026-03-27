# Yuzu YAML DSL Specification

**Version:** v1alpha1
**API Version:** `yuzu.io/v1alpha1`
**Status:** Normative specification
**Audience:** Content authors, integrators, plugin developers
**Basis:** `docs/Instruction-Engine.md` design document

---

## Table of Contents

1. [Overview](#1-overview)
2. [Document Structure](#2-document-structure)
3. [Kind: InstructionDefinition](#3-kind-instructiondefinition)
4. [Kind: InstructionSet](#4-kind-instructionset)
5. [Kind: PolicyFragment (Phase 5)](#5-kind-policyfragment-phase-5)
6. [Kind: Policy (Phase 5)](#6-kind-policy-phase-5)
7. [Kind: TriggerTemplate (Phase 4)](#7-kind-triggertemplate-phase-4)
8. [Kind: ProductPack (Phase 7)](#8-kind-productpack-phase-7)
9. [Expression Language](#9-expression-language)
10. [Parameter Type System](#10-parameter-type-system)
11. [Result Column Type System](#11-result-column-type-system)
12. [Concurrency Model](#12-concurrency-model)
13. [Error Code Taxonomy](#13-error-code-taxonomy)
14. [Substrate Primitive Reference](#14-substrate-primitive-reference)

---

## 1. Overview

Yuzu's YAML DSL defines the content model for the instruction engine. All instruction content -- definitions, grouping, policy, triggers, and distribution bundles -- is authored as YAML documents conforming to this specification.

Every document begins with `apiVersion: yuzu.io/v1alpha1` and a `kind` field that determines its schema. The six kinds form a compositional hierarchy:

```
ProductPack
 +-- InstructionSet[]
      +-- InstructionDefinition[]
           |-- Parameter Schema
           |-- Result Schema
           +-- Execution Spec (plugin + action + defaults)

PolicyFragment
 |-- Check: ref -> InstructionDefinition
 |-- Compliance expression
 |-- Fix: ref -> InstructionDefinition
 +-- PostCheck: ref -> InstructionDefinition

Policy
 |-- Scope (device targeting)
 |-- Fragment ref + parameter bindings
 |-- Trigger refs
 +-- Rollout strategy

TriggerTemplate
 |-- Source type (interval, file, service, event_log, registry, startup)
 |-- Parameter schema
 +-- Debounce config
```

A definition can exist standalone (without a set or pack). Sets are the permission boundary. Packs are the distribution boundary.

---

## 2. Document Structure

Every YAML document MUST contain the following top-level fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `apiVersion` | string | Yes | Must be `yuzu.io/v1alpha1`. |
| `kind` | string | Yes | One of: `InstructionDefinition`, `InstructionSet`, `PolicyFragment`, `Policy`, `TriggerTemplate`, `ProductPack`. |
| `metadata` | object | Yes | Identity and descriptive fields. Structure varies by kind. |
| `spec` | object | Yes (except InstructionSet) | Kind-specific specification. InstructionSet uses top-level fields instead. |
| `status` | object | No | Runtime status. Set by the server, not by authors. |

---

## 3. Kind: InstructionDefinition

The core unit of the content model. Every ad-hoc command, scheduled task, policy check, and remediation action is an InstructionDefinition.

### 3.1 Full Schema

#### `metadata`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | Yes | -- | Globally unique identifier. Convention: `<scope>.<domain>.<action>` (e.g., `crossplatform.service.inspect`). |
| `displayName` | string | Yes | -- | Human-readable name shown in the dashboard. |
| `version` | string | Yes | -- | Semantic version (e.g., `1.2.0`). Used for compatibility checks and pack versioning. |
| `description` | string | No | `""` | Detailed description of what this definition does. |
| `tags` | list of string | No | `[]` | Freeform tags for categorization and search. |

#### `spec`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | `question` (read-only, does not modify state) or `action` (may modify state). Determines approval defaults and UI treatment. |
| `platforms` | list of string | Yes | -- | Target platforms. Values: `windows`, `linux`, `darwin`. |
| `execution` | object | Yes | -- | Execution configuration. See below. |
| `parameters` | object | No | `{}` | JSON Schema subset defining input parameters. See below. |
| `result` | object | No | `{}` | Result schema defining output columns and aggregation. See below. |
| `readablePayload` | string | No | `""` | Human-readable template string for audit display. Supports `${paramName}` interpolation. |
| `gather` | object | No | -- | Gather window configuration. |
| `response` | object | No | -- | Response storage configuration. |
| `approval` | object | No | -- | Approval workflow configuration. |
| `permissions` | object | No | -- | Role-based access control. |
| `compatibility` | object | No | -- | Agent version and plugin requirements. |
| `legacy_shim` | object | No | -- | Auto-generation from plugin descriptors. |

#### `spec.execution`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `plugin` | string | Yes | -- | Plugin identifier (must match a registered plugin's `name` field). |
| `action` | string | Yes | -- | Action name (must exist in the plugin's `actions[]` array). |
| `concurrency` | string | No | `per-device` | Concurrency mode. Values: `per-device`, `per-definition`, `per-set`, `global:<N>`, `unlimited`. See [Section 12](#12-concurrency-model). |
| `stagger` | object | No | -- | Stagger configuration for large-fleet dispatch. |
| `minSuccessPercent` | integer | No | `100` | Minimum percentage of agents that must succeed. `0` = best-effort, `100` = all must succeed. |

#### `spec.execution.stagger`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `maxDelaySeconds` | integer | No | `0` | Maximum random delay before execution on each agent. `0` = no stagger (all agents execute immediately). |
| `fixedDelaySeconds` | integer | No | `0` | Fixed delay before execution on each agent, added before the random stagger. `0` = no fixed delay. Total wait = `fixedDelaySeconds` + random(`0`, `maxDelaySeconds`). |

#### `spec.parameters`

A JSON Schema subset. The root object describes the parameter shape.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | Must be `object`. |
| `required` | list of string | No | `[]` | List of parameter names that must be provided. |
| `properties` | map of string to object | Yes | -- | Parameter definitions. Each key is a parameter name; value is a parameter descriptor. |

Each parameter descriptor supports:

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | Parameter type. Values: `string`, `boolean`, `int32`, `int64`, `datetime`, `guid`. See [Section 10](#10-parameter-type-system). |
| `displayName` | string | No | -- | Human-readable label for the dashboard form. |
| `description` | string | No | `""` | Parameter description. |
| `default` | varies | No | -- | Default value if not provided. Must match the declared type. |
| `validation` | object | No | -- | Validation constraints. See below. |

#### `spec.parameters.properties.<name>.validation`

| Field | Type | Applicable Types | Description |
|---|---|---|---|
| `maxLength` | integer | `string` | Maximum string length. |
| `minLength` | integer | `string` | Minimum string length. |
| `pattern` | string | `string` | Regular expression the value must match. |
| `enum` | list | `string` | Allowed values. The value must be one of the listed strings. |
| `minimum` | number | `int32`, `int64` | Minimum numeric value (inclusive). |
| `maximum` | number | `int32`, `int64` | Maximum numeric value (inclusive). |

#### `spec.result`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `columns` | list of object | Yes | -- | Result column definitions. |
| `aggregation` | object | No | -- | Server-side aggregation configuration. |

Each column object:

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | Yes | -- | Column identifier. |
| `type` | string | Yes | -- | Column type. Values: `bool`, `int32`, `int64`, `string`, `datetime`, `guid`, `clob`. See [Section 11](#11-result-column-type-system). |

#### `spec.result.aggregation`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `groupBy` | list of string | No | `[]` | Column names to group by when aggregating across agents. |
| `operations` | list of string | No | `[]` | Aggregation operations. Values: `count`, `sum`, `avg`, `min`, `max`. |

#### `spec.gather`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `ttlSeconds` | integer | No | `300` | Maximum time (in seconds) the agent has to respond. After this window, the execution is marked as timed out. |

#### `spec.response`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `retentionDays` | integer | No | `90` | Number of days to retain response data in the ResponseStore before TTL cleanup. |

#### `spec.approval`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | string | No | `auto` | Approval mode. `auto` -- no approval required. `role-gated` -- requires approval from a user with an approved role. `always` -- every execution requires explicit approval. |

#### `spec.permissions`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `executeRoles` | list of string | No | `[]` | Roles permitted to execute this definition. Empty list means no restriction. |
| `authorRoles` | list of string | No | `[]` | Roles permitted to create or modify this definition. |

#### `spec.compatibility`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `minAgentVersion` | string | No | -- | Minimum agent version required to execute this definition. Agents below this version are skipped during dispatch (error `4003`). |
| `requiredPlugins` | list of string | No | `[]` | Plugins that must be loaded on the agent. If any required plugin is missing, the agent is skipped (error `4001`). |

#### `spec.legacy_shim`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `enabled` | boolean | No | `false` | When `true`, this definition was auto-generated from a plugin descriptor. The parameter schema uses `additionalProperties: {type: string}` (open schema). |

#### `status`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `phase` | string | No | `proposed` | Lifecycle phase. Values: `proposed`, `active`, `deprecated`, `archived`. Set by the server. |

### 3.2 Complete Example

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: crossplatform.service.inspect
  displayName: Inspect Service Status
  version: 1.2.0
  description: Returns the current state, startup type, and PID of a named service.
  tags:
    - services
    - operations
spec:
  type: question                         # question (read-only) | action (may modify state)
  platforms:
    - windows
    - linux
    - darwin
  execution:
    plugin: services
    action: inspect
    concurrency: per-device              # per-device | per-definition | per-set | global:<N> | unlimited
    stagger:
      maxDelaySeconds: 0                 # 0 = no stagger
      fixedDelaySeconds: 0               # 0 = no fixed delay
  parameters:
    type: object
    required:
      - serviceName
    properties:
      serviceName:
        type: string
        displayName: Service Name
        description: The name of the service to inspect.
        validation:
          maxLength: 256
      verbose:
        type: boolean
        default: false
  result:
    columns:
      - name: serviceName
        type: string
      - name: state
        type: string
      - name: startupType
        type: string
      - name: pid
        type: int32
    aggregation:
      groupBy:
        - state
      operations:
        - count
  readablePayload: "Inspect service '${serviceName}'"
  gather:
    ttlSeconds: 300                      # agent must respond within this window
  response:
    retentionDays: 90
  approval:
    mode: auto                           # auto | role-gated | always
  permissions:
    executeRoles:
      - endpoint-operator
      - endpoint-admin
    authorRoles:
      - content-author
  compatibility:
    minAgentVersion: 0.9.0
    requiredPlugins:
      - services
  legacy_shim:
    enabled: true                        # auto-generate from plugin descriptor if true
status:
  phase: proposed
```

---

## 4. Kind: InstructionSet

The grouping unit and permission boundary. Sets aggregate definitions, policy fragments, and workflow templates under a shared permission model.

### 4.1 Full Schema

#### `metadata`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | Yes | -- | Globally unique identifier. Convention: `<scope>.<domain>.<area>` (e.g., `core.crossplatform.services`). |
| `displayName` | string | Yes | -- | Human-readable name. |
| `version` | string | Yes | -- | Semantic version. |
| `description` | string | No | `""` | Detailed description. |
| `platforms` | list of string | No | `[]` | Target platforms. Values: `windows`, `linux`, `darwin`. |
| `permissions` | object | No | -- | Set-level role-based access control. |
| `contents` | object | Yes | -- | References to contained items. |
| `defaults` | object | No | -- | Default values applied to contained definitions. |
| `publishing` | object | No | -- | Publishing and visibility configuration. |

#### `metadata.permissions`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `executeRoles` | list of string | No | `[]` | Roles permitted to execute definitions in this set. |
| `authorRoles` | list of string | No | `[]` | Roles permitted to author or modify definitions in this set. |
| `approveRoles` | list of string | No | `[]` | Roles permitted to approve executions of definitions in this set. |

#### `metadata.contents`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `instructionDefinitions` | list of string | No | `[]` | IDs of InstructionDefinition documents included in this set. |
| `policyFragments` | list of string | No | `[]` | IDs of PolicyFragment documents included in this set. |
| `workflowTemplates` | list of string | No | `[]` | IDs of workflow templates included in this set. |

#### `metadata.defaults`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `approvalMode` | string | No | `auto` | Default approval mode for definitions in this set that do not specify their own. Values: `auto`, `role-gated`, `always`. |
| `responseRetentionDays` | integer | No | `90` | Default response retention for definitions in this set. |
| `targetEstimationRequiredAbove` | integer | No | -- | When the estimated target device count exceeds this threshold, the UI requires the operator to confirm before dispatch. |

#### `metadata.publishing`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `signed` | boolean | No | `false` | Whether this set is cryptographically signed. |
| `visibility` | string | No | `org` | Visibility scope. Values: `org` (visible to the organization), `private` (visible only to authors), `public` (visible to all). |

#### `status`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `phase` | string | No | `proposed` | Lifecycle phase. Values: `proposed`, `active`, `deprecated`, `archived`. |

### 4.2 Complete Example

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionSet
metadata:
  id: core.crossplatform.services
  displayName: Cross-Platform Service Management
  version: 1.0.0
  description: Inspect, start, stop, and restart services across all platforms.
  platforms:
    - windows
    - linux
    - darwin
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
      - crossplatform.service.inspect
      - crossplatform.service.start
      - crossplatform.service.stop
      - crossplatform.service.restart
      - crossplatform.service.set_start_mode
    policyFragments:
      - fragment.service.must_be_running
    workflowTemplates:
      - workflow.restart_then_verify
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

---

## 5. Kind: PolicyFragment (Phase 5)

> **Implementation phase:** Phase 5 -- Policy engine. Not yet implemented.

A reusable check/fix block that encapsulates a compliance check, optional remediation, and post-check verification. Fragments are composed into Policies (Section 6) for deployment to device scopes.

### 5.1 Full Schema

#### `metadata`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | Yes | -- | Globally unique identifier. Convention: `fragment.<domain>.<check>` (e.g., `fragment.service.must_be_running`). |
| `displayName` | string | Yes | -- | Human-readable name. |
| `version` | string | Yes | -- | Semantic version. |
| `description` | string | No | `""` | Detailed description. |

#### `spec`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `platforms` | list of string | Yes | -- | Target platforms. Values: `windows`, `linux`, `darwin`. |
| `inputs` | object | Yes | -- | JSON Schema subset defining input parameters for this fragment. Same schema format as InstructionDefinition `parameters`. |
| `check` | object | Yes | -- | The compliance check to run. |
| `compliance` | object | Yes | -- | Compliance evaluation rules. |
| `fix` | object | No | -- | Optional remediation action. |
| `postCheck` | object | No | -- | Optional post-remediation verification. |
| `debounce` | object | No | -- | Rate-limiting configuration. |
| `exceptionModel` | object | No | -- | Exception and suppression configuration. |

#### `spec.inputs`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | Must be `object`. |
| `required` | list of string | No | `[]` | Required input parameter names. |
| `properties` | map of string to object | Yes | -- | Input parameter definitions. Each value follows the same schema as InstructionDefinition parameter descriptors. |

#### `spec.check`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `ref` | string | Yes | -- | ID of the InstructionDefinition to execute as the compliance check. |
| `with` | map of string to string | No | `{}` | Parameter bindings. Values support `${inputs.<name>}` interpolation from fragment inputs. |

#### `spec.compliance`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `expression` | string | Yes | -- | Primary compliance expression. Evaluated against the check result. Uses CEL syntax (Phase 5). Example: `result.state == "running"`. |
| `states` | object | Yes | -- | State mapping expressions. |

#### `spec.compliance.states`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `compliant` | string | Yes | -- | Expression that evaluates to `true` when the device is compliant. Example: `result.state == "running"`. |
| `noncompliant` | string | Yes | -- | Expression that evaluates to `true` when the device is noncompliant. Example: `result.state != "running"`. |
| `error` | string | No | -- | Expression that evaluates to `true` when the check itself failed. Example: `result.error != null`. |

#### `spec.fix`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `when` | string | No | -- | Condition under which remediation is attempted. Supports `${inputs.<name>}` interpolation. Example: `${inputs.autoRemediate} == true`. |
| `ref` | string | Yes | -- | ID of the InstructionDefinition to execute as the remediation action. |
| `with` | map of string to string | No | `{}` | Parameter bindings. Values support `${inputs.<name>}` interpolation. |

#### `spec.postCheck`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `ref` | string | Yes | -- | ID of the InstructionDefinition to execute as the post-remediation verification check. |
| `with` | map of string to string | No | `{}` | Parameter bindings. Values support `${inputs.<name>}` interpolation. |

#### `spec.debounce`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `minIntervalSeconds` | integer | No | `300` | Minimum interval between consecutive evaluations of this fragment on a single device. Prevents remediation loops. |

#### `spec.exceptionModel`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `allowTemporarySuppressions` | boolean | No | `false` | When `true`, administrators can temporarily suppress this fragment for specific devices. |

#### `status`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `phase` | string | No | `proposed` | Lifecycle phase. Values: `proposed`, `active`, `deprecated`, `archived`. |

### 5.2 Complete Example

```yaml
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
metadata:
  id: fragment.service.must_be_running
  displayName: Service must be running
  version: 1.0.0
  description: Reusable fragment that checks a service and optionally restarts it.
spec:
  platforms:
    - windows
    - linux
    - darwin
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
    ref: crossplatform.service.inspect
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
    ref: crossplatform.service.restart
    with:
      serviceName: ${inputs.serviceName}
  postCheck:
    ref: crossplatform.service.inspect
    with:
      serviceName: ${inputs.serviceName}
  debounce:
    minIntervalSeconds: 300
  exceptionModel:
    allowTemporarySuppressions: true
status:
  phase: proposed
```

---

## 6. Kind: Policy (Phase 5)

> **Implementation phase:** Phase 5 -- Policy engine. Not yet implemented.

A Policy binds a PolicyFragment to a device scope and a set of triggers. Policies are the deployment unit for compliance enforcement.

### 6.1 Full Schema

#### `metadata`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | Yes | -- | Globally unique identifier. Convention: `policy.<platform>.<target>.<check>` (e.g., `policy.windows.spooler.running`). |
| `displayName` | string | Yes | -- | Human-readable name. |
| `version` | string | Yes | -- | Semantic version. |
| `description` | string | No | `""` | Detailed description. |

#### `spec`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `scope` | object | Yes | -- | Device targeting configuration. |
| `assignment` | object | No | -- | Management group assignment. |
| `fragment` | object | Yes | -- | PolicyFragment reference and parameter bindings. |
| `triggers` | list of object | No | `[]` | TriggerTemplate references that initiate evaluation. |
| `schedule` | object | No | -- | Cron-based evaluation schedule. |
| `rollout` | object | No | -- | Gradual rollout configuration. |
| `approvals` | object | No | -- | Approval requirements for deployment and changes. |
| `compliance` | object | No | -- | Compliance reporting configuration. |
| `exceptions` | object | No | -- | Device-level exception configuration. |

#### `spec.scope`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `selector` | object | Yes | -- | Device selector. |

#### `spec.scope.selector`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `platform` | string | No | -- | Target platform filter. Values: `windows`, `linux`, `darwin`. |
| `tags` | list of string | No | `[]` | Devices must have all listed tags. |

Note: For advanced targeting, use the Scope DSL expression language (Section 9) in the scope expression field of an execution rather than the selector shorthand.

#### `spec.assignment`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | string | No | `dynamic` | Assignment mode. `dynamic` -- devices matching the scope are continuously included. `static` -- devices are assigned at deployment time and do not change. |
| `managementGroups` | list of string | No | `[]` | Management group names to which this policy is assigned. |

#### `spec.fragment`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `ref` | string | Yes | -- | ID of the PolicyFragment to bind. |
| `with` | map of string to varies | No | `{}` | Parameter bindings passed to the fragment's `inputs`. |

#### `spec.triggers[]`

Each trigger object:

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `ref` | string | Yes | -- | ID of a TriggerTemplate. |
| `with` | map of string to varies | No | `{}` | Parameter bindings for the trigger. |

#### `spec.schedule`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `cron` | string | No | -- | Cron expression for periodic evaluation. Standard 5-field cron syntax. Example: `"*/15 * * * *"`. |
| `timezone` | string | No | `UTC` | IANA timezone name for cron evaluation. |

#### `spec.rollout`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `strategy` | string | No | `immediate` | Rollout strategy. Values: `immediate` (all devices at once), `gradual` (phased rollout). |
| `maxConcurrentPercent` | integer | No | `100` | Maximum percentage of in-scope devices that can be evaluating the policy concurrently. Only meaningful when `strategy` is `gradual`. |

#### `spec.approvals`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `requiredForInitialDeploy` | boolean | No | `false` | When `true`, deploying this policy for the first time requires approval. |
| `requiredForRemediationChange` | boolean | No | `false` | When `true`, changes to the fragment's fix action require approval before taking effect. |

#### `spec.compliance`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `cacheTtlSeconds` | integer | No | `300` | Duration (in seconds) to cache compliance evaluation results before requiring re-evaluation. |
| `responseRetentionDays` | integer | No | `90` | Number of days to retain compliance check response data. |
| `emitEventsOnStateChange` | boolean | No | `false` | When `true`, emit structured events when a device transitions between compliant, noncompliant, and error states. |

#### `spec.exceptions`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `allowDeviceLevelExemption` | boolean | No | `false` | When `true`, administrators can exempt individual devices from this policy. |
| `exemptionMaxDays` | integer | No | -- | Maximum number of days an exemption can remain active. After this period, the exemption expires and the policy resumes enforcement. |

#### `status`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `phase` | string | No | `proposed` | Lifecycle phase. Values: `proposed`, `active`, `deprecated`, `archived`. |

### 6.2 Complete Example

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
    ref: fragment.service.must_be_running
    with:
      serviceName: Spooler
      autoRemediate: true
  triggers:
    - ref: trigger.interval.five_minutes
    - ref: trigger.service_status_changed
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

---

## 7. Kind: TriggerTemplate (Phase 4)

> **Implementation phase:** Phase 4 -- Agent infrastructure. Not yet implemented.

A TriggerTemplate defines an event source that can initiate policy evaluation or instruction execution on the agent.

### 7.1 Full Schema

#### `metadata`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | Yes | -- | Globally unique identifier. Convention: `trigger.<platform>.<source>.<detail>` (e.g., `trigger.windows.eventlog.pattern`). |
| `displayName` | string | Yes | -- | Human-readable name. |
| `version` | string | Yes | -- | Semantic version. |
| `description` | string | No | `""` | Detailed description. |

#### `spec`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `platforms` | list of string | Yes | -- | Target platforms. Values: `windows`, `linux`, `darwin`. |
| `source` | object | Yes | -- | Event source configuration. |
| `parameters` | object | No | `{}` | JSON Schema subset defining configurable parameters for this trigger. Same schema format as InstructionDefinition `parameters`. |
| `debounce` | object | No | -- | Debounce configuration to prevent trigger storms. |
| `delivery` | object | No | -- | Event delivery configuration. |
| `outputs` | object | No | -- | JSON Schema subset describing the output payload produced when the trigger fires. |

#### `spec.source`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | Trigger source type. Values: `interval`, `filesystem`, `service`, `windows-event-log`, `registry`, `agent-startup`. |

Trigger source types:

| Type | Description | Platform |
|---|---|---|
| `interval` | Timer-based, minimum 30 seconds | All |
| `filesystem` | File/directory change notification (ReadDirectoryChangesW / inotify / FSEvents) | All |
| `service` | Service state change notification (SCM / systemd) | Windows, Linux |
| `windows-event-log` | Windows event log record matching | Windows only |
| `registry` | Registry key change notification | Windows only |
| `agent-startup` | Fires once when the agent starts | All |

#### `spec.debounce`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | string | No | `global` | Debounce mode. `global` -- one debounce timer for all events from this trigger. `keyed` -- separate debounce timers per unique key (computed from `keyExpression`). |
| `keyExpression` | string | No | -- | Expression that computes the debounce key from trigger event fields. Required when `mode` is `keyed`. Supports `${fieldName}` interpolation. |
| `minIntervalSeconds` | integer | No | `60` | Minimum interval between trigger firings. Events arriving within this window after a firing are suppressed. |

#### `spec.delivery`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | string | No | `local-agent` | Delivery mode. `local-agent` -- trigger is evaluated and delivered locally on the agent. |
| `persistTriggerEvents` | boolean | No | `false` | When `true`, trigger events are persisted to the agent's local KV store for diagnostic purposes. |

#### `spec.outputs`

A JSON Schema subset describing the structured payload produced when the trigger fires. This payload is available to downstream consumers (policy evaluations, instruction parameter bindings).

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | Yes | -- | Must be `object`. |
| `properties` | map of string to object | Yes | -- | Output field definitions. Each value specifies `type` (string, integer, boolean) and optional `description`. |

#### `status`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `phase` | string | No | `proposed` | Lifecycle phase. Values: `proposed`, `active`, `deprecated`, `archived`. |

### 7.2 Complete Example

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

---

## 8. Kind: ProductPack (Phase 7)

> **Implementation phase:** Phase 7 -- Scale and integration. Not yet implemented.

A ProductPack is a signed distribution bundle containing instruction sets, definitions, policy fragments, policies, trigger templates, dashboards, and documentation. Packs are the unit of distribution and trust.

### 8.1 Full Schema

#### `metadata`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | Yes | -- | Globally unique identifier. Convention: `pack.<scope>.<name>` (e.g., `pack.core.endpoint-ops`). |
| `displayName` | string | Yes | -- | Human-readable name. |
| `version` | string | Yes | -- | Semantic version. |
| `description` | string | No | `""` | Detailed description. |

#### `spec`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `publisher` | object | Yes | -- | Publisher identity. |
| `compatibility` | object | Yes | -- | Version and API compatibility requirements. |
| `contents` | object | Yes | -- | References to all items included in the pack. |
| `dependencies` | object | No | -- | Plugin and pack dependencies. |
| `security` | object | Yes | -- | Cryptographic signing and verification. |
| `distribution` | object | No | -- | Archive format and import behavior. |

#### `spec.publisher`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | Yes | -- | Publisher name (organization or individual). |
| `contact` | string | No | -- | Contact email address. |

#### `spec.compatibility`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `minServerVersion` | string | Yes | -- | Minimum Yuzu server version required to import this pack. |
| `minAgentVersion` | string | Yes | -- | Minimum Yuzu agent version required to execute content from this pack. |
| `requiredApiVersions` | list of string | No | `[]` | API versions that the server must support. Values: `yuzu.io/v1alpha1`. |

#### `spec.contents`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `instructionSets` | list of string | No | `[]` | IDs of InstructionSet documents included in the pack. |
| `instructionDefinitions` | list of string | No | `[]` | IDs of standalone InstructionDefinition documents included in the pack. |
| `policyFragments` | list of string | No | `[]` | IDs of PolicyFragment documents included in the pack. |
| `policies` | list of string | No | `[]` | IDs of Policy documents included in the pack. |
| `triggerTemplates` | list of string | No | `[]` | IDs of TriggerTemplate documents included in the pack. |
| `dashboards` | list of string | No | `[]` | IDs of dashboard definitions included in the pack. |
| `docs` | list of string | No | `[]` | Paths to documentation files included in the pack. |

#### `spec.dependencies`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `plugins` | list of string | No | `[]` | Agent plugins that must be available to execute content from this pack. |
| `packs` | list of string | No | `[]` | Other ProductPack IDs that this pack depends on. |

#### `spec.security`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `signing` | object | Yes | -- | Signing algorithm and key identification. |
| `signature` | object | Yes | -- | Manifest signature. |
| `checksums` | object | Yes | -- | Manifest integrity checksums. |
| `trustChain` | object | No | -- | Trust chain anchoring the signing key to an organization root key. |
| `revocationListUrl` | string | No | -- | URL of the JSON Certificate Revocation List for checking key revocation status. |

#### `spec.security.signing`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `algorithm` | string | Yes | -- | Signing algorithm. Must be `ed25519`. |
| `keyId` | string | Yes | -- | Identifier of the signing key. Used for key lookup in the trust store. |
| `keyFingerprint` | string | Yes | -- | SHA-256 fingerprint of the signing key. Format: `SHA256:<hex>`. |

#### `spec.security.signature`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `manifestHash` | string | Yes | -- | SHA-256 hash of the pack manifest file. |
| `value` | string | Yes | -- | Base64-encoded Ed25519 signature of the manifest hash. |

#### `spec.security.checksums`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `manifestSha256` | string | Yes | -- | SHA-256 hash of the manifest file. Used for integrity verification before signature check. |

#### `spec.security.trustChain`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `rootKeyFingerprint` | string | No | -- | SHA-256 fingerprint of the organization root key. Format: `SHA256:<hex>`. |
| `signingKeyCertificate` | string | No | -- | Base64-encoded DER certificate of the signing key, signed by the root key. |

#### `spec.distribution`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `format` | string | No | `tar.zst` | Archive format. Must be `tar.zst` (tar archive with Zstandard compression). |
| `importMode` | string | No | `staged` | Import behavior. `staged` -- contents are imported to a staging area and activated after review. `direct` -- contents are imported and activated immediately. |
| `allowPartialImport` | boolean | No | `false` | When `true`, the server imports items that pass validation even if some items fail. When `false`, the entire import is rejected on any validation failure. |

#### `status`

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `phase` | string | No | `proposed` | Lifecycle phase. Values: `proposed`, `active`, `deprecated`, `archived`. |

### 8.2 Complete Example

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
      - core.crossplatform.services
      - core.crossplatform.processes
    instructionDefinitions:
      - crossplatform.service.inspect
      - crossplatform.service.restart
      - crossplatform.process.list
      - crossplatform.process.kill
    policyFragments:
      - fragment.service.must_be_running
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
    signing:
      algorithm: ed25519
      keyId: yuzu-core-release-2026
      keyFingerprint: "SHA256:..."
    signature:
      manifestHash: <sha256-of-manifest>
      value: <base64-ed25519-signature>
    checksums:
      manifestSha256: <sha256>
    trustChain:
      rootKeyFingerprint: "SHA256:..."
      signingKeyCertificate: <base64-der>
    revocationListUrl: "https://packs.yuzu.example/crl.json"
  distribution:
    format: tar.zst
    importMode: staged
    allowPartialImport: false
status:
  phase: proposed
```

---

## 9. Expression Language

### 9.1 Scope DSL

The scope engine (`server/core/src/scope_engine.cpp`) implements a recursive-descent parser for device targeting expressions. This DSL is used in `spec.scope` fields and dashboard filter expressions.

#### Grammar

```
expr       ::= or_expr
or_expr    ::= and_expr ('OR' and_expr)*
and_expr   ::= not_expr ('AND' not_expr)*
not_expr   ::= 'NOT' not_expr | primary
primary    ::= '(' expr ')' | condition
condition  ::= IDENT op value
op         ::= '==' | '!=' | 'LIKE' | '<' | '>' | '<=' | '>=' | 'IN' | 'CONTAINS'
value      ::= QUOTED_STRING | '(' value_list ')' | IDENT
value_list ::= value (',' value)*
```

#### Operators

| Operator | Description | Example |
|---|---|---|
| `==` | Equality | `ostype == "windows"` |
| `!=` | Inequality | `ostype != "linux"` |
| `LIKE` | Wildcard matching (`*` and `?` globbing) | `hostname LIKE "web-*"` |
| `<` | Less than (numeric comparison) | `agent_version < "1.0.0"` |
| `>` | Greater than (numeric comparison) | `cpu_count > "4"` |
| `<=` | Less than or equal | `agent_version <= "0.9.0"` |
| `>=` | Greater than or equal | `agent_version >= "0.9.0"` |
| `IN` | Membership in a value list | `arch IN ("x86_64", "aarch64")` |
| `CONTAINS` | Case-insensitive substring search | `hostname CONTAINS "prod"` |

#### Combinators

| Combinator | Description | Example |
|---|---|---|
| `AND` | Logical conjunction | `ostype == "windows" AND tag:env == "production"` |
| `OR` | Logical disjunction | `hostname LIKE "web-*" OR hostname LIKE "api-*"` |
| `NOT` | Logical negation | `NOT tag:quarantined == "true"` |

#### Features

- Case-insensitive keyword matching (AND, OR, NOT, LIKE, IN, CONTAINS)
- Wildcard LIKE with `*` (match any characters) and `?` (match single character) globbing
- Numeric comparison with `std::from_chars` fallback to `std::stod` (Apple libc++ compatibility)
- Case-insensitive substring search via CONTAINS
- Maximum nesting depth of 10
- `AttributeResolver` callback decouples parsing from data access

#### Examples

```
ostype == "windows" AND tag:env == "production"
hostname LIKE "web-*" OR hostname LIKE "api-*"
arch IN ("x86_64", "aarch64") AND NOT tag:quarantined == "true"
agent_version >= "0.9.0"
```

### 9.2 Planned Scope DSL Extensions

| Extension | Syntax | Use Case |
|---|---|---|
| `MATCHES` | `hostname MATCHES "^web-\\d+$"` | Regex matching for complex patterns |
| `EXISTS` | `EXISTS tag:env` | Tag presence check (no value comparison) |
| `len()` | `len(tag:name) > 5` | String length for validation |
| `startswith()` | `startswith(hostname, "web-")` | Prefix check (more readable than LIKE) |

### 9.3 CEL (Common Expression Language)

Yuzu implements a CEL-compatible expression evaluator (`server/core/src/cel_eval.cpp`) for typed policy evaluation expressions. CEL is not used for device targeting (the scope DSL is simpler and sufficient for that purpose).

**Where CEL applies:**

- `spec.compliance.expression` in PolicyFragments
- `spec.fix.when` conditional expressions in PolicyFragments
- `spec.rollout.condition` for staged rollouts in Policies
- `WorkflowStep.condition` for conditional workflow steps

**Where the scope DSL stays:**

- All device targeting (`spec.scope.selector`)
- `ScopeEngine` evaluation in the dispatch path
- Dashboard filter expressions

#### Type System

| Type | CEL Syntax | Examples |
|---|---|---|
| null | `null` | `result.error == null` |
| bool | `true`, `false` | `result.enabled == true` |
| int | integer literals | `result.count > 5`, `3 + 4` |
| double | floating-point literals | `result.score >= 80.5` |
| string | single or double quotes | `result.status == 'running'` |
| timestamp | `timestamp('...')` | `timestamp('2024-01-15T10:30:00Z')` |
| duration | `duration('...')` | `duration('1h')`, `duration('30m')`, `duration('5s')` |
| list | `[...]` | `result.status in ['running', 'starting']` |

Variables from instruction results are provided as strings and automatically coerced to typed values: `"true"`/`"false"` to bool, integer strings to int, float strings to double, ISO 8601 strings to timestamp.

#### Operators

| Category | Operators |
|---|---|
| Comparison | `==`, `!=`, `<`, `>`, `<=`, `>=` |
| Logical | `&&`, `\|\|`, `!` |
| Arithmetic | `+`, `-`, `*`, `/`, `%` |
| Membership | `in` (e.g., `x in [1, 2, 3]`) |
| Ternary | `condition ? then : else` |

String `+` performs concatenation. Timestamp arithmetic: `timestamp + duration = timestamp`, `timestamp - timestamp = duration`.

#### Built-in Functions

| Function | Description | Example |
|---|---|---|
| `size()` | String length or list size | `result.name.size() > 3` |
| `startsWith()` | String prefix check | `result.path.startsWith('/usr')` |
| `endsWith()` | String suffix check | `result.path.endsWith('.log')` |
| `contains()` | Substring check (case-insensitive) | `result.name.contains('agent')` |
| `matches()` | Regex match (ECMAScript) | `result.host.matches('^web-\\d+$')` |
| `timestamp()` | Parse ISO 8601 string | `timestamp('2024-01-15T10:30:00Z')` |
| `duration()` | Parse duration string | `duration('1h')` |
| `int()` | Cast to integer | `int('42')` |
| `double()` | Cast to double | `double('3.14')` |
| `string()` | Cast to string | `string(42)` |
| `has()` | Check field presence | `has('field_name')` |

#### Backward Compatibility

Legacy compliance expressions using `AND`, `OR`, `NOT`, `contains`, and `startswith` keywords continue to work. The evaluator accepts both CEL syntax (`&&`, `||`, `!`, `.contains()`, `.startsWith()`) and legacy keyword syntax. New fragments are automatically migrated to CEL syntax via `cel::migrate_expression()`.

**Precedence note:** The keyword `NOT` has lower precedence than comparison operators (for backward compatibility), so `NOT result.status == 'failed'` is parsed as `NOT (result.status == 'failed')`. The CEL `!` operator has standard unary precedence, so `!result.status == 'failed'` is parsed as `(!result.status) == 'failed'`. Use parentheses when mixing styles to avoid ambiguity.

#### Safety Limits

| Limit | Value | Purpose |
|---|---|---|
| Max expression length | 4096 chars | Prevents DoS from oversized input |
| Max nesting depth | 64 levels | Prevents stack overflow from deeply nested parens |
| Max list elements | 1000 | Prevents memory exhaustion from large list literals |
| Max regex pattern | 256 chars | Mitigates ReDoS via `matches()` |

#### Examples

```cel
# Basic compliance check
result.status == 'running'

# Typed comparison with arithmetic
result.cpu_percent < 90 && result.memory_mb > 512

# Ternary for computed compliance
result.score >= 80 ? true : false

# Timestamp comparison
timestamp(result.last_check) + duration('1h') > timestamp(result.current_time)

# List membership
result.os in ['windows', 'linux', 'darwin']

# String functions
result.hostname.startsWith('web-') && result.hostname.matches('^web-\\d+$')

# Combined check with duration
result.uptime_seconds > 3600 && result.status == 'running'
```

---

## 10. Parameter Type System

InstructionDefinition parameters and PolicyFragment inputs use the following type set:

| Type | Description | Wire Format | Example |
|---|---|---|---|
| `string` | UTF-8 text | String | `"Spooler"` |
| `boolean` | Boolean flag | `true` or `false` | `true` |
| `int32` | 32-bit signed integer | Numeric string | `"42"` |
| `int64` | 64-bit signed integer | Numeric string | `"9223372036854775807"` |
| `datetime` | ISO 8601 timestamp | String | `"2026-03-17T18:20:00Z"` |
| `guid` | UUID / GUID | String | `"550e8400-e29b-41d4-a716-446655440000"` |

Parameters are transmitted as `map<string, string>` in the `CommandRequest` protobuf message. The server validates parameter values against the declared type and constraints before dispatch.

### Validation Constraints

| Constraint | Applicable Types | Description |
|---|---|---|
| `maxLength` | `string` | Maximum character count. |
| `minLength` | `string` | Minimum character count. |
| `pattern` | `string` | Regular expression the value must match. |
| `enum` | `string` | List of allowed values. |
| `minimum` | `int32`, `int64` | Minimum value (inclusive). |
| `maximum` | `int32`, `int64` | Maximum value (inclusive). |

---

## 11. Result Column Type System

Result schemas declare typed columns for structured output. These types enable downstream consumption by ClickHouse, Splunk, CSV export, and the dashboard aggregation engine.

| Type | Description | Example Value |
|---|---|---|
| `bool` | Boolean | `true`, `false` |
| `int32` | 32-bit signed integer | `4592` |
| `int64` | 64-bit signed integer | `1710700800000` |
| `string` | UTF-8 text | `"running"` |
| `datetime` | ISO 8601 timestamp | `"2026-03-17T18:20:00Z"` |
| `guid` | UUID / GUID | `"550e8400-e29b-41d4-a716-446655440000"` |
| `clob` | Character large object -- for large text fields | Multi-line log output, stack traces |

The `clob` type indicates a potentially large text field. The server may apply configurable truncation to `clob` columns to limit storage consumption.

---

## 12. Concurrency Model

Five concurrency modes control parallel execution of instruction definitions. The default (`per-device`) requires zero server coordination and scales to any fleet size.

| Mode | Enforcement | Scope | Use Case |
|---|---|---|---|
| `per-device` | Agent-side | One execution of this definition per device at a time | Default. Prevents conflicting operations on the same device. |
| `per-definition` | Server-side | One fleet-wide execution of this definition at a time | Dangerous global operations (schema migration, bulk delete). |
| `per-set` | Agent-side | One execution of any definition in this set per device | Set-level mutual exclusion (e.g., all patch operations). |
| `global:<N>` | Server-side | At most N concurrent executions fleet-wide | Patch rollouts, license-limited operations. Server maintains a semaphore in SQLite. |
| `unlimited` | None | No limits | Read-only queries, diagnostic gathering. |

### Agent-Side Enforcement (per-device, per-set)

The agent maintains an in-memory `std::unordered_set` of active definition IDs (or set IDs). On `CommandRequest` arrival, the agent checks the set. If occupied, the agent returns `REJECTED` with error code `3003` (`ORCH_CONCURRENCY_LIMIT`). No server round-trip is required.

### Server-Side Enforcement (per-definition, global:N)

The server checks a `concurrency_locks` SQLite table before dispatch. If the lock is held (or the semaphore count is at the limit), the execution enters a wait queue. The lock is released when the execution completes or times out.

### YAML Syntax

```yaml
spec:
  execution:
    concurrency: per-device          # default
    # concurrency: per-definition    # one fleet-wide at a time
    # concurrency: per-set           # one per set per device
    # concurrency: global:50         # at most 50 concurrent across fleet
    # concurrency: unlimited         # no limits
```

---

## 13. Error Code Taxonomy

Errors are categorized into four domains with non-overlapping numeric ranges.

### 1xxx -- Plugin Errors

| Code | Name | Description | Retry |
|---|---|---|---|
| 1001 | `PLUGIN_ACTION_NOT_FOUND` | Plugin does not support the requested action | Never |
| 1002 | `PLUGIN_PARAM_INVALID` | Parameter validation failed | Never |
| 1003 | `PLUGIN_PERMISSION_DENIED` | OS-level permission denied (e.g., non-admin) | Never |
| 1004 | `PLUGIN_RESOURCE_MISSING` | Target resource does not exist (service, file, etc.) | Never |
| 1005 | `PLUGIN_OPERATION_FAILED` | Action executed but failed (non-zero exit, exception) | Transient: yes; Deterministic: no |
| 1006 | `PLUGIN_CRASH` | Plugin segfaulted or threw unhandled exception | Never |
| 1007 | `PLUGIN_TIMEOUT` | Plugin did not complete within gather TTL | Yes (once) |

### 2xxx -- Transport Errors

| Code | Name | Description | Retry |
|---|---|---|---|
| 2001 | `TRANSPORT_DISCONNECTED` | Agent lost connection during execution | Always |
| 2002 | `TRANSPORT_STREAM_ERROR` | gRPC stream broken mid-response | Always |
| 2003 | `TRANSPORT_RESPONSE_TOO_LARGE` | Response exceeds max message size | Never |

### 3xxx -- Orchestration Errors

| Code | Name | Description | Retry |
|---|---|---|---|
| 3001 | `ORCH_EXPIRED` | Instruction passed its `expires_at` before dispatch | Never |
| 3002 | `ORCH_AGENT_MISSING` | Target agent not connected at dispatch time | Yes (on reconnect) |
| 3003 | `ORCH_CONCURRENCY_LIMIT` | Concurrency mode blocked execution | Yes (after slot frees) |
| 3004 | `ORCH_APPROVAL_REQUIRED` | Execution blocked pending approval | No (awaits human) |
| 3005 | `ORCH_CANCELLED` | Execution cancelled by operator | Never |

### 4xxx -- Agent Errors

| Code | Name | Description | Retry |
|---|---|---|---|
| 4001 | `AGENT_PLUGIN_NOT_LOADED` | Required plugin not available on agent | Never |
| 4002 | `AGENT_SHUTTING_DOWN` | Agent is in shutdown sequence | Yes (on reconnect) |
| 4003 | `AGENT_VERSION_INCOMPATIBLE` | Agent version below `minAgentVersion` | Never |

### Retry Semantics

| Category | Default Retry | Max Attempts | Backoff |
|---|---|---|---|
| Transport (2xxx) | Always | 3 | Exponential (1s, 2s, 4s) |
| Transient plugin (1005, 1007) | If `retryable: true` in definition | 2 | Linear (5s) |
| Deterministic plugin (1001-1004, 1006) | Never | 0 | -- |
| Agent (4001-4003) | Never (except 4002 on reconnect) | 1 | -- |
| Orchestration (3001-3005) | Per-code as noted | -- | -- |

---

## 14. Substrate Primitive Reference

This section enumerates the stable builtin primitives that content authors target. Each primitive maps to a backing plugin and one or more agent actions. Platform availability is marked per column.

**Status key:**
- **Verified** -- grounded in existing plugin code in `agents/plugins/`
- **Planned** -- in roadmap with GitHub issue
- **Proposed** -- recommended in design document

### 14.1 System and Identity

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `system.info` | `os_info` | Y | Y | Y | Verified |
| `system.status` | `status` | Y | Y | Y | Verified |
| `device.identity` | `device_identity` | Y | Y | Y | Verified |
| `hardware.inventory` | `hardware` | Y | Y | Y | Verified |
| `device.tags.get` | `tags` | Y | Y | Y | Verified |
| `device.tags.set` | `tags` | Y | Y | Y | Verified |
| `device.asset_tags.sync` | `asset_tags` | Y | Y | Y | Verified |
| `device.asset_tags.status` | `asset_tags` | Y | Y | Y | Verified |
| `device.asset_tags.get` | `asset_tags` | Y | Y | Y | Verified |
| `device.asset_tags.changes` | `asset_tags` | Y | Y | Y | Verified |
| `agent.health` | `diagnostics` | Y | Y | Y | Verified |
| `agent.restart` | `agent_actions` | Y | Y | Y | Verified |
| `agent.sleep` | agent core | Y | Y | Y | Verified |
| `agent.log.read` | `agent_logging` | Y | Y | Y | Verified |
| `agent.log.key_files` | `agent_logging` | Y | Y | Y | Verified |

### 14.2 Process and Execution

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `process.list` | `processes` | Y | Y | Y | Verified |
| `process.inspect` | `procfetch` | Y | Y | Y | Verified |
| `process.kill` | `processes` | Y | Y | Y | Verified |
| `process.start` | `script_exec` | Y | Y | Y | Proposed |
| `script.run` | `script_exec` | Y | Y | Y | Verified |
| `command.run` | `script_exec` | Y | Y | Y | Verified |

### 14.3 Services and Daemons

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `service.list` | `services` | Y | Y | Y | Verified |
| `service.inspect` | `services` | Y | Y | Y | Proposed |
| `service.start` | `services` | Y | Y | Y | Verified |
| `service.stop` | `services` | Y | Y | Y | Verified |
| `service.restart` | `services` | Y | Y | Y | Verified |
| `service.set_start_mode` | `services` | Y | Y | Y | Verified |

### 14.4 User, Session, and Identity

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `user.list` | `users` | Y | Y | Y | Verified |
| `user.logged_on` | `users` | Y | Y | Y | Verified |
| `user.group_members` | `users` | Y | Y | Y | Verified |
| `user.primary_user` | `users` | Y | Y | Y | Verified |
| `user.session_history` | `users` | Y | Y | Y | Verified |
| `user.group_membership` | `users` (ext) | Y | Y | Y | Planned |
| `session.list` | `users` (ext) | Y | Y | Y | Planned |
| `session.active_user` | `users` (ext) | Y | Y | Y | Planned |
| `session.notify` | `interaction` | Y | Y | Y | Verified |
| `session.prompt` | `interaction` | Y | Y | Y | Verified |
| `session.input` | `interaction` | Y | Y | Y | Verified |

### 14.5 Network

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `network.config.get` | `network_config` | Y | Y | Y | Verified |
| `network.route.list` | `network_config` | Y | Y | Y | Verified |
| `network.connection.list` | `netstat` | Y | Y | Y | Verified |
| `network.socket.owner` | `sockwho` | Y | Y | Y | Verified |
| `network.dns.flush` | `network_actions` | Y | Y | Y | Verified |
| `network.diagnostics.run` | `network_diag` | Y | Y | Y | Verified |
| `network.adapter.enable` | `network_actions` | Y | Y | Y | Verified |
| `network.adapter.disable` | `network_actions` | Y | Y | Y | Verified |
| `network.wifi.list` | `wifi` | Y | Y | Y | Verified |
| `network.wol.wake` | `wol` | Y | Y | Y | Verified |
| `network.wol.check` | `wol` | Y | Y | Y | Verified |
| `network.quarantine` | `quarantine` | Y | Y | - | Planned |

### 14.6 Software and Patching

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `software.inventory` | `installed_apps` | Y | Y | Y | Verified |
| `software.package.inventory` | `msi_packages` | Y | - | - | Verified |
| `software.uninstall` | `software_actions` | Y | Y | Y | Verified |
| `software.install` | content staging | Y | Y | Y | Planned |
| `software.update` | pkg adapter | Y | Y | Y | Proposed |
| `software.sccm.query` | `sccm` | Y | - | - | Verified |
| `patch.inventory` | `windows_updates` | Y | Y | Y | Verified |
| `patch.pending_reboot` | `windows_updates` | Y | Y | Y | Verified |
| `patch.install` | `patch` | Y | Y | Y | Planned |
| `patch.scan` | `vuln_scan` | Y | Y | Y | Verified |

### 14.7 Filesystem and Content Staging

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `file.list` | `filesystem` | Y | Y | Y | Verified |
| `file.search` | `filesystem` | Y | Y | Y | Verified |
| `file.read` | `filesystem` | Y | Y | Y | Verified |
| `file.write` | `filesystem` (ext) | Y | Y | Y | Planned |
| `file.hash` | `filesystem` | Y | Y | Y | Verified |
| `file.delete` | `filesystem` | Y | Y | Y | Verified |
| `file.exists` | `filesystem` | Y | Y | Y | Verified |
| `file.permissions.inspect` | `filesystem` (ext) | Y | Y | Y | Planned |
| `file.signature.verify` | `filesystem` (ext) | Y | - | Y | Planned |
| `file.temp.create` | SDK (`yuzu_create_temp_file`) | Y | Y | Y | Verified |
| `content.download` | `http_client` | Y | Y | Y | Verified |
| `content.get` | `http_client` | Y | Y | Y | Verified |
| `content.head` | `http_client` | Y | Y | Y | Verified |
| `content.stage` | `content_dist` | Y | Y | Y | Verified |
| `content.execute` | `content_dist` | Y | Y | Y | Verified |
| `content.list_staged` | `content_dist` | Y | Y | Y | Verified |
| `content.cleanup` | `content_dist` | Y | Y | Y | Verified |

### 14.8 Security and Compliance

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `security.antivirus.status` | `antivirus` | Y | Y | Y | Verified |
| `security.firewall.status` | `firewall` | Y | Y | Y | Verified |
| `security.disk_encryption.status` | `bitlocker` | Y | - | - | Verified |
| `security.disk_encryption.status` | LUKS/FileVault adapter | - | Y | Y | Proposed |
| `security.vulnerability.scan` | `vuln_scan` | Y | Y | Y | Verified |
| `security.event_log.query` | `event_logs` | Y | Y | Y | Verified |
| `security.ioc.check` | `ioc` | Y | Y | Y | Planned |
| `security.certificate.inventory` | `certificates` | Y | Y | Y | Planned |

### 14.9 Registry and WMI (Windows)

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `registry.get_value` | `registry` | Y | - | - | Verified |
| `registry.set_value` | `registry` | Y | - | - | Verified |
| `registry.delete_value` | `registry` | Y | - | - | Verified |
| `registry.delete_key` | `registry` | Y | - | - | Verified |
| `registry.key_exists` | `registry` | Y | - | - | Verified |
| `registry.enumerate_keys` | `registry` | Y | - | - | Verified |
| `registry.enumerate_values` | `registry` | Y | - | - | Verified |
| `registry.get_user_value` | `registry` | Y | - | - | Verified |
| `wmi.query` | `wmi` | Y | - | - | Verified |
| `wmi.get_instance` | `wmi` | Y | - | - | Verified |

### 14.10 Agent Key-Value Storage

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `storage.set` | `storage` | Y | Y | Y | Verified |
| `storage.get` | `storage` | Y | Y | Y | Verified |
| `storage.delete` | `storage` | Y | Y | Y | Verified |
| `storage.list` | `storage` | Y | Y | Y | Verified |
| `storage.clear` | `storage` | Y | Y | Y | Verified |

### 14.11 Workflow Primitives

| Primitive | Backing | Status |
|---|---|---|
| `result.filter` | Server-side (ResponseStore) | Planned |
| `result.group_by` | Server-side (ResponseStore) | Planned |
| `result.sort` | Server-side (ResponseStore) | Planned |
| `result.count` | Server-side (ResponseStore) | Planned |
| `workflow.if` | Server orchestrator | Proposed |
| `workflow.foreach` | Server orchestrator | Proposed |
| `workflow.retry` | Server orchestrator | Proposed |

### 14.12 Trigger Primitives

| Primitive | Backing | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `trigger.interval` | Trigger engine | Y | Y | Y | Verified |
| `trigger.filesystem_change` | Trigger engine | Y | Y | Y | Verified |
| `trigger.service_change` | Trigger engine | Y | Y | - | Verified |
| `trigger.windows_event_log` | Trigger engine | Y | - | - | Verified |
| `trigger.registry_change` | Trigger engine | Y | - | - | Verified |
| `trigger.agent_startup` | Agent core | Y | Y | Y | Verified |

### 14.13 Governance Primitives

| Primitive | Backing | Status |
|---|---|---|
| `scope.estimate_targets` | ScopeEngine | Proposed |
| `scope.resolve_devices` | ScopeEngine | Proposed |
| `approval.submit` | ApprovalManager | Planned |
| `approval.approve` | ApprovalManager | Planned |
| `approval.reject` | ApprovalManager | Planned |
| `audit.emit` | AuditStore | Verified |
| `response.persist` | ResponseStore | Verified |
| `response.aggregate` | ResponseStore | Planned |
| `response.export` | Data export | Planned |
| `policy.check` | Policy engine | Verified |
| `policy.fix` | Policy engine | Verified |
| `policy.evaluate` | Policy engine | Verified |
| `policy.recheck` | Policy engine | Verified |

### 14.14 Device Discovery

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `discovery.arp_scan` | `discovery` | Y | Y | Y | Verified |
| `discovery.ping_sweep` | `discovery` | Y | Y | Y | Verified |
| `discovery.port_scan` | `discovery` | Y | Y | Y | Verified |

### 14.15 Timeline Activity Record (TAR)

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `tar.query` | `tar` | Y | Y | Y | Verified |
| `tar.stats` | `tar` | Y | Y | Y | Verified |
| `tar.purge` | `tar` | Y | Y | Y | Verified |
| `tar.configure` | `tar` | Y | Y | Y | Verified |

### 14.16 Test and Debug

| Primitive | Backing Plugin | Win | Linux | macOS | Status |
|---|---|:---:|:---:|:---:|---|
| `testing.chargen.start` | `chargen` | Y | Y | Y | Verified |
| `testing.chargen.stop` | `chargen` | Y | Y | Y | Verified |

**`testing.chargen.start`** -- Start an RFC 864 character generator session for throughput benchmarking. Generates a continuous stream of printable ASCII characters to measure agent-to-server data-plane performance.

**`testing.chargen.stop`** -- Stop all running chargen sessions on the target device.
