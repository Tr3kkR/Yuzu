# Yuzu Context

Yuzu is an agentic enterprise endpoint management platform. It provides one control plane where humans and agentic workers can query, command, scan, patch, and enforce policy compliance across Windows, Linux, and macOS fleets.

## Agent daemon

The C++ endpoint process under `agents/core/` that runs on a managed device, maintains server or gateway connectivity, executes plugin actions, reports results, and enforces local policy.

## Governance agent

A review role used during the governance pipeline. In Claude these roles live under `.claude/agents/`; in Codex they are compact role prompts in `.codex/skills/governance/SKILL.md`.

## Agentic worker

An external LLM-driven client that operates Yuzu through MCP, REST, or the dashboard. Agentic workers need stable discovery, consistent error envelopes, auditable actions, and operator-equivalent workflows.

## Instruction

A typed unit of endpoint work. Instructions are defined as YAML-backed `InstructionDefinition` content, grouped into instruction sets and product packs, dispatched through the command protocol, and persisted with audit and response data.

## Product pack

A packaged set of instruction content that represents a coherent operational capability. Product packs are build-time embedded from `content/packs/*.yaml` and seed the server's instruction store on first boot.

## Scope

The device target expression for an instruction, policy, query, or workflow. Scopes compose filters such as tags, OS, management groups, and prior result sets; they are part of the authorization and audit boundary.

## Guardian

The Guaranteed State policy enforcement system. Guardian evaluates desired-state policy fragments, triggers checks or remediation, and can route sensitive actions through approval or quarantine flows.

## Guard

A single Guaranteed-State rule: a trigger (Spark), a desired-state check (Assertion), and an optional remediation. A Guard has its own enabled/disabled state, an Observe-or-Enforce mode, and optional Prerequisites. A Guard is a building block — on its own it is a definition only and is never deployed; it reaches devices only as a member of a Baseline.

## Baseline

A named, deployable collection of one or more Guards, targeted at devices via an **assignment**: a set of *included* management groups minus a set of *excluded* management groups (exclusion wins — a device in both an included and an excluded group is not targeted). The Baseline is the only deployable unit in Guardian — **individual Guards are never deployed on their own** (the same shape as a Jamf Configuration Profile, an Intune baseline, or a GPO). Deploying a Baseline applies its enabled member Guards to the assigned devices, subject to each Guard's Prerequisites.

## Assignment

A Baseline's device targeting: a set of *included* management groups minus a set of *excluded* management groups, where **exclusion wins** (a device in both an included and an excluded group is not targeted). Targeting is at whole-Baseline granularity — the same shape as a Jamf Configuration Profile's Scope (Targets − Exclusions) or an Intune assignment. A management group may be static (explicit members) or dynamic (criteria-defined, the equivalent of a Jamf Smart Group). Distinct from a Guard's **Prerequisites**, which gate applicability one level finer, per-Guard.

## Prerequisites

A Guard's technical applicability condition — a Scope expression over device facts (e.g. OS version, form factor, installed software) that must hold for the Guard to apply on a given device. Prerequisites are distinct from a Baseline's management-group targeting: a Guard applies on a device when the device is in the Baseline's management groups **and** the device satisfies the Guard's Prerequisites.

## Mode (Observe / Enforce)

A Guard's response posture. **Observe** detects and alerts on drift without writing back (the user-facing term; it replaces the earlier "Watch", and the still-older "audit" — the stored/wire value remains `audit`). **Enforce** additionally remediates — writing the expected state back, governed by the Guard's resilience policy. Mode is fixed when the Guard is authored; a different posture is a different Guard.

## Deploy

Applying Guardian policy to devices. Deploying a Baseline **converges every assigned device to its complete desired guard set** — the per-device union of the enabled member Guards of all deployed Baselines whose assignment includes that device, each gated by the device's Prerequisites. Convergence is to a device's *total* policy (as in Puppet/DSC/GPO), not to one Baseline's fragment; so removing a Guard from a Baseline and re-deploying actually removes it from any device no other deployed Baseline still delivers it to.

## TAR

Timeline Activity Record. TAR captures ordered endpoint activity and response history so operators and agentic workers can reconstruct what happened during investigation, remediation, and audit workflows.

## Gateway

The Erlang service under `gateway/` that scales agent connectivity and command fanout. It proxies registration and heartbeat traffic upstream to the server, exposes agent-facing gRPC, and provides management forwarding for server-dispatched commands.

## Reachability

Whether one node in the fleet can initiate a network connection to another. Yuzu distinguishes two kinds and commits to one:

- **Observed reachability** — an edge backed by a network flow the fleet's own agents *actually saw* (a `fleet_snapshot.v1` connection whose destination resolves to another fleet member via the server's IP→agent map). This is the spine of Yuzu's reachability graph. It deliberately **undercounts** what is possible — a path that policy permits but no host ever exercised is invisible — and that recall trade-off is accepted because trustworthy, low-false-positive results are the product's cornerstone.
- **Potential reachability** — what the network/firewall *policy would allow*, independent of whether a flow was ever observed. Yuzu can only ever approximate the **host-firewall** slice of this (the set of `(port, protocol, allowed-source)` a host would accept), and only after structured firewall parsing that does not exist yet — it is a later, clearly-labeled enrichment, never conflated with observed edges.

**Fabric-level reachability** — what switch/router ACLs, cloud security groups, and VLAN segmentation permit — is **out of scope**: an on-box agent cannot see it and Yuzu never fabricates it. A seam is left to *consume* it from an upstream source or *publish* Yuzu's observed graph upstream in a future iteration.

Distinct from **Scope**, which is a device-*set* target expression, not a graph; reachability is about edges between nodes, not membership.

## Cohort

The comparison population for fleet-relative performance benchmarking: the set of reporting devices sharing a value for an **operator-chosen tag key** (e.g. every device tagged `model: Latitude 7440`, or `image: vanilla` vs `image: layered`). Cohorts are derived from tags — never from self-asserted inventory or a central hardware column — so hardware-model cohorts exist only where an operator (or an agentic worker, via the asset-tagging recipe) has tagged the fleet. A cohort below the statistical floor (10 reporting devices) is reported as too small rather than given noisy percentiles; devices carrying no value for the chosen key form an explicit untagged residual, never a silent omission. Distinct from **Scope** (a targeting expression) and from a Management Group (an authz/targeting grouping): a cohort is a read-side analytical grouping with no authorization meaning.

## Reporting population

The denominator that travels with every fleet-aggregate performance statistic: how many devices actually contributed values in the current cycle. A fleet average over 12 devices is never presented as fleet-wide truth without its population; a metric nobody reported is absent, never a fabricated zero.

## App-perf daily roll-up (B1)

The centralized per-device daily summary of a device's **resource-significant app-versions**: one record per `(device, app, version, UTC day)` carrying sample-weighted CPU and working-set averages, their peaks, and a sample count, derived on the agent from the on-device `procperf_hourly` warehouse and shipped daily. It is the fleet-queryable layer ("which devices ran v124, and how did it perform") that complements the on-device, federated-on-demand drill — distinct from **installed software** inventory (a complete app-presence census; B1 is performance over the top-N consumers only).

## App-perf fleet roll-up (B2)

The fleet-aggregate trend layer over [[App-perf daily roll-up (B1)]]: one record per `(app, version, UTC day)` summarising how that app-version performed **across all devices** that ran it that day — device count, fleet CPU/working-set means and maxima, and a fixed-bucket histogram of the per-device daily values from which fleet percentiles are derived. It deliberately drops the device dimension (no `agent_id`) — it answers "did v125 run hotter than v124 across the fleet", not "on which device". Distinct from B1 (per-device, 31-day, the drill-down source) by retention (180 days) and grain (fleet, not device).

## Resource-significant app-version

An `(application, version)` pair that appeared among a device's top-N CPU- or working-set-consuming processes during sampling, and therefore the unit B1 measures. The qualifier is load-bearing: B1 deliberately does **not** record every app that ran — only those significant enough to surface in `procperf` — so "ran on this device" in a B1 context always means "ran among its top resource consumers."

## Asset value (Crown jewel)

A risk-weighting of how much a node matters to defend — a *value* axis, **orthogonal** to tags, management groups, and scope (which are *targeting* axes). **Operator-declared**: the defender knows what matters and Yuzu does not guess it, though optional inference *hints* may suggest a value (never auto-apply it). Value is carried by the **service** — the process/listening unit where a vulnerability and an exposed port actually live — and may also be declared on an addressable instance (container, VM, bare-metal host). A host's **effective value is the maximum** of the values of the services/instances it carries: a box is as valuable a target as its most valuable tenant. A **crown jewel** is the high end of that axis — the service whose compromise is the attacker's objective and the defender's nightmare. New term; does not collide with any existing Yuzu concept.

## Trust zone

An operator-declared, ordered trust tier over network positions — a labeled set of CIDRs and/or sites (e.g. `internet` < `partner-extranet` (MPLS / third-party via an extranet block) < `branch-campus` (staff sites with fewer physical controls) < `datacenter` (where crown jewels live)). Trust zones are **declared, not inferred**: Yuzu cannot tell that `10.50.0.0/16` is the branch LAN or that an off-fleet peer arrived over an MPLS extranet — the operator labels the ranges, which Yuzu matches against the host `local_ips` and connection addresses it already collects. This is what disambiguates the blunt `External` edge into `internet` / `partner-extranet` / `branch`. A flow crossing from a lower-trust zone into a higher-trust one is a **cross-trust-boundary** edge — the source side of attack-path enumeration and the cut side of segmentation analysis. **Orthogonal** to **Management Group** (device-grouping for authz/targeting) and to **Scope** (a device-set expression): a host sits in exactly one trust zone *and* any number of management groups. With **Asset value**, trust zones bracket the attack graph — value declares *what attackers are after*, trust zones declare *where they start*.

## Entry point

A service an attacker is assumed able to reach from outside a defended zone — the *source set* for attack-path enumeration. In v1, an entry point is any service **exposed across a trust-zone boundary** (reachable from a zone of lower trust than the service's own), the lowest tier being the public Internet; laptops in low-trust staff zones are entry points as phishing / initial-access landing nodes. **Assume-breach** entry — treating *any* node as a possible foothold to model post-initial-access lateral movement — is a later, explicitly separate view, not the v1 default.

## Attack path

A directed chain through the reachability graph from an **entry point** to a **crown jewel**, where each hop is an observed reachability edge whose destination service carries an exploitable vulnerability. Each hop is weighted by the probability an attacker can exploit the destination service on arrival; the path's score is the product of its hop probabilities — found as a shortest *weighted* path so the **most probable** route surfaces, depth-bounded to the few hops that constitute a real threat. A finding's rank is driven by whether it sits on a short, probable attack path to value — **not** by raw CVSS. Distinct from **TAR** (observed temporal activity): an attack path is a structural statement about *possible* compromise routes, grounded in observed reachability but oriented toward what *could* happen.

## Chokepoint

A node or edge lying on many high-value attack paths, such that removing it — patching/isolating the host, or closing the port/flow — severs the most at-risk value for the least defender effort. Ranked by **defender ROI**: the sum of `crown-jewel value × path probability` over the attack paths the removal would break, **not** by generic graph centrality. The minimum-effort set of removals that fully severs a trust zone from crown jewels it should not reach is a **segmentation recommendation** (a cost-weighted min-cut). Because the graph is observed-grounded, a chokepoint severs *observed* paths; policy-permitted-but-unobserved paths are out of scope until host-firewall potential-reachability enrichment lands.
