---
status: accepted
date: 2026-07-01
owner: "@lesault (Andy Younie)"
decided-with: "@Tr3kkR (maintainer)"
depends-on: 0018 (server-authoritative matching — produces the findings that attach to the graph); fleet-topology store (observed graph)
related: docs/vuln-scan-capability-map.md V5/V7; docs/fleet-viz-invariants.md; docs/vuln-scan-roadmap.md M3/M5
supersedes-direction: the grill-session recommendation that CAVM must score on *potential* reachability from day one
---

# 4002 — CAVM MVP scores on observed reachability; potential reachability deferred

> Records a deliberate, eyes-open MVP trade-off taken 2026-07-01 (@lesault + @Tr3kkR): the first
> CAVM increment scores attack paths over the **observed** reachability graph Yuzu already produces,
> accepting a known limitation, rather than blocking on a potential-reachability engine. The
> limitation and the forward path are documented here so a future reader does not find observed-only
> scoring and assume the under-count was an oversight.

## Context

CAVM attack-path scoring (reachability, centrality, AMAPC, choke-points) is a graph walk. Two
substrates were considered:

- **Observed reachability** — `FleetTopologyStore`: edges are connections agents *actually saw*
  (4-tuple + owning PID). Already built; Yuzu's existing head-start.
- **Potential reachability** — what listening services + host firewall + network segmentation
  *would allow*, observed or not. Not built; the hard part (cross-host segmentation) is not
  derivable from endpoint data alone (see the deferred work below).

The load-bearing fact about the choice: **observed reachability is a *lower bound* on true
reachability.** A path an attacker could take but that no benign connection happened to traverse in
the collection window has **no edge** in the observed graph. So a risk score computed on it
**systematically under-counts** attack paths — it can read "safer than reality," never "riskier."
For a security metric that is the dangerous (false-negative) direction.

The grill-session analysis concluded the *correct* substrate is potential reachability, and that a
security score should **err toward over-counting** (over-warn), which observed reachability does not
do. This ADR consciously **accepts the under-count for the MVP** in exchange for shipping the
differentiator on infrastructure that already exists, and mitigates it with honest surfacing plus a
forward path — rather than blocking the MVP on the potential-reachability engine.

## Decision

**The CAVM MVP scores over the observed reachability graph. Potential reachability is deferred.**
Two guardrails make the trade-off honest and reversible:

1. **Observed-derived exposure is surfaced as a *lower bound*, never as an authoritative "safe"
   verdict.** Same honesty principle as ADR-0019 (`not-assessed` — never present incompleteness as
   completeness): scores/labels read as "based on observed comms" and must not license a
   "this host is not reachable / is safe" conclusion. The absence of an observed edge is *not*
   evidence of unreachability.
2. **The edge model carries a `provenance` field from day one** (`observed` | future `potential`),
   even though the MVP only populates `observed`. This is the cheap insurance that makes the later
   move to potential reachability an **additive layer** (populate `potential` edges, widen the walk)
   rather than a rearchitecture.

## Consequences

**Gained:**
- **Ships on existing infrastructure** — reuses `FleetTopologyStore`; no new collector or
  reachability engine blocks the first CAVM increment.
- **Real service-dependency signal** — the observed graph is genuinely good at showing actual comms
  and service dependencies; that value is real and immediate even as a lower bound.
- **Reversible** — the `provenance` field + honest surfacing mean adopting potential reachability
  later neither invalidates stored data nor rewrites the score's contract.

**Costs accepted (stated openly):**
1. **Systematic under-count / false-negative risk.** Attack paths never observed are invisible; the
   score is a lower bound on risk. Mitigated *only* by honest surfacing (guardrail 1), **not**
   eliminated. This is the deliberate MVP debt.
2. **Staleness in the other direction** — an observed edge whose firewall/service has since changed
   may over-state a specific path; minor next to the under-count.

## Forward path (deferred — the eventual correctness fix)

Move to **potential reachability** as `observed ∪ potential`, built in accuracy layers:
- **Endpoint-local potential** (listening services — have them; + host-firewall rules — extend the
  existing `firewall` collector to a normalized cross-OS model) with an **assume-flat network**
  default, which **over-counts** (the correct, conservative direction).
- **Network-fabric segmentation** (cloud NSG/security-group + firewall/switch config ingestion, or
  active probing — the latter is fraught: agent-to-agent probing resembles lateral movement) to
  refine assume-flat into proven segmentation. Same "own the endpoint-derivable part, federate the
  external part" pattern as ADR-0018 Lane 3.
- Governing invariant when it lands: **reachability must err toward over-counting, never
  under-counting.** A future ADR records the potential-reachability engine when it is built.

## Ratification

**Status: accepted** (2026-07-09), per @Tr3kkR's standing convention: an ADR merged via reviewed PR
carries `status: accepted` on `dev`. Already decided by the vuln_scan owner with the maintainer per
the original text below.
