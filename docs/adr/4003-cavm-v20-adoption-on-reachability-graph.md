---
status: accepted
date: 2026-07-16
owner: "@lesault (Andy Younie)"
depends-on: 0002 (reachability graph data model — the host/service node tiers this ADR runs CAVM's algorithms on directly, no asset-level collapse); 0005 (attack-path and chokepoint scoring algorithms — the algorithmic home this ADR extends with CAVM's formal metrics); 4001 (vulnerability dashboard + Attack Path Explorer — the consuming surface for AMAPC/CPS/the Explorer); 4002 (CAVM MVP scores on observed reachability — the substrate decision this ADR builds on unchanged, not revisited)
related: 4004 (vulnerability finding disposition lifecycle — `gate_state`'s rescore triggers are this ADR's Decision 1 scope, formally landed there); CONTEXT.md (`Asset value (Crown jewel)`, `Trust zone`, `Entry point`, `Attack path`, `Chokepoint` — existing committed vocabulary this ADR implements against, and for `Chokepoint`, amends)
supersedes-direction: CONTEXT.md's `Chokepoint` entry's "not by generic graph centrality" stance, AND ADR-0005's Chokepoints bullet ("path-set frequency over the computed top-k paths... not Brandes betweenness") — both amended to a value-weighted chain centrality reusing ADR-0005's own bounded path machinery, not classical Brandes betweenness (Decision 5); confirmed with Tr3kkR (original author of the CONTEXT.md entry) 2026-07-16 — the original exclusion wasn't a deliberate design call, centrality simply wasn't considered at the time
---

# 4003 — CAVM v20 adoption on Yuzu's reachability graph

> Records how Yuzu adopts the CAVM v20 whitepaper (Andy Younie, July 2026 — an external design document, not tracked in this repo) into the reachability-graph architecture ADR-0002/0005 already committed, and into the observed-reachability MVP trade-off ADR-4002 already accepted. CAVM v20 is a substantially more complete graph-theoretic prioritization framework (formal metrics, an operational stability layer, remediation batching, speculative scoring) than anything scoped when 4001/4002 landed. This ADR decides what's adopted now, what's deferred, and — critically — how CAVM's own default graph model (coarser, asset-level, no existing integration) maps onto Yuzu's *already more precise* service-level graph, rather than adopting CAVM's model wholesale and discarding what Yuzu already has.

## Context

ADR-4002 (2026-07-01) committed Yuzu to observed reachability as a deliberate, eyes-open lower-bound MVP substrate for CAVM-style scoring. It did not decide *how much* of CAVM's actual algorithmic machinery Yuzu adopts, because CAVM's own specification hadn't reached this level of formality yet. The v20 whitepaper now provides: chain centrality, crown-jewel reachability, chained risk, and an attacker-prior component composing into a per-vulnerability composite priority score (CPS); average minimum attack path complexity (AMAPC) as a board-level resilience metric; exploitation utility classification (EUC) as a per-instance attacker-state-transition taxonomy; a gate model for protecting scheduled remediation from rescore churn (landed separately in ADR-4004); speculative scoring; and remediation batching.

Two things make this reconciliation non-trivial rather than a straight port:

1. **CAVM's default graph model is coarser than Yuzu's own.** The whitepaper's node schema (Annex B.1) is asset-level, with privilege-state expansion applied uniformly (Annex B.3 Stage 7 — every node duplicated into `@none/@user/@admin/@system` variants). ADR-0002 already rejected a flat host-only graph for the same reason CAVM's own reasoning would predict — *"cannot express 'the CVE is on the SSH service that is actually exposed' vs 'a CVE on a library nothing listens on'"* — and already commits CVE/value attachment to the **service** node tier, not the host. Adopting CAVM's coarser default would be a regression against Yuzu's own committed architecture, not an upgrade.
2. **CONTEXT.md already has committed vocabulary CAVM's whitepaper doesn't know about.** `Asset value (Crown jewel)`, `Trust zone`, `Entry point`, `Attack path`, and `Chokepoint` are all pre-existing, ratified glossary terms (authored against ADR-0002/0005) that overlap heavily with CAVM's crown-jewel/breach-point/AMAPC/chokepoint concepts — in most cases more precisely than CAVM's own defaults. This ADR reconciles CAVM's formal algorithms against *that* vocabulary, not the other way around.

## Decision

### 1. Staged adoption, not the full v20 framework

Adopted now, on data Yuzu already ingests, no new external integration required:

- **Chain centrality** (value-weighted — Decision 5), **crown-jewel reachability**, **chained risk**, and **AMAPC** — the whitepaper's four core graph metrics.
- **The composite priority score (CPS)** — the per-vulnerability ranking a remediation queue is actually ordered by (Annex C.5). Its `attacker_prior` component degrades gracefully to EPSS-only with no CTI (per the whitepaper's own §3.3 design), which the module already ingests, so CPS is fully computable without the CTI dependency below.
- **EUC** (exploitation utility classification) — Decision 4.

Named future work, explicitly not blocking this ADR or M1–M5 of the vulnerability-management module:

- **CTI/TTP-weighted `attacker_prior`** — no threat-intel ingestion source exists in Yuzu today; `attacker_prior` runs EPSS-only until one does.
- **SOC/EDR/SIEM-integration-dependent gate triggers** (SOC anomaly detection, MOAK-class+KEV combo) — ADR-4004's `gate_state` ships with only the triggers sourced from data already flowing (KEV addition, EPSS threshold breach, EPSS week-on-week spike, published PoC).
- **Speculative scoring's AI-assisted-scan-status input** — this is a source-code SAST-class capability (Constantine-class tooling), unrelated to package/CVE correlation; a different capability Yuzu doesn't have, not a near-term extension of this module.
- **Remediation batching / co-location sequencing** — maps cleanly onto the existing `/auto` Deploy machinery (`DeploymentRunStore`) as a future consumer, but isn't built now.
- **Crown-jewel Stage 3/4 automation** (CMDB enrichment, automated crown-jewel detection from data-flow/auth-log analysis) — Decision 6 below builds Stage 1/2 (manual, operator-declared) only.

### 2. CAVM's path algorithms run directly on ADR-0002's service-level graph — no asset-level collapse

Chain centrality, crown-jewel reachability, chained risk, min-path-complexity (AMAPC), and CPS all operate on the graph exactly as ADR-0002 defines it: host nodes and service nodes (`host, port, protocol, owning process`), CVE/value attached at the service, two edge classes (network reachability, local-IPC). This is *more* precise than CAVM's own asset-level default, not a simplification of it — it already targets the "which running service actually exposes the vulnerable package" precision CAVM's whitepaper doesn't natively have.

**Known, honestly-flagged gap, not solved by this decision:** the process-to-package correlation ("does this specific listening service actually load this specific vulnerable library") isn't collected today. ADR-0002 already designs CVE-to-service attachment on the assumption this exists; the collector that makes it true doesn't yet. This ADR doesn't fix that — it's a named dependency for whichever milestone lands the component-inventory-to-process correlation.

### 3. Privilege escalation — a bounded ladder on the host tier, not the service tier

CAVM's Stage 7 privilege-state expansion (`@none/@user/@admin/@system` per node) is adopted, but scoped to ADR-0002's **host** node tier only, not applied per-service. This keeps duplication bounded at 4 states per host rather than 4 states × every service on it.

**Every F/LM/PE exploit edge bridges to `host@<privilege_postcondition>`, not only PE-classified findings.** CAVM's own edge schema (Annex B.2) already carries `privilege_precondition`/`privilege_postcondition` on every exploit edge, not just PE ones — a foothold RCE with postcondition `user` lands the attacker at `host@user`, not merely at the compromised service. PE edges are the special case that need no new service compromise at all: a pure `host@<precondition> → host@<postcondition>` transition using whatever's already been reached, generalizing ADR-0002's existing "setuid/sudo hop" local-IPC edge kind. Any local-IPC or network edge whose exploit precondition requires a given host privilege level is only traversable once that `host@<state>` node has been reached earlier in the same path walk — structural ordering by construction, no runtime precondition check needed, the same trick CAVM's own Stage 7 relies on.

**DA (data access) edges are excluded from this bridge by default.** CAVM's own EUC definition for DA gives its postcondition as "access to data on or accessible from the target," not genuine execution presence on the host — a leaked config file is not a landed session. Bridging a bare DA edge to `host@<postcondition>` would let downstream PE/LM edges become wrongly traversable off a data leak that never actually put the attacker on the box. Where leaked data (e.g. credentials) genuinely grants presence, that's modeled as a separate F or LM edge using that data, not as the DA edge itself touching the host-state ladder.

**The bridge is a zero-cost annotation, not a second weighted hop.** An exploit edge's destination is `(service, host-state)` jointly — the same edge, not an additional edge with its own `edge_complexity`. Charging a second hop's worth of complexity for host-state arrival would inflate AMAPC and distort centrality for no real reason: the attacker didn't do extra work by also holding host-level privilege, that's a side-effect of the exploit they already paid for.

This is a narrow, per-node, exploit-sequencing device only. It is explicitly **not** the cross-host identity/account/ACL graph ADR-0002 already declared out of scope ("no identity/account nodes... the BloodHound space we do not enter") — that non-goal stands unchanged; this ladder never models group membership, credential relationships, or domain trust, only "what privilege level has an attacker reached on this one host via exploitation."

### 4. EUC computed at graph-construction time, as an edge attribute — never persisted separately

EUC depends jointly on a finding, the network position it's approached from, and the current privilege state at that point in a path — genuinely per-edge, not per-finding or per-node. It is computed by `attack_path_engine` during the same pass that already builds the reachability→exploit-edge graph (ADR-0002 Stage 4 in the construction pipeline sense), living in the same in-memory, TTL-evicting structure `FleetTopologyStore` already uses (rebuilt daily with incremental updates), never a finding-store column and never a standalone refreshed SQL table. Precomputing it independently of an actual path-walk would mean materializing EUC for every theoretical edge, most of which no centrality/AMAPC computation ever traverses.

### 5. Chokepoint ranking adopts CAVM's chain-centrality mechanism, value-weighted — amends CONTEXT.md and ADR-0005, not classical betweenness

CONTEXT.md's `Chokepoint` entry currently ranks by defender ROI (`crown-jewel value × path probability`, summed over every path a removal would break), explicitly *not* by generic graph centrality. ADR-0005 rejected "Brandes betweenness" more specifically, for two stated reasons: computational cost (O(V·E), a real concern at the 1.2M-host/HSBC-scale target) and semantic correctness ("wrong — weights all-pairs equally"). **Neither objection applies to CAVM's chain centrality as actually specified, and this decision does not reopen either rejection:**

- **Not all-pairs.** CAVM's algorithm is `for source in breach_points: for target in crown_jewels:` — already scoped to the declared entry-point/crown-jewel surface (ADR-0005's own "sources/sinks are the declared surface" bounding principle), never a graph-wide all-pairs computation. ADR-0005's "wrong — weights all-pairs equally" objection was never applicable to it.
- **Not O(V·E).** Computed as a Dijkstra-class shortest-path search per breach-point source, bounded by the declared surface — the same complexity shape as ADR-0005 §5.1's own attack-path scoring, not a separate graph-wide pass. In practice it should reuse the already-computed top-k paths from that same scoring step (ADR-0005 §5.2's own "nearly free" path-set-frequency computation), rather than a fresh `all_shortest_paths` traversal per pair.

CAVM's chain centrality and ADR-0005's existing chokepoint formula are, underneath, close to the same computation described from two angles — both reuse the already-computed entry→jewel paths, both weight by crown-jewel value. What CAVM's version adds is dividing credit fairly across *every* crown jewel a node reaches, rather than summing per-path without normalizing across the full crown-jewel set: (a) it counts only the single lowest-complexity ("least complex" — CAVM's own Annex I.3 derives this as mathematically equivalent to "most probable," not merely similar) path per breach-point/crown-jewel pair, not every viable path; (b) CAVM's default is unweighted, each crown jewel contributing an equal flat share regardless of value.

**Decision: adopt CAVM's shortest/least-complex-path centrality mechanism, but value-weight it** — each `(entry point, crown jewel)` pair's contribution to a node's score is scaled by that crown jewel's declared value (Decision 6), not a flat unit (`entry point` is Yuzu's term for CAVM's `breach_point` — Decision 6 maps the two):

```
centrality[node] += value(crown_jewel) / (len(paths) * normaliser)
# normaliser = len(breach_points) * sum(value(cj) for cj in crown_jewels)
```

`paths` here is ADR-0005 §5.1's already-computed shortest/top-k path set for that breach-point/crown-jewel pair (Dijkstra/Yen's output), not a separate traversal — this is a credit-accumulation pass over existing output, the same tractability shape as ADR-0005's own chokepoint formula, not a new graph algorithm.

This resolves the concrete case that motivated the switch: a chokepoint severing paths to ten medium-value crown jewels and a chokepoint severing paths to one high- and one low-value crown jewel are now ranked by their actual summed value, not by raw target count. `CONTEXT.md`'s `Chokepoint` entry is amended accordingly — its "not by generic graph centrality" line is retired in favor of this value-weighted variant.

**Resolved (2026-07-16):** Tr3kkR authored the original `Chokepoint`/`Attack path` entries; asked directly, he confirmed excluding centrality wasn't a deliberate design call against it — it simply wasn't considered when the entry was written. No reason to preserve the exclusion surfaced, so this decision stands without qualification.

### 6. Crown-jewel and breach-point (trust-zone) declaration — a dedicated mechanism, not tags

CONTEXT.md's `Asset value (Crown jewel)` and `Trust zone` entries are already committed, and both are already explicit, non-tag-derived axes: `Asset value` states it directly ("operator-declared... orthogonal to tags, management groups, and scope"); `Trust zone` is declared CIDR/site tiers, stated as "orthogonal to Management Group... and to Scope" (tags aren't mentioned there, but the entry never derives zones from tags either — declared ranges only). Neither has any implementation today (verified: no `crown_jewel`/`trust_zone` symbol exists anywhere in `server/core/src/`). This ADR builds them as designed, rather than retrofitting the general tag system:

- **Value** is a 3-tier operator-declared axis (`crown-jewel` / `high` / `standard`) carried by the **service** (matching CONTEXT.md's existing "value is carried by the service... a host's effective value is the maximum of the values of the services/instances it carries"). `crown-jewel` is the axis's top tier and the only value CAVM's centrality/AMAPC/CPS algorithms treat as crown-jewel-set membership; `high`/`standard` are manual operator context only, feeding nothing algorithmically yet. A continuous `mission_criticality` float (CAVM Annex B.1) and inheritance from Yuzu's existing `service` tag/ownership model are named future work, arriving with a CMDB integration that doesn't exist yet.
- **Breach points map onto CONTEXT.md's already-committed `Trust zone` + `Entry point` machinery**, not a new CAVM-shaped `breach-exposure` category. An operator declares ordered trust tiers (CIDR/site, e.g. `internet < partner-extranet < branch-campus < datacenter`); `Entry point` is *derived* — any service exposed across a trust-zone boundary — rather than separately tagged per device. This is a direct, cleaner mapping of CAVM's three breach-point categories (internet-facing / user-reachable / third-party ≈ services exposed from the internet / a low-trust staff-branch zone / a partner-extranet zone respectively), already more precise than CAVM's manual three-category tag because it derives from the trust-zone topology rather than requiring per-device manual classification. **Known, honestly-flagged gap, not solved by this decision:** trust-zone *declaration* has no implementation today, and neither does the entry-point *derivation* computation that reads it against the reachability graph (comparing each service's trust zone to the zones it's reachable from) — this decision specifies the shape, it doesn't build the computation, same as Decision 2's process-to-package correlation gap.
- **RBAC:** new dedicated securables (e.g. `AssetValue:Write`, `TrustZone:Write`) — not `Tag:Write` — seeded onto `Administrator` only, matching the precedent this codebase already uses for consequential write access on this exact module lineage (`Vulnerability` CRUD is Administrator-only per ADR-4001; `rbac_store.cpp`'s Operator seed is curated per-securable, never a blanket grant, and reserves security-sensitive write access — e.g. `ApiToken` — for narrow dedicated roles or Administrator). Crown-jewel/trust-zone declarations drive CPS/AMAPC/chokepoint ranking end-to-end, so a wrong declaration has real downstream consequence — the same bar `Vulnerability` CRUD is already held to. Read access, if a `:Read` operation is introduced, can extend to `Operator`/other roles separately; this decision is about `:Write` only. Fully reconfigurable via Yuzu's existing granular RBAC `role_permissions` model with zero new mechanism required.

## Considered and rejected

- **CAVM's own asset-level node model with uniform privilege-state expansion.** Rejected — coarser than what ADR-0002 already commits to, and would discard the service-level precision that's the entire reason ADR-0002 rejected a flat host graph in the first place.
- **Unweighted chain centrality, as CAVM specifies it by default.** Rejected — produces the wrong ranking on the "many low-value targets vs. few high-value targets" case; value-weighting is a straightforward, low-cost modification that preserves centrality's real contribution (rewarding nodes on paths to *multiple* crown jewels) without discarding value.
- **Folding crown-jewel/breach-point declaration into the general tag system.** Considered mid-design (a `criticality`/`breach-exposure` tag-category pair), then rejected on discovering CONTEXT.md already commits both concepts as explicitly non-tag-based, and neither is implemented yet — no reason to retrofit tags over building what was already designed.
- **Adopting the full v20 framework in one pass.** Rejected per the whitepaper's own maturity-gradient argument and Yuzu's existing "don't block core matching on CAVM" posture (§7 of the vulnerability-management module's own design work) — CTI, SOC integration, speculative scoring's AI-input, and remediation batching all carry real external dependencies Yuzu doesn't have yet.
- **Classical (Brandes) all-pairs betweenness centrality.** Still rejected, for the exact reasons ADR-0005 already gave (O(V·E) at 1.2M-host scale; "wrong — weights all-pairs equally"). This ADR does not reopen that rejection — CAVM's chain centrality as actually specified was never that algorithm (Decision 5 above), so there was no live tension to resolve, only a documentation gap where ADR-0005 and `docs/vuln-scan-engine-design.md` weren't cross-referenced against this ADR's arrival.

## Consequences

**Gained:**
- A materially more complete graph-scoring model (CPS + AMAPC + value-weighted centrality + EUC) than ADR-4001/4002 originally scoped, built without regressing any of ADR-0002's existing precision.
- CONTEXT.md's pre-existing crown-jewel/trust-zone/entry-point vocabulary turns out to already be a better fit for CAVM's breach-point/crown-jewel concepts than CAVM's own defaults — validated, not replaced.
- A clean value-weighted synthesis of Yuzu's original defender-ROI chokepoint philosophy and CAVM's centrality contribution, rather than having to pick one wholesale.
- Confirmed, not just asserted, that value-weighted chain centrality is tractable at the 1.2M-host/HSBC-scale target ADR-0005 set — reuses that ADR's own bounded, declared-surface-scoped path machinery rather than a separate graph-wide computation, and ADR-0005/`docs/vuln-scan-engine-design.md` now cross-reference this ADR instead of silently describing a superseded formula.

**Costs / open items:**
- The process-to-package correlation collector (which service actually loads which vulnerable component) still doesn't exist — EUC and service-level CVE attachment both assume it; this ADR names the gap, doesn't close it.
- The crown-jewel/trust-zone declaration mechanism (store, RBAC, dashboard surface) *and* the entry-point derivation computation that reads trust zones against the reachability graph are both specified here but not yet built — CONTEXT.md described the shape years before any implementation landed, and this ADR is the first to schedule the actual build.
- CTI, SOC-driven gate triggers, speculative scoring's AI-scan input, and remediation batching remain named, undated future work — none has a committed milestone.
