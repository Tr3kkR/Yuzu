---
status: accepted
date: 2026-06-08
owner: "@lesault (Andy Younie)"
---

# 0005 — Attack-path & chokepoint scoring: bounded max-probability paths, ROI chokepoints

## Context

Raw CVSS ranking is noise at fleet scale. We want findings ranked by their position on a
probable attack path from an entry point to a crown jewel, plus chokepoint and segmentation
recommendations — at up to **1.2M hosts (HSBC scale)**. The naive approach (enumerate all
attack paths) is the well-known attack-graph state explosion (worst-case factorial paths);
generic betweenness centrality is O(V·E) and answers the wrong question.

## Decision

- **Attack-path scoring** — edge weight `w = -log P(traverse)` where `P(traverse)` is the
  probability of exploiting the *destination service* on arrival (from EPSS ×
  CVSS-exploitability × KEV × network-vs-local × auth-required — **Andy owns this function,
  G4**). Non-negative weights ⇒ most-probable path = shortest weighted path = **Dijkstra**;
  top-k = **Yen's k-shortest paths**; **depth-bounded** (`d ≈ 5`). The per-finding
  attack-path score **replaces raw CVSS as the default ranking.**
- **Chokepoints** — **path-set frequency** over the computed top-k paths, weighted by
  `crown-jewel value × path probability` (defender ROI), **not** Brandes betweenness.
- **Segmentation** — **cost-weighted min-cut** between entry-zone source and crown-jewel
  sink, capacities = *defender operational cost*. Cuts **observed** paths only (ADR-0001).
- **Multi-jewel campaign cost** — Steiner tree is NP-hard; approximate via **MST (Kruskal)
  over the metric closure** (later, Phase 8).
- **Scale** — tractability is N-independent (depth-bounding makes per-source cost depend on
  the d-hop neighborhood; sources/sinks are the *declared* surface). The loading constraint
  at 1.2M is solved by an **edge pre-filter**: agents self-flag `(has-KEV ∧ exposes-service)`,
  `(is-crown-jewel)`, `(on-cross-trust-boundary)` as zero-message local facts; the server
  assembles only the flagged subgraph and runs **O(depth)-round label propagation**
  (distributed Bellman-Ford / Pregel) over it.
- **Two-matcher split** — a deliberate, bounded exception to collect-thin: an **agent-side
  KEV-only pre-filter** (the KEV catalog is ~1,200 CVEs, ~200× smaller than NVD) self-flags
  candidates for pruning; the **server-side authoritative matcher** remains the only source
  of low-FP findings. The ~200× size ratio is the line — anyone promoting the agent KEV
  flag to an authoritative finding re-imports #1206's backport false-positives.

## Consequences

- **The local tripwire proposes; the bounded propagation confirms.** A local-heuristic flag
  is never shipped as a finding.
- **Escape hatch:** if even the pre-filtered set stops fitting centrally, push the whole
  propagation to the agents (true distributed Pregel). Documented; not v1.
- Andy owns the model knobs (G4 probability function, depth bound, segmentation cost model,
  acceptance bar); Eng owns the algorithm choices, justified by tractability.
