# Vuln-Scan Roadmap

**Status:** working roadmap for the vuln_scan / CAVM workstream (owner: Andy / @lesault).
**Created:** 2026-06-30.
**Last reconciled:** 2026-07-01 — against ADR-0018 (D1 wire-format correction, no-exceptions
KEV-pre-filter strike, Lane 1/2/3 routing) and ADR-0019 (tri-state findings + coverage dimension).

This roadmap is the **canonical sequencing** for the workstream. It reconciles three views into
one ordered plan:
- the North Star design — `docs/vuln-scan-engine-design.md` (floor = Phases 1–5, differentiator = Phases 6–8);
- the capability map — `docs/vuln-scan-capability-map.md` (domains V1–V8);
- the architecture decisions taken in design review (below).

It supersedes the ad-hoc "Epic 1–7" framing used in early discussion. Where the capability map
still cites "Epic N", read the milestone here instead.

---

## Locked architecture decisions

1. **Server-authoritative matching (collect-thin / correlate-rich)** — **ADR-0018**. The agent
   collects; the server decides. Matching moves off the agent (the ~40 hard-coded
   `cve_rules.hpp` rules retire). **No exceptions** — an earlier draft's agent-side **KEV-only
   pre-filter** was struck 2026-07-01; any future real-time local tripwire belongs to DEX, not
   vuln_scan.
2. **Agent emits a structured typed identity; CPE and PURL are both server-derived.** —
   **ADR-0018 D1.** The wire format is `PackageIdentity`/`AppIdentity` (a decomposed `oneof`:
   ecosystem, name, epoch, version, release, arch), **not** a PURL string. Matching then routes
   by ecosystem into three lanes: **Lane 1** distro packages (deb/rpm/apk) → OVAL-primary,
   NVD-fallback on the full EVR; **Lane 2** language ecosystems (pypi/npm/gem/cargo/…) →
   OSV.dev by a server-derived PURL (deterministic, no CPE guessing); **Lane 3** OS-native GUI
   apps (Windows/macOS) → **not-assessed** in v1 (no curated detection content authored;
   federation deferred to ADR-0020). CPE itself is only derived for Lane 1's NVD-fallback and
   Lane 3's future federation — see memory `vuln-scan-agent-emits-purl` and capability-map
   V1.3/V2.
3. **Server substrate is Postgres** (ADR-0006/0012). New server stores are born-on-PG.
4. **Findings are tri-state; coverage is a first-class, separate dimension** — **ADR-0019**.
   Per-`(host, package)` status is **vulnerable / assessed-clean / not-assessed** — a package
   outside every feed's scope is never silently reported as clean. Each scan also reports a
   **coverage metric** (assessed N of M installed packages) alongside the vulnerability count.

---

## Current baseline (2026-06-30)

| Area | State |
|---|---|
| Agent matching | ~40 **hard-coded** CVEs (`cve_rules.hpp`); substring product match + naive comparator. Runs on-demand, emits pipe-delimited findings. |
| Agent inventory | `name\|version` only; duplicate collector (vuln_scan vs `installed_apps`). No source/arch/EVR — target is a typed `PackageIdentity`/`AppIdentity` record (ADR-0018), not PURL. |
| Server NVD | `nvd_client`+`nvd_db`+`nvd_sync` **wired**, but the store is a flat `cve(product, affected_below)` (no CPE ranges) and **keyword-scoped**. Consumed only by the topology vuln overlay; the plugin never queries it. |
| OVAL / EPSS / KEV / CVSS-vector | **None** (design-doc only). |
| Topology graph | `FleetTopologyStore` — observed graph, in-memory 60s, no persistence, no vuln attach. |
| Asset value / crown jewels | **None.** |
| CAVM scoring (composite / AMAPC / chokepoints / gates) | **None.** |

---

## Milestones

Each milestone: **Goal · Deliverables (→ V-capabilities) · Depends on · Acceptance · Your decisions (R4/R6)**.

### M1a — NVD correlation MVP (floor; prove the pipeline)
Maps to North Star **Phase 1**: *"inventory emits normalised identity (CPE/PURL + source + arch);
server matches against an NVD mirror with real version-range logic for a pilot product set."*
(That design-doc phrasing predates ADR-0018 D1 — the wire format is the typed identity `oneof`,
not CPE/PURL; CPE/PURL are both server-side derivations off it.) This milestone stands up
**Lane 1's NVD-fallback** for a pilot distro; M1b adds the OVAL-primary override on top.

- **Goal:** real server-side NVD matching for a pilot product set, replacing the hard-coded path.
- **Deliverables:**
  - Agent **typed-identity collector** (dpkg/rpm/apk + `/etc/os-release` namespace + arch + full
    EVR → `PackageIdentity`; Windows `DisplayName`/`Publisher`/`FileVersion` + macOS bundle id →
    `AppIdentity`) + kernel/OS-build rows; **unify the duplicate collector**. → V1.3, V1.1
  - **Wire format** — structured identity record on the inventory payload; `agent_pb`+`gateway_pb` regen. → V1.3
  - **NVD store reshape** to `cpeMatch` + `versionStart/EndIncluding/Excluding` (born-on-PG); re-ingest parsing the cpeMatch arrays; drop keyword scoping. → V2.2
  - **Identity→CPE map** — curated/exact for the pilot set (pgvector fuzzy deferred to Lane 3
    federation, ADR-0018/ADR-0020). → V2.3
  - **Range-aware comparator** (recover #1206: epoch / rpmvercmp / semver). → V2.1
  - **Correlation engine** + born-on-PG **findings store** (current-state, dedup, per-device,
    **tri-state status** vulnerable/assessed-clean/not-assessed per ADR-0019). → V2.3, V4.4, V4.5
  - **Dispatch rewire** — on-demand scan returns the typed identity record → server correlates → findings surface (live view). → V4.1, V4.2
- **Depends on:** typed-identity collector (agent) before server correlation.
- **Acceptance:** match **parity vs a hand-labelled reference host**; **no lower-bound false
  positives** (G-bar); a package outside NVD's scope reports **not-assessed**, never a false
  "clean" (ADR-0019).
- **Your decisions:** pilot product set; full-NVD vs targeted mirror; API key; refresh cadence.

### M1b — OVAL / backport correctness (the FP-killer, R3)
Maps to North Star **Phase 2** (backport correctness) and **ADR-0018 Lane 1**
(OVAL-primary, NVD-fallback for distro packages).

- **Goal:** eliminate false positives on backport-fixed distro packages.
- **Deliverables:** OVAL/distro-advisory ingestion for **one pilot distro** (e.g. Ubuntu USN/OVAL);
  full-EVR (from `PackageIdentity`) → advisory match; **prefer-OVAL-over-NVD** routing for
  distro-packaged software, making Lane 1's OVAL-primary/NVD-fallback split real. → V2.4, V2.3
- **Depends on:** M1a (typed-identity emit + correlation engine).
- **Acceptance:** zero FPs on a backport-fixed reference set; OVAL verdict overrides NVD for distro pkgs.
- **Your decisions:** which distro(s); OVAL feed sources + freshness SLOs (R4).
- **Open tension (flagging, not resolving):** the pre-reconciliation roadmap listed "pgvector
  fuzzy PURL→CPE for the long tail" as an M1b deliverable, but ADR-0018 Lane 3 places pgvector
  fuzzy CPE matching in the **deferred GUI-app federation** track (its own future ADR-0020), not
  in distro/OVAL work. Removed from M1b here; Andy to confirm there's no separate long-tail
  fuzzy-match need for distro packages *outside* Lane 3 before this is fully closed.

### M2 — Enrichment & prioritisation
- **Goal:** make findings rankable, not just present; make findings honest (ADR-0019).
- **Deliverables:** EPSS + CISA KEV + CVSS-vector ingestion into the enrichment store; per-finding
  flags/scores; **tri-state finding status + per-host coverage counters** (assessed N of M),
  feed-sync timestamp threaded onto each "assessed-clean" verdict, not-assessed reasons grouped
  (no-OVAL-stream / no-CPE-mapping / side-loaded). → V2.5, V2.6, V2.7, V2.8, V4.5
- **Depends on:** M1a (findings store).
- **Acceptance:** findings carry EPSS/KEV/CVSS; KEV-flagged actively-exploited CVEs surface first;
  coverage is reported as a first-class number beside the vulnerability count, never inferred from it.
- **Removed (ADR-0018, 2026-07-01):** the agent-side KEV-only pre-filter previously listed here
  is struck — no agent-side exception survives; see Locked architecture decision #1.

### M3 — Topology join (vulnerable **and** reachable)
- **Goal:** connect findings to the reachability graph.
- **Deliverables:** persist the topology graph (born-on-PG, keep the in-memory hot path); attach
  findings to service/host nodes; vuln overlay in fleet viz. → V5.2, V5.3, V5.4
- **Depends on:** M1a (findings store), existing `FleetTopologyStore`.
- **Acceptance:** a service node renders its CVEs; "vulnerable + reachable" is queryable.

### M4 — Asset model (crown jewels)
- **Goal:** the gating prerequisite for scoring.
- **Deliverables:** crown-jewel/asset-value designation (born-on-PG store + dashboard/REST + RBAC
  securable + audit); value on topology nodes. → V6.1, V6.2
- **Depends on:** M3 (nodes to annotate).
- **Acceptance:** operator designates jewels; value flows onto nodes.

### M5 — CAVM scoring (the differentiator)
Maps to North Star **Phases 6–8** (ADR-0001/0002/0003/0005).

- **Goal:** attack-path-aware prioritisation.
- **Deliverables, in order:** EUC edge typing (Foothold/LM/PE/DA) → composite priority score
  (C.5) → crown-jewel reachability + chain centrality → **AMAPC** → choke-point analysis
  (2-approx MST/Steiner) → gate model (act_now/attend/monitor/track) + visibility discount.
  → V7.1–V7.7
- **Depends on:** M2 (threat weight), M3 (graph), M4 (asset value).
- **Acceptance:** scored backlog matches hand-ranked reference scenarios; AMAPC stable + monotonic.

### M6 — Operational integration
- **Goal:** close the loop with SOC + leadership.
- **Deliverables:** SOC real-time rescoring (alert → edge-weight modulation via events/SSE);
  board metric / AMAPC-trend gauges + panel; remediation batching/governance. → V8.1, V8.2, V8.3
- **Depends on:** M5.
- **Acceptance:** alerts re-rank live; AMAPC trend reported; remediation batches actionable.

---

## Cross-walk

| Milestone | North Star | Capability-map | Net-new vs reuse |
|---|---|---|---|
| M1a | Phase 1 | V1.1/V1.3, V2.1/V2.2/V2.3, V4.1/V4.2/V4.4/V4.5 | reshape NVD store; new collector/comparator/engine; reuse sync transport |
| M1b | Phase 2 | V2.4, V2.3 | all new (OVAL) |
| M2 | floor | V2.5–V2.8, V4.5 | all new |
| M3 | floor | V5.2–V5.4 | persist + attach; reuse graph |
| M4 | floor | V6.1–V6.2 | all new |
| M5 | Phases 6–8 | V7.1–V7.7 | all new |
| M6 | Phases 6–8 | V8.1–V8.3 | new; reuse events/SSE |

---

## Open decisions (yours, R4/R6)

1. **Pilot scope** — start M1a **NVD-only, one OS family** (smallest slice that hits the
   acceptance bar), or go straight to **M1a+M1b one distro** (proves the differentiator from
   day one)? *Recommendation: M1a NVD-only first to de-risk the pipeline, then M1b.*
2. **Branch scope** — keep a dedicated branch to the **agent typed-identity emit** (first PR,
   independently testable against a reference host), or make it a **Phase-1 epic branch**?
   *Recommendation: agent-identity-only PR first; server M1a on follow-ups.* **Branch note:**
   `feat/vuln-scan-v1-inventory` was cut early and never carried unique commits — as of
   2026-07-01 it is an ancestor of `dev` (stale), so PR 1 should branch fresh off current `dev`
   rather than reuse it.
3. **Data sources** — full-NVD vs targeted mirror; OVAL distro(s); EPSS/KEV feeds; freshness SLOs.

---

## Immediate next slice

**PR 1: agent typed-identity collector + wire format** — unify the collector, emit the
structured `PackageIdentity`/`AppIdentity` record (per-OS, ecosystem-discriminated `oneof`
per ADR-0018 D1), add kernel/OS-build rows, extend the proto. Validate the identity output
against a reference host (PURL, where it's needed at all — Lane 2 OSV.dev queries, SBOM
export — is a server-side derivation, never emitted by the agent). No server behaviour change
yet, so it's cleanly reviewable and independently testable. Server M1a pieces (NVD reshape →
comparator → engine → findings store → dispatch rewire) follow on subsequent PRs. Cut this PR
fresh off current `dev` — `feat/vuln-scan-v1-inventory` is stale (see Open decisions #2).
