---
status: accepted
date: 2026-07-01
owner: "@lesault (Andy Younie)"
depends-on: 0018 (server-authoritative matching — the engine that produces these findings); 0005 (two-matcher split)
related: docs/vuln-scan-engine-design.md §4.4; docs/vuln-scan-roadmap.md M2; docs/vuln-scan-capability-map.md V4; 0023 (correlation engine — first consumer, provisional number)
amended: 2026-07-05 (correlation-engine grill-with-docs session) — adds a fourth status `potential` and an orthogonal confidence axis (see Amendment)
---

# 0019 — Vulnerability findings are tri-state; coverage is a dimension separate from vulnerability

> Crystallised in the 2026-07-01 grill-with-docs session. Records *what a scan result means* for a
> package the feeds do not cover — the difference between "we looked and it's clean" and "we never
> looked." Load-bearing for the floor's honesty bar and for the differentiator's integrity claim.

## Context

The server-authoritative matcher (ADR-0018) routes each installed-software identity to a feed —
distro packages to OVAL, the Windows/macOS-GUI and language-ecosystem tail to CPE/NVD. For a given
`(host, package)` the naive model has two outcomes: **matched an advisory → vulnerable**, or **no
match → clean**.

That two-state model is wrong, because it collapses two genuinely different situations into
"clean":

- **(a) The package is within a feed's coverage and no advisory matches.** "No known
  vulnerabilities" is a *true* assertion. Trusting the feed's silence is correct here — feed
  correctness is about accuracy *within scope*.
- **(b) No feed covers the package at all** — a side-loaded vendor `.deb`, a language package the
  feeds don't track, or an EOL distro whose OVAL stream stopped publishing. The feed's silence here
  does **not** mean "safe"; it means **we never looked.**

"Assume the vuln feed is correct" licenses only (a). It says nothing about packages *outside* the
feed's scope. Conflating "the feed is authoritative for what it covers" with "the feed covers
everything" is the classic scanner lie, and in security tooling the resulting failure is a false
**negative** — the more dangerous direction.

### The failure the two-state model produces

An **EOL Ubuntu 18.04** host. Canonical no longer publishes standard OVAL for it (moved to paid
ESM). The router sends every `deb` package to the Bionic OVAL stream; the stream has no current
rows; so **every package "matches no feed"** and the two-state model reports **"no vulnerabilities
found"** on a host that is a swiss-cheese of unpatched CVEs. That is not a coverage gap — it is
**false assurance**, which is *worse* than no scan, because a reader sees "clean" and moves on.

## Decision

**A vulnerability finding is tri-state, and coverage is tracked as a dimension separate from
vulnerability status.**

1. **Per-`(host, package)` status is one of three values:**
   - **Vulnerable** — matched an advisory in a covering feed.
   - **Assessed–clean** — within a covering feed's scope, no match. Reported as *"no known
     vulnerabilities, as of feed-sync timestamp T"* (the absence of a finding has a shelf life, so
     the assertion is timestamped to the feed version it was evaluated against).
   - **Not-assessed** — the package is identified but **no feed covers it**. Surfaced explicitly as
     *unknown / not assessed* — **never** rendered as clean, never silently dropped.

2. **Coverage is a first-class, separate dimension.** Each host scan carries a **coverage metric**:
   *assessed N of M installed packages; (M−N) not-assessed.* Coverage answers "how much of this box
   did we actually evaluate," which is orthogonal to "how many vulnerabilities did we find." The two
   dimensions are reported side by side and neither is inferable from the other.

## Consequences

**Gained:**
- **Honest reporting.** The EOL-18.04 host reports "0 vulnerabilities, but only 12 of 430 packages
  assessed" instead of a false all-clear. The gap becomes a *visible, actionable number* — operators
  can act on low coverage (upgrade the distro, buy ESM, add a feed) instead of being lied to.
- **Differentiator integrity.** The CAVM attack-path scoring (ADR-0018's differentiator, roadmap
  M5) cannot credibly rank a host's risk if some installed packages are dark and unaccounted-for.
  A per-host coverage number is the precondition for claiming scoring completeness.
- **False-negative containment.** The most dangerous failure mode in a scanner — silently missing
  real vulnerabilities — is surfaced as low coverage rather than hidden behind a clean verdict.

**Costs accepted:**
1. **More data model + UI surface.** Findings carry a status enum (not a boolean) and each host
   carries coverage counters; the dashboard/REST must present coverage as a first-class figure, not
   a footnote. Deliberate — the honesty is the point.
2. **"Not-assessed" can look like noise on messy fleets.** A fleet full of side-loaded software
   will show large not-assessed counts. This is truthful signal, not noise, but it needs good
   defaults (group/aggregate not-assessed by reason: no-OVAL-stream vs no-CPE-mapping vs
   side-loaded) so operators can triage rather than drown.
3. **Feed-freshness must be carried.** "Assessed–clean as of T" requires threading the feed-sync
   timestamp through to the finding, so a stale feed produces a *stale-clean* signal, not a
   confidently-clean one.

**Ownership.** Andy owns the finding-status taxonomy and the coverage-metric definition; Eng owns
carrying the feed-version timestamp and computing coverage counters at correlation time.

## Amendment — 2026-07-05: a fourth status `potential`, plus a confidence axis

> Added during the correlation-engine design (grill-with-docs). The original tri-state assumed the
> matching feed for a given package is *backport-correct* — true for OVAL (Lane 1's authoritative
> source, ADR-0018) but **not** for raw NVD-on-distro. M1a (`docs/vuln-scan-roadmap.md`) stands up the
> correlation engine on **NVD-only, before OVAL lands (M1b)**. Against NVD alone, a distro package's
> `release` backport suffix (`1.1.1f-1ubuntu2.16`) is invisible, so an in-range NVD hit on a
> distro package is *not* a confirmed vulnerability — it is the dominant false-positive source ADR-0018
> lines 67-73 warns about. Asserting such a hit as **Vulnerable** would reintroduce exactly the
> scanner-lie this ADR exists to prevent, in the false-**positive** direction.

**The finding status is extended from three values to four:**

- **Vulnerable** — matched an advisory in a **backport-correct** feed (OVAL, M1b), or a curated exact-CPE
  match where backport is not a confound. *An asserted, confirmed vulnerability.*
- **`potential`** *(new)* — matched an NVD version range, but the match is **not backport-confirmed** (no
  OVAL for this package yet). Surfaced as *"unconfirmed — pending OVAL backport check, as of feed-sync T"*,
  and **counted separately from Vulnerable** (never folded into the vulnerable headline). When OVAL lands
  (M1b) each `potential` resolves deterministically → **Vulnerable** (OVAL: not-backported) or →
  **Assessed–clean** (OVAL: backport-fixed) **only if the finding's identity confidence is `high`**; a
  `low`-confidence `potential` that OVAL marks backport-fixed resolves to **Not-assessed** instead — the
  confidence gate applies at every point a finding could become `assessed-clean`, not just at initial
  correlation. **This is not a final verdict**: like any other record, it is re-assessed on the next
  qualifying trigger (ingest content-change or a new-CVE feed delta) — a persistent NVD range match keeps
  resurfacing as `potential (low)` each cycle rather than being silently dropped.
- **Assessed–clean** — within a covering feed's scope, no match, **and the package identity was resolved
  at high confidence**. A low-confidence identity match that looks clean is never assessed-clean — see
  the confidence rule below.
- **Not-assessed** — no feed covers the package, or the package's identity could only be resolved at low
  confidence **and no advisory matched** (a low-confidence match against an in-range advisory is still
  `potential`, carrying `confidence: low` — see below; this carve-out only ever removes a clean verdict,
  never a positive one); identified but never evaluated.

**A second, orthogonal dimension: `confidence`.** Independent of status, each `potential`/Vulnerable
finding carries `confidence ∈ {high, low}` reflecting the **identity-mapping** certainty — `high` = a
curated or exact CPE identity; `low` = a best-effort normalized-name match. Confidence answers "did we map
this package to the right CPE product," which is orthogonal to status's "what did the feed say." (This is
the same separation-of-dimensions principle as coverage vs vulnerability, applied to identity.)

**Low-confidence identity can never produce a clean verdict.** Without this rule, a wrong best-effort
name-prefix match that happens to land on a safe NVD product would become a counted, timestamped
`assessed-clean` finding with no confidence field attached to ever flag it — reintroducing, in the
false-**negative** direction, exactly the false-assurance failure this ADR exists to prevent. So a
`low`-confidence match **that would otherwise read clean** (no advisory in range) is routed to
`not-assessed` (reason `identity-low-confidence`) instead; only a `high`-confidence identity can produce
`assessed-clean`. **This rule never demotes a positive match** — a low-confidence identity that DOES land
an in-range advisory still surfaces as `potential (confidence: low)`, per the confidence axis above; the
carve-out only ever removes a clean verdict. **Coverage consequence:** a low-confidence-identity record
that would have been clean now counts toward coverage as `not-assessed` — the coverage number may read
lower than a naive identity-match rate would suggest. That is deliberate honesty, not a regression.

**Feed-freshness threading (realises cost #3 above).** Every `potential` and Assessed–clean verdict is
stamped with the NVD catalog feed-sync timestamp, so a stale mirror yields a *stale* signal, not a
confidently-current one.

**Consequence — M1a acceptance reconciled.** The roadmap's M1a bar is *"no lower-bound false positives."*
The MVP hits it **because it never asserts Vulnerable on a distro package pre-OVAL** — such hits are
`potential`, explicitly unconfirmed. The confirmed-Vulnerable bucket is ~empty until M1b; that is the
honest state, not a gap.

**Ownership.** Andy owns the finding-status taxonomy, so this amendment is within the ADR owner's remit;
it is recorded here rather than as a new ADR because it refines this ADR's core taxonomy. Route through the
same `/governance` path on the implementing PR.

## Ratification

**Status: accepted** (2026-07-09). Authored by the vuln_scan domain owner. Less cross-cutting than
ADR-0018 (it does not redraw the agent↔server boundary), but it commits the finding data model and
the reporting surface. **Accepted per @Tr3kkR's standing convention (2026-07-09): an ADR merged via
reviewed PR carries `status: accepted` on `dev`.** Already merged and standing on `dev` since
2026-07-01 without objection.
