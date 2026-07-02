---
status: proposed
date: 2026-07-01
owner: "@lesault (Andy Younie)"
depends-on: 0018 (server-authoritative matching — the engine that produces these findings); 0005 (two-matcher split)
related: docs/vuln-scan-engine-design.md §4.4; docs/vuln-scan-roadmap.md M2; docs/vuln-scan-capability-map.md V4
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

## Ratification

**Status: proposed.** Authored by the vuln_scan domain owner. Less cross-cutting than ADR-0018
(it does not redraw the agent↔server boundary), but it commits the finding data model and the
reporting surface, so route it through the normal review / `/governance` path together with
ADR-0018 rather than self-accepting. Record the accepting reviewer + date here on acceptance.
