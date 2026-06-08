# Modern Vulnerability Detection Engine — Design & Roadmap

| | |
|---|---|
| **Status** | Draft — for review |
| **Domain owner** | @lesault (Andy Younie) — vulnerability management |
| **Eng partner** | TBD |
| **Created** | 2026-06-08 |
| **Supersedes** | the static PoC matcher in `agents/plugins/vuln_scan/` |
| **Builds on** | PR #1206 (spike — proved the rule-delivery plumbing) |
| **Related** | `docs/capability-map.md` §9, `docs/enterprise-parity-plan.md`, `docs/data-architecture.md` |

---

## 1. Goal

Turn Yuzu's vulnerability scanning from a static proof-of-concept (a hand-written
list of ~42 CVEs matched by substring) into a **modern, on-box, agent-based
vulnerability detection engine** whose results an enterprise security team would
actually trust and act on.

"Trustworthy" is the whole game. A scanner that cries wolf — flagging packages
that are already patched — gets muted within a week. The bar is **low false-positive
rate on a real, patched fleet**, not raw CVE count.

### Non-goals (for the first cut)
- Network/unauthenticated scanning. We are on-box and agent-based on purpose.
- Full software-composition analysis (SBOM of language-ecosystem deps). Valuable,
  but a later phase.
- Replacing a commercial scanner's entire feature set. We want a credible,
  honest core first.

---

## 2. The mental model: *collect thin, correlate rich*

Modern agent-based scanners do **not** do the hard matching on the endpoint. The
agent's job is to report *what is installed* in a canonical form; a backend
service correlates that against a rich, continuously-updated vulnerability data
plane. This keeps the agent small and lets the matching logic (the part that is
hard and changes often) live where it can be updated without touching every
endpoint.

```
   ┌─────────────────────────────┐         ┌──────────────────────────────────────┐
   │  Agent (per endpoint)        │         │  Server — Vuln Correlation Service     │
   │                              │         │                                        │
   │  Inventory collector         │ inventory│  ┌────────────────────────────────┐   │
   │   dpkg/rpm/apk/registry/...  ├─────────►│  │ Identity normaliser (CPE/PURL) │   │
   │   → name, version, source,   │  (CPE/   │  └───────────────┬────────────────┘   │
   │     arch, normalized id      │   PURL)  │                  ▼                     │
   │                              │         │  ┌────────────────────────────────┐    │
   │  (kernel, OS build, app      │         │  │ Correlation engine             │    │
   │   bundles as additional      │         │  │  • version-range matching       │    │
   │   inventory rows)            │         │  │  • backport / fixed-status      │    │
   └─────────────────────────────┘         │  │    from distro advisories       │    │
                                            │  └───────────────┬────────────────┘    │
   Vuln data plane (synced on the server):  │                  ▼                     │
     • NVD (CPE + version ranges)           │  ┌────────────────────────────────┐    │
     • Distro advisories / OVAL             │  │ Prioritiser (CVSS+EPSS+KEV+ctx)│    │
       (Ubuntu USN, Debian, RHEL, Alpine)   │  └───────────────┬────────────────┘    │
     • OSV.dev (pre-merged, ecosystem)      │                  ▼                     │
     • CISA KEV, FIRST EPSS                 │           Findings store → dashboard/REST/MCP │
                                            └────────────────────────────────────────┘
```

The PoC and PR #1206 put the matcher **on the agent** with a single-threshold
rule list. That is the part we are replacing. The agent keeps only the inventory
collector (which #1206 already has, as the `inventory` action).

---

## 3. Where we are today

### 3.1 What the PR #1206 spike proved (keep this)
- **Runtime rule delivery**: `update_rules` action + `<data_dir>/staged/cve_rules.json`
  + real SHA-256 integrity verification + `content_dist.stage` delivery. Rules can
  be refreshed without re-shipping the agent.
- **Automated data refresh**: a weekly GitHub Actions workflow regenerates the
  ruleset from NVD and opens a CODEOWNERS-gated PR.
- **Inventory action**: `vuln_scan.inventory` emits `name|version` per package —
  the seed of *collect thin*.
- **Breadth of collection surface**: package managers across Win/Linux/macOS,
  kernel version, file-level binary version (PE VERSIONINFO / `.app` Info.plist),
  CIS config checks.
- **A version comparator** that understands Debian epochs, RPM/Alpine release
  suffixes, and semver pre-release ordering.

### 3.2 What it does *not* do yet (the engine gap)
The matcher is still the PoC's logic — `substring(product) && version < threshold`
— now fed a larger but lossy keyword-subset of NVD. Concrete evidence from the
generated `content/cve_rules.json` (335 rules):

- **Coverage collapses silently.** The generator queries 31 product keywords;
  **only 10 produced any rule.** Zero rules for `linux-kernel`, `windows`,
  `chrome`, `firefox`, `python`, `node`, `php`, `docker`, `kubernetes`, `mysql`,
  `postgresql`, `git`, `samba`. The new `kernel_scan` and Windows paths therefore
  have **no rules to match against.** (Root cause: `_extract_version()` takes the
  first `cpeMatch` containing a literal token substring and requires a single end
  bound — e.g. token `"linux-kernel"` never matches CPE `linux_kernel`.)
- **Lower version bound is discarded.** NVD's "2.0 ≤ v < 2.4" becomes "v < 2.4",
  so hosts on unaffected older majors are flagged. Range-less CVEs are dropped
  (false negatives).
- **No backport awareness.** A patched `openssl 3.0.2-0ubuntu1.18` is compared as
  upstream `3.0.2 < 3.0.8` and flagged — even though the fix is backported. This
  alone makes the current output untrustworthy on any real Linux fleet.
- **Identity is a display-name substring**, not CPE/PURL: `python` matches
  `ipython`; `git` matches `digit`.
- **No CVSS vector / EPSS / KEV** — severity is a bare label.

These are not bugs to patch in place; they are the absence of the engine. They
are also exactly the areas where **Andy's domain judgment is the input** and the
machine-generated code guessed wrong.

---

## 4. Requirements — and who owns each decision

| # | Requirement | What "modern" needs | Decision owner |
|---|---|---|---|
| R1 | **Canonical identity** | Map each installed artifact to CPE 2.3 and/or PURL, not a display name. | Eng, with Andy validating the mapping for key products |
| R2 | **Version-range semantics** | Honor `versionStart*`/`versionEnd*`, multiple ranges per CVE, "all versions". | Eng |
| R3 | **Backport / fixed-status** | Consume distro security advisories / OVAL (Ubuntu USN, Debian, RHEL OVAL, Alpine secdb) so distro-patched packages are not flagged. | **Andy** — which feeds, which distros first |
| R4 | **Data sources & freshness** | Choose the vuln data plane and refresh SLO. | **Andy** — see §5 |
| R5 | **Prioritisation** | CVSS base (+temporal/env), EPSS, CISA KEV, asset context. | **Andy** — the scoring model |
| R6 | **Coverage** | Full NVD ingest + kernel + OS + endpoint apps; not 10 server packages. | Andy (target product list) + Eng |
| R7 | **Acceptance / quality bar** | Precision/recall targets; "zero FPs on a fully-patched reference box." | **Andy** — sets the thresholds |
| R8 | **SBOM / SCA (later)** | Language-ecosystem deps (npm/pip/maven/cargo). | Andy + Eng (phase 5) |

---

## 5. Data plane — the first decisions for Andy

This is the highest-leverage set of choices and it is squarely a VM-domain call.
Options, with trade-offs:

- **NVD** (JSON 2.0 feeds or API): authoritative for CPE + CVSS + version ranges,
  but no backport/fixed-status, and CPE quality varies. Prefer the **bulk JSON
  feeds** over per-keyword API calls (complete, cacheable, no rate-limit games).
- **Distro advisories / OVAL** (Ubuntu USN/OVAL, Debian Security Tracker, RHEL
  OVAL, Alpine secdb): the **only** way to get backport-correct results on Linux.
  This is the single most important addition over #1206.
- **OSV.dev**: pre-merged, range-native, covers OS distros + language ecosystems
  with a clean schema. Strong candidate to reduce ingestion work.
- **CISA KEV**: known-exploited list — high-signal prioritisation.
- **FIRST EPSS**: exploit-probability score — prioritisation.
- **Windows**: NVD CPEs are weak here; consider MSRC CVRF / winget metadata.

**Andy's first call:** pick the primary correlation source (recommendation:
OSV.dev for ranges + distro feeds for backports, NVD for CVSS enrichment) and the
distro priority order. Everything downstream keys off this.

---

## 6. Phased roadmap (vertical slices Andy can drive)

Each phase is a shippable slice with an acceptance test. Andy owns the domain
decisions and the acceptance bar; an eng partner (or a coding agent working to
his spec) implements.

- **Phase 0 — Spike (DONE, PR #1206).** Rule-delivery plumbing, inventory action,
  collection breadth. *Outcome: plumbing proven; matcher acknowledged as PoC-grade.*

- **Phase 1 — Server-side correlation MVP.** Extend `inventory` to emit normalised
  identity (CPE/PURL + source + arch). Stand up a server correlation service that
  matches inventory against an NVD mirror with **real version-range logic** for a
  small pilot product set. Replace substring+threshold for those products.
  *Acceptance (Andy): match parity vs a hand-labelled reference host; no
  lower-bound false positives.*

- **Phase 2 — Backport correctness (the FP killer).** Add distro-advisory/OVAL
  correlation so patched packages report clean. *Acceptance (Andy): a
  fully-patched Ubuntu + RHEL reference box returns ZERO package CVEs.* This is the
  phase that makes the product trustworthy.

- **Phase 3 — Prioritisation.** CVSS vector + EPSS + KEV on every finding; default
  views ranked by exploitability, not raw severity. *Acceptance (Andy): the
  scoring model and default thresholds.*

- **Phase 4 — Coverage breadth.** Full data ingest; kernel (fix the CPE identity),
  Windows (MSRC), endpoint apps. *Acceptance (Andy): target product list covered;
  recall measured against a known-vulnerable reference set.*

- **Phase 5 — SBOM / SCA.** Language-ecosystem deps. *Acceptance: later.*

---

## 7. Quality bar — how we'll know it's "modern"

- **Precision** ≥ target on a labelled fleet (Andy sets it; backport FPs are the
  main enemy). A patched reference box must report clean.
- **Recall** ≥ target against a known-vulnerable reference set.
- **Freshness**: data-plane sync SLO (e.g. ≤ 24h from advisory publication).
- **On-box cost**: inventory collection bounded (CPU/mem/time budget per scan).
- **Honesty**: until Phase 2 lands, `capability-map.md` describes this as an
  early heuristic matcher, **not** "modern vulnerability scanning."

---

## 8. Open questions for Andy (decide these first)

1. **Primary correlation data source?** (OSV.dev vs NVD+OVAL composition.)
2. **Distro priority order** for backport feeds? (Ubuntu/Debian/RHEL/Alpine — which first?)
3. **Prioritisation model**: CVSS-only, or CVSS×EPSS×KEV weighting? Default ranking?
4. **Acceptance thresholds**: what FP rate is "trustworthy"? What's the reference fleet?
5. **Server-side vs on-box matching** for the MVP — confirm the *collect-thin* split.
6. **Target product/coverage list** for Phase 1 pilot and Phase 4 breadth.

---

## Appendix A — Evidence from the #1206 spike

- Configured keywords: 31. Products with ≥1 generated rule: **10**
  (`apache, curl, log4j, nginx, openjdk, openssh, openssl, polkit, sudo, 7-zip`).
- Zero rules: `chrome, confluence, docker, dotnet, exim, firefox, git, grafana,
  jenkins, kubernetes, linux-kernel, mysql, postfix, postgresql, putty, python,
  samba, windows, winrar`.
- `kernel_scan` (Linux/macOS) and the Windows path have no rules to match.
- Matching primitive: `icontains(app.name, rule.product) && compare_versions(app.version, affected_below) < 0`.
- Rule schema collapses NVD ranges to a single `affected_below` (== `fixed_in`),
  discarding lower bounds; CVEs without a single end bound are dropped.
