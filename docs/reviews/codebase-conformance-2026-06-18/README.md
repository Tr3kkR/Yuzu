# Codebase Conformance Audit — 2026-06-18

Compares the codebase (branch `feat/postgres-f3-flip` @ `1f375f29`) against the *intent*
recorded in its documents, across four tiers: ADRs + CLAUDE.md routed concerns (architectural
law), WIRED/SHIPPED status markers (current-state claims), user manuals (behavioral spec), and
capability-map/roadmap (aspirational).

- **[register.md](./register.md)** — the drift register: all 388 claims scored
  CONFIRMED / DRIFTED / PARTIAL / UNVERIFIABLE, with code evidence, severity, drift direction,
  per-tier stats, and the Phase-3 live-UAT evidence table.
- **[proposed-record-updates.md](./proposed-record-updates.md)** — drafted ADR / CLAUDE.md
  corrections (in scope) + product-doc proposals (your triage) + code-side gaps (flagged, not filed).
- **register-data.json** — the merged structured rows (machine-readable, for re-querying).

**Method:** 17-domain multi-agent fan-out; every claim statically verified then adversarially
re-checked by an independent skeptic; behavioral claims confirmed against a live Postgres-flipped
stack. **Result:** 340/388 (87%) confirmed; Tier-A architectural law holds 189/201. Dominant
pattern: docs lag *behind* the code.
