- **Issue-standard guard (ADR-3001 pillar 4).** A `PreToolUse` hook
  (`scripts/hooks/issue-standard-guard.py`) now holds `gh issue create` in
  Claude sessions to `docs/agents/issue-standard.md`: it denies a filing whose
  labels break the contract (exactly one type; `roadmap` XOR a priority plus a
  triage state; no automation-owned labels at filing), asks for a human check
  on a `security`-labelled create or when no duplicate-search probe ran earlier
  in the session, and best-effort checks the body sections when they are
  statically visible. It fails open on every ambiguity. Ships with the first
  automated tests `scripts/hooks/` has ever had.
