- **Issue-lifecycle standard adopted (ADR-3001, amended A1).** Filing, labelling, and closing
  GitHub issues now follow `docs/agents/issue-standard.md`: mandatory duplicate search before
  filing, four body sections (Context / Evidence / Acceptance criteria / Origin), a three-axis
  label contract (type + priority-or-`roadmap` + triage state), and never-close rules for
  automation — `security`-labelled, `do-not-close`-labelled, or listed in
  `scripts/tracker/do-not-close.txt` (seeded with the deliberately-held-open security surface,
  live before any close automation exists). ADR-3001 is accepted and amended in place (A1):
  close-on-merge moves to a `push`-to-`dev` trigger, the triage sweep loses its autonomous
  closure tier, the per-PR close cap drops to 6, and the CODEOWNERS artefact is descoped. The
  `/governance` and `/test` skills now file deferred findings per the standard (dedupe-first,
  `governance-deferred` label, filed-and-not-filed run reports), and every instruction surface
  (CLAUDE.md, AGENTS.md, CODEX.md, CONTRIBUTING.md, the PR template) routes to it.
