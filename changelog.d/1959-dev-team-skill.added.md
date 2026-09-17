- **`/dev-team` senior-led delegation workflow is now committed project-level tooling.** The
  skill (`.claude/skills/dev-team/`) plus its two agents (`junior-developer`,
  `enterprise-architect` in `.claude/agents/`) move from personal user-global config into the
  repo, so every collaborator gets them via git instead of installing by hand. An Opus "senior"
  session decomposes a task, dispatches Sonnet `junior-developer` subagents in parallel,
  autonomously resolves their escalations (consulting a Fable `enterprise-architect` for
  material or disputed calls), then integrates behind `/test` + `/governance` — committing the
  reconciled tree before governing it so the gate always covers the exact range that gets
  pushed. Additive only; no existing agent or skill is modified. Invoke `/dev-team <task>` (#1959).
