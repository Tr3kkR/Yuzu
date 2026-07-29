# Governance findings ledger — fragments

One file per `/governance` run, mirroring `changelog.d/`. Each line is a JSON object
describing one finding.

```
governance.d/<PR-or-issue-number>-<short-slug>.<random>.jsonl
```

- `<PR-or-issue-number>` — the PR number if you have it, else the issue.
- `<short-slug>` — 2–5 words, kebab-case.
- `<random>` — supplied by `mktemp`, which creates with `O_EXCL`. Two runs in the same
  second on the same PR cannot collide; uniqueness is enforced by the filesystem rather
  than assumed from a timestamp.

One file per **run**, not per PR. Gate 8 iterates, and `pass_ordinal` distinguishes rounds
*inside* a file; a fresh run gets a fresh fragment.

## Why these are committed

The ledger is evidence for whoever reviews the pull request: which findings were raised,
which were fixed, which were deferred and by whom. A per-machine path cannot be read by the
reviewer, and SOC 2 CC8.1 evidence has to be retrievable by someone other than the person
who generated it (#2618, decided on #2604).

Two costs, accepted deliberately: fragments appear in diffs, and an uncommitted fragment is
destroyed by `git clean` — the same window a changelog fragment already lives in. Commit it
with the work it reviews.

## Throwaway local runs

Set `YUZU_GOV_LOG_DIR` to a scratch directory outside the repo. Nothing is written here and
nothing needs cleaning up.

## Fields

Defined in `.claude/skills/governance/SKILL.md` under Gate 8 — `run_id`, `commit_range`,
`agent`, `pass_ordinal`, `finding_id`, `severity_native`, `severity_mapped`, `trigger`,
`impact`, `exposure`, `epistemic_status`, `independent_reporters`, `policy_floor`,
`provenance`, `disposition`, `caused_by`, `adjudicated_by`, `waiver_rationale`,
`file`, `line`, `summary`.

## Retention

Not decided. Nothing prunes these today. Whether they are pruned, assembled at release, or
kept indefinitely as compliance evidence is a separate call and deliberately not made here.
