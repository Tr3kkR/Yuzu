# Governance findings ledger — fragments

One file per `/governance` run, mirroring `changelog.d/`. Each line is a JSON object
describing one finding.

```
governance.d/<PR-or-issue-number>-<short-slug>.<random>.jsonl
```

- `<PR-or-issue-number>` — the PR number if you have it, else the issue.
- `<short-slug>` — 2–5 words, kebab-case.
- `<random>` — a `mktemp` stem, with the final `.jsonl` path created under `noclobber`
  so the committed artifact itself is opened `O_EXCL`. A suffix collision therefore FAILS
  LOUDLY rather than overwriting an earlier run's findings; uniqueness is enforced by the
  filesystem rather than assumed from a timestamp. The recipe is in the skill — do not
  reimplement it with `mv`, which overwrites silently.

One file per **run**, not per PR. Gate 8 iterates, and `pass_ordinal` distinguishes rounds
*inside* a file; a fresh run gets a fresh fragment.

A fragment is not sealed when the run ends. Findings from a PR review, an
`/adversarial-review`, or another external pass are appended to it with
`source: "collaborator"` / `"external-model"`, and a finding already recorded may later gain
a `refuted` disposition. An absent `collaborator` row means nothing was recorded — it is not
evidence that no external review happened.

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

**Defined in one place only:** the Gate 8 field table in
`.claude/skills/governance/SKILL.md`. Deliberately not restated here — an earlier draft of
this README listed the fields and had already dropped `classification`, which is exactly the
second-copy drift the governance rule itself forbids.

## Retention

Not decided. Nothing prunes these today. Whether they are pruned, assembled at release, or
kept indefinitely as compliance evidence is a separate call and deliberately not made here.
