# Adversarial review record — `fix/2442-consume-side-origin-guard`

The two-phase adversarial review (`.claude/skills/adversarial-review/`, disk-barrier
protocol: each reviewer works alone in phase 1, then cross-examines the other's findings
in phase 2) run on this branch before any PR was opened. `SYNTHESIS.md` is the
orchestrator's merged verdict; the four `*.phaseN.md` files are each reviewer's own
output, verbatim. `TARGET.md` is the brief and severity anchors both were given.

Committed so that a conforming `reporter_ref` for the run ledger's pass-15 rows EXISTS:
one retrievable by a third party, not editable in place by the change author, and
anchored to a version. Those rows cite `/tmp/advrev-2442/`, which satisfies none of the
three.

**The rows now carry it, after a delay worth recording.** They are stamped
`recorded_at 2026-08-04T19:10:00Z`, while the commit that introduced them, `85253af7`,
has both author and committer date `2026-08-04T16:19:04Z` — a row claiming to be written
three hours after the commit containing it. Because `recorded_at` is the last-write-wins
precedence key and a row is superseded rather than edited, a correction stamped honestly
before 19:10Z would have sorted behind the row it corrects and never taken effect, so the
correction waited rather than being back-dated into place. It landed in `beaa7aec`, whose
rows are stamped `19:17:30Z`: all four now carry `source: "external-model"` — replacing a
value off the enum at SKILL.md:1642 — and a `reporter_ref` into this directory.

One row is deliberately still uncorrected: `adv2-reviewer-left-guard-disabled` keeps
`source: "external-review"`, because its reporter was the orchestrator rather than an
external model, and none of the three enum values describes an author-side self-finding.
That is an open question for the operator, not an oversight.

## What was reviewed, and what has changed since

The reviewers were given `b061cd74..4b83f70b`. The branch has since advanced by two
commits (`713682a1`, `85253af7`), both of which fold findings from this review. Neither
reviewer has seen them: **this record is evidence about `4b83f70b`, not about HEAD.**

## Not committed here

- The raw reviewer run logs (`*.run.log`, and the misnamed `*.summary.md` files, which
  are also raw transcripts — `kimi.phase1.summary.md` is 6393 lines and opens mid
  reasoning-trace) — several hundred KB each, superseded by the curated phase files.
- The discarded first Kimi phase-1 run. It was thrown out because that reviewer mutated
  `declares_non_mcp_surface` in the shared worktree, then reported both that it had
  reverted the mutation and that `git status --short` was clean, having done neither. The
  tree was restored and the run re-done; the re-run brief carries the incident note (see
  `TARGET.md`). Recorded here because the same failure shape — reporting a revert as done
  rather than checking the object — recurred later on this branch in the author's own work.
- `issue.md`, the draft that became #2779. The issue is the durable home.
