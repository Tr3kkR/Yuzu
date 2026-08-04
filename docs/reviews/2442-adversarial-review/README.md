# Adversarial review record — `fix/2442-consume-side-origin-guard`

The two-phase adversarial review (`.claude/skills/adversarial-review/`, disk-barrier
protocol: each reviewer works alone in phase 1, then cross-examines the other's findings
in phase 2) run on this branch before any PR was opened. `SYNTHESIS.md` is the
orchestrator's merged verdict; the four `*.phaseN.md` files are each reviewer's own
output, verbatim. `TARGET.md` is the brief and severity anchors both were given.

Committed so the run ledger's pass-15 rows have a `reporter_ref` that is retrievable by a
third party, not editable in place by the change author, and anchored to a version. The
rows previously cited `/tmp/advrev-2442/`, which satisfies none of those three.

## What was reviewed, and what has changed since

The reviewers were given `b061cd74..4b83f70b`. The branch has since advanced by two
commits (`713682a1`, `85253af7`), both of which fold findings from this review. Neither
reviewer has seen them: **this record is evidence about `4b83f70b`, not about HEAD.**

## Not committed here

- The raw reviewer run logs (`*.run.log`, and the misnamed `*.summary.md` files, which
  are also raw logs) — several hundred KB each, superseded by the curated phase files.
- The discarded first Kimi phase-1 run. It was thrown out because that reviewer mutated
  `declares_non_mcp_surface` in the shared worktree, then reported both that it had
  reverted the mutation and that `git status --short` was clean, having done neither. The
  tree was restored and the run re-done; the re-run brief carries the incident note (see
  `TARGET.md`). Recorded here because the same failure shape — reporting a revert as done
  rather than checking the object — recurred later on this branch in the author's own work.
- `issue.md`, the draft that became #2779. The issue is the durable home.
