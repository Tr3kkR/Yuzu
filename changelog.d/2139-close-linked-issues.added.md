- **`Closes #N` now works on dev merges (ADR-3001 pillar 2, #2139).** A new
  `close-linked-issues` workflow runs on every push to `dev`, parses the merged PRs' bodies with
  the repo's single closing-keyword grammar (`scripts/tracker/closing_refs.py` — GitHub's keywords
  plus comma/`and` chains, code-fence/quote stripping, and negation suppression, acceptance-tested
  against GitHub's own `closingIssuesReferences` oracle with zero false negatives), and closes the
  claimed issues as `completed` with a self-identifying evidence comment naming the PR, merge SHA,
  merging human, and run URL. Never-close rules are structural: `security`-labelled,
  `do-not-close`-labelled, `scripts/tracker/do-not-close.txt`-listed, assigned, or open-PR-linked
  issues get an advisory comment instead — and the driver fails closed if the never-close list is
  missing. A per-PR cap (>6 refs) skips the batch into a `needs-triage` issue rather than closing
  in bulk. Liveness is three mechanisms: an `if: failure()` alert job (opens/updates an
  `automation-broken` issue, self-healing on green), a per-push leak scan, and a frozen parser
  fixture corpus in CI. The bundled driver also carries the one-time #2139 backfill
  (maintainer-reviewed dry-run diff, hard-stop on any security-labelled candidate) and
  `--undo-push` for exact-batch reversal. A deterministic zizmor guard fails any PR that deletes
  the workflow, adds a `paths:` filter, or moves it off the `push:` trigger.
