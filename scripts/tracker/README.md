# scripts/tracker/ — issue-tracker automation (ADR-3001)

Tooling for the issue-lifecycle guardrails programme
(`docs/adr/3001-issue-lifecycle-guardrails.md`, as amended by A1). Distinct
from `scripts/issues/`, which holds static issue *bodies* for the historical
one-shot `create_issues.sh` backfill.

| File | Owner PR | Purpose |
|---|---|---|
| `closing_refs.py` | PR 2 | **The** closing-keyword parser — the only implementation. Imported by the workflow, the backfill, the undo path, the leak scan, and the test corpus. Grammar: GitHub's closing keywords + comma/`and` chains, with code-fence/quote/comment stripping and negation suppression (`--selftest` runs the embedded cases). |
| `close_linked_issues.py` | PR 2 | The driver behind `.github/workflows/close-linked-issues.yml`: `--push` (workflow), `--backfill` (one-time #2139 sweep; `--execute` additionally needs `--yes-i-reviewed`), `--undo-push` (reopen an exact prior batch), `--leak-scan` (completeness backstop). Always dry-run unless `--execute`. **Fails closed** if `do-not-close.txt` is missing or unparseable. |
| `do-not-close.txt` | PR 1 (#2168) | The committed never-close list — issue numbers no automation may ever close (issue-standard.md §5.1). Number-keyed because labels have been wrong before. Only a reviewed PR changes it; the `do-not-close` *label* is the maintainer's instant, no-PR marker (union semantics). |
| `bootstrap-labels.sh` | PR 1 (#2168) | Idempotent creation of the six automation labels. Run at PR-1 merge, before the first agent filing. |

Never-close ladder, order load-bearing (see `close_linked_issues.py`):
cap → self → not-an-issue → not-open → marker-idempotent → `security` →
`do-not-close` (label ∪ file) → assigned → open linked PR → close as
`completed` with a self-identifying evidence comment.

Run everything with `python` on Windows dev boxes (`python3` is the Store
stub); CI runners use `python3`.
