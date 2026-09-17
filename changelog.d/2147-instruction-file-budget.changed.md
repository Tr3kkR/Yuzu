- Reduced the always-loaded agent instruction files by 44% (161,845 → 90,451 characters) and
  documented the standard that keeps them there. `CLAUDE.md` and `AGENTS.md` are now contents pages
  that route to `docs/`, rather than carrying the detail themselves: `CLAUDE.md` 35,633 → 15,218 and
  `AGENTS.md` 49,859 → 16,395, with the two routed-concern tables dropping from 38,545 and 37,808 to
  30,520 and 28,318. Detail moved to six new documents — `docs/testing/unit-test-conventions.md`,
  `docs/build-guide.md`, `docs/clock-guarded-retention.md`, `docs/ota-pull-bounds.md`,
  `docs/command-dedup.md` and `docs/instruction-file-standard.md` — plus the existing
  `docs/auth-architecture.md`, the governance skill, and the Guardian design document. No invariant,
  issue reference or ADR citation was dropped: all 83 issue references and 28 ADR references in the
  previous files still resolve.
- Added `docs/instruction-file-standard.md`, which defines where a rule belongs — a hook, a header
  comment at the site, a `docs/` file plus a routed-concern row, a routed-concern row alone, and only
  then an instruction file — along with the one-canonical-home rule, pay-as-you-go budgeting, and
  machine-readable expiry markers for temporary sections. Linked from `CONTRIBUTING.md`.
- Extended `tests/test_issue_docs.py` from `CLAUDE.md` alone to all four always-loaded files, behind
  a 32,000-character budget that sits below the existing 40,000 hard cap so the next approach is
  caught with runway. The two routed-concern tables and `AGENTS.md` had never been measured; both
  tables had independently grown to within ~2,000 characters of the cap, and `AGENTS.md` was already
  25% over it. The check now also fails on an expired `EXPIRES:` marker and on any backticked repo
  path that resolves nowhere.
- Removed the expired "Active workstreams" blocks from `CLAUDE.md` and `AGENTS.md` and deleted
  `docs/workstreams.md`, per that document's own teardown procedure; its stated window closed on
  2026-08-05. Also removed a skills paragraph describing an install command that no longer exists,
  three citations of a private memory directory that resolved nowhere, and `AGENTS.md`'s duplicate
  copy of the routed-concern tables, which had drifted far enough to still describe `CaStore` and
  `AuthDB` as SQLite stores and to cite three `.codex/agents/*.md` briefs that do not exist.
- Added routed-concern table structure validation to `tests/test_issue_docs.py`: every row must have
  three populated columns, no row's `Loaded by` column may duplicate its `Doc` column, and a literal
  `|` inside a cell must be escaped. An unescaped `|` shifts every column to its right, which is how
  one CATASTROPHIC row's agent list was silently replaced by a copy of its own doc pointer — leaving
  a credential-revocation surface with no review trigger while the table still looked well-formed.
  Nothing previously validated table columns; a row that names no trigger defeats governance
  standing rule 1.
