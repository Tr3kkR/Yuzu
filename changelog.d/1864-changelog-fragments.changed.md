- **Changelog moved to per-PR fragment files (`changelog.d/`).** PRs no longer edit
  `CHANGELOG.md` — each change adds one uniquely-named fragment
  (`changelog.d/<PR#>-<slug>.<section>.md`, body = the finished bullet), and
  `scripts/assemble-changelog.py promote X.Y.Z` assembles fragments (plus any legacy
  `[Unreleased]` content) into the release section at tag time. This removes the
  standing `[Unreleased]` merge-conflict → re-approval loop that hit every second PR.
  Enforced in depth: a committed Claude Code PreToolUse hook denies direct
  `CHANGELOG.md` edits with fix-it instructions, the new `Changelog fragments`
  docs-lint job lints fragments and fails PRs whose diff changes `[Unreleased]`
  content, and `scripts/release-preflight.sh` blocks tagging while unpromoted
  fragments remain. Pre-convention branches convert with one command:
  `scripts/assemble-changelog.py --extract origin/dev --id <PR#>` (moves the branch's
  `[Unreleased]` additions into fragments and restores `CHANGELOG.md` to dev's
  version). Convention: `changelog.d/README.md`.
