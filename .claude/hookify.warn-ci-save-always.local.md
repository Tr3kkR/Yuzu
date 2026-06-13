---
name: warn-ci-save-always
enabled: true
event: file
action: warn
conditions:
  - field: file_path
    operator: regex_match
    pattern: \.github/workflows/.*\.ya?ml$
  - field: new_text
    operator: regex_match
    pattern: save-always:\s*true
---

**[WARN] `save-always: true` is forbidden in Yuzu CI (zizmor guard enforces this).**

`save-always` saves the cache even on cancellation, which poisons the cache with
partial artifacts.

Use the split pattern instead:
- `actions/cache/restore` at the start of the job
- a paired `actions/cache/save` at the end (gated on success)

For self-hosted runners, prefer a local filesystem cache under `runner.tool_cache`
(no GHA cache round-trip). Full snippets in `.claude/skills/ci-cache/SKILL.md`.
