---
name: warn-sqlite3-changes
enabled: true
event: file
action: warn
conditions:
  - field: file_path
    operator: regex_match
    pattern: \.(cpp|hpp)$
  - field: new_text
    operator: contains
    pattern: sqlite3_changes
---

**[WARN] `sqlite3_changes()` after `sqlite3_step()` on a shared connection is a data race (#1033).**

`sqlite3_changes()` reads `db->nChange` without the per-connection mutex, so it
races any concurrent `step()` on the same handle. FULLMUTEX serialises individual
API calls but NOT the `step -> changes` pair -- it's both a TSan data race and a
correctness bug.

Use one of the two correct idioms:
- Put `RETURNING` on the statement so the result rides the `step()` return code, or
- For a genuine row count, wrap the `step -> changes` pair under `sqlite3_db_mutex`.

(Ignore if you're only reading an existing #1033 site you're not modifying.)
