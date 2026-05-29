---
name: warn-temp-path-steady-clock-salt
enabled: true
event: file
action: warn
conditions:
  - field: file_path
    operator: regex_match
    pattern: tests/.*\.cpp$
  - field: new_text
    operator: contains
    pattern: steady_clock
  - field: new_text
    operator: regex_match
    pattern: (/tmp/|tmpnam|temp_path|tmp_path|unique_temp|TempDbFile|\.db\b)
---

**[WARN] Are you salting a temp path / DB filename with `steady_clock`? Don't (#473).**

This edit mentions `steady_clock` alongside temp-path tokens. If the clock value
is being used to make a filename unique, it silently collides under I/O
serialisation on `yuzu-local-windows` (flake #473) -- exactly like the
`std::hash<std::thread::id>` anti-pattern.

Use the shared helpers instead:

    auto path = yuzu::test::unique_temp_path("prefix");
    yuzu::test::TempDbFile db;

IGNORE this warning if `steady_clock` here is purely for timing / elapsed-duration
measurement -- that's a legitimate use and not what this rule targets.
