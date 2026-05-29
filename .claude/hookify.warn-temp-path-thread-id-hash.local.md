---
name: warn-temp-path-thread-id-hash
enabled: true
event: file
action: warn
conditions:
  - field: file_path
    operator: regex_match
    pattern: tests/.*\.cpp$
  - field: new_text
    operator: regex_match
    pattern: std::hash\s*<\s*std::thread::id\s*>
---

**[WARN] Don't salt temp-path / DB uniqueness with `std::hash<std::thread::id>` (#473).**

It silently collides under Defender-induced I/O serialisation on
`yuzu-local-windows`, which produced flake #473.

Use the shared helpers instead:

    #include "test_helpers.hpp"
    auto path = yuzu::test::unique_temp_path("prefix");
    yuzu::test::TempDbFile db;          // for SQLite temp DBs

Rationale and residual adoption: header comment in `tests/unit/test_helpers.hpp` + #482.
