---
name: warn-drop-include-type-system
enabled: true
event: file
action: warn
conditions:
  - field: file_path
    operator: ends_with
    pattern: meson.build
  - field: old_text
    operator: contains
    pattern: "include_type: 'system'"
  - field: new_text
    operator: not_contains
    pattern: "include_type: 'system'"
---

**[WARN] This edit removes `include_type: 'system'` from a `meson.build` -- that's load-bearing.**

Every `dependency()` is marked `include_type: 'system'` so vcpkg / gRPC / abseil /
protobuf / Catch2 deprecation warnings are treated as `-isystem` and silenced,
while our own code stays under `warning_level=3`. Dropping it floods the build log
with third-party warnings and buries our own.

Keep `include_type: 'system'` on every dependency unless you have a specific,
documented reason. If you're intentionally splitting one dependency out, re-add it
in the new form so the net set is unchanged.
