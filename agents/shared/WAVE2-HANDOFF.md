# Wave 2 handoff — WP-0 shared headers

WP-0 lands four header-only helpers under `agents/shared/` (`icmp_probe.hpp`,
`runner_status.hpp`, `sudo_argv.hpp`, `host_arg.hpp`) plus their Catch2 unit
tests under `tests/unit/`. WP-0 does not edit `tests/meson.build` — the
integrator wires the three new test TUs into `agent_test_exe`'s source list.

## tests/meson.build

Append these three lines to `agent_test_exe`'s `files(...)` source list
(`agents/shared` is already on that target's `include_directories`, so no
new include path is needed):

```
'unit/test_runner_status.cpp',
'unit/test_host_arg.cpp',
'unit/test_sudo_argv.cpp',
```
