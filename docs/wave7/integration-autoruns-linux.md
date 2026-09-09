# autoruns Linux leg integration notes (P13)

P13 owns `agents/plugins/autoruns/src/autoruns_linux.cpp` (`collect_linux`),
`tests/unit/test_autoruns_linux_local.cpp`, and this doc. It does not own any
hotspot file — `autoruns_win.cpp` (P12) and `autoruns_macos.cpp` (P14) are
siblings; the integrator wires all three leg TUs into the `autoruns` meson
target per P11's own `docs/wave7/integration-autoruns.md` checklist. No edit
in this doc duplicates that checklist.

## Sink-manifest row (docs/agent-spawn-sink-manifest.md)

`collect_linux` has exactly one spawn site: the rung-2 `systemctl
list-timers` fallback, reached only when none of the three system systemd
unit directories (`/etc/systemd/system`, `/usr/lib/systemd/system`,
`/lib/systemd/system`) could be enumerated. Every other acquisition in this
leg is a bounded local file read or directory listing — no other process is
ever spawned.

Row, in the exact column format of `docs/agent-spawn-sink-manifest.md:52`,
to be appended to that file's "Registered sites" table when this package
lands:

| Site ID | Location | Mechanism | Platform | Provenance | Mutating | Shell features | Privilege | Ladder review | Rung + evidence | Registration |
|---|---|---|---|---|---|---|---|---|---|---|
| `autoruns/collect_linux#1` | `agents/plugins/autoruns/src/autoruns_linux.cpp:collect_linux` | runner argv | Linux | compile-time literal argv | read-only | none — no pipeline/redirection; `--all`/`--no-pager`/`--no-legend` are direct argv flags, not shell syntax | none | no rung-1 API for this data on this OS in this plugin; the rung-1 path (reading the systemd unit directories directly) is attempted first and only falls back here when all three are unreadable | 2 — direct argv via yuzu::agent::run_bounded_subprocess; rung 1 passed over: no rung-1 API for systemd timer enumeration in this plugin, and the rung-1 directory-read path is unavailable on this host; rung 3 avoided: no shell hop, argv resolved via probe_tool_path | n/a |

## Capability-matrix expectation (docs/os-capability-matrix.md)

The generated block (`tools/capmatrix-gen`, read from `YuzuActionDescriptor`
capability declarations, never hand-edited — see the repo's own generated-
block discipline) should, once `autoruns_linux.cpp` is wired into the Linux
build, regenerate the autoruns plugin's Linux cells to:

- `list` / `catalog` — ✅ Full (`YUZU_SUPPORT_SUPPORTED`, rung 1) — the
  `kActionDescriptors[...].linux_leg` mechanism string in
  `autoruns_plugin.cpp` already reads "file reads of cron/anacron/at/systemd
  unit dirs/XDG autostart; systemctl list-timers argv fallback only when no
  unit dir is readable", which now matches this leg's real implementation
  (previously WAVE7_NOTES_PENDING/aspirational; P13 makes it accurate).

No `os-capability-matrix.md` row is hand-edited by this package — the
integrator regenerates the block on the canonical host (Linux; a macOS
regeneration has previously produced an inaccurate downgrade — see this
repo's own regeneration-host precedent) per that doc's own instructions,
after the three per-OS leg TUs are all present.

## Verification the integrator should run

**Required integrator step, not owned by this package:** register
`tests/unit/test_autoruns_linux_local.cpp` in `tests/meson.build`'s
`sources()` list (a one-line addition mirroring the sibling
`test_*_local_dispatcher.cpp` entries immediately above the current
`unit/test_autoruns_parsers.cpp` line) before running the commands below --
`tests/meson.build` is outside P13's `owned_files`, so this TU is not wired
into the test build by this package's own patch, and none of its assertions
(including the H1-class systemd-enablement regression check) run until it
is added.

```
meson compile -C build-linux autoruns_plugin_lib
meson test -C build-linux --suite server -- [autoruns]
```

Confirm the registration landed: `grep -n "test_autoruns_linux_local" tests/meson.build`
should return a match.

P13's own scoped syntax checks (`-fsyntax-only` against the real `__linux__`
guard, in a `ubuntu:24.04` container) and the lexical spawn-gate run are in
the structured summary's `evidence`; the above needs the full multi-package
merge (P12/P13/P14's leg TUs plus P11's own checklist edits) and a real
Linux build host.
