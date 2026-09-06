# Integration: autoruns macOS leg (P14)

P14 owns only `agents/plugins/autoruns/src/autoruns_macos.{cpp,hpp}` and
`tests/unit/test_autoruns_macos_local.cpp` — no hotspot file. This doc is
reference material for the integrator once P11/P12/P13/P14 land together
(P11's `docs/wave7/integration-autoruns.md` has the actual wiring checklist);
it covers the two things specific to the macOS leg.

## 1. Capability-matrix (`docs/os-capability-matrix.md`) expectations

Once `autoruns_plugin_lib` builds with `autoruns_macos.cpp` wired in and
`tools/capmatrix-gen` runs against it, the generated block's macOS rows for
the `autoruns` plugin should read:

| SourceId (as `source_id_string`) | macOS declared support | Rung | Mechanism |
|---|---|---|---|
| `mac_launchdaemons` | supported | 1 | file read + `CFPropertyListCreateWithData` |
| `mac_launchagents` | supported | 1 | file read + `CFPropertyListCreateWithData` |
| `mac_system_launchdaemons` | supported | 1 | file read + `CFPropertyListCreateWithData` |
| `mac_system_launchagents` | supported | 1 | file read + `CFPropertyListCreateWithData` |
| `mac_user_launchagents` | supported | 1 | file read + `CFPropertyListCreateWithData` |
| `mac_login_items` | **constrained** | — | no public read API (BTM database) |
| `mac_periodic` | supported | 1 | directory listing (no content read) |
| `mac_emond` | supported | 1 | file read + `CFPropertyListCreateWithData` |

This is generated from `kSourceCatalog` (`autoruns_catalog.hpp`, P11 —
already declares these eight exactly this way) plus P14's leg actually
compiling and linking; no manual edit to the generated doc block is needed
or permitted (`docs/os-capability-matrix.md`'s own `<!-- BEGIN/END
GENERATED -->` banner) — regenerate on Linux per this repo's standing rule
(capmatrix on this Mac has previously silently downgraded a rung; the
canonical host for this generator is Linux).

## 2. `autoruns_plugin.cpp`'s `kActionDescriptors` macOS note text

`autoruns_plugin.cpp` (P11, not owned by this package) carries a
`WAVE7_NOTES_PENDING` placeholder for the macOS leg's mechanism notes on
both the `list` and `catalog` action descriptors. Once P14 lands, the
factual content that text should carry is:

> File-truth only, rung 1: `CFPropertyListCreateWithData` over launchd
> plists (system + per-user LaunchDaemons/LaunchAgents), `/etc/periodic`
> directory listings, and `/etc/emond.d/rules` plists. Login Items is
> CONSTRAINED — the list lives in a private per-user BTM database with no
> public read API; this leg never shells out to `osascript`, `launchctl`,
> or `sfltool`. A plist's own `Disabled` key is read, but `launchctl
> print-disabled`'s separate override database is NOT consulted — this is
> file truth, not launchd's live runtime state, a deliberate divergence
> from a services-style plugin that does read launchctl state.

(Editing that text is out of this package's `owned_files`; left here for
whichever package/PR next touches `autoruns_plugin.cpp`'s descriptors — see
that file's own `WAVE7_NOTES_PENDING` comment, PR11.5/P15.)

## 3. `signed_state` — manual/decision text

For whichever doc eventually documents the `autorun|` row schema for
operators (no `autoruns` section exists yet in `docs/user-manual/
agent-plugins.md` as of this package), the `signed` column's macOS values
need this explanation:

> **`signed` column, macOS rows only.** `apple_system` means the row's
> `location` path falls under `/System/Library/` — a path judgement only,
> made by matching the literal path prefix. It is NOT a code-signature
> verification: this plugin never calls `SecStaticCodeCheckValidity` or any
> other Security.framework API, so `apple_system` should be read as "Apple
> ships this location" rather than "this specific file's signature was
> checked and is valid." Every other macOS row — everything under
> `/Library/`, a user's `~/Library/LaunchAgents`, `/etc/periodic`, and
> `/etc/emond.d` — is `not_checked`: this plugin has not asked anything
> about that file's signature. A future PR wiring a real
> `SecStaticCodeCheckValidity` call adds new `signed` values; it does not
> repurpose `apple_system`/`not_checked` to mean something they do not
> today (`autoruns_parsers.hpp`'s own `Signed` enum doc comment is the
> source of truth this text summarizes).

## Notes for the integrator

- No hotspot edits from this package — P11's `integration-autoruns.md`
  already covers every shared file (`meson.build`, `tests/meson.build`,
  `server.cpp`, the Python capability-catalogue tests). This package's only
  wiring dependency is `agents/plugins/autoruns/meson.build`'s existing
  `elif host_machine.system() == 'darwin'` branch already naming
  `src/autoruns_macos.cpp` (present in the base tree since P11 authored that
  meson file) — no meson edit needed for this leg to build once the file
  exists.
- `tests/meson.build`'s `sources` list currently wires only
  `unit/test_autoruns_parsers.cpp` (its own comment: "dispatcher test lands
  with the OS legs") — `unit/test_autoruns_local_dispatcher.cpp` (P11's file,
  already in the tree) and this package's
  `unit/test_autoruns_macos_local.cpp` both still need adding at this
  integration point. The `../agents/plugins/autoruns/src` include dir
  (line 475) and `CoreFoundation` framework dependency (line ~83, already
  present for the IOKit/`ScopedIOObject` vectors) both already cover these
  two new files — no new include dir or dependency line needed, only the two
  `sources` entries.
- No new include dir is needed for `ScopedCFRef`
  (`agents/core/include/yuzu/agent/scoped_cfref.hpp`) either: it resolves
  through `yuzu_agent_core_dep` (agents/core/meson.build's own
  `include_directories('include')`), which `agent_test_exe` already links
  (`tests/meson.build:534`) — not through a `tests/meson.build`
  `include_directories()` line naming `agents/core/include` directly (no
  such line exists in the unit-test target's own list; `tests/meson.build:
  479` is `../agents/core/src`, for `dex_event.hpp`, an unrelated header).

## 4. Enablement gap: RunAtLoad/KeepAlive/Start* are not modelled

The objective's enablement rule — "RunAtLoad/KeepAlive/Start* present ->
enabled; none -> unmodelled" — is not reachable as written. `LaunchdFields`
(`autoruns_parsers.hpp`, P11, outside this package's `owned_files`) carries
no members for those four keys, so `launchd_row_from_fields` always falls
back to `Enabled::enabled` when `Disabled` is absent, regardless of whether
RunAtLoad/KeepAlive/Start* are present — the `unmodelled` branch this leg's
objective describes can never fire. `autoruns_macos.hpp`'s own SCOPE NOTE
above `plist_to_launchd_fields` documents this at the code site; it is
repeated here because it is exactly the kind of gap that is easy to miss at
integration time. Whoever next touches `LaunchdFields` (P11/P15) should
either add the four members (and update `launchd_row_from_fields`'s
enablement branch to use them) or explicitly accept the current
`Disabled`-only rule as final — `tests/unit/test_autoruns_macos_local.cpp`
pins today's actual fallback (a plist with none of the four keys still
reports `enabled`, not `unmodelled`) so a change either way shows up as a
deliberate test edit, not a silent behavior drift.
