# autoruns integration checklist (P11)

P11 owns the plugin skeleton, catalog, parsers, fragment, content definition
and tests. It does NOT own any "hotspot" file — every edit below is for
IT-WIRING to apply once P11's files (and P12/P13/P14's per-OS leg TUs) are
merged into the integration tree. Every line is quoted verbatim from the
sibling plugin (`disk_actions` / `filesystem_posture` / `power_health`) this
plugin's own shape was modelled on, so the same edit pattern applies with
`autoruns` substituted for the sibling's name.

## 1. Root `meson.build` — plugin subdir

Add, in the `agents/plugins/*` subdir block (alongside `disk_actions`):

```meson
    subdir('agents/plugins/autoruns')
```

(precedent: `meson.build:443: subdir('agents/plugins/disk_actions')`)

## 2. `tests/meson.build` — sources, include_directories, link_depends

Three separate edits, each a single appended line (one-per-line, to survive a
line-based merge — see the file's own comment above `link_depends` about
"non-conflicting inserts... two independent appends land as two independent
inserted lines").

**a. `sources` list** (near `test_disk_actions_local_dispatcher.cpp`):

```meson
    'unit/test_autoruns_parsers.cpp',
    'unit/test_autoruns_local_dispatcher.cpp', # Wave 7 PR11: real autoruns dylib/.so/.dll
```

**b. `include_directories`** (pure-header include for
`autoruns_parsers.hpp`/`autoruns_catalog.hpp`, alongside
`../agents/plugins/disk_actions/src`):

```meson
    include_directories('../agents/plugins/autoruns/src'), # autoruns_parsers.hpp / autoruns_catalog.hpp (pure helpers)
```

**c. `link_depends`** (alongside `disk_actions_plugin_lib`):

```meson
                autoruns_plugin_lib,
```

**d. `YUZU_TEST_FIXTURE_DIR` — already wired.** No edit needed: the define
(`tests/meson.build` around line 516,
`'-DYUZU_TEST_FIXTURE_DIR="' + (meson.project_source_root() / 'tests' / 'unit' / 'fixtures').replace('\\', '/') + '"'`)
was added ahead of this package and both autoruns test files use it directly.

## 3. `server/core/src/server.cpp` — capability fragment include + composition

```cpp
#include "capability_decls/plugin_action_catalogue_autoruns.hpp"
```

(precedent: `server.cpp:135: #include "capability_decls/plugin_action_catalogue_disk_actions.hpp"`)

```cpp
        yuzu::server::capdecls::plugin_action_catalogue_autoruns(),
```

(precedent: `server.cpp:22441: yuzu::server::capdecls::plugin_action_catalogue_disk_actions(),`)

## 4. Test/py registries (four files)

**a. `tests/test_capability_catalogue_complete.py`** — `FRAGMENT_FILES` list
and the module docstring's file-list sentence both need
`plugin_action_catalogue_autoruns.hpp` appended, alongside
`plugin_action_catalogue_disk_actions.hpp`. Nothing else needs editing here:
`parse_plugin_actions` globs `agents/plugins/*/src/*.cpp` and discovers
`autoruns`'s `actions()` override automatically.

**b. `tests/test_capability_gate_consistency.py`** — same `FRAGMENT_FILES`
append, plus `EXPECTED_TOTAL_ROWS` (currently 196, comment: "Wave 7 wave-1:
+3 app_usage...; autoruns +2 and execution_artifacts +3 follow in later
waves") becomes `198` (+2 for `autoruns.list` / `autoruns.catalog`), with the
comment's "follow in later waves" clause for autoruns removed since it has
now landed.

**c. `tests/unit/test_new_plugins.cpp`** — append a `DESCRIPTOR_TEST` row
alongside the `disk_actions` / `filesystem_posture` ones:

```cpp
DESCRIPTOR_TEST("autoruns", "autoruns", 2, "list", "catalog")
```

**d. `tests/meson.build`** — covered in section 2 above (sources /
include_directories / link_depends are the fourth registry-shaped hotspot
this plugin touches in that file).

## 5. `deploy/packaging/windows/yuzu-agent.iss`

```
Source: "{#BuildDir}\agents\plugins\autoruns\autoruns.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
```

(precedent: `yuzu-agent.iss:79`, the `disk_actions.dll` row — same
`Components: plugins\system` group, no [InstallDelete] concern since this is
a new plugin, not a retirement.)

## 6. `scripts/dev/check-windows-tu-syntax.sh`

Add the Windows leg TU (P12's `autoruns_win.cpp`) once it exists:

```
    agents/plugins/autoruns/src/autoruns_win.cpp
```

(precedent: `check-windows-tu-syntax.sh:54: agents/plugins/disk_actions/src/disk_actions_win.cpp`)

## Verification the integrator should run

```
meson compile -C build-macos autoruns_plugin_lib
meson test -C build-macos --suite server -- [autoruns]
```

(P11's own scoped syntax checks and standalone Catch2 pure-logic run are in
the structured summary's `evidence`; the above needs the full multi-package
merge — P12/P13/P14's leg TUs plus this checklist's hotspot edits — and the
shared build lock per the run context.)
