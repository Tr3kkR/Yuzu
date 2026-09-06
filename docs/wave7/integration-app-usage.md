# Integration: app_usage plugin (P22)

Hotspot edits this package does NOT make (boundaries: root meson.build,
tests/meson.build, server.cpp, python tests are out of scope for the
engineer) — verbatim lines for the integrator to splice in, each modeled
directly on `power_health`'s existing wiring.

## 1. Root `meson.build` — new subdir line

Alongside the existing `subdir('agents/plugins/power_health')` (line 473):

```meson
subdir('agents/plugins/app_usage')
```

## 2. `tests/meson.build`

**Sources** (alongside the `test_power_health_*` pair, ~line 454-457):

```meson
    'unit/test_app_usage_parsers.cpp',           # P22: pure sqlite seam (app_usage_parsers.hpp),
                                                # :memory: fixture db, no OS calls
    'unit/test_app_usage_local_dispatcher.cpp',  # P22: real app_usage dylib/.so/.dll via
                                                # LocalDispatcher, UNGUARDED (no init()) — proves
                                                # execute() alone resolves a sane tar.db path
```

**Include dir** (alongside `power_health/src`, ~line 466):

```meson
    include_directories('../agents/plugins/app_usage/src'),  # app_usage_parsers.hpp (pure helpers)
```

This package's `verification` field also needs `sqlite3_dep` on the syntax
check / standalone Catch2 build — already a dependency of `agent_test_exe`
(tests/meson.build:521), so no new dependency line is needed for the real
build.

**link_depends** (alongside `power_health_plugin_lib`, ~line 593):

```meson
                app_usage_plugin_lib,
```

so `test_app_usage_local_dispatcher.cpp`'s `PluginHandle::load()` never
races the plugin's own build.

## 3. `server/core/src/server.cpp`

**Include** (alongside the `plugin_action_catalogue_power_health.hpp`
include, line 137):

```cpp
#include "capability_decls/plugin_action_catalogue_app_usage.hpp"
```

**Composition line** (alongside the `plugin_action_catalogue_power_health()`
call site, line 22416 — wherever the live `CommandCapabilityRegistry` is
composed):

```cpp
        yuzu::server::capdecls::plugin_action_catalogue_app_usage(),
```

## 4. `tests/unit/server/test_real_capability_registry.hpp`

Include (alongside line 31) and composition-list entry (alongside line 51):

```cpp
#include "capability_decls/plugin_action_catalogue_app_usage.hpp"
```

```cpp
        capdecls::plugin_action_catalogue_app_usage(),
```

## 5. `tests/unit/server/test_capability_catalogue.cpp`

Include (alongside line 28):

```cpp
#include "capability_decls/plugin_action_catalogue_app_usage.hpp"
```

`all_labeled_sources()` entry (alongside the `power_health` row, line 118):

```cpp
        {"app_usage", capdecls::plugin_action_catalogue_app_usage(), false},
```

`build_registry()` entry (alongside line 136 — the source count in that
function's comment, currently "eight sources", becomes "nine sources"):

```cpp
        capdecls::plugin_action_catalogue_app_usage(),
```

Unlike `power_health` (which also gets a `power_health.set_power_plan`
Destructive-row expectation around line 180), `app_usage` has no mutating
action, so it needs no equivalent entry there.

## 6. `tests/unit/server/test_dispatch_destructive_gate.cpp`

Include (alongside line 45) and the two `CommandCapabilityRegistry`
construction sites (alongside lines 347 and 394):

```cpp
#include "capability_decls/plugin_action_catalogue_app_usage.hpp"
```

```cpp
        capdecls::plugin_action_catalogue_app_usage(),
```

All three of `app_usage`'s rows are ReadOnly/None, so — unlike
`power_health`'s `set_power_plan` — this package adds no new Destructive
row to either registry's expected row-count comment beyond the plain
addition of 3 ReadOnly rows; update whichever running total that file
tracks by +3.

## 7. Python capability-catalogue tests

`tests/test_capability_catalogue_complete.py`'s `FRAGMENT_FILES` list
(alongside line 80):

```python
    "server/core/src/capability_decls/plugin_action_catalogue_app_usage.hpp",
```

`tests/test_capability_gate_consistency.py` carries the same
`FRAGMENT_FILES` list shape — add the identical line there too.

## 8. `deploy/packaging/windows/yuzu-agent.iss`

Alongside the `power_health.dll` `Source:` line (line 85):

```iss
Source: "{#BuildDir}\agents\plugins\app_usage\app_usage.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
```

## Notes for the integrator

- `test_capability_catalogue`'s `kSeededSecurableTypes` check (P0's
  responsibility) is what validates that this fragment's `"Forensics"`
  literal matches P0's seeded `rbac_store.cpp` entry byte-for-byte — that
  check can only pass once P0 has landed in the integration branch.
- `agents/plugins/tar/src/tar_usage.hpp` (P21, wave 2) is NOT a build
  dependency of this package — `app_usage_parsers.hpp` deliberately
  duplicates its `normalise_exe_key()` rule rather than including the
  header, since P21 and P22 have no `depends_on` relationship. If P21's
  rule ever changes, `test_app_usage_parsers.cpp`'s 10-input parity suite
  is what will need updating to match — there is no shared code that
  updates itself.
- `usage_daily` / `usage_daily_user` / `usage_live` (P21's tables) do not
  need to exist in the tree for this package's own verification: the
  parser tests build their own `:memory:` fixture schema, and the
  dispatcher test's `constrained|tar_db_unavailable` branch is exercised
  on any host with no live tar.db (every CI runner today). The
  `meta|`/`usage|` success branch only exercises for real once a host
  runs both `tar` (P21 folding data into `usage_daily`) and `app_usage`
  against the same `<data_dir>/tar.db`.
