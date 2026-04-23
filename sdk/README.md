# Yuzu Plugin SDK

Public, ABI-stable C interface plus a thin C++23 wrapper for writing
plugins that load into the Yuzu agent at runtime.

## Contents

| File | Purpose |
|------|---------|
| `include/yuzu/plugin.h` | Stable C ABI — the only supported boundary for third-party plugin authors |
| `include/yuzu/plugin.hpp` | C++23 convenience wrapper (inline, header-only) |
| `include/yuzu/sdk.hpp` | Common helpers (JSON, logging, metrics, secure-zero, string utilities) |

## ABI compatibility

The C ABI advertises a version macro (`YUZU_PLUGIN_ABI_VERSION`). The
agent refuses to load plugins whose declared version is below
`YUZU_PLUGIN_ABI_VERSION_MIN`. Breaking ABI changes require bumping
the major version and are reviewed by the `architect` agent before
landing.

## License

The Yuzu agent and server are licensed under AGPL-3.0-or-later (see
top-level [`LICENSE`](../LICENSE)). The Plugin SDK carries an
**additional permission** — an AGPL linking exception — that allows
plugins to be distributed under any license (including proprietary
ones) provided they consume only the stable C ABI defined here and do
not statically link any Yuzu implementation code.

**Read the exception in full** before shipping a proprietary plugin:
[`LICENSE-SDK.md`](LICENSE-SDK.md).

## How to write a plugin

See the worked example under `agents/plugins/example/` and the author
guide in `docs/plugin-author-guide.md` (if present). In short:

1. Copy `agents/plugins/example/` as a starting point.
2. Implement your plugin class using the `YUZU_PLUGIN_EXPORT` macro
   from `plugin.hpp`.
3. Add a `meson.build` that produces a shared library.
4. Register the plugin directory in `agents/plugins/meson.build` (or
   distribute your plugin independently and drop it into the agent's
   plugin directory at runtime).

The `plugin-developer` agent (`.claude/agents/plugin-developer.md`)
reviews any change that touches the SDK or adds a plugin.
