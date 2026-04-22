# C++ Coding Conventions — Yuzu

The `cpp-expert` agent loads this document on any C++ source change. CLAUDE.md keeps a one-line pointer.

## Language

- **C++23 throughout.** Use `std::expected<T, E>` for errors, `std::span` for contiguous ranges, `std::string_view` for non-owning string refs, `std::format` for string formatting.
- Cross-compiler matrix: GCC 13+, Clang 18+, MSVC 19.38+, Apple Clang 15+. See `docs/ci-cpp23-troubleshooting.md` for known feature divergences.

## Naming

- Namespaces: `yuzu::`, `yuzu::agent::`, `yuzu::server::`.
- PascalCase for classes, snake_case for variables and functions.
- `k`-prefix for constants (`kMaxRetries`).
- Trailing `_` for private members (`db_`, `mtx_`).

## Headers

- `#pragma once` only — no include guards.
- Include order: STL → third-party → project.

## Plugin ABI

- The C API in `sdk/include/yuzu/plugin.h` must stay stable. No C++ types cross the boundary — only `const char*`, fixed-size arrays, and C enums.
- C++ ergonomics live in `plugin.hpp` (CRTP + `YUZU_PLUGIN_EXPORT` macro). Don't break the C boundary when extending the C++ wrapper.
- `YUZU_PLUGIN_ABI_VERSION` increments on any layout change with a migration plan (architect agent gates this).

### Reserved plugin names

The agent reserves a small namespace of plugin names for internal dispatch intercepts. Any plugin declaring one of these names in `YuzuPluginDescriptor::name` is **rejected at load time** by `PluginLoader::scan` (see `agents/core/include/yuzu/agent/plugin_loader.hpp` `kReservedPluginNames`) — the rejection is logged at `error` and counted in `yuzu_agent_plugin_rejected_total{reason="reserved_name"}`.

| Name          | Purpose                                                            |
|---------------|--------------------------------------------------------------------|
| `__guard__`   | Guardian engine dispatch (see `docs/yuzu-guardian-design-v1.1.md` §7.2) |
| `__system__`  | Reserved for future system-scope commands                          |
| `__update__`  | Reserved for OTA update commands                                   |

Do not pick names matching `__*__` for third-party plugins; treat the double-underscore-bracketed convention as the internal-dispatch namespace and avoid it entirely. Adding a new reserved name requires updating `kReservedPluginNames` and the unit test in `tests/unit/test_plugin_loader.cpp` that pins the exact set.

## Entry points

Both the agent and the server use:

- **CLI11** for argument parsing.
- **spdlog** for structured logging.
- A `Factory::create(config)->run()` pattern with SIGINT/SIGTERM handlers.

## Visibility

- `-fvisibility=hidden` is set globally.
- Use `YUZU_EXPORT` to expose symbols intentionally.

## Concurrency

- `mutable std::shared_mutex mtx_` for SQLite-backed stores.
- `std::atomic` for stop flags and counters.
- `std::unique_lock` / `std::shared_lock` pairing — never bare `lock()/unlock()` calls.
- SQLite stores use `sqlite3_open_v2(... SQLITE_OPEN_FULLMUTEX ...)` AND application-level mutexes — see `docs/darwin-compat.md` for why the application-level mutex is mandatory, not optional.

## Forbidden in new code

- Raw error codes or output parameters (use `std::expected`).
- printf-family calls (use `std::format` or spdlog).
- Raw `new`/`delete` (use RAII).
- Manual resource cleanup (use RAII / smart pointers).
- C++ types crossing the C ABI boundary in `plugin.h`.
