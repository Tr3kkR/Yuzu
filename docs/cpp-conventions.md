# C++ Coding Conventions — Yuzu

The `cpp-expert` and `cpp-safety` agents load this document on any C++ source change. CLAUDE.md keeps a one-line pointer.

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

## Windows string conversion

- A Windows plugin needing wide↔UTF-8 conversion must use the shared header `agents/plugins/shared/win_str.hpp` (`yuzu::win::to_wide` / `from_wide` / `reg_sz_to_utf8`) rather than hand-rolling another `MultiByteToWideChar`/`WideCharToMultiByte` copy. It is header-only and `#ifdef _WIN32`-guarded, so build isolation is preserved (each plugin compiles its own inline copy). Add `include_directories('../shared')` to the plugin's `meson.build`. Registry **string** reads must go through the wide `Reg*W` APIs (#1662/#1682) — see the ADR-0016 routed-concern row in `CLAUDE.md`. (Agent-core code outside `agents/plugins/` cannot reach this header and keeps its own copies pending a separate consolidation.)

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

## Resource ownership and lifetime

Governance is stricter than style guidance: every C++ diff must prove ownership for each resource boundary it adds or touches. The Gate 1 Resource Ledger names the owner type, acquisition point, release point, transfer behavior, and failure cleanup for every fd, HANDLE, SOCKET, `FILE*`, `sqlite3_stmt*`, `sqlite3*`, OpenSSL object, BCrypt handle, allocated C string, mapped library, temp path, subprocess, callback context, and thread.

New or touched C++ code should use a small RAII owner, `std::unique_ptr` with a deleter, or a local scope guard. Manual cleanup is a governance finding unless the code documents why a wrapper is impossible or would be less safe. Check every early return between acquisition and release.

Resource owner types must be non-copyable when copying would double-release. Prefer move-only wrappers with explicit transfer semantics; any use of `release()` must immediately hand the resource to another named owner.

Borrowed data is allowed only when its source lifetime is obvious at the call site. Do not store `std::string_view`, `std::span`, raw plugin contexts, or callback user data beyond the lifetime of the object they view. If a C ABI trampoline stores or returns a pointer, document who owns the context and who frees output strings.

Shell/process boundaries must prefer argv-style execution. New `system()`, `popen()`, shell strings, `fork`/`exec`, and `CreateProcess` sites require explicit validation and a documented exception when a shell is unavoidable.

Casts at ABI or syscall boundaries need a local aliasing/lifetime proof. `reinterpret_cast` and `const_cast` sites should explain alignment, constness, and ownership assumptions unless they are isolated behind an already-reviewed wrapper.

Safety-sensitive ownership changes need targeted validation. Use ASan/UBSan when memory/resource ownership changes, TSan when thread lifetime, callback ownership, shared state, or store locking changes, and platform-specific tests for Windows HANDLE/service code or POSIX fd/socket/process code.

## Static-asset translation units

Two patterns coexist for embedding static front-end assets in the server binary; they are not interchangeable.

### Pattern A — hand-written TU

Use for assets we author in this repo (page HTML shells, small bespoke JS modules, hand-curated bundle code).

- Single namespace-scope `extern const std::string` (or `extern const char* const` for HTML strings) declared in the consuming TU and defined in its own `.cpp` (e.g. `viz_page_ui.cpp`, `tar_page_ui.cpp`, `yuzu_viz_js_bundle.cpp`, `charts_js_bundle.cpp`).
- Source code is the authoritative form; raw-string literal embeds the body verbatim.
- Stay under MSVC's 16,380-byte raw-string-literal limit (C2026); chunk by hand or migrate to Pattern B once growth approaches the limit.
- Test tags in `tests/unit/server/test_static_js_bundle.cpp` follow the surface they describe, not the TU pattern: `[viz][page]` / `[viz][routes]` for the HTML pages and routes, `[static-js][viz]` / `[static-js][three]` / `[static-js][htmx]` for JS bundles.

### Pattern B — codegen TU

Use for vendored assets (Three.js r168, ECharts, Inter typeface, htmx bundles large enough that hand-chunking is tedious).

- Source file lives in `server/core/vendor/` (text) or `server/core/vendor/<asset>/` (binary).
- `meson.build` declares a `custom_target` that invokes `server/core/scripts/embed_js.py` (text) or `embed_binary.py` (binary). The script chunks input bytes into raw-string fragments and concatenates them at static-init time so MSVC's per-literal 16,380-byte limit cannot be hit.
- Generated symbol is `kFooJs` for input symbol `FooJs` (the script prepends `k`).
- Pair every vendored asset with a `<asset>-NOTICE.txt` carrying licence + upstream URL + SPDX identifier + SHA-256 (recompute via `shasum -a 256 …`); the test suite pins the byte count, the NOTICE pins the hash, and a vendor refresh updates both in lock-step.
- Generated `.cpp` lands in `meson.build`'s `meson.current_build_dir()` and is added to the static library's source list as the custom-target object — do not commit the generated TU.

### Naming

- Symbols emitted by codegen drop the file suffix (`kThreeJs`, not `kThreeMinifiedJs`). For asset families with multiple files, name the second symbol after the upstream class or module so the link is unambiguous (`kThreeOrbitControlsJs`, not `kThreeOrbitJs`). Rename history is gated on the same architectural review as any other ABI-shaped symbol change.

## Forbidden in new code

- Raw error codes or output parameters (use `std::expected`).
- printf-family calls (use `std::format` or spdlog).
- Raw `new`/`delete` (use RAII).
- Manual resource cleanup (use RAII / smart pointers).
- C++ types crossing the C ABI boundary in `plugin.h`.
- Borrowed `std::string_view`, `std::span`, raw pointer, or callback context escaping its owner.
- Shell command construction when argv-style execution is feasible.
