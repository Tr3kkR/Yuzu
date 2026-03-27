# Contributing to Yuzu

## Getting Started

1. **Prerequisites**: Meson 1.9.2, Ninja, CMake, a C++23 compiler, and vcpkg. See [CLAUDE.md](CLAUDE.md) for full build instructions.
2. **Clone and build**:
   ```bash
   git clone https://github.com/Tr3kkR/Yuzu.git && cd Yuzu
   ./scripts/setup.sh
   meson compile -C builddir
   ```

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for how components interact.

See [`docs/roadmap.md`](docs/roadmap.md) for the development plan.

See [`docs/capability-map.md`](docs/capability-map.md) for the target feature set.

## Branch Naming

- `feature/<short-description>` for new functionality
- `fix/<short-description>` for bug fixes
- `fix/<finding-id>-<short-description>` for RC sprint findings (e.g., `fix/C1-gateway-tls`)

Branch from `main`. Keep branches focused on a single change.

## Erlang Gateway

The gateway (`gateway/`) is a standalone rebar3 project using Erlang/OTP. See `docs/erlang-gateway-blueprint.md` for the architecture.

- Run EUnit tests: `cd gateway && rebar3 eunit`
- Run Common Test: `cd gateway && rebar3 ct --dir apps/yuzu_gw/test`
- Always pass `--dir apps/yuzu_gw/test` with `--suite` flags
- Review all Erlang changes with the erlang-dev agent (`.claude/agents/erlang-dev.md`)

## MCP Server

The MCP server is embedded in the C++ server at `POST /mcp/v1/`. Changes to MCP tools, resources, or prompts are in `server/core/src/mcp_server.hpp` / `mcp_server.cpp`. Tests are in `tests/unit/server/test_mcp_server.cpp`.

## Governance

All code changes follow mandatory governance gates defined in `CLAUDE.md`. In summary: change summary, security + docs deep-dive, domain-triggered review, correctness & resilience analysis (happy-path + unhappy-path + consistency-auditor in parallel), chaos analysis (chaos-injector), all findings addressed before merge. See the Agent Team section in CLAUDE.md for the full workflow and gate definitions.

## Pull Request Process

1. Ensure CI passes (builds on Linux, Windows, macOS, ARM64)
2. Run `clang-tidy` locally against changed files (the repo `.clang-tidy` config is picked up automatically)
3. Write a clear PR title and description using the PR template
4. Keep PRs small where possible; large features should be broken into incremental PRs

## Coding Standards

The project follows C++23 conventions enforced by `.clang-tidy`:

- **Naming**: PascalCase classes, snake_case functions/variables, `k`-prefix constants, trailing `_` for private members
- **Error handling**: Use `std::expected<T, E>` — no exceptions in core code
- **Includes**: `#pragma once`, ordered STL → third-party → project
- **Strings**: Prefer `std::string_view` for parameters, `std::format` for formatting
- **Memory**: No raw `new`/`delete`; use smart pointers and RAII

See [CLAUDE.md](CLAUDE.md) for the complete coding conventions.

## Observability Standards

When adding new features:

- **Metrics**: Use Prometheus naming (`yuzu_server_*` / `yuzu_agent_*`) with consistent labels (`agent_id`, `plugin`, `method`, `status`)
- **Response schemas**: All instruction responses must declare typed columns (bool, int32, int64, string, datetime) for downstream analytics
- **Audit events**: Use the structured format: `{timestamp, principal, action, target_type, target_id, detail}`
- **Events**: Follow the common envelope: `{event_type, timestamp, source, payload}`

## Writing Plugins

Plugins use a stable C ABI (`sdk/include/yuzu/plugin.h`) with a C++ wrapper (`sdk/include/yuzu/plugin.hpp`).

1. Copy `agents/plugins/example/` as a starting point
2. Implement your plugin class using the `YUZU_PLUGIN_EXPORT` macro
3. Add a `meson.build` that builds a shared library
4. Register your plugin directory in the parent `meson.build`

See the existing plugins for patterns.

## Running Tests

```bash
./scripts/setup.sh --tests
meson test -C builddir --print-errorlogs
```

Tests use [Catch2](https://github.com/catchorg/Catch2) and live in `tests/unit/`.

## Build System

Meson is the sole build system. **Every time you add, remove, or rename a source file, update `meson.build` in the affected directory.** Do not use CMake as a build system (it exists only as a Meson dependency method).
