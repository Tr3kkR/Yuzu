# Yuzu — OpenAI Codex Guide

## Project Overview

Yuzu is an enterprise endpoint management platform written in C++23. It consists of a server that manages a fleet of agents installed on Windows, Linux, and macOS endpoints. Agents load plugins (shared libraries) to collect data and execute actions. Communication is via gRPC/Protobuf with mTLS.

The goal is to build a complete endpoint management platform — real-time querying, command orchestration, desired-state compliance, security response, and observability — competitive with commercial products.

## Architecture

- **Server** (`server/core/`): gRPC service + HTMX web dashboard + REST API v1 (70+ endpoints). Manages agent sessions, dispatches commands, stores responses, evaluates policies, handles auth/RBAC. Includes MCP (Model Context Protocol) server for AI integration.
- **Agent** (`agents/core/`): Connects to server via gRPC. Loads plugins from a directory. Executes commands. Reports inventory. Evaluates local policy rules via trigger engine. KV storage, content staging, desktop interaction.
- **Plugins** (`agents/plugins/*/`): 44 shared-library plugins with a stable C ABI (`sdk/include/yuzu/plugin.h`). Covers hardware, network, security, filesystem, registry, WMI, processes, services, and more.
- **Gateway** (`gateway/`): Erlang/OTP gateway node with process-per-agent supervision, heartbeat batching, consistent hash ring, and Prometheus metrics.
- **Proto** (`proto/`): Protobuf definitions are the source of truth for the wire protocol. Three services: AgentService, ManagementService, GatewayUpstream.
- **SDK** (`sdk/`): Stable C ABI in `plugin.h`, ergonomic C++23 wrapper in `plugin.hpp` using CRTP.

## Build System

**Meson only.** CMake exists only as a dependency method for Meson.

```bash
# Linux/macOS
./scripts/setup.sh
meson compile -C builddir

# Windows (MSYS2 bash)
source ./setup_msvc_env.sh
meson compile -C builddir
```

When adding/removing source files, update `meson.build` in the affected directory.

## Language and Style

- **C++23**: Use `std::expected<T, E>` (not exceptions), `std::span`, `std::string_view`, `std::format`, ranges.
- **Naming**: PascalCase classes, snake_case functions/variables, `k`-prefix constants, trailing `_` for private members.
- **Namespaces**: `yuzu::`, `yuzu::agent::`, `yuzu::server::`.
- **Headers**: `#pragma once`. Order: STL → third-party → project.
- **No raw new/delete**: Use smart pointers and RAII.
- **Plugin ABI**: The C API in `plugin.h` must remain stable. Never break the C boundary.

## Key Dependencies

- gRPC + Protobuf (transport)
- cpp-httplib (HTTP server for dashboard/REST)
- spdlog (logging)
- CLI11 (argument parsing)
- nlohmann/json (JSON handling)
- SQLite (embedded storage)
- Catch2 (testing)
- vcpkg (package management, manifest mode)

## Development Roadmap

The project follows a phased roadmap (`docs/roadmap.md`) with 72 GitHub issues across 7 phases (all complete):

1. **Phase 0**: Foundation — HTTPS, OTA agent updates, SDK utilities
2. **Phase 1**: Server data infrastructure — response store, audit, tags, scope engine
3. **Phase 2**: Instruction system — definitions, scheduling, approvals, workflows
4. **Phase 3**: Security & RBAC — granular permissions, management groups, OIDC, REST API
5. **Phase 4**: Agent infrastructure — KV storage, triggers, content distribution
6. **Phase 5**: Policy engine — desired-state rules, compliance dashboard
7. **Phase 6**: Windows depth — registry, WMI, per-user operations
8. **Phase 7**: Scale & integration — gateway nodes, health monitoring, patches, webhooks

## Observability

All metrics are Prometheus-compatible with `yuzu_` prefix and consistent labels. Design all data schemas (responses, audit, inventory) to be easily consumed by ClickHouse, Splunk, or Grafana:

- Response data is typed (bool, int32, int64, string, datetime)
- Audit events are structured JSON
- Events follow a common envelope: `{event_type, timestamp, source, payload}`

## Working in This Repo

- Check `docs/roadmap.md` for the current plan and issue dependencies
- Check `docs/capability-map.md` for the target feature set (142 capabilities, 96 done)
- Check `docs/architecture.md` for component interaction details
- Run `meson compile -C builddir` to verify changes compile
- Run `meson test -C builddir` to run tests (requires `-Dbuild_tests=true`)
- On Windows, always `source ./setup_msvc_env.sh` before building
- Do not use `vcvars64.bat` — it fails due to extension errors
