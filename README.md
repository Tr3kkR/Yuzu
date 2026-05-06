# Yuzu

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Tr3kkR/Yuzu/badge)](https://scorecard.dev/viewer/?uri=github.com/Tr3kkR/Yuzu)
<!-- OpenSSF Best Practices Badge: application in progress (issue #407). Once approved, replace <ID> with the project id from bestpractices.dev. -->
<!-- [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<ID>/badge)](https://www.bestpractices.dev/projects/<ID>) -->
[![Zizmor](https://github.com/Tr3kkR/Yuzu/actions/workflows/zizmor.yml/badge.svg?branch=main)](https://github.com/Tr3kkR/Yuzu/actions/workflows/zizmor.yml)

**Enterprise endpoint management platform.** Real-time visibility, orchestration, and compliance across Windows, Linux, and macOS fleets — built from the ground up in modern C++23.

Yuzu gives operations and security teams a single control plane to query, command, patch, and enforce policy on every managed endpoint in real time. Agents are lightweight, plugin-extensible, and report structured telemetry that is natively compatible with Prometheus, Grafana, ClickHouse, and Splunk.

## What Yuzu Does

- **Real-time querying** — Ask questions ("which machines are missing patch KB5034441?") and get streaming answers from thousands of endpoints in seconds.
- **Command orchestration** — Dispatch actions (restart a service, kill a process, deploy a package) to one device or an entire fleet, with approval workflows and scheduling.
- **Continuous compliance** — Define desired-state policies ("BitLocker must be enabled") that agents evaluate locally on triggers (file change, service crash, interval) and auto-remediate.
- **Security response** — Quarantine compromised devices, check indicators of compromise, inventory certificates, and collect forensic data.
- **Plugin extensibility** — A stable C ABI means plugins can be written in any language that produces a shared library. 44 plugins ship out of the box covering hardware, network, security, software, and more.
- **AI integration** — An embedded MCP (Model Context Protocol) server exposes 23 tools for AI-driven fleet querying, compliance reporting, and supervised command execution.

## Instruction Engine

Every operation in Yuzu flows through the **instruction engine** — a governed lifecycle that transforms ad-hoc commands into reusable, versioned, auditable definitions.

**Content model:**

```
ProductPack                    (signed distribution bundle)
 └── InstructionSet            (permission boundary, grouping)
      └── InstructionDefinition (reusable operation template)
           ├── Parameter Schema (typed inputs with validation)
           ├── Result Schema    (typed output columns)
           └── Execution Spec   (plugin + action + defaults)
```

**How it works:**

1. **Author** an InstructionDefinition in YAML — declare the plugin, action, typed parameters, result columns, approval mode, and platform compatibility.
2. **Import** it via the dashboard or REST API. The server validates the schema and stores the YAML verbatim alongside denormalized columns for efficient queries.
3. **Execute** the definition against a scope expression (`ostype == "windows" AND tag:env == "production"`). The engine validates parameters, checks approvals, dispatches via gRPC, and tracks per-agent progress.
4. **Analyze** results using typed aggregation, filtering, and CSV/JSON export.
5. **Schedule** recurring executions with cron-style frequency and scope-based targeting.

Definitions are `question` (read-only, auto-approved) or `action` (may modify state, approval-gated). Every execution is audited, every response is persisted, and every state-changing action can require approval.

See [`docs/Instruction-Engine.md`](docs/Instruction-Engine.md) for the full architecture, [`docs/yaml-dsl-spec.md`](docs/yaml-dsl-spec.md) for the YAML specification, and [`docs/getting-started.md`](docs/getting-started.md) for a hands-on tutorial.

## Architecture

```
                        ┌──────────────────────────────────────────────────────────┐
                        │                      Yuzu Server                          │
                        │                                                          │
  Operators ──────────► │  ┌────────────┐  ┌─────────────┐  ┌──────────────────┐  │
  (Browser / API)       │  │  REST API  │  │  Instruction │  │  Policy Engine   │  │
                        │  │  (v1)      │  │  Engine      │  │  (Guaranteed     │  │
                        │  └────────────┘  └─────────────┘  │   State)         │  │
                        │  ┌────────────┐  ┌─────────────┐  └──────────────────┘  │
                        │  │  HTMX      │  │  Response    │  ┌──────────────────┐  │
                        │  │  Dashboard │  │  Store       │  │  RBAC / Auth     │  │
                        │  └────────────┘  │  (SQLite)    │  │  OIDC · API Keys │  │
                        │  ┌────────────┐  └─────────────┘  └──────────────────┘  │
                        │  │  Metrics   │  ┌─────────────┐  ┌──────────────────┐  │
  Prometheus ◄───────── │  │  /metrics  │  │  Audit Log  │  │  Scheduler       │  │
  Grafana               │  └────────────┘  └─────────────┘  └──────────────────┘  │
                        │                                                          │
                        └────────────────────────┬─────────────────────────────────┘
                                                 │
                              gRPC / Protobuf / mTLS (bidirectional streaming)
                                                 │
           ┌─────────────────────────────────────┼──────────────────────────────────┐
           │                                     │                                  │
   ┌───────┴───────┐                   ┌─────────┴────────┐             ┌───────────┴──────┐
   │  Yuzu Agent   │                   │   Yuzu Agent     │             │   Yuzu Agent     │
   │  (Windows)    │                   │   (Linux)        │             │   (macOS)        │
   │               │                   │                  │             │                  │
   │  Plugin Host  │                   │  Plugin Host     │             │  Plugin Host     │
   │  Trigger Eng. │                   │  Trigger Eng.    │             │  Trigger Eng.    │
   │  KV Storage   │                   │  KV Storage      │             │  KV Storage      │
   │  Metrics      │                   │  Metrics         │             │  Metrics         │
   └───────────────┘                   └──────────────────┘             └──────────────────┘
```

### Optional: Gateway Nodes

For large or distributed deployments, gateway nodes sit between agents and the server to reduce WAN traffic, batch heartbeats, and provide local TLS termination.

```
  Agents ──► Gateway (branch office) ──► Server (datacenter)
```

## Observability and Integration

Yuzu is designed to be a first-class data source in modern observability stacks:

| Integration | How |
|---|---|
| **Prometheus** | `/metrics` endpoint on both server and agent. Counters, gauges, histograms with labels. Grafana-ready. |
| **Grafana** | Pre-built dashboard templates for fleet health, command throughput, policy compliance, and agent connectivity. |
| **ClickHouse** | Structured response data and inventory use columnar-friendly schemas (typed columns, timestamps, agent IDs). Feed via the REST API or response offloading webhooks. |
| **Splunk** | Audit logs and event subscriptions emit structured JSON. Agents can POST directly to Splunk HEC via the `http_client` plugin. |
| **Webhooks** | Event subscriptions push JSON payloads to any HTTP endpoint on agent lifecycle, policy compliance changes, and instruction completion. |

### Metrics Philosophy

Every metric follows the Prometheus naming convention (`yuzu_server_*`, `yuzu_agent_*`) with consistent labels (`agent_id`, `plugin`, `method`, `status`). This makes it trivial to build Grafana dashboards, set up alerting rules, or feed data into ClickHouse materialized views for long-term analysis.

Response data is typed (bool, int32, int64, string, datetime, CLOB) and schematized per instruction definition, making it straightforward to map into ClickHouse tables or Splunk sourcetypes for correlation workflows.

## Key Design Decisions

| Concern | Choice | Rationale |
|---|---|---|
| Language | C++23 | `std::expected`, ranges, `std::format`. Low memory footprint for agents on constrained endpoints. |
| Build | Meson + vcpkg | Fast builds, reproducible dependencies, cross-platform. CMake available as a dependency method only. |
| Transport | gRPC + Protobuf | Bidirectional streaming, strongly typed, TLS built-in, language-neutral. |
| Plugin ABI | Stable C ABI | Binary-stable across compiler versions. Language-agnostic. `dlopen`/`LoadLibrary` safe. |
| Web UI | HTMX + server-rendered HTML | No JavaScript framework. Server renders fragments. Minimal client complexity. |
| Storage | SQLite (embedded) | Zero-config, single-file, fast. Agent uses it for KV storage and identity. Server uses it for responses, audit, and config. |
| Auth | PBKDF2 + RBAC + OIDC | Session cookies for browsers, API tokens for automation, OIDC for enterprise SSO. |
| Platforms | Windows, Linux, macOS (ARM64), ARM | Enterprise + edge coverage. Cross-compiled from CI. macOS Intel (x64) is not currently built or tested — only Apple Silicon (ARM64) is supported. |

## Project Layout

```
Yuzu/
├── agents/core/              Agent daemon (gRPC client, plugin loader, trigger engine)
├── agents/plugins/           44 plugins (hardware, network, security, filesystem, etc.)
├── server/core/              Server daemon (sessions, auth, dashboard, REST API)
├── gateway/                  Erlang/OTP gateway node (standalone rebar3 project)
├── sdk/                      Public SDK — stable C ABI (plugin.h) + C++23 wrapper (plugin.hpp)
├── proto/                    Protobuf definitions (source of truth for wire protocol)
│   ├── yuzu/agent/v1/        AgentService: Register, Heartbeat, ExecuteCommand, Subscribe
│   ├── yuzu/common/v1/       Shared types: Platform, Timestamp, ErrorDetail
│   ├── yuzu/server/v1/       ManagementService: ListAgents, SendCommand, WatchEvents
│   └── yuzu/gateway/v1/      GatewayUpstream — server-side RPCs the Erlang gateway calls into
├── docs/                     Architecture and roadmap documentation
├── meson/                    Cross-compilation and native files
├── scripts/                  Build helpers (setup.sh, deploy_build_dlls.py)
├── tests/unit/               Catch2 unit tests
└── .github/workflows/        CI: Linux, Windows, macOS, ARM64 cross-compile
```

## Install

Prebuilt artifacts are published with every tagged release. If you just want to run Yuzu, start here — you do not need to build from source.

- **Release binaries & installers** (server/agent for Linux, Windows, macOS; Compose Wizard zip): [GitHub Releases](https://github.com/Tr3kkR/Yuzu/releases). Latest stable is v0.10.0; v0.11.0-rc1 is the most recent pre-release.
- **Container images** (published to GHCR on every tag):
  - `ghcr.io/tr3kkr/yuzu-server:<version>`
  - `ghcr.io/tr3kkr/yuzu-agent:<version>`
  - `ghcr.io/tr3kkr/yuzu-gateway:<version>`
- **Docker Compose** quickstart: [`deploy/docker/docker-compose.yml`](deploy/docker/docker-compose.yml) stands up the full server + gateway + agent stack. Reference wiring for UAT is [`deploy/docker/docker-compose.reference.yml`](deploy/docker/docker-compose.reference.yml).

```bash
# Pull and run the latest stable release via compose
curl -fsSL https://raw.githubusercontent.com/Tr3kkR/Yuzu/main/deploy/docker/docker-compose.yml -o docker-compose.yml
YUZU_VERSION=0.10.0 docker compose up -d
```

Open `http://localhost:8080` and sign in with the credentials set during first-run provisioning.

## Building

### Prerequisites

- Meson 1.9.2, Ninja
- CMake (required by Meson's cmake dependency method)
- C++23 compiler: GCC 13+, Clang 18+, MSVC 19.38+, or Apple Clang 15+
- [vcpkg](https://github.com/microsoft/vcpkg) with `VCPKG_ROOT` set
- Python 3 with **PyYAML** (`pip install pyyaml`, or `pacman -S python-yaml`
  on MSYS2). Required at `meson setup` for the build-time
  `InstructionDefinition` content embed; meson configure fails fast
  with a clear error if missing.

### Quick Start

```bash
./scripts/setup.sh                              # debug build
./scripts/setup.sh --buildtype release --lto    # release + LTO
./scripts/setup.sh --tests                      # enable unit tests
```

### Manual

```bash
vcpkg install --triplet x64-linux --x-manifest-root=.
meson setup builddir --buildtype=debug -Dcmake_prefix_path=$VCPKG_ROOT/installed/x64-linux
meson compile -C builddir
```

### Windows (MSYS2 bash)

```bash
source ./setup_msvc_env.sh
meson compile -C builddir
```

### Build Options

| Option | Default | Notes |
|---|---|---|
| `-Dbuild_agent` | true | Agent daemon |
| `-Dbuild_server` | true | Server daemon |
| `-Dbuild_tests` | false | Catch2 test suite |
| `-Dbuild_examples` | true | Example plugins |
| `-Db_lto` | false | Link-time optimisation |
| `-Db_sanitize=address,undefined` | — | ASan + UBSan |

## Writing a Plugin

Plugins are shared libraries (`.dll`/`.so`) exporting a C ABI descriptor. See [`sdk/include/yuzu/plugin.h`](sdk/include/yuzu/plugin.h) and [`agents/plugins/example/`](agents/plugins/example/).

```cpp
#include <yuzu/plugin.hpp>

class MyPlugin final : public yuzu::Plugin {
public:
    std::string_view name()    const noexcept override { return "my-plugin"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    // implement execute() to handle actions...
};

YUZU_PLUGIN_EXPORT(MyPlugin)
```

## Running

```bash
# Start the server
./builddir/server/core/yuzu-server --listen 0.0.0.0:50051 --web-port 8080

# Start an agent (connects to server)
./builddir/agents/core/yuzu-agent --server localhost:50051 --plugin-dir ./builddir/agents/plugins
```

Open `http://localhost:8080` for the web dashboard.

## Roadmap

See [`docs/roadmap.md`](docs/roadmap.md) for the full development roadmap organized into 7 phases, from foundation completion through policy engine, security, and scale-out architecture.

See [`docs/capability-map.md`](docs/capability-map.md) for the live capability inventory and progress.

## Contributing

Pull requests welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) — it covers the build, branch naming (`feature/*`, `fix/*`), the governance-gated PR workflow, C++23 coding standards, observability conventions, and the plugin SDK. Architectural and release context lives in [CLAUDE.md](CLAUDE.md).

Good first issues are labelled [`good first issue`](https://github.com/Tr3kkR/Yuzu/labels/good%20first%20issue); broader backlogs are grouped by area (`enterprise-readiness`, `security`, `docs`, `compliance`).

## Reporting Issues

- **Bugs** — open a [bug report](https://github.com/Tr3kkR/Yuzu/issues/new?template=bug_report.md). Include version (`yuzu-server --version`), OS, and reproduction steps.
- **Feature requests** — open a [feature request](https://github.com/Tr3kkR/Yuzu/issues/new?template=feature_request.md). Tie it to a use case so scope stays concrete.
- **Security vulnerabilities** — do **not** file a public issue. Follow [SECURITY.md](SECURITY.md) and submit via [GitHub's private vulnerability reporting](https://github.com/Tr3kkR/Yuzu/security/advisories/new). Acknowledgement within 48 hours.
- **Questions & discussion** — [GitHub Discussions](https://github.com/Tr3kkR/Yuzu/discussions) for usage questions; use issues for anything actionable.

## License

Yuzu is dual-licensed:

- **Community Edition** — [GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later). If you modify Yuzu and operate it as a network service, §13 requires you to offer the modified source to all users of that service. See [NOTICE](NOTICE) for attribution.
- **Enterprise Edition** — a commercial license covering premium features under [`enterprise/`](enterprise/). See [`enterprise/LICENSE-ENTERPRISE.md`](enterprise/LICENSE-ENTERPRISE.md) for terms and contact details.
- **Plugin authors** — the stable C ABI in [`sdk/`](sdk/) is covered by a linking exception documented in [`sdk/LICENSE-SDK.md`](sdk/LICENSE-SDK.md); proprietary plugins that consume only the ABI remain permitted.

Contributions require a signed [Contributor License Agreement](CLA.md); see [CONTRIBUTING.md](CONTRIBUTING.md).

Releases tagged before the AGPL transition (≤ v0.11.x) remain available under their original Apache-2.0 grant to everyone who received them. Only releases cut after the transition are governed by AGPL.
