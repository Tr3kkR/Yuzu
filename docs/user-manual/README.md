# Yuzu User Manual

Yuzu is an enterprise endpoint management platform -- a single control plane for querying, commanding, patching, and enforcing compliance on Windows, Linux, and macOS fleets in real time. This manual covers day-to-day operations for administrators and operators.

All `curl` examples assume a running Yuzu server at `http://localhost:8080` and an active admin session cookie in `$COOKIE`. Replace with your session token or API token as appropriate.

---

## Table of Contents

| Section | Description |
|---|---|
| [Device Management](device-management.md) | Agent enrollment (3-tier), heartbeat, identity, OTA updates, and device lifecycle |
| [Authentication](authentication.md) | Login, session management, mTLS, and Windows certificate store integration |
| [RBAC](rbac.md) | Role-based access control -- principals, roles, securable types, per-operation permissions |
| [Asset Tagging](../asset-tagging-guide.md) | Structured tags (role, environment, location, service), categories, and tag compliance |
| [Management Groups](management-groups.md) | Hierarchical device grouping for access scoping and policy inheritance |
| [Instruction Engine](instruction-engine.md) | Instruction definitions, sets, parameter/result schemas, scheduling, and approval workflows |
| [Scope Engine](scope-engine.md) | Expression-tree device targeting with AND/OR/NOT, tags, OS filters, and wildcards |
| [Audit Log](audit-log.md) | Structured audit events -- who did what, when, on which devices |
| [Response Store](response-store.md) | Persistent, filterable, aggregatable instruction response data |
| [Agent Plugins](agent-plugins.md) | Plugin architecture, available plugins, and plugin development |
| [Policy Engine](policy-engine.md) | Desired-state rules, triggers, compliance checks, and auto-remediation |
| [Metrics](metrics.md) | Prometheus `/metrics` endpoint, label conventions, and Grafana integration |
| [Server Administration](server-administration.md) | Configuration, TLS, user management, first-run setup, and backup |
| [REST API Reference](rest-api-reference.md) | Complete REST API v1 endpoint reference with request/response examples |
| [Gateway](gateway.md) | Erlang/OTP gateway node for multi-site deployments and scale-out |
| [TAR (Timeline Activity Record)](tar.md) | Continuous system state change tracking -- processes, network, services, users |
| [Upgrading](upgrading.md) | Version upgrades, rollback, and migration |
| [MCP (AI Integration)](mcp.md) | Model Context Protocol server -- AI-driven fleet querying, tools, tokens, and approval workflows |
| [Security Hardening](security-hardening.md) | mTLS setup, firewall rules, secret management, and production hardening |

### Operations Guides

| Section | Description |
|---|---|
| [Troubleshooting](../operations/troubleshooting.md) | Common issues, log diagnosis, and resolution steps |
| [Disaster Recovery](../operations/disaster-recovery.md) | Backup strategy, restore procedures, and failover architecture |
| [Certificate Renewal](../operations/certificate-renewal.md) | TLS certificate lifecycle, rotation, and automated renewal |
| [Capacity Planning](../operations/capacity-planning.md) | Server sizing, storage growth, network bandwidth, and scaling patterns |

---

## Supported Platforms

| Platform | Architecture | Server | Agent | Gateway |
|----------|-------------|--------|-------|---------|
| Linux | x64 (amd64) | Yes | Yes | Yes |
| Linux | ARM64 (aarch64) | Cross-compiled | Cross-compiled | Yes |
| Windows | x64 | Yes | Yes | -- |
| macOS | ARM64 (Apple Silicon) | Yes | Yes | -- |
| macOS | x64 (Intel) | Not supported | Not supported | -- |

> **Note:** macOS Intel (x64) builds are not currently produced or tested. Only Apple Silicon (ARM64) Macs running macOS 14+ are supported. If you require macOS Intel support, please open an issue.

## Quick Start

1. **Start the server** -- run `yuzu-server` with a configuration file or accept interactive first-run setup.
2. **Enroll an agent** -- run `yuzu-agent --server <host>:<port>` on a target endpoint. The agent will appear in the pending queue (Tier 1) or auto-enroll with a token (Tier 2).
3. **Approve the agent** -- open the Settings page in the dashboard or use the REST API to approve pending agents.
4. **Run your first instruction** -- see the [Getting Started tutorial](../getting-started.md) for a step-by-step walkthrough.

## Related Documentation

- [Getting Started Tutorial](../getting-started.md) -- hands-on walkthrough of the Instruction Engine
- [Architecture Overview](../architecture.md) -- system design and component interactions
- [YAML DSL Specification](../yaml-dsl-spec.md) -- formal spec for instruction definitions
- [Roadmap](../roadmap.md) -- planned features and issue tracking
- [Capability Map](../capability-map.md) -- 139 capabilities across 7 phases
