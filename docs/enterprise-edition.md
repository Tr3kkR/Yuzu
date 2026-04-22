# Yuzu Enterprise Edition

Yuzu ships under a **dual-licence model**: the core platform is free
software under the GNU Affero General Public License v3.0 or later
(AGPL-3.0-or-later, the "Community Edition"), and a paid "Enterprise
Edition" adds commercial-licensed modules built from the
[`enterprise/`](../enterprise/) subtree.

This document describes the split, the feature boundary, and how
operators should decide which edition they need.

## Why two editions

- **Protect the commons.** The AGPL requires any operator running a
  modified Yuzu as a network service to publish their modifications.
  Permissive licenses (Apache, MIT) allow competitors to resell hosted
  Yuzu without contributing back; AGPL closes that gap.
- **Fund the project.** The Enterprise Edition pays for full-time
  engineering, security response, compliance work, and customer
  support. Every cent of commercial revenue feeds back into the same
  code tree the Community Edition users consume.
- **Give serious operators a serious commercial contract.** The
  Community Edition ships "as is" under the AGPL; enterprise customers
  get a commercial license with negotiated indemnification, support
  SLAs, and the ability to distribute Yuzu derivatives without AGPL
  copyleft obligations.

## What's in each edition

### Community Edition (AGPL-3.0-or-later)

Everything outside of the `enterprise/` directory:

- Agent daemon (C++23, cross-platform)
- Server daemon (REST API, dashboard, policy engine, scheduler, audit)
- Gateway (Erlang/OTP command-fanout plane for fleet-scale deployments)
- OIDC authentication (provider + consumer)
- Standard RBAC (principals, roles, per-operation permissions,
  management groups)
- Guardian (Guaranteed State) baseline engine and rule set
- 44 bundled plugins (hardware, network, security, filesystem,
  compliance, more)
- Full plugin SDK with AGPL linking exception — proprietary third-party
  plugins are permitted (see [`sdk/LICENSE-SDK.md`](../sdk/LICENSE-SDK.md))

### Enterprise Edition (commercial license)

Built only when `-Denable_enterprise=true` is passed to `meson setup`.
Planned scope:

- **Identity** — SAML 2.0 SSO, SCIM directory sync, conditional-access
  integration with major IdPs (Okta, Entra ID, Google Workspace).
- **Advanced RBAC** — attribute-based access control, hierarchical role
  inheritance, time-boxed grants, delegated administration, break-glass
  procedures with audit amplification.
- **Compliance packs** — curated Guardian rulepacks for SOC 2 Type II,
  HIPAA, PCI-DSS, CIS benchmarks; automated evidence generation and
  control-mapping exports.
- **Multi-tenancy** — full organisational isolation for MSP
  deployments; per-tenant data encryption keys; tenant-scoped operator
  personas.
- **Premium reporting** — scheduled posture snapshots, executive
  dashboards, drift analytics, CSV/PDF compliance exports.
- **Priority support** — 24×7 incident response, dedicated engineering
  liaison, hot-patch delivery ahead of OSS release cadence.

Not all of the above exists yet — the `enterprise/` directory currently
contains only the scaffold (`README.md`, `LICENSE-ENTERPRISE.md`,
`meson.build`). Each premium feature lands in its own PR on top of this
scaffold, typically by deepening an interface that already exists in
the OSS tree (e.g. enterprise SSO wraps the existing
`server/core/src/oidc_provider.cpp`).

## How operators should choose

- **You run Yuzu for yourself or your organisation and you don't modify
  it.** Community Edition is fine. AGPL §13 is a *no-op* if you're not
  distributing a modified version.
- **You modify Yuzu internally.** Community Edition is still fine,
  provided you offer the modified source to users of your service. If
  that's every employee, posting to an internal git server works.
- **You want to resell a hosted Yuzu product to third parties without
  publishing your modifications.** You need an Enterprise license.
- **You need SSO/SCIM/SAML, compliance packs, or multi-tenant
  isolation.** You need an Enterprise license regardless of AGPL
  considerations — those are enterprise-only features.
- **You are a Managed Service Provider deploying Yuzu across many
  customers.** You need the multi-tenancy + advanced RBAC features in
  the Enterprise Edition.

## Build instructions

Community build:

```bash
./scripts/setup.sh --buildtype release
meson compile -C build-linux
```

Enterprise build (requires a commercial license, see
[`enterprise/LICENSE-ENTERPRISE.md`](../enterprise/LICENSE-ENTERPRISE.md)):

```bash
./scripts/setup.sh --buildtype release
meson configure build-linux -Denable_enterprise=true
meson compile -C build-linux
```

The Meson feature summary prints `Enterprise: true` when the flag is
set. A `message()` is also emitted during configure to prevent
accidental enablement.

## CI

The default CI matrix builds the Community Edition only. Enterprise
builds live in a separate gated workflow (to be added) that runs on
credentialed runners and publishes to a private artefact channel.

## How to purchase

Contact the copyright holder listed in [`/NOTICE`](../NOTICE). A formal
sales channel will be established before the first Enterprise-era
release ships.

## Roadmap

See [`docs/roadmap.md`](roadmap.md) for the project-wide roadmap. The
Enterprise-specific order-of-operations is:

1. Scaffold (`enterprise/` directory, Meson flag, licence placeholder, docs) — **done**.
2. Legal review of `LICENSE-ENTERPRISE.md`, `CLA.md`, and `sdk/LICENSE-SDK.md`.
3. Trademark sweep for the "Yuzu" name.
4. First premium module: SAML/SSO in `enterprise/server/sso/`.
5. Directory sync (SCIM) and advanced RBAC.
6. Compliance packs and reporting.
7. Multi-tenancy isolation (requires schema migration — biggest lift).
