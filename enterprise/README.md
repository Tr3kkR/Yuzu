# Yuzu Enterprise Edition

> **This directory is not licensed under the AGPL.** See
> [`LICENSE-ENTERPRISE.md`](LICENSE-ENTERPRISE.md) for the terms. The
> rest of the repository is AGPL-3.0-or-later.

## What lives here

This subtree will host **commercial-licensed premium modules** that are
not part of the Community Edition. Current scope (planned, not yet
implemented):

- **SAML / SSO** — enterprise-grade single sign-on layered on top of the
  existing OIDC provider in `server/core/src/oidc_provider.cpp`.
- **SCIM directory sync** — bulk user/group provisioning from IdPs.
- **Advanced RBAC** — hierarchical role inheritance, attribute-based
  access control, time-boxed grants.
- **Premium Guardian rulepacks** — pre-built compliance-aligned policy
  libraries for SOC 2, HIPAA, PCI-DSS.
- **Compliance reporting** — automated evidence generation, SOC 2
  control-mapping exports, scheduled posture reports.
- **Multi-tenancy** — organisation isolation for MSP deployments.

## How to build

The default OSS build does **not** include any enterprise code:

```bash
./scripts/setup.sh --buildtype release
```

To build with enterprise modules (requires a commercial licence — see
[`LICENSE-ENTERPRISE.md`](LICENSE-ENTERPRISE.md)):

```bash
./scripts/setup.sh --buildtype release
meson configure build-linux -Denable_enterprise=true
meson compile -C build-linux
```

Or in one shot at configure time:

```bash
meson setup build-linux-ent -Denable_enterprise=true
meson compile -C build-linux-ent
```

The Meson feature summary will print `Enterprise: true` when the flag is
active. A build warning is emitted to make accidental enablement
obvious.

## Licensing

- **Community users** — do not enable `-Denable_enterprise=true` unless
  you hold a valid commercial licence. The default is off; you cannot
  accidentally build enterprise artefacts by running the standard setup
  script.
- **Commercial customers** — see [`LICENSE-ENTERPRISE.md`](LICENSE-ENTERPRISE.md).
- **Contributors** — external contributions to `enterprise/` are
  accepted only under the terms of the project-wide
  [`CLA.md`](../CLA.md), which grants the copyright holder the ability
  to re-license contributions under both the AGPL and the commercial
  licence.

## Directory layout (planned)

```
enterprise/
  README.md              — this file
  LICENSE-ENTERPRISE.md  — commercial licence terms
  meson.build            — build-system entry point (conditional on -Denable_enterprise=true)
  server/                — premium server modules (SSO, SCIM, RBAC, compliance)
  agents/                — premium agent modules (where applicable)
  docs/                  — customer-facing documentation for enterprise features
```

Only `README.md`, `LICENSE-ENTERPRISE.md`, and `meson.build` exist at
the time this scaffold lands. Premium features arrive in follow-up PRs.

See [`docs/enterprise-edition.md`](../docs/enterprise-edition.md) for
the roadmap.
