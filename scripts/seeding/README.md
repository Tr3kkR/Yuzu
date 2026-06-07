# Guardian Guards & Baselines — shareable starter set

A known-good set of Guardian Guards + Baselines you can drop into any Yuzu instance
in one command, so everyone starts from the same content.

## What's here

```
guards/
  cis-01..cis-41-*.json                 # 41 CIS Microsoft Windows 11 Benchmark Guards (audit / observe)
  demo-rdp-disabled-enforce.json        # enforce: HKLM\...\Terminal Server\fDenyTSConnections = 1
  demo-spooler-running-enforce.json     # enforce: the Print Spooler service stays running
baselines/
  cis-windows-11.json                   # Baseline "CIS Windows 11"  — the 41 CIS Guards (observe)
  demo-enforcements.json                # Baseline "Demo Enforcements" — the 2 enforce Guards
```

- **CIS Windows 11** — 41 registry Guards derived from the CIS Microsoft Windows 11
  Benchmark, in **audit** mode (detect + report, never write back).
- **Demo Enforcements** — 2 **enforce** Guards that demonstrate remediation (a registry
  write-back and a service-control restart).

## Run it

```bash
# Create all the Guards + Baselines as DRAFTS (nothing takes effect yet):
python scripts/seeding/seed-guardian-demo.py

# ...or create AND deploy (Guards start evaluating / enforcing on connected agents):
python scripts/seeding/seed-guardian-demo.py --deploy
```

Targets a local UAT rig by default. Point it at any instance with env vars:

| Variable | Default | Meaning |
|---|---|---|
| `YUZU_BASE` | `http://localhost:8080` | server URL |
| `YUZU_ADMIN_USER` | `admin` | admin username |
| `YUZU_ADMIN_PASS` | `YuzuUatAdmin1!` | admin password (the local UAT default) |

Stdlib-only Python 3 (no `pip install`); idempotent — safe to re-run.

## How the seeder works

1. **Log in** — POSTs `YUZU_ADMIN_USER` / `PASS` to `/login` and keeps the session cookie.
2. **Create the Guards** — POSTs every `guards/*.json` to
   `POST /api/v1/guaranteed-state/rules`. A Guard that already exists is treated as
   success.
3. **Create the Baselines** — reads each `baselines/*.json`, resolves its
   `member_rule_ids` to the Guards' **names** (the Baseline form matches members by name,
   not id, so the seeder looks the names up from the live store — this also handles the
   em-dash in the CIS names), then POSTs each Baseline to
   `POST /fragments/guardian/baselines` as a **draft**.
4. **Deploy (only with `--deploy`)** — finds each Baseline's id and POSTs
   `/fragments/guardian/baseline/<id>/deploy`.

### Why deploy is opt-in (important)

A **Guard only takes effect on an agent once its Baseline is _deployed_** — authoring a
Guard, or leaving its Baseline a draft, does nothing on any endpoint. The seeder leaves
everything a draft by default; `--deploy` activates it.

That matters because **`demo-rdp-disabled-enforce`, once deployed, writes
`fDenyTSConnections = 1` — i.e. it disables RDP** on every targeted agent. That's a
no-op where RDP is already disabled (the common secure default), but it *will* disable
RDP where it's currently enabled. Deploy deliberately.

## Add more

Drop more `*.json` Guard descriptors in `guards/` and/or Baseline descriptors in
`baselines/` (a Baseline descriptor is `{ name, description, member_rule_ids[] }`); the
seeder picks them up automatically on the next run.

---

> **Note — MVP / demo mechanism.** This file-and-seeder approach is deliberately
> simple, for MVP and demo purposes. A more robust mechanism for uploading Guards and
> Baselines — with provenance / authenticity verification — is in the backlog; until
> then, this lets the team share a known-good starter set.
