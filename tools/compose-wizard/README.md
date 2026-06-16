# 🍊 Yuzu Compose Wizard

A browser-based wizard for generating customised Yuzu `docker-compose.yml` and `.env` files. Zero dependencies — just open `index.html` in a browser.

## Why?

The default `docker-compose.uat.yml` works, but it has:
- Hardcoded ports, passwords, and versions
- Several known gotchas that trip up new users
- Minimal comments explaining what each section does

This wizard walks you through a step-by-step configuration and generates a production-ready compose file with proper defaults, helpful comments, and a separate `.env` file for easy reconfiguration.

## Known Gotchas Addressed

| Issue | Fix |
|-------|-----|
| Missing PostgreSQL substrate | Wizard provisions a bundled `yuzu-postgres` service (or wires an external DSN) — the server has a substrate to talk to (ADR-0006/0008) |
| Postgres superuser == app password | Bundled mode enforces two distinct credentials; the image's first-boot init refuses equal passwords |
| Secrets baked into compose | Postgres credentials/DSN live in `.env`; the compose YAML only references `${...}` |
| Missing `--data-dir` flag | Always included — still needed for config, OTA binaries, and not-yet-migrated SQLite stores |
| RBAC config doesn't enforce | Comment added noting this is a known issue |
| Port conflicts detected | Wizard warns about common conflicts |
| Hardcoded passwords | All credentials configurable, with production warnings |
| No `.env` separation | Generated `.env` file separates config from compose |
| TLS was all-or-files | Three-way TLS mode: **Default certs** (server auto-generates a per-install CA + leaf certs on first boot — encrypted-by-default, no files), **Operator certs** (`--cert`/`--key` + optional `--ca-cert`, bind-mounted from `./certs`), or **Plaintext** (`--no-tls --no-https`, dev only) |
| Default certs not persisted | Default mode mounts a volume at `/etc/yuzu/certs` so the auto-generated CA survives a recreate — otherwise every `down && up` mints a fresh CA and breaks enrolled-agent trust |
| Gateway hostname not in cert SANs | When the gateway is enabled, `--cert-san dns:gateway` is injected automatically so agents dialing the gateway by name pass hostname validation (PKI PR5b gateway-edge requirement); operators can add their own server hostname/IP too |
| Gateway crash-loop on default cookie (#1483) | A unique `YUZU_GW_COOKIE` is generated into `.env` and referenced by the gateway service, so it doesn't fail-closed on the insecure default Erlang distribution cookie |
| HTTPS served on 8443, wizard used 8080 (#1484) | In TLS modes the dashboard/API is published and health-checked on container port **8443** (8080 is the HTTP→HTTPS redirect); plaintext stays on 8080 |
| Gateway↔server plaintext vs strict-mTLS upstream (#1485) | Default-certs + gateway now emits the secure topology: shared `/etc/yuzu/certs` volume, `--cert-group yuzu-pki`, `dns:server` SAN, and a `{https,...}` gateway sys.config (mutual-TLS upstream, one-way agent listener, strict-mTLS mgmt) — modelled on `deploy/docker/reference-gateway-sys.config`. Operator + gateway is blocked with guidance (interim) |
| Gateway healthcheck used bash `/dev/tcp` (#1486) | The gateway image ships no bash/curl, so the probe always failed. Removed; the gateway now gates on `depends_on: server: service_healthy` instead |
| Server healthcheck used `curl` (#1487) | The server image ships no curl. Replaced with a bash `/dev/tcp` TCP-connect probe on the real serving port (8443/8080), matching `docker-compose.uat.yml` |
| Admin `admin:admin` hash didn't validate (#1488) | The admin credential row is now derived in-browser via SubtleCrypto **PBKDF2-HMAC-SHA256, 100k iters** for the password you enter — matching the server KDF, so login actually works (the old row put the password in the role field and shipped a stale hash) |

## Usage

```bash
# Just open it
open tools/compose-wizard/index.html

# Or serve it locally
cd tools/compose-wizard && python3 -m http.server 8000
```

Then open `http://localhost:8000` in your browser.

## Tech Stack

- **HTML** — Single page, no build step
- **HTMX** — Step navigation feel (loaded from CDN)
- **Vanilla JS** — YAML generation, no framework
- **CSS** — Yuzu-themed, responsive

## Development

No build tools needed. Edit files, refresh browser. That's it.

```bash
# Live reload (optional)
npx serve .
```

## Future Ideas

- [ ] Admin password hash generator (using Web Crypto API)
- [ ] Export/import wizard config as JSON
- [ ] Validate generated compose with `docker-compose config`
- [ ] Dark mode
- [ ] Embed in Yuzu docs site