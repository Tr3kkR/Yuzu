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
| Missing `--data-dir` flag | Always included — SQLite stores fail silently without it |
| RBAC config doesn't enforce | Comment added noting this is a known issue |
| Port conflicts detected | Wizard warns about common conflicts |
| Hardcoded passwords | All credentials configurable, with production warnings |
| No `.env` separation | Generated `.env` file separates config from compose |

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