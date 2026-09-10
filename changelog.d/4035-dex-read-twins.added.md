- **8 new DEX REST + MCP twins closing the api-parity #2146 Batch A gaps.**
  `GET /api/v1/dex/app`, `/apps`, `/catalogue/group`, `/health`, `/trends`,
  `/overview`, `/devices/{id}/history`, and `/devices/{id}/observations/{event_id}`
  (plus their MCP twins `get_dex_app`, `list_dex_apps`, `get_dex_catalogue_group`,
  `get_dex_health`, `get_dex_trends`, `get_dex_overview`, `get_dex_device_history`,
  `get_dex_observation`) expose the app blast-radius drill, app-centric stability
  list, signal-family drill, composite health score, cross-OS trends, fleet
  overview, per-device signal history, and single-observation detail an agentic
  worker previously had no machine-readable access to. Every pair shares one
  pure builder function (`dex_read_model.hpp`) so the REST and MCP response
  shapes cannot drift (per `docs/api-twin-recipe.md`'s Rule 1). `app`/`overview`
  fail-closed audit (`dex.app.view`/`dex.overview.view`) on their affected-
  device lists, which are confined to the caller's management-group scope
  (ADR-0017 World A) exactly like the equivalent dashboard fragments — the
  crash/health aggregates themselves remain fleet-wide; `device/history` and
  `observation` reuse the existing per-device scoped gate +
  `dex.device.view`/`dex.observation.view` audit verbs; `apps`/`catalogue/group`/
  `health`/`trends` are fleet aggregates with no per-agent identity and are not
  audited.

  Known gap (tracked, not closed by this change): the corresponding
  `/fragments/dex/*` dashboard renderers still take a store handle and
  re-query internally rather than calling the new shared builders — their
  computation was ported into `dex_read_model.hpp` line-for-line so the
  numbers cannot drift today, but the call graph is not yet unified per
  `docs/api-twin-recipe.md` Rule 1's full intent. Splitting each
  `render_dex_*_fragment` into a model-taking renderer plus a thin
  store-taking overload is a follow-up (the observation fragment already
  takes a model, so it needs no change).
