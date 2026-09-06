- **REST v1 read-twins for the Settings dashboard (api-parity programme #2146).** The eight
  `/fragments/settings/*` sub-areas previously reachable only through the dashboard — TLS, HTTPS,
  gateway, server-config, MCP, data-retention, analytics, and plugin-signing — now have `GET
  /api/v1/settings/*` twins (plugin-signing's twin is the hardened, previously off-ledger `GET
  /api/v1/agent/plugin-policy`), sharing pure builder functions with the HTML fragments so the two
  views cannot drift. Four new RBAC securables (`TlsConfig`, `PluginSigning`, `ServerConfig`,
  `AnalyticsConfig`, all `Read`) replace the prior whole-route admin-only gate, granted to
  Administrator only and floored in `authz_topology_floor.hpp` so an RBAC-off deployment stays
  admin-gated. The four highest-sensitivity reads (TLS, HTTPS, plugin-signing, analytics) are
  audited fail-closed; the other four are not (operational config, nothing secret). No MCP tool was
  added for any of these eight — issue #520 explicitly bars MCP tokens from server-administration
  surfaces including "settings" and "TLS"; see `docs/mcp-server.md` and `docs/auth-architecture.md`
  for the recorded decision.
