- **Gateway routing directory becomes dispatch-authoritative, fallback-only (HA WS-4 slice 4.2b).**
  `GatewayRouteStore`'s directory write posture is now fail-closed for the one row-creating write
  (`register_fresh` refuses `ProxyRegister` with `UNAVAILABLE` on a degraded store; the other five
  writer sites stay deliberately fail-open) and renews now correlate both `agent_id` and `session_id`,
  not `session_id` alone. Confined dispatch consults the directory as a fallback: only when the local
  agent registry has no live session for a target does the batched directory read run, and every send
  still passes the existing per-device confinement check before going out — this changes no routing
  outcome on a single-replica deployment, since a directly-connected agent never has a directory row.
  The directory is populated only for gateway-fronted fleets, so direct-connect deployments are
  entirely unaffected by this slice. A
  degraded directory read during dispatch (`route_unreadable`) now reschedules the affected command with
  back-off, exactly like an unreadable containment/quarantine state, instead of reporting a false "no
  agents reached." Two new alert rules ship in `docs/prometheus/yuzu-alerts.yml`'s `yuzu-gateway` group
  for a degraded directory write and a degraded directory read during dispatch. Multi-cluster gateway
  fan-out, the durable cross-replica session lookup, and `gateway_node` convergence remain outstanding
  WS-4 work.
