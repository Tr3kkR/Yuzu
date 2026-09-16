- **Gateway routing directory writer-path hardening (HA WS-4 slice 4.2a).** `GatewayRouteStore`
  remains inert (no dispatch surface reads it yet), but the directory itself is now durably
  self-healing: `deregister` tombstones a route instead of deleting it, closing the window where a
  late/reordered CONNECTED notification could resurrect a torn-down route; a new clock-guarded
  background reaper (`reap_stale_routes`, ~5-minute cadence) sweeps leases expired well past their
  grace window and stale tombstones; and an unknown-but-presented gateway session now renews its
  existing directory row instead of minting a fresh connection epoch, closing a fresh-branch clobber
  window. A new `yuzu_server_gateway_route_desync_total{op,outcome}` counter gives operators
  visibility into session-guard rejections (in-memory/durable-directory disagreement) distinct from
  the existing write-failure counter. Remaining WS-4 4.2 obligations — the fail-closed write posture
  flip, the companion alert rule, durable cross-replica session lookup, and gateway-side replay
  session writeback — are tracked for later WS-4/WS-5 slices.
