- **Fenced agent→cluster gateway routing directory (HA WS-4 slice 4.1).** A new born-on-Postgres
  `GatewayRouteStore` records which gateway cluster/node currently holds each agent's live gRPC
  stream (`agent_id, cluster_id, gateway_node, connection_epoch, session_id, lease_until`), the
  foundation a future dispatch surface will use to route a command to the gateway actually holding
  the connection instead of relying on the single-process `AgentRegistry` that active-active server
  replicas cannot share. A server-minted, strictly-increasing epoch orders a fresh `ProxyRegister`
  against an existing row (a delayed, out-of-order registration cannot overwrite a newer one), and
  `session_id` equality guards every follow-up write, so a stale connect/disconnect notification from
  an already-superseded session cannot tear down a newer re-home. The gateway now also carries an
  agent's existing session id on a circuit-recovery `ProxyRegister` replay, so the server reuses the
  session instead of minting a new one. **This directory is inert in this slice** — it is written on
  every gateway connect/disconnect/heartbeat, but nothing yet reads it to route a dispatch; that
  wiring, and the accompanying flip from today's fail-open write posture to fail-closed, is a later
  WS-4 slice.
