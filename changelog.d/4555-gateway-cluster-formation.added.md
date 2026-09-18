- **Gateway multi-node cluster formation (HA WS-4, `#4555`).** The Erlang
  gateway now forms and maintains a real distributed-Erlang mesh across
  replicas: an always-on redial loop resolves peer addresses via DNS (a
  configurable seed name, defaulting to the reference Compose service name —
  zero extra config for a scaled `docker compose up --scale gateway=N`) or
  an explicit static list, and connects to each. This is what makes the
  earlier per-agent cross-node routing (HA WS-4 4.3a) actually take effect
  in a deployed cluster — previously the mechanism existed but had nothing
  to route across. Ships with a minimum distribution-cookie length
  requirement, new `yuzu_gw_cluster_peers_resolved`/`peers_connected`
  metrics and a partial-mesh alert, and a scale-capable reference Compose
  rig (`docker-compose.reference-gateway-cluster.yml`) demonstrating it.
  **Breaking —** the gateway's Erlang node short name changed from a
  hardcoded `yuzu_gw1` to a shared `yuzu_gw` (every replica now advertises
  the same short name, distinguished only by address) to support
  `docker compose up --scale`; a single-node deployment boots identically,
  but external tooling hardcoding the old full node name
  (`yuzu_gw1@127.0.0.1`) needs updating. See `docs/user-manual/upgrading.md`.
