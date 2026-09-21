- **The server can now dispatch commands across multiple independently-clustered gateways.**
  Deployments where gateway-fronted agents are split across separate Erlang gateway clusters (for
  example, one per trust zone or region) previously had every command forwarded to a single
  configured gateway address, regardless of which cluster the target agent was actually connected
  to — a command destined for an agent on a different cluster was silently misdirected. A new
  `--gateway-cluster-addr` option (repeatable, `cluster_id=host:port`) lets an operator configure a
  per-cluster gateway management address; the server now dials the cluster an agent's gateway
  actually announced, falling back to the existing single `--gateway-command-addr` for any
  deployment that doesn't configure per-cluster addresses (no change in behavior for existing
  single-cluster installs). A malformed or duplicate `--gateway-cluster-addr` entry now fails
  startup with a clear error instead of being silently dropped.
