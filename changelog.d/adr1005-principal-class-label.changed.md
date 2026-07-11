- **`yuzu_http_requests_total` gains a `principal_class` label** (`human` =
  session cookie, `agent` = bearer/API token, `none` = no credential;
  `engine` reserved for ADR-1005 engine principals). Classification is by
  credential presentation, not validated session — it is a traffic-shape
  label, never an authorization signal.

  **Upgrade note:** adding a label changes Prometheus series identity — the
  old `{method,status}` series stop incrementing at upgrade and new
  `{method,status,principal_class}` series start at zero. Selector-style
  queries (`rate(yuzu_http_requests_total{method="GET"}[5m])`) and
  `sum by (method, status)` aggregations are unaffected; only dashboards or
  rules matching the exact label set, or joining on series identity, need
  updating.
