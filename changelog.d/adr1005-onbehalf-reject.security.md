- **On-behalf-of assertions are now rejected on every ingress surface
  (ADR-1005 Interim rules).** Five header/metadata names are reserved —
  `On-Behalf-Of`, `X-On-Behalf-Of`, `X-Yuzu-On-Behalf-Of`,
  `X-Yuzu-Delegated-Operator`, `X-Yuzu-Delegation-Artifact` (case-insensitive)
  — and any HTTP request carrying one (REST, MCP, dashboard, static)
  receives `403` with the A4 error envelope before authentication (sole
  recorded exception: the four health-probe paths ignore the header, so a
  header-stamping proxy cannot crash-loop the server); a gRPC call
  carrying one as a metadata key is cancelled at a server interceptor and
  independently rejected again at every RPC handler's own entry point
  before any side effect can commit — see `docs/auth-architecture.md` for
  the enforcement seam. Nothing previously consumed these headers, so no
  legitimate integration breaks — but
  an integration *testing* a delegation header will now see the rejection.
  Server-verifiable delegation arrives with the ADR-1005 auth follow-up;
  client-asserted delegation stays rejected permanently. Rejections are
  counted in the new `yuzu_onbehalf_rejected_total{surface,event="security"}`
  metric (log lines are throttled; the counter records every event).
