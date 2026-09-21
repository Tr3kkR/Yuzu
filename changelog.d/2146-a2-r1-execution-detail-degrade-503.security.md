- **Execution-detail reads no longer produce a false 404 or a false denial-audit row during a
  transient backend degrade.** `GET /fragments/executions/{id}/detail`, `GET
  /sse/executions/{id}`, and `GET /api/v1/events?execution_id=` (all three pre-existing routes)
  previously read the execution via the plain, non-degrade-aware tracker accessor, which
  collapsed "execution genuinely does not exist or is outside the caller's scope" and "the
  backend read failed transiently" into the same not-found outcome. A brief connection-pool or
  query hiccup therefore returned a misleading 404 to a legitimate owner, and, for a non-owner
  caller, permanently wrote an incorrect access-denial row to the audit log, indistinguishable
  from a real access attempt. All three routes now distinguish the two cases and return their own
  native 503 (with retry guidance) on a transient degrade, writing no denial-audit row at all in
  that case. No change to visibility, confinement, or audit behavior on a genuine not-found or a
  genuine denial.
