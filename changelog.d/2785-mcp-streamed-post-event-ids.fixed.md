- MCP streamed POST: progress and final frames now carry their replay-ring event
  id as the SSE `id:` line (#2785). A client that only ever saw the POST
  connection can now hand that id back as `Last-Event-ID` on the GET channel
  after a drop, making the documented resume contract reachable from the POST
  surface. A final with no ring counterpart (poisoned or pinless settle) carries
  no `id:` line rather than a cursor that would resume onto nothing. GET SSE
  behavior is unchanged.
