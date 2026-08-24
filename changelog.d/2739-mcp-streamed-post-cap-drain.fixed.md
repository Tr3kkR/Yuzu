- MCP streamed POST: the 120 s response cap is now enforced while progress keeps
  arriving (#2739). After the cap expires the bridge delivers one final drain of
  already-latched progress frames, then settles the response — bounding it at the
  cap plus at most two pump ticks plus one progress drain instead of the
  execution's whole duration. A terminal latched inside that window is still
  delivered as a normal completion, and progress latched after the drain pass is
  parked to the session replay ring for GET resume rather than lost. The
  execution itself is never cancelled by a cap close. Sizing guidance in the
  server-admin manual and `docs/mcp-server.md` now states the enforced bound.
