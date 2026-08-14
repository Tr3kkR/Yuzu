- **A presented `Mcp-Session-Id` reaching a `POST /mcp/v1/` audit row is now
  sanitized.** Found while documenting the `mcp.session.*` audit family
  (#2917): the non-`initialize` presented-session validation check on `POST`
  passed the attacker-controlled header's first 8 bytes into the
  `mcp.session.reject` audit row raw, unlike every other of the 13 call sites
  producing `mcp.session.*` rows — including the `GET` and `DELETE` siblings,
  the latter having already been fixed for exactly this gap once before (its
  own code comment says so). A crafted `Mcp-Session-Id` could inject `;`/`=`
  field separators into the flat `k=v;k=v` `detail` format SIEM tooling
  parses. Fixed to match the established `sanitize_detail_value()` pattern;
  regression test added (the header is attacker-controlled until it
  validates, so an unknown/malformed id reliably exercises this path — real
  CR/LF bytes are unreachable through an HTTP header value at all, blocked by
  httplib's own field-value validation, so the test covers the realistically
  reachable `;`/`=` injection instead).
