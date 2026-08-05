- MCP streamed POST: the 120 s response cap is now enforced while progress keeps
  arriving (#2739). After the cap expires the bridge delivers one final drain of
  already-latched progress frames, then settles the response — bounding it at the
  cap plus at most two pump ticks plus one mailbox drain instead of the
  execution's whole duration. A terminal latched inside that window is still
  delivered as a normal completion, and progress latched after the drain pass is
  parked to the session replay ring for GET resume rather than lost. The
  execution itself is never cancelled by a cap close. Sizing guidance in the
  server-admin manual and `docs/mcp-server.md` now states the enforced bound.
  Supersedes two statements in this release's own streamed-POST dormant-landing
  entry. Its "two bounds defects are open against it" is written in the present
  tense but describes the state before this entry: #2739 and #2740 are both fixed
  in this same release, so nothing an operator opting in early owns remains open
  from that pair (two narrower residuals of the #2740 fix, #2794 and #2795, are
  described in its own entry). And its "the follow-up PR carries both fixes and
  turns it on" is half right: both fixes are here, but turning
  `--mcp-enable-streamed-post` on by default is a separate rung and has not
  happened.
