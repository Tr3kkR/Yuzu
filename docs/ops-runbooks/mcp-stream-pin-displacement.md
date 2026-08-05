# Runbook: MCP replay-ring pin displacement / unpinned final

**Alerts:** `YuzuMcpStreamPinDisplaced`, `YuzuMcpStreamFinalUnpinned`,
`YuzuMcpBridgePinReleaseFailed`
**Severity:** warning.

For `YuzuMcpStreamPinDisplaced` and `YuzuMcpStreamFinalUnpinned`: **not a page, no
remediation.** No data is lost, no restart helps, clients recover on their own. What
these want from you is a judgement — whether a genuine accounting bug should be filed.

`YuzuMcpBridgePinReleaseFailed` is **different** and the line above does not apply to
it: it needs a genuinely broken platform mutex, so any nonzero value is a signal about
the HOST, not about MCP. Treat it as you would any other host-fault signal; the MCP-side
consequence (a session one call over its cap for the lifetime of the over-admitted call) is the
minor half.

## What has happened

Every streamed MCP request's final response frame is committed to the session's replay
ring and **pinned** (exempt from ring eviction) so a client that reconnects late can
still resume it. `YuzuMcpStreamPinDisplaced` means a session's pin slots were all full
and the oldest pin was displaced to make room.

The derivation lives in `server/core/src/mcp_stream.hpp`'s `What a FULL PIN-SLOT SET means` block. The statement below is this document's own self-contained summary — you may not have that file — so if the answer changes, change the derivation there first and then propagate to every operator surface, this one included.

The short version, for triage only: a full slot set is a **signal to corroborate, not a
verdict**. A *successful* #2740 reclaim cannot cause one — it releases a pin and adds a
charge, so the session stays *at* cap. Only two paths can, each with its own counter,
and step 2 below is how you rule them out.

- `yuzu_mcp_stream_final_unpinned_total` moving is a different and worse condition than
  displacement: a final was committed with **no pin at all**, meaning the displacement
  path was bypassed or the array was sized to zero. Treat it as genuine drift without
  the rule-out below.

## Client impact

Worst case, a client resuming a displaced-and-since-evicted terminal gets its session
terminated with a coherent `404`, re-initializes, and fetches the result durably by
`execution_id` — the standard eviction ladder, no silent gap. Most of the time there
is no client impact at all.

A displaced final is **not** "delivered". These frames are ring-only; nothing delivers
one except a resume.

## What to do

1. **Capture.** The stream metric family (`yuzu_mcp_stream_*`, `yuzu_mcp_bridge_*`) and
   any `mcp.stream.attach` / `mcp.stream.close` / `mcp.bridge.pin_displaced_for_admission`
   audit rows around the increment.

2. **Corroborate before concluding.** The alert fires on any displacement, so the
   rule-out is yours to do. A **successful** #2740 reclaim cannot have caused it — the
   reclaim releases one pin and adds one charge, so the session stays *at* cap and a
   slot is always free. Only two paths can, and each increment of them explains exactly
   one slot:

   | counter | what it means | explains how much? |
   |---|---|---|
   | `yuzu_mcp_bridge_pin_release_raced_total` | the release lost a race (#2795) | at most one slot, per increment |
   | `yuzu_mcp_bridge_pin_release_failed_total` | the release threw and was contained (#2805) | one slot, per increment |
   | `yuzu_mcp_bridge_pin_displaced_for_admission_total` | a successful reclaim | **zero — NOT a cause. Do not rule out against it.** |

   The third row is listed precisely so you do not have to wonder why it is missing. A
   successful reclaim releases a pin and adds a charge, so the session stays *at* cap and
   nothing is displaced; it is ordinary, expected traffic, and counting it here would let
   routine client churn explain away real drift. Displacement in excess of what the first
   two rows explain is the residue worth filing.

3. **File, unless the rule-out is clean and complete.** Title: "MCP streamed-POST
   admission accounting drift", attach the capture. The interesting question is how
   `pinned_count() + unpinned` and the admission cap disagreed. **When in doubt, file** —
   this alert is diagnostic, a spurious report costs a triage pass, and a suppressed
   real one costs exactly the bug this alert exists to surface.

4. **Do not restart the server**: the counters are cumulative diagnostics, the degraded
   behavior is self-limiting, and a restart destroys the in-memory session state you
   would want to inspect.

## Why this procedure changed

An earlier revision told you to file unconditionally; the revision after that told you
to dismiss whenever any reclaim counter had moved. Both were wrong, in opposite
directions, and the second was worse — a successful reclaim explains **no** displacement
at all, so "a reclaim moved" cannot dismiss any of it.

That revision also told you to rule out #2795 by checking two counters, at a time when
the #2795 path incremented **neither** — it reset its own record before both counter
guards ran. The procedure therefore concluded "genuine drift" for precisely the case it
was written to excuse. `yuzu_mcp_bridge_pin_release_raced_total` exists because of that:
the residual had to become observable before any procedure about it could be honest.

A third revision briefly netted the reclaim counter out of the alert expression itself.
That was wrong for a more basic reason — a successful reclaim cannot cause a
displacement at all, so the subtraction removed real signal in proportion to ordinary
client churn. The alert is a plain threshold again and the rule-out lives here, where a
human can see which term applied.
