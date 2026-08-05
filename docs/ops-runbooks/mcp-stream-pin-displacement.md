# Runbook: MCP replay-ring pin displacement / unpinned final

**Alerts:** `YuzuMcpStreamPinDisplaced`, `YuzuMcpStreamFinalUnpinned`,
`YuzuMcpBridgePinReleaseFailed`, `YuzuMcpStreamedPinSlotsWedged`
**Severity:** warning. **This is not a page and needs no remediation.** No data is
lost, no restart helps, and clients recover on their own. What the alert wants from
you is a judgement — whether a genuine accounting bug should be filed — not an
intervention.

## What has happened

Every streamed MCP request's final response frame is committed to the session's replay
ring and **pinned** (exempt from ring eviction) so a client that reconnects late can
still resume it. `YuzuMcpStreamPinDisplaced` means a session's pin slots were all full
and the oldest pin was displaced to make room.

**What a full slot set means is defined in exactly one place:** the
`What a FULL PIN-SLOT SET means` block on `McpStreamState` in
`server/core/src/mcp_stream.hpp`. Read it there. It is deliberately not restated here,
in the alert rules, in `/metrics` HELP, or in the user manual — it previously existed as a
paraphrase in every file that mentioned it, and after #2740 falsified the claim,
successive review rounds each found and fixed a different subset.

The short version, for triage only: a full slot set is a **signal to corroborate, not a
verdict**. Three paths legitimately put a session one call over its cap, each with its
own counter, and the alert expression already nets all three out.

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

2. **Corroborate before concluding.** `YuzuMcpStreamPinDisplaced`'s expression already
   subtracts the three benign paths, so an alert that fired has *already* survived the
   rule-out. Confirm that against the capture rather than re-deriving it:

   | counter | what it means | explains how much? |
   |---|---|---|
   | `yuzu_mcp_bridge_pin_displaced_for_admission_total` | a #2740 reclaim released a pin deliberately | **one slot, per increment** |
   | `yuzu_mcp_bridge_pin_release_raced_total` | the release lost a race (#2795) | one slot, per increment |
   | `yuzu_mcp_bridge_pin_release_failed_total` | the release threw and was contained (#2805) | one slot, per increment |

   The per-increment bound is the thing to check, and it is why "a reclaim happened" is
   **not** on its own a reason to dismiss. Each increment accounts for exactly one slot
   of over-admission; displacement in excess of what the three counters explain is the
   residue worth filing.

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
directions, and the second was worse — a reclaim explains one slot, so "a reclaim moved"
does not explain an arbitrary amount of displacement.

That revision also told you to rule out #2795 by checking two counters, at a time when
the #2795 path incremented **neither** — it reset its own record before both counter
guards ran. The procedure therefore concluded "genuine drift" for precisely the case it
was written to excuse. `yuzu_mcp_bridge_pin_release_raced_total` exists because of that:
the residual had to become observable before any procedure about it could be honest.
