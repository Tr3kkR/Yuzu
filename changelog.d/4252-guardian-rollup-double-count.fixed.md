- **Guardian dashboard compliance % no longer double-counts Linux Service Guards**
  (#4252). The fleet/by-guard/by-baseline census and the per-guard/per-baseline detail
  pages treated every non-Windows agent as "not implemented" for every Guard type — correct
  for Registry/File (genuinely Windows-only), but wrong for Service, which arms
  (observe-only) on Linux too. A Linux agent with a real compliant/drifted status row for a
  Service rule was folded into that rule's "not implemented" bucket a second time,
  corrupting the headline "% compliant" and the fleet/by-baseline breakdowns. The platform
  support check is now guard-type-aware (Registry/File = Windows only; Service = Windows +
  Linux, not macOS), and every render site excludes an (agent, rule) pair that already owns
  a real status row from the synthetic "not implemented" fold. The fleet honesty banner is
  now pair-level (an agent is flagged only if it owns an actually-unenforced pair, not
  merely for being on a platform Guardian doesn't fully support everything on) and its copy
  no longer claims a blanket "Windows only" capability.

  Known accepted limitation: a deployed Service rule targeting a Linux agent whose guard
  never arms (no system D-Bus — this includes every containerized/compose agent, including
  this repo's own reference UAT rigs — a disabled build flag, or an invalid unit name) now
  vanishes from the denominator entirely rather than being flagged "not implemented", since
  the platform is genuinely supported and the agent simply never reported. This has the same
  shape as today's silent omission of any other unreported pair (e.g. an unreported Windows
  pair), so it is not a new class of problem, but it means such a pair is not currently
  visible on the dashboard at all. A `yuzu_server_guardian_platform_matrix_stale_total{spark_type}`
  counter now fires (render-time only, at the fleet and baseline-page views) if the
  hardcoded support matrix ever again disagrees with what an agent actually reports.
