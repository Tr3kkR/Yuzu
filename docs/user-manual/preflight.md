# Pre-flight readiness checks (`/auto`)

The **Pre-flight** page is an operator surface for a **go/no-go check across a
device cohort before a fleet change** (a rollout, a patch, an upgrade). You pick a
scope and a set of thresholds, run it, and get a result grouped by device. It is
reached at **`/auto`** by URL — it is deliberately not a navigation tab yet, and
the same checks are intended to be driven headless by an orchestrator later.

## The checks

Each run dispatches up to five **read-only** checks to the in-scope devices and
applies your thresholds server-side:

| Check | Threshold | Passes when |
|---|---|---|
| **Target App** | app name + min / max version (optional) | the named app is installed and its version is within `[min, max]` |
| **OS version** | minimum OS version | the device OS version is at or above the floor |
| **Arch** | required architecture (`x86_64` / `arm64` / `any`) | the device architecture matches |
| **Free disk** | minimum free GiB (+ optional volume) | free space on the volume is at or above the floor |
| **Pending reboot** | block or warn | no reboot is pending (a pending reboot fails when *block*, or warns when *warn*) |

The Target App check only runs when you give it an app name; the rest always run.

## Reading the result

Devices are grouped by outcome, with a run-level summary and per-device check
badges:

- **Pass** — every blocking check passed.
- **Failed** — at least one blocking check failed (the device is **no-go**). The
  *Failed by* chips let you filter the failed group by which check failed.
- **Warn-only** — warnings (e.g. a pending reboot under the *warn* policy) but no
  blocking failure.
- **Incomplete** — the device has not answered every check yet (or never answers).

Click a device name to open its per-device view.

## Run window and offline devices

A run keeps re-trying for its **window** (the "catch offline" minutes). A device
that is offline at dispatch still reports if it **reconnects within the window**;
a device that never answers stays **Incomplete**. The page itself pauses polling
after a few minutes, but the run continues server-side for the whole window —
reopen it from **Recent runs** to refresh.

## Persistence and retention

Runs are **saved** and listed in the **Recent runs** rail; reopen one to revisit
its result (a completed run reads its stored grid, so it survives even after the
underlying responses are pruned). Saved runs are **kept 14 days**, then pruned
automatically. Delete a run from the rail (you are asked to confirm first).

Runs are **owner-scoped**: you only see and can delete your own runs, and opening
another operator's run is indistinguishable from a run that does not exist.

If the run store's schema cannot be initialized at boot (for example, after a
conflicting manual schema alteration in Postgres), the server **refuses to start**
and logs `[PG] Refusing to start`. Treat this like any other Postgres migration
failure — restore the schema or redeploy from a clean database. (A *transient*
store error while the server is already running just degrades `/auto` to an
"unavailable" note; it does not take the server down.)

## Verify — before / after performance

The **Verify** stage at the bottom of `/auto` answers a different question from
pre-flight: *after* an upgrade, **did it change how the same machines perform?**
Pick a cohort (a management group), an application, the **baseline** version (what
they ran before) and the **candidate** version (what was installed), and a window,
then **Compare**.

The comparison is **cohort-paired**. For each machine that ran *both* versions in
the window, Verify takes that machine's own baseline-version performance and its own
candidate-version performance and computes the difference *per machine*, then
aggregates those differences. The window is anchored to **each machine's own version
history**, not to a fixed "last N days", so a rollout where different machines
upgraded at different times still pairs correctly. A machine that ran only one of the
two versions in the window is **excluded and counted** (never guessed at). This
matters: a fleet-wide "version A vs version B" average would compare *different
machines* and could blame the build for a difference that is really just a different
population — pairing on the machine removes that.

Verify is **evidence, not a verdict.** It shows the measured shift — CPU and
working-set before→after means, the typical (median) per-machine change, the spread
across machines (p95), and how many machines went up / stayed flat / went down — and
**lets you judge**. It never labels a build "bad" or "regressed", and there is no
pass/fail gate (unlike pre-flight's go/no-go). An AI colleague driving the rollout
reads the same numbers over MCP and makes the call.

Real canaries are small — two or three devices — so Verify deliberately has **no
minimum cohort size**: a small paired set is shown with an *"indicative"* note rather
than hidden. Because that means reading a handful of named machines' data, the
comparison is **recorded in the audit log**. The aggregate is shown without any
per-machine identity; the **per-machine pairs** are behind a separate *"Show
per-machine pairs"* click, so opening that view is a deliberate, separately-audited
action.

Verify reads the retained per-device performance history, so a candidate version only
appears once the upgraded machines have reported it (the next daily sync after the
upgrade). It does not dispatch anything to the devices.

The same comparison is available to automation: REST `GET /api/v1/dex/perf/compare`
and MCP `compare_app_perf_versions` return the aggregate (no per-machine identity).

## Permissions

| Action | Permission |
|---|---|
| View the page / a result / the rail | `Infrastructure:Read` |
| Run a pre-flight | `Infrastructure:Read` + `Execution:Execute` |
| Delete a saved run | `Execution:Execute` (and you must be the owner) |
| Open the Verify form | `Infrastructure:Read` |
| Run a Verify comparison / open the per-machine drill | `GuaranteedState:Read` |

Pre-flight runs and deletes are recorded in the [audit log](audit-log.md) as
`preflight.run` and `preflight.run.delete`. A Verify comparison (aggregate read and
the per-machine drill) is recorded as `dex.app_perf.compare`.
