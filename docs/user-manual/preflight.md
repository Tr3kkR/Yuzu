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

## Deploying to the go-cohort

Pre-flight is the **assess** half of a change; the **act** half lives on the same
page. When a run completes and has a go-cohort (devices in **Pass** or
**Warn-only**), a **Deploy go-cohort** button appears on the result. It opens a
deploy panel where you give an **artifact** — a download **URL**, a **filename**,
the expected **SHA-256**, and optional silent-install **arguments** — and confirm.
The deployment then, on exactly the devices that cleared:

1. **Stages** the installer — the agent downloads it and verifies the SHA-256 (a
   hash mismatch fails the device; the file is never executed).
2. **Executes** the staged installer once the hash is confirmed, and records the
   exit code.

The progress view is **aggregate-first**: a count strip (targeted / succeeded /
executing / in-flight / failed / skipped) and a progress bar are the headline, with
the per-device list below, problem-first. A device is **Succeeded** on exit 0,
**Failed** on a stage error or a non-zero exit, and **Skipped** if you no longer
have scope to it when the step is dispatched — it is never run.

Two safety properties matter because executing an installer changes the endpoint:

- **Run-once.** The execute step is claimed before it is dispatched, so an
  installer runs **at most once per device** even if you reload the page, several
  tabs poll at once, or the server restarts mid-deployment.
- **Re-authorization.** Every tick re-checks the devices you can currently see. A
  device that has dropped out of your scope since the pre-flight run is **skipped**,
  not executed.

A deployment is driven by the open page today; closing it pauses progress (the
state is durable) and reopening resumes. The same engine is designed to be driven
headless by an automation worker later.

## Permissions

| Action | Permission |
|---|---|
| View the page / a result / the rail | `Infrastructure:Read` |
| Run a pre-flight | `Infrastructure:Read` + `Execution:Execute` |
| Delete a saved run | `Execution:Execute` (and you must be the owner) |
| Open the deploy panel / view a deployment | `SoftwareDeployment:Read` |
| Deploy to a go-cohort / advance / delete a deployment | `SoftwareDeployment:Execute` (and you must be the owner) |

Pre-flight runs and deletes are recorded in the [audit log](audit-log.md) as
`preflight.run` and `preflight.run.delete`; deployments as `deployment.create`,
`deployment.advance`, and `deployment.delete`.
