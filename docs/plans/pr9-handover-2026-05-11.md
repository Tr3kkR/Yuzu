# PR 9 Handover — Cross-machine + external edges

**Status:** Next rung on the `feat/viz-engine` ladder. Nothing started yet —
this is a pickup brief, not in-flight work.

**Branch:** `feat/viz-engine` at `cb80a28` (PR 8 shipped + visually verified
end-to-end, pushed to `origin/feat/viz-engine`).

**Date of brief:** 2026-05-11.

## Where things stand

PRs 1–8 of the 11-PR ladder are complete and pushed. Eight of eleven PRs
done. The visualisation today renders:

- Cubes for each fleet machine (PR 6)
- Process dots inside each cube, coloured by category (PR 7)
- **Faint white lines between paired loopback peers inside each cube (PR 8, just landed `cb80a28`)**

The wire shape is `fleet_topology.v1` `schema_minor=2`. The renderer
bundle is ~50 KB against an 80 KB ceiling. Local edges are paired
server-side via reciprocal 4-tuple matching; unmatched halves dropped.

## PR 9 scope (per `docs/plans/feat-viz-engine-plan-2026-05-09.md` § PR 9)

> **Demo:** visible cross-cube traffic lines; faded edges to a single dark
> "External" sphere for non-fleet remote_addrs.
>
> - Server already produced `dst_agent_id` per edge in PR 2.
> - For each `INTERNAL_FLEET` edge: surface socket marker (small sphere) on
>   the cube face nearest the destination cube, edge from process →
>   source-side socket → dest-side socket → dest process.
> - For each `EXTERNAL` edge: faded edge to a single dark sphere fixed at
>   `(0, 30, 0)` labelled "External".
> - **Edge bundling**: when `≥8` edges between a cube pair, replace with a
>   single thicker edge labelled `Nx`.

The server already classifies edges as `InternalFleet` / `External` and
sets `dst_agent_id` for InternalFleet. PR 9 is therefore primarily a
**renderer change** with one server-side enrichment:

| Layer | Work |
|---|---|
| Server | None required for InternalFleet (already classified + `dst_agent_id` set). For External: consider whether the renderer needs help resolving `dst_addr` → an externalised name / org for the tooltip; reuses existing `dst_addr` field. Could be a stretch goal. |
| Renderer | Cross-cube edge geometry — pick the face on each cube nearest the peer; pin a socket marker (small sphere) at that face; line from process → src socket → dst socket → process. Then bundling: pre-aggregate ≥8 edges per cube-pair into one labelled line. External sentinel: one fixed sphere at `(0, 30, 0)`. |
| Tests | Server: assert `dst_agent_id` survives the new path; no new server tests strictly required. Renderer: bundle-string smoke pins for `InternalFleet`, `External`, the sentinel position, and edge-bundling count threshold. |

## Pickup sequence

1. **Run R8 governance on `cb80a28` BEFORE starting PR 9.** PR 8 shipped
   without a hardening round; the standing convention is `/governance
   <range>` after each feature PR. Likely findings: arch-S1 (lockstep
   registration array including the new `edgeMeshes`-equivalent — PR 8 added
   line meshes to `processGroup` without a top-level index, which PR 9 will
   want for raycast hover); arch-S3 (`__internal` snapshot test); per-host
   pairing O(n²) refactor candidate noting the (addr,port)→pid hash
   alternative.

2. **Plan PR 9 with the user.** Open questions:
   - Edge geometry: straight 4-segment polyline (process → face → face →
     process) vs Bézier curve? The plan doc says straight; a curve hides
     z-fighting at high edge density.
   - Socket markers per face: keep them visible always, or only on hover?
   - Edge-bundling: ≥8 is the plan-doc threshold; consider operator-tunable.

3. **Start in TDD per PR 7/8 cadence**. Server tests first (likely a small
   sanity-pin set — most of the InternalFleet machinery is already tested
   from PR 2). Renderer changes go into `static/yuzu-viz.js` and are
   bundle-smoke-tested in `tests/unit/server/test_static_js_bundle.cpp`.

4. **Visual proof before commit** is mandatory per `feedback_visual_features
   _need_visual_proof`. PR 9 visual requires:
   - Two registered agents (the current rig only has one — the OrbStack
     `yuzu` VM)
   - At least one INTERNAL_FLEET connection between them
   - At least one EXTERNAL connection (anything reaching out to the
     internet — `apt update`, `curl example.com`, etc.)

5. **Add a second agent for visual proof.** Options in order of cleanness:
   - Spin up a second OrbStack VM (`orb create ubuntu another-yuzu` then
     repeat the staging from `pr8-handover` § "Pickup sequence") — gives a
     real second host with real services
   - Add a second container in the compose under the `in-container-agent`
     profile and have the two hosts talk to each other via the bridge
     network (this would only produce inter-container traffic, which today
     classifies as `External` because no `local_ips` overlap with fleet
     IPs — server-side classification work might be needed first)
   - **Recommendation: real second VM.** The InternalFleet path is the
     headline; spending the bringup time once unlocks PR 9 + PR 10 visuals.

## Current running state — tear down

These are still running at session close 2026-05-11:

```
docker ps                          # yuzu-viz-server + yuzu-viz-gateway
orb -m yuzu pgrep -af yuzu-agent   # agent PID 6482 (registered)
orb -m yuzu systemctl status \
    yuzu-redis-poker yuzu-pg-poker # transient pokers (likely already
                                   # exited; 2-second loops between sleeps)
```

**To tear down completely** (do this before the next session if you don't
need the live demo):

```bash
# Stop VM agent + pokers + viz-UAT containers
orb -m yuzu sudo pkill -f yuzu-agent
orb -m yuzu sudo systemctl stop yuzu-redis-poker.service yuzu-pg-poker.service 2>/dev/null || true
bash scripts/start-viz-uat.sh stop
```

**To keep the rig and just refresh** (faster for next session):

```bash
# Just stop the agent; viz-UAT containers stay up
orb -m yuzu sudo pkill -f yuzu-agent
# Later, regenerate enrollment token and re-launch:
VIZ_UAT_AGENT_MODE=vm bash scripts/start-viz-uat.sh restart
# (then re-run the agent on the VM with the new token)
```

The OrbStack VM `yuzu` (Ubuntu Questing arm64, 24 GB allocated) has
postgres + redis + prometheus + node_exporter installed; tearing down the
agent doesn't tear those down. They'll be running idle. Cost: a few hundred
MB of RAM.

## Anti-mistakes (learned this session)

1. **OrbStack VM → host = `192.168.139.2`, not `.1`.** Default-route IP
   answers ICMP but no TCP forwards. See
   `memory/reference_orbstack_vm_addressing.md`. The launcher's printed
   gateway-IP guess is wrong on contact — set it correctly.

2. **OrbStack injects `HTTP_PROXY=proxyproxy.orb.internal:8305` into every
   container** by default. gRPC honours it and 502s. Any new compose
   service needs `NO_PROXY=*` per `docker-compose.viz-uat.yml`.

3. **Real loopback traffic only.** Don't manufacture `nc` pairs to satisfy
   visual proof — the OrbStack VM with Prometheus scraping node_exporter is
   the canonical rig, and the visual that lands from real services is the
   one that proves the feature.

4. **Run R8 governance on `cb80a28` BEFORE PR 9.** Established convention
   per CLAUDE.md; deferring it just compounds the next round.

## Cross-references

- Master plan: `docs/plans/feat-viz-engine-plan-2026-05-09.md`
- Standing invariants: `docs/fleet-viz-invariants.md` (includes PR 8 edge
  invariants section added today)
- Threat Graph roadmap: `docs/plans/threat-graph-roadmap.md` (post-PR-11
  direction; not blocking PR 9)
- Memory: `project_viz_engine_branch_2026-05-10.md`, `reference_orbstack
  _vm_addressing.md`, `feedback_visual_features_need_visual_proof.md`
