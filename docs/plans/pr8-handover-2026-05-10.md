# PR 8 Handover — Intra-cube localhost edges

**Status:** Server + renderer code complete in working tree. **NOT committed.**
**NOT visually verified.** Held pending a working viz-UAT visual loop.

**Worktree:** `/Users/nathan/Yuzu-viz` on `feat/viz-engine` at HEAD `98576db`.
Diff is unstaged and uncommitted as of session end 2026-05-10.

## Why uncommitted

Visualisation is a visual feature. The renderer code is present and the
JSON wire shape verifies at the HTTP level, but no human has confirmed
the LineSegments actually draw between paired process dots in a browser.
Bundle-string presence ≠ correct render. Land only after a working visual
proof exists. The blocker is viz-UAT environment plumbing (see below),
not the PR-8 code.

## What was built

### Server (C++)

| File | Change |
|---|---|
| `server/core/src/fleet_topology_types.hpp` | New `ConnectionEdge::dst_pid` field; JSON `to_json` emits `dst_pid` only when non-zero; `TopologySnapshot::to_json` bumps `schema_minor` 1→2 |
| `server/core/src/fleet_topology_store.cpp` | `build_snapshot()` adds a pairing pass: for each `EdgeScope::Local` edge, search same machine's connections for the reciprocal half (swapped 4-tuple) and set `dst_pid = peer.src_pid`. Then `std::erase_if` drops any `Local` edge with `dst_pid == 0` (unmatched halves) |

Algorithm complexity: O(n²) per machine over connection count. Acceptable
for typical per-host connection counts; an `(addr,port) → pid` hash index
is a refactor candidate when n routinely exceeds a few hundred.

### Renderer (JS)

| File | Change |
|---|---|
| `server/core/static/yuzu-viz.js` | In `addMachines()` per-cube assembly: build a `pidToPos` Map alongside dots; after dot placement, for each Local-scope edge with finite `src_pid` and `dst_pid`, look up the two `THREE.Vector3` positions and add a `THREE.LineSegments(BufferGeometry from points, LineBasicMaterial({color:0xffffff, transparent:true, opacity:0.3}))` to the per-cube `processGroup` |

Disposal: lines join the per-cube `processGroup` and are released by
`clearFleet`'s `traverse(disposeNode)` walk — no separate edge index
required.

### Tests (Catch2)

| File | Cases added |
|---|---|
| `tests/unit/server/test_fleet_topology_store.cpp` | 6 new under `[pr8]` tag — reciprocal pair both ways; unmatched drop; non-Local untouched; JSON shape + `schema_minor=2` + `dst_pid` only-when-non-zero; IPv6 ::1 pair; two pairs on same machine no cross-match |
| `tests/unit/server/test_static_js_bundle.cpp` | 1 new under `[pr8]` — pins `scope !== 'local'`, `THREE.LineSegments`, `LineBasicMaterial`, `c.dst_pid` substring presence |

### Tests adjusted (existing contract change)

| File | Why |
|---|---|
| `tests/unit/server/test_fleet_topology_store.cpp` line 152 | "loopback connections classified as Local" — original used non-reciprocal pairs that would now be dropped; reshaped to two reciprocal pairs (one IPv4 + one IPv6) |
| `tests/unit/server/test_viz_routes.cpp` lines 142, 176 | Two `schema_minor == 1` assertions bumped to `== 2` |

### Docs

| File | Why |
|---|---|
| `docs/fleet-viz-invariants.md` | New "Edge invariants — PR 8" section documenting dst_pid resolution, drop-unmatched rule, schema_minor=2, renderer line construction, and `Number.isFinite` guards |

## Test status

```
build-macos/tests/yuzu_server_tests "[pr8]"
  All tests passed (45 assertions in 7 test cases)

build-macos/tests/yuzu_server_tests "[viz],[static-js]"
  All tests passed (476 assertions in 133 test cases)

build-macos/tests/yuzu_server_tests "[auth]"
  All tests passed (128 assertions in 50 test cases)   # sanity, unaffected
```

## Wire-level verification

`schema_minor=2` confirmed live against the rebuilt viz-UAT stack
(`http://localhost:8080/api/v1/viz/fleet/topology` returned 200, body
contains `"schema_minor":2`). End-to-end agent → server topology
population blocked by the proxy issue below.

## Blocker — viz-UAT environment

OrbStack (the user's Docker Desktop replacement) sets these env vars at
the host:

```
HTTP_PROXY=http://proxyproxy.orb.internal:8305
HTTPS_PROXY=http://proxyproxy.orb.internal:8305
NO_PROXY=localhost,127.0.0.1,...,gateway.docker.internal,...
```

Docker compose forwards these into containers. The agent container
attempts to call its gateway via the compose service hostname `gateway`,
which is **not** in NO_PROXY. The agent's gRPC client routes through the
proxy, which returns 502:

```
[error] Failed to register with server: failed to connect to all addresses;
        last error: UNKNOWN: ipv4:0.250.250.200:8305:
        HTTP proxy returned response code 502
[info] Reconnecting in 2s (attempt #1)
```

The result: agent never registers → server never gets a snapshot →
`/api/v1/viz/fleet/topology` returns `machines:[]` → no cubes, no
processes, no edges, nothing to render.

**Two-step fix when picking this up:**

1. Add `NO_PROXY=*` (or explicitly include `gateway` + `server` + `agent`)
   to each service in `deploy/docker/docker-compose.viz-uat.yml`, OR
   document that `start-viz-uat.sh` should `unset HTTP_PROXY HTTPS_PROXY`
   before `docker compose up`.
2. Even after the proxy is fixed: the agent container is
   `debian:trixie-slim` running only `yuzu-agent`. There are no
   loopback-talking peer processes to produce reciprocal half-pairs. To
   visually verify PR 8 you also need to **manufacture loopback traffic**,
   e.g. an entrypoint shim that backgrounds `nc -l 127.0.0.1:9999 &` plus
   `nc 127.0.0.1 9999 &` so the next `tar.fleet_snapshot` returns at
   least one reciprocal pair.

## Pickup sequence for next session

1. **Read** `git diff` on the worktree — that is PR 8.
2. **Fix viz-UAT proxy**: edit `deploy/docker/docker-compose.viz-uat.yml`
   to set `NO_PROXY=*` (or equivalent) per service.
3. **Manufacture loopback traffic** in the agent container (entrypoint
   nc-pair shim).
4. **Rebuild and start** viz-UAT.
5. **Open `http://localhost:8080/viz/fleet`** in a browser. Confirm:
   - Cube renders for the agent machine
   - Process dots appear inside the cube
   - Faint white lines connect the `nc` peer dots (opacity 0.3)
   - Lines disappear on cube clear / refresh
6. **Commit** as one or two commits (e.g. `feat(server,viz): pair
   loopback edges` + `feat(viz): render intra-cube edges`) and **PR
   against dev**.
7. **Run governance pipeline** on the commit range.

## Related context

- `#947` reopened — regression probes from `#948` triggered SIGSEGV on
  GHA `macos-15` PR fast-path. Bug is environment-specific (macOS 15 +
  AuthDB-attached path); diagnosis posted on the issue. Worktree at
  `/Users/nathan/Yuzu-947`.
- `#948` (regression probes) in **draft** until `#947` is fixed.
- Memory note `project_viz_engine_branch_2026-05-10.md` updated this
  session to reflect PR 8 in-flight state.

## File checklist for handover-resumption sanity

```
M  CLAUDE.md                                       # earlier trim, unrelated to PR 8
?? docs/agents/                                    # untracked, pre-existing
?? docs/fleet-viz-invariants.md                    # earlier trim extraction
?? docs/plans/pr8-handover-2026-05-10.md           # THIS FILE
M  server/core/src/fleet_topology_store.cpp        # PR 8 server
M  server/core/src/fleet_topology_types.hpp        # PR 8 wire
M  server/core/static/yuzu-viz.js                  # PR 8 renderer
M  tests/unit/server/test_fleet_topology_store.cpp # PR 8 + 1 adjustment
M  tests/unit/server/test_static_js_bundle.cpp     # PR 8
M  tests/unit/server/test_viz_routes.cpp           # schema_minor bump
```

When resuming, the first 4 entries above (CLAUDE.md, docs/agents,
fleet-viz-invariants, this handover) are independent of PR 8 and should
be committed separately or left for their own owners.
