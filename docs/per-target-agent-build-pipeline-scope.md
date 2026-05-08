# Per-target agent build pipeline — scope

**Status**: deferred. Phase 1 ready to execute; Phase 2 gated on #376
(Conan + QUIC migration) landing first.

**History**: scoped 2026-05-07. Decision to gate on #376 captured in
"Decisions captured from the user" §4 and "Resolved: out-of-scope work
this plan depends on" at the bottom.

## Context

Yuzu currently ships exactly one Linux agent build: amd64, glibc 2.39 (Ubuntu
24.04 base), produced by `deploy/docker/Dockerfile.agent` and the
`build-linux-x64` job in `.github/workflows/release.yml` (lines 36–234). That
single artifact does not run on the four other targets we just stood up:

| Target | Why current artifact won't run |
|---|---|
| OrbStack `yuzu` (Ubuntu 25.10 arm64) | Wrong arch; needs aarch64 binary |
| Debian bookworm-slim amd64 | glibc 2.36 < linker baseline 2.39 (`GLIBC_2.38`/`GLIBC_2.39` symbols) |
| Alpine 3.23.4 amd64 | musl ABI ≠ glibc; gcompat path proven dead by canary (see below) |
| Alpine 3.23.4 arm64 | musl + arch flip |

Goal: a build pipeline that produces an agent-only artifact for each of the
four targets. "Agent-only" means `yuzu-agent` + `libyuzu_agent_core.so` + the
44 plugin `.so`s — **without** the server, gateway, or test surface.

Pipeline runs locally on OrbStack first, with a clear migration path to
`release.yml` once each target is green.

## Strategic dependency: #376 (Conan + QUIC migration)

There is a **planned migration off vcpkg → Conan and off gRPC → QUIC** with
**protobuf retained** (issue #376; `.claude/agents/build-ci.md:181-183`).
Currently deferred behind customer commitments but planned. This migration
materially changes the Alpine scope:

**What goes away**: `gRPC` and its transitive deps `abseil`, `re2`,
`c-ares`, `upb`. These are exactly the ports with the worst musl story in
vcpkg today — the entire Phase 2.0 dry-run risk gate is them.

**What stays**: `protobuf`, `openssl`, `sqlite3`, `spdlog`, `nlohmann-json`,
`cli11`, `cpp-httplib`. All of these have first-class musl support in both
vcpkg and Conan.

**What's added**: a QUIC implementation (likely MsQuic per build-ci.md:183;
or quiche/lsquic/ngtcp2). MsQuic supports Linux x86_64 musl natively and
publishes Alpine packages.

**Conan's musl story**: Conan profiles natively express
`compiler.libc=musl`, recipes for the post-#376 dep set are well-tested on
musl, and Conan's cross-build story is more mature than vcpkg's. Combined
with the gRPC/abseil/re2 amputation, this collapses the Alpine risk from
"high — port debugging is the largest unknown in the plan" to "low —
straightforward Conan profile + musl build inside Alpine."

**Sequencing implication**: doing Alpine on the current vcpkg+grpc stack
means doing throwaway musl ports of abseil and grpc that #376 deletes.
Recommend Phase 2 (Alpine) be **gated on #376 landing**. Phase 1 (glibc
targets) is unaffected — bookworm and Ubuntu-arm64 build cleanly on the
current stack today.

If #376 cannot move forward in a useful timeframe and Alpine is needed
sooner, the original musl-on-vcpkg plan below remains executable but
should be understood as **a one-time use binary that gets thrown away
when #376 lands**.

## Decisions captured from the user

1. **Alpine path: musl-native rebuild.** gcompat-first was the original ask;
   a canary against the v0.11.0 release binary disproved it (see "Alpine
   canary" below). gcompat does not provide the glibc-2.38 / libstdc++-14
   symbols the binary references, and patching gcompat is not in scope.
2. **Artifacts**: OCI image per target + `.apk` for the two Alpine targets.
   No tarballs. No `.deb` in v1.
3. **CI timing**: `release.yml` integration deferred to Phase 3, after Phase
   1+2 are locally smoke-tested.
4. **Alpine sequencing vs #376**: **Pull #376 forward first, then do Alpine.**
   #376 is treated as a hard prerequisite to Phase 2, not as a parallel
   workstream. Scoping #376 itself is OUT OF SCOPE for this plan — it is a
   multi-week cross-cutting migration touching agent/server/gateway/SDK and
   needs its own scoping exercise (see `docs/dependency-rollout-2026-04-14.md`,
   `.claude/agents/build-ci.md:181-183`). This plan only describes how Phase
   2 (Alpine) executes ASSUMING #376 has landed.

## Alpine canary (evidence for the musl-native decision)

Pulled v0.11.0 `yuzu-linux-x64.tar.gz` from the GitHub release. Inside an
`alpine:3.23.4` container with `gcompat libstdc++ openssl` installed, ran
`yuzu-agent --version`. Failure. Salient missing symbols when
`libyuzu_agent_core.so` was loaded:

- **glibc 2.38+ C23 wrappers**: `__isoc23_strtoul`, `__isoc23_strtoll`,
  `__isoc23_strtol`, `__isoc23_strtoull`, `__isoc23_sscanf`. These are
  emitted by `gcc-13`'s `<stdlib.h>` when compiled against glibc 2.38+
  headers; gcompat does not provide them.
- **glibc-specific syscall wrappers**: `fcntl64`. Musl uses unsuffixed
  `fcntl`.
- **glibc-specific RNG**: `arc4random_buf`. Musl 1.2+ ships this, but the
  binary references it via glibc symbol versioning that gcompat doesn't
  expose.
- **libstdc++ `__float128` `to_chars`**: `_ZSt8to_charsPcS_DF128_*`. The
  Alpine libstdc++ does not export these on x86_64 because Alpine builds
  gcc without `__float128` support.

`scanelf -n` confirmed every plugin `.so` and the agent binary all reference
`libc.so.6 libstdc++.so.6 libgcc_s.so.1 libm.so.6 ld-linux-x86-64.so.2` plus
`libyuzu_agent_core.so` — i.e. they share the same glibc/libstdc++ symbol
surface that the canary just rejected. Patching one library doesn't help;
the whole stack needs musl-native rebuilds.

---

## What's already wired up (reusable)

| Asset | Path | Coverage |
|---|---|---|
| Cross file for aarch64 glibc | `meson/cross/aarch64-linux-gnu.ini` | Reusable as-is |
| Triplet inference | `scripts/setup.sh:75-81` (maps `*aarch64*` → `arm64-linux`) | Reusable; expects a triplet file we still need to create |
| Build-only-the-agent flag | `meson.build:80-83` (`-Dbuild_server=false`) | Reusable |
| Dynamic linkage default triplet | `triplets/x64-linux-asan.cmake`, `triplets/x64-linux-static.cmake` | Pattern to copy for `arm64-linux` |
| Plugin loader portability | `agents/core/src/plugin_loader.cpp:8-27` (`dlopen` + `.so` on Unix) | Works on musl; portable |
| OpenSSL dependency | unconditional in `vcpkg.json:20` | Must satisfy on every target; vcpkg openssl supports musl |
| Docker buildx multi-arch | OrbStack's `default` and `orbstack` builders advertise `linux/amd64`+`linux/arm64`+`linux/arm/v7` | Avoids needing a separate ARM64 runner for local builds |
| Existing `Dockerfile.agent` template | `deploy/docker/Dockerfile.agent:1-53` | Direct template for the bookworm and Ubuntu-arm64 Dockerfiles |

---

## What's missing (net-new work)

1. **One vcpkg triplet** (Phase 1 only — vcpkg goes away in #376):
   - `triplets/arm64-linux.cmake` — referenced by `scripts/setup.sh` but no file in `triplets/`.

2. **Conan profiles** (Phase 2, post-#376):
   - `conan/profiles/linux-musl-x86_64`
   - `conan/profiles/linux-musl-aarch64`
   - (And whatever profiles #376 establishes for the existing glibc/Windows/macOS targets — those land in #376, not here.)

3. **Three Dockerfiles**:
   - `deploy/docker/Dockerfile.agent-debian-bookworm` (amd64) — Phase 1
   - `deploy/docker/Dockerfile.agent-ubuntu-arm64` (Ubuntu 24.04, arm64) — Phase 1
   - `deploy/docker/Dockerfile.agent-alpine` (Alpine 3.23.4 builder + runtime, parameterised by `--platform`) — Phase 2

4. **Dep posture post-#376** (Phase 2 risk register):
   - `openssl`, `sqlite3`, `spdlog`, `nlohmann-json`, `cli11`, `cpp-httplib`, `protobuf` — all build cleanly on musl via Conan recipes.
   - QUIC library — pick depends on #376; MsQuic and ngtcp2 both have published musl support.
   - `abseil`, `grpc`, `re2`, `c-ares`, `upb` — **gone**. The historical Phase 2 risk evaporates.

5. **`.apk` packaging for Alpine** (Phase 2):
   - `deploy/packaging/alpine/APKBUILD` template
   - `deploy/packaging/alpine/build-apk.sh` (mirrors `deploy/packaging/debian/build-deb.sh:1-152`)
   - OpenRC service file `deploy/packaging/alpine/yuzu-agent.initd` (modeled on `deploy/systemd/yuzu-agent.service:1-28`)

6. **`install-agent-user.sh` Alpine branch** (Phase 2):
   - Currently rejects any `uname -s` that isn't `Darwin` or `Linux` (lines 120–157). The Linux branch assumes systemd, `/etc/sudoers.d/`, `systemd-journal` group.
   - Add distro detection via `/etc/os-release` and a parallel Alpine path: no `systemd-journal` group; OpenRC unit instead of systemd; `setcap` still works (Alpine has `libcap`).
   - Bookworm and Ubuntu-arm64 do NOT need any change — they use the existing Linux/systemd path.

7. **Plugin runtime survey on Alpine** (test-time, not build-time):
   - `agents/plugins/quarantine` — uses `/usr/sbin/iptables` (works on Alpine if `iptables` apk installed).
   - `agents/plugins/services` — uses `systemctl` (broken on Alpine; no-op on this image, log and continue).
   - `agents/plugins/firewall` — runtime-detects iptables/pfctl (works).
   - `agents/plugins/network_actions` — needs spot-check (Phase 2 task).
   - **v1 policy: ship the full plugin set; plugins that need systemd no-op on Alpine.** Document in the Dockerfile header. OpenRC ports are backlog work.

---

## Recommended architecture

**One Dockerfile per target, multi-stage, build-inside-the-target.** Same
pattern as the existing `Dockerfile.agent` but with the base image swapped.
For the two glibc targets this is straightforward. For Alpine, both stages
run on Alpine — Conan, gcc, meson, and the agent itself all build natively
against musl.

### Build matrix

| # | Target | Builder base | Runtime base | Build deps tooling | Buildx platform |
|---|---|---|---|---|---|
| 1 | Ubuntu 24.04 arm64 | `ubuntu:24.04` (arm64) | `ubuntu:24.04` (arm64) | vcpkg, triplet `arm64-linux` (NEW) | `linux/arm64` |
| 2 | Debian bookworm amd64 | `debian:bookworm-slim` | `debian:bookworm-slim` | vcpkg, triplet `x64-linux` (gcc-13 from `bookworm-backports`) | `linux/amd64` |
| 3 | Alpine 3.23.4 amd64 | `alpine:3.23.4` (amd64) | `alpine:3.23.4` (amd64) | Conan, profile `linux-musl-x86_64` (post-#376) | `linux/amd64` |
| 4 | Alpine 3.23.4 arm64 | `alpine:3.23.4` (arm64) | `alpine:3.23.4` (arm64) | Conan, profile `linux-musl-aarch64` (post-#376) | `linux/arm64` |

For #1, `--platform linux/arm64` makes the build happen as if on arm64 (qemu
emulation under buildx, native on Apple Silicon). The toolchain inside
`ubuntu:24.04` arm64 builds for arm64 naturally. No cross file needed.

For #2, bookworm ships gcc-12 by default; gcc-13 lives in
`bookworm-backports`. The Dockerfile must enable that source. Acceptable;
documented inline.

For #3 and #4, the build runs entirely inside Alpine using the Conan
toolchain that #376 establishes. `apk add build-base gcc g++ cmake ninja
meson python3 git pkgconfig openssl-dev linux-headers` plus `pip install
conan` gives us the toolchain; Conan resolves deps against the musl
profile. Plugin `.so`s, `libyuzu_agent_core.so`, and `yuzu-agent` are all
musl-linked ELF.

### Output artifacts (per target)

For each target we produce **one OCI image**:

- `yuzu-agent:ubuntu-24.04-arm64`
- `yuzu-agent:debian-bookworm-amd64`
- `yuzu-agent:alpine-3.23.4-amd64`
- `yuzu-agent:alpine-3.23.4-arm64`

Plus, for the two Alpine targets only, an **`.apk` package**:

- `dist/yuzu-agent-<version>-r0.x86_64.apk`
- `dist/yuzu-agent-<version>-r0.aarch64.apk`

The `.apk` ships the same files the OCI image holds in `/usr/local/bin` and
`/usr/lib/yuzu/plugins`, plus the OpenRC init script at
`/etc/init.d/yuzu-agent`. Built via `abuild` inside the Alpine OCI image.

### Driver script

A single `scripts/build-agent-target.sh <target>` that:

1. Resolves `<target>` → (Dockerfile, build context, platform, image tag).
2. Runs `docker buildx build --platform <platform> --load -t <tag> -f <Dockerfile> .`.
3. For Alpine targets, additionally runs `abuild` inside the resulting
   image, then `docker cp` the produced `.apk` out to `dist/`.
4. Echoes the resulting image tag, size, and (for Alpine) `.apk` path.

Targets list lives in a small associative array at the top of the script —
adding a 5th target later is editing one block.

---

## Phasing

**Phase 1 — Glibc targets (low risk, ~½ day)**

- Add `triplets/arm64-linux.cmake` (clone `triplets/x64-linux-static.cmake`, set `VCPKG_TARGET_ARCHITECTURE arm64`, dynamic linkage).
- Write `Dockerfile.agent-ubuntu-arm64` (clone of `Dockerfile.agent` with `--platform linux/arm64` discipline; vcpkg triplet=`arm64-linux`).
- Write `Dockerfile.agent-debian-bookworm` (swap base to `debian:bookworm-slim`, add `bookworm-backports` for gcc-13, vcpkg triplet=`x64-linux`).
- Write `scripts/build-agent-target.sh` with these two targets initially.
- Smoke test: `--version`, plugin `.so` count = 44, `ldd` shows no missing symbols, agent registers against the existing UAT server.

**Phase Interlude — #376 (Conan + QUIC migration)**

Hard prerequisite to Phase 2. Not scoped here. Scope this in a separate
plan; expected shape:

- vcpkg → Conan migration (every target, not just Alpine)
- gRPC → QUIC (likely MsQuic) migration touching agent, server, gateway, SDK
- protobuf retained
- abseil, re2, c-ares, upb deleted from dep graph
- New transport implementation, mTLS preserved
- Multi-week effort per `.claude/agents/build-ci.md:183`

This plan resumes at Phase 2 once #376 closes.

**Phase 2 — Alpine via Conan musl-native (~1 day after #376)**

With abseil/grpc/re2/c-ares deleted from the dep graph and a Conan musl
profile available, Phase 2 collapses to "set the profile, build, smoke
test."

- **2.0** Author a Conan musl profile per arch (`profiles/linux-musl-x86_64`, `profiles/linux-musl-aarch64`). Verify `protobuf openssl sqlite3 spdlog nlohmann-json cli11 cpp-httplib <quic-lib>` install cleanly inside Alpine 3.23.4 against each profile.
- **2.1** Write `Dockerfile.agent-alpine` (Alpine builder + runtime, both stages musl-native). Build amd64 first.
- **2.2** Smoke test: `--version` succeeds, plugin `.so` count = 44, `scanelf -n yuzu-agent` shows `ld-musl-*.so.1` and NOT `libc.so.6`, agent registers against UAT.
- **2.3** Add arm64 (second Conan profile, second buildx target).
- **2.4** `.apk` packaging: `deploy/packaging/alpine/APKBUILD`, `build-apk.sh`, `yuzu-agent.initd` (OpenRC). Wire into driver script. Smoke test: `apk add ./yuzu-agent-*.apk` inside a fresh Alpine container, `rc-service yuzu-agent start`, verify the agent talks to UAT.
- **2.5** Edit `scripts/install-agent-user.sh` to add an Alpine branch (distro detection via `/etc/os-release`, OpenRC unit install, no `systemd-journal` group).

**Phase 3 — CI integration (separate scope, deferred)**

- Unsuspend the Linux ARM64 job in `release.yml:236-243`.
- Add Debian bookworm and Alpine matrix entries.
- Update `scripts/check-compose-versions.sh:37-44` if any compose file
  starts referencing the new images.
- Decide on `ghcr.io/tr3kkr/yuzu-agent:*` tagging convention for
  per-target images (e.g. `:0.10.0-debian-bookworm`).
- Out of scope until Phase 1 and Phase 2 binaries are smoke-tested locally.

---

## Critical files

| File | Action | Phase |
|---|---|---|
| `triplets/arm64-linux.cmake` | NEW — clone of `triplets/x64-linux-static.cmake`; arch=arm64; linkage=dynamic | 1 |
| `deploy/docker/Dockerfile.agent-ubuntu-arm64` | NEW — clone of `deploy/docker/Dockerfile.agent` with arm64 wiring | 1 |
| `deploy/docker/Dockerfile.agent-debian-bookworm` | NEW — bookworm-slim base, gcc-13 from backports | 1 |
| `scripts/build-agent-target.sh` | NEW — driver, extended each phase | 1, 2 |
| `conan/profiles/linux-musl-x86_64` | NEW (Phase 2; assumes #376's Conan layout exists) | 2 |
| `conan/profiles/linux-musl-aarch64` | NEW | 2 |
| `deploy/docker/Dockerfile.agent-alpine` | NEW — Alpine builder + runtime, parameterised by `--platform` | 2 |
| `deploy/packaging/alpine/APKBUILD` | NEW | 2 |
| `deploy/packaging/alpine/build-apk.sh` | NEW — mirrors `deploy/packaging/debian/build-deb.sh:1-152` | 2 |
| `deploy/packaging/alpine/yuzu-agent.initd` | NEW — OpenRC, modeled on `deploy/systemd/yuzu-agent.service:1-28` | 2 |
| `scripts/install-agent-user.sh` | EDIT — add Alpine branch in the `case "$OS"` block at lines 120–157, distro detection via `/etc/os-release` | 2 |

No edits required in any phase to: `meson.build`, `vcpkg.json`,
`agents/core/`, any plugin source, the existing `Dockerfile.agent`. The
`-Dbuild_server=false` flag and existing portable code do all the work.

---

## Verification

**Phase 1 smoke tests** (each new image):

```bash
# 1. Build
bash scripts/build-agent-target.sh ubuntu-24.04-arm64
bash scripts/build-agent-target.sh debian-bookworm-amd64

# 2. Binary launches
docker run --rm --platform linux/arm64 yuzu-agent:ubuntu-24.04-arm64 --version
docker run --rm --platform linux/amd64 yuzu-agent:debian-bookworm-amd64 --version

# 3. Plugin .so files are present and openable
docker run --rm yuzu-agent:debian-bookworm-amd64 \
    sh -c 'ls /usr/lib/yuzu/plugins/ | wc -l'   # expect 44
docker run --rm yuzu-agent:debian-bookworm-amd64 \
    sh -c 'for p in /usr/lib/yuzu/plugins/*.so; do
             ldd "$p" 2>&1 | grep -q "not found" && echo MISS:$p
           done'                                  # expect no output

# 4. End-to-end: agent registers with the existing UAT server
bash scripts/start-UAT.sh                         # bring up server+gateway
docker run --rm --network host \
    yuzu-agent:debian-bookworm-amd64 \
    --server localhost:50051 --no-tls
# observe Register + heartbeat in server log
```

**Phase 2 dry-run gate (assumes #376 Conan recipes are merged)**:

```bash
docker run --rm -it --platform linux/amd64 alpine:3.23.4 sh -c '
  apk add --no-cache build-base cmake ninja meson python3 py3-pip git \
    pkgconfig openssl-dev linux-headers && \
  pip install --break-system-packages conan && \
  cd /yuzu && conan install . \
    --profile=conan/profiles/linux-musl-x86_64 \
    --build=missing
'
# Success → Phase 2.1+. Failure → an unexpected post-#376 dep regression; surface and pause.
```

**Phase 2 smoke tests** (each Alpine image):

- Same `--version` / plugin-load / register sequence.
- `scanelf -n yuzu-agent` should NOT show `libc.so.6` — only `ld-musl-*.so.1`.
- `apk add ./yuzu-agent-*.apk` install round-trip:
  ```bash
  docker run --rm -v "$PWD/dist:/dist" alpine:3.23.4 sh -c '
    apk update && apk add openrc && \
    apk add --allow-untrusted /dist/yuzu-agent-*.apk && \
    rc-service yuzu-agent start && \
    sleep 2 && rc-service yuzu-agent status
  '
  ```

**Pipeline self-test** (after Phase 2):

```bash
for t in ubuntu-24.04-arm64 debian-bookworm-amd64 alpine-3.23.4-amd64 alpine-3.23.4-arm64; do
  bash scripts/build-agent-target.sh "$t" || echo "FAIL: $t"
done
docker images --format '{{.Repository}}:{{.Tag}}\t{{.Size}}' | grep yuzu-agent | sort
ls -la dist/*.apk
```

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **#376 stalls indefinitely → Alpine blocked** | Low-Medium | Medium | Fallback: redo this scope on the current vcpkg+grpc stack with musl ports of abseil/grpc/re2; treat as one-time-use binary that gets thrown away when #376 eventually lands |
| **#376 lands but its Conan recipes don't include musl profiles** | Low | Medium | Phase 2.0 dry-run gate catches this; scope's Phase 2 then expands to author the missing Conan musl profiles |
| Bookworm gcc-13 not available without enabling `bookworm-backports` | High | Low | Document the apt source in the Dockerfile; alternative: clang-16 from bookworm main |
| musl `arc4random_buf` semantics differ from glibc's | Low | Low | musl 1.2.0+ provides it; Alpine 3.23.4 ships musl 1.2.5+. No code changes needed |
| `services` plugin no-ops on Alpine (no systemd) | High | Low | Document in Dockerfile header; OpenRC port is backlog |
| `arm64` build via buildx emulation is slow on Intel macOS | N/A here (Apple Silicon) | — | — |
| `release.yml` ARM64 job unsuspend exposes infra dep on a runner | Medium | Medium | Phase 3 only; not on critical path for local dev |
| musl libstdc++ ABI surprises in plugin `dlopen` | Medium | Medium | All plugins built in same musl pipeline as core, so ABI is consistent. Risk is from third-party plugins post-launch — out of scope here |
| `abuild` build inside our own image needs a non-root abuilder user | Medium | Low | Standard Alpine packaging pattern; documented in `deploy/packaging/alpine/build-apk.sh` |

---

## Resolved: out-of-scope work this plan depends on

**#376 (Conan + QUIC migration)** is a hard prerequisite to Phase 2 and is
explicitly not scoped here. It needs its own scoping document covering:

- Conan recipe authoring or migration for every existing dep (protobuf,
  openssl, sqlite3, spdlog, nlohmann-json, cli11, cpp-httplib).
- QUIC library selection (MsQuic vs ngtcp2 vs quiche vs lsquic), with
  Linux/macOS/Windows + glibc/musl support matrix.
- Transport rewrite in `proto/`, `agents/core/`, `server/core/`, `gateway/`,
  `sdk/` — replacing gRPC bidirectional streams (Subscribe, Register,
  GatewayUpstream, ManagementService) with QUIC primitives.
- mTLS preservation across the new transport.
- vcpkg → Conan cutover for CI runners (Linux self-hosted, Windows local,
  macos-15) including cache strategy migration.
- Removal of the `triplets/x64-windows.cmake` static-link override and the
  `meson.build` Windows-specific `cxx.find_library()` block (#375 option D
  becomes obsolete; that's much of the value).
- Removal of the #501 absl-DLL-seed mismatch test workarounds.

When #376 closes, this plan's Phase 2 picks up.
