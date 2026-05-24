# Agent bundle — three-triplet delivery image

A single **chiselled** (FROM scratch) container image that carries the Yuzu
agent for three target triplets at one pinned version:

| Triplet | OS / arch | Toolchain | Signing |
|---|---|---|---|
| `linux-x64` | Linux x86_64 (glibc) | GCC | — |
| `windows-x64` | Windows x86_64 | MSVC | Authenticode |
| `macos-arm64` | macOS Apple Silicon | Apple Clang | notarized |

It exists so a design partner who can only **`docker pull`** can still get the
right agent onto every endpoint OS — the companion to the chiselled
server/gateway demo images (`docs/demo-environment.md`).

Image: `ghcr.io/<owner>/yuzu-agent-bundle-chisel:<version>`

> ⚠ **This is a delivery vehicle, not a runtime.** A Linux container cannot run
> a Windows `.exe` or a macOS Mach-O. The image stores the binaries and offers a
> busybox userland to copy them out — nothing in it executes the agents. To
> *run* a Linux agent in a container, use `yuzu-agent-chisel` instead.

## Why it's assembled from release artifacts (not built from source)

The Windows (MSVC) and macOS (Apple Clang) agents **cannot be cross-built in a
Linux Docker stage** — they require their native toolchains. So this image is
not compiled: `scripts/build-agent-bundle.sh` downloads the signed/notarized
per-platform archives **and** native installers from the matching GitHub
*release*, verifies them against the release `SHA256SUMS`, lays them out under
`/opt/yuzu-agents`, and bakes that tree into the chiselled image. This is the
same provenance customers get from the Releases page — just packaged for
`docker pull`.

Each triplet ships **both** forms:

```
/opt/yuzu-agents/
  README.txt              VERSION   SHA256SUMS   UPSTREAM-SHA256SUMS
  linux-x64/
    installers/   yuzu-agent_<v>_amd64.deb   yuzu-agent-<v>.x86_64.rpm
    payload/      bin/yuzu-agent  bin/libyuzu_agent_core.so  plugins/*.so
  windows-x64/
    installers/   YuzuAgentSetup-<v>.exe
    payload/      bin/yuzu-agent.exe  bin/yuzu_agent_core.dll  bin/*.dll  plugins/*.dll
  macos-arm64/
    installers/   YuzuAgent-<v>-macos-arm64.pkg
    payload/      bin/yuzu-agent  bin/libyuzu_agent_core.dylib  plugins/*.dylib
```

- **`payload/`** — raw agent binary + core library + plugins (Windows also gets
  the vcpkg runtime DLLs). Sideload / run-in-foreground. The natural fit for the
  **no-TLS demo stack** because you pass `--no-tls` directly.
- **`installers/`** — native packages that install a background service and a
  dedicated user. The fit for a **persistent / real (TLS) deployment**. Note the
  installers default to TLS on, so add `--no-tls` if you point them at the demo.

## Build & publish (maintainers)

```bash
# Build locally for your host arch (downloads + verifies + assembles + smoke-tests):
bash scripts/build-agent-bundle.sh                      # default version

# Pin a specific release and push a single-arch image:
bash scripts/build-agent-bundle.sh --version 0.11.0 --push

# Multi-arch (so arm64 and amd64 hosts both pull natively) — pushes to the registry:
bash scripts/build-agent-bundle.sh --multiarch --push
```

The script verifies all seven artifacts against the release `SHA256SUMS` and
**refuses to build** on mismatch; when `gh` is present it also best-effort
verifies the SLSA provenance attestation. Registry owner is derived from
`origin` (override with `--registry`); image name with `--image-name`.

### Version pinning

The default version tracks the latest release line that has published
Windows/macOS agent artifacts. The demo server/gateway are on the **0.12.0**
line, but there is no `v0.12.0` *final* release yet — only **`v0.12.0-rc0`**
carries the three platform archives — so the current default is `0.12.0-rc0`.
**Bump the `VERSION` default in `scripts/build-agent-bundle.sh` to `0.12.0` once
the v0.12.0 GA release publishes its artifacts**, so the bundle matches the demo
stack exactly.

## Use it (partner)

```bash
docker pull ghcr.io/<owner>/yuzu-agent-bundle-chisel:<version>

# Self-extract the whole tree into ./yuzu-agents/ :
docker run --rm -v "$PWD:/out" ghcr.io/<owner>/yuzu-agent-bundle-chisel:<version>

# …or copy it out without running anything in the container:
cid=$(docker create ghcr.io/<owner>/yuzu-agent-bundle-chisel:<version>)
docker cp "$cid:/opt/yuzu-agents" .
docker rm "$cid"

# Other entrypoint verbs:
docker run --rm <img> list     # recursive listing
docker run --rm <img>          # prints the bundle README
```

Then copy the directory for each endpoint's OS onto that machine and follow its
`README.txt`. Quick reference (point every agent at the **gateway's** agent port
`50051` and the enrollment token from the demo, e.g.
`/tmp/yuzu-demo/enrollment-token`):

**Linux** — foreground (demo):
```bash
cd yuzu-agents/linux-x64/payload
LD_LIBRARY_PATH="$PWD/bin" ./bin/yuzu-agent \
  --server <GATEWAY_HOST>:50051 --no-tls --enrollment-token <TOKEN> \
  --plugin-dir "$PWD/plugins" --data-dir ./data --log-level info
```
Persistent: `sudo apt-get install ./installers/<deb>` (or `dnf install ./installers/<rpm>`),
then `sudo systemctl edit yuzu-agent` to set `--server`/`--enrollment-token`
(+ `--no-tls` for the demo) and `sudo systemctl enable --now yuzu-agent`.

**macOS** — foreground (demo):
```bash
cd yuzu-agents/macos-arm64/payload
DYLD_LIBRARY_PATH="$PWD/bin" ./bin/yuzu-agent \
  --server <GATEWAY_HOST>:50051 --no-tls --enrollment-token <TOKEN> \
  --plugin-dir "$PWD/plugins" --data-dir ./data --log-level info
```
Persistent: `sudo installer -pkg installers/<pkg> -target /`, then add
`--server`/`--enrollment-token` to `/Library/LaunchDaemons/com.yuzu.agent.plist`
and `launchctl bootstrap system …`.

**Windows** — foreground (demo, PowerShell):
```powershell
cd yuzu-agents\windows-x64\payload
.\bin\yuzu-agent.exe --server <GATEWAY_HOST>:50051 --no-tls `
  --enrollment-token <TOKEN> --plugin-dir .\plugins --data-dir .\data --log-level info
```
Persistent: run `installers\YuzuAgentSetup-<v>.exe` (enter gateway + token on the
config page), or `… /VERYSILENT /SUPPRESSMSGBOXES /TOKEN=<TOKEN>`. Service name
`YuzuAgent`.

## Verify integrity

Every file is checksummed twice over:

```bash
cd yuzu-agents
sha256sum -c SHA256SUMS          # checksums of the laid-out tree
# UPSTREAM-SHA256SUMS is the signed checksum manifest from the GitHub release.
```

The Windows binaries are Authenticode-signed and the macOS binaries are
notarized; those signatures are embedded in the files and survive the
copy in/out of the image. If macOS quarantines a copied file, clear it with
`xattr -dr com.apple.quarantine <dir>`.

## Files

- `deploy/docker/Dockerfile.agent-bundle.chisel` — the chiselled assembler.
- `scripts/build-agent-bundle.sh` — download → verify → lay out → build → (push).
- This doc.
