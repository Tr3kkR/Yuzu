#!/usr/bin/env bash
#
# Verify the healthcheck RUNTIME INVARIANTS of the Yuzu container images (#751).
#
# Every Yuzu compose file healthchecks its containers with a probe that depends
# on a tool baked into the image, not on the application:
#
#   deploy/docker/Dockerfile.server         bash + /dev/tcp   (apt-installed bash)
#   deploy/docker/Dockerfile.gateway        busybox wget --spider   (alpine busybox)
#   deploy/docker/Dockerfile.server.chisel  /bin/busybox wget --spider
#   deploy/docker/Dockerfile.gateway.chisel /bin/busybox wget --spider
#   deploy/docker/Dockerfile.agent.chisel   /bin/busybox wget --spider
#
# Those dependencies are invisible to the application and to every test we run:
# a base-image swap (trixie-slim -> a variant without bash), a dropped apt
# package, or a chisel slice change that stops shipping the busybox symlink
# breaks nothing at build time and nothing at boot. It breaks only the
# healthcheck -- so Compose parks every container in `unhealthy` forever, and
# anything with `depends_on: condition: service_healthy` never starts. The
# application itself is fine, which is what makes it so easy to ship.
#
# This script is the gate. It runs each image's REAL healthcheck probe against
# a known-good HTTP listener and requires it to succeed.
#
# Why a live listener rather than a bare capability check: the obvious probe --
# connect to a closed port and accept "connection refused" -- cannot tell a
# working bash from a bash built without /dev/tcp. Both exit 1 (a bash without
# net redirections treats /dev/tcp/... as an ordinary missing file). Probing
# against a listener that IS accepting connections collapses that ambiguity:
# exit 0 is the only passing outcome, so a bash that has lost /dev/tcp fails
# here instead of passing.
#
# Usage:
#   scripts/ci/verify-healthcheck-invariants.sh <role>=<image> [<role>=<image> ...]
#
# Example:
#   scripts/ci/verify-healthcheck-invariants.sh \
#       server=ghcr.io/tr3kkr/yuzu-server:0.13.0 \
#       gateway-chisel=yuzu-gateway-chisel:ci
#
# Exits non-zero, naming the missing tool, if any invariant is broken.

set -euo pipefail

# The gate runs on Linux runners, but it is also meant to be runnable by hand on
# a dev box. Under Git Bash / MSYS2 on Windows, absolute-looking arguments such
# as `/bin/busybox` are silently rewritten into Windows paths
# (`C:/Program Files/Git/usr/bin/busybox`) before docker ever sees them, which
# makes every probe fail with a bogus "tool is missing". Opt out of that
# rewriting. Both variables are inert on Linux and macOS.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

# Listener image, pinned by digest for supply-chain hygiene. It is a test
# fixture only -- nothing is shipped from it, and it is never the image under
# test.
#
# The official busybox image, NOT alpine: Alpine's busybox is built without the
# `httpd` applet (it is split out into the busybox-extras package), so an alpine
# listener silently exits and every probe then fails for the wrong reason.
PROBE_IMAGE="${PROBE_IMAGE:-busybox:1.37@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028}"

# Port the probe listener serves on, inside the shared network namespace. Not
# published to the host, so it cannot collide with anything on the runner.
PROBE_PORT="${PROBE_PORT:-18080}"

# Sidecar name. $$ alone is not enough: Big Tam runs four runners against ONE
# dockerd, and the PR gate sets cancel-in-progress, so a cancelled job can be
# killed before the EXIT trap fires and leak a still-running listener. A later
# job that happened to draw the same PID would then collide on the name and fail
# for a reason that has nothing to do with the image under test. $RANDOM makes
# the name unique per run; stale leaks are swept below.
SIDECAR="yuzu-hc-probe-$$-${RANDOM}"

usage() {
    # $1 = exit status. `--help` is a successful, deliberate request for the
    # usage text; a malformed argument is an error. Same text, different status.
    local rc="${1:-2}"
    if [ "$rc" -eq 0 ]; then
        exec 3>&1     # `--help`: usage is the requested output -> stdout
    else
        exec 3>&2     # bad invocation: usage is a diagnostic -> stderr
    fi
    cat >&3 <<EOF
usage: $0 <role>=<image> [<role>=<image> ...]

roles:
  server           requires: bash, /dev/tcp, grep
  gateway          requires: wget (busybox applet) supporting --spider
  server-chisel    requires: /bin/busybox with a wget applet supporting --spider
  gateway-chisel   requires: /bin/busybox with a wget applet supporting --spider
  agent-chisel     requires: /bin/busybox with a wget applet supporting --spider

Each probe runs the image's REAL healthcheck command against a live listener, so
a tool that is present but has lost the capability the healthcheck needs (a bash
built without /dev/tcp, a wget without --spider) fails here rather than passing.
EOF
    exit "$rc"
}

cleanup() {
    docker rm -f "$SIDECAR" >/dev/null 2>&1 || true
}

# Sweep listeners leaked by an earlier run that was killed before its EXIT trap
# could fire (the PR gate cancels superseded runs, and Big Tam's four runners
# share one dockerd). Only ever removes this script's own probe containers.
sweep_stale_listeners() {
    local stale
    stale="$(docker ps -aq --filter 'name=^yuzu-hc-probe-' 2>/dev/null || true)"
    if [ -n "$stale" ]; then
        echo "note: removing $(echo "$stale" | wc -l) leaked probe listener(s) from a previous run" >&2
        # shellcheck disable=SC2086  # word-splitting is intended: one id per arg
        docker rm -f $stale >/dev/null 2>&1 || true
    fi
}

# Start the known-good HTTP listener. Serves a 200 on /healthz, which is what
# both probe families (bash /dev/tcp + HTTP parse; busybox wget --spider) need.
start_listener() {
    docker run -d --rm --name "$SIDECAR" "$PROBE_IMAGE" \
        sh -c "mkdir -p /www && echo ok > /www/healthz && exec httpd -f -p ${PROBE_PORT} -h /www" >/dev/null

    # C-style loop, not `seq`: keeps the script dependent on bash alone, so it
    # runs the same by hand on a dev box as it does on the Linux runners.
    local i
    for (( i = 0; i < 50; i++ )); do
        if docker exec "$SIDECAR" \
            wget -q -O /dev/null "http://127.0.0.1:${PROBE_PORT}/healthz" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done

    echo "FATAL: probe listener ($PROBE_IMAGE) never came up on port ${PROBE_PORT}" >&2
    echo "       This is a bug in the gate, not in the image under test." >&2
    return 1
}

# Run a probe inside the image under test, joined to the listener's network
# namespace so 127.0.0.1:$PROBE_PORT is the listener.
#
# The image's own ENTRYPOINT is overridden: we are testing the image's TOOLS,
# not booting the application. The default USER is deliberately NOT overridden
# -- the real healthcheck runs as that user, so the probe must too (a tool that
# exists but is not executable by the runtime user is still a broken invariant).
probe() {
    local entrypoint="$1"; shift
    local image="$1"; shift
    docker run --rm \
        --network "container:${SIDECAR}" \
        --entrypoint "$entrypoint" \
        "$image" "$@"
}

# Map a docker-run exit status onto a diagnosis that names the tool.
#
#   127 = executable not found            -> the tool is GONE from the image
#   126 = found but not executable        -> present, but the runtime user cannot run it
#   other non-zero = tool ran and failed  -> present, but the CAPABILITY is gone
#                                            (a listener is up, so this cannot be
#                                             a connection failure)
diagnose() {
    local rc="$1" role="$2" tool="$3" capability="$4"

    case "$rc" in
        127)
            echo "  FAIL [$role]: \`$tool\` is MISSING from the image." >&2
            echo "        The healthcheck for this image invokes \`$tool\`; with the tool gone," >&2
            echo "        every container from this image parks in \`unhealthy\` forever and" >&2
            echo "        anything with \`depends_on: condition: service_healthy\` never starts." >&2
            echo "        Restore \`$tool\`, or update EVERY compose healthcheck for this image." >&2
            ;;
        126)
            echo "  FAIL [$role]: \`$tool\` exists but is NOT EXECUTABLE by the image's runtime user." >&2
            echo "        The healthcheck runs as that user, so this breaks it exactly as if" >&2
            echo "        the tool were missing." >&2
            ;;
        *)
            echo "  FAIL [$role]: \`$tool\` is present, but $capability" >&2
            echo "        The probe ran against a listener that IS accepting connections and" >&2
            echo "        serving 200s, so this is a lost capability -- not a connection error." >&2
            ;;
    esac
}

main() {
    case "${1:-}" in
        -h|--help) usage 0 ;;
    esac

    [ "$#" -gt 0 ] || usage 2
    command -v docker >/dev/null 2>&1 || { echo "FATAL: docker not on PATH" >&2; exit 1; }

    # Validate arguments before doing any work, so a typo fails in <1s.
    local pair role image
    for pair in "$@"; do
        role="${pair%%=*}"
        image="${pair#*=}"
        if [ "$role" = "$pair" ] || [ -z "$role" ] || [ -z "$image" ]; then
            echo "FATAL: expected <role>=<image>, got '$pair'" >&2
            usage 2
        fi
        case "$role" in
            server|gateway|server-chisel|gateway-chisel|agent-chisel) ;;
            *) echo "FATAL: unknown role '$role'" >&2; usage 2 ;;
        esac
        if ! docker image inspect "$image" >/dev/null 2>&1; then
            echo "FATAL: image '$image' is not present locally (build or pull it first)" >&2
            exit 1
        fi
    done

    trap cleanup EXIT
    sweep_stale_listeners
    start_listener

    local failures=0 rc
    local url="http://127.0.0.1:${PROBE_PORT}/healthz"

    for pair in "$@"; do
        role="${pair%%=*}"
        image="${pair#*=}"
        echo "==> [$role] $image"

        rc=0
        case "$role" in
            server)
                # The real healthcheck (docker-compose.uat.yml): open a TCP
                # connection via bash's /dev/tcp, speak HTTP/1.0, and grep the
                # status line. Reproduced verbatim in shape, so bash, /dev/tcp
                # and grep are all exercised the way production exercises them.
                probe bash "$image" -c \
                    "exec 3<>/dev/tcp/127.0.0.1/${PROBE_PORT} \
                     && printf 'GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n' >&3 \
                     && grep -q '200 OK' <&3 ; rc=\$? ; exec 3>&- ; exit \$rc" \
                    >/dev/null 2>&1 || rc=$?
                [ "$rc" -eq 0 ] || diagnose "$rc" "$role" "bash" \
                    "its /dev/tcp support (or grep) no longer works."
                ;;
            gateway)
                # The real healthcheck: `wget --spider -q <url>` off PATH.
                probe wget "$image" --spider -q "$url" >/dev/null 2>&1 || rc=$?
                [ "$rc" -eq 0 ] || diagnose "$rc" "$role" "wget" \
                    "it no longer supports --spider (is this still busybox wget?)."
                ;;
            server-chisel|gateway-chisel|agent-chisel)
                # The real healthcheck (docker-compose.demo.yml) invokes busybox
                # by ABSOLUTE PATH: ["CMD", "/bin/busybox", "wget", "--spider", ...].
                # Probing that exact path is the point -- the chisel images build
                # busybox into /usr/bin and rely on the usrmerge /bin symlink, so
                # a slice change that breaks the path breaks the healthcheck even
                # though busybox itself is still in the image.
                probe /bin/busybox "$image" wget --spider -q "$url" >/dev/null 2>&1 || rc=$?
                [ "$rc" -eq 0 ] || diagnose "$rc" "$role" "/bin/busybox" \
                    "its wget applet no longer supports --spider."
                ;;
        esac

        if [ "$rc" -eq 0 ]; then
            echo "  ok"
        else
            failures=$((failures + 1))
        fi
    done

    echo
    if [ "$failures" -ne 0 ]; then
        echo "FAILED: $failures image(s) have a broken healthcheck invariant." >&2
        echo "See the RUNTIME INVARIANT comments in deploy/docker/Dockerfile.* and #751." >&2
        return 1
    fi
    echo "All healthcheck runtime invariants hold."
}

main "$@"
