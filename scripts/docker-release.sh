#!/usr/bin/env bash
# docker-release.sh — Build and push Yuzu Docker images to GHCR
#
# Usage:
#   ./scripts/docker-release.sh v0.8.0              # build + push
#   ./scripts/docker-release.sh --build-only v0.8.0  # build only, no push
#   ./scripts/docker-release.sh --dry-run v0.8.0     # print commands only
#
# Requires: docker, gh (GitHub CLI, authenticated)
# Designed for: Windows (Docker Desktop) + MSYS2 bash

set -euo pipefail

# ── Parse flags ───────────────────────────────────────────────────────────
DRY_RUN=false
BUILD_ONLY=false
VERSION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)   DRY_RUN=true; shift ;;
        --build-only) BUILD_ONLY=true; shift ;;
        -h|--help)
            sed -n '2,7p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        v*)          VERSION="$1"; shift ;;
        *)           echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 [--dry-run|--build-only] <version-tag>"
    echo "  e.g. $0 v0.8.0"
    exit 1
fi

# ── Validate version format ──────────────────────────────────────────────
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "Error: version must match v<major>.<minor>.<patch>[...]  (got: $VERSION)"
    exit 1
fi

TAG="${VERSION#v}"  # strip leading v → 0.8.0

# ── Derive GHCR owner from git remote (lowercase) ───────────────────────
REMOTE_URL=$(git remote get-url origin 2>/dev/null || true)
if [[ -z "$REMOTE_URL" ]]; then
    echo "Error: no git remote 'origin' found"
    exit 1
fi
OWNER=$(echo "$REMOTE_URL" | sed -E 's|.*github\.com[:/]([^/]+)/.*|\1|' | tr '[:upper:]' '[:lower:]')
REGISTRY="ghcr.io/${OWNER}"

echo "=== Yuzu Docker Release ==="
echo "  Version:  $VERSION ($TAG)"
echo "  Registry: $REGISTRY"
echo "  Platform: linux/amd64"
echo ""

# ── Determine tags ───────────────────────────────────────────────────────
SERVER_IMAGES=("${REGISTRY}/yuzu-server:${TAG}")
GATEWAY_IMAGES=("${REGISTRY}/yuzu-gateway:${TAG}")

# Stable releases (no prerelease suffix) also get :latest and :major.minor
if [[ ! "$TAG" =~ -(alpha|beta|rc) ]]; then
    MAJOR_MINOR=$(echo "$TAG" | grep -oP '^\d+\.\d+')
    SERVER_IMAGES+=("${REGISTRY}/yuzu-server:${MAJOR_MINOR}" "${REGISTRY}/yuzu-server:latest")
    GATEWAY_IMAGES+=("${REGISTRY}/yuzu-gateway:${MAJOR_MINOR}" "${REGISTRY}/yuzu-gateway:latest")
    echo "  Stable release — tagging: ${TAG}, ${MAJOR_MINOR}, latest"
else
    echo "  Pre-release — tagging: ${TAG} only"
fi
echo ""

# ── Helper: run or print ─────────────────────────────────────────────────
run() {
    if $DRY_RUN; then
        echo "[dry-run] $*"
    else
        echo "+ $*"
        MSYS_NO_PATHCONV=1 "$@"
    fi
}

# ── Preflight checks ─────────────────────────────────────────────────────
if ! $DRY_RUN; then
    # Docker running?
    if ! docker info >/dev/null 2>&1; then
        echo "Error: Docker is not running. Start Docker Desktop and retry."
        exit 1
    fi

    # Repo root?
    REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
    if [[ -z "$REPO_ROOT" ]]; then
        echo "Error: not inside a git repository"
        exit 1
    fi
    cd "$REPO_ROOT"

    # Dockerfiles exist?
    for f in deploy/docker/Dockerfile.server deploy/docker/Dockerfile.gateway; do
        if [[ ! -f "$f" ]]; then
            echo "Error: $f not found"
            exit 1
        fi
    done

    # Authenticate to GHCR via gh CLI
    echo "Authenticating to ghcr.io via gh CLI..."
    GH_TOKEN=$(gh auth token 2>/dev/null || true)
    if [[ -z "$GH_TOKEN" ]]; then
        echo "Error: gh auth token failed. Run 'gh auth login' first."
        exit 1
    fi
    echo "$GH_TOKEN" | MSYS_NO_PATHCONV=1 docker login ghcr.io -u "$(gh api user -q .login)" --password-stdin
    echo ""
fi

# ── Build images ─────────────────────────────────────────────────────────
echo "=== Building yuzu-server ==="
BUILD_ARGS=(-f deploy/docker/Dockerfile.server --platform linux/amd64)
for img in "${SERVER_IMAGES[@]}"; do
    BUILD_ARGS+=(-t "$img")
done
run docker build "${BUILD_ARGS[@]}" .
echo ""

echo "=== Building yuzu-gateway ==="
BUILD_ARGS=(-f deploy/docker/Dockerfile.gateway --platform linux/amd64)
for img in "${GATEWAY_IMAGES[@]}"; do
    BUILD_ARGS+=(-t "$img")
done
run docker build "${BUILD_ARGS[@]}" .
echo ""

# ── Push images ──────────────────────────────────────────────────────────
if $BUILD_ONLY; then
    echo "=== Build complete (--build-only, skipping push) ==="
else
    echo "=== Pushing images ==="
    for img in "${SERVER_IMAGES[@]}" "${GATEWAY_IMAGES[@]}"; do
        run docker push "$img"
    done
    echo ""

    echo "=== Done ==="
    echo ""
    echo "Pull commands:"
    echo "  docker pull ${REGISTRY}/yuzu-server:${TAG}"
    echo "  docker pull ${REGISTRY}/yuzu-gateway:${TAG}"
fi
