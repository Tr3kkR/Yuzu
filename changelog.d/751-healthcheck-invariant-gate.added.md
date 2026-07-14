- **CI gate for the container healthcheck runtime invariants.** Every Yuzu image's
  compose healthcheck depends on a tool baked into the image rather than on the
  application — bash + `/dev/tcp` for `yuzu-server`, busybox `wget --spider` for
  `yuzu-gateway`, and `/bin/busybox` (by absolute path) for the three FROM-scratch
  chisel images — and no automated gate exercised them. A base-image swap, a
  dropped apt package, or a chisel slice change that stops shipping the busybox
  symlink breaks nothing at build time and nothing at boot: it breaks only the
  healthcheck, so Compose parks every container `unhealthy` forever and anything
  waiting on `condition: service_healthy` never starts, with no application failure
  to point at. `scripts/ci/verify-healthcheck-invariants.sh` now runs each image's
  real probe against a live HTTP listener — so a bash that has lost `/dev/tcp` is
  caught, not just a missing binary — from a new `docker-healthcheck-invariants.yml`
  workflow on PRs and mainline pushes, and from `release.yml` between the image
  build and the registry push, so a broken image is never published.
