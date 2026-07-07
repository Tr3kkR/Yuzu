- **Container base images and builder pip installs are now pinned by hash.**
  Every registry base image in the deploy Dockerfiles (ubuntu, erlang, node,
  postgres, envoy, debian) is pinned to its manifest-list digest, and the
  builder images install meson through hash-verified requirements files
  (`deploy/docker/requirements-meson*.txt`, `pip --require-hashes`).
  Dependabot's docker and pip ecosystems now also watch
  `deploy/docker/cedar-vale/` and `deploy/docker/`, so digest refreshes and
  meson bumps arrive as normal dependency PRs.
