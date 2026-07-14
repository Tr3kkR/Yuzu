- **Pre-release QA now actually runs — it never had.** Its `resolve` job gated on
  `startsWith(github.event.workflow_run.head_branch, 'v')`, but for a tag-triggered
  `workflow_run` GitHub reports `head_branch` as the *branch* the tagged commit sits
  on (`main`), never the tag. Every Release run was a `v*` tag push and every
  resulting Pre-release QA run reported `head_branch=main`, so the condition was
  false every time: artifact verification, the Docker integration test, the soak
  test, the upgrade test, the Trivy scan and all four installer jobs had never
  executed, while the workflow reported green. It now gates on the triggering
  Release run being a successful tag build and recovers the tag from the commit it
  built. Two bugs that had been hiding behind the dead trigger are fixed with it:
  the QA, soak and upgrade stacks healthchecked the server with `curl`, which is not
  installed in the server image (the container could never report healthy, and
  `gateway` waits on `condition: service_healthy`), and `REGISTRY` was built from the
  mixed-case `github.repository_owner`, giving `ghcr.io/Tr3kkR/...` — a reference
  Docker rejects outright, since repository names must be lowercase.
