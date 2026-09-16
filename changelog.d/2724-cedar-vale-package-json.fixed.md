- **Cedar & Vale demo app tier builds again.** A Dependabot merge had committed both sides of a
  dependency-bump conflict into `deploy/docker/cedar-vale/app/package.json` and its lockfile,
  leaving both as invalid JSON and failing `npm ci` during the tier-app image build — which blocked
  `scripts/start-demo.sh` with the Cedar & Vale overlay and `scripts/start-viz-uat.sh` with the
  `cedar-vale-app` profile. Resolved to the versions the two bumps actually intended (`express`
  5.2.1, `pg` 8.22.0) and regenerated the lockfile with the npm the build uses.
