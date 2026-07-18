# Big Tam runner telemetry

Big Tam hosts four native Ubuntu runner agents (`yuzu-bigtam-linux-{0..3}`).
Each agent owns a persistent SQLite database at:

```text
/srv/ci/work-N/_tool/yuzu-test-runs/yuzu-bigtam-linux-N/test-runs.db
```

The provisioner reads each runner's registered `workFolder` from
`/home/runner/rN/.runner` rather than assuming its location. On the live host
those work folders are `/srv/ci/work-N`. The database lives under that runner's
tool cache, outside its checkout, and is therefore unaffected by
`actions/checkout`, branch-switch wipes, or build-dir cleanup. Do not point two
runner agents at the same database: per-runner files avoid making telemetry
itself a shared-host SQLite contention source.

Provision or repair all four databases and install their systemd environment
drop-ins from a Yuzu checkout:

```bash
sudo bash deploy/linux/Provision-BigTam-Runner-Telemetry.sh
```

The script deliberately does not restart a runner that may be executing CI.
Apply the drop-ins during a safe window:

```bash
sudo systemctl restart 'actions.runner.Tr3kkR-Yuzu.yuzu-bigtam-linux-*.service'
```

The main CI workflow does not wait for that restart: its telemetry start step
derives the same per-runner path from `RUNNER_TOOL_CACHE` and `RUNNER_NAME`,
initializes the schema idempotently, and exports `YUZU_TEST_DB` for the job.

Verify a database locally on Big Tam:

```bash
YUZU_TEST_DB=/srv/ci/work-0/_tool/yuzu-test-runs/yuzu-bigtam-linux-0/test-runs.db \
  bash scripts/test/test-db-init.sh --check
YUZU_TEST_DB=/srv/ci/work-0/_tool/yuzu-test-runs/yuzu-bigtam-linux-0/test-runs.db \
  bash scripts/test/test-db-query.sh ci-suite-stats --since 30d
```
