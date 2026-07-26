# Runbook: audit retention clock guard

Covers the `YuzuAuditRetention*` alert family (`docs/prometheus/yuzu-alerts.yml`).
Background: `docs/user-manual/audit-log.md`, ADR-0006, issue #2360.

> **Read this first.** These rules are NOT active unless you wired them up.
> `deploy/prometheus/prometheus.yml` reads `/etc/prometheus/rules/*.yml`, but no
> shipped compose file mounts `docs/prometheus/yuzu-alerts.yml` there, and the
> repo ships no Alertmanager configuration. Until you mount the rules and point
> Prometheus at an Alertmanager, the `severity:` labels below route nowhere and
> the guard's only durable signal is a counter nobody is watching. Wiring that up
> is a prerequisite for treating any of this as a SOC 2 detective control.

## What the guard does, in one paragraph

`audit_events` rows expire on a TTL derived from the server's wall clock. A
forward clock jump makes every row look expired at once, and the delete that
follows takes the whole retained window. The guard bounds that: a pass DECLINES
ONCE (latched) when it would expire every datable row, when more than 7 days
elapsed since the previous pass, or when the stored clock reading is ahead of
now. It then PACES - the next pass deletes, capped at 25,000 rows.

**It bounds the blast radius; it does not prevent loss.** A sustained clock or
operational fault drains roughly 600k rows/day after that single decline. The
alert is the control. The guard is the seatbelt.

## YuzuAuditRetentionClockAnomaly - a pass declined

**Nothing was deleted.** You have time; do not rush a fix that deletes more.

1. Confirm the clock: `timedatectl status`, `chronyc tracking` (or `ntpq -p`).
   Look for a large offset, a recent step, or `System clock synchronized: no`.
2. If the clock is fine, the other trigger is elapsed time. Was this server down,
   suspended, or restored from a snapshot more than 7 days ago? Check
   `journalctl --list-boots` and the uptime. Elapsed time cannot distinguish a
   clock jump from an outage, which is why the warn text names both.
3. Check the server log for the specific line - it names which trigger fired
   (`DeclineWipe`, `DeclineStep`, `DeclineImplausible`, `DeclineFirstPass`).
4. **On a brand-new install, a first-pass decline is expected and benign.**

**Action:** fix time sync. Nothing else is required - the next pass resumes,
paced. If the clock was genuinely wrong, decide before it drains whether the
already-expired rows should be preserved (snapshot `audit.db` now).

**Escalate** if declines repeat on a server whose clock is verifiably correct:
that suggests a corrupt or hand-edited `audit_retention_meta` reading, which is
durable state living in the same database as the evidence.

## YuzuAuditRetentionFailing - passes are erroring

Retention is not running at all, so `audit.db` grows without bound. Check the
log for the sqlite error, then disk space, file permissions on `audit.db`, and
whether a failed migration closed the store (in which case audit WRITES are also
failing and behavioural-PII routes are returning 503 - a much louder problem).

## YuzuAuditRetentionCapBinding - the backlog is outrunning the drain

Expiry is producing rows faster than 25,000/pass/hour (600k/day) removes them.

The cap and the 60-minute interval are **compile-time constants** with no flag
and no environment override. There is no runtime lever: draining faster requires
a code change and a release. Size the problem first -
`SELECT COUNT(*) FROM audit_events WHERE ttl_expires_at > 0 AND ttl_expires_at < strftime('%s','now')`
- then open an engineering ticket with that number. A 4.5M backlog takes about
7.5 days to drain; 45M takes about 75 days.

## YuzuAuditRetentionIndexMissing - the gauge reads 0

Every pass now full-scans `audit_events` under the exclusive lock that every
audit write takes: roughly 1 second at 5M rows, 10 seconds at 50M, growing with
the table. Audit writes - including the fail-closed pre-serve audit on
behavioural-PII routes - queue behind it.

The index is built best-effort at startup and the gauge is evaluated **once, at
startup**, so it cannot see an index dropped at runtime. Verify directly:

```sql
SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_audit_ttl_id';
```

Recreate it, or restart the server to rebuild it. On a large table expect the
build to take seconds to tens of seconds, during which the server has not yet
bound its listener - see the `start_period` note in
`docs/user-manual/upgrading.md`.

## YuzuAuditRetentionStateNotPersisting

The durable clock reading is not being written. The elapsed-time detector is the
only half of the guard that survives a restart, so while this persists a restart
loses its comparison point. Check disk and permissions on `audit.db`.

## Verifying recovery

```
yuzu_server_audit_clock_anomaly_skips_total   # stops increasing
yuzu_server_audit_rows_deleted_total          # resumes increasing
yuzu_server_audit_retention_cap_reached_total # flat once the backlog drains
```

Read the skips and failed counters **together**. Both leave rows undeleted, so a
table that never shrinks looks identical either way; only the pair distinguishes
"the guard is protecting the table" from "cleanup is broken".
