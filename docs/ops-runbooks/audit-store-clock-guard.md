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
ONCE when it would expire every datable row, when more than 7 days elapsed
since the previous pass, when the stored clock reading is ahead of now, or when
there is no stored reading at all so the elapsed-time check cannot run. It then
PACES - the next pass deletes, capped at 25,000 rows.

The first three LATCH, so each is declined once and then paced. The fourth (no
stored reading) deliberately does not: it is a missing comparison point, not an
anomaly, and spending the latch on it would let a real anomaly arriving on the
very next pass delete undeclined.

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
4. **Is this simply the first pass since the upgrade?** Check the log for
   `DeclineFirstPass` -- "no stored clock reading to compare against". Every
   existing database declines exactly once on its first pass under a build that
   has the guard, because the elapsed-time check has no anchor yet. It is
   expected, benign, and self-heals on the next pass. **On a fleet upgrade
   expect one alert per server; stand them down.**

   Note this does NOT happen on a brand-new install: with nothing expired the
   pass returns before the guard is reached. The case that fires is an UPGRADE
   or a RESTORE of a database that already holds an expired backlog.

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

## YuzuAuditRetentionNotRunning - no pass has run

`audit.db` is growing and NOTHING else will tell you: every other rule here fires
on activity, so a server whose retention never runs looks exactly like an idle
one. This rule fires on the ABSENCE of increase in
`yuzu_server_audit_retention_passes_total`, which counts passes ATTEMPTED
(whatever the outcome), and on the series being absent entirely.

Most likely causes, in order:

1. **The server is restarting more often than the cleanup interval.** The loop
   sleeps a full interval (60 minutes by default) BEFORE its first pass, so a
   server that never stays up an hour never completes one. Check uptime and the
   restart history first - this needs no fault to reach.
2. **The series is absent**: the server is down, the scrape target is wrong, or
   the store was never constructed. Check `up` for the job.
3. **The cleanup thread died.** Look for a crash or an exception around the
   store in the log.

The alert is deliberately suppressed for the first 3 hours of a server's uptime,
because the sleep-first loop makes early zeros expected.

## Verifying recovery

```
yuzu_server_audit_clock_anomaly_skips_total   # stops increasing
yuzu_server_audit_rows_deleted_total          # resumes increasing
yuzu_server_audit_retention_cap_reached_total # flat once the backlog drains
yuzu_server_audit_retention_passes_total      # increasing at the cleanup cadence
```

Read the skips and failed counters **together**. Both leave rows undeleted, so a
table that never shrinks looks identical either way; only the pair distinguishes
"the guard is protecting the table" from "cleanup is broken".
