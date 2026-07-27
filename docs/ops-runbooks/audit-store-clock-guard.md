# Runbook: audit store health - retention clock guard and write path

Covers the `YuzuAuditRetention*` alert family and `YuzuAuditPersistFailures`
(`docs/prometheus/yuzu-alerts.yml`) - i.e. `audit.db` health, both the write path
and the retention path.
Background: `docs/user-manual/audit-log.md`, ADR-0006, issue #2360.

> **Read this first.** These rules are NOT active unless you wired them up.
> `deploy/prometheus/prometheus.yml` reads `/etc/prometheus/rules/*.yml`, but no
> shipped compose file mounts `docs/prometheus/yuzu-alerts.yml` there, and the
> repo ships no Alertmanager configuration. Until you mount the rules and point
> Prometheus at an Alertmanager, the `severity:` labels below route nowhere and
> the guard's only durable signal is a counter nobody is watching. Wiring that up
> is a prerequisite for treating any of this as a SOC 2 detective control.

## The retention guard, in one paragraph

(For the write path, see the `YuzuAuditPersistFailures` section below.)

`audit_events` rows expire on a TTL derived from the server's wall clock. A
forward clock jump makes every row look expired at once, and the delete that
follows takes the whole retained window. The guard bounds that: a pass declines
when it would expire every datable row, when more than 7 days elapsed since the
previous pass, or when the stored clock reading is unusable. Reducing
`audit_retention_days` can also produce one, by narrowing the survivor horizon.
It then PACES - the next pass deletes, capped at 25,000 rows.

**A missing stored reading is NOT a trigger on its own.** Plain absence is the
ordinary fresh-install case and says nothing about the clock; it becomes visible
only as the no-previous-reading variant of the would-expire-everything decline.
Do not read a decline as evidence that the clock moved until the log line says
so.

A repeat of the SAME condition is suppressed, so a legitimately all-expired
store still ages out; a DIFFERENT anomaly arriving underneath a reported one is
still declined and still counted. Which cases repeat and which are suppressed,
and the preconditions on each, are stated in the user-manual runbook rather than
here: [The retention clock guard](../user-manual/audit-log.md#the-retention-clock-guard).
This page is the alert-response surface; that one is the behaviour surface.

**It bounds the blast radius; it does not prevent loss.** A sustained clock or
operational fault drains roughly 600k rows/day after that single decline. The
alert is the control. The guard is the seatbelt.

## YuzuAuditPersistFailures - audit WRITES are failing

Not a retention problem, and much louder than one:
`yuzu_server_audit_emit_failed_total` is rising, so events are not reaching
`audit.db` at all. Behavioural-PII REST routes
are fail-closed, so they are returning `503` while this persists, and the
evidence for whatever is happening right now is not being recorded.

Check, in order: disk space and inode exhaustion on the `audit.db` volume; file
permissions; whether a failed migration closed the store (the log says so
explicitly, and `/healthz` will show it); and SQLite errors in the log. Retention
alerts may be silent throughout - a closed store does not run passes.

**If behavioural-data routes are returning 503 but this counter is FLAT**, look
for a `bad_alloc`-class throw in the audit pipeline instead. That path fails
closed the same way but is only warn-logged, never counted, so the counter
cannot see it.

## YuzuAuditRetentionClockAnomaly - a pass declined

**Nothing was deleted.** You have time; do not rush a fix that deletes more.

1. Confirm the clock: `timedatectl status`, `chronyc tracking` (or `ntpq -p`).
   Look for a large offset, a recent step, or `System clock synchronized: no`.
2. If the clock is fine, the other trigger is elapsed time. Was this server down,
   suspended, or restored from a snapshot more than 7 days ago? Check
   `journalctl --list-boots` and the uptime. Elapsed time cannot distinguish a
   clock jump from an outage, which is why the warn text names both.
3. Check the server log for the specific line - each decline names its own
   trigger in prose. Grep the phrases, not enum names (the enum names are
   internal and are never printed):
   - `"would expire EVERY datable audit row"` - the wipe outcome test fired.
   - `"elapsed since the last retention pass, over the"` - the elapsed-time
     check fired; the line prints the measured gap against the threshold.
   - `"the stored retention clock reading is not usable"` - the persisted
     reading was ahead of now, negative, non-integer or unreadable.
4. **Is this the first guarded pass against an existing database?** That case
   reads `"the first retention pass against this database"`. It happens on an
   UPGRADE or a RESTORE, never on a brand-new install - with nothing expired the
   pass returns before the guard is reached.

   **Do not stand it down on sight.** It is reported only when the pass would
   ALSO have expired every datable row, so the trigger that makes it visible is
   the wipe outcome test, not merely a missing anchor. Treat it as the wipe case
   above: confirm the clock before letting the next pass drain.

**Action:** fix time sync. Nothing else is required - the next pass resumes,
paced. If the clock was genuinely wrong, decide before it drains whether the
already-expired rows should be preserved (snapshot `audit.db` now).

**Escalate** if declines repeat on a server whose clock is verifiably correct:
that suggests a corrupt or hand-edited `audit_retention_meta` reading, which is
durable state living in the same database as the evidence.

## YuzuAuditRetentionFailing - passes are erroring

Passes are being ATTEMPTED and are erroring or only partially healthy - one of
the failure sites fires even after a successful delete, so this does not mean
nothing was deleted. It is also NOT the reaper stopping: that is
`YuzuAuditRetentionNotRunning`, a separate rule keyed on no pass being attempted
at all. Check the
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

## YuzuAuditRetentionNotRunning

No retention pass has been ATTEMPTED for three hours. This is the one failure the
other rules in this family cannot report: they all key on a counter rising, and
nothing is running to raise one, so the store looks identical to a quiet healthy
one while `audit.db` grows without bound and the configured window stops being
enforced.

Check that the store opened at boot (a failed migration closes it, and
`start_cleanup()` then early-returns), and look for `AuditStore: retention pass
threw` in the log. The rule carries an uptime guard because the cleanup thread
sleeps a full interval before its first pass, so a freshly started server
legitimately has no pass yet.

> There is deliberately NO metric for a missing retention index. The index is
> built best-effort outside the migration runner and its absence degrades
> retention to full scans rather than taking the audit trail offline; it is
> logged as an error at startup and nowhere else (tracked in #2526). If you
> suspect it, check directly:
>
> ```sql
> SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_audit_ttl_id';
> ```
>
> A missing index means every pass full-scans `audit_events` under the exclusive
> lock every audit write takes - roughly 1 second at 5M rows, 10 at 50M. Restart
> the server to rebuild it, and see the `start_period` note in
> `docs/user-manual/upgrading.md` first.

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
