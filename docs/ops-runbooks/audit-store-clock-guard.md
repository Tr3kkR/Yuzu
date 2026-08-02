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
follows takes the whole retained window. The guard bounds that: a pass it will
not trust DECLINES and deletes nothing, and every pass it accepts is capped at
25,000 rows.

**Why a pass declined, and whether it is expected, is answered elsewhere:** the
"Was this expected?" ladder in
[The retention clock guard](../user-manual/audit-log.md#the-retention-clock-guard).
This page deliberately does not restate the rule - restating it is what put a
wrong trigger list here twice. For what actually fired on a given alert, read the
log line (step 3 below); it names its own trigger.

**It bounds the blast radius; it does not prevent loss.** A sustained clock or
operational fault drains roughly 600k rows/day. The alert is the control. The
guard is the seatbelt.

**Known gap (#2579), and it is the one this page cannot alert you to.** A pass
that begins with no readable stored reading has no missing-anchor trigger, so on
a host whose clock is ALREADY skewed forward it deletes without declining - and
keeps doing so on every later pass while the skew persists, because there is then
no step to detect and no wipe to declare. The 600k rows/day figure above IS that
case. It reaches this page's alerts only when the backlog binds the cap
(`YuzuAuditRetentionCapBinding`); a sub-cap pass moves no counter here at all and
looks exactly like routine expiry. Bound, signals and the retrospective check:
[Limits](../user-manual/audit-log.md#the-retention-clock-guard).

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
2. If the clock is fine, another trigger is elapsed time. Was this server down,
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
4. If the line reads `"the first retention pass against this database"`, **do NOT
   stand it down on sight** - treat it exactly as the wipe case above and confirm
   the clock before letting the next pass drain. That line carries its own
   caveat about what can and cannot be said about the clock; read it in full.

**Action:** address whichever cause steps 1-4 identified - a clock fault needs
time sync; a recent `audit_retention_days` reduction needs nothing. Note the log
line names the TRIGGER, not the root cause: a reduction and a clock jump can both
surface as the wipe line, which is why step 1 comes first. The next pass then
resumes, paced. If the clock was genuinely wrong, decide before it drains whether
the already-expired rows should be preserved (snapshot `audit.db` now).

**If declines REPEAT, step 1 is not sufficient on its own.** Work the
"Was this expected?" ladder on the canonical page before concluding the clock is
fine: [The retention clock guard](../user-manual/audit-log.md#the-retention-clock-guard).
**Escalate** once that ladder is exhausted: a corrupt or hand-edited
`audit_retention_meta` reading is durable state living in the same database as
the evidence.

## YuzuAuditRetentionFailing - passes are erroring

Passes are being ATTEMPTED and are erroring. This does NOT mean nothing was
deleted, and it is NOT the reaper stopping - that is
`YuzuAuditRetentionNotRunning`, a separate rule. Check the
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
