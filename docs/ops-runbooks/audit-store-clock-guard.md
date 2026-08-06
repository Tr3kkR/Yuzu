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

**The bootstrap decline (#2579), and why it is not one of your alerts.** A pass
that begins with NO stored clock reading while rows are already expired declines
once, warns, and anchors the reading - it cannot tell whether the clock was wrong
before the guard ever ran, so it holds back rather than delete. That decline
raises `yuzu_server_audit_retention_bootstrap_declines_total` and NOT the
clock-anomaly series, deliberately: it makes no claim that the clock moved, so it
must not fire an alert that says one did. Expect 0 or 1 per database, typically on
the upgrade to schema v3. A value that keeps climbing means the anchor is not
surviving — triage for that is
[YuzuAuditRetentionAnchorNotSurviving](#yuzuauditretentionanchornotsurviving)
below, and it is stated there rather than here so it has one home. The
full trigger list and the reasoning behind these signals live on the canonical
page: [Limits](../user-manual/audit-log.md#the-retention-clock-guard).

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
   - `"no stored clock reading to compare against"` - the bootstrap decline
     (#2579). This one does NOT raise the clock-anomaly counter, so it cannot be
     what fired THIS alert; you are seeing it beside another trigger.
4. If the line reads `"the first retention pass against this database"`, **do NOT
   stand it down on sight** - treat it exactly as the wipe case above and confirm
   the clock before letting the next pass drain. That line carries its own
   caveat about what can and cannot be said about the clock; read it in full.

**Action:** address whichever cause steps 1-4 identified - a clock fault needs
time sync; a recent `audit_retention_days` reduction needs nothing. Note the log
line names the TRIGGER, not the root cause: a reduction and a clock jump can both
surface as the wipe line, which is why step 1 comes first. The next pass then
resumes, paced. If the clock was genuinely wrong, decide before it drains whether
the already-expired rows should be preserved - page the window out through
`/api/audit` per
[Protecting evidence right now](../user-manual/audit-log.md#the-retention-clock-guard),
which works on any deployment. Do NOT reach for a file-level snapshot here: a
raw copy of a live WAL database can be torn, and the shipped server image
carries no `sqlite3` to take a clean one.

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
legitimately has no pass yet. That grace excuses a server only while its uptime
has at most ONE reset across the alert window - one restart is an ordinary
install-then-config-fix, while a process restarting more often than hourly never
accumulates uptime past the grace, and a crash loop is a leading cause of zero
completed passes, so it must not be excused. If the alert is firing on a young
server, check whether it is actually restarting:
`resets(yuzu_server_uptime_seconds[3h])`.

> **If you suspect a crash loop but this alert is SILENT, check the target
> identity first.** `resets()` needs one continuous series per server. When a
> restart changes the `instance` label - dynamic-port or IP-based service
> discovery, a rescheduled pod - every restart starts a fresh series with no
> resets and a young uptime, so the grace applies forever and this rule cannot
> fire. That is a scrape-configuration problem, not a rule problem: target a
> stable identity. Confirm restarts directly with `journalctl --list-boots`, or
> the orchestrator's restart count, rather than trusting `resets()` alone.

**Before assuming a crash loop, check the uptime series exists.** If
`yuzu_server_uptime_seconds` returns nothing for this instance, the rule fired
on its absent-series arm (deliberate — a server that stops exporting uptime must
not be able to silence its own liveness alert), and the fault is in the scrape
path, not the reaper: check the target is up and that a `metric_relabel_configs`
rule is not dropping it. The separate `YuzuAuditRetentionMetricMissing` alert
covers the other half of this — the retention *counter* not being scraped at
all, which leaves this rule unable to fire for anyone.

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

## YuzuAuditRetentionMetricMissing

No `yuzu_server_audit_retention_passes_total` series exists in this Prometheus at
all, so `YuzuAuditRetentionNotRunning` cannot fire for anyone: `increase()` over a
metric with no series is an empty vector, and an alert that selects nothing never
alerts. Retention is unmonitored until this is resolved.

**Check `up` for the Yuzu target first — this rule cannot tell these three states
apart.**

- **`up` is 0.** The server or its scrape is down. This is an OUTAGE, not a
  monitoring gap, and on a single-server Prometheus this rule may be the only one
  firing, because nothing in the shipped rule set alerts on `up` directly. Work
  the outage; this alert clears when scraping resumes.
- **`up` returns no series at all.** Two very different things look identical
  here, so do not assume the benign one:
  - this Prometheus was never configured to scrape a Yuzu server — **expected and
    ignorable** before the first one is stood up. Check the targets page.
  - the target has **left service discovery**. Under dynamic-port, IP-based or
    scheduler-managed SD that is exactly what a dead or deleted server looks
    like. An empty target list for a fleet you believe is running is an outage.
- **`up` is 1.** The metric itself is missing. Either the server predates it (the
  rules file is a copy you apply yourself, so it routinely runs ahead of the
  servers it points at), or a scrape config is dropping it. Confirm with
  `curl -s <server>/metrics | grep audit_retention_passes`, then check
  `metric_relabel_configs`.

It is **fleet-wide by construction**: `absent()` fires only when NO series exists
anywhere in this Prometheus, so one server going quiet among many is invisible
here. Use a `up`-based target-down alert for per-target coverage.

## YuzuAuditRetentionAnchorNotSurviving

The guard has declined more than once in a day for having NO stored clock
reading. Expect that AT MOST ONCE per database, on the upgrade that adds the
reading. Repeating means the anchor is being lost between passes, so the
restart-surviving half of the clock guard is not working and every pass starts
blind. **Nothing was deleted by those passes** - this is lost detection, not lost
evidence.

Check `yuzu_server_audit_retention_persist_failed_total` FIRST. If it is rising,
the server cannot write the row: disk, permissions, or a read-only mount. If it
is FLAT, the row is being destroyed outside the server - a restore from a pre-v3
backup, a replica rehydrated from a template, a disk-level rollback - which that
counter cannot see, because the write it counts succeeded every time. A flat
`persist_failed_total` is therefore not evidence the anchor is fine; it only
rules out one of the two causes.

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
