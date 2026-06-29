# Auth DB Recovery Runbook

Operator runbook for recovering a Yuzu server when its on-disk authentication
database (`auth.db`) cannot be opened or fails the integrity check at startup.
Symptoms covered, recovery procedure, prevention via routine backup, and the
Windows-specific Defender exclusion.

This runbook assumes a single-node Yuzu deployment. For HA deployments the
recovery procedure must be coordinated with the active leader; see
`docs/architecture.md` for the leader-follower model once HA lands.

## Detection signal

`yuzu-server` exits with a non-zero status at startup and `journalctl -u
yuzu-server` (Linux) or the Windows event log shows one of these lines:

```
[error] Auth DB integrity check failed: <sqlite-error>
[error] Failed to open auth DB: <path> (<errno>)
[error] AuthDB: schema migration failed, closing database
```

If the systemd unit shipped in this release (`deploy/systemd/yuzu-server.service`)
is in use, the unit will retry up to `StartLimitBurst=3` times within
`StartLimitIntervalSec=60` and then enter the `failed` state:

```
$ systemctl status yuzu-server
● yuzu-server.service - Yuzu Endpoint Management Server
     Loaded: loaded (...)
     Active: failed (Result: start-limit-hit) since ...
```

That `failed` state is the lever: it stops a tight crash-loop from drowning
the journal and surfaces the underlying problem cleanly.

## Recovery procedure

The on-disk schema is rebuilt from the seed config (`yuzu-server.cfg`) on
fresh boot. The runtime state (active sessions, in-memory user list) does
NOT need to be preserved across this procedure — operators will need to
re-authenticate after recovery.

### Linux

```bash
# Stop the service so the file is closed.
sudo systemctl stop yuzu-server

# Archive the corrupt DB for forensics. Do NOT delete it without a copy;
# support may need to inspect the corruption signature.
sudo sqlite3 /var/lib/yuzu/auth.db ".backup /var/lib/yuzu/auth.db.corrupt-$(date +%s)"

# Move the live file aside (NOT delete — keep one operator-recoverable
# copy in case the corruption was actually a permission/ownership issue
# that's reversible).
sudo mv /var/lib/yuzu/auth.db /var/lib/yuzu/auth.db.broken
sudo mv /var/lib/yuzu/auth.db-wal /var/lib/yuzu/auth.db-wal.broken 2>/dev/null || true
sudo mv /var/lib/yuzu/auth.db-shm /var/lib/yuzu/auth.db-shm.broken 2>/dev/null || true

# Reset the unit's restart counter so it can boot again.
sudo systemctl reset-failed yuzu-server

# Start it. The server re-seeds AuthDB from yuzu-server.cfg on first boot.
sudo systemctl start yuzu-server
sudo systemctl status yuzu-server
```

### Windows

```powershell
# Stop the service.
Stop-Service Yuzu

# Archive the corrupt DB.
Copy-Item C:\ProgramData\Yuzu\auth.db `
          C:\ProgramData\Yuzu\auth.db.corrupt-$(Get-Date -Format yyyyMMdd-HHmmss)

# Move the live file aside.
Move-Item C:\ProgramData\Yuzu\auth.db     C:\ProgramData\Yuzu\auth.db.broken
Move-Item C:\ProgramData\Yuzu\auth.db-wal C:\ProgramData\Yuzu\auth.db-wal.broken -ErrorAction SilentlyContinue
Move-Item C:\ProgramData\Yuzu\auth.db-shm C:\ProgramData\Yuzu\auth.db-shm.broken -ErrorAction SilentlyContinue

# Start the service.
Start-Service Yuzu
Get-Service Yuzu
```

After the server is back online:

1. Log in with the admin credentials from `yuzu-server.cfg`.
2. Re-create any user accounts that existed only in `auth.db` (i.e. created
   via Settings > Users after the seed config was first written). Accounts
   created via the seed config itself are restored automatically.
3. Re-issue any enrollment tokens — token state lives in `auth.db`.
4. File a support ticket with the archived `auth.db.corrupt-<timestamp>` file
   attached so the corruption signature can be analysed.

## Prevention — routine backup

`auth.db` should be backed up alongside the rest of `/var/lib/yuzu` (Linux)
or `C:\ProgramData\Yuzu` (Windows) on the operator's existing backup
schedule. The backup procedure must NOT rely on `cp` against the live
file — SQLite's WAL means a naive `cp` can produce a torn copy that fails
integrity checks on restore.

Use the built-in `.backup` SQLite command, which is WAL-aware:

```bash
sudo sqlite3 /var/lib/yuzu/auth.db ".backup /var/backups/yuzu/auth.db.$(date +%s)"
```

```powershell
sqlite3 C:\ProgramData\Yuzu\auth.db `
        ".backup C:\backups\yuzu\auth.db.$(Get-Date -Format yyyyMMdd-HHmmss)"
```

Run nightly on the same cadence as the rest of the data-directory backup.
The backup file is itself a valid SQLite database — restore by stopping the
service, copying the backup over `auth.db`, and starting the service.

## Windows: Defender exclusion

On Windows production deploys, Defender's real-time scan can hold the
`auth.db-wal` file open during agent enrollment storms (multiple concurrent
writes from the cleanup thread + token validation). The symptom is
sporadic `SQLITE_BUSY` returns in `[warn]` lines that recover after a
retry. Adding the data directory to Defender's exclusion list eliminates
this entirely.

Path-based exclusion (Group Policy / `Set-MpPreference`):

```powershell
Add-MpPreference -ExclusionPath 'C:\ProgramData\Yuzu\auth.db'
Add-MpPreference -ExclusionPath 'C:\ProgramData\Yuzu\auth.db-wal'
Add-MpPreference -ExclusionPath 'C:\ProgramData\Yuzu\auth.db-shm'
```

Or by glob if your policy syntax allows it:

```powershell
Add-MpPreference -ExclusionPath 'C:\ProgramData\Yuzu\auth.db*'
```

The exclusion is safe: `auth.db` is written only by `yuzu-server.exe`, the
file is not user-editable, and password hashes are PBKDF2-SHA256 (salted)
so a Defender bypass does not weaken credential storage.

## Filesystem permissions

`auth.db` is created with mode `0600` (owner read/write only) on Linux and
the equivalent restricted ACL on Windows. If `ls -l` shows anything other
than `-rw-------` for `auth.db` on Linux, fix it before doing anything else
— a world-readable `auth.db` exposes the salt and hash for offline crack
attempts:

```bash
sudo chmod 0600 /var/lib/yuzu/auth.db
sudo chown yuzu:yuzu /var/lib/yuzu/auth.db
```

## Emergency session revocation (dashboard unreachable)

When the dashboard is down or unreachable but you need to force-logout a
compromised account immediately, you can clear sessions directly from
the SQLite database. This is the recipe of last resort — the standard
flow is **Settings > User Management > Revoke sessions** (admin) or
**Sign out everywhere** (self), both of which produce audit rows and
metrics. The manual flow below produces no audit row, so file an
incident note recording the action.

```bash
# 1. Identify how many sessions exist for the target user.
sqlite3 /var/lib/yuzu/auth.db \
  "SELECT username, COUNT(*) FROM sessions GROUP BY username;"

# 2. Wipe every session for the target user. Parameterise to avoid
#    quoting accidents.
sqlite3 /var/lib/yuzu/auth.db \
  "DELETE FROM sessions WHERE username = 'alice';"

# 3. Restart the server. The in-memory sessions_ map is rebuilt empty
#    on startup; without a restart, in-memory cookie sessions remain
#    valid until they hit the next validate_session check (cleanup
#    sweeper has a finite window). Restart guarantees immediate effect.
systemctl restart yuzu-server   # or service yuzu-server restart
```

After the restart, validate that the target user's previously-issued
cookies return 401 and that they can re-authenticate normally. File a
manual audit-log entry referencing the incident ticket so the
unaudited DB-level action is traceable in the SOC 2 evidence chain.

## Account lockout recovery (locked out by failed-login lockout)

Account lockout (SOC 2 CC6.3) locks a local-password account after
`--auth-lockout-threshold` (default 5) consecutive failed `POST /login`
attempts, for `--auth-lockout-window-secs` (default 900 s). A locked
account returns the **same generic 401 as a bad password** — there is no
"you are locked" message — so a confused user may not realise they are
locked rather than mistyping. Escalation order:

1. **Standard path (preferred):** another admin clears it immediately via
   `POST /api/v1/users/{username}/unlock` (`UserManagement:Write` + MFA
   step-up). This produces the `auth.lockout.cleared` / `admin_unlock`
   audit row. The dashboard equivalent is on the user's row in
   Settings → Users.
2. **Wait it out:** the lock auto-expires after the window (default 15 min)
   with no action. A subsequent *successful* login also clears the counter.
3. **Last resort — dashboard/REST unreachable, or the SOLE admin is locked
   out** (the unlock endpoint needs a second privileged principal). Clear
   the lockout columns directly in SQLite:

```bash
# Inspect the lockout state for the target user.
sqlite3 /var/lib/yuzu/auth.db \
  "SELECT username, failed_login_count, locked_until FROM users WHERE username = 'alice';"

# Clear the lock (single user).
sqlite3 /var/lib/yuzu/auth.db \
  "UPDATE users SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL WHERE username = 'alice';"

# Mass-unlock — ONLY after a threshold misconfiguration (e.g. accidentally
# deploying --auth-lockout-threshold=1) locked many/all accounts:
# sqlite3 /var/lib/yuzu/auth.db \
#   "UPDATE users SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL;"
```

A restart is **not** required — the lockout state is read from `auth.db`
on the next `POST /login`, so the clear takes effect immediately. The
SQL clear produces **no** `auth.lockout.cleared` audit row, so file a
manual audit-log entry referencing the incident ticket (SOC 2 CC6.3
evidence chain), and fix the misconfiguration (`--auth-lockout-threshold`)
before restarting if a too-low threshold caused the mass lockout. There is
no break-glass CLI for lockout today (unlike `--mfa-reset`); the auto-expiry
window is the standing safety net.

## Verifying persistence after a Settings → Revoke sessions click

The dashboard flow is dual-write (in-memory + `auth.db`). If the response
body reports `db_persisted: false` or the audit row shows `result=partial`
with `db_error=true`, the in-memory wipe succeeded but persisted rows
remain. A server restart will resurrect them. Verify and remediate:

```bash
sqlite3 /var/lib/yuzu/auth.db \
  "SELECT username, expires_at FROM sessions WHERE username = 'alice';"
```

If rows are returned, repeat the **Revoke sessions** click after the DB
lock clears (typically a minute), or use the manual flow above and
restart.

## Limit-of-blast-radius — what you CANNOT recover from

- **Lost `yuzu-server.cfg`.** This file is the seed for the AuthDB on first
  boot. If both `auth.db` AND `yuzu-server.cfg` are lost, the recovery
  procedure cannot rebuild the admin account. Run
  `yuzu-server --first-run-setup` to interactively create a new admin and
  write a fresh config, then restart normally.

- **Encrypted backups whose key is also lost.** AuthDB's contents are
  hashed (PBKDF2) but session tokens and enrollment-token raw values are
  symmetric. If your backup encryption key is lost, the backup is not
  recoverable.

## Emergency MFA disable (break-glass)

**When to use.** An operator (typically an admin) has lost both their
authenticator device AND every recovery code they were issued — or has
been locked out by MFA enforcement (the IdP not asserting `amr`, a sole
admin who could not enroll). They cannot log in, and the Settings →
Multi-Factor Authentication panel is gated behind login so the dashboard
path is unreachable.

### Preferred: the `--mfa-reset` CLI (audited, #1226)

`yuzu-server --mfa-reset <username>` clears the user's MFA enrollment and
exits **without starting the server**. Unlike the manual SQL below it
**writes an audit row** (`mfa.reset.breakglass`, principal = the OS
account that ran it) — so the break-glass is captured in `audit.db`, not
just your change-management system.

**Authorisation — read the threat model.** `--mfa-reset` is a deliberate
break-glass primitive: it strips a user's second factor with **no MFA,
admin-password, or token check of its own**. The *only* enforced control
is OS-level access — anyone who can execute a `yuzu-server` binary with
**read access to `data-dir/auth.db`** can downgrade **any** user
(including the sole admin) to password-only auth. It does not verify it is
*actually* running as the service account; "run as the service account" is
the operational expectation, not a code-enforced gate. Treat host access
to `auth.db` as equivalent to MFA-reset authority for every account, and
protect it accordingly:

- Run on the server host as the service account that owns `auth.db`
  (typically `_yuzu` / `yuzu` / `NT SERVICE\YuzuAgent`; see
  `docs/agent-privilege-model.md`).
- Keep `data-dir` (and `auth.db`) `0700`/`0600`, owned by the service
  account, so unprivileged local users cannot read it and thus cannot
  wield the primitive.
- Gate the invocation behind a narrow `sudoers` entry (a dedicated
  break-glass group, ideally with a separate approver) rather than broad
  `sudo` — the audit principal is the real OS identity (`getpwuid` /
  `GetUserNameA`, **not** the forgeable `$USER`/`$USERNAME` env var), so a
  tight sudoers entry gives you trustworthy attribution.

**Detective control — alert on the audit action.** Because the CLI exits
without starting the server, it emits **no Prometheus metric** — the
`audit.db` row is the detective signal. Configure your SIEM/log pipeline
to raise a high-severity alert whenever an `mfa.reset.breakglass` action
appears in `audit_events`; an unexpected one is an authentication-downgrade
event and should page on-call.

No TLS/HTTPS flags are required (the command never serves).

**Audit is mandatory and fail-closed (#1226 hardening).** The CLI opens
and verifies `audit.db` is **writable before** it clears any MFA; if the
audit store is unavailable (disk full, permissions, corruption) it
**refuses to proceed and exits non-zero** rather than silently clearing a
second factor with no evidence. If the audit write fails *after* the clear
(e.g. disk fills mid-operation) it also exits non-zero with a loud
"record this reset manually NOW" message. A `{"status":"ok",...}` line on
stdout with exit code 0 therefore means an audit row **did** persist.

```bash
sudo -u _yuzu yuzu-server \
  --config /etc/yuzu/yuzu-server.cfg \
  --data-dir /var/lib/yuzu \
  --mfa-reset alice
# {"status":"ok","user":"alice","action":"mfa.reset.breakglass"}
```

It is safe to run while the server is up: the CLI opens its **own**
`auth.db` connection (it does not talk to the running server process), and
the clear is a single atomic transaction — SQLite's WAL + FULLMUTEX
serialise it against the server's concurrent reads/writes. The user can now
sign in with their password alone;
under MFA enforcement they will be walked through enrollment at next
login. Still record the action (operator, time, reason) in your
change-management system — the `audit.db` row plus that record form the
SOC 2 CC6.6 break-glass evidence chain.

### Fallback: direct SQL (no built binary available)

If a `yuzu-server` binary is not available on the host, the equivalent
DB surgery is below. **This path does NOT write an audit row** — record
it manually.

```bash
# 1. Stop the server so SQLite is not contended (optional but safer).
sudo systemctl stop yuzu-server

# 2. Backup auth.db BEFORE the surgery.
sudo cp /var/lib/yuzu/auth.db /var/lib/yuzu/auth.db.before-mfa-rescue.$(date +%s)

# 3. Clear the MFA state for the locked-out user.
sudo -u _yuzu sqlite3 /var/lib/yuzu/auth.db <<'SQL'
UPDATE users
   SET mfa_totp_secret = NULL,
       mfa_enrolled_at = NULL,
       mfa_disabled_at = CURRENT_TIMESTAMP,
       mfa_last_counter = 0
 WHERE username = 'alice';
DELETE FROM mfa_recovery_codes WHERE username = 'alice';
SELECT changes();
SQL

# 4. Restart the server.
sudo systemctl start yuzu-server
```

The operator can now log in with their password alone and (optionally)
re-enroll via Settings → Multi-Factor Authentication.

**Procedure (Windows).** Same SQL, run from an elevated PowerShell as
the service account against `C:\ProgramData\Yuzu\auth.db`. Stop the
`YuzuServer` service first; restart with `Start-Service YuzuServer`.

**Audit trail.** Because this bypasses the audit-emitting code path,
manually record:

- Operator name who performed the disable
- Target username
- Timestamp
- Reason (lost device, locked out, etc.)
- Approval reference (change ticket, on-call paging record)

Per SOC 2 CC6.6 the break-glass procedure is itself an auditable event
and the manual record is the evidence chain.

## Break-glass arm (IdP outage under `--auth-mode=sso-only`)

When the server runs in hardened mode (`--auth-mode=sso-only`), local-password
login is disabled fleet-wide and only OIDC SSO mints a session. If the IdP is
**down**, the single configured `--break-glass-user` is the recovery path — but
it is dormant until **armed**, and arming is an out-of-band host operation (it
must NOT depend on a session, because the IdP being down is exactly why you need
it). This is the analog of `--mfa-reset` and follows the same audited contract
(#1226).

```bash
# On the server host, as the service account (Linux example):
sudo -u _yuzu yuzu-server \
  --config /etc/yuzu/yuzu-server.cfg \
  --data-dir /var/lib/yuzu \
  --break-glass-user alice \
  --break-glass-arm
# → arms `alice` for --break-glass-window-secs (default 24h, auto-expiring),
#   prints {"status":"ok",...,"armed_until":"..."} and EXITS (does not serve).
```

Contract / safeguards:

- **Prerequisite (enforced):** the break-glass account must exist and have **MFA
  enrolled** — the arm refuses (exit non-zero) otherwise. A break-glass account
  with no second factor is never allowed.
- **Audited:** writes an `auth.breakglass.armed` audit row attributed to the
  **kernel OS identity** that ran the CLI (not the forgeable `USER` env var),
  `principal_role=break-glass`. The audit store is verified **writable before**
  the arm mutates — if it isn't, the arm refuses, so the exemption is never
  granted without a record.
- **Login still needs MFA.** After arming, `alice` can log in locally under
  sso-only, but the mandatory TOTP challenge still runs. There is **no metric**
  for the arm itself — the `auth.breakglass.armed` audit row is the detective
  signal; configure your SIEM to alert on it.
- **Auto-expiry, no early-disarm command.** The window auto-expires (no
  `--break-glass-disarm` yet — tracked follow-up). To close it early, you can
  reduce exposure by restoring SSO; the exemption lapses on its own.

> **DoS caveat (security-guardian LOW):** the break-glass account is subject to
> the normal failed-login lockout. An attacker who knows the break-glass
> username could, by submitting wrong passwords *while it is armed*, lock it via
> `--auth-lockout-threshold` during the very outage it exists for. The lock
> **auto-expires** (`--auth-lockout-window-secs`, default 15 min), and while the
> account is *un-armed* the password is never evaluated (so it cannot be
> brute-forced or locked then). If you need to clear a lock immediately during an
> incident, use the admin unlock `POST /api/v1/users/<name>/unlock` (requires an
> authenticated admin — i.e. another operator who can still reach the system) or
> wait out the window. Consider a longer break-glass username that is not
> guessable, and keep the lockout window short.

## Locked out by MFA enforcement misconfiguration (PR 3)

`--mfa-enforcement=admin-only|required` (PR 3) can lock operators out in
two ways that are NOT "lost device" — they are policy/IdP
misconfigurations. The recovery is the same first move: **bring the server
back up in `optional` mode**, fix the underlying state, then re-enable.

**Symptom A — SSO users can't reach high-risk endpoints.** Your IdP does
not assert an `amr` claim containing a recognized MFA method, so OIDC
sessions are never seeded with an MFA proof. (Note: such sessions still
*pass* the step-up gate — they are not blocked from normal operation — so
this only bites if you expected SSO step-up to enforce MFA.) Fix the IdP's
authorization-server policy to emit `amr` (Entra: `mfa`; others: `otp` /
`hwk` / etc.), then re-test. No server surgery needed.

**Symptom B — the sole admin can't complete login-time enrollment.** A
fresh single-admin deployment was started straight into `required`, and
the admin's enrollment-pending token expired (default
`--mfa-login-pending-secs=120`) before they scanned the QR, OR
`mfa_init_enrollment` failed transiently. No session was minted and the
dashboard is unreachable.

**Recovery procedure.**

```bash
# 1. Restart the server with enforcement relaxed. This re-seeds the
#    in-memory config from the flag/env; auth.db is untouched.
sudo systemctl stop yuzu-server
sudo systemctl set-environment YUZU_MFA_ENFORCEMENT=optional   # or edit the unit's flag
sudo systemctl start yuzu-server

# 2. Log in with password alone, enroll via Settings → Multi-Factor
#    Authentication (this issues a fresh secret + recovery codes), and
#    SAVE the recovery codes.

# 3. Once the required accounts are enrolled, restore enforcement and
#    restart.
sudo systemctl unset-environment YUZU_MFA_ENFORCEMENT          # back to the unit default
sudo systemctl restart yuzu-server
```

On Windows, edit the service's `YUZU_MFA_ENFORCEMENT` environment variable
(or the `--mfa-enforcement` argument in the service definition), then
`Restart-Service YuzuServer`.

**Prevention.** Enroll the admin under `optional` *before* switching to
`required`, and validate your IdP's `amr` assertion before relying on
enforcement for SSO users. See `docs/user-manual/upgrading.md` §
"⚠️ Breaking: `--mfa-enforcement` now enforces".

## Post-restore migration check

If you restore `auth.db` from a backup taken before the v2 schema
migration (the MFA migration), the binary will boot but every MFA
column will be absent. The MigrationRunner runs the v2 migration on the
first AuthDB open after the restore so the columns are added back, but
any user who had MFA enrolled BEFORE the backup was taken loses their
TOTP enrollment silently — the columns are re-created empty. After
restoring a pre-v2 backup:

```bash
sudo -u _yuzu sqlite3 /var/lib/yuzu/auth.db \
  "SELECT username FROM users WHERE mfa_enrolled_at IS NOT NULL;"
```

If the result is empty AND your pre-incident state had enrolled users,
notify them to re-enroll. Document the data-loss event in the change
record.

## Backup encryption requirement

`auth.db` contains the raw TOTP secret bytes (PR1 ships plaintext-at-
rest with the 0600 file mode as the only compensating control;
encryption-at-rest via AES-256-GCM is a planned follow-up). Backups MUST
be encrypted at rest if the backup store has any threat model that
includes exfiltration — restic, BorgBackup, or `gpg --symmetric` all
satisfy this. SOC 2 CC6.1 audit will flag unencrypted backups of
`auth.db` as a finding even though the file itself is 0600 on the live
host.

## Cross-references

- File location convention: `docs/user-manual/server-admin.md` §
  Configuration Files.
- AuthDB schema and migration policy: `docs/auth-architecture.md` § AuthDB.
- MFA design: `docs/auth-mfa-design.md`.
- systemd unit definition: `deploy/systemd/yuzu-server.service`.
