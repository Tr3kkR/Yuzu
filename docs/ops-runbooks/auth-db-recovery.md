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
authenticator device AND every recovery code they were issued. They
cannot log in. The Settings → Multi-Factor Authentication panel is
gated behind login so the dashboard path is unreachable. PR1 of the MFA
ladder does not include an admin "force-disable for user X" REST route;
that ships in a follow-up.

**Authorisation.** Direct DB write — must run on the server host as the
service account that owns `auth.db` (typically `_yuzu` / `yuzu` /
`NT SERVICE\YuzuAgent`; see `docs/agent-privilege-model.md`). Every
emergency disable should be logged in your change-management system
with the operator name, time, and reason — the audit chain in
`audit.db` will NOT contain a row for this disable (it bypasses the
audit-emitting code path).

**Procedure (Unix).**

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
