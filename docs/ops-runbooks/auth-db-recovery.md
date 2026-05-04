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

## Cross-references

- File location convention: `docs/user-manual/server-admin.md` §
  Configuration Files.
- AuthDB schema and migration policy: `docs/auth-architecture.md` § AuthDB.
- systemd unit definition: `deploy/systemd/yuzu-server.service`.
