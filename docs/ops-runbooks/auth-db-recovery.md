# Auth Store Recovery Runbook

<!-- yuzu:anchor release=v0.13.0 -->

Operator runbook for recovering a Yuzu server when authentication is broken
or an operator is locked out.

**Read this first if you are mid-incident — this document describes
`v0.13.0`, the latest tagged release, unless a section is explicitly marked
"Not in v0.13.0" below:**

<!-- yuzu:claim id=auth-store-sqlite status=shipped evidence=server/core/src/auth_db.cpp#sqlite3_open_v2 -->
1. **Auth data lives in an on-disk SQLite file, `auth.db`** — there is no
   PostgreSQL involved in authentication at this release. (Yuzu's server
   substrate migration to PostgreSQL is underway and several *other* stores
   already require it — `--postgres-dsn`/`YUZU_POSTGRES_DSN` unset or
   unreachable still refuses to boot — but the `auth` schema specifically
   has **not** migrated yet at `v0.13.0`. See "Not in v0.13.0" below for
   what changes once it does.)
2. **TOTP (MFA) secrets are stored in plaintext in `auth.db`, protected only
   by the file's `0600` permission mode** — there is no encryption key to
   pair with a backup at this release. A `.backup`/copy of `auth.db` **is**
   a complete backup of everything auth-related, including MFA secrets. Do
   **not** assume you need a separate key file — you don't, yet. (This
   changes in a future release — see "Not in v0.13.0" below — which is a
   *security improvement* but also changes what "a complete backup" means;
   re-read this document after upgrading rather than assuming it still
   applies unchanged.)

This runbook assumes a single-node Yuzu deployment. For HA, see
"Not in v0.13.0" below — it is not shipped at this release.

## Detection signal

`yuzu-server` exits with a non-zero status at startup and `journalctl -u
yuzu-server` (Linux) or the Windows event log shows one of these lines:

```
[error] Auth DB integrity check failed: <sqlite-error>
[error] Failed to open auth DB: <path> (<errno>)
[error] AuthDB: schema migration failed, closing database
```

If the shipped systemd unit is in use it retries `StartLimitBurst=3` times
within `StartLimitIntervalSec=60`, then enters `failed`:

```
$ systemctl status yuzu-server
● yuzu-server.service - Yuzu Endpoint Management Server
     Active: failed (Result: start-limit-hit) since ...
```

That `failed` state is deliberate — it stops a crash-loop from drowning the
journal. Clear it with `systemctl reset-failed yuzu-server` once fixed.

**If the server fails to start with a `[PG] Refusing to start: ...` line
instead of the three above:** that is a *different* store failing (Yuzu
requires Postgres for its other stores even though auth itself doesn't use
it yet) — see "Not in v0.13.0" below for what that means, but the fix is a
Postgres fix (DSN, reachability, credentials), not an auth-recovery
procedure.

## Recovery procedure

The on-disk schema is rebuilt from the seed config (`yuzu-server.cfg`) on
fresh boot. Runtime state (active sessions, in-memory user list) does NOT
need to be preserved across this procedure — operators will need to
re-authenticate after recovery.

### Linux

```bash
# Stop the service so the file is closed.
sudo systemctl stop yuzu-server

# Archive the corrupt DB for forensics. Do NOT delete it without a copy —
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
4. File a support ticket with the archived `auth.db.corrupt-<timestamp>`
   file attached so the corruption signature can be analysed.

## Prevention — routine backup

`auth.db` should be backed up alongside the rest of `/var/lib/yuzu` (Linux)
or `C:\ProgramData\Yuzu` (Windows) on the operator's existing backup
schedule. The backup procedure must NOT rely on `cp` against the live file
— SQLite's WAL means a naive `cp` can produce a torn copy that fails
integrity checks on restore. Use the built-in `.backup` command, which is
WAL-aware:

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

<!-- yuzu:claim id=mfa-secret-plaintext-at-rest status=shipped evidence=server/core/src/auth_db.cpp#mfa_totp_secret BLOB -->
**Backup encryption requirement.** `auth.db` contains the raw TOTP secret
bytes in plaintext — the `0600` file mode on the live host is the *only*
compensating control at this release (see "Not in v0.13.0" below for the
planned encryption-at-rest). Backups MUST be encrypted at rest if your
threat model includes exfiltration of the backup store — restic,
BorgBackup, or `gpg --symmetric` all satisfy this. A SOC 2 CC6.1 audit will
flag an unencrypted `auth.db` backup as a finding even though the live file
is `0600`.

## Windows: Defender exclusion

On Windows production deploys, Defender's real-time scan can hold the
`auth.db-wal` file open during agent enrollment storms (multiple concurrent
writes from the cleanup thread + token validation). The symptom is
sporadic `SQLITE_BUSY` returns in `[warn]` lines that recover after a
retry. Adding the data directory to Defender's exclusion list eliminates
this entirely.

```powershell
Add-MpPreference -ExclusionPath 'C:\ProgramData\Yuzu\auth.db'
Add-MpPreference -ExclusionPath 'C:\ProgramData\Yuzu\auth.db-wal'
Add-MpPreference -ExclusionPath 'C:\ProgramData\Yuzu\auth.db-shm'
```

Or by glob if your policy syntax allows it: `Add-MpPreference
-ExclusionPath 'C:\ProgramData\Yuzu\auth.db*'`.

The exclusion is safe: `auth.db` is written only by `yuzu-server.exe`, the
file is not user-editable, and password hashes are PBKDF2-SHA256 (salted)
so a Defender bypass does not weaken credential storage.

## Filesystem permissions

`auth.db` is created with mode `0600` (owner read/write only) on Linux and
the equivalent restricted ACL on Windows. If `ls -l` shows anything other
than `-rw-------` for `auth.db` on Linux, fix it before doing anything else
— a world-readable `auth.db` exposes password hashes AND plaintext MFA
secrets for offline attack:

```bash
sudo chmod 0600 /var/lib/yuzu/auth.db
sudo chown yuzu:yuzu /var/lib/yuzu/auth.db
```

## Emergency session revocation

<!-- yuzu:claim id=rest-session-revoke status=shipped evidence=server/core/src/rest_api_v1.cpp#/api/v1/sessions/me -->
**At this release, sessions are in-memory only — there is no PostgreSQL
durable-session store to worry about, and no build-discrimination step is
needed.** A server restart clears every session immediately, and is the
fastest fleet-wide revocation there is (no database access required).

**Preferred — REST API, audited, no restart needed** (targeted, one
operator at a time):

```bash
# Revoke every session for one operator (admin), needs UserManagement:Write.
curl -fsS -X DELETE "https://yuzu.internal/api/v1/sessions?username=alice" \
     -H "Authorization: Bearer $TOKEN"

# Revoke your own (self-service, "sign out everywhere").
curl -fsS -X DELETE https://yuzu.internal/api/v1/sessions/me \
     -H "Authorization: Bearer $TOKEN"
```

Both are dual-write (in-memory + `auth.db`). If the response body reports
`db_persisted: false` or the audit row shows `result=partial` with
`db_error=true`, the in-memory wipe succeeded but the persisted row was not
cleared — a restart would resurrect it. Verify and remediate:

```bash
sqlite3 /var/lib/yuzu/auth.db \
  "SELECT username, expires_at FROM sessions WHERE username = 'alice';"
```

If rows are returned, repeat the REST call once the DB lock clears
(typically under a minute), or use the manual flow below and restart.

**Last resort — dashboard/API unreachable.** This is the recipe of last
resort; it produces no audit row, so file an incident note recording the
action:

```bash
# 1. Identify how many sessions exist for the target user.
sqlite3 /var/lib/yuzu/auth.db \
  "SELECT username, COUNT(*) FROM sessions GROUP BY username;"

# 2. Wipe every session for the target user.
sqlite3 /var/lib/yuzu/auth.db \
  "DELETE FROM sessions WHERE username = 'alice';"

# 3. Restart the server. Without a restart, an already-established
#    in-memory cookie session remains valid until it next hits the
#    validate_session check (the cleanup sweeper has a finite window) —
#    restart guarantees immediate effect fleet-wide.
systemctl restart yuzu-server   # or service yuzu-server restart
```

After the restart, verify the target user's previously-issued cookies
return 401 and that they can re-authenticate normally. File a manual
audit-log entry referencing the incident ticket so the unaudited DB-level
action is traceable in the SOC 2 evidence chain.

API tokens are a separate credential class and are **not** revoked by
either the REST calls or a restart — revoke them explicitly via the token
endpoints.

## Account lockout recovery

An operator is locked out by failed-login lockout
(`--auth-lockout-threshold`, default 5 within `--auth-lockout-window-secs`,
default 900). A locked account returns the same generic 401 as a bad
password. The window auto-expires, so the first question is whether you
need to act at all — waiting it out is the zero-risk path. A subsequent
*successful* login also clears the counter.

<!-- yuzu:claim id=account-lockout status=shipped evidence=server/core/src/main.cpp#--auth-lockout-threshold -->
<!-- yuzu:claim id=admin-unlock-endpoint status=shipped evidence=server/core/src/rest_api_v1.cpp#/users/{username}/unlock -->
**Preferred — admin API** (audited, no database access needed):

```bash
curl -fsS -X POST "https://yuzu.internal/api/v1/users/alice/unlock" \
     -H "Authorization: Bearer $TOKEN"
```

Requires `UserManagement:Write` (plus MFA step-up when the caller is
enrolled). Self-target is allowed. Produces the `auth.lockout.cleared` /
`admin_unlock` audit row.

**Fallback — direct SQL**, when every admin is locked out and no valid
token exists. This writes no audit row; record it in your
change-management system:

```bash
sqlite3 /var/lib/yuzu/auth.db \
  "SELECT username, failed_login_count, locked_until FROM users WHERE username = 'alice';"

sqlite3 /var/lib/yuzu/auth.db \
  "UPDATE users SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL WHERE username = 'alice';"
```

A restart is **not** required — the lockout state is read from `auth.db` on
the next `POST /login`, so the clear takes effect immediately.

Mass-unlock is a threshold-misconfiguration remedy only (e.g. someone
deployed `--auth-lockout-threshold=1`). Fix the flag in the same
maintenance window, or you will be back:

```bash
sqlite3 /var/lib/yuzu/auth.db \
  "UPDATE users SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL;"
```

There is no break-glass CLI for lockout (unlike `--mfa-reset` below); the
auto-expiry window is the standing safety net.

## Emergency MFA disable (break-glass)

**When to use.** An operator has lost both their authenticator device *and*
every recovery code — or has been locked out by MFA enforcement (the IdP
not asserting `amr`, a sole admin who could not enroll). The Settings → MFA
panel is behind login, so the dashboard path is unreachable.

<!-- yuzu:claim id=mfa-reset-cli status=shipped evidence=server/core/src/main.cpp#--mfa-reset -->
### The `--mfa-reset` CLI (audited)

`yuzu-server --mfa-reset <username>` clears the user's MFA enrolment and
exits **without starting the server**. It writes an audit row
(`mfa.reset.breakglass`, principal = the OS account that ran it) to
`auth.db`'s companion audit store.

```bash
sudo -u _yuzu yuzu-server \
  --config /etc/yuzu/yuzu-server.cfg \
  --data-dir /var/lib/yuzu \
  --mfa-reset alice
# {"status":"ok","user":"alice","action":"mfa.reset.breakglass"}
```

**Authorisation — read the threat model.** `--mfa-reset` strips a second
factor with **no MFA, admin-password, or token check of its own**. The only
enforced control is OS-level access: anyone who can run a `yuzu-server`
binary with read access to `data-dir/auth.db` can downgrade **any**
account, including the sole admin. It does not verify it is running as the
service account — that is an operational expectation, not a code-enforced
gate. Treat host access to `auth.db` as equivalent to MFA-reset authority
over every account:

- Run on the server host as the service account (`_yuzu` / `yuzu` /
  `NT SERVICE\YuzuAgent`; see `docs/agent-privilege-model.md`).
- Keep `data-dir` (and `auth.db`) `0700`/`0600`, service-account owned.
- Gate the invocation behind a narrow `sudoers` entry — ideally a dedicated
  break-glass group with a separate approver. The audit principal is the
  real OS identity (`getpwuid`/`GetUserNameA`, **not** the forgeable
  `$USER`), so a tight sudoers entry gives trustworthy attribution.

**Audit is mandatory and fail-closed.** The CLI verifies the audit store is
writable *before* clearing any MFA, and refuses to proceed if it is not.
Because the CLI exits without serving, it emits no Prometheus metric — the
audit row is the only signal. Alert on `mfa.reset.breakglass` in
`audit_events`; an unexpected one is an authentication-downgrade event and
should page on-call.

It is safe to run while the server is up: the one-shot opens its own
`auth.db` connection and does not talk to the running process; SQLite's WAL
+ FULLMUTEX serialise it against the server's concurrent reads/writes.

### Fallback: direct SQL

Only when no `yuzu-server` binary is available on the host. **Writes no
audit row** — record it manually.

```bash
sudo systemctl stop yuzu-server   # optional but safer — avoids contending SQLite
sudo cp /var/lib/yuzu/auth.db /var/lib/yuzu/auth.db.before-mfa-rescue.$(date +%s)

sudo -u _yuzu sqlite3 /var/lib/yuzu/auth.db <<'SQL'
UPDATE users
   SET mfa_totp_secret  = NULL,
       mfa_enrolled_at  = NULL,
       mfa_disabled_at  = CURRENT_TIMESTAMP,
       mfa_last_counter = 0
 WHERE username = 'alice';
DELETE FROM mfa_recovery_codes WHERE username = 'alice';
SQL

sudo systemctl start yuzu-server
```

Clearing the secret needs no key (you are writing NULL, not reading
ciphertext) — this works regardless of the "Not in v0.13.0" encryption
status below. Record manually: operator name, target username, timestamp,
reason, and an approval reference (change ticket, on-call paging record) —
this is the SOC 2 CC6.6 break-glass evidence chain for this path.

<!-- yuzu:claim id=break-glass-arm status=shipped evidence=server/core/src/main.cpp#--break-glass-arm -->
## Break-glass arm (IdP outage under `--auth-mode=sso-only`)

Under `--auth-mode=sso-only` only an SSO provider (OIDC or SAML) mints a session. If the IdP is down, the
`--break-glass-user` account is the way back in — but it is exempt **only while
armed**, and arming is an out-of-band host CLI operation so it works when the
IdP does not.

```bash
sudo -u _yuzu yuzu-server \
  --config /etc/yuzu/yuzu-server.cfg \
  --data-dir /var/lib/yuzu \
  --break-glass-user alice \
  --break-glass-arm
# → arms `alice` for --break-glass-window-secs (default 24h, auto-expiring),
#   prints {"status":"ok",...,"armed_until":"..."} and EXITS (does not serve).
```

- **Prerequisite (enforced):** the break-glass account must exist and have
  **MFA enrolled** — the arm refuses otherwise.
- **Audited:** writes an `auth.breakglass.armed` audit row attributed to
  the real OS identity, checked writable *before* the arm mutates — if the
  audit store is unavailable, the arm refuses, so the exemption is never
  granted without a record.
- **Login still needs MFA** — arming does not skip the TOTP challenge.
- **Auto-expiry only** — no early-disarm command; restoring SSO is the way
  to reduce exposure before the window lapses.
- The break-glass account is **exempt from failed-login lockout** while
  `--auth-mode=sso-only` (so an attacker cannot lock the escape hatch by
  spraying wrong passwords during the very outage it exists for) — it
  still requires its second factor, and every attempt is audited
  (`auth.login_failed`) and per-IP rate-limited. Pick a non-guessable
  break-glass username regardless.

## Locked out by MFA enforcement misconfiguration

`--mfa-enforcement=required` (or `admin-only`) can lock operators out via
an IdP not asserting the expected `amr` claim, or a sole admin whose
login-time enrollment window expired before they scanned the QR code.
Enforcement is read from configuration at startup, not from the database,
so the fix is a restart with the flag relaxed — no data surgery:

```bash
# 1. Relax enforcement and restart. auth.db is untouched.
sudo systemctl edit yuzu-server     # --mfa-enforcement=optional
sudo systemctl restart yuzu-server

# 2. Log in with password alone, enroll via Settings → Multi-Factor
#    Authentication, and SAVE the recovery codes.

# 3. Restore enforcement and restart.
```

**Prevention.** Enroll the admin under `optional` *before* switching to
`required`, and validate your IdP's `amr` assertion before relying on
enforcement for SSO users.

## Post-restore migration check

If you restore `auth.db` from a backup taken before an MFA-related schema
migration, the binary will boot but the MFA columns from that migration
will be empty — the migration runner re-adds the columns on first open, but
any user who had MFA enrolled before the backup loses their TOTP
enrollment silently. After restoring an old backup:

```bash
sqlite3 /var/lib/yuzu/auth.db \
  "SELECT username FROM users WHERE mfa_enrolled_at IS NOT NULL;"
```

If the result is empty AND your pre-incident state had enrolled users,
notify them to re-enroll. Document the data-loss event in the change
record.

## What you cannot recover from

- **Lost `yuzu-server.cfg` and a lost/unreadable `auth.db`.** The config is
  the seed for the admin account on first boot. If both are gone, run
  `yuzu-server --first-run-setup` to create a new admin interactively and
  write a fresh config.
- **Encrypted backups whose key is also lost.** Standard; nothing
  Yuzu-specific — `auth.db` itself needs no key at this release (see
  above), but if *you* chose to encrypt the backup file and lost that
  key, the backup is not recoverable.

## Cross-references

- `docs/auth-architecture.md` — auth model, hardened mode, break-glass design
- `docs/user-manual/server-admin.md` — configuration files, upgrade notes
- `docs/adr/0006-server-postgresql-substrate.md` — the substrate migration
  program (see "Not in v0.13.0" below for what applies to `auth` today)
- `docs/adr/0010-secrets-at-rest-envelope-encryption.md` — planned MFA-secret
  encryption (see "Not in v0.13.0" below)
- `docs/agent-privilege-model.md` — service accounts and sudoers
- `docs/ops-runbooks/engine-principal-store-recovery.md` — `engine:` namespace
- `docs/operations/disaster-recovery.md` — the full backup/restore
  procedure. **This file's own copy is the pre-fix version** (reverted to
  `origin/dev` as part of a PO decision splitting DR-procedure fixes into
  separately-tracked work, **issue #4135**) — do not rely on it as the
  second half of a real recovery until that fix has landed in the
  procedure you run.
- Restore drill and the corrected DR procedure: tracked in **issue #4135**.
  Neither the drill transcripts nor the corrected scripts/doc are part of
  this branch's documentation set; no branch name is cited here on
  purpose — an unmerged branch reference goes stale the day it merges or
  is renamed, and the issue number is the durable pointer.

---

## Not in v0.13.0 — planned for a future release

**Everything below describes `dev`-HEAD (this checkout), not the
installed release most readers have.** If you are mid-incident on
`v0.13.0`, stop reading here — none of this applies to you; use the
sections above. Re-verify every claim below against your own commit
before relying on it (`git cat-file -e <your-tag>:<path>`) — this section
is not re-checked every time a new release cuts, and a claim that says
"not in v0.13.0" today may be wrong for whatever you are actually running.

### AuthDB migrates to PostgreSQL (ADR-0006/0007)

<!-- yuzu:claim id=auth-store-postgres status=planned evidence=server/core/src/auth_db.cpp#PgPool -->
At `dev`-HEAD, `auth` data lives in the server's **PostgreSQL substrate,
schema `auth`** — there is no `auth.db` file there, and there is nothing to
move aside. The detection table above does not apply; instead:

| Log line | Meaning |
|---|---|
| `[PG] Refusing to start: no PostgreSQL DSN` | `--postgres-dsn` / `YUZU_POSTGRES_DSN` is unset |
| `[PG] Refusing to start: cannot reach PostgreSQL substrate: …` | Postgres down, wrong DSN, network/auth failure |
| `[PG] Refusing to start: auth store (AuthDB) migration/open failed` | Database reachable, `auth` schema could not be created/opened |
| `[PG] Refusing to start: SecretCodec::init() failed — …` | The secrets seam could not initialise (see the KEK section below) |

**Postgres substrate unreachable.** Confirm from the Yuzu host, as the
service account, using the server's own DSN:
`sudo -u _yuzu psql "$YUZU_POSTGRES_DSN" -c 'SELECT 1'`. Work the usual
causes: Postgres service down; `pg_hba.conf` rejecting the host/user; TLS
mismatch; network path; credential rotation; connection limit exhausted.
Yuzu restarts cleanly once Postgres is reachable — no auth data is lost by
the outage itself.

**`auth` schema migration failure.** Usual causes, in likelihood order:
insufficient privilege (verify with
`psql "$YUZU_POSTGRES_DSN" -c "SELECT has_database_privilege(current_user, current_database(), 'CREATE');"`),
or schema drift (a partially-created `auth` schema from an interrupted
migration). Inspect with
`psql "$YUZU_POSTGRES_DSN" -c "\dt auth.*"` and
`psql "$YUZU_POSTGRES_DSN" -c "SELECT * FROM public.schema_meta WHERE store = 'auth';"`
before touching anything — the migration runner refusing to proceed on
drift is the fail-closed behaviour working, not a bug.

If the schema truly must be rebuilt from the seed config (a deployment with
no auth data worth keeping), **every step below must succeed before the
next one runs — do not run these as independent, unchained lines.** A
`pg_dump` that fails silently (permission error, disk full, a missing
target directory) followed by an unconditional `DROP SCHEMA` is
irreversible destruction of every local account, MFA enrolment, and
enrollment token in the schema, with the backup the procedure itself
specified silently absent:

```bash
set -euo pipefail
STAMP=$(date +%s)
DUMP="/var/backups/yuzu/auth-before-drop-$STAMP.dump"

# --format=custom (not plain SQL) so pg_restore --list can structurally
# validate the file before anything is dropped.
pg_dump "$YUZU_POSTGRES_DSN" --schema=auth --format=custom -f "$DUMP"
test -s "$DUMP"                              # non-empty, or stop here
pg_restore --list "$DUMP" >/dev/null          # structurally valid, or stop here

# Only reached if every check above succeeded.
psql "$YUZU_POSTGRES_DSN" -c 'DROP SCHEMA auth CASCADE;'
psql "$YUZU_POSTGRES_DSN" -c "DELETE FROM public.schema_meta WHERE store = 'auth';"
sudo systemctl restart yuzu-server
```

`set -euo pipefail` at the top means any failing step aborts the whole
sequence before reaching the `DROP` — this is the fix for the version of
this procedure that used to present these as separate copy-pasteable
lines with no chaining, which let an operator's mid-incident copy-paste
run the `DROP` even after a failed dump. On restart the server re-seeds
the admin account from `yuzu-server.cfg`.

### Post-restore verification (Postgres substrate)

```bash
systemctl status yuzu-server
curl -fsS http://127.0.0.1:8080/health

psql "$YUZU_POSTGRES_DSN" -c "SELECT store, version FROM public.schema_meta WHERE store IN ('auth','scim_store');"

# The KEK-resolution check below needs `set -o pipefail` (or checking curl's
# exit status separately) — a bare `curl | grep` masks a curl failure as
# "grep found nothing", which this step's own pass condition ("must be
# ZERO, or absent entirely") cannot then distinguish from a genuine zero.
# It ALSO only works from the server's own loopback (127.0.0.1/::1 are the
# only addresses /metrics serves unauthenticated) and only over plain HTTP
# (a TLS-by-default image rejects a plain http:// probe outright) — run it
# ON the server host, not from a container bridge or a remote jump box.
set -o pipefail
curl -fsS http://127.0.0.1:8080/metrics | grep secret_decrypt_failures_total
echo "curl+grep exit: $?"   # nonzero here means the CHECK ITSELF failed to
                             # run — re-run from the right host before
                             # trusting a "not found" result as "zero".

# A real MFA login works end-to-end (not just "the page loads").
```

The KEK check is the one people skip. It is the only cheap check that
distinguishes "restored correctly" from "restored, and every MFA user will
be locked out the moment they try to log in" — see the KEK section below.

### Secrets-at-rest envelope encryption for MFA (ADR-0010)

<!-- yuzu:claim id=mfa-secret-envelope-encryption status=planned evidence=server/core/src/auth_db.cpp#SecretCodec -->
At `dev`-HEAD, TOTP secrets in `auth.users.mfa_totp_secret` are
envelope-encrypted (ADR-0010) — a real change from the plaintext-at-rest
description above. The wrapped data key travels with the row in Postgres,
but the key-encryption key (KEK) that unwraps it is a **file, not in the
database**:

| | Path |
|---|---|
| Linux / macOS | `/etc/yuzu/certs/secrets-kek-v<N>.key` |
| Windows | `C:\ProgramData\Yuzu\certs\secrets-kek-v<N>.key` |

**A Postgres dump alone is no longer a complete backup once this ships for
you.** Restore the dump next to a *different* KEK and every MFA decrypt
fails closed — users are locked out of MFA with `SecretUnavailable` errors
and a `yuzu_server_secret_decrypt_failures_total{failure_class="kek_unresolvable"}`
counter climbing. Capture the database dump and the keys directory as a
pair, from the same point in time, and restore them as a pair:

```bash
STAMP=$(date +%Y%m%dT%H%M%SZ)
sudo -u _yuzu pg_dump "$YUZU_POSTGRES_DSN" --format=custom \
     > /var/backups/yuzu/yuzu-$STAMP.dump
sudo tar -czf /var/backups/yuzu/yuzu-keys-$STAMP.tar.gz \
     -C /etc/yuzu certs
```

Rules that follow: encrypt the key archive at rest, separately from the
dump if your threat model allows; never restore a dump onto a host whose
keys directory came from a different backup generation (treat MFA
enrolments as lost and plan a re-enrolment if you cannot prove they are
paired); retain old KEK versions after a rotation (needed to read backups
taken before the rotation completed); drill it — restore into a scratch
database + scratch keys directory and verify a real TOTP login succeeds.

`SecretCodec::init()` failing at boot means the KEK is missing/unreadable
— check ownership/permissions (`sudo -u _yuzu ls -l
/etc/yuzu/certs/secrets-kek-v*.key`); absent on a fresh install is normal
(the server generates one and logs it); absent on an existing install
means the KEK has been lost — do **not** let the server generate a new one
and consider it fixed, a new KEK cannot decrypt existing blobs. Admin
sign-in still survives a permanently-lost KEK (MFA recovery codes are
verify-only PBKDF2 hashes and need no KEK; password hashes are unaffected)
— every enrolled user's TOTP is unrecoverable and must re-enroll.

### Durable PostgreSQL-backed operator sessions (ADR-2002 §4, HA WS-1/1a, tracked #4283)

<!-- yuzu:claim id=session-store-durable-pg status=planned evidence=server/core/src/server.cpp#SessionStore -->
**No tagged release ships this today (verified 2026-09-11 via `git
cat-file -e <tag>:server/core/src/session_store.hpp`, which fails on every
release including `v0.13.0`).** At `dev`-HEAD, `SessionStore` is a
born-on-PG durable store wired into `AuthManager`, so sessions
write-through to PostgreSQL and **survive a restart, a crash, or a replica
failover.** This reverses the guidance in "Emergency session revocation"
above: **restarting a `dev`-HEAD server does NOT revoke a session** — the
durable row is untouched and the session is live again the moment the
server (or its replacement replica) comes back up.

**There is no reliable way to tell which build you are running from inside
this document, and this document should not pretend otherwise.** A
previous revision tried a log-line check and a Postgres-query check; both
were found, live, to give a confident WRONG answer rather than an honest
"can't tell" (a healthy durable boot logs nothing distinguishing it from
legacy; a Postgres query is unusable during the very outage this section
exists for). **If you must know for certain: ask whoever deployed the
build, or check the deployed commit** (`yuzu-server --version` prints the
git commit hash) **against your own build/release history** — do not trust
an in-band runtime check to tell you.

<!-- yuzu:claim id=version-flag-commit-hash status=shipped evidence=server/core/src/main.cpp#kGitCommitHash -->
**During an actual Postgres outage or `SessionStore` degrade, no
documented revocation path is complete, and a "success" you observe may
not be one:**

- **Restart revokes nothing durably.** The durable row survives; once
  Postgres recovers, it is exactly as valid as before the restart.
- **The REST revocation call can return 401/403 for a reason that has
  nothing to do with revocation succeeding or failing.** Both RBAC reads
  and the session-generation check serve from a bounded stale-serve cache
  during a brief outage (~5s for RBAC, ~30s for the session generation
  check) and then fail closed once that bound elapses — meaning the
  `DELETE /api/v1/sessions` handler is never even reached; the request
  itself is rejected. **A 401 returned from an endpoint you called to
  "sign out everywhere" is easy to misread as "it worked" — it did not.**
  No local wipe occurred, no durable delete occurred, and a compromised
  session already past that window is untouched.
- **If the call DOES reach the handler**, it still performs the
  process-local in-memory wipe unconditionally even if the durable delete
  fails (`db_persisted=false`, audited `result="partial"`, `db_error=true`
  — `docs/auth-architecture.md`'s "the local wipe still done so the
  operator's kill NOW intent is honored" language) — but that local wipe
  does not survive Postgres recovering with the row still undeleted: the
  next validation of that same bearer token re-reads the still-present row
  and the session is live again.
- **The only genuinely implementable containment options during the
  outage are network-layer, and only two are real:** block the specific
  source IP at a reverse proxy or firewall (a reverse proxy can see a
  connection's source IP; it cannot see a raw bearer token's hash, which
  lives in the unreachable Postgres instance — a token-hash-based deny
  rule is not something a proxy can execute), or take the whole listener
  offline. Neither is a substitute for the durable delete; both are
  better than believing an inaccessible 401 was a success.
- **Once Postgres has actually recovered**, issue the REST call and
  confirm the audit record reports `db_persisted=true` (not `"partial"`)
  before treating the session as revoked. If it still reports partial,
  retry rather than assume success from the HTTP status alone.

API tokens remain a separate credential class unaffected by any of the
above, on both builds.
