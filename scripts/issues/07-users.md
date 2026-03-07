## Summary

New **users** plugin that enumerates logged-on users, interactive sessions, local user accounts, and local administrator group members.

## Actions

- **logged_on** — Lists all users currently logged on to the system, including logon type and session ID. Output: `user|username|domain|logon_type|session_id` per user.
- **sessions** — Lists active interactive sessions (console, RDP) with state and idle time. Output: `session|id|username|state|client|idle_seconds` per session.
- **local_users** — Enumerates local user accounts with enabled/disabled status and last logon time. Output: `local_user|username|enabled|last_logon|description` per account.
- **local_admins** — Lists members of the local Administrators group (or sudo/wheel group on Linux). Output: `admin|name|type|domain` per member.

## Notes

- **Windows**: `WTSEnumerateSessions` + `WTSQuerySessionInformation` for sessions, `NetUserEnum` for local users, `NetLocalGroupGetMembers` for admins.
- **Linux**: Parse `who`/`w` or `utmp` for logged-on users, `/etc/passwd` + `/etc/shadow` for local accounts, parse `/etc/group` for sudo/wheel members.
- **macOS**: `who`, `dscl . -list /Users` for local accounts, `dscl . -read /Groups/admin` for admins.

## Files

- `agents/plugins/users/src/users_plugin.cpp` (new)
- `agents/plugins/users/CMakeLists.txt` (new)
- `agents/plugins/users/meson.build` (new)
