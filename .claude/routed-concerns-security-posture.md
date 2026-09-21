<!-- The security-posture half of the "Routed concerns" table of CLAUDE.md
     (repo root), pulled in by its @-import — loaded every session, same
     authority as CLAUDE.md itself. Split out of `routed-concerns.md` (Wave 8)
     because that file sits at its 40k-per-file ceiling; platform/product/
     data/observability concerns stay in `routed-concerns.md`, auth and
     access-control in `routed-concerns-access-control.md`. Row discipline
     unchanged: catastrophic-if-violated invariants + doc pointers only —
     detail goes in the plugin README. -->

| Concern | Doc | Loaded by |
|---|---|---|
| `system_hardening` plugin — read-only exploit-mitigation/kernel-hardening posture (`Security`, ExecuteGate::None): fixed key allowlists only (never an unbounded /proc/sys or sysctl walk, never a shell-out); every key reports one of value / `absent` (ENOENT or Win32 not-found) / `unreadable` (any other errno or Win32 error; a refusal also reports `PERMISSION_DENIED`) — a read failure is never rendered as "not hardened". | `agents/plugins/system_hardening/README.md` | `security-guardian` + `cpp-safety` on `agents/plugins/system_hardening/`, `plugin_action_catalogue_system_hardening.hpp` |
