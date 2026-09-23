<!-- The security-posture half of the "Routed concerns" table of CLAUDE.md
     (repo root), pulled in by its @-import — loaded every session, same
     authority as CLAUDE.md itself. Split out of `routed-concerns.md` (Wave 8)
     so the routed-concern tables stay under the ceiling; platform/product/
     data/observability concerns stay in `routed-concerns.md`, auth and
     access-control in `routed-concerns-access-control.md`, and Forensics /
     per-user-software-data concerns in `routed-concerns-software-estate.md`.
     Row discipline unchanged: catastrophic-if-violated invariants + doc
     pointers only — detail goes in the plugin README. -->

| Concern | Doc | Loaded by |
|---|---|---|
| `app_control` plugin — read-only Windows WDAC/AppLocker posture (`Security`, ExecuteGate::None): registry reads (`CI\Policy`, `SrpV2`), a `CiPolicies\Active` listing, a `SiPolicy.p7b` presence stat and `wmi_bounded` CIM only. **CATASTROPHIC-IF-VIOLATED:** never raw COM, never PowerShell, never a policy mutation (#282's add_rule/remove_rule are a separate Destructive-class PR); a failed read returns `constrained` + reason, never an empty success. | `agents/plugins/app_control/README.md` | `security-guardian` + `cpp-safety` on `agents/plugins/app_control/`, `plugin_action_catalogue_app_control.hpp` |
| `local_security_policy` plugin — read-only password/lockout/audit policy posture and sudoers content (`Security` securable, `ExecuteGate::None`, no mutation, no new securable). Windows is a rung-2 `secedit /export` argv leaf (never `/configure`/`/import`/`auditpol`; `argv[0]` resolved via `windows_system_directory()`, never a literal) whose output — the WHOLE `SECURITYPOLICY` area — is staged in an agent-owned, owner-only `agent.data_dir` scratch dir, removed on return, and every dispatch first sweeps orphans older than one hour (a crash with no later dispatch leaves one); measured only as LocalSystem on one standalone host. macOS is a rung-2 `pwpolicy` leaf; a plist item not in the documented shape is an `unreadable` row + `pwpolicy:<defect>` token, never the clean no-policy row. A failed read is an `unreadable` row + token, never absent or empty: `PERMISSION_DENIED` only when every read was refused and nothing was readable, else `CONSTRAINED`. In a container (`Dockerfile.agent`) the Linux leg reads the IMAGE's `/etc`, not the host's. Residual silent-by-design cases (one absent PAM alternative, a file that sets nothing reported, a malformed PAM line) are listed in the README caveats. | `agents/plugins/local_security_policy/README.md` | `security-guardian`+`cpp-safety` on `agents/plugins/local_security_policy/`, `plugin_action_catalogue_local_security_policy.hpp` |
