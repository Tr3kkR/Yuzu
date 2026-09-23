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
| `system_hardening` plugin — read-only exploit-mitigation/kernel-hardening posture (`Security`, ExecuteGate::None): fixed key allowlists only (never an unbounded /proc/sys or sysctl walk, never a shell-out); every key reports one of value / `absent` / `unreadable` (a refusal also reports `PERMISSION_DENIED`) — a read failure is never rendered as "not hardened". **`absent` requires the surface to be confirmed present:** a Linux ENOENT counts only when `statfs` confirms `/proc/sys` is procfs (else remapped to `errno_19`, `remap_enoent_for_surface`), and a Win32 not-found counts only on a VALUE — a missing `Session Manager\kernel` KEY is `unreadable`/`key_missing` (`ReadSource::structural_key`). Never let a hidden or missing surface read as a clean `absent`. | `agents/plugins/system_hardening/README.md` | `security-guardian` + `cpp-safety` on `agents/plugins/system_hardening/`, `plugin_action_catalogue_system_hardening.hpp` |
