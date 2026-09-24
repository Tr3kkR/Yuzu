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
| `firmware_posture` plugin — read-only firmware/BIOS vendor, version, update-pending posture (`Security`, ExecuteGate::None): fwupd is only ever listed (`GetDevices`/`GetUpgrades`), never asked to install, verify or activate; sd-bus is a system pkg-config dependency, never a `vcpkg.json` entry; a definitive absence (no DMI; fwupd not on a system bus that answered) is a state, a failed read (an unopenable bus, ENOTDIR, a WMI fault after the class was proven present) is `unreadable` plus a token, never `absent`. | `agents/plugins/firmware_posture/README.md` | `security-guardian` + `cpp-safety` on `agents/plugins/firmware_posture/`, `plugin_action_catalogue_firmware_posture.hpp` |
