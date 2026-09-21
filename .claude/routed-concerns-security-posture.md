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
| `firmware_posture` plugin — read-only firmware/BIOS vendor, version, update-pending posture (`Security`, ExecuteGate::None): fwupd is only ever listed (`GetDevices`/`GetUpgrades`), never asked to install, verify or activate; sd-bus is a system pkg-config dependency, never a `vcpkg.json` entry; a definitive absence (no DMI, no fwupd daemon) is a state, a failed read is `unreadable` plus a token, never `absent`. | `agents/plugins/firmware_posture/README.md` | `security-guardian` + `cpp-safety` on `agents/plugins/firmware_posture/`, `plugin_action_catalogue_firmware_posture.hpp` |
