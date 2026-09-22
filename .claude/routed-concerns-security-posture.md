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
| `privacy_permissions` plugin — per-app sensitive-permission grants (camera/microphone/location/full-disk-access equivalents), read-only (`Forensics` securable, `AdminOrApproval`, default-off via the server-side plugin-config kill switch — same posture as `execution_artifacts`): the plugin never requests, revokes or modifies a grant on any platform, only reads one; a refused read (SIP/TCC denial, `ERROR_ACCESS_DENIED` on the registry, an `AccessDenied`-shaped D-Bus error) is `denied`, never silently collapsed into `absent`; TCC.db is opened in-process, never via a `sqlite3` CLI shellout. | `agents/plugins/privacy_permissions/README.md` | `security-guardian` + `cpp-safety` on `agents/plugins/privacy_permissions/`, `plugin_action_catalogue_privacy_permissions.hpp` |
