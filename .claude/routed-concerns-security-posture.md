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
| `local_security_policy` plugin — read-only password/lockout/audit policy posture and sudoers content (`Security` securable, `ExecuteGate::None`, no mutation, no new securable). Windows is a rung-2 `secedit /export` argv leaf (never `/configure`/`/import`/`auditpol`) whose output lands in an agent-owned, owner-only scratch dir that every dispatch first sweeps; macOS is a rung-2 `pwpolicy` leaf. A refused read is `permission_denied`, never an empty result. | `agents/plugins/local_security_policy/README.md` | `security-guardian`+`cpp-safety` on `agents/plugins/local_security_policy/`, `plugin_action_catalogue_local_security_policy.hpp` |
