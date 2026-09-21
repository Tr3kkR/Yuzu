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
| `app_control` plugin — read-only Windows WDAC/AppLocker posture (`Security`, ExecuteGate::None): registry reads (`CI\Policy`, `SrpV2`), a `CiPolicies\Active` listing, a `SiPolicy.p7b` presence stat and `wmi_bounded` CIM only. **CATASTROPHIC-IF-VIOLATED:** never raw COM, never PowerShell, never a policy mutation (#282's add_rule/remove_rule are a separate Destructive-class PR); a failed read returns `constrained` + reason, never an empty success. | `agents/plugins/app_control/README.md` | `security-guardian` + `cpp-safety` on `agents/plugins/app_control/`, `plugin_action_catalogue_app_control.hpp` |
