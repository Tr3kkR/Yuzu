<!-- The Forensics / per-user-software-data half of the "Routed concerns"
     table of CLAUDE.md (repo root), pulled in by its @-import — loaded
     every session, same authority as CLAUDE.md itself. Split out of
     `routed-concerns.md` (Wave 10 P2a-3) so both files stay under the
     40k-per-file ceiling; the platform/product/data/observability concerns
     remain in the sibling `routed-concerns.md`, auth/access-control/
     request-admission in `routed-concerns-access-control.md`. Row
     discipline unchanged: catastrophic-if-violated invariants + doc
     pointers only — detail goes in the routed doc. -->

| Concern | Doc | Loaded by |
|---|---|---|
| **`browser_inventory` plugin (Forensics, default-off, per-user browser data)** — reads per-user Chromium-family browser profile and extension state (`browsers`/`profiles`/`extensions` actions). CATASTROPHIC-IF-VIOLATED: it must never emit an account identifier, browsing history, cookies or bookmarks — no `user_name`, `gaia_id` or e-mail address in any row, on any OS leg. Enforced structurally in `browser_inventory_parsers.hpp` (`BrowserProfileRow`/`ExtensionStateRow` simply have no such field); a reviewer adding a field to either row struct must re-verify this invariant, not just compile-check it. Ships DEFAULT-OFF behind the server-side plugin-config kill switch (`PluginConfigStore::seed_kill_switch_default_off`, the `execution_artifacts` precedent — do NOT model this on `app_usage`'s `tar_config` check, a different mechanism) and gates at `Forensics:Read`/`AdminOrApproval`, single-target only, same boundary as `execution_artifacts`/`app_usage`. | `agents/plugins/browser_inventory/README.md` | `security-guardian`+`cpp-safety` on `agents/plugins/browser_inventory/`, `plugin_action_catalogue_browser_inventory.hpp` |
