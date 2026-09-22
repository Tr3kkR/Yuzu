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
| **`browser_inventory` plugin (Forensics, default-off, per-user browser data)** — reads per-user Chromium-family browser profile state (`browsers`/`profiles` actions; the per-profile `extensions` action follows as its own PR). CATASTROPHIC-IF-VIOLATED: it must never emit a browsing-account identifier, browsing history, cookies or bookmarks — no `gaia_id`, no e-mail address, no Chromium `info_cache` `user_name`/`gaia_name` field, in any row, on any OS leg. **Amended 2026-09-22 (Alex):** the LOCAL OS/home-directory account name (e.g. the `alice` in `/home/alice`) is explicitly PERMITTED on the `profiles` row — it disambiguates which of several local users on a shared machine a profile belongs to, is machine-local, and is not itself a personal/cloud identifier; it is NOT covered by the identifiers this clause forbids. `BrowserProfileRow` (the pure JSON row model in `browser_inventory_parsers.hpp`) still has no such field and never will — the local username is added only when the Linux leg formats the wire row (`browser_inventory_linux_parsers.hpp`'s `linux_profile_rows_at`), never inside the parser. A reviewer adding a `gaia_id`/`user_name`(browsing-account)/e-mail/history/cookie/bookmark field to `BrowserProfileRow` or any wire-row builder must re-verify this invariant, not just compile-check it. Ships DEFAULT-OFF behind the server-side plugin-config kill switch (`PluginConfigStore::seed_kill_switch_default_off`, the `execution_artifacts` precedent — do NOT model this on `app_usage`'s `tar_config` check, a different mechanism) and gates at `Forensics:Read`/`AdminOrApproval`, single-target only, same boundary as `execution_artifacts`/`app_usage`. | `agents/plugins/browser_inventory/README.md` | `security-guardian`+`cpp-safety` on `agents/plugins/browser_inventory/`, `plugin_action_catalogue_browser_inventory.hpp` |
