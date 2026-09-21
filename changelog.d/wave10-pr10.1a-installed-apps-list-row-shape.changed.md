- **Breaking — `installed_apps` `list` rows grow from five to seven `|`-separated fields (definition `crossplatform.software.inventory` 1.1.0, plugin 1.2.0).**
  Each `app|` row now ends `…|install_date|install_location|bundle_id`. A script, SIEM parser or export job that
  unpacks or anchors exactly five fields fails or drops every row from an upgraded agent, and one that reads the
  last field as `install_date` now reads `bundle_id`. The first five fields keep their position; every field is
  now escape-aware (`\` folds to `/`, `|` to `\|`, CR/LF to a space, a field over 4 KiB is cut) — a no-op for
  every value in the three reference captures. Policies or scripts that substring-match the raw `output` now
  also see install paths and bundle identifiers. On macOS, applications sharing a name now sort by (name,
  install_location); the previous relative order was arbitrary. `query`, `list_per_user` and the daily-sync
  inventory are unchanged. Agents not yet on plugin 1.2.0 keep emitting five fields, so both shapes
  coexist during a rollout: read by position and treat a missing sixth or seventh field as "not reported". See the
  `installed_apps list` note in `docs/user-manual/server-admin.md` (Upgrade Notes).
