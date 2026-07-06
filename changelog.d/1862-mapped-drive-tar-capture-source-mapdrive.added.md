- **Mapped-drive TAR capture source (`mapdrive`, capability-map §3.8).** New opt-in
  (default-off) TAR capture source recording network-share mappings in **both**
  directions — outbound (drives this host maps to remote shares) and inbound (remote
  hosts mapping this host's shares, the lateral-movement signal) — distinguished by a
  `direction` column and queryable via `$MapDrive_Live`/`$MapDrive_Hourly`. Beyond the
  standard periodic snapshot-diff (`appeared`/`removed`), a one-time backfill at agent
  init seeds *previously* mapped drives (`origin='historical'`) from persistent OS
  artifacts — Windows registry `Network`/`Map Network Drive MRU`/`MountPoints2` across
  offline profiles + Security event log 4624 network logons; Linux `/etc/fstab` + Samba
  connect logs. Live enumeration uses `WNetEnumResourceW` + `NetSessionEnum` (Windows,
  inbound needs local-admin/Server-Operator) and `/proc/mounts` + `smbstatus` (Linux,
  inbound needs Samba); macOS is planned. Rows carry usernames and remote share paths
  (identity/usage-class telemetry — enabling is audited). Enable with
  `tar.configure {"mapdrive_enabled":"true"}`; the historical backfill materializes on
  the first agent restart after enabling. See `docs/user-manual/tar.md`.
