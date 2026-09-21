- **`installed_apps` `list` now reports each application's install location and macOS bundle identifier.**
  Two trailing columns are added to every `app|` row: the install location (the Windows
  Uninstall-key `InstallLocation`, or the location macOS reports (normally the `.app` bundle);
  `-` where an entry has none, which is every Linux row by design) and the macOS bundle
  identifier. Backslashes in the new columns are emitted as `/` (`safe_output_field`). This
  lands the ADR-0028 `installed_apps`/`InstallLocation` sequencing dependency for the operator
  `list` action only — the ADR-0016 daily-sync row is unchanged.
