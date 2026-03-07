## Summary

New **device_identity** plugin that reports the host machine's identity within the network and directory infrastructure.

## Actions

- **device_name** — Returns the configured computer/hostname. Output: `device_name|WORKSTATION01`.
- **domain** — Returns the Active Directory or DNS domain the device is joined to. On non-domain machines, returns "WORKGROUP" or equivalent. Output: `domain|corp.example.com`, `joined|true/false`.
- **organizational_unit** — Returns the AD Organizational Unit (OU) the computer object resides in. Requires LDAP/AD query on Windows; returns empty on Linux/macOS unless joined via SSSD/Samba. Output: `ou|OU=Workstations,DC=corp,DC=example,DC=com`.

## Notes

- **Windows**: `GetComputerNameEx` for hostname/domain, `NetGetJoinInformation` for domain join status, LDAP query via `ADsGetObject` for OU.
- **Linux**: `hostname`, `/etc/resolv.conf` for domain, `realm list` or SSSD config for AD join status.
- **macOS**: `scutil --get ComputerName`, `dsconfigad -show` for AD binding.
- OU query may require elevated privileges or domain connectivity.

## Files

- `agents/plugins/device_identity/src/device_identity_plugin.cpp` (new)
- `agents/plugins/device_identity/CMakeLists.txt` (new)
- `agents/plugins/device_identity/meson.build` (new)
