## Summary

New **bitlocker** plugin (Windows-only) that reports BitLocker drive encryption status and provides actions to enable or disable encryption.

## Actions

- **state** — Returns the BitLocker encryption state for each volume (encrypted, decrypted, encrypting, decrypting), protection status, and encryption method. Output: `volume|drive|status|protection|method|percent` per volume.
- **enable** — Params: `drive` (optional, default C:). Enables BitLocker encryption on the specified drive. Output: `status|ok/error`, `message|...`.
- **disable** — Params: `drive` (optional, default C:). Disables BitLocker encryption (begins decryption) on the specified drive. Output: `status|ok/error`, `message|...`.

## Notes

- **Windows only**: Use WMI `Win32_EncryptableVolume` class or `manage-bde` command-line tool.
- Enable/disable require administrative privileges and may require TPM or recovery key configuration.
- On Linux/macOS, these actions return `error|platform not supported`. Consider LUKS support on Linux as a future enhancement.

## Files

- `agents/plugins/bitlocker/src/bitlocker_plugin.cpp` (new)
- `agents/plugins/bitlocker/CMakeLists.txt` (new)
- `agents/plugins/bitlocker/meson.build` (new)
