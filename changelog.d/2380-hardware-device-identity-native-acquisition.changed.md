- **`hardware` and `device_identity` plugins acquire data natively instead of shelling out.**
  On macOS, manufacturer/model/processors/system now read directly via `sysctlbyname`/IOKit
  instead of spawning `sysctl`/`ioreg`; BIOS and disk inventory, and the `device_identity`
  domain/OU lookups, now run through the agent's bounded subprocess runner (a fixed
  deadline, no shell) instead of an unbounded `popen`. On Linux, disk inventory reads
  `/sys/block` natively instead of spawning `lsblk`, and AD-join detection queries sssd's
  D-Bus InfoPipe first, falling back to `realm list` (unchanged, unprivileged) when InfoPipe
  is unreachable under the agent's own service account -- the common case on a default SSSD
  configuration. Linux disk rows now report a real media type
  (SSD/HDD/Removable) instead of a placeholder, and macOS BIOS reporting now recognizes
  Apple Silicon's "System Firmware Version" label (previously reported "unknown" on every
  Apple Silicon Mac).
