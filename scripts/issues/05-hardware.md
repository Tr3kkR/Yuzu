## Summary

New **hardware** plugin that inventories the physical hardware of the host machine: manufacturer, model, BIOS/UEFI version, processors, memory modules, and disk drives.

## Actions

- **manufacturer** — Returns the system manufacturer (e.g., Dell, Lenovo, VMware). Output: `manufacturer|Dell Inc.`.
- **model** — Returns the system model/product name. Output: `model|OptiPlex 7090`.
- **bios** — Returns BIOS/UEFI vendor, version, and release date. Output: `bios_vendor|Dell`, `bios_version|2.14.0`, `bios_date|2024-03-15`.
- **processors** — Lists installed CPUs with model, cores, threads, and clock speed. Output: `cpu|index|model|cores|threads|mhz` per CPU.
- **memory** — Lists installed memory modules with size, type, speed, and slot. Output: `dimm|slot|size_mb|type|speed_mhz` per module.
- **disks** — Lists physical and logical disk drives with size, type, and model. Output: `disk|index|model|size_gb|type|interface` per disk.

## Notes

- **Windows**: WMI queries (`Win32_ComputerSystem`, `Win32_BIOS`, `Win32_Processor`, `Win32_PhysicalMemory`, `Win32_DiskDrive`). Use COM/WMI or `wmic` subprocess.
- **Linux**: Parse `/sys/class/dmi/id/` for manufacturer/model/BIOS, `/proc/cpuinfo` for CPUs, `dmidecode` for memory (may need root), `/sys/block/` and `lsblk` for disks.
- **macOS**: `system_profiler SPHardwareDataType -json` for most fields, `diskutil list` for disks.

## Files

- `agents/plugins/hardware/src/hardware_plugin.cpp` (new)
- `agents/plugins/hardware/CMakeLists.txt` (new)
- `agents/plugins/hardware/meson.build` (new)
