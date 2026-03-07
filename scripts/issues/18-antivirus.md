## Summary

New **antivirus** plugin that detects installed antivirus products and reports their protection status (real-time protection, definition freshness).

## Actions

- **products** — Lists installed antivirus/anti-malware products with vendor, version, and registration status. Output: `av|name|vendor|version|registered` per product.
- **status** — Returns the protection state: real-time protection on/off, definition version, last scan time, last definition update. Output: `realtime_protection|enabled/disabled`, `definition_version|X`, `last_scan|epoch_ms`, `last_update|epoch_ms`.

## Notes

- **Windows**: Query WMI `SecurityCenter2\AntiVirusProduct` namespace. For Windows Defender specifically, use `Get-MpComputerStatus` PowerShell or WMI `MSFT_MpComputerStatus`.
- **Linux**: Check for ClamAV (`clamd`), Sophos, CrowdFalcon, etc. via process detection and config file presence. No standard API.
- **macOS**: Check for XProtect status, plus third-party AV via process/bundle detection.
- Returns `av_count|0` with no product entries on platforms without detectable AV.

## Files

- `agents/plugins/antivirus/src/antivirus_plugin.cpp` (new)
- `agents/plugins/antivirus/CMakeLists.txt` (new)
- `agents/plugins/antivirus/meson.build` (new)
