- **DEX fleet performance denominators are per-OS.** `GET /api/v1/dex/perf/fleet` and the MCP
  `get_dex_perf_fleet` tool now carry `linux_online`/`macos_online`/`reporting_windows`/
  `reporting_linux`/`reporting_macos` alongside the original `windows_online`/`reporting` fields
  (unchanged), fixing the known limitation where the Windows-only `windows_online` denominator
  could be legitimately exceeded by `reporting` on a mixed Windows/Linux fleet. `GET
  /api/v1/dex/perf/devices` and MCP `list_dex_perf_devices` rows gain a trailing `os` field, and
  the not-reporting drill now spans every OS with a real perf collector (Windows + Linux) instead
  of Windows only. New `yuzu_fleet_perf_os_{reporting,cpu_pct,commit_pct,disk_lat_ms}{os[,stat]}`
  Prometheus gauges publish the same per-OS breakdown, alongside the unchanged fleet-wide
  `yuzu_fleet_perf_*` families.
