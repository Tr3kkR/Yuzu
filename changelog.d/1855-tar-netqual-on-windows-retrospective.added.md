- **TAR netqual on Windows + retrospective network quality (ADR-0020).** The
  per-connection TCP-quality source (`netqual`, opt-in) now collects on Windows
  via TCP ESTATS — smoothed RTT/jitter, per-tick loss, retrans/segs context per
  ESTABLISHED connection, privacy-bucketed as before (`kSupportedConstrained`:
  needs an elevated agent; non-elevated records nothing and `tar.status` reports
  the new `netqual_capture_method` key as `none`). Two retrospective layers
  answer "what was network quality like before TAR was running": a per-boot
  baseline (`$NetQual_Boot`, since-boot TCP retransmit + interface-error totals
  captured once at agent start, no elevation) and a new opt-in **`netconn`**
  source (`$NetConn_Live`, `netconn_enabled`) that backfills OS-retained
  connectivity history — network connect/disconnect, NCSI internet-capability
  changes, Wi-Fi connect/fail/disconnect with reason codes — reaching
  days-to-weeks before TAR (or the agent) existed on the box. netconn stores
  closed enum tokens and numeric reason codes only: no SSID, BSSID, profile
  name, interface GUID, or MAC is ever extracted (fixture-pinned allow-list
  parser). The retrospective reach is operator-configurable via
  `netconn_lookback_seconds` (default 7 days; `0` disables the pre-enablement
  read entirely, for jurisdictions/works-councils where retrospective
  collection is not permitted — see ADR-0020). Linux/macOS netconn and the
  macOS netqual collector remain planned (schema registered, queryable-empty).
