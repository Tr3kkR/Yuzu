- **Guardian arm-ledger and executor-ceiling fleet telemetry (rung 9c PR-3).**
  New heartbeat tags `yuzu.guardian_arm_pending` / `yuzu.guardian_arm_failed`
  (re-statable gauges of the ack ledger's current accepted-and-outstanding and
  currently-failed spark arm counts) and `yuzu.guardian_io_arm_disarm_rejected_ceiling`
  (a monitor-only counter of R5.1's physical-orphan admission ceiling), each rolled
  up fleet-wide as `yuzu_fleet_guardian_arm_pending` / `yuzu_fleet_guardian_arm_failed`
  / `yuzu_fleet_guardian_io_arm_disarm_rejected_ceiling`. Dormant while `prefer_spark`
  is off (every released agent today).
