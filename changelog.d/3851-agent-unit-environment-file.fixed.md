- **`yuzu-agent.service` now loads `/etc/yuzu-agent/yuzu-agent.env` (`EnvironmentFile=-`) - #3851.**
  Deploy-time agent settings - chiefly `YUZU_AGENT_SPARK_DISABLE=1`, the `prefer_spark` rollback
  lever - now persist across restarts, reboots, and package upgrades, instead of requiring a
  manual `systemctl edit` drop-in every time. The path is deliberately agent-dedicated, not the
  shared `/etc/yuzu/` a co-installed `yuzu-server` package also claims. The file is not shipped
  by the `.deb`/`.rpm`: create it by hand, root-owned `0600`; absence is a no-op (leading `-`).
  Remove the assignment to re-enable spark. An `.rpm` upgrade restarts the unit automatically; a
  `.deb` upgrade leaves a pending change applied only at the next restart. Linux/systemd only -
  Windows and macOS persistence is a separate follow-up (#3973).
