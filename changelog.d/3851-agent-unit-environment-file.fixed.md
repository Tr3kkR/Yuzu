- **`yuzu-agent.service` now loads `/etc/yuzu/yuzu-agent.env` (`EnvironmentFile=-`).** Deploy-time
  agent settings - chiefly `YUZU_AGENT_SPARK_DISABLE=1`, the `prefer_spark` rollback lever - now
  persist across restarts, reboots, and package upgrades, instead of requiring a manual
  `systemctl edit` drop-in every time. The file is not shipped by the `.deb`/`.rpm`: create it
  by hand, root-owned `0600`; absence is a no-op (leading `-`). Remove the assignment to
  re-enable spark; changes take effect at the agent's next restart. Linux/systemd only -
  Windows and macOS persistence is a follow-up (#3851).
