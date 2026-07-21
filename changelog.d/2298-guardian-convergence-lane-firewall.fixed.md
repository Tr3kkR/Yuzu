- **A Guardian convergence lane that throws no longer terminates the agent.** The four
  convergence sweep threads ran without an exception firewall, so an allocation failure during
  a sweep took down the whole daemon; they now count and log the failure and keep running,
  matching the outbox drain worker. The count surfaces under the existing
  `yuzu.guardian_journal_maint_exceptions` heartbeat tag.
