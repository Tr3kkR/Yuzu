- **A Guardian convergence lane that throws no longer terminates the agent.** The four
  convergence sweep threads ran without an exception firewall, so an allocation failure during
  a sweep took down the whole daemon; they now count and log the failure and keep running,
  matching the outbox drain worker. Like the rest of this change the lanes only run once the
  Spark detection path is authoritative, so no currently-released agent is affected. The count surfaces under its own
  `yuzu.guardian_sweep_exceptions` heartbeat tag - deliberately separate from the journal's
  `yuzu.guardian_journal_maint_exceptions`, because a detection failure and an audit-trail
  failure need different responses.
