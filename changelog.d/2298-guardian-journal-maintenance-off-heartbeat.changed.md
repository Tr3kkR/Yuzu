- **Guardian durable-journal maintenance no longer runs on the agent heartbeat or reconnect
  threads.** Retention pruning and journal replay-paging are both KvStore-bound full-journal
  passes that can block on its 5 s busy timeout; running them inline meant a large or contended
  journal could delay a heartbeat (reporting the endpoint as falsely stale) or slow a reconnect.
  They now run on the existing Guardian outbox drain worker, which already does KvStore I/O per
  send, so no new thread is introduced. The heartbeat keeps only the cheap retry-persist that
  lets a failed durable write self-heal, and the reconnect hook now *wakes* the worker instead of
  paging inline - replay after a reconnect stays prompt. Both maintenance passes are paced on
  their own timers (30 s for replay paging, ~2 minutes for retention) rather than on a tick
  count, so an event burst cannot make them run repeatedly. Operator-visible behaviour is
  otherwise unchanged: prune/page failures still surface under the same
  `yuzu.guardian_journal_maint_exceptions` heartbeat counter. This machinery is wired but
  dormant until the Spark detection path becomes the authoritative backend, so no
  currently-released agent changes behaviour.
- **A slow server connection can no longer starve Guardian journal retention.** Each drain pass
  now ships at most 512 entries (or 2 seconds' worth, whichever comes first) before the worker
  re-checks its other work, and re-drains immediately if more remain. Previously one pass drained
  the entire 4096-entry send window, which on a slow link took long enough to hold off retention
  until the journal reached its write ceiling and began dropping lifecycle audit records. The
  compliance/health outbox is also guaranteed a share of each pass, so a busy lifecycle log
  cannot delay drift reporting.
- **A Guardian convergence lane that throws no longer terminates the agent.** The four
  convergence sweep threads ran without an exception firewall, so an allocation failure during a
  sweep took down the whole daemon; they now count and log the failure and keep running, matching
  the drain worker.
