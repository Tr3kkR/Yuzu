- **Guardian durable-journal maintenance no longer runs on the agent heartbeat or reconnect
  threads.** Retention pruning and journal replay-paging are both KvStore-bound full-journal
  passes that can block on its 5 s busy timeout; running them inline meant a large or contended
  journal could delay a heartbeat (reporting the endpoint as falsely stale) or slow a reconnect.
  They now run on the existing Guardian outbox drain worker, which already does KvStore I/O per
  send, so no new thread is introduced. The heartbeat keeps only the cheap retry-persist that
  lets a failed durable write self-heal, and the reconnect hook now *wakes* the worker instead of
  paging inline - replay after a reconnect stays prompt. Retention pruning is now paced on a
  ~2-minute timer rather than a tick count, so an event burst cannot make it scan repeatedly.
  Operator-visible behaviour is unchanged: prune/page failures still surface under the same
  `guardian_journal_maint_exceptions` heartbeat counter.
