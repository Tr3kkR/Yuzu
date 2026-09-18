- **Guardian Spark: M1 priority-lane demotion can no longer be starved forever by a
  chronically-full outbox or an Event-only eval stream.** `GuardianSparkRuntime::
  evaluate_key`'s demotion bookkeeping (F5 6c, #2298) decided whether a still-pending
  rule left the 5s priority lane inside the same commit that put its outbox entry on
  the wire — a rule whose every read was rejected at the outbox cap never reached that
  decision at all, and the elapsed-time arm was only ever checked on a committed
  Convergence-reason pass, so a key driven solely by Event-reason evals never demoted
  no matter how much time passed. Both are now decided on the read outcome, ahead of
  the enqueue attempt, so a rejected pass still counts toward demotion and the
  elapsed-time arm is checked on every Unknown pass regardless of reason (#2992).
