- **Guardian spark (lands dormant: `prefer_spark_` stays false, so no
  production arm or disarm takes the new path until the flip): bounded
  compensating-disarm cleanup, a terminal-recovery maintenance sweep, and a
  real-time retained-disarm count.** A late-succeeding arm nobody wants now
  reserves its compensating-disarm capacity before the arm ever dispatches,
  closing an unbounded-accumulation path to the per-instance alive-worker
  ceiling; a maintenance pass reaps a rare double-fault residue that could
  otherwise leave a key permanently unable to re-arm; and `disarm_retained()`
  now reflects claims currently stuck, not a lifetime total, with the
  convergence lane redriving them automatically (#4221).
