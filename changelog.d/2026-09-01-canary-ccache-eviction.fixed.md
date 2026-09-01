- **Workflow-canary wallclock expected back at its ~3.5-4.5 min warm baseline,
  and the repo's Actions cache freed from eviction churn.** The canary's ccache key hashed every source file,
  so it never exact-hit and every run saved a fresh multi-GB entry; the job also
  inherited the self-hosted 30G `CCACHE_MAXSIZE`, so the entry never trimmed and
  grew monotonically. The resulting pool (measured 7x over GitHub's 10 GB repo
  quota) LRU-evicted the canary's own freshest entries - bimodal 8-20 min
  degraded rebuilds - and starved every other cache in the repo. The key is now
  an ISO-week bucket (roughly one saved entry per week; ccache's own
  preprocessed-input hashing absorbs source drift) and the canary job caps
  `CCACHE_MAXSIZE` at 1.5G.
