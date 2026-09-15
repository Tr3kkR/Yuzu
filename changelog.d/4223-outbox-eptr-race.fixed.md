- Agent: **Fixes a TSan-flagged data race in `GuardianOutboxSendExecutor`'s exception
  hand-off (#4223).** Lands dormant — Guardian does not route detection through Spark
  in any shipped build (`prefer_spark_` is a compile-time default), so this ships no
  user-facing behavior change. A throwing send's `exception_ptr` was copied, not moved,
  at the detached worker's publish site, leaving the worker holding a live second
  reference destroyed off-lock; under CPU starvation that reference could be the one
  that freed the exception object while the caller thread was still reading it, with no
  happens-before edge between the two. Now unconditionally emptied at the same point
  (`std::exchange`, not `std::move` — `std::exception_ptr` has no move constructor on
  libc++ as shipped by any released Clang/Apple Clang, so a plain move would have
  silently kept behaving like the original copy there), so the worker's reference is
  gone by the time it could ever race the caller, on every supported toolchain.
