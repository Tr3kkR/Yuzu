- `#3990` R5.7 T2 driver (PR #4614 review, Gate-3 cpp-expert): fixed two real
  gaps and one cosmetic cross-reference error in the race test added to close
  the original Doomgoose finding. The `releaser` thread was joined
  unconditionally after `detach_all()`, but `detach_all()` is not `noexcept`
  and nothing protected `releaser` if it ever threw - a joinable `std::thread`
  destroyed mid-unwind is `std::terminate()`, not a catchable failure.
  Restructured to match this file's own established "declare the thread
  first, the guard after" idiom, so the guard's destructor safely joins a
  still-live `releaser` before `detach_all()`'s own hypothetical throw could
  reach it. Also tightened the race's "withdrawn" outcome check to the
  specific error string, matching this file's own established precedent,
  rather than treating any non-success as the expected outcome - a
  regression-detection gap, not a live defect today. Verified 20/20 clean
  runs and the full agent suite green after the fix.
