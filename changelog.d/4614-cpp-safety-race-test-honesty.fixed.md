- `#3990` R5.7 T2 driver (PR #4614 review, scoped Gate-3 cpp-safety +
  quality-engineer): fixed a build break (a leaked debug `std::cerr` line
  from a concurrent reviewer's own mutation-testing edits landed in a prior
  commit on this branch) and three real gaps in the new race test added to
  close the original Doomgoose finding. First, the test's own comment
  claimed protection against a regression that reorders operations inside
  `detach_all()`'s single locked block or splits it into two lock scopes -
  both independently proven, empirically and by direct code reading, to be
  unobservable to any runtime concurrency test; the comment now states
  honestly what the test does and doesn't verify. Second, the race as
  originally constructed let `detach_all()` win every single time (150/150
  and 3000/3000 sampled runs by two independent reviewers) - the
  "callback commits, detach_all() detaches it" branch and its cleanup path
  were never actually exercised despite the loop. A small deliberate
  stagger on alternating iterations now biases the race the other way often
  enough that the test asserts both orderings were actually observed, not
  merely legal in theory. Third, added the missing RAII release guard
  between the parked future's creation and the first throwing `REQUIRE`,
  matching this file's own established idiom - without it, a failed
  precondition check would unwind into the future's blocking destructor
  with nothing left to release the parked backend, leaking the whole
  runtime graph for that iteration.
