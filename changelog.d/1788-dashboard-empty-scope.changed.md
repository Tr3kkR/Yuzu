- **Breaking — the dashboard execute routes now refuse a supplied-but-empty `scope`.**
  `POST /api/dashboard/execute` and `POST /api/dashboard/tar-execute` previously could not tell an
  OMITTED `scope` from one supplied as empty (`scope=`): the form helper returned `""` for both, so
  a request that named NOBODY silently became a broadcast to every device the caller could reach.
  That is the form-encoded twin of the `extract_json_string_array` erasure #2500 closed on the JSON
  routes, and `dispatch_target_shape.hpp` states the rule directly — an omitted targeting argument
  means the whole fleet; a supplied one that resolves to nothing is an error. The two are now
  distinguished: omission still broadcasts, `scope=` is refused and dispatches to nobody, and
  `__all__` is passed through **by name** rather than stripped to empty, so the fleet is reached
  deliberately and never inferred from emptiness. Browser users are unaffected (the UI has always
  sent `__all__`). Automation that posts these forms with a blank `scope` field will stop
  dispatching — send `scope=__all__` to keep the previous behaviour. See the upgrade note in
  `docs/user-manual/server-admin.md`.
