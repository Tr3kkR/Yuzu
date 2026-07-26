- **`POST /api/v1/result-sets/from-tar-query` and its sibling producers no longer broadcast when
  a supplied `parent_id` names no parent set.** `parent_id` is the targeting argument on these
  routes — present and non-empty scopes the dispatch to that result set's current members,
  absent dispatches to every connected agent. The guard was `present && is_string && !empty`,
  so `{"parent_id": 123}` and `{"parent_id": ""}` fell through to the untargeted arm: a caller
  that believed it was narrowing to one result set ran its query across the whole fleet
  instead. Found while auditing this call site during the #2500 fix; the same defect shape as
  the `agent_ids` widening on `POST /api/command`, on a route that issue does not name.

- **Behaviour change:** a **supplied** `parent_id` must now name a parent — a non-string value,
  an empty string, or an explicit `null` returns `400 RESULT_SET_BAD_PARENT` instead of silently
  dispatching fleet-wide. `null` is rejected rather than read as "absent" because a client that
  serialises an unset field as `null` and one whose parent lookup returned nothing are
  indistinguishable at this point, and only one of them wants the entire fleet. **Omit the key**
  to dispatch to all agents deliberately — unchanged, and covered by its own test.
