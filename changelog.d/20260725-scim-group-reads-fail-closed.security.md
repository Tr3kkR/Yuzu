- **SCIM group membership reads now fail closed.** A failed membership read was previously
  indistinguishable from "this group has no members." Because `PATCH /scim/v2/Groups/{id}` folds
  its member operations onto the current membership and then persists the whole set, a momentary
  database interruption could commit that emptiness — silently and permanently deleting a group's
  entire membership, and with it any `role=admin` that membership conferred. Group reads,
  role recomputation, and the PUT/PATCH/DELETE membership writes now return HTTP 503 and change
  nothing when the store cannot answer; the IdP's retry succeeds. A genuinely empty group is still
  reported as empty.
