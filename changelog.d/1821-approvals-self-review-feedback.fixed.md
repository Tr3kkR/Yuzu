- **Approvals tab: no more dead Approve/Reject buttons on your own requests** (#1821).
  A pending request you submitted now shows "You submitted this — another reviewer
  must approve" instead of buttons whose backend denial (self-approval is forbidden)
  was silently swallowed. Any other approve/reject denial now surfaces as an error
  toast via an `HX-Trigger` header on the 400 response instead of a silent no-op,
  and every denied approve/reject attempt is now recorded in the audit log
  (`approval.approve` / `approval.reject` with `result=denied`) and the server log.
