- **Two security-surface counts corrected in the operator docs.** `authentication.md` said eleven
  endpoints require a fresh MFA step-up proof; the gate is wired on twenty-two, and the omitted
  eleven are the entire engine-principal lifecycle (create/delete, credential mint/rotate/confirm,
  role grant/revoke, transfer-owner), account unlock, and the token rotate/confirm pair — so the
  doc understated which mutations are protected. `security-hardening.md`'s quarantine
  threat-model section described three server-internal pushes as exempt from the containment
  dispatch gate; `SystemReservedPush` has four enumerators — the on-demand inventory sync
  (`__sync__.now`) was missing from both the count and the channel-by-channel table, in a section
  whose stated purpose is letting a reviewer account for every channel that reaches a contained
  device.
