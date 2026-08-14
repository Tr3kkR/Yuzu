- **SAML 2.0 SP AuthnRequests can now be signed.** New `--saml-sp-key`
  (`YUZU_SAML_SP_KEY`) flag points at an SP signing private key PEM
  (**RSA only** — EC and RSA-PSS keys are rejected). When set, SP-initiated
  AuthnRequests are signed over the HTTP-Redirect binding with
  RSA PKCS#1 v1.5 + SHA-256 (`SigAlg`
  `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`), carried as the
  `SigAlg`/`Signature` query parameters. The flag is optional and
  backward-compatible: when unset, AuthnRequests remain unsigned, same as
  prior releases. Fails closed — a configured key that is unreadable,
  over-permissioned, oversized, malformed, encrypted, or not RSA disables SAML entirely
  at boot (loudly, never a silent fall-back to unsigned requests), and a
  per-request signing failure fails `/auth/saml/start` rather than emitting
  an unsigned redirect.
