- **OIDC JWT signature verification now fails closed on Windows (#1856).** On the
  Windows server build, `OidcProvider::verify_jwt_signature` was a stub that
  returned success without verifying the token signature — an attacker-forged ID
  token would have been accepted, allowing arbitrary OIDC session minting
  (account takeover). It now returns an error (OIDC login is refused on Windows)
  until a BCrypt/CNG verifier is implemented. Linux/macOS (OpenSSL) verification
  is unchanged. Yuzu is Linux-first, so this path was likely latent in practice;
  the fix removes the forged-token hole regardless.
