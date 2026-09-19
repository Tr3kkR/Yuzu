- **Breaking — Gateway distribution cookie now requires a minimum 32-character length.**
  DNS-based cluster discovery (`#4555`) means a gateway node dials addresses
  it did not choose by hand, and the Erlang distribution handshake's
  initiator sends the cookie hash first — a short custom cookie is
  brute-forceable offline from a legitimately-dialing node. Set
  `YUZU_GW_COOKIE` to a real generated value (`openssl rand -hex 32`); the
  existing `YUZU_GW_ALLOW_DEFAULT_COOKIE=1` dev/CI override still bypasses
  this, unchanged.
