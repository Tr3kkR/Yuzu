- **Gateway management plane now pins its peer to the server's key (#1422).**
  The `:50063` command-fan-out listener previously admitted *any* cert issued
  by the install CA — including any enrolled agent's leaf and the gateway's own
  group-readable leaf — so one compromised endpoint could command the whole
  fleet and enumerate it. The mgmt listener now runs a grpcbox `auth_fun`
  (`yuzu_gw_authz:check_mgmt_peer/1`) that requires the peer's SPKI SHA-256 to
  match `{yuzu_gw, mgmt_peer_pins}` (default: the shared-volume
  `default-server.pem`, re-read on change so server leaf rotation self-heals;
  bring-your-own-cert installs set `{cert_file, ...}` or `{spki_sha256, "..."}`
  pins, two pins overlap a rotation) plus the `serverAuth` EKU agent leaves
  never carry. Rejections are pre-handler `UNAUTHENTICATED` — a vendored
  grpcbox fix (second `_checkouts` patch hunk) stops terminated streams from
  still executing service handlers. The gateway now **refuses to boot** when a
  network-reachable `management_pb` listener lacks the full posture (strict
  mTLS material, `verify_peer`, `fail_if_no_peer_cert`, the pin `auth_fun`,
  non-empty pins); loopback binds are exempt and `{allow_insecure_mgmt, true}`
  is an explicit lab-rig acknowledgement (pre-seeded in the UAT/demo configs,
  whose composes no longer publish `:50063` to the host — the compose wizard
  likewise stops publishing it and seeds the acknowledgement).
  **Upgrade note:** deployments mounting a custom mTLS mgmt sys.config must add
  the `auth_fun` + `mgmt_peer_pins` (new images refuse to boot without them);
  conversely a config referencing `yuzu_gw_authz` on a pre-#1422 gateway image
  fails with `undef` — a silently dead mgmt plane. Update the image and the
  mounted config **together**: a dev checkout's `reference-gateway-sys.config`
  is ahead of the pinned release image until the next release ships, so do not
  `git pull` that config onto a stack still running the previous image. Full
  ordering guidance: `docs/user-manual/server-admin.md` "Upgrade Notes".
  Remaining tracked residual: no CRL/OCSP check on this path.
