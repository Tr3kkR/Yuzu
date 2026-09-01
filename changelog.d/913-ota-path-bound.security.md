- **The agent OTA pull path is now bounded (#913, #911, #416).**
  `DownloadUpdate` previously had no bound in any dimension: any
  mTLS-authenticated agent could open unlimited parallel streams, each pinning
  a gRPC thread on blocking disk reads and network writes, and monopolise
  fleet-update capacity. Every pull is now admitted through a per-peer gate
  with two independent dimensions — in-flight concurrency
  (`--ota-max-concurrent-per-peer`/`YUZU_OTA_MAX_CONCURRENT_PER_PEER`, default
  2) and a token bucket (`--ota-rate-capacity`/`YUZU_OTA_RATE_CAPACITY`,
  default 20; `--ota-rate-refill-per-min`/`YUZU_OTA_RATE_REFILL_PER_MIN`,
  default 1). The concurrency cap is the primary defence and the bucket is
  deliberately loose: the attack is parallel streams, which a semaphore stops
  exactly, whereas a tight bucket meters retries and locks out honest
  slow-link and flapping agents. Exhausting either returns gRPC
  `RESOURCE_EXHAUSTED` and increments the pre-seeded, bounded-label
  `yuzu_ota_download_admission_total{decision}` counter, with refunds tracked
  separately on `yuzu_ota_download_refund_total{reason}` so `decision` stays a
  true partition. Admission keys on the
  peer certificate identity, falling back to peer IP when none is presented
  (the agent listener does not always require a client certificate, and a
  single shared bucket would let one unenrolled agent lock out the rest); the
  keying in force is visible on
  `yuzu_ota_admission_key_mode_total{mode}`, and the per-peer map is capped by
  `--ota-max-peers-tracked`/`YUZU_OTA_MAX_PEERS_TRACKED` (default 50000).
- **OTA transfers are deadline-bounded (#911).** A whole-transfer deadline
  (`--ota-transfer-deadline-secs`/`YUZU_OTA_TRANSFER_DEADLINE_SECS`, default
  900) is enforced by cancelling the RPC from a watchdog thread — the only
  mechanism that unblocks a synchronous `ServerWriter::Write` stalled on a
  collapsed HTTP/2 receive window, which keepalive does not detect. A separate
  per-chunk bound
  (`--ota-chunk-write-deadline-secs`/`YUZU_OTA_CHUNK_WRITE_DEADLINE_SECS`,
  default 30) aborts a slow-drip peer earlier; raise it for fleets on
  genuinely slow links. Both surface on
  `yuzu_ota_download_deadline_exceeded_total{phase}`. A transfer that trips a
  server-imposed deadline REFUNDS its rate token, so a slow or flapping agent
  cannot spend itself into a lockout.
- **Server-wide gRPC resource bounds (#913).** The single `ServerBuilder`
  previously set keepalive/ping arguments and nothing else — no
  `ResourceQuota` and no stream cap existed anywhere on the server, which is
  what made the unbounded OTA path severe rather than theoretical. It now
  carries a per-connection HTTP/2 stream cap
  (`--grpc-max-concurrent-streams`/`YUZU_GRPC_MAX_CONCURRENT_STREAMS`, default
  128) and a `ResourceQuota` memory ceiling
  (`--grpc-max-resource-memory-mb`/`YUZU_GRPC_MAX_RESOURCE_MEMORY_MB`, default
  512). Both reject at capacity rather than queueing.
- **Positive peer identity on the OTA RPCs (#416, PARTIAL — does not close it).**
  `CheckForUpdate` and
  `DownloadUpdate` previously checked only that a peer was *not* revoked, and
  the `agent_id` in the request body was unverified despite selecting rollout
  eligibility. Both now require a positive certificate identity and bind the
  claimed `agent_id` to the certificate's CN/SAN, rejecting a mismatch with
  `UNAUTHENTICATED` plus a `session.ota_identity_rejected` audit row and the
  `yuzu_grpc_ota_identity_rejected_total{event="security",rpc,reason}` counter.
  A request omitting `agent_id` entirely is refused with `INVALID_ARGUMENT`
  rather than skipping the bind, so the check cannot be evaded by omission.
  This is gated on the agent listener actually requiring a client certificate,
  so the default-certificate bootstrap path for unenrolled agents is
  unaffected.

  **This does NOT close #416.** That issue also asks for update binaries to be
  signed and the signature verified agent-side. The agent verifies a SHA-256
  today, but against a hash the server supplied over the same channel — that is
  integrity, not authenticity, and it does not help if the channel or server is
  the thing you are defending against. Signing is release-plane work touching
  the packaging pipeline and is tracked separately; #416 stays open.
- **Caveat — per-process, not fleet-wide.** OTA admission state lives in one
  server process's memory. Behind a load balancer with two or more replicas a
  peer that reconnects to a different replica gets a fresh allowance, so the
  effective ceiling is `configured_cap x replica_count`. This is not a
  regression (no limit existed before), but it is a real ceiling on the
  guarantee; shared cross-instance state is follow-up work. Admission
  rejections are metric-only with no audit row (a high-frequency operational
  event, not a lifecycle action). See `docs/user-manual/server-admin.md`.
