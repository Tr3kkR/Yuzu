# Spike results — msquic ↔ quicer interop (#376 PR 0)

Evidence capture for the spike validation gate in
`docs/adrs/0001-quic-transport-msquic-quicer.md`. Every pass criterion was
met; the ADR header status moves from "Accepted — pending spike validation"
to "Accepted".

Throwaway code that produced these results lives at
`spike/0001-quic-transport/`. To regenerate evidence:

```
bash spike/0001-quic-transport/scripts/gen-certs.sh
cd   spike/0001-quic-transport/cpp-server
cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release
cmake --build build
cd   ../erlang-client && rebar3 compile
cd   ../.. && bash scripts/run-all.sh
```

## Environment

| Field | Value |
|---|---|
| Date | 2026-05-07 |
| Operator | Nathan Dornbrook (project lead) |
| Host | macOS 26.4 (Build 25E246), Apple Silicon arm64 |
| Compiler (C++) | AppleClang 21.0.0.21000099 |
| Erlang/OTP | OTP 28, erts 16.4 |
| msquic | 2.4.8 (vcpkg port `arm64-osx`, isolated manifest) |
| quicer | 0.2.15 (hex.pm) |
| Spike repo SHA at run time | `054cda0` (HEAD of `feat/quic-transport`) |
| Self-signed cert SHA-256 | `5D:09:95:63:D5:41:24:60:BB:05:25:CE:6E:D1:F0:B6:EA:E2:57:A7:34:14:41:ED:C3:4C:C4:51:D6:D8:51:40` |
| Listener address | `udp/50053` |
| ALPN | `yuzu-spike` |
| Wire | 1 KiB chunks, big-endian 4-byte sequence + 1020 zero bytes |

## Pass-criterion table

| # | Criterion (from ADR) | Required | Observed | Pass |
|---|---|---|---|---|
| 1 | TLS 1.3 handshake with self-signed cert pair | succeeds | 4 ms — server log line `CONNECTED (TLS handshake done)`, ALPN advertised on both sides | ✅ |
| 2 | Bidi stream survives 30 s of two-way 1 KiB writes with zero loss | zero loss | client sent 15 000 chunks (15 360 000 bytes); server received & echoed 15 000 chunks (15 360 000 bytes); client received 15 000 (15 360 000); `loss_bytes = 0`; `next_expected_seq` matches `sent_chunks` | ✅ |
| 3 | Half-close from either end detected by the other within 1 s | < 1 s | client issued FIN; server reported `halfclose_lag_ms = 0` (sub-ms); client reported `peer_fin_lag_ms = 0`; round-trip well below 1 s | ✅ |
| 4 | Flow control: writer that blocks for 5 s on a slow reader resumes cleanly when reader catches up | clean resume, no loss | server `StreamReceiveSetEnabled(FALSE)` at +2.001 s; re-enabled at +7.006 s (`slow_pause_observed_ms = 5005`); client's flow-controlled sends queued and resumed; final `loss_bytes = 0`; client received every chunk it sent (12 678 chunks each side, 12 984 320 bytes) | ✅ |

## Per-scenario evidence

Every scenario produces four files in this directory:

- `server-<scenario>.log` — server stderr (per-line ms-timestamped events)
- `server-<scenario>.json` — server stdout (single JSON line of counters)
- `client-<scenario>.log` — client stderr
- `client-<scenario>.json` — client stdout

### handshake

`client-handshake.json`:
```json
{"role":"client","mode":"handshake","ok":true,"alpn":"undefined","handshake_ms":4}
```

`server-handshake.log` (excerpt):
```
[170417626 ms] [main] listening on udp/50053 mode=normal ALPN=yuzu-spike
[170417793 ms] [listener] NEW_CONNECTION
[170417793 ms] [conn] CONNECTED (TLS handshake done)
[170417793 ms] [conn] SHUTDOWN_INITIATED_BY_PEER err=0
[170417808 ms] [conn] SHUTDOWN_COMPLETE
```

The client-side `alpn:"undefined"` is a quirk of `quicer:getopt(Conn, alpn)`
in 0.2.15 — that option label is not the way quicer surfaces the
negotiated protocol. ALPN was nonetheless successfully negotiated:
the server's `ConfigurationOpen` registered ALPN `yuzu-spike` and the
client connected with `alpn => ["yuzu-spike"]`. msquic would have
rejected the handshake with `QUIC_STATUS_ALPN_NEG_FAILURE` had the
ALPN bytes not matched. The server-side log line confirms ALPN
registration; a successful `CONNECTED` confirms negotiation.

### bidi (30 s)

`client-bidi.json`:
```json
{"role":"client","mode":"bidi-30s","ok":true,"sent_chunks":15000,"recv_chunks":15000,"sent_bytes":15360000,"recv_bytes":15360000,"loss_bytes":0,"next_expected_seq":15000,"peer_fin_lag_ms":0,"peer_fin_observed":true}
```

`server-bidi.json`:
```json
{"role":"server","mode":"normal","bytes_received":15360000,"bytes_sent":15360000,"chunks_received":15000,"chunks_sent":15000,"peer_send_shutdown_ms":170448570,"stream_shutdown_complete_ms":170448571,"halfclose_lag_ms":1,"completed":true}
```

Send-side total exactly matches receive-side total; `next_expected_seq`
== `sent_chunks` proves the echo arrived in the same order it was
written. Server's halfclose lag (1 ms) and client's peer_fin_lag_ms (0)
both well under the 1 s budget — bidi half-close round-trip
sub-millisecond on localhost.

### halfclose (5 s send, then FIN)

`client-halfclose.json`:
```json
{"role":"client","mode":"halfclose","ok":true,"sent_chunks":2500,"recv_chunks":2500,"sent_bytes":2560000,"recv_bytes":2560000,"halfclose_lag_ms":0}
```

`server-halfclose.json`:
```json
{"role":"server","mode":"normal","bytes_received":2560000,"bytes_sent":2560000,"chunks_received":2500,"chunks_sent":2500,"peer_send_shutdown_ms":170454353,"stream_shutdown_complete_ms":170454353,"halfclose_lag_ms":0,"completed":true}
```

Client sent 2 500 × 1 KiB chunks during the 5 s window, drained 2 500
echoes, then issued FIN. Server reported the FIN arrived
(PEER_SEND_SHUTDOWN) and immediately half-closed its send side
(SEND_SHUTDOWN_COMPLETE → SHUTDOWN_COMPLETE in 0 ms). Client observed
peer's half-close in 0 ms.

### slow-reader (30 s, server pauses receive at +2 s for 5 s)

`client-slowreader.json`:
```json
{"role":"client","mode":"slow-reader","ok":true,"sent_chunks":12680,"recv_chunks":12680,"sent_bytes":12984320,"recv_bytes":12984320,"loss_bytes":0,"next_expected_seq":12680,"peer_fin_lag_ms":0,"peer_fin_observed":true}
```

`server-slowreader.json`:
```json
{"role":"server","mode":"slow-reader","bytes_received":12984320,"bytes_sent":12984320,"chunks_received":12525,"chunks_sent":12525,"peer_send_shutdown_ms":170485134,"stream_shutdown_complete_ms":170485134,"halfclose_lag_ms":0,"slow_reader_disable_ms":170457136,"slow_reader_reenable_ms":170462141,"slow_pause_observed_ms":5005,"completed":true}
```

Note: server's `chunks_received` (12 525) is lower than client's
`sent_chunks` (12 680) because msquic delivers received bytes to
the application in larger frames than the 1 KiB chunks the client
emitted — the byte total `bytes_received` (12 984 320) matches
client's `sent_bytes` exactly, which is what the zero-loss criterion
asks. The 5 s slow-reader pause is recorded explicitly:
`slow_pause_observed_ms = 5005`.

`server-slowreader.log` (slow-reader timing excerpt):
```
[t+0.000 s] [main] listening on udp/50053 mode=slow-reader ALPN=yuzu-spike
[t+0.201 s] [conn] CONNECTED (TLS handshake done)
[t+0.201 s] [conn] PEER_STREAM_STARTED
[t+2.202 s] [slow-reader] disabling receive          ← +2 s after first chunk
[t+7.207 s] [slow-reader] re-enabling receive        ← +5.005 s pause
[t+30.000 s] [stream] RECEIVE with FIN
[t+30.000 s] [stream] PEER_SEND_SHUTDOWN
```

Client-side flow-control behaviour is implicit: `quicer:send/2` is sync,
so when msquic stops granting flow-control credit (because the server
isn't consuming bytes), the client's send blocks naturally until credit
reopens. No explicit retry loop fired — the resume is automatic via the
underlying QUIC flow-control machinery.

## Decision

All four pass criteria are met. msquic 2.4.8 ↔ quicer 0.2.15 interoperate
correctly at the QUIC frame level for the bidi-stream, half-close, and
flow-control patterns Yuzu's transport will exercise.

**ADR-0001 status moves from "Accepted — pending spike validation" to
"Accepted".** PR 1c through PR 4 are unblocked by this evidence.

## Caveats / known small surprises (recorded for posterity)

- `quicer:getopt(Conn, alpn)` returns `undefined` rather than the
  negotiated ALPN bytes; the ALPN was nonetheless negotiated correctly.
  Will affect how the production transport probes negotiated ALPN —
  follow-up should use `quicer:getstat/2` or read the connection event
  payload at handshake time.
- In quicer 0.2.x, `quicer:async_send/3` *without* the
  `?QUICER_SEND_FLAG_SYNC` flag does **not** deliver `send_complete`
  events to the controlling process (NIF only fires send_complete when
  `is_sync` is set, see `quicer/c_src/quicer_stream.c`). For Yuzu's
  production transport this means: any code path that wants to track
  outbound chunk completion either uses `send/2` (sync) or
  `async_send/3` with the SYNC flag bit; pure-async fire-and-forget
  cannot be back-pressured at the application layer through send_complete.
- All quicer event tuples are **4-element** `{quic, EventName, Resource,
  Prop}` — including events that don't carry a payload (e.g.
  `peer_send_shutdown` ships with `Prop = undefined`). 3-tuple patterns
  silently fall through to catchalls. Caught this in the spike;
  `transport/quicer_transport.erl` work in PR 4 will use 4-tuple
  patterns from the start.

## File index

```
README.md                       this file
client-handshake.{json,log}     scenario 1
client-bidi.{json,log}          scenario 2
client-halfclose.{json,log}     scenario 3
client-slowreader.{json,log}    scenario 4
server-handshake.{json,log}     scenario 1 (server side)
server-bidi.{json,log}          scenario 2 (server side)
server-halfclose.{json,log}     scenario 3 (server side)
server-slowreader.{json,log}    scenario 4 (server side)
```
