# app_usage fixtures (Wave 7 / A2)

Real process-lifecycle captures for the usage-tracking / process-events parsers.

## Files

| File | What it proves |
|---|---|
| `process_events_linux.txt` | 135 lines, real capture from a `ubuntu:24.04` container: `/proc/[0-9]*/status` polled every ~150ms for ~20s while 46 short-lived processes were spawned. |
| `process_events_macos.txt` | 123 lines, real capture from this Mac: `ps -axo pid,ppid,comm,user` polled every ~150ms for ~20s while 45 short-lived `/bin/sleep` processes were spawned (filtered post-capture to the synthetic `sleep` processes to stay legible — see its `.provenance.txt`). |

## Format (this fixture set's own convention — not a wire format)

```
ts_unix|action|pid|ppid|image_name|user
```

`action` is `started` or `stopped`, derived by diffing consecutive poll
snapshots (appearance/disappearance), matching what
`agents/plugins/tar/src/tar_proc_stream.cpp` produces conceptually. That
source does **not** emit this line format — it emits a typed `ProcEvent`
struct (`tar_proc_stream.hpp:27-51`: `ts_unix`, `is_start`, `pid`, `ppid`,
`image_name`, `sid`, `user`, `uid`, `exit_code`). The mapping is
`action=started` → `is_start=true`, `action=stopped` → `is_start=false`,
`name` → `image_name`. A test consuming these fixtures needs to translate
this line format into `ProcEvent` values itself.

## Pairing shapes present (what P21 needs)

Both files were checked for the three shapes a process-event consumer must
handle:

| Shape | Linux | macOS |
|---|---|---|
| A pid whose start **and** stop both appear | present — 64 matched pairs | present — 61 matched pairs |
| An orphan stop (stop with no observed start — a process already running before capture began) | present — 3 pids (`8`, `9`, `11`; the container's early PID-1/helper shells, one of which was a deliberately pre-spawned `sleep 3` still running when sampling started) | present — 1 pid (`21213`, the deliberately pre-spawned `sleep` running before the first sample frame) |
| A pid reuse (a pid that stops and is later reassigned to a different process within the capture window) | **absent** — not observed in this run. 20s / 46 processes on this container's pid namespace did not cycle a pid back into use before capture ended. | **absent** — not observed in this run for the same reason. |

Pid reuse is real-world genuine but did not occur in either capture window;
it is recorded here as absent-because-not-observed, not reconstructed by
hand (reconstructing a pid-reuse line would misrepresent it as captured
data). A consumer test needing that shape should either widen the capture
window/process count to increase the odds of reuse, or treat it as an
explicitly synthetic case in the test itself rather than relying on this
fixture.

Also present in both files: starts with no observed stop (process still
running when capture ended) — 4 on Linux, 0 on macOS — a fourth real shape
worth knowing about even though it wasn't asked for by name.

## Windows process events

Not captured here. Windows process-lifecycle data in this repo comes from
the ETW collector (`agents/plugins/tar/src/tar_proc_etw.cpp`), and its
existing in-tree fixture corpus is `tests/unit/test_tar_proc_etw.cpp` —
use that corpus rather than fixtures in this directory.
