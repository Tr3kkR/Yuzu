# TAR removable-media capture

The `removable` TAR source records removable-storage attach/detach activity
and correlates running processes to binaries executing from a currently
attached removable volume (`exec_from_removable`). Like every other TAR
capture source it is **forensic evidence**, not a policy engine — it records
what happened, it does not block anything.

**This source ships DEFAULT-ON.** Every other TAR capture source added since
1.5 has shipped opt-in (`<source>_enabled` defaulting to `false`) pending an
explicit enablement decision. `removable` diverges from that pattern: it is
enabled out of the box, on every OS, from this release. If your fleet
standardises on opt-in capture sources, set `removable_enabled=false`
per-agent or fleet-wide the same way as any other TAR source
(`docs/user-manual/tar.md#configuration`).

Default-on is **not** a finding that this source is privacy-neutral. It
records vendor/product/serial and executed-binary paths — identity and
usage-class data — so the works-council posture applies in full. Under the
Wave 6 ruling (`docs/tar-implementer.md`) that posture attaches to the
**lookback control** rather than to the enable flag: set
`removable_lookback_seconds=0` for forward-only collection on a host where a
retrospective read of the OS's retained removable history is not lawful.
Because the obligation now lands at *upgrade* rather than at an operator's
opt-in, it is a stronger duty to disclose, not a weaker one.

## What it captures

- **`attached` / `detached`** — a removable volume's arrival or departure,
  with vendor/product/serial (or the anonymous-serial fallback identity —
  see below), bus, volume/mount point, and size.
- **`present_at_baseline`** — emitted exactly once, the first time this
  source ever runs on an agent, for every removable device already attached
  at that moment. This is how a device that was plugged in before the agent
  started still gets an identity row, without pretending to know when it was
  actually attached.
- **`exec_from_removable`** — a running process whose canonical on-disk
  executable path resolves under a currently-attached removable volume's
  root. Built from `ProcessInfo::exec_path` **only** — never the command
  line, which on Linux is NUL-flattened and on every OS is attacker/user
  controlled and frequently relative. A process whose executable path could
  not be resolved contributes no row; this source never guesses.
- **`capture_gap`** — a log/channel wrap, a re-enable after a disabled
  window, a persisted cursor that failed to parse (re-baselined per
  `CursorOutcome::CursorLost`), or the capture queue overflowing before a
  batch could be committed. A gap event never fabricates the events it
  couldn't see; it only records the fact that a window is missing. A single
  Windows channel failing outright (as opposed to the whole tick) is
  reported via the collection's `detail` text while its siblings advance —
  it does not itself produce a `capture_gap` row, since the channel's cursor
  is retained unchanged and nothing has actually been lost yet.
- **A missed OS notification is reconciled, not silently absorbed.** Every
  platform re-derives its full current device state each tick and diffs it
  against the persisted attach set; a device the OS never told this source
  about arriving or leaving (a missed DiskArbitration callback, netlink
  datagram, or Partition/Diagnostic record) still produces an explicit
  `attached`/`detached` row, evidenced `...:reconcile:...`, rather than
  drifting the two states out of sync indefinitely.

## Device identity and its one known limitation

Every row carries a `device_key` — a stable identifier for one physical
device, used to group its attach/detach/exec history and to decide which
volumes are "currently attached" for `exec_from_removable` correlation.

- **When the device reports a real serial number**, `device_key` is derived
  from vendor + product + serial. A serial is trusted whenever it is
  non-empty and not a generic placeholder (all-whitespace or all-zero — some
  cheap USB controllers report a fixed `000000000000` for every unit of a
  given model).
- **When the serial is missing or generic**, `device_key` falls back to
  vendor + product + a platform-stable *instance* identifier instead:
  Windows uses the PnP device instance path from the event payload on the
  channel-backfill leg, and (on the live-snapshot leg) the volume's own GUID
  path, falling back to the physical-drive number and then the drive letter
  if neither is available; macOS uses `kDADiskDescriptionMediaUUIDKey`,
  falling back to the BSD device name when no media UUID is reported; Linux
  uses the `/sys/block` device symlink target plus WWID where the controller
  exposes one.

**Known limitation**: the anonymous-serial fallback is not a hardware
identity, only a topology one. Two physically different, generic-serial
devices attached to the *same port/instance path at different times* (e.g.
two identical cheap USB sticks used one after another in the same port) can
be assigned the **same** `device_key`, appearing in the history as one
continuous device. Every row produced via the fallback path is marked in its
`evidence` column (`...anonymous-serial-fallback`), so this ambiguity is
always visible in the data, never silent.

## Hybrid capture model

Two mechanisms feed the same table:

1. **Per-tick snapshot** of currently-attached removable devices, diffed
   against the previous tick's attach set. This is the only source of truth
   on macOS and Linux (neither has a durable removable-media history log this
   source reads).
2. **Cursor-based backfill from durable OS logs**, Windows only (see below).
   Bounded on first run by `removable_lookback_seconds` (default 604800 —
   7 days; `0` disables all pre-enablement history — forward-only capture).

## Per-OS mechanism

### Windows — MEASURED, the-rig, 2026-09-04

Three channels, independently cursored:

| Channel | Role |
|---|---|
| `Microsoft-Windows-Partition/Diagnostic` | Identity authority — every attach/detach row's vendor/product/serial/bus/size comes from here. |
| `Microsoft-Windows-Kernel-PnP/Configuration` | Corroboration — cursor tracked, contributes no rows of its own. |
| `Microsoft-Windows-Storsvc/Diagnostic` | Corroboration — cursor tracked, contributes no rows of its own. |

**`Microsoft-Windows-DriverFrameworks-UserMode/Operational` is deliberately
NOT read.** It was the original design's assumption; a live measurement
against real hardware found it `IsEnabled=False` on a stock Windows box — an
implementation built on it would ship green in review and capture nothing,
forever. This is a corrected divergence from the original design, not an
oversight.

**Attach and detach share the same Event ID (1006).** There is no distinct
removal event on this channel. The two are told apart purely by payload: an
attach carries a non-zero `Capacity`/`BytesPerSector`/`PartitionCount` and
`UserRemovalPolicy=true`; a detach of the same device (same `SerialNumber`,
same `DiskId`) carries all-zero geometry fields and
`UserRemovalPolicy=false`. Removable-vs-internal is decided by `BusType`
(USB = `7`) — **not** by event ID; the same channel logs BusType `17`
(NVMe) rows for every internal disk, on the same event ID, and those are
excluded before anything reaches the database.

`Kernel-PnP/Configuration` is a circular buffer and **will wrap** — a real
capture on the-rig observed it evict from 1432 to 1352 retained records
during one attach/detach cycle. A stored cursor pointing behind the
channel's current oldest-retained record is reported as a `capture_gap`
naming the channel, and that channel alone re-baselines at its current head
— the other two channels' cursors are untouched.

`HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` is **not read at collection
time**. It is a *history* key (populated on first-ever attach, retained
after detach, absent when nothing has ever been attached) rather than a
liveness signal, and the Partition/Diagnostic channel alone already carries
everything this source's identity columns need. Its absence on a clean
machine is expected, not an error.

`setupapi.dev.log` parsing is **out of scope** for this release — flagged
here as a follow-up, not silently dropped.

### macOS — CONSTRAINED, live-only

DiskArbitration (`DARegisterDiskAppeared/DisappearedCallback`, filtered on
`kDADiskDescriptionMediaRemovableKey`/`MediaEjectableKey`) on a private
dispatch queue. macOS has no durable removable-media log this source reads,
so capture is **live-only**: an attach/detach that happens while the agent
is stopped, or during a disabled window, produces a `capture_gap` on the next
start/re-enable, never a backfilled row. Baseline uses `getfsstat` (the same
mechanism `tar_mapdrive`'s macOS leg uses) plus
`DADiskCreateFromBSDName`/`DADiskCopyDescription`.

### Linux — CONSTRAINED

A `NETLINK_KOBJECT_UEVENT` socket, opened once and drained non-blocking each
tick, for `SUBSYSTEM=block`/`DEVTYPE=disk` add/remove events (partition
sub-devices are excluded). Identity comes from `/sys/block/<dev>/{removable,
device/vendor,device/model,device/serial}`, best-effort — many USB
mass-storage bridges don't expose all four files, and this source degrades
identity rather than guessing. Baseline is a `/sys/block` scan. Like macOS,
this is live-only: no durable history log is read.

`exec_from_removable` correlation reads `/proc/mounts` (the kernel symlink to
`/proc/self/mounts`) each tick and matches every row whose mount source is
`/dev/<name>` against the removable disks this leg currently knows about —
`nvme0n1p2`/`mmcblk0p1`-style partition names map to their parent whole-disk
name, and classic `sdb1`-style names strip their trailing partition number;
the kernel's octal escapes in the mount-point field (`\040` etc.) are
decoded. A failed `/proc/mounts` read degrades to **no** exec-from-removable
roots for that tick only — attach/detach/baseline capture is unaffected, and
because the correlation re-runs every tick, a transient failure recovers on
its own on the next successful read (never an error, never a fabricated
gap). **Known residual limitation**: a removable device mounted through an
intermediate device-mapper layer — most commonly a LUKS-encrypted stick,
which appears as `/dev/mapper/*` rather than the underlying `/dev/sdX`
partition — does not correlate, because the mount source is not the
removable block device itself; executions from such a volume are not
claimed by this source.

## Configuration

Same shape as every other TAR cursor-model source
(`docs/user-manual/tar.md#configuration`):

| Key | Default | Meaning |
|---|---|---|
| `removable_enabled` | `true` | Master on/off switch. **Default-on** — see above. |
| `removable_lookback_seconds` | `604800` (7 days) | First-run Windows backfill window. `0` = forward-only, no pre-enablement history. |

## Hardware checks needed from you

The device-**present** path (an actual USB mass-storage device attached and
then removed) is built and fixture-tested against a REAL Windows capture
(the-rig, 2026-09-04 — a Kingston DataTraveler 3.0), but that capture was
taken on a desktop with no removable device *attached during the automated
test run itself*: `HKLM\...\USBSTOR` is absent and the live snapshot leg sees
zero removable volumes on that host, so CI and every local gate exercise only
the honest-empty / no-device path. If you have a Windows machine (laptop or
desktop) you can attach a USB stick to:

1. Attach a USB mass-storage device, wait a few seconds, then safely eject
   it.
2. Run this exact query and paste the raw XML rows here as a candidate REAL
   CAPTURE fixture (replace nothing — the command is complete as written):

   ```powershell
   wevtutil qe Microsoft-Windows-Partition/Diagnostic /c:10 /f:xml
   ```

3. **Expected output shape**: at least two `<Event>` records with
   `<EventID>1006</EventID>` and the same `SerialNumber`/`DiskId` — one with
   non-zero `Capacity`/`BytesPerSector`/`PartitionCount` and
   `UserRemovalPolicy=true` (the attach), one with all of those zeroed and
   `UserRemovalPolicy=false` (the detach).
4. **Pass criteria**:
   - Both rows carry `BusType=7`.
   - `Manufacturer`, `Model`, and `SerialNumber` are populated (not `NULL`/
     empty) on both rows.
   - The automated test suite's explicit no-device `SKIP`
     (`test_tar_removable.cpp`, "no removable device attached on this host —
     device-present leg not exercised") does **NOT** appear when you run the
     tests on your machine with the device attached — its absence is the
     signal the real device-present leg executed and was asserted, not
     skipped.

Until that capture lands, the device-present path is **not** described as
"verified" anywhere in this source's docs, changelog, or capability
declaration — only the no-device path (which is what every CI/local run
actually exercises) is. The fixture seam
(`tests/unit/test_tar_removable.cpp`) accepts a pasted real capture as a
drop-in replacement for the current trimmed the-rig fixtures without any
test reshaping.
