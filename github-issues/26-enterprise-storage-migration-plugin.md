---
title: "[ENT] Storage migration orchestration plugin (e.g., NetApp → Pure Storage)"
labels: enhancement, enterprise, plugin, storage
assignees: ""
---

## Summary

Enterprise environments need the ability to safely migrate a machine's primary OS and data storage from one array to another (e.g., NetApp → Pure Storage) with minimal downtime, verification at every step, and rollback capability. Yuzu's agent+plugin architecture is uniquely positioned to orchestrate this across a fleet — the agent is already on each machine, the command dispatch supports streaming output and progress reporting, and the dashboard provides real-time visibility.

This issue covers building a `storage-migrate` plugin and the supporting server-side orchestration workflow.

## Migration Methods Available

The right method depends on virtualization layer, OS, filesystem, and array capabilities. A production plugin should support multiple strategies:

### 1. Host-side LVM mirror + pvmove (Linux — recommended for block storage)

Best for: Linux machines with LVM, block-level LUNs (iSCSI/FC).

| Step | Action | Downtime |
|------|--------|----------|
| 1 | Discover current PVs, VGs, LVs, mount points | None |
| 2 | Present new Pure LUN to host (multipath/rescan) | None |
| 3 | `pvcreate` on new LUN | None |
| 4 | `vgextend <vg> <new_pv>` | None |
| 5 | `pvmove <old_pv> <new_pv>` (live block migration) | None |
| 6 | `vgreduce <vg> <old_pv>` | None |
| 7 | `pvremove <old_pv>` | None |
| 8 | Verify checksums / data integrity | None |
| 9 | Remove old NetApp LUN from host | None |

**Total downtime: zero** (pvmove is online). One reboot may be desired to confirm boot-from-new-array if the migrated volume includes `/boot`.

### 2. Pure Storage array-level import (Pure Cloud Block Store / Purity)

Best for: When both arrays have SAN connectivity.

Pure supports native volume import from NetApp (ONTAP) via:
- **Pure Purity `purevol import`** — copies data at the array level
- **Pure Cloud Block Store** host-side migration tool

Yuzu's role: trigger the import via CLI/API on the agent, monitor progress, verify, cutover multipath.

### 3. rsync / filesystem-level copy (NFS or data-only volumes)

Best for: NFS mounts, non-boot data volumes, file servers.

| Step | Action | Downtime |
|------|--------|----------|
| 1 | Mount new Pure NFS export alongside old | None |
| 2 | Initial `rsync -avHAX --progress` | None |
| 3 | Quiesce application (stop writes) | **Brief** |
| 4 | Final `rsync --delete` (delta sync) | **Brief** |
| 5 | Remount new path, restart application | **Brief** |
| 6 | Verify checksums | None |

**Total downtime: seconds to minutes** (final sync + remount).

### 4. Multipath cutover (dual-fabric SAN)

Best for: Machines with multipath I/O already configured.

Present both NetApp and Pure LUNs simultaneously. Use `dm-multipath` to add the Pure path, verify I/O, then remove the NetApp path. Essentially a path migration, not a data migration — requires array-level replication first.

### 5. OS-level disk cloning (boot volume migration)

For migrating the boot/OS volume:
- `dd` with `conv=sync,noerror` from old block device to new
- Or `clonezilla`-style image-based
- Requires reboot to boot from new device
- Update GRUB/bootloader to reference new device
- Update `/etc/fstab` with new UUIDs

**Total downtime: one reboot**.

### 6. VMware Storage vMotion (virtualized environments)

If machines are VMs: Storage vMotion migrates VMDK files between datastores with zero guest downtime. Yuzu agents on the VMs can verify pre/post but the migration itself is handled by vCenter. A Yuzu server-side integration could call the vSphere API.

---

## How Yuzu Helps

### Plugin: `storage-migrate`

A new Yuzu plugin deployed to agents on target machines. Actions:

| Action | Description |
|--------|-------------|
| `preflight` | Discover current storage layout (LVM, mounts, multipath, array type). Report readiness. |
| `present_lun` | Rescan SCSI bus, discover new Pure LUN, create multipath device |
| `migrate_lvm` | Execute pvmove from old PV to new PV (stream progress via `yuzu_ctx_report_progress`) |
| `migrate_rsync` | rsync from old mount to new mount, report delta stats |
| `verify` | Checksum comparison (block-level or file-level) between old and new |
| `cutover` | Update fstab, remount, update bootloader if needed |
| `rollback` | Reverse cutover — remount old, remove new PV |
| `cleanup` | Remove old PV, unmount old NFS, remove stale multipath paths |
| `status` | Report current migration state for this machine |

### Server-side orchestration (dashboard / ManagementService)

The server coordinates fleet-wide migration:

1. **Batch scheduling** — Migrate machines in rolling batches (e.g., 10 at a time)
2. **Dependency awareness** — Don't migrate DB replicas simultaneously; respect HA groups
3. **Pre-flight gate** — All machines in a batch must pass `preflight` before any begin
4. **Progress dashboard** — Real-time SSE events showing per-machine migration progress
5. **Automatic rollback** — If `verify` fails, trigger `rollback` automatically
6. **Audit trail** — Every action logged with timestamps (see audit logging issue)

### Workflow example (LVM migration)

```
Operator: POST /api/command
{
  "plugin": "storage-migrate",
  "action": "preflight",
  "agent_ids": ["machine-01", "machine-02", ..., "machine-50"]
}

  → All agents report: VG=data_vg, PV=/dev/sda3 (NetApp), Free PE=0
  → All pass preflight ✓

Operator: POST /api/command
{
  "plugin": "storage-migrate",
  "action": "present_lun",
  "parameters": {
    "target_wwn": "5001500150015001",
    "expected_size_gb": "500"
  },
  "agent_ids": ["machine-01", ..., "machine-10"]   // Batch 1
}

  → Agents rescan SCSI, find /dev/sdb (Pure), create multipath device
  → Report: new_device=/dev/mapper/mpath1, size=500G ✓

Operator: POST /api/command
{
  "plugin": "storage-migrate",
  "action": "migrate_lvm",
  "parameters": {
    "source_pv": "/dev/mapper/mpath0",
    "target_pv": "/dev/mapper/mpath1"
  },
  "agent_ids": ["machine-01", ..., "machine-10"]
}

  → Agents stream: "pvmove: 10%... 20%... 50%... 100%"
  → Progress visible in dashboard via /events SSE

Operator: POST /api/command  { action: "verify", ... }
  → Agents report: block checksums match ✓

Operator: POST /api/command  { action: "cutover", ... }
  → Agents update fstab, confirm new mount

Operator: POST /api/command  { action: "cleanup", ... }
  → Agents remove old NetApp PV
```

---

## Implementation Plan

### Phase 1: Core plugin (Linux LVM + rsync)

1. Create `agents/plugins/storage-migrate/` with C ABI plugin
2. Actions: `preflight`, `migrate_lvm`, `migrate_rsync`, `verify`, `status`
3. Use `yuzu_ctx_report_progress()` for pvmove/rsync progress streaming
4. Use `yuzu_ctx_write_output()` for structured JSON status updates
5. Unit tests with mock block devices (loopback + LVM)

### Phase 2: Cutover, rollback, and LUN management

6. Actions: `present_lun`, `cutover`, `rollback`, `cleanup`
7. fstab manipulation with backup/restore
8. Bootloader update for boot volume migration
9. Multipath device management (multipathd integration)

### Phase 3: Server-side orchestration

10. Batch scheduling API (`POST /api/migrate/start` with batch config)
11. Pre-flight gate logic (all-pass-or-abort)
12. Automatic rollback on verify failure
13. Dashboard migration progress view
14. InventoryReport integration (storage inventory per agent)

### Phase 4: Platform expansion

15. Windows support (Storage Spaces, disk management via PowerShell)
16. VMware vMotion integration (vSphere API from server)
17. Pure Storage REST API integration for array-level imports

---

## Safety and Verification

Every step must be idempotent and reversible:

| Concern | Mitigation |
|---------|-----------|
| Data loss | Block-level or file-level checksums before and after every migration step |
| Partial migration | `status` action reports exact state; `rollback` reverses to last known-good |
| Boot failure | Bootloader updated only after verified copy; old boot entry preserved |
| Fstab corruption | Backup `/etc/fstab` before modification; rollback restores backup |
| Network partition | Agent continues local migration; reports status on reconnect |
| Concurrent access | Plugin acquires advisory lock; rejects concurrent migrate commands |
| Wrong LUN | `present_lun` validates expected size, WWN, and array serial number |

## Acceptance Criteria

- [ ] `storage-migrate` plugin builds and loads on Linux agents
- [ ] `preflight` reports LVM layout, mount points, multipath status
- [ ] `migrate_lvm` executes online pvmove with progress streaming
- [ ] `migrate_rsync` performs delta sync with progress
- [ ] `verify` compares block checksums (SHA-256) between source and target
- [ ] `cutover` updates fstab and optionally bootloader
- [ ] `rollback` reverses any step back to original state
- [ ] End-to-end test with loopback devices simulating NetApp→Pure
- [ ] Dashboard shows real-time per-machine migration progress
- [ ] Audit log captures all migration actions with timestamps

## References

- Plugin ABI: `sdk/include/yuzu/plugin.h`
- Command dispatch: `proto/yuzu/agent/v1/agent.proto`
- Progress reporting: `yuzu_ctx_report_progress()`, `yuzu_ctx_write_output()`
- Inventory reporting: `ReportInventory` RPC for storage layout data
