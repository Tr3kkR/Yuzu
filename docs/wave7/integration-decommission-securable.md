# Integration: Decommission securable promotion (P26)

`docs/enterprise-readiness-soc2-first-customer.md` is integrator-owned (P26's
boundaries forbid editing it directly). Two of its rows describe the old
`SoftwareLicensing:Delete AND Inventory:Delete AND GuaranteedState:Delete`
gate and must be updated to match the promoted `Decommission:Delete`
securable this package ships. Splice the verbatim replacements below.

## 1. Line :343 — Installed-software inventory row

Find (inside the "Per-device purge is WIRED" cell):

```
(scoped `SoftwareLicensing:Delete` **and** `Inventory:Delete` **and**
`GuaranteedState:Delete` — a conjunction over every securable the cascade
erases through; audit-before-erase fail-closed)
```

Replace with:

```
(scoped `Decommission:Delete` — a device-level erasure securable
authorizing for the cascade's whole blast radius, replacing the earlier
per-store conjunction (ADR-0024 Decision 9, amended Wave 7 PR7.2);
audit-before-erase fail-closed)
```

## 2. Line :348 — Software-licensing detection inventory row

Find:

```
The **agent-decommission cascade** (`AgentDecommission` fanning
`SoftwareLicensingStore::delete_agent` across all five per-agent stores,
built by ADR-0024) is **LIVE**, triggered by **`DELETE
/api/v1/sle/agents/{id}`**: gated on the per-device scoped
`SoftwareLicensing:Delete` **and** `Inventory:Delete` **and**
`GuaranteedState:Delete` conjunction (the cascade's blast radius spans all
three securables),
```

Replace with:

```
The **agent-decommission cascade** (`AgentDecommission` fanning
`SoftwareLicensingStore::delete_agent` across all six per-agent stores,
built by ADR-0024) is **LIVE**, triggered by **`DELETE
/api/v1/sle/agents/{id}`**: gated on the per-device scoped
`Decommission:Delete` securable (ADR-0024 Decision 9, amended Wave 7
PR7.2) — one grant authorizing for the cascade's whole blast radius, in
place of the earlier per-store conjunction,
```

(The literal phrase to search-and-replace both times is **`scoped
`Decommission:Delete``** in place of the old three-securable conjunction
text — kept above in full for exact byte matching since the surrounding
prose differs slightly between the two rows.)

## 3. `app_usage_store` data-inventory row wording (for P24)

P24 owns adding the `app_usage_store` row to this same table. Per PLAN-01
ruling (b) and this package's cascade wiring, P24's row's disposal-method
cell must say the store is the SIXTH member of the cascade and use
`Decommission:Delete`, not any of the old per-store securables:

```
**Whole-device purge is WIRED** (ADR-0024, Wave 7 PR7.2) —
`AppUsageStore::delete_agent` is the sixth store fanned by the
`AgentDecommission` cascade behind the audited **`DELETE
/api/v1/sle/agents/{id}`** route, gated on the per-device-scoped
`Decommission:Delete` securable (not `Forensics:Delete` — `Forensics`
governs this store's READ route only). The store's two-table
(`usage_state` + `agent_last_used`) single-transaction delete means it can
never be half-erased inside one decommission attempt. **Row-level /
per-subject DSAR (Art. 17) erasure remains unwired** — the cascade is
whole-device only (#1666).
```

## 4. `git grep` — every conjunction string that must be gone

Run from the repo root after both P26 and P24 land:

```
git grep -n 'SoftwareLicensing:Delete.*Inventory:Delete.*GuaranteedState:Delete\|SoftwareLicensing.*∧.*Inventory.*∧.*GuaranteedState'
```

Expected surviving hits (allowlisted — history/preserved text, not a live
instruction to fix):

- `changelog.d/264-software-licensing-detection.added.md` — a released
  changelog fragment; released fragments are never edited.
- `docs/adr/0024-software-licensing-entitlements.md` Decision 9's
  *Reversed 2026-09-06 (Wave 7 PR7.2):* paragraph — deliberately quotes the
  original conjunction and rejection text as history (the whole point of a
  "Reversed" annotation is to keep what it reversed legible).
- `docs/authz-model.md` — P0-owned; its `Decommission` securable row
  describes the conjunction it replaces as history. Not touched by P26
  (boundaries).
- `server/core/src/rbac_store.cpp` — P0-owned comment quoting the old
  conjunction as the rationale for the `Decommission` seed grants. Not
  touched by P26 (boundaries).

Any OTHER hit (in particular `docs/enterprise-readiness-soc2-first-customer.md`
lines :343/:348, until this integration is spliced in) is a live instance
still describing the retired gate and must be fixed via section 1/2 above.
