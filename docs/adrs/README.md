# Architecture Decision Records

This directory records significant architectural decisions made during
Yuzu development. ADRs are the authoritative record of *why* a load-
bearing decision was made; they are referenced by `CLAUDE.md`, by the
governance pipeline (Gate 6 compliance-officer cites them as
Workstream F evidence), and by the SOC 2 change-management trail.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-quic-transport-msquic-quicer.md) | Use msquic + quicer for QUIC transport | Accepted — pending spike validation (#376) |

## Format

Files are named `NNNN-short-slug.md` with a four-digit zero-padded
sequence prefix and a kebab-case slug. Status values follow the Nygard
convention:

- **Proposed** — under review
- **Accepted** — ratified; implementation may begin
- **Rejected** — considered and turned down
- **Superseded** — replaced by a later ADR (link to the successor)

The header of each ADR carries: Status, Accepted-by (named approver +
date), Tracking issue, Supersedes, Related. The body covers Context,
Decision, Alternatives considered, Consequences (positive + negative),
Mitigation matrix, References.

When an ADR's status flips (e.g., a spike-validation gate fails and
status changes from Accepted → Rejected), update the file in place and
add a one-line note in this index. A successor ADR (if any) is added
as a new file with a new sequence number, not by renaming the old one.

## Historical decisions

Decisions predating this log live in `historical/`. They were not
recorded as ADRs at the time and are reconstructed retrospectively
from issues, commit messages, and CLAUDE.md context. Issue #367 tracks
the backfill effort.
