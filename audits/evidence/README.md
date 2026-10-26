# Dynamic evidence

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

VM-phase evidence for the t4–t10 runs: logs, scripts, transcripts, and decompiled snippets.
t1–t3 evidence was not migrated; reports that cite `t1_*`/`t3_*` are historical. This is
**evidence**, not a reusable toolkit.

- PoC sources and compiled harnesses are in [`../../poc/historical/`](../../poc/historical/).
- Reports written before 2026-10-24 call this folder `audits\dynamic_evidence\`; the current path
  is `audits/evidence/`.
- Do not run anything here on the host. Dynamic work only in the snapshotted VM.
- VM rules live in the local, gitignored `VM_ACCESS.md`; never in this repo.
- Current severity: [`../scope/SEVERITY.md`](../scope/SEVERITY.md).
- Current status: [`../STATUS.md`](../STATUS.md).

`t7_guest_vsock.sys` is retained because it is the guest build used for the t7 comparison, not as
corpus. The corpus copy is `drivers/vsock.sys` (look up its hash in
`indexes/drivers_manifest.csv`).
