# START HERE

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

## Goal

Find and verify **kernel memory-write vulnerabilities** in Windows kernel drivers.

Only kernel memory writes count. Hardware-only writes (MSR/port/PCI/SMBus/EC/MMIO) are
`HW-ONLY`. Local-administrator reachability (`R2`) is in scope. Setup is a severity field,
not a disqualifier.

## Read in this order

1. [`PROJECT_GOAL.md`](PROJECT_GOAL.md) — the single statement of the goal.
2. [`PROJECT_MAP.md`](PROJECT_MAP.md) — where everything lives.
3. [`audits/scope/AUDIT_SCOPE.md`](audits/scope/AUDIT_SCOPE.md) — reach tiers and what counts.
4. [`audits/scope/SEVERITY.md`](audits/scope/SEVERITY.md) — MW1–MW4 / `NO-MEMORY-WRITE` / `BLOCKED`.
5. [`audits/scope/STATIC_ANALYSIS_AGENT_PROMPT.md`](audits/scope/STATIC_ANALYSIS_AGENT_PROMPT.md) — default audit prompt.
6. [`audits/STATUS.md`](audits/STATUS.md) — **single live status and queue**.
7. [`DRIVER_COLLECTION_PLAYBOOK.md`](DRIVER_COLLECTION_PLAYBOOK.md) — how to download/harvest more drivers.
8. [`downloads/README.md`](downloads/README.md) — quick-start for a future download.

## Current status

- Corpus: **386 unique drivers in the repo** (verified exports removed), all flat in
  [`drivers/`](drivers/). The manifest has **387 rows**: it also records local-only `vgk.sys`.
- Batch provenance: `indexes/drivers_manifest.csv` and `indexes/collections/`.
- `indexes/dedupe/existing_hashes.txt` — **925 tracked** (+7 exported hashes kept in the gitignored local gate)
- Known-bad: 5,833 hashes (`indexes/dedupe/known_bad_hashes.txt`).
- Live audit status and queue: [`audits/STATUS.md`](audits/STATUS.md).
- Reports: [`audits/reports/`](audits/reports/) (current + retained historical; `STATUS.md` is
  authoritative).

## Rules for AI agents

- **One drivers folder:** new drivers go in `drivers/`, after the dedupe gate. Do not create
  `_collectedN`, `v2`, `new`, or parallel project trees.
- **Only `.sys` in `drivers/`.** No installers, no `.inf`/`.cat`, no app trees, no screenshots.
- **Downloads are scratch:** download and extract in `downloads/`; run
  `tools/filter_new_drivers.ps1 -OutDir drivers -UpdateExisting` to copy only deduped `.sys`
  into `drivers/`; delete the rest. Do not copy by hand. See `DRIVER_COLLECTION_PLAYBOOK.md` §2.1.
- **Batch metadata:** put URLs, manifests, and summaries in
  `indexes/collections/collected<N>/`; put the driver hashes in `indexes/drivers_manifest.csv`.
- **PoCs:** future PoCs go in `poc/<driver>/`; historical harnesses are in `poc/historical/`.
  Never run them on the host.
- **Audits:** current reports go in `audits/reports/`; old reports go in `audits/legacy/`.
- Use `tools/filter_new_drivers.ps1 -UpdateExisting` before adding any driver; it is the only
  writer into `drivers/` and keeps the dedupe gate current.
- Read `PROJECT_GOAL.md`, `audits/scope/AUDIT_SCOPE.md`,
  `audits/scope/SEVERITY.md`, and the default prompt before auditing.
- Static analysis only on the host; dynamic testing only in the snapshotted VM (local gitignored `VM_ACCESS.md`).
