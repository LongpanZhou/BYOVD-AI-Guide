# Project Goal - Set Up and Run Your Own Hunt

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

> [!NOTE]
> This branch ships **instructions only**: the folder skeleton, the ledgers, and the method. Your
> lab starts at zero - no drivers, no reports, no verdicts. The worked example (a full corpus and
> its results) lives on the [`example`](https://github.com/LongpanZhou/BYOVD-AI-Guide/tree/example)
> branch.

## Goal

Set up your own lab and run your own hunt for **kernel memory-write vulnerabilities** in Windows
drivers. The division of labor:

- **You provide the drivers** - download vendor utility packages and harvest the `.sys` files
  (or start from your own host's drivers).
- **You drive, the AI executes** - you ask an AI agent to run each step of the loop:
  collect -> blocklist-check -> audit -> dynamic-verify -> record.
- **The lab accumulates your verdicts** - one report and one `audits/STATUS.md` row per driver,
  in your own copy of this structure.

The target class lives in [`WANTED_LEDGER.md`](WANTED_LEDGER.md) - edit it to re-target the hunt.
The single question for every driver is:

> Can this driver be made to write kernel memory, from the access I have?

## Scope

| Axis | Values |
|---|---|
| **Reach** | `R1` unprivileged / authenticated user ; `R2` local administrator (**in scope**) ; `R3` devnode / hardware / composition |
| **Setup** | `none` ; `service` ; `devnode` ; `hardware` ; `composition` - a severity field, **not** a disqualifier |
| **Memory write** | arbitrary write, OOB/pool overflow, write-what-where, physical-memory write, MDL mapping, kernel-VA corruption |
| **Out of scope** | input injection, RGB/config control, DoS-only, info-leak-only, hardware-only writes |
| **Corpus payload** | `.sys` only. No installers, `.inf`/`.cat`, app trees, or screenshots in `drivers/`. |

**Hardware-only writes do not count.** MSR, port I/O, PCI config, SMBus/EC, and fixed-window MMIO
are flagged `HW-ONLY` and are `NO-MEMORY-WRITE` unless they chain into a memory write.

## Severity

Use [`audits/scope/SEVERITY.md`](audits/scope/SEVERITY.md):

- **MW1** arbitrary kernel memory write, ready now
- **MW2** constrained/gated kernel memory write
- **MW3** physical-memory mapping/write only
- **MW4** narrow/fixed memory write
- **NO-MEMORY-WRITE** (including `HW-ONLY`)
- **BLOCKED** (known-bad / unsigned-HVCI / component missing)

## Canonical documents

| Document | Role |
|---|---|
| [`AGENTS.md`](AGENTS.md) | Reading order and operating rules for AI agents |
| [`PROJECT_MAP.md`](PROJECT_MAP.md) | Folder/file map |
| [`PROJECT_GOAL.md`](PROJECT_GOAL.md) | This file; single statement of the goal |
| [`audits/README.md`](audits/README.md) | Audits tree layout |
| [`audits/STATUS.md`](audits/STATUS.md) | **Single live status and queue** - yours, starts empty |
| [`audits/scope/AUDIT_SCOPE.md`](audits/scope/AUDIT_SCOPE.md) | Reach tiers, setup field, what counts |
| [`audits/scope/SEVERITY.md`](audits/scope/SEVERITY.md) | MW1-MW4 scale; `HW-ONLY` exclusion |
| [`audits/scope/STATIC_ANALYSIS_AGENT_PROMPT.md`](audits/scope/STATIC_ANALYSIS_AGENT_PROMPT.md) | Default prompt for every summoned audit agent |
| [`DRIVER_COLLECTION_PLAYBOOK.md`](DRIVER_COLLECTION_PLAYBOOK.md) | How to download/harvest more drivers |
| [`downloads/README.md`](downloads/README.md) | Future-download quick-start |

## End state - what your lab looks like after the loop runs

Everything below starts **empty** on this branch and fills up as you run each step:

| Path | What ends up there | Filled by |
|---|---|---|
| `drivers/` | your collected, deduped `.sys` files, flat | collect step |
| `indexes/` | your manifest, dedupe hashes, batch metadata | collect step |
| `audits/evidence/` | blocklist checks, dump triage | blocklist / dynamic steps |
| `audits/reports/` | one canonical report per driver | audit step |
| `audits/STATUS.md` | one verdict row per driver - **the single live queue** | record step |
| `poc/dynamic/` | VM-only PoC logs | dynamic step |

**The single live status/queue source is [`audits/STATUS.md`](audits/STATUS.md).** Do not copy the
queue into other docs.

## Handling

- Static analysis only on the host.
- No driver load, service creation, or registry writes.
- Dynamic work only in the snapshotted VM, never the host.
- No exploit code or PoC in reports; PoCs live in `poc/`.
- **Download hygiene:** extract in `downloads/`; run the mandatory gate
  `tools/filter_new_drivers.ps1 -SourceDir downloads/_harvest -OutDir drivers -Manifest indexes/collections/collected<N>/manifest.csv -UpdateExisting`
  to copy only deduped `.sys` into
  `drivers/` and update the gate; delete the installer, extract tree, and every non-driver payload
  before the batch is accepted. See `DRIVER_COLLECTION_PLAYBOOK.md` section 2.1 and `downloads/README.md`.
