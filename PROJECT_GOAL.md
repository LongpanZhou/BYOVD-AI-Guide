# Project Goal — Kernel Memory-Write Vulnerabilities

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

## Goal

Find and verify **kernel memory-write vulnerabilities** in Windows drivers collected from this host
and from vendor utility packages. The target class lives in the
[`WANTED_LEDGER.md`](WANTED_LEDGER.md) — edit it to re-target the hunt.

The single question for every driver is:

> Can this driver be made to write kernel memory, from the access I have?

## Scope

| Axis | Values |
|---|---|
| **Reach** | `R1` unprivileged / authenticated user · `R2` local administrator (**in scope**) · `R3` devnode / hardware / composition |
| **Setup** | `none` · `service` · `devnode` · `hardware` · `composition` — a severity field, **not** a disqualifier |
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
| [`START_HERE.md`](START_HERE.md) | Reading order for humans and AI agents |
| [`PROJECT_MAP.md`](PROJECT_MAP.md) | Folder/file map |
| [`PROJECT_GOAL.md`](PROJECT_GOAL.md) | This file; single statement of the goal |
| [`audits/README.md`](audits/README.md) | Audits tree and historical-report warning |
| [`audits/STATUS.md`](audits/STATUS.md) | **Single live status and queue** |
| [`audits/scope/AUDIT_SCOPE.md`](audits/scope/AUDIT_SCOPE.md) | Reach tiers, setup field, what counts |
| [`audits/scope/SEVERITY.md`](audits/scope/SEVERITY.md) | MW1–MW4 scale; `HW-ONLY` exclusion |
| [`audits/scope/STATIC_ANALYSIS_AGENT_PROMPT.md`](audits/scope/STATIC_ANALYSIS_AGENT_PROMPT.md) | Default prompt for every summoned audit agent |
| [`DRIVER_COLLECTION_PLAYBOOK.md`](DRIVER_COLLECTION_PLAYBOOK.md) | How to download/harvest more drivers |
| [`downloads/README.md`](downloads/README.md) | Future-download quick-start |

## Current corpus

All drivers are flat in [`drivers/`](drivers/); batch provenance is in
[`indexes/drivers_manifest.csv`](indexes/drivers_manifest.csv) and `indexes/collections/`.

| Batch | Binaries |
|---|---:|
| Original host corpus | 94 |
| `collected2` | 135 |
| `collected3` | 11 |
| `collected5` (R1–R4) | 41 |
| `collected1` (S1–S6) | 106 |
| **Total in repo** | **386** |

Batch counts sum to 387: the original 94 includes `vgk.sys`, which is local-only and not in
`drivers/`.

Dedupe index: **925 tracked hashes** in `indexes/dedupe/existing_hashes.txt` + **7 exported
hashes** in a gitignored local gate file (932 total).
Known-bad: 5,833 hashes (`indexes/dedupe/known_bad_hashes.txt`).

## Current audit state

**The single live status/queue source is [`audits/STATUS.md`](audits/STATUS.md).**
Do not copy the queue into other docs.

Top current results:

| Driver | Verdict | Note |
|---|---|---|
| CPU-Z `cpuz_x64` (both builds) | **MW1** | R2, signed; physical data copied to a caller-chosen kernel address |
| AIDA64 `kerneld-x64` | **MW2** | R2, signed; arbitrary physical write + kernel pointer leak |
| HP `rtf64x64` | **MW2** | R1/R3, signed; LWF composition required |
| `silabser` | **MW2** | R1, hardware-gated; CP210x pool OOB |
| `bxvbda` | **MW2** | R3, hardware-gated; W1 caller-VA + W2 BAR OOB |
| Sandboxie `SbieDrv` | **MW2** | R2 trusted-caller gate; heap/stack overflow paths |
| DirectIo64 | **MW3** | R2, signed; physical-memory mapping + one-bit physical clear |
| GPU-Z `nvflash_x64` | **MW3** | R3 hardware, signed; constrained OOB BAR write |
| ImDisk `imdisk.sys` | **MW4** | fixed-value kernel write, crash-first |
| Spacedesk Bus | **MW3** | composition-gated MDL mapping |
| CorsairGamingAudio64 | **MW3** | hardware-gated pool overflow |
| ThrottleStop `LowLevel_x64` / x86 | **BLOCKED** (static MW3/W3P) | unsigned; physical R/W mapped into user mode; no kernel leak |
| SIVI64 | **BLOCKED** | IA-64 image, not loadable on x64 |
| RTCore32 | **BLOCKED** | known-bad/blocklisted; static MW2 reference only |
| ArgusMonitor | **NO-MEMORY-WRITE (HW-ONLY)** | open interface, but MSR/SMBus/EC/MMIO only |
| Spacedesk Audio | **NO-MEMORY-WRITE** | open devnode, no write sink |
| CorsairVBusDriver64 | **NO-MEMORY-WRITE** (admin-gated UAF residual) | no established write primitive |

## Handling

- Static analysis only on the host.
- No driver load, service creation, or registry writes.
- Dynamic work only in the snapshotted VM, never the host.
- No exploit code or PoC in reports; PoCs live in `poc/`.
- **Download hygiene:** extract in `downloads/`; run
  `tools/filter_new_drivers.ps1 -OutDir drivers -UpdateExisting` to copy only deduped `.sys` into
  `drivers/` and update the gate; delete the installer, extract tree, and every non-driver payload
  before the batch is accepted. See `DRIVER_COLLECTION_PLAYBOOK.md` §2.1 and `downloads/README.md`.

Historical per-driver reports may still use the old `WRITE-*` vocabulary and unprivileged-only
wording. The canonical documents above govern new work; `SEVERITY.md` maps old verdicts to MW.
