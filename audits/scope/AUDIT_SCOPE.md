# Audit Scope - canonical (2026-10-24)

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

Canonical goal: [`../../PROJECT_GOAL.md`](../../PROJECT_GOAL.md).

**Default agent prompt:** `audits\scope\STATIC_ANALYSIS_AGENT_PROMPT.md` -
memory-write-only, admin-inclusive, with the MW1-MW4 scale.

## Objective

Find kernel **memory-write primitives** in third-party Windows drivers. The requester has local administrator access, so both unprivileged and admin-reachable paths are in scope.

Input-injection and config-control remain out of scope unless they lead to a memory write.

## Reach tiers

| Tier | Meaning | Treatment |
|---|---|---|
| **R1** | Unprivileged / authenticated user | Highest severity; fully audit |
| **R2** | Local administrator | **In scope**; fully audit, record the gate |
| **R3** | Requires devnode / INF / hardware / composition | Audit if assigned; record setup cost |

## Setup field

Every report must state `Setup required: none | service | devnode | hardware | composition`. This is a severity field, not a disqualifier.

- `service` = create/start a kernel service, but no devnode, hardware, or composition.
- `none` = the device exists at driver load with no service/devnode step.
- `devnode` = INF/PnP device creation.
- `hardware` = the physical device/dongle must be present.
- `composition` = a larger software stack or virtual bus must be installed.

**Architecture rule:** a non-loadable build (i386 on x64, ARM64 on x64, IA-64, Alpha AXP,
PowerPC) is `BLOCKED (architecture)` even if a group report records a sibling's static primitive.
Do not count it as MW1-MW4 or NO-MEMORY-WRITE in the aggregate register.

## What counts

- Caller-controlled data reaching a kernel write, copy, or mapping.
- `MmMapIoSpace`, `MmMapLockedPagesSpecifyCache`, `MmCopyMemory`, `ZwMapViewOfSection`, `MmGetPhysicalAddress`, `KeStackAttachProcess`.
- Hardware writes (MSR `wrmsr`, port I/O `IN`/`OUT`, PCI config, SMBus/EC, fixed-window MMIO) **only when they can be chained into a kernel memory write**. Otherwise they are flagged `HW-ONLY` and do not count.
- Missing `ProbeForWrite`, output-length checks, or METHOD_NEITHER pointer validation.
- Permissive DACL or a deterministic auth handshake that any opener can satisfy.

## What does not count

- Mere IOCTL presence without a memory-write path.
- Input injection or RGB/config control alone.
- Admin access alone; the report must identify the primitive and the exact gate.

## Severity

Use `audits\scope\SEVERITY.md`. The scale is memory-write-only:

- **MW1** arbitrary kernel memory write, ready now
- **MW2** constrained/gated kernel memory write
- **MW3** physical-memory mapping/write only
- **MW4** narrow/fixed memory write
- **NO-MEMORY-WRITE** (including `HW-ONLY`)
- **BLOCKED** (known-bad/unsigned/blocklisted)

## Report requirements

- File, SHA-256, analysis date, static-only method.
- Entry -> device/interface -> effective DACL -> dispatch -> IOCTL table -> access checks -> primitive -> verdict.
- `Reach: unprivileged | authenticated user | local administrator | devnode/hardware`.
- `Setup required: none | service | devnode | hardware | composition`.
- `Write quality: W1 | W2 | W3 | W3P | W0` (`W3P` = physical-memory/PA-only).
- `Severity: MW1 | MW2 | MW3 | MW4 | NO-MEMORY-WRITE | BLOCKED`.
- Limitations and unresolved paths.
