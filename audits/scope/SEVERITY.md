# Kernel Memory-Write Severity — exploitability-first (2026-10-24)

> [!CAUTION]
> **AI-written.** This document was written by an AI agent and may contain mistakes. Verify
> commands, paths, versions, and hashes against your own environment before relying on them.

**Only kernel memory writes count.** Hardware-only writes — MSR, port I/O, PCI config,
SMBus/EC, fixed-window MMIO — are **not** memory writes and are flagged `HW-ONLY`. They matter
only if they can be chained into a memory write.

The question is:

> How close is this to an actual kernel memory write that **I** can perform on this machine?

## Inputs

| Input | Values |
|---|---|
| **Reach** | `R1` unprivileged / authenticated user · `R2` local administrator · `R3` devnode / hardware / composition |
| **Setup** | `none` · `service` · `devnode` · `hardware` · `composition` |
| **Write quality** | `W1` arbitrary target + value · `W2` constrained target/value · `W3` fixed/narrow · `W3P` physical-memory (PA-only) mapping/write · `W0` no memory write |
| **Loadability** | signed/HVCI-ok · unsigned/test-signing · blocklisted |
| **Modifiers** | KASLR read/leak · crash reliability · device present |

## Levels

| Level | Meaning | Required conditions | Example |
|---|---|---|---|
| **MW1 — CRITICAL** | Arbitrary or fully controlled **kernel memory write**, usable now with your access. | `R1`/`R2` + `W1` + `Setup: none` + loadable. | Admin-open write-what-where; unprivileged arbitrary pool write. |
| **MW2 — HIGH** | Real kernel memory write, but constrained: fixed/limited target/value, needs a leak, or needs a devnode/composition/hardware you can stage. | `R1`/`R2` + `W2`; or `R3` + `W1`. | constrained OOB write; composition-gated write; dongle/hardware-gated write. |
| **MW3 — MEDIUM** | Physical-memory mapping/write only (PA-based, not arbitrary kernel VA), or a memory write that needs specific hardware you may not have. | `W3P`; or `W2` + `R3` hardware. | physical-address map/clear; user-mapped physical memory; fixed physmem window. |
| **MW4 — LOW** | Narrow/fixed memory write, unreliable, or requires an unavailable device; mainly DoS/leak. | `W3`; crash-first; no target control. | fixed 6-byte OOB; fixed-value fill; write reachable only via crash. |
| **NO-MEMORY-WRITE** | No kernel memory write. Hardware-only writes, info leak, DoS, config control, or no device. | `W0` or `HW-ONLY`. | hardware-access interface only (WRMSR/SMBus/EC/MMIO); no write sink. |
| **BLOCKED** | A memory write may exist, but the driver is known-bad/blocklisted, unsigned under HVCI, or the component is unobtainable. | Status flag. | blocklisted driver; unsigned under HVCI; component unobtainable. |

`service` means "create/start a kernel service, but no devnode, hardware, or composition". Rate it
like `none` unless the service itself is the only gate and the driver cannot be loaded by the
target user.

## Matrix

| Reach / Setup | W1 arbitrary | W2 constrained | W3 fixed | W3P PA-only | W0 none |
|---|---|---|---|---|---|
| R1 unprivileged, none | **MW1** | **MW2** | MW4 | MW3 | NO-MEMORY-WRITE |
| R2 admin, none | **MW1** | **MW2** | MW4 | MW3 | NO-MEMORY-WRITE |
| R3 devnode/composition | **MW2** | **MW3** | MW4 | MW3 | NO-MEMORY-WRITE |
| R3 hardware/dongle | **MW2** | **MW3** | MW4 | MW3 | NO-MEMORY-WRITE |
| HW-only (MSR/port/PCI/SMBus/EC/MMIO) | — | — | — | — | **NO-MEMORY-WRITE (HW-ONLY)** |

Modifiers:

- A kernel **read / KASLR leak** raises one level when the write needs an address.
- A primitive that reliably **bugchecks before the write** is capped at MW4.
- A device **not present** caps at MW3.
- Unsigned / HVCI-blocked is `BLOCKED`, but the static primitive can still be MW1/MW2.

## `HW-ONLY` flag

Use for drivers whose only write capability is:

- `WRMSR` / `RDMSR`
- port I/O (`IN`/`OUT`)
- PCI config space
- SMBus / EC
- fixed-window device MMIO

`HW-ONLY` is **not** a memory-write level. It only matters if it enables a memory write:
disabling SMEP/SMAP via MSR, programming a DMA engine, remapping a BAR, etc.

## Architecture rule

A build that cannot load on the target architecture is **`BLOCKED (architecture)`**, regardless of
what a group/family report says about a sibling build. The static primitive may still be recorded
for reference, but the non-loadable build is not counted as MW1–MW4 or NO-MEMORY-WRITE in the
aggregate register. This applies to i386 on x64, ARM64 on x64, IA-64, Alpha AXP, and PowerPC.

## Report fields

`MW<n> — reach=<R1|R2|R3> setup=<none|service|devnode|hardware|composition> write=<W1|W2|W3|W3P|W0> load=<signed|unsigned|blocked>`

Examples:

- `MW1 — reach=R2 setup=none write=W1 load=signed` = admin-open arbitrary kernel write.
- `MW2 — reach=R3 setup=hardware write=W1 load=signed` = arbitrary write but needs a dongle.
- `MW3 — reach=R2 setup=none write=W3P load=signed` = physical-memory mapping/write.
- `NO-MEMORY-WRITE (HW-ONLY) — reach=R1` = open hardware-access interface, no kernel memory write.
