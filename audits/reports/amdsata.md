# Audit: amdsata.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\amdsata.sys` |
| Recorded SHA-256 | `D5231F97E5432234A8A19904E59C324E825AF04881AA195C19CCC9E6A7684B14` (verified vs triage_index.csv + local Get-FileHash) |
| Company/Version | Advanced Micro Devices — 1.1.3.277 (NT.150223-1854) "AHCI 1.3 Device Driver" (in-box; signed CN=Microsoft Windows) |
| Method | Static-only via LOCAL Ghidra 12.1.4 headless (javac-compiled GhidraScript). REA bridge contended (mis-serves + nvlddmkm timeouts) → per-protocol fallback; full import/string/priv sweep, 115 functions, entry + 3 largest functions decompiled |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs (image base `0x1c0000000`).

## Entry surface

Pure StorPort AHCI miniport, 115 functions. Import-name blob (`0x1c00191e2`–`0x1c001943a`) contains **only StorPort* DDIs + RtlGetVersion** (+ legacy `ScsiPortNotification` thunk string). **No `IoCreateDevice`, no device/DOS names, no SDDL, no interface GUIDs, no WDF.** `AmdSataWMI` keyword indicates the StorPort-managed WMI plane (owned/gated by storport.sys). **No user-openable surface of its own → short-form.**

## Memory-write analysis

- `entry` (`0x1c001a000`): builds `HW_INITIALIZATION_DATA` (0xd0) with callback table (`FindAdapter=FUN_1c0008ba0`, `HwInitialize/PrepareHw=FUN_1c000caa0`, `StartIo=FUN_1c000b840`, …) → `StorPortInitialize`. No device creation anywhere on the chain.
- Config plane: `FindAdapter` reads ~45 `AmdSata*` keywords via `StorPortRegistryRead` with **fixed sizes (4/3 bytes)** into `StorPortAllocateRegistryBuffer`-managed buffers; `StorPortRegistryWrite` used for the driver's own counter (`AmdSataCounter`). All HKLM admin config.
- Extension init: `memset` of fixed `0x1af0`-stride per-port structures, loop bounded by the port count byte at `+0x1c`; per-port stride `0x371`/`0x1b88`. All writes land in the driver's own kernel extension — no caller-influenced destination or length.
- **Absent primitives:** zero `Mm*`/`Zw*`/`Se*`/`Io*` imports; no `ZwOpenSection`/`\Device\PhysicalMemory`/`MmCopyMemory`; no METHOD_NEITHER dispatch (SRB plane only, admin-gated through storport.sys); instruction sweep = no privileged instructions (`priv_ins.txt` = "none").

## Memory-touching IOCTL table

None in-binary — SRB/pass-through surfaces are owned by storport.sys/classpnp (admin-gated device opening), buffers probed/locked by the storage stack.

## Verdict + VM confirmation plan

**NO-WRITE.** StorPort-DDI-only miniport with no control device, no privileged imports, and only fixed-stride/registry-bounded writes into its own extension. No unprivileged kernel memory-write primitive.

VM plan (describe only; not warranted): load, verify no control device exists (`!object \Device` enum for AMD names), `!poolused` for its tags — no corruption test indicated.

*End of report.*
