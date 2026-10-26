# Audit: megasas.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\megasas.sys` |
| Recorded SHA-256 | `9041FDEB932F2CBBCE4A017256C81B3733604403AA343D4532910436E8288CA9` (verified vs triage_index.csv) |
| Company/Version | Avago Technologies — MEGASAS RAID Controller Driver for Windows, 6.706.06.00 (NT.150223-1854); internal name/source ref `megasas2.sys`, PDB `megasas.pdb` |
| Method | Static-only audit via LOCAL Ghidra 12.1.4 headless (`C:\tools\ghidra_12.1.4_PUBLIC`, project `agentH\ghidraProj\projH`, `DumpDecomp.java`); strings + imports recon first; per changed engine policy REA bridge NOT used |
| Verdict | **NO-WRITE** |
| Analysis date | 2026-10-24 |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed, no REA bridge session was opened. All addresses are Ghidra-linked VAs at image base `0x1c0000000`. All tool/binary output treated as data; no instructions found embedded in target content.

## Entry surface

- **StorPort/ScsiPort dual-mode legacy miniport** (in-box LSI MegaRAID SAS driver). `entry` @ `0x1c000f000` (INIT) builds a 0xd0-byte `HW_INITIALIZATION_DATA` (0x9a60 dev-ext, 0x700 LU-ext) and calls `StorPortInitialize`. Callbacks: `FUN_1c0002060` (HwInitialize), `FUN_1c0003ce0` (HwBuildIo), `FUN_1c0007bb0` (HwStartIo), `FUN_1c0001000` (HwInterrupt), `FUN_1c0008e50` (HwFindAdapter region), plus reset/timers.
- **Complete external surface (Ghidra externals, all imports):** 19 entries = `StorPort{Initialize, GetUncachedExtension, StallExecution, ExtendedFunction, GetScatterGatherList, Busy, GetPhysicalAddress, SynchronizeAccess, Resume, Ready, SetDeviceQueueDepth, SetBusDataByOffset, LogError, GetDeviceBase, GetBusData, Notification, Pause, QuerySystemTime}` + `ScsiPortNotification` + `strstr` + `RtlIsNtDdiVersionAvailable` + `__C_specific_handler`. **Zero `Mm*`/`Zw*`/`IoCreateDevice*`/`WdfDeviceCreate`/`ProbeFor*`/`Se*` imports.**
- **No device of its own:** no `IoCreateDevice`/`IoCreateDeviceSecure`/`IoCreateSymbolicLink`/`WdfDeviceCreate` in the 133-procedure inventory; the full string inventory (357 strings) contains **no `\Device\` or `\DosDevices\` name and no SDDL string**. Storport miniports publish no control device — the only user-reachable command plane is the storage stack's adapter/RaidPort PDO (default DACL = admin-gated) and the WMI plane (`MofResource`/`ScsiMiniPort`/`MOFDATA` resources, also storage-stack gated).
- Registry config params (`balancecount`, `msiqueues`, `maxiosize`, …) are driver-key values, not kernel-write primitives.

## Memory-write analysis

- **No mapping/probe primitives:** zero `MmMapIoSpace`/`MmProbeAndLockPages`/`MmMapLockedPagesSpecifyCache`/`MmCopyMemory`/`ZwOpenSection`/`\Device\PhysicalMemory` references anywhere in imports, strings, or decompile. Nothing maps caller memory into system VA; nothing maps physical addresses from caller input.
- **SRB_IOCTL plane exists but is not a kernel-write primitive:** `FUN_1c0004264` (BuildIo gate) validates legacy SRB (Function byte @ SRB+2): rejects invalid target/path/LUN combos (`SrbStatus 0x20`), rejects `0x20`/`0x12/0x13` functions, and **accepts `SRB_FUNCTION_IO_CONTROL` (0x02)** (no pending-DCMD check beyond `DE+0x2168`). IO_CONTROL SRBs flow through the same request pipeline (`FUN_1c0003ce0` → StartIo/DCMD path) as normal firmware commands — the SRB_IO_CONTROL payload is DMA'd to the RAID firmware via `StorPortGetPhysicalAddress`/`DataBuffer` physical addresses. No `memcpy`/`memset` call site with a caller-controlled length writing into a fixed kernel buffer was found: the only library-copy call sites (`FUN_1c000a6c0` memcpy kit) are the fixed `0x1a`-length `ScsiMiniPort`/MofResource name copies in the WMI registration helper (decomp lines 7487–7489).
- **MSR/GDT/IDT checklist: all byte-scan hits are false positives (byte-context verified).** `0F 30` (wrmsr) hits at file 0xC823/0xC852/0xD681 fall entirely inside the Authenticode certificate blob (cert table 0xC800–0xE938); `0F 32` (rdmsr)/`0F 08` (invd) hits at 0xA2F1–0xA829 fall in `.rdata` (jump-table/constant data). `lgdt/lidt/lmsw/wbinvd-in-.text`: none. SGDT-scan hits elsewhere in the family are `0F 01 00` inside RIP-relative displacements (e.g. `mov eax,[rip+0x10FF8]`) — read-only or non-instructions. No reachable privileged instruction exists.
- **No METHOD_NEITHER-style direct user-buffer access** is possible: the driver has no IRP dispatch of its own; all buffer access is storport-marshalled SRB data.

## Memory-touching IOCTL table

Driver owns no device object and no IOCTL dispatch: no IOCTL codes of its own. SRB plane (storport-mediated, storage-stack gated — admin by default DACL):

| SRB function | Path | Kernel write | Check |
|---|---|---|---|
| SRB_FUNCTION_IO_CONTROL (0x02) | `FUN_1c0004264` gate → DCMD/DMA pipeline | payload DMA'd to firmware, not kernel struct | no caller-length kernel copy found |
| SRB_FUNCTION_WMI / MofResource plane | storage-stack mediated | fixed 0x1a name copies only | fixed-length |

## Verdict + VM confirmation plan

**NO-WRITE.** megasas.sys is a pure storport/scsiport dual-mode miniport: zero Mm*/Zw*/device-creation imports, no `\Device\`/SDDL strings, no user-openable control device, no MDL/probe/physical-mapping primitives, and no unchecked copy/fill of caller data into kernel memory on the only command plane (SRB_IOCTL → firmware DMA). No privileged-instruction primitives (wrmsr/GDT/IDT) exist in real code. Unprivileged users cannot reach any driver handler; there is no memory-write primitive to confirm.

Coverage: ~85% — complete import/externals enumeration, complete string inventory, line-level review of `entry`, HwBuildIo (`FUN_1c0003ce0`, `FUN_1c0004264`), HwStartIo (`FUN_1c0007bb0` + helpers), and all library-copy call sites; all 133 functions decompiled (dump retained), remaining handler bodies reviewed structurally (zero suspicious DDIs to reach them with).

VM plan (orchestrator-owned, non-destructive): if ever loaded, confirm `!object` on the adapter device shows the default (admin) DACL and that a restricted-token open of the storage PDO fails; no IOCTL probing is warranted by the static evidence. No dynamic test needed for this verdict.

*End of report.*
