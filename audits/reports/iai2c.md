# Audit: iai2c.sys

| Field | Value |
|---|---|
| File | `C:\Users\<scrubbed>\Desktop\driver_candidates\iai2c.sys` |
| Recorded SHA-256 | `9296A14590DFD94A3C728CAF3CA91BA211F27974F9CFF8417CDDC00D1453315C` (verified against triage_index.csv; recon.py hash re-verified) |
| Company/Version | Intel(R) Corporation 1.1.1.0 (Intel(R) Serial IO I2C Driver; older sibling of Agent D's cleared iaLPSSi_I2C.sys 1.1.253.0) |
| Method | Static-only audit via LOCAL Ghidra 12.1.4 headless + host PE/string/byte recon (4 `.text` byte hits resolved); REA shared bridge contended (Agent D-validated fallback). No device opened, no IOCTL executed. |
| Verdict | **NO-WRITE** |

> Static-only. No driver was loaded, no device was opened, no IOCTL was executed. Addresses are linked VAs at image base `0x140000000`. KPROCESSOR_MODE enum applied correctly (KernelMode=0, UserMode=1).

## Entry surface

KMDF **SpbCx client** driver (`SPBCx`/`KmdfLibrary` bind strings; ACPI HWIDs `ACPI\VEN_8086&DEV_0F41&REV_0002` / `ACPI\VEN_8086&DEV_22C1`). **No SDDL string, no device/interface naming of its own** -> the Spb controller FDO (created via the SpbCx/KMDF path) carries the default device SD (System + Administrators) -> unprivileged open denied. All user-reachable control flows through SpbCx's validated SpbCtl interface. `\Device\MBI` (UTF-16 string) is a **target** the driver references internally via `IoGetDeviceObjectPointer` (`FUN_1400127a0`/`FUN_1400127fc`, FILE_ALL_ACCESS=0x1f01ff) for its Mailbox-Interface peer - kernel-internal peer stack, not an exported surface. Registry config keys (`iai2c`: `ForceDma`, `BufferSize`, `BUS_*` timing) are config-control - out of scope.

## Memory-write analysis

- **`MmMapIoSpaceEx`** - two sites (prepare-hardware/power, decomp lines 3390/8626): source = PnP **translated** `CmResourceTypeMemory` descriptors (`start@+4`, `len@+0xc` via WDF runtime table), protection `0x204`; `MmUnmapIoSpace` teardown. Not attacker-influenced; BAR registers only (HAL `KeStallExecutionProcessor` polling).
- **MDL kit (Spb transfer access)** - sites at decomp lines 2160/2241/2280/2314/2361/7947/8016/10515/10584: walks the **SpbCx transfer MDL chain** (`transfer+0x30` list, `transfer+0x28` length), per-MDL `MdlFlags&0x5` pre-check reuses `MDL->MappedSystemVa`, else `MmMapLockedPagesSpecifyCache(MDL, **KernelMode**, MmCached, 0, FALSE, NormalPagePriority|MdlMappingNoWrite)` - the documented SpbCx client pattern over transfer buffers already **locked/probed by the I/O manager** when the request arrived. Byte-level access is offset-walked within each MDL's `ByteCount` (`offset < MDL->ByteCount`); the re-MDL sites (`IoAllocateMdl(systemVA, MDL->ByteCount)` + `MmBuildMdlForNonPagedPool`, lines 2178/2333/2380/2474) build DMA descriptors over the caller's own pinned pages. **No `MmProbeAndLockPages` import - this driver never probes/mapps attacker MDLs itself**; no KernelMode map of attacker-chosen kernel addresses (the `MdlFlags&0x5` shortcut only reuses already-mapped state).
- **`MmAllocateContiguousMemorySpecifyCache(0xffa, ...)`** (decomp line 5783): fixed-size DMA bounce buffer, driver-owned, freed via `MmFreeContiguousMemory`.
- All `memset` sites: fixed sizes (`0x200`, `0x310`, `0xd8`, `0x90`, `0x68`, `0x50`, `0x48`, `0x38`, `0x28`, `0x24`, `0x20`) on driver-owned buffers, or **exact-fit on framework-returned sizes** (alloc-and-query pattern at `FUN_1400101cf`-family: size queried by the framework -> `ExAllocatePoolWithTag(NonPaged, size, 'iLPS')` -> memset(same size) -> re-query) - no length-carrying overflow.
- `IoBuildSynchronousFsdRequest(0x1b=IRP_MJ_PNP, MBI device, ...)` (decomp line 10760): internal mailbox request with kernel-allocated buffers and hand-written stack-location fields - kernel-internal, no user path.
- Privileged instructions: `.text` hits resolved at byte level - `0x9f57`/`0xa08c` = `MOV R9,CR8`/`MOV R10,CR8` (TPR reads, benign); `0x2605`/`0x281d` = displacements of RIP-relative `CALL [rip+...]`/`LEA` instructions (mid-instruction false positives); `.rdata`/`.rsrc` hits are data. **No** `wrmsr`/`rdmsr`/`lgdt`/`sgdt`/CR-writes in code.
- No `ZwOpenSection`, `\Device\PhysicalMemory`, `MmCopyMemory`, `ProbeFor*`, METHOD_NEITHER plane attributable to this file (Spb owns the queue).

## Memory-touching IOCTL table

none (client registers no own dispatch; SpbCx owns the queue; device SD = default, admin-gated).

## Verdict + VM confirmation plan

**NO-WRITE.** Older sibling of the iaLPSSi_I2C codebase Agent D cleared: SpbCx client, default (admin-gated) device SD, Spb-transfer system-VA mapping over I/O-manager-locked MDLs only, PnP BARs only, fixed/exact-fit fills, benign CR8 reads. No kernel-memory-write primitive in-file; worst-case-DACL convention adds nothing because the transfer-buffer path is validated upstream by SpbCx regardless of who opened.

VM plan (orchestrator-owned, describe-only): none warranted. If ever dynamic: unpriv open attempt on the SpbCtl interface -> expect denial; confirm the MBI reference is only the SerialIO mailbox stack.

*End of report.*
