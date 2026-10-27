# Audit: idisplay,1_FA82D229.sys

| Field | Value |
|---|---|
| File | drivers\idisplay,1_FA82D229.sys |
| SHA-256 | FA82D229E8AB478198C1415B3E77F0A303EC27B9076652F1531DE44094014BBB |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\idisplay_1_FA82D229.txt, 3,071 lines; the comma-named stem was relaunched as idisplay_1_FA82D229): named section created at dump 576-577 (\BaseNamedObjects\iDisplayController, size 0xC0090) in FUN_0040175c (dump 378-449): RtlSetDaclSecurityDescriptor with a NULL DACL at 402 (create path) and at 444 on the object returned by ObGetObjectSecurity (both paths); ZwMapViewOfSection to the current process RW at 452 |
| Company / version | None; file version None; "None" |
| Signature | Authenticode Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher, OU=MOPR, O=Microsoft Corporation, L=Redmond, S=Washington, C=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1498820093 |
| Reach | n/a (architecture). Device model: Intel-style iDisplay controller (display filter) driver. Imports: MmProbeAndLockPages, MmMapLockedPagesSpecifyCache, IoAllocateMdl, ZwCreateSection, ZwOpenSection, ZwMapViewOfSection, ObGetObjectSecurity, RtlSetDaclSecurityDescriptor, MmGetPhysicalAddress, MmGetSystemRoutineAddress. Device opened by \Device\DxgKrnl (dump 2308). No SDDL string; the DACL is set in code. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePoolWithTag, IoAllocateMdl, IoFreeMdl, MmAllocateContiguousMemorySpecifyCacheNode, MmFreeContiguousMemory, MmGetPhysicalAddress, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages, MmUserProbeAddress, RtlCompareMemory, RtlCreateSecurityDescriptor, RtlSetDaclSecurityDescriptor, ZwCreateSection, ZwLoadDriver, ZwMapViewOfSection, ZwOpenSection, ZwUnmapViewOfSection, memcpy, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Static primitive (shared memory, arch x86): the section named \BaseNamedObjects\iDisplayController is created (or opened) and its security descriptor is given a NULL DACL (dump 402, 444-446), then mapped read/write into the calling process (dump 452, PAGE_READWRITE). The kernel reads the mapped records (magic 0xFEEDDEAD check at dump 587-589; fields copied at dump 591-592). Anything an unprivileged user can write there is trusted by the driver. Whether the same object is writable by a kernel path and the exact read-back use were not traced in full. Architecture BLOCKED; not graded for write quality.

## 2 Verdict

**BLOCKED (architecture).** idisplay,1_FA82D229.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
