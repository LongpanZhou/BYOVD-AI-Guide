# Audit: idisplay,2_287771E7.sys

| Field | Value |
|---|---|
| File | drivers\idisplay,2_287771E7.sys |
| SHA-256 | 287771E78834AF54A5DF10D071AE0B49E1E7641B98BBF9A0BD510E3D88256451 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\idisplay_2_287771E7.txt, 3,071 lines, identical to idisplay,1 except the program name, 4 diff lines): the same named-section code: NULL DACL at dump 402 and 444-446; ZwCreateSection/ZwOpenSection at 409/411; ZwMapViewOfSection RW at 452; \BaseNamedObjects\iDisplayController at 576 |
| Company / version | None; file version None; "None" |
| Signature | Authenticode Valid; signer CN=SHAPE GmbH, O=SHAPE GmbH, L=Stuttgart, S=Baden-Wurttemberg, C=DE, PostalCode=70174, STREET=Fritz-Elsas-Str. 50, SERIALNUMBER=HRB 20147, OID.1.3.6.1.4.1.311.60.2.1.2=Baden-Wurttemberg, OID.1.3.6.1.4.1.311.60.2.1.3=DE, OID.2.5.4.15=Private Organization |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1498820093 |
| Reach | n/a (architecture). Device model: Intel-style iDisplay controller (display filter, second build). Imports as in the sibling build: MmProbeAndLockPages, MmMapLockedPagesSpecifyCache, IoAllocateMdl, ZwCreateSection, ZwOpenSection, ZwMapViewOfSection, ObGetObjectSecurity, RtlSetDaclSecurityDescriptor, MmGetPhysicalAddress. Device reference \Device\DxgKrnl (dump 2308). No SDDL string; the DACL is set in code. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePoolWithTag, IoAllocateMdl, IoFreeMdl, MmAllocateContiguousMemorySpecifyCacheNode, MmFreeContiguousMemory, MmGetPhysicalAddress, MmMapLockedPagesSpecifyCache, MmProbeAndLockPages, MmUserProbeAddress, RtlCompareMemory, RtlCreateSecurityDescriptor, RtlSetDaclSecurityDescriptor, ZwCreateSection, ZwLoadDriver, ZwMapViewOfSection, ZwOpenSection, ZwUnmapViewOfSection, memcpy, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Static primitive (shared memory, arch x86), as in the sibling idisplay,1 build: the named section \BaseNamedObjects\iDisplayController is created or opened and given a NULL DACL (dump 402, 444-446), then mapped read/write into the calling process (dump 452). The kernel parses records from the mapped view (magic 0xFEEDDEAD check at dump 587-589, fields copied at 591-592). Any unprivileged user who can write there influences driver control data. Not traced in full: which fields reach a kernel write. Architecture BLOCKED; not graded for write quality.

## 2 Verdict

**BLOCKED (architecture).** idisplay,2_287771E7.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
