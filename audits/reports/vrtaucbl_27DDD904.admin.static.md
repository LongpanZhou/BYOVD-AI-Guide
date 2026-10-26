# Audit: vrtaucbl_27DDD904.sys

| Field | Value |
|---|---|
| File | drivers\vrtaucbl_27DDD904.sys |
| SHA-256 | 27DDD9041AECFD3EB39EB5895D3980A8EF594289DF486D029B4E653F1CADBA86 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\vrtaucbl_27DDD904.txt, 22,851 lines, arch x86; a different build from vrtaucbl_0A3D3BAB, 45,362 diff lines): copy-out helper at dump 8812-8833 (memcpy of param_3 bytes into struct+0x3c direct buffer, or struct+0xC MDL-mapped buffer); ProbeForWrite at 8828 only when the flag at struct+0x20 is set and the direct path is taken; MmMapLockedPagesSpecifyCache (KernelMode) at 15111 |
| Company / version | Eugene (Evgenii) Muzychenko; file version 4.71.0.14195; "Virtual Audio Cable - kernel-mode WDM/KS driver" |
| Signature | Authenticode Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1781974248 |
| Reach | n/a (architecture). Device model: Virtual audio cable (vrtaucbl, x86 build). IoCreateDevice, IoAttachDeviceToDeviceStack, IoAllocateIrp, ProbeForWrite (imported). No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: HAL.dll, ntoskrnl.exe, ks.sys, portcls.sys.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePool, ExFreePool, ExFreePoolWithTag, KsProbeStreamIrp, MmAllocatePagesForMdl, MmCreateSection, MmFreePagesFromMdl, MmGetPhysicalAddress, MmMapLockedPagesSpecifyCache, MmMapViewInSystemSpace, MmMapViewOfSection, MmUnmapViewOfSection, PcRegisterPhysicalConnection, ProbeForRead, ProbeForWrite, RtlFillMemory, RtlMoveMemory, RtlZeroMemory, ZwCreateKey, memcpy, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Candidate primitive (x86 build; not graded, architecture BLOCKED): the copy-out helper (dump 8825-8829) writes param_3 bytes to the destination in struct+0x3c. Without the flag at struct+0x20 (or on the MDL path) there is no ProbeForWrite, so the destination is whatever address the struct holds. The function has an SEH frame (__except_handler4), which stops faults on bad user pointers but not writes to a valid kernel address. Where the flag and the destination are set was not traced. Verify before sign-off.

## 2 Verdict

**BLOCKED (architecture).** vrtaucbl_27DDD904.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see §1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
