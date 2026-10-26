# Audit: CMTAC_F6772F57.sys

| Field | Value |
|---|---|
| File | drivers\CMTAC_F6772F57.sys |
| SHA-256 | F6772F57C69F02775DAF4E13376DA3026F9A88C0ADFC9BF9F8F0442CB069212B |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\CMTAC_F6772F57.txt): IoAllocateMdl + MmBuildMdlForNonPagedPool + MmMapLockedPagesSpecifyCache at dump 206693-206711 with AccessMode argument 1 (UserMode): a nonpaged driver buffer is mapped into the caller address space |
| Company / version | Cooler Master Technology; file version 10.0.0019.11832; "Cooler Master Technology MH670 Driver" |
| Signature | Authenticode Valid; signer CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1557388322 |
| Reach | n/a (architecture). Device model: Cooler Master MH670 audio driver (PortCls + MDL). IoRegisterDeviceInterface, PcNewPort. No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, portcls.sys, HAL.dll, USBD.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePool, ExAllocatePoolWithTag, ExFreePool, IoAllocateMdl, IoFreeMdl, MmBuildMdlForNonPagedPool, MmMapLockedPagesSpecifyCache, PcRegisterPhysicalConnection, RtlCompareMemory, ZwCreateFile, memcpy, memmove, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Static primitive (checklist: MDL mapped into user mode): the MDL over a driver nonpaged buffer is mapped with AccessMode UserMode (dump 206711, arguments pushed at 206699-206710). The buffer VA, length and protection were not resolved in this pass, so whether user writes reach kernel control data is not determined. Architecture BLOCKED; write quality not assessed.

## 2 Verdict

**BLOCKED (architecture).** CMTAC_F6772F57.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see §1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
