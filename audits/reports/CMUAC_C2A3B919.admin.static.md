# Audit: CMUAC_C2A3B919.sys

| Field | Value |
|---|---|
| File | drivers\CMUAC_C2A3B919.sys |
| SHA-256 | C2A3B9197AB734D7D42AC8B2003973C63E52849F914E93F50ED87B2FDFD3F79C |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: run (Ghidra 12.1.4, dump out_c1\CMUAC_C2A3B919.txt): IoAllocateMdl + MmBuildMdlForNonPagedPool + MmMapLockedPagesSpecifyCache at dump 65824-65840 with AccessMode 1 (UserMode); PcNewPort at 56803/57083/62340 |
| Company / version | C-MEDIA; file version 7.0.0015.8345; "C-MEDIA USB Audio Class 1.0 and 2.0 Device Driver Driver" |
| Signature | Authenticode NotSigned; signer none |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1435217507 |
| Reach | n/a (architecture). Device model: Cooler Master UAC audio driver (PortCls). PcNewPort at dump 56803, 57083, 62340. IoRegisterDeviceInterface, IoCreateDevice (device creation under PortCls). No SDDL string in the image. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, portcls.sys, HAL.dll, USBD.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePool, ExAllocatePoolWithTag, ExFreePool, IoAllocateMdl, IoFreeMdl, MmBuildMdlForNonPagedPool, MmMapLockedPagesSpecifyCache, PcRegisterPhysicalConnection, RtlCompareMemory, ZwCreateFile, memcpy, memset.
- Memory write visible in imports: yes (a mapping or MDL-mapping API is imported; the mapped write is not confirmed in this pass)
- Static primitive: Static primitive (checklist: MDL mapped into user mode): the MDL over a driver nonpaged buffer (object at offset 0x128, dump 65826-65837, length 0x20 via MmMapLockedPagesSpecifyCache priority argument) is mapped with AccessMode UserMode (dump 65840). The buffer contents and what user writes can reach were not resolved in this pass. Architecture BLOCKED; write quality not assessed.

## 2 Verdict

**BLOCKED (architecture).** CMUAC_C2A3B919.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see §1 for the static primitive).

## 3 Limitations

- Ghidra dump was run for this image (see Method); the primitive note records the call sites checked. Unchecked paths are listed in the note and do not change the BLOCKED (architecture) status.
- No driver load, no execution, no registry writes, no web lookup.
