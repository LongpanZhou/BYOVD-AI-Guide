# Audit: IonEnum_7439AFF2.sys

| Field | Value |
|---|---|
| File | drivers\IonEnum_7439AFF2.sys |
| SHA-256 | 7439AFF2D771A161F4ACE940037C871F32EBB90F9241E4E3425918470088A0F1 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: not run (imports sufficient) |
| Company / version | Digi International; file version 6.04.001; "Serial Port Enumerator 32 bit" |
| Signature | Authenticode NotSigned; signer none |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1605295597 |
| Reach | n/a (architecture). Device model: Serial port enumerator: IoCreateDevice, IoRegisterDeviceInterface. No SDDL string. Effective DACL default. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.dll.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePoolWithTag, IoCreateDevice, memcpy, memset.
- Memory write visible in imports: no (no mapping, physical-memory or ProbeForWrite API imported; internal copies only)
- Static primitive: No mapping API imported (MmMapIoSpace, MmMapLockedPagesSpecifyCache, ZwMapViewOfSection absent). memcpy and memset present (internal copies, not traced). No kernel-VA write primitive visible in imports.

## 2 Verdict

**BLOCKED (architecture).** IonEnum_7439AFF2.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see §1 for the static primitive).

## 3 Limitations

- Static PE triage only. Ghidra was not run on this image (see Method). Imports and strings are not evidence of the absence of an in-object write.
- No driver load, no execution, no registry writes, no web lookup.
