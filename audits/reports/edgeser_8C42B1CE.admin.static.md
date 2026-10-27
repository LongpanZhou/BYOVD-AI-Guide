# Audit: edgeser_8C42B1CE.sys

| Field | Value |
|---|---|
| File | drivers\edgeser_8C42B1CE.sys |
| SHA-256 | 8C42B1CE8A88789CD9CBBE76DC682868640326E565A5CEA603A2D25547070492 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: not run (imports sufficient) |
| Company / version | Digi International; file version 6.04.001; "Edgeport Serial Driver 32 bit" |
| Signature | Authenticode UnknownError; signer CN="WDKTestCert davidi,132294677773414589" |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1605295608 |
| Reach | n/a (architecture). Device model: Devices: \Device\EdgeSer%u, \Device\USBSERIAL%03u; symlinks \DosDevices\COM%u, \DosDevices\USBSERIAL%03u. No SDDL string. Effective DACL default. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: USBD.SYS, ntoskrnl.exe, HAL.dll.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePoolWithTag, IoCreateDevice, MmLockPagableDataSection, MmUnlockPagableImageSection, ZwCreateFile, memcpy, memset.
- Memory write visible in imports: no (no mapping, physical-memory or ProbeForWrite API imported; internal copies only)
- Static primitive: No mapping API imported. memcpy present (internal). IoCreateUnprotectedSymbolicLink and IoCreateSymbolicLink present. No kernel-VA write primitive visible in imports.

## 2 Verdict

**BLOCKED (architecture).** edgeser_8C42B1CE.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Static PE triage only. Ghidra was not run on this image (see Method). Imports and strings are not evidence of the absence of an in-object write.
- No driver load, no execution, no registry writes, no web lookup.
