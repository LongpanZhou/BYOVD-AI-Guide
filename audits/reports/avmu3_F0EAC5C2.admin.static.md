# Audit: avmu3_F0EAC5C2.sys

| Field | Value |
|---|---|
| File | drivers\avmu3_F0EAC5C2.sys |
| SHA-256 | F0EAC5C2455DFB4BBCA6B186BD664E3C89744B012BD7D81D57C4F214902B2E1E |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: not run (imports sufficient) |
| Company / version | AVerMedia TECHNOLOGIES, Inc.; file version 1.0.0.33; "AVerMedia Hybrid TV Driver" |
| Signature | Authenticode NotSigned; signer none |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1400648130 |
| Reach | n/a (architecture). Device model: KS / WDM filter; IoRegisterDeviceInterface. No SDDL string. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: NTOSKRNL.EXE, HAL.DLL, ks.sys, ntoskrnl.exe, USBD.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePool, ExFreePoolWithTag, RtlCompareMemory, ZwCreateFile, ZwCreateKey, memcpy, memmove, memset.
- Memory write visible in imports: no (no mapping, physical-memory or ProbeForWrite API imported; internal copies only)
- Static primitive: No mapping API imported. memcpy and memmove present (internal). KS framework (KsInitializeDriver). No kernel-VA write primitive visible in imports.

## 2 Verdict

**BLOCKED (architecture).** avmu3_F0EAC5C2.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Static PE triage only. Ghidra was not run on this image (see Method). Imports and strings are not evidence of the absence of an in-object write.
- No driver load, no execution, no registry writes, no web lookup.
