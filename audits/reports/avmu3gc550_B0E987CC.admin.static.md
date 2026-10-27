# Audit: avmu3gc550_B0E987CC.sys

| Field | Value |
|---|---|
| File | drivers\avmu3gc550_B0E987CC.sys |
| SHA-256 | B0E987CC23D0C591C57D2948AE422AE565BF070B99351A49C769E3F00EC11A40 |
| Analysis date | 2026-10-25 |
| Method | Static PE triage (non-x64; not loadable on x64). Import table, strings, Authenticode and version info. Ghidra: not run (imports sufficient) |
| Company / version | AVerMedia TECHNOLOGIES, Inc.; file version 3.0.0.79; "AVerMedia Hybrid TV Driver" |
| Signature | Authenticode NotSigned; signer none |
| Architecture | x86 (PE32, i386); machine 0x14c; built 1448336914 |
| Reach | n/a (architecture). Device model: KS / WDM filter; IoRegisterDeviceInterface. No SDDL string. |
| Setup required | n/a (architecture: cannot be loaded on x64 Windows) |
| Write quality | not assessed (architecture) |
| Severity | BLOCKED |
| HW-only | no |

## 1 Triage

- Imports from: ntoskrnl.exe, HAL.DLL, ks.sys, USBD.SYS.
- Dangerous imports (regex: map, MDL, copy, physical, probe, memory, section, HAL bus/port, security, pool, create-device): ExAllocatePoolWithTag, ExFreePool, ExFreePoolWithTag, RtlCompareMemory, ZwCreateFile, ZwCreateKey, memcpy, memmove, memset.
- Memory write visible in imports: no (no mapping, physical-memory or ProbeForWrite API imported; internal copies only)
- Static primitive: No mapping API imported. memcpy and memmove present (internal). KS framework. No kernel-VA write primitive visible in imports.

## 2 Verdict

**BLOCKED (architecture).** avmu3gc550_B0E987CC.sys is x86 (PE32, i386) and cannot be loaded on x64 Windows. Write quality is not assessed for non-x64 images (see section 1 for the static primitive).

## 3 Limitations

- Static PE triage only. Ghidra was not run on this image (see Method). Imports and strings are not evidence of the absence of an in-object write.
- No driver load, no execution, no registry writes, no web lookup.
